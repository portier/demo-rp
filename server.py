#!/usr/bin/env python3
"""Portier demo website.

This website exposes the following HTTP endpoints:

================ =====================================================
HTTP Endpoint    Description
================ =====================================================
GET  /           Render homepage
GET  /static/... Server static assets
POST /login      Redirect to the broker and begin authentication
POST /verify     Receive an id_token via the broker and complete login
POST /logout     Clear session cookies
GET  /logout     Display a button to POST /logout
================ =====================================================

Attempting to ``GET /login`` or ``GET /verify`` will redirect to ``/``.
"""

from base64 import urlsafe_b64decode
from datetime import timedelta
from urllib.parse import urlencode
from urllib.request import urlopen
from uuid import uuid4
import json
import os
import re

from bottle import Bottle, redirect, request, response, static_file, template
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import fakeredis
import jwt
import redis
import settings

DIR = os.path.dirname(os.path.abspath(__file__))

SETTINGS = settings.load()

if SETTINGS['RedisURL']:
    REDIS = redis.StrictRedis.from_url(SETTINGS['RedisURL'])
else:
    REDIS = fakeredis.FakeStrictRedis()  # <-- Only suitable for local testing

app = Bottle()


# HTTP Routes ----------------------------------------------------------------


@app.get('/')
def index():
    """Render the homepage."""
    # Check if the user has a session cookie
    email = request.get_cookie('email', secret=SETTINGS['Secret'])
    if email:
        return template('verified', email=email)
    else:
        return template('index')


@app.get('/login')
def login_get():
    """Redirect GET /login to /."""
    return redirect('/')


@app.post('/login')
def login_post():
    """Redirect to the broker to begin an Authentication Request.

    The specific parameters used in the Authentication Request are described in
    the OpenID Connect `Implicit Flow`_ spec, which Portier brokers implement.

    To prevent replay attacks, each Authentication Request is tagged with a
    unique nonce. This nonce is echoed back via the broker during user login.

    .. _Implicit Flow:
        https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
    """
    # Get the user's email address from the HTTP POST form data
    email = request.forms['email']

    # Generate and store a nonce for this authentication request
    nonce = uuid4().hex
    REDIS.setex(nonce, timedelta(minutes=15).seconds, '')

    # Forward the user to the broker, along with all necessary parameters
    query_args = urlencode({
        'login_hint': email,
        'scope': 'openid email',
        'nonce': nonce,
        'response_type': 'id_token',
        'client_id': SETTINGS['WebsiteURL'],
        'redirect_uri': SETTINGS['WebsiteURL'] + '/verify',
    })

    # FIXME: The Authorization Endpoint should be discovered, not hardcoded
    url = SETTINGS['BrokerURL'] + '/auth?' + query_args

    return redirect(url)


@app.get('/verify')
def verify_get():
    """Redirect GET /verify to /."""
    return redirect('/')


@app.post('/verify')
def verify_post():
    """Validate an Identity Token and log the user in.

    If the token is valid and signed by a trusted broker, you can directly log
    the user into the site, just like you would if you had verified a password.

    Normally, this would include setting a signed, http-only session cookie.
    """
    # Get the user's signed identity token from the HTTP POST form data
    token = request.forms['id_token']

    # Check the validity and authenticity of the identity token
    try:
        email = get_verified_email(token)
    except RuntimeError as exc:
        response.status = 400
        return template('error', error=exc)

    # Done logging in! Set a session cookie with the following properties:
    # - It should be cryptographically signed to prevent tampering.
    # - It should be marked 'http-only' to prevent exfiltration via XSS.
    # - If possible, it should be marked 'secure' so it's only sent via HTTPS.
    response.set_cookie('email', email,
                        secret=SETTINGS['Secret'],
                        secure=SETTINGS['WebsiteURL'].startswith('https://'),
                        httponly=True)

    return redirect('/')


@app.post('/logout')
def logout_post():
    """Clear session cookies."""
    response.delete_cookie('email')
    return redirect('/')


@app.get('/logout')
def logout_get():
    """Display a button that POSTS to /logout."""
    return template('logout')


@app.get('/static/<path:path>')
def static(path):
    """Serve static files."""
    return static_file(path, os.path.join(DIR, 'static'))


# Protocol Helpers -----------------------------------------------------------


def b64dec(string):
    """Decode unpadded URL-safe Base64 strings.

    Base64 values in JWTs and JWKs have their padding '=' characters stripped
    during serialization. Before decoding, we must re-append padding characters
    so that the encoded value's final length is evenly divisible by 4.
    """
    padding = '=' * ((4 - len(string) % 4) % 4)
    return urlsafe_b64decode(string + padding)


def discover_keys(broker):
    """Discover and return a Broker's public keys.

    Returns a dict mapping from Key ID strings to Public Key instances.

    Portier brokers implement the `OpenID Connect Discovery`_ specification.
    This function follows that specification to discover the broker's current
    cryptographic public keys:

    1. Fetch the Discovery Document from ``/.well-known/openid-configuration``.
    2. Parse it as JSON and read the ``jwks_uri`` property.
    3. Fetch the URL referenced by ``jwks_uri`` to retrieve a `JWK Set`_.
    4. Parse the JWK Set as JSON and extract keys from the ``keys`` property.

    Portier currently only supports keys with the ``RS256`` algorithm type.

    .. _OpenID Connect Discovery:
        https://openid.net/specs/openid-connect-discovery-1_0.html
    .. _JWK Set: https://tools.ietf.org/html/rfc7517#section-5
    """
    # Fetch Discovery Document
    res = urlopen(''.join((broker, '/.well-known/openid-configuration')))
    discovery = json.loads(res.read().decode('utf-8'))
    if 'jwks_uri' not in discovery:
        raise RuntimeError('No jwks_uri in discovery document')

    # Fetch the JWK Set document
    res = urlopen(discovery['jwks_uri'])
    jwks = json.loads(res.read().decode('utf-8'))
    if 'keys' not in jwks:
        raise RuntimeError('No keys found in JWK Set')

    # Return the discovered keys as a Key ID -> RSA Public Key dictionary
    return {key['kid']: jwk_to_rsa(key) for key in jwks['keys']
            if key['alg'] == 'RS256'}


def jwk_to_rsa(key):
    """Convert a deserialized JWK into an RSA Public Key instance."""
    e = int.from_bytes(b64dec(key['e']), 'big')
    n = int.from_bytes(b64dec(key['n']), 'big')
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())


def get_verified_email(token):
    """Validate an Identity Token (JWT) and return its subject (email address).

    In Portier, the subject field contains the user's verified email address.

    This functions checks the authenticity of the JWT with the following steps:

    1. Verify that the JWT has a valid signature from a trusted broker.
    2. Validate that all claims are present and conform to expectations:

        * ``aud`` (audience) must match this website's origin.
        * ``iss`` (issuer) must match the broker's origin.
        * ``exp`` (expires) must be in the future.
        * ``iat`` (issued at) must be in the past.
        * ``sub`` (subject) must be an email address.
        * ``nonce`` (cryptographic nonce) must not have been seen previously.

    3. If present, verify that the ``nbf`` (not before) claim is in the past.

    Timestamps are allowed a few minutes of leeway to account for clock skew.

    This demo relies on the `PyJWT`_ library to check signatures and validate
    all claims except for ``sub`` and ``nonce``. Those are checked separately.

    .. _PyJWT: https://github.com/jpadilla/pyjwt
    """
    # Retrieve this broker's public keys
    keys = discover_keys(SETTINGS['BrokerURL'])

    # Locate the specific key used to sign this JWT via its ``kid`` header.
    raw_header, _, _ = token.partition('.')
    header = json.loads(b64dec(raw_header).decode('utf-8'))
    try:
        pub_key = keys[header['kid']]
    except KeyError:
        raise RuntimeError('Cannot find public key with ID %s' % header['kid'])

    # Verify the JWT's signature and validate its claims
    try:
        payload = jwt.decode(token, pub_key,
                             algorithms=['RS256'],
                             audience=SETTINGS['WebsiteURL'],
                             issuer=SETTINGS['BrokerURL'],
                             leeway=3 * 60)
    except Exception as exc:
        raise RuntimeError('Invalid JWT: %s' % exc)

    # Validate that the subject resembles an email address
    if not re.match('.+@.+', payload['sub']):
        raise RuntimeError('Invalid email address: %s' % payload['sub'])

    # Invalidate the nonce used in this JWT to prevent re-use
    if not REDIS.delete(payload['nonce']):
        raise RuntimeError('Invalid, expired, or re-used nonce')

    # Done!
    return payload['sub']


# Server Boilerplate ---------------------------------------------------------


if __name__ == '__main__':
    print("Starting Portier Demo...")
    print("-> Demo URL: %s" % SETTINGS['WebsiteURL'])
    print("-> Broker URL: %s" % SETTINGS['BrokerURL'])
    print("-> Redis: %s" % REDIS)
    print()

    app.run(host=SETTINGS['ListenIP'], port=SETTINGS['ListenPort'],
            server='aiohttp')
