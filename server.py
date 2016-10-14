#!/usr/bin/env python3

from base64 import urlsafe_b64decode
from configparser import ConfigParser
from urllib.parse import urlencode
from urllib.request import urlopen
from uuid import uuid4
import json
import os
import re

from bottle import (
    Bottle, redirect, request, response, static_file, template
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import fakeredis
import jwt
import redis

DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_META = (
    # Environment Var    Config Key    Default Value
    ('DEMO_LISTEN_IP',   'ListenIP',   '127.0.0.1'),
    ('DEMO_LISTEN_PORT', 'ListenPort', '8000'),
    ('DEMO_WEBSITE_URL', 'WebsiteURL', 'http://localhost:8000'),
    ('DEMO_BROKER_URL',  'BrokerURL',  'https://broker.portier.io'),
    ('DEMO_REDIS_URL',   'RedisURL',   None),
)

CONFIG_PARSER = ConfigParser(default_section='PortierDemo',
                             defaults={k: v for _, k, v in CONFIG_META})

# Override defaults with values in config.ini
CONFIG_PARSER.read('config.ini')

# Override defaults with autodetected metadata on Heroku
# ...Port
if 'PORT' in os.environ:
    CONFIG_PARSER[CONFIG_PARSER.default_section]['ListenIP'] = '0.0.0.0'
    CONFIG_PARSER[CONFIG_PARSER.default_section]['ListenPort'] = os.environ['PORT'] # noqa

# ...WebsiteURL
if 'HEROKU_APP_NAME' in os.environ:
    url = 'https://%s.herokuapp.com' % os.environ['HEROKU_APP_NAME']
    CONFIG_PARSER[CONFIG_PARSER.default_section]['WebsiteURL'] = url

# ...RedisURL
for var in ('REDISTOGO_URL', 'REDISGREEN_URL', 'REDISCLOUD_URL', 'REDIS_URL', 'OPENREDIS_URL'): # noqa
    if var in os.environ:
        CONFIG_PARSER[CONFIG_PARSER.default_section]['RedisURL'] = os.environ[var]  # noqa
        break

# Override values in config.ini with environment variables
for var, key, _ in CONFIG_META:
    if var in os.environ:
        CONFIG_PARSER[CONFIG_PARSER.default_section][key] = os.environ[var]

SETTINGS = CONFIG_PARSER[CONFIG_PARSER.default_section]

# Identity tokens expire after a few minutes, but might be reused while valid.
#
# To defend against replay attacks, sites must supply a nonce during
# authentication which is echoed back in the identity token.
#
# For simplicity, this demo defaults to FakeRedis. Use real Redis in prod.
if SETTINGS['RedisURL']:
    REDIS = redis.StrictRedis.from_url(SETTINGS['RedisURL'])
else:
    REDIS = fakeredis.FakeStrictRedis()

app = Bottle()


@app.get('/')
def index():
    return template('index')


@app.post('/login')
def login():
    # Read the user's email address from the POSTed form data
    email = request.forms['email']

    # Generate and store a nonce to uniquely identify this login request.
    # This allows us to prevent identity tokens from being used more than once.
    nonce = uuid4().hex

    # Wrap Redis SET/EXPIRE in a MULTI/EXEC transaction to ensure both happen.
    # Without the transaction, we risk adding a nonce but not its expiration.
    txn = REDIS.pipeline()
    txn.set(nonce, '')
    txn.expire(nonce, 15 * 60)  # 15 minutes
    txn.execute()

    # Forward the user to the broker, along with all necessary parameters
    auth_url = '%s/auth?%s' % (
        SETTINGS['BrokerURL'],
        urlencode({
            'login_hint': email,
            'scope': 'openid email',
            'nonce': nonce,
            'response_type': 'id_token',
            'client_id': SETTINGS['WebsiteURL'],
            'redirect_uri': '%s/verify' % SETTINGS['WebsiteURL']
        })
    )
    return redirect(auth_url)


@app.post('/verify')
def verify():
    # Read the signed identity token from the POSTed form data
    token = request.forms['id_token']

    try:
        email = get_verified_email(token)
    except RuntimeError as exc:
        response.status = 400
        return template('error', error=exc)

    # At this stage, the user is verified to own the email address. This is
    # where you'd set a cookie to maintain a session in your app. Be sure to
    # restrict the cookie to your secure origin, with the http-only flag set.
    return template('verified', email=email)


@app.get('/static/<path:path>')
def static(path):
    return static_file(path, os.path.join(DIR, 'static'))


def b64dec(string):
    # Pad the base64 string with '=' to a multiple of 4 characters
    padding = '=' * ((4 - len(string) % 4) % 4)
    return urlsafe_b64decode(string + padding)


def discover_keys(broker):
    """Discover and return the broker's public keys"""""

    # Fetch the OpenID Connect Dynamic Discovery document
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
    """Convert a deserialized JWK into an RSA Public Key instance"""
    e = int.from_bytes(b64dec(key['e']), 'big')
    n = int.from_bytes(b64dec(key['n']), 'big')
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())


def get_verified_email(token):
    # Discover and deserialize the key used to sign this JWT
    keys = discover_keys(SETTINGS['BrokerURL'])

    raw_header, _, _ = token.partition('.')
    header = json.loads(b64dec(raw_header).decode('utf-8'))
    try:
        pub_key = keys[header['kid']]
    except KeyError:
        raise RuntimeError('Cannot find key with ID %s' % header['kid'])

    # We must ensure that all JWTs have a valid cryptographic signature.
    # Portier only supports OpenID Connect's default signing algorithm: RS256.
    #
    # OpenID Connect's JWTs also have six required claims that we must verify:
    #
    # - `aud` (audience) must match this website's origin.
    # - `iss` (issuer) must match the broker's origin.
    # - `exp` (expires) must be in the future.
    # - `iat` (issued at) must be in the past.
    # - `sub` (subject) must be an email address.
    # - `nonce` (cryptographic nonce) must not have been seen previously.
    #
    # The following, optional claims may also appear in the JWT payload:
    #
    # - `nbf` (not before) must be in the past.
    #
    # We delegate to PyJWT, which checks signatures and validates all claims
    # except `sub` and `nonce`. Timestamps are allowed a small margin of error.
    #
    # More info at: https://github.com/jpadilla/pyjwt
    try:
        payload = jwt.decode(token, pub_key,
                             algorithms=['RS256'],
                             audience=SETTINGS['WebsiteURL'],
                             issuer=SETTINGS['BrokerURL'],
                             leeway=3 * 60)
    except Exception as exc:
        raise RuntimeError('Invalid JWT: %s' % exc)

    # Check that the subject looks like an email address
    subject = payload['sub']
    if not re.match('.+@.+', subject):
        raise RuntimeError('Invalid email address: %s' % subject)

    # Invalidate this nonce
    if not REDIS.delete(payload['nonce']):
        raise RuntimeError('Invalid or expired nonce')

    return subject


if __name__ == '__main__':
    print("Starting Portier Demo...")
    print("-> Demo URL: %s" % SETTINGS['WebsiteURL'])
    print("-> Broker URL: %s" % SETTINGS['BrokerURL'])
    print("-> Redis: %s" % REDIS)
    print()

    app.run(host=SETTINGS['ListenIP'], port=SETTINGS['ListenPort'])
