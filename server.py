#!/usr/bin/env python3

from base64 import urlsafe_b64decode
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse
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
import jwt

DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG = json.load(open(os.path.join(DIR, 'config.json')))

# Identity tokens expire after a few minutes, but might be reused while valid.
#
# To defend against replay attacks, sites can optionally supply a nonce during
# authentication which is echoed back in the identity token.
#
# For simplicity, this example uses a plain Python dict. This approach breaks
# in multi-threaded environments. In production, use a real database for this.

NONCES = {}

app = Bottle()


@app.get('/')
def index():
    return template('index')


@app.post('/login')
def login():
    email = request.forms['email']

    nonce = uuid4().hex
    expiry = datetime.utcnow() + timedelta(minutes=30)
    NONCES[nonce] = expiry.timestamp()

    auth_url = '%s/auth?%s' % (
        CONFIG['portier_origin'],
        urlencode({
            'login_hint': email,
            'scope': 'openid email',
            'nonce': nonce,
            'response_type': 'id_token',
            'client_id': CONFIG['rp_origin'],
            'redirect_uri': '%s/verify' % CONFIG['rp_origin']
        })
    )
    return redirect(auth_url)


@app.post('/verify')
def verify():
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


def b64dec(s):
    return urlsafe_b64decode(s.encode('ascii') + b'=' * (4 - len(s) % 4))


def get_verified_email(token):
    # Discover where the Broker's public keys are located
    rsp = urlopen(''.join((
        CONFIG['portier_origin'],
        '/.well-known/openid-configuration',
    )))
    config = json.loads(rsp.read().decode('utf-8'))
    if 'jwks_uri' not in config:
        raise RuntimeError('No jwks_uri in discovery document')

    rsp = urlopen(config['jwks_uri'])
    try:
        keys = json.loads(rsp.read().decode('utf-8'))['keys']
    except Exception:
        raise RuntimeError('No keys found in JWK Set')

    raw_header = token.split('.', 1)[0]
    header = json.loads(b64dec(raw_header).decode('utf-8'))
    try:
        key = [k for k in keys if k['kid'] == header['kid']][0]
    except Exception:
        raise RuntimeError('Cannot find key with ID %s' % header['kid'])

    e = int.from_bytes(b64dec(key['e']), 'big')
    n = int.from_bytes(b64dec(key['n']), 'big')
    pub_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())

    # PyJWT checks the following for us:
    #  - header is using an appropriate signing algorithm
    #  - signature is valid and matches pub_key
    #  - aud matches our (the relying party) origin
    #  - iss matches the Portier origin
    #  - exp > (now) > nbf, and (now) > iat
    #    (the leeway argument specifies the allowed margin for these)
    try:
        payload = jwt.decode(token, pub_key,
                             algorithms=['RS256'],
                             audience=CONFIG['rp_origin'],
                             issuer=CONFIG['portier_origin'],
                             leeway=3 * 60)
    except Exception as exc:
        raise RuntimeError('Invalid JWT: %s' % exc)

    sub = payload['sub']
    if not re.match('.+@.+', sub):
        raise RuntimeError('Invalid email address: %s' % sub)

    # Garbage collect expired nonces
    global NONCES
    NONCES = {nonce: expiry for nonce, expiry in NONCES.items()
              if expiry >= datetime.utcnow().timestamp()}

    # Invalidate this nonce by removing it from NONCES
    try:
        NONCES.pop(payload['nonce'])
    except KeyError:
        raise RuntimeError('Invalid or expired nonce')

    return payload['sub']


if __name__ == '__main__':
    host, port = urlparse(CONFIG['rp_origin']).netloc.split(':')
    app.run(host=host, port=port)
