#!/usr/bin/env python3

from base64 import urlsafe_b64decode
from urllib import parse, request
from wsgiref import simple_server
import binascii
import json
import mimetypes
import os
import re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import bottle
import jwt

DIR = os.path.dirname(os.path.abspath(__file__))

META = json.load(open(os.path.join(DIR, 'config.json')))

# Our example nonce storage is a dict indexed by email. This works for our very
# basic single-process server, but normally you'd store these in a database or
# in the session data.
NONCES = {}


def template(path, status=200, **kwargs):
    headers = {'Content-Type': 'text/html; charset=utf-8'}
    return status, headers, bottle.template(path, **kwargs).encode('utf-8')


def parse_post_body(env):
    data = env['wsgi.input'].read(int(env['CONTENT_LENGTH']))
    params = {}
    for key, values in parse.parse_qs(data).items():
        params[key.decode('ascii')] = [v.decode('ascii') for v in values]
    return params


def index(env):
    return template('index', **META)


def login(env):

    if env['REQUEST_METHOD'] != 'POST':
        return 400, {}, b''

    email = parse_post_body(env)['email'][0]

    nonce = binascii.hexlify(os.urandom(8)).decode('ascii')
    NONCES[email] = nonce

    auth_url = '%s/auth?%s' % (
        META['portier_origin'],
        parse.urlencode({
            'login_hint': email,
            'scope': 'openid email',
            'nonce': nonce,
            'response_type': 'id_token',
            'client_id': META['rp_origin'],
            'redirect_uri': '%s/verify' % META['rp_origin']
        })
    )
    return 303, {'Location': auth_url}, b''


def verify(env):

    if env['REQUEST_METHOD'] != 'POST':
        return 400, {}, b''

    token = parse_post_body(env)['id_token'][0]

    result = get_verified_email(token)
    if 'error' in result:
        return template('error', 400, error=result['error'])

    # At this stage, the user is verified to own the email address. This is
    # where you'd set a cookie to maintain a session in your app. Be sure to
    # restrict the cookie to your secure origin, with the http-only flag set.
    return template('verified', email=result['email'])


def static(env):
    pi = [] if not env['PATH_INFO'] else env['PATH_INFO'].strip('/').split('/')
    fn = os.path.join(DIR, 'static', '/'.join(pi[1:]))
    type = mimetypes.guess_type(fn)[0]
    with open(fn, 'rb') as f:
        src = f.read()
    return 200, {'Content-Type': type}, src


def b64dec(s):
    return urlsafe_b64decode(s.encode('ascii') + b'=' * (4 - len(s) % 4))


def get_verified_email(token):
    rsp = request.urlopen(''.join((
        META['portier_origin'],
        '/.well-known/openid-configuration',
    )))
    config = json.loads(rsp.read().decode('utf-8'))
    if 'jwks_uri' not in config:
        return {'error': 'No jwks_uri in discovery document.'}

    rsp = request.urlopen(config['jwks_uri'])
    try:
        keys = json.loads(rsp.read().decode('utf-8'))['keys']
    except Exception:
        return {'error': 'Problem finding keys in JWK key set.'}

    raw_header = token.split('.', 1)[0]
    header = json.loads(b64dec(raw_header).decode('utf-8'))
    try:
        key = [k for k in keys if k['kid'] == header['kid']][0]
    except Exception:
        return {'error': 'Cannot find key with ID %s.' % header['kid']}

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
                             audience=META['rp_origin'],
                             issuer=META['portier_origin'],
                             leeway=3 * 60)
    except Exception:
        return {'error': 'Invalid token'}

    sub = payload['sub']
    if not re.match('.+@.+', sub):
        return {'error': 'Invalid email: %s' % sub}

    # Make sure the nonce cannot be used on further attempts.
    nonce = NONCES.pop(sub, None)
    if not nonce or payload['nonce'] != nonce:
        return {'error': 'Session expired'}

    return {'email': payload['sub']}


HANDLERS = {'index': index, 'login': login, 'verify': verify, 'static': static}
STATUS = {200: '200 OK', 303: '303 See Other', 400: '400 Bad Request'}


def application(env, respond):
    pi = [] if not env['PATH_INFO'] else env['PATH_INFO'].strip('/').split('/')
    handler = pi[0] if pi and pi[0] else 'index'
    status, headers, content = HANDLERS[handler](env)
    respond(STATUS[status], list(headers.items()))
    return [content]


if __name__ == '__main__':
    host, port = parse.urlparse(META['rp_origin']).netloc.split(':')
    simple_server.make_server(host, int(port), application).serve_forever()
