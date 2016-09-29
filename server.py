#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from base64 import urlsafe_b64decode
import json
import jwt
import re
from urllib import parse, request
from time import time
from wsgiref import simple_server
import os, mimetypes, html

DIR = os.path.dirname(os.path.abspath(__file__))

META = json.load(open(os.path.join(DIR, 'config.json')))

def template(tpl, status=200, **vars):
    with open(os.path.join(DIR, tpl) + '.tpl') as f:
        src = f.read()
    for k, v in vars.items():
        src = src.replace('{{ %s }}' % k, html.escape(v, True))
    headers = {'Content-Type': 'text/html; charset=utf-8'}
    return 200, headers, src.encode('utf-8')


def index(env):
    return template('template/index', **META)


def login(env):

    if env['REQUEST_METHOD'] == 'GET':
        return 302, {'Location': META['rp_origin'] + '/'}, b''

    body = env['wsgi.input'].read(int(env['CONTENT_LENGTH']))
    token = parse.parse_qs(body)[b'id_token'][0].decode('ascii')
    result = get_verified_email(token)
    if 'error' in result:
        return template('template/error', 400,
                        error=result['error'])

    # At this stage, the user is verified to own the email address. This is
    # where you'd set a cookie to maintain a session in your app. Be sure to
    # restrict the cookie to your secure origin, with the http-only flag set.
    return template('template/verified',
                    email=result['email'])


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
    if not re.match('.+@.+', sub):  # <-- TODO: Use a proper parser.
        return {'error': 'Invalid email: %s' % sub}

    return {'email': payload['sub']}


HANDLERS = {'index': index, 'login': login, 'static': static}
STATUS = {200: '200 OK', 302: '302 Found', 400: '400 Bad Request'}

def application(env, respond):
    pi = [] if not env['PATH_INFO'] else env['PATH_INFO'].strip('/').split('/')
    handler = pi[0] if pi and pi[0] else 'index'
    status, headers, content = HANDLERS[handler](env)
    respond(STATUS[status], list(headers.items()))
    return [content]


if __name__ == '__main__':
    host, port = parse.urlparse(META['rp_origin']).netloc.split(':')
    simple_server.make_server(host, int(port), application).serve_forever()
