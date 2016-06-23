#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from base64 import urlsafe_b64decode
import json
from os import getenv
import re
from urllib import parse, request
from time import time
from wsgiref import simple_server
import os, mimetypes, html

DIR = os.path.dirname(os.path.abspath(__file__))

META = {
    'LA_ORIGIN': 'https://letsauth.xavamedia.nl',
    'RP_ORIGIN': 'http://xavamedia.nl:%s' % getenv('PORT', '8000'),
}

if getenv('HEROKU_APP_NAME'):
    META['RP_ORIGIN'] = 'https://%s.herokuapp.com' % getenv('HEROKU_APP_NAME')


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
        return 302, {'Location': META['RP_ORIGIN'] + '/'}, b''

    body = env['wsgi.input'].read(int(env['CONTENT_LENGTH']))
    jwt = parse.parse_qs(body)[b'id_token'][0].decode('ascii')
    result = get_verified_email(jwt)
    if 'error' in result:
        return template('template/error', 400,
                        error=result['error'])

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


def get_verified_email(jwt):
    # FIXME: This blindly trusts the JWT. Need to verify:
    # [ ] header is using an appropriate signing algorithm
    # [x] signature is valid and matches a key from the LA provider's JWK Set
    # [x] iss matches a trusted LA provider's origin
    # [x] aud matches this site's origin
    # [x] exp > (now) > iat, with some margin
    # [-] sub is a valid email address

    rsp = request.urlopen(''.join((
        META['LA_ORIGIN'],
        '/.well-known/openid-configuration',
    )))
    config = json.loads(rsp.read().decode('utf-8'))
    rsp = request.urlopen(config['jwks_uri'])
    keys = json.loads(rsp.read().decode('utf-8'))['keys']

    raw_header, raw_payload, raw_signature = jwt.split('.')
    header = json.loads(b64dec(raw_header).decode('utf-8'))
    key = [k for k in keys if k['kid'] == header['kid']][0]
    e = int.from_bytes(b64dec(key['e']), 'big')
    n = int.from_bytes(b64dec(key['n']), 'big')
    pub_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())

    signature = b64dec(raw_signature)
    verifier = pub_key.verifier(signature, padding.PKCS1v15(), hashes.SHA256())
    verifier.update(b'.'.join((
        raw_header.encode('ascii'),
        raw_payload.encode('ascii'),
    )))
    try:
        verifier.verify()
    except Exception:
        return {'error': 'Invalid signature'}

    payload = json.loads(b64dec(raw_payload).decode('utf-8'))
    iss = payload['iss']
    known_iss = META['LA_ORIGIN']
    if iss != known_iss:
        return {'error':
                'Untrusted issuer. Expected %s, got %s' % (known_iss, iss)}

    aud = payload['aud']
    known_aud = META['RP_ORIGIN']
    if aud != known_aud:
        return {'error':
                'Audience mismatch. Expected %s, got %s' % (known_aud, aud)}

    iat = payload['iat']
    exp = payload['exp']
    now = int(time())
    slack = 3 * 60  # 3 minutes
    currently_valid = (iat - slack) < now < (exp + slack)
    if not currently_valid:
        return {'error':
                'Timestamp error. iat %d < now %d < exp %d' % (iat, now, exp)}

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
    host, port = parse.urlparse(META['RP_ORIGIN']).netloc.split(':')
    simple_server.make_server(host, int(port), application).serve_forever()
