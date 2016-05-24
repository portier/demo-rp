#!/usr/bin/env python3

from base64 import urlsafe_b64decode as b64dec
import json
from os import getenv
import re
from urllib import parse
from time import time
from wsgiref import simple_server
import os, mimetypes

DIR = os.path.dirname(os.path.abspath(__file__))

META = {
    'LA_ORIGIN': 'https://laoidc.herokuapp.com',
    'RP_ORIGIN': 'http://localhost:%s' % getenv('PORT', '8080'),
}

if getenv('HEROKU_APP_NAME'):
    META['RP_ORIGIN'] = 'https://%s.herokuapp.com' % getenv('HEROKU_APP_NAME')


def template(tpl, status=200, **vars):
    with open(os.path.join(DIR, tpl) + '.tpl') as f:
        src = f.read()
    for k, v in vars.items():
        src = src.replace('{{ %s }}' % k, v)
    headers = {'Content-Type': 'text/html; charset=utf-8'}
    return 200, headers, src.encode('utf-8')


def index(env):
    return template('template/index', **META)


def login(env):

    if env['REQUEST_METHOD'] == 'GET':
        return index(env)

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


def get_verified_email(jwt):
    # FIXME: This blindly trusts the JWT. Need to verify:
    # [ ] header is using an appropriate signing algorithm
    # [ ] signature is valid and matches a key from the LA provider's JWK Set
    # [x] iss matches a trusted LA provider's origin
    # [x] aud matches this site's origin
    # [x] exp > (now) > iat, with some margin
    # [-] sub is a valid email address

    (raw_header, raw_payload, raw_signature) = jwt.split('.')
    payload = json.loads(b64dec(raw_payload + '====').decode('utf-8'))

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
STATUS = {200: '200 OK', 400: '400 Bad Request'}

def application(env, respond):
    pi = [] if not env['PATH_INFO'] else env['PATH_INFO'].strip('/').split('/')
    handler = pi[0] if pi and pi[0] else 'index'
    status, headers, content = HANDLERS[handler](env)
    respond(STATUS[status], list(headers.items()))
    return [content]


if __name__ == '__main__':
    host, port = parse.urlparse(META['RP_ORIGIN']).netloc.split(':')
    simple_server.make_server(host, int(port), application).serve_forever()
