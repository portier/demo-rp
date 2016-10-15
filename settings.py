"""Configuration parser for the Portier demo application."""

from configparser import ConfigParser
from os import environ as ENV

META = (
    # Environment Var    Config Key    Default Value
    ('DEMO_LISTEN_IP',   'ListenIP',   '127.0.0.1'),
    ('DEMO_LISTEN_PORT', 'ListenPort', '8000'),
    ('DEMO_WEBSITE_URL', 'WebsiteURL', 'http://localhost:8000'),
    ('DEMO_BROKER_URL',  'BrokerURL',  'https://broker.portier.io'),
    ('DEMO_REDIS_URL',   'RedisURL',   None),
)

HEROKU_REDIS_ENV_VARS = ('REDISTOGO_URL', 'REDISGREEN_URL', 'REDISCLOUD_URL',
                         'REDIS_URL', 'OPENREDIS_URL')

INI_SECTION = 'PortierDemo'


def load():
    """Determine the demo's effective configuration.

    Order of precedence, from highest to lowest:

    1. App-specific environment variables (``DEMO_`` ones)
    2. Common and Heroku-specific environment variables
    3. Values in ``config.ini``
    4. Default values

    See ``README.rst`` and ``config.ini.dist`` for more information.
    """
    parser = ConfigParser(default_section=INI_SECTION,
                          defaults={key: val for _, key, val in META})

    settings = parser[INI_SECTION]

    # Read values from config.ini
    parser.read('config.ini')

    # Detect common environment variables on Heroku
    if 'PORT' in ENV:
        settings['ListenIP'] = '0.0.0.0'  # Necessary on Heroku
        settings['ListenPort'] = ENV['PORT']

    if 'HEROKU_APP_NAME' in ENV:
        url = 'https://%s.herokuapp.com' % ENV['HEROKU_APP_NAME']
        settings['WebsiteURL'] = url

    for var in HEROKU_REDIS_ENV_VARS:
        if var in ENV:
            settings['RedisURL'] = ENV[var]
            break

    # Read app-specific environment variables
    for var, key, _ in META:
        if var in ENV:
            settings[key] = ENV[var]

    return settings
