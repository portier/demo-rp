Portier Relying Party Demo
==========================

This is a minimal Python implementation of a Portier Relying Party.
To get started, you need Python 3.4 or newer.

.. code-block:: bash

    python3 -m venv ./venv
    ./venv/bin/pip install -r requirements.txt
    ./venv/bin/python3 ./server.py

Configuration
-------------

By default, this demo listens on ``http://localhost:8000`` and delegates to the
production `Portier Broker`_ at ``https://broker.portier.io``. This should be
sufficient for local development and testing of this demo.

To override these values, you can either modify the ``config.ini`` file (there
is an example in ``config.ini.dist``), or set environment variables.

Environment variables always take precedence over ``config.ini``.

============== ==================== =========================
``config.ini`` Environment Variable Default Value
============== ==================== =========================
ListenIP       DEMO_LISTEN_IP       127.0.0.1
ListenPort     DEMO_LISTEN_PORT     8000
WebsiteURL     DEMO_WEBSITE_URL     http://localhost:8000
BrokerURL      DEMO_BROKER_URL      https://broker.portier.io
RedisURL       DEMO_REDIS_URL       (none - uses FakeRedis)
Secret         DEMO_SECRET          (none - generates one)
============== ==================== =========================

About Redis
^^^^^^^^^^^

To prevent replay attacks, this demo needs to be able to store and retrieve a
`nonce`_ for each login attempt. `Redis`_ is a great choice for this, since all
its operations are atomic and it supports time-based expiration of data.

For production deployments of this demo, you must provide a Redis server via the
``RedisURL`` setting. For local testing, this demo uses `FakeRedis`_.

Deploying on Heroku
^^^^^^^^^^^^^^^^^^^

In addition to the environment variables above, this demo will attempt to detect
available metadata when deployed on Heroku.

If ``$PORT`` is set, the app will bind to ``0.0.0.0:${PORT}`` by default. This
can be overriden by setting the ``DEMO_LISTEN_IP`` and ``DEMO_LISTEN_PORT``
environment variables.

If `Dyno Metadata`_ is enabled for your application, the ``WebsiteURL`` will
default to the hostname ``https://${HEROKU_APP_NAME}.herokuapp.com``. This can
still be overridden by setting the ``DEMO_WEBSITE_URL`` environment variable.

If you are using `Redis To Go`_, `RedisGreen`_, `RedisCloud`_, `Heroku Redis`_,
or `openredis`_ with your deployment, this demo will automatically detect and
default the first provider it finds from that list. This can still be overridden
by setting the ``DEMO_REDIS_URL`` environment variable.

.. _Portier Broker: https://github.com/portier/portier-broker
.. _FakeRedis: https://github.com/jamesls/fakeredis
.. _Redis: http://redis.io/
.. _nonce: https://en.wikipedia.org/wiki/Cryptographic_nonce
.. _Dyno Metadata: https://devcenter.heroku.com/articles/dyno-metadata
.. _Redis To Go: https://elements.heroku.com/addons/redistogo
.. _RedisGreen: https://elements.heroku.com/addons/redisgreen
.. _RedisCloud: https://elements.heroku.com/addons/rediscloud
.. _Heroku Redis: https://elements.heroku.com/addons/heroku-redis
.. _openredis: https://elements.heroku.com/addons/openredis
