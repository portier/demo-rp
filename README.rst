Portier Relying Party Demo
==========================

This is a minimal Python implementation of a Portier Relying Party. It is
implemented in Python 3. To get started:

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
============== ==================== =========================

About Redis
^^^^^^^^^^^

To prevent replay attacks, this demo needs to be able to store and retrieve a
`nonce`_ for each login attempt. `Redis`_ is a great choice for this, since all
its operations are atomic and it supports time-based expiration of data.

For production deployments of this demo, you must provide a Redis server via the
``RedisURL`` setting. For local testing, this demo uses `FakeRedis`_.

.. _Portier Broker: https://github.com/portier/portier-broker
.. _FakeRedis: https://github.com/jamesls/fakeredis
.. _Redis: http://redis.io/
.. _nonce: https://en.wikipedia.org/wiki/Cryptographic_nonce
