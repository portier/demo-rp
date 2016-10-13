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
============== ==================== =========================

.. _Portier Broker: https://github.com/portier/portier-broker
