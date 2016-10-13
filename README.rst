Portier Relying Party Demo
==========================

This is a minimal Python implementation of a Portier Relying Party. It is
implemented in Python 3. To get started:

.. code-block:: bash

    python3 -m venv ./venv
    ./venv/bin/pip install -r requirements.txt
    cp config.json.dist config.json
    ./venv/bin/python3 ./server.py

The server runs on port 8000 by default, which can be changed by editing
``config.json``. The template works fine for local development, with the
Portier broker running locally as well.

The primary use of this implementation is testing the `broker`_ code.

.. _broker: https://github.com/portier/portier-broker
