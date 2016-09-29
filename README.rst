Portier Relying Party demo code
===============================

This is a minimal Python implementation of a Portier Relying Party. It is
implemented in Python 3. To get started:

.. code-block:: bash

    pip install virtualenv
    virtualenv --python=python3.5 venv
    source venv/bin/activate

    pip install -r requirements.txt

    cp config.json.dist config.json

    ./server.py

The server runs on port 8000 by default, which can be changed by editing
``config.json``. The template works fine for local development, with the
Portier broker running locally as well.

The primary use of this implementation is testing the `broker`_ code.

.. _broker: https://github.com/portier/portier-broker
