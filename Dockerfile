# To use this image, you typically specify at least the DEMO_WEBSITE_URL
# environment variable. See README.rst for all available variables.
# (You should rarely have to change the DEMO_LISTEN_* settings.)
#
# Alternatively, you may (read-only) mount a config at /app/config.ini.

FROM python:3

COPY . /app
WORKDIR /app

RUN set -x \
 && pip install --no-cache-dir -r requirements.txt \
 && useradd -r -d /app -s /sbin/nologin app

USER app
ENV DEMO_LISTEN_IP 0.0.0.0
CMD ["python", "./server.py"]
EXPOSE 8000
