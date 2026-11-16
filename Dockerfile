FROM python:3.9-slim

RUN pip install --no-cache-dir "setuptools<58" wheel \
    && pip install --no-cache-dir "eventlet==0.30.2" \
    && pip install --no-cache-dir --no-build-isolation "ryu==4.34"

WORKDIR /app

CMD ["ryu-manager", "--version"]
