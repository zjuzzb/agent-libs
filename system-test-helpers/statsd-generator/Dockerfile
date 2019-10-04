FROM alpine:latest
MAINTAINER QA Team
COPY statsd-generator.py /
RUN apk add --no-cache python3 && \
    python3 -m ensurepip && \
    rm  -r /usr/lib/python*/ensurepip && \
    pip3 install --no-cache --upgrade pip setuptools wheel && \
    pip3 install --no-cache statsd
CMD ["/usr/bin/env", "python3", "statsd-generator.py"]
