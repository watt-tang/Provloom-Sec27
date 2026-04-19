FROM python:3.10-slim

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

RUN HTTP_PROXY=${HTTP_PROXY} HTTPS_PROXY=${HTTPS_PROXY} NO_PROXY=${NO_PROXY} apt-get update \
    && apt-get install -y --no-install-recommends strace ca-certificates tini time \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY app /opt/skill_sandbox/app
ENV PYTHONPATH=/opt/skill_sandbox
ENTRYPOINT ["/usr/bin/tini", "--"]
