FROM python:3.10-slim

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

RUN HTTP_PROXY=${HTTP_PROXY} HTTPS_PROXY=${HTTPS_PROXY} NO_PROXY=${NO_PROXY} apt-get update \
    && apt-get install -y --no-install-recommends strace ca-certificates curl tini time \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN HTTP_PROXY=${HTTP_PROXY} HTTPS_PROXY=${HTTPS_PROXY} NO_PROXY=${NO_PROXY} curl -fsSL https://tinyclaw.net/install.sh | sh \
    && mv /tmp/tinyclaw /usr/local/bin/tinyclaw \
    && chmod +x /usr/local/bin/tinyclaw

WORKDIR /workspace
COPY app /opt/skill_sandbox/app
ENV PYTHONPATH=/opt/skill_sandbox
ENTRYPOINT ["/usr/bin/tini", "--"]
