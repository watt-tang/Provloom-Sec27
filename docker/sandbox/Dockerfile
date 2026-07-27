FROM python:3.10-slim

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG IMAGE_TAG=skill-runtime-sandbox:dynamic-v3
ARG SOURCE_FINGERPRINT=unknown
ARG BUILD_TIMESTAMP=unknown
ARG DYNAMIC_ANALYSIS_VERSION=3.0

RUN HTTP_PROXY=${HTTP_PROXY} HTTPS_PROXY=${HTTPS_PROXY} NO_PROXY=${NO_PROXY} apt-get update \
    && apt-get install -y --no-install-recommends strace ca-certificates tini time \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY app /opt/skill_sandbox/app
RUN printf '%s\n' \
    '{' \
    "  \"build_timestamp\": \"${BUILD_TIMESTAMP}\"," \
    "  \"image_tag\": \"${IMAGE_TAG}\"," \
    "  \"source_fingerprint\": \"${SOURCE_FINGERPRINT}\"," \
    "  \"dynamic_analysis_version\": \"${DYNAMIC_ANALYSIS_VERSION}\"," \
    '  "dynamic_version": "v3",' \
    '  "semantic_profile": "evidence-graded-carrier-aware",' \
    '  "canonical_assessment_enabled": true,' \
    '  "canonical_assessment_version": "1.0",' \
    '  "alignment_version": "1.0"' \
    '}' > /opt/skill_sandbox/runtime-build-info.json
ENV PYTHONPATH=/opt/skill_sandbox
ENTRYPOINT ["/usr/bin/tini", "--"]
