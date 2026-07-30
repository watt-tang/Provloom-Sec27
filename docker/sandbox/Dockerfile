FROM python:3.10-slim

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG IMAGE_TAG=skill-runtime-sandbox:dynamic-v3
ARG SOURCE_FINGERPRINT=unknown
ARG BUILD_TIMESTAMP=unknown
ARG DYNAMIC_ANALYSIS_VERSION=3.0
LABEL org.provloom.image_tag="${IMAGE_TAG}" \
      org.provloom.source_fingerprint="${SOURCE_FINGERPRINT}" \
      org.provloom.dynamic_analysis_version="${DYNAMIC_ANALYSIS_VERSION}"

RUN HTTP_PROXY=${HTTP_PROXY} HTTPS_PROXY=${HTTPS_PROXY} NO_PROXY=${NO_PROXY} apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        curl \
        git \
        gzip \
        jq \
        strace \
        tar \
        tini \
        time \
        unzip \
        wget \
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
RUN printf '%s\n' \
    "git=$(git --version 2>/dev/null || true)" \
    "curl=$(curl --version 2>/dev/null | head -n 1 || true)" \
    "wget=$(wget --version 2>/dev/null | head -n 1 || true)" \
    "tar=$(tar --version 2>/dev/null | head -n 1 || true)" \
    "gzip=$(gzip --version 2>/dev/null | head -n 1 || true)" \
    "unzip=$(unzip -v 2>/dev/null | head -n 1 || true)" \
    "jq=$(jq --version 2>/dev/null || true)" \
    "coreutils=$(realpath --version 2>/dev/null | head -n 1 || true)" \
    "shell=$(sh --version 2>/dev/null | head -n 1 || echo sh)" \
    "python=$(python --version 2>/dev/null || true)" \
    > /opt/skill_sandbox/installed-tool-versions.txt
ENV PYTHONPATH=/opt/skill_sandbox
ENTRYPOINT ["/usr/bin/tini", "--"]
