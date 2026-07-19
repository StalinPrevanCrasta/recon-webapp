# syntax=docker/dockerfile:1.7

##############################
# Stage 1: build Go recon tools
# Only runs again when tool versions change.
##############################
FROM golang:1.26-bookworm AS tools
ENV GOBIN=/out
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.14.0 && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0 && \
    go install github.com/ffuf/ffuf/v2@v2.2.1 && \
    # gowitness 3.1.1 pinned by immutable pseudo-version (tag has no v prefix)
    go install github.com/sensepost/gowitness@v0.0.0-20251124071355-df54b384f416 && \
    go install github.com/d3mondev/puredns/v2@v2.1.1 && \
    go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@v1.2.1

##############################
# Stage 2: runtime
# No Go toolchain, git, build-essential or seclists here.
# App code is copied last so code-only edits rebuild in seconds.
##############################
FROM kalilinux/kali-rolling@sha256:b3d7855dd35daa5e56a6806e9c34cb91c954d9a8a97b78c3352438732a61a079
ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/opt/venv/bin:$PATH \
    RECON_DATA_DIR=/data \
    DEFAULT_FFUF_WORDLIST=/app/wordlists/default/common.txt
WORKDIR /app

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv ca-certificates curl \
    chromium xvfb amass massdns dnsutils

COPY --from=tools /out/ /usr/local/bin/

# httpx -tech-detect needs this model; download it at build time so scans do not
# fail or stall on first-run network initialization inside the worker.
RUN mkdir -p /root/.dit && \
    curl -fsSL --retry 3 --retry-delay 5 \
    https://huggingface.co/datasets/happyhackingspace/dit/resolve/main/model.json \
    -o /root/.dit/model.json

COPY requirements.txt /app/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m venv /opt/venv && /opt/venv/bin/pip install -r /app/requirements.txt && \
    rm -f /opt/venv/bin/httpx

COPY wordlists /app/wordlists
COPY app /app/app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
