# syntax=docker/dockerfile:1.7
FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive PATH=/root/go/bin:/usr/local/go/bin:$PATH RECON_DATA_DIR=/data
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv ca-certificates curl git golang-go build-essential libpcap-dev \
    chromium xvfb amass massdns dnsutils && \
    rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.9.0 && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.5 && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.7.2 && \
    go install github.com/ffuf/ffuf/v2@v2.2.1 && \
    go install github.com/sensepost/gowitness@v0.0.0-20260422172756-4f562901bc23 && \
    go install github.com/d3mondev/puredns/v2@v2.1.1 && \
    go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@v1.2.1 && \
    go install github.com/lc/gau/v2/cmd/gau@v2.2.4 && \
    go install github.com/projectdiscovery/katana/cmd/katana@v1.6.1
ARG TRUFFLEHOG_VERSION=3.96.0
RUN curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog
COPY requirements.txt /app/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m venv /opt/venv && /opt/venv/bin/pip install -r /app/requirements.txt
ENV PATH=/opt/venv/bin:/root/go/bin:$PATH
COPY wordlists /app/wordlists
COPY app /app/app
CMD ["celery", "-A", "app.tasks.celery_app", "worker", "--loglevel=INFO", "--concurrency=2"]
