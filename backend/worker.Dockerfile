# syntax=docker/dockerfile:1.7
FROM golang:1.26-bookworm AS tools-builder
ARG NUCLEI_VERSION=v3.11.0
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git build-essential libpcap-dev && \
    rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.9.0 && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.5 && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.7.2 && \
    go install github.com/ffuf/ffuf/v2@v2.2.1 && \
    go install github.com/sensepost/gowitness@v0.0.0-20260422172756-4f562901bc23 && \
    go install github.com/d3mondev/puredns/v2@v2.1.1 && \
    go install github.com/lc/gau/v2/cmd/gau@v2.2.4 && \
    go install github.com/projectdiscovery/katana/cmd/katana@v1.6.1 && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} && \
    go install github.com/hahwul/dalfox/v2@latest

FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive PATH=/usr/local/bin:$PATH RECON_DATA_DIR=/data
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv ca-certificates curl git libpcap0.8 \
    chromium xvfb amass dnsutils && \
    rm -rf /var/lib/apt/lists/*
COPY --from=tools-builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=tools-builder /go/bin/naabu /usr/local/bin/naabu
COPY --from=tools-builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=tools-builder /go/bin/ffuf /usr/local/bin/ffuf
COPY --from=tools-builder /go/bin/gowitness /usr/local/bin/gowitness
COPY --from=tools-builder /go/bin/puredns /usr/local/bin/puredns
COPY --from=tools-builder /go/bin/gau /usr/local/bin/gau
COPY --from=tools-builder /go/bin/katana /usr/local/bin/katana
COPY --from=tools-builder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools-builder /go/bin/dalfox /usr/local/bin/dalfox
ARG TRUFFLEHOG_VERSION=3.96.0
RUN curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog
COPY requirements.txt /app/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m venv /opt/venv && /opt/venv/bin/pip install -r /app/requirements.txt
ENV PATH=/usr/local/bin:/opt/venv/bin:$PATH
COPY wordlists /app/wordlists
COPY app /app/app
COPY worker-entrypoint.sh /usr/local/bin/worker-entrypoint.sh
RUN chmod +x /usr/local/bin/worker-entrypoint.sh
ENTRYPOINT ["worker-entrypoint.sh"]
CMD ["celery", "-A", "app.tasks.celery_app", "worker", "--loglevel=INFO", "--concurrency=2"]
