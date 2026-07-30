# syntax=docker/dockerfile:1.7
FROM golang:1.26-bookworm AS tools-builder
ENV GOPROXY=https://proxy.golang.org,direct
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/hahwul/dalfox/v2@latest

FROM python:3.13-slim-bookworm
ENV DEBIAN_FRONTEND=noninteractive RECON_DATA_DIR=/data DEFAULT_FFUF_WORDLIST=/app/wordlists/default/common.txt
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*
COPY requirements.txt /app/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m venv /opt/venv && /opt/venv/bin/pip install -r /app/requirements.txt
ENV PATH=/opt/venv/bin:$PATH
COPY --from=tools-builder /go/bin/dalfox /usr/local/bin/dalfox
COPY wordlists /app/wordlists
COPY app /app/app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
