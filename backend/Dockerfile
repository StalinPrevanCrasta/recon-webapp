# syntax=docker/dockerfile:1.7
FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive RECON_DATA_DIR=/data DEFAULT_FFUF_WORDLIST=/app/wordlists/default/common.txt
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*
COPY requirements.txt /app/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m venv /opt/venv && /opt/venv/bin/pip install -r /app/requirements.txt
ENV PATH=/opt/venv/bin:$PATH
COPY wordlists /app/wordlists
COPY app /app/app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
