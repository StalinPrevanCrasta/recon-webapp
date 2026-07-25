FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive PATH=/root/go/bin:/usr/local/go/bin:$PATH RECON_DATA_DIR=/data DEFAULT_FFUF_WORDLIST=/usr/share/seclists/Discovery/Web-Content/common.txt
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv ca-certificates curl git golang-go build-essential seclists \
    chromium xvfb amass massdns dnsutils && \
    rm -rf /var/lib/apt/lists/*
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/sensepost/gowitness@latest && \
    go install github.com/d3mondev/puredns/v2@latest && \
    go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
COPY requirements.txt /app/requirements.txt
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt
ENV PATH=/root/go/bin:/opt/venv/bin:$PATH
COPY wordlists /app/wordlists
COPY app /app/app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
