# Bug Bounty Recon Webapp

Self-hosted Dockerized recon dashboard for subdomain enumeration, live host probing, FFUF content discovery, screenshots, raw-output review, exports, and diffable scan history.

The dashboard also includes an optional localhost-oriented **Live Container Logs** viewer at `/logs` for Docker Compose service logs.

## Documentation

- **User guide:** [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) — how to configure, run, review, export, rerun stages, use Burp/proxy settings, and troubleshoot the app.
- This README is only the quick start and project overview.

## Run

```bash
docker compose up -d --build
```

Open the UI at http://localhost:3001 and the API at http://localhost:8000.

Port notes: Redis is internal-only. The frontend maps to host port `3001` to avoid common local conflicts on `3000`.

## Services

- `backend`: FastAPI API and SQLite persistence
- `worker`: Celery worker that executes recon stages without blocking the UI
- `redis`: Celery broker/result backend
- `frontend`: React dashboard served by nginx


## Live Docker logs viewer

The dashboard header includes **▣ View Logs**, which opens `/logs` in a new browser tab. This page streams infrastructure/container logs for the approved Docker Compose services only:

- `backend` / API
- `worker` / Celery Worker
- `frontend`
- `redis`

The frontend and backend are served from the same origin in Docker: nginx serves the React app and proxies `/api/` to the FastAPI backend, so `/logs` loads the same single-page app and calls `/api/system/logs/*`.

### Enablement and security

This project currently has no authentication layer. Container logs can contain sensitive operational data, request headers, tokens, and credentials. Do **not** expose the log viewer publicly without authentication and authorization.

The Docker Compose development configuration enables the viewer explicitly and mounts the Docker socket read-only into the API container:

```yaml
/var/run/docker.sock:/var/run/docker.sock:ro
```

Important: a read-only Docker socket is still powerful. The backend therefore does **not** expose generic Docker operations, does **not** run Docker shell commands, and only maps client selections to the configured service allowlist.

Environment variables:

```env
ENABLE_DOCKER_LOG_VIEWER=true
DOCKER_LOG_TAIL=200
DOCKER_LOG_MAX_TAIL=2000
DOCKER_LOG_BUFFER_LIMIT=10000
DOCKER_LOG_ALLOWED_SERVICES=backend,worker,frontend,redis
DOCKER_LOG_REDACTION=true
```

Set `ENABLE_DOCKER_LOG_VIEWER=false` to make log APIs return `403`.

### Features

- Server-Sent Events stream at `/api/system/logs/stream?container=all&tail=200`
- service list at `/api/system/logs/containers`
- All containers or one approved service
- recent tail history plus live follow
- heartbeat events
- reconnect UI with exponential backoff
- pause/resume, clear local screen, auto-scroll, jump to latest
- search/filter and log level filter
- copy visible logs and download buffered logs
- server-side redaction for likely authorization headers, bearer tokens, cookies, passwords, database URLs, proxy credentials, JWTs, and common secret assignments
- frontend buffer limit around 10,000 lines; rendered view is capped to keep the browser responsive

### Log rotation

`docker-compose.yml` configures json-file log rotation for Compose services:

```yaml
logging:
  driver: json-file
  options:
    max-size: "10m"
    max-file: "3"
```

### Troubleshooting

- `403 Docker log viewer is disabled`: set `ENABLE_DOCKER_LOG_VIEWER=true` and recreate the backend container.
- `Docker logs are unavailable because the API cannot access the Docker daemon`: confirm the Docker socket mount exists and Docker Desktop/daemon is running.
- a service shows `missing`: the approved service name exists in the allowlist but no Compose container with label `com.docker.compose.service=<name>` is currently present.
- no live updates: use **Reconnect**, check backend logs, and confirm `/api/system/logs/containers` returns running services.

## Persisted data

Docker volumes/bind mounts persist data across restarts:

- SQLite DB: `recon-data:/data/recon.db`
- Wordlists: `./wordlists -> /data/wordlists`
- Screenshots: `./screenshots -> /data/screenshots`
- Raw tool output: `./raw-output -> /data/raw`

## Recon tools included in backend/worker image

The backend image installs: `subfinder`, `amass`, `httpx`, `ffuf`, `gowitness`, `puredns`, `massdns`, and `shuffledns`.

## Default FFUF wordlist

FFUF uses the selected uploaded dirb wordlist first. If no dirb wordlist is selected, the backend resolves a default wordlist in this order:

1. `DEFAULT_FFUF_WORDLIST`
2. bundled `/app/wordlists/default/common.txt`

Default environment value:

```env
DEFAULT_FFUF_WORDLIST=/usr/share/seclists/Discovery/Web-Content/common.txt
```

The backend/worker Docker image installs SecLists so `/usr/share/seclists/Discovery/Web-Content/common.txt` is available in both containers. If neither the configured default nor bundled fallback exists, FFUF scans are rejected with a clear validation error instead of being silently skipped.

FFUF also runs with automatic calibration (`-ac`) and a per-host wildcard baseline. Before each host fuzz, the worker probes random non-existent paths and records status, size, word count, line count, and a body hash in raw logs. Repeated wildcard responses are used as dynamic `-fs`/`-fw`/`-fl` filters and matching results are stored as `filtered` instead of counted as high-confidence content.

Rebuild after changing Docker defaults:

```bash
docker compose build backend worker
docker compose up -d --no-build --force-recreate backend worker frontend
```

## Workflow

See [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) for the full operating guide. Short version:

1. Upload/select subdomain and directory wordlists.
2. Configure User-Agent, arbitrary headers, and proxy in Settings.
3. Enter a domain and click **Run Recon**.
4. Review tabs: Subdomains, Live Hosts, Directories, Screenshots, Raw Output.
5. Export JSON/CSV from a target view.

## Verification commands

```bash
python -m pytest backend/tests -q
npm --prefix frontend run build
docker compose config
docker compose build
curl http://localhost:8000/api/health
```
