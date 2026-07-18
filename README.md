# Bug Bounty Recon Webapp

Self-hosted Dockerized recon dashboard for subdomain enumeration, live host probing, FFUF content discovery, screenshots, raw-output review, exports, and diffable scan history.

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

## Persisted data

Docker volumes/bind mounts persist data across restarts:

- SQLite DB: `recon-data:/data/recon.db`
- Wordlists: `./wordlists -> /data/wordlists`
- Screenshots: `./screenshots -> /data/screenshots`
- Raw tool output: `./raw-output -> /data/raw`

## Recon tools included in backend/worker image

The backend image installs: `subfinder`, `amass`, `httpx`, `ffuf`, `gowitness`, `puredns`, `massdns`, and `shuffledns`.

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
