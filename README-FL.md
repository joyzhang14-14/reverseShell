# Federated learning coordinator & worker (consent-only)

Use only on machines and networks where participants have agreed to take part.

## Dependencies

```bash
pip install -r requirements-fl.txt
```

## Coordinator

Set a shared secret and optional data directory:

```bash
export FL_API_TOKEN='change-me-long-random'
export FL_DATA_DIR=./fl_data   # optional
uvicorn fl_coordinator:APP --host 127.0.0.1 --port 8000
```

- `POST /api/v1/heartbeat` — worker registration + resource payload; response includes `task`, `round_id`, `task_id`.
- `POST /api/v1/task_result` — report `ok` / `failed` and stderr tail.
- `POST /api/v1/rounds/{round_id}/upload` — multipart chunk upload (`meta` JSON + `chunk` file).
- `POST /api/v1/rounds/{round_id}/aggregate` — MVP: lists merged files under `artifacts/`.
- `GET /api/v1/workers` — worker pool snapshot.
- `POST /api/v1/admin/task` — JSON body `{"task_spec": {...}, "task_id": "...", "round_id": 2}` to change the active task.

Use HTTPS and reverse-proxy auth in production.

## Worker

```bash
export FL_API_TOKEN='same-as-coordinator'
python3 fl_worker.py --coordinator http://127.0.0.1:8000 --token "$FL_API_TOKEN"
```

Options:

- `--insecure` — skip TLS certificate verification (HTTPS labs only).
- `--dump-resources` — print `ResourceMonitor` JSON and exit.
- `--artifact /path/to/file` — extra files to upload after a successful task (repeatable).

## Docker images (worker)

`FLWorker.allowed_image_prefixes` defaults to lab-friendly prefixes. Override in code or extend CLI if you need additional registries.

## Labs

Pair with a local HTTP coordinator (no TLS) for development; enable TLS for any shared network.
