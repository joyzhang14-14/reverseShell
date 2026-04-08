"""
Federated learning coordinator (FastAPI): heartbeats, task assignment, chunked uploads, aggregate hook.
Consent-only deployment; protect with FL_API_TOKEN and TLS in production.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from pydantic import BaseModel, Field

APP = FastAPI(title="FL Coordinator", version="0.1")

DATA_DIR = Path(os.environ.get("FL_DATA_DIR", "./fl_data"))
DB_PATH = DATA_DIR / "coordinator.db"
ARTIFACT_DIR = DATA_DIR / "artifacts"

_lock = threading.Lock()


def verify_bearer(authorization: Optional[str] = Header(None)) -> None:
    expected = os.environ.get("FL_API_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="FL_API_TOKEN not configured on server")
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    if authorization[7:] != expected:
        raise HTTPException(status_code=403, detail="invalid token")


@contextmanager
def db() -> Any:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_schema() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS workers (
                worker_id TEXT PRIMARY KEY,
                hostname TEXT,
                resources_json TEXT,
                labels_json TEXT,
                last_seen REAL
            );
            CREATE TABLE IF NOT EXISTS task_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                worker_id TEXT,
                round_id INTEGER,
                task_id TEXT,
                status TEXT,
                stderr_tail TEXT,
                exit_code INTEGER,
                ts REAL
            );
            CREATE TABLE IF NOT EXISTS kv (
                k TEXT PRIMARY KEY,
                v TEXT
            );
            CREATE TABLE IF NOT EXISTS chunk_registry (
                round_id INTEGER,
                worker_id TEXT,
                file_name TEXT,
                chunk_index INTEGER,
                total_chunks INTEGER,
                expected_sha256 TEXT,
                file_size INTEGER,
                PRIMARY KEY (round_id, worker_id, file_name, chunk_index)
            );
            """
        )


def kv_get(conn: sqlite3.Connection, key: str, default: str) -> str:
    row = conn.execute("SELECT v FROM kv WHERE k = ?", (key,)).fetchone()
    return row["v"] if row else default


def kv_set(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", (key, value))


DEFAULT_TASK = {
    "command": ["python3", "-c", "print('fl_worker_ok')"],
    "max_retries": 2,
    "timeout_sec": 120,
    "artifact_dir": None,
}


def ensure_defaults(conn: sqlite3.Connection) -> None:
    if not conn.execute("SELECT 1 FROM kv WHERE k = 'current_round_id'").fetchone():
        kv_set(conn, "current_round_id", "1")
    if not conn.execute("SELECT 1 FROM kv WHERE k = 'current_task_spec'").fetchone():
        kv_set(conn, "current_task_spec", json.dumps(DEFAULT_TASK))
    if not conn.execute("SELECT 1 FROM kv WHERE k = 'current_task_id'").fetchone():
        kv_set(conn, "current_task_id", "default")


class HeartbeatIn(BaseModel):
    worker_id: Optional[str] = None
    hostname: str = ""
    resources: Dict[str, Any] = Field(default_factory=dict)
    labels: Dict[str, Any] = Field(default_factory=dict)


class HeartbeatOut(BaseModel):
    worker_id: str
    round_id: int
    task_id: str
    task: Optional[Dict[str, Any]] = None


class TaskResultIn(BaseModel):
    worker_id: str
    round_id: int
    task_id: str
    status: str
    stderr_tail: str = ""
    exit_code: Optional[int] = None


@APP.on_event("startup")
def _startup() -> None:
    init_schema()
    with db() as conn:
        ensure_defaults(conn)


@APP.post("/api/v1/heartbeat", response_model=HeartbeatOut)
def heartbeat(body: HeartbeatIn, _: None = Depends(verify_bearer)) -> HeartbeatOut:
    import time

    now = time.time()
    wid = body.worker_id or str(uuid.uuid4())
    with db() as conn:
        ensure_defaults(conn)
        conn.execute(
            """
            INSERT INTO workers (worker_id, hostname, resources_json, labels_json, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(worker_id) DO UPDATE SET
                hostname = excluded.hostname,
                resources_json = excluded.resources_json,
                labels_json = excluded.labels_json,
                last_seen = excluded.last_seen
            """,
            (
                wid,
                body.hostname,
                json.dumps(body.resources),
                json.dumps(body.labels),
                now,
            ),
        )
        round_id = int(kv_get(conn, "current_round_id", "1"))
        task_raw = kv_get(conn, "current_task_spec", json.dumps(DEFAULT_TASK))
        task_id = kv_get(conn, "current_task_id", "default")
        task = json.loads(task_raw)
    return HeartbeatOut(worker_id=wid, round_id=round_id, task_id=task_id, task=task)


@APP.post("/api/v1/task_result")
def task_result(body: TaskResultIn, _: None = Depends(verify_bearer)) -> Dict[str, str]:
    import time

    with db() as conn:
        conn.execute(
            """
            INSERT INTO task_results (worker_id, round_id, task_id, status, stderr_tail, exit_code, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                body.worker_id,
                body.round_id,
                body.task_id,
                body.status,
                body.stderr_tail,
                body.exit_code,
                time.time(),
            ),
        )
    return {"status": "ok"}


def _chunk_path(round_id: int, worker_id: str, file_name: str, idx: int) -> Path:
    d = ARTIFACT_DIR / str(round_id) / worker_id / file_name
    d.mkdir(parents=True, exist_ok=True)
    return d / f".part.{idx:06d}"


def _try_finalize_upload(round_id: int, worker_id: str, file_name: str, meta: Dict[str, Any]) -> None:
    total = int(meta["total_chunks"])
    digest = meta["sha256"]
    base = ARTIFACT_DIR / str(round_id) / worker_id
    parts_dir = base / file_name
    if not parts_dir.is_dir():
        return
    found = sorted(parts_dir.glob(".part.*"))
    if len(found) < total:
        return
    out_path = base / f"merged_{file_name}"
    h = hashlib.sha256()
    with open(out_path, "wb") as out:
        for p in found:
            with open(p, "rb") as pc:
                b = pc.read()
                out.write(b)
                h.update(b)
    if h.hexdigest() != digest:
        out_path.unlink(missing_ok=True)
        raise ValueError(f"sha256 mismatch for {file_name}")
    for p in found:
        p.unlink(missing_ok=True)
    try:
        parts_dir.rmdir()
    except OSError:
        pass


@APP.post("/api/v1/rounds/{round_id}/upload")
async def upload_chunk(
    round_id: int,
    meta: str = Form(...),
    chunk: UploadFile = File(...),
    _: None = Depends(verify_bearer),
) -> Dict[str, Any]:
    data = json.loads(meta)
    worker_id = data["worker_id"]
    file_name = data["file_name"]
    idx = int(data["chunk_index"])
    total = int(data["total_chunks"])
    expected_sha = data["sha256"]
    file_size = int(data.get("file_size", -1))
    raw = await chunk.read()
    path = _chunk_path(round_id, worker_id, file_name, idx)
    with _lock:
        path.write_bytes(raw)
        with db() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO chunk_registry
                (round_id, worker_id, file_name, chunk_index, total_chunks, expected_sha256, file_size)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (round_id, worker_id, file_name, idx, total, expected_sha, file_size),
            )
        try:
            _try_finalize_upload(
                round_id,
                worker_id,
                file_name,
                {"total_chunks": total, "sha256": expected_sha},
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
    return {"status": "accepted", "chunk_index": idx}


@APP.post("/api/v1/rounds/{round_id}/aggregate")
def aggregate(
    round_id: int,
    _: None = Depends(verify_bearer),
) -> Dict[str, Any]:
    """MVP: list merged artifacts; real FedAvg would load tensors here."""
    base = ARTIFACT_DIR / str(round_id)
    merged: List[str] = []
    if base.is_dir():
        for p in base.rglob("merged_*"):
            if p.is_file():
                merged.append(str(p))
    return {"round_id": round_id, "merged_files": merged, "note": "placeholder aggregation"}


@APP.get("/api/v1/workers")
def list_workers(_: None = Depends(verify_bearer)) -> List[Dict[str, Any]]:
    import time

    with db() as conn:
        rows = conn.execute("SELECT * FROM workers ORDER BY last_seen DESC").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["resources"] = json.loads(d.pop("resources_json") or "{}")
        d["labels"] = json.loads(d.pop("labels_json") or "{}")
        d["last_seen_age_sec"] = time.time() - (d["last_seen"] or 0)
        out.append(d)
    return out


@APP.post("/api/v1/admin/task")
def admin_set_task(
    payload: Dict[str, Any],
    _: None = Depends(verify_bearer),
) -> Dict[str, str]:
    spec = payload.get("task_spec")
    task_id = payload.get("task_id", "default")
    round_id = payload.get("round_id")
    if spec is None:
        raise HTTPException(400, "task_spec required")
    with db() as conn:
        kv_set(conn, "current_task_spec", json.dumps(spec))
        kv_set(conn, "current_task_id", str(task_id))
        if round_id is not None:
            kv_set(conn, "current_round_id", str(int(round_id)))
    return {"status": "ok"}


# Uvicorn: uvicorn fl_coordinator:APP --reload --host 0.0.0.0 --port 8000
