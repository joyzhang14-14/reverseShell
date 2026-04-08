"""
Federated learning worker (consented nodes only).
Reports resources, pulls tasks from coordinator, runs local step, uploads artifacts in chunks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore


def _default_worker_id_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".fl_worker_id")


class ResourceMonitor:
    """Collect GPU (nvidia-smi), CPU, and memory; return JSON-serializable dict."""

    def collect_gpu(self) -> List[Dict[str, Any]]:
        gpus: List[Dict[str, Any]] = []
        try:
            proc = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=index,name,memory.total,memory.used,utilization.gpu,temperature.gpu",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode != 0:
                return gpus
            for line in proc.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 6:
                    continue
                gpus.append(
                    {
                        "index": int(parts[0]) if parts[0].isdigit() else parts[0],
                        "name": parts[1],
                        "memory_total_mib": parts[2],
                        "memory_used_mib": parts[3],
                        "utilization_pct": parts[4],
                        "temperature_c": parts[5],
                    }
                )
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
            pass
        return gpus

    def collect_cpu_memory(self) -> Dict[str, Any]:
        if psutil:
            try:
                vm = psutil.virtual_memory()
                return {
                    "cpu_logical_cores": psutil.cpu_count(logical=True),
                    "cpu_physical_cores": psutil.cpu_count(logical=False),
                    "memory_total_bytes": vm.total,
                    "memory_available_bytes": vm.available,
                    "memory_percent": vm.percent,
                }
            except (SystemError, OSError, RuntimeError):
                pass
        out: Dict[str, Any] = {"cpu_logical_cores": None, "memory_total_bytes": None}
        try:
            if sys.platform == "darwin":
                r = subprocess.run(["sysctl", "-n", "hw.logicalcpu", "hw.memsize"], capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    lines = r.stdout.strip().split("\n")
                    if len(lines) >= 2:
                        out["cpu_logical_cores"] = int(lines[0].strip())
                        out["memory_total_bytes"] = int(lines[1].strip())
            elif sys.platform.startswith("linux"):
                r = subprocess.run(["nproc"], capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    out["cpu_logical_cores"] = int(r.stdout.strip())
                with open("/proc/meminfo", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            parts = line.split()
                            out["memory_total_bytes"] = int(parts[1]) * 1024
                            break
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError, OSError):
            pass
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": socket.gethostname(),
            "gpu": self.collect_gpu(),
            "cpu_memory": self.collect_cpu_memory(),
            "platform": sys.platform,
        }


@dataclass
class HttpClient:
    base_url: str
    api_token: str
    verify_ssl: bool = True
    timeout: int = 120

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def post_json(self, path: str, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        url = self.base_url.rstrip("/") + path
        data = json.dumps(body).encode("utf-8")
        ctx = None
        if url.lower().startswith("https"):
            import ssl

            ctx = ssl.create_default_context()
            if not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
        req = Request(url, data=data, headers=self._headers(), method="POST")
        try:
            with urlopen(req, timeout=self.timeout, context=ctx) as resp:
                raw = resp.read().decode("utf-8")
                return resp.status, json.loads(raw) if raw else {}
        except HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            try:
                return e.code, json.loads(err_body)
            except json.JSONDecodeError:
                return e.code, {"detail": err_body}
        except URLError as e:
            raise RuntimeError(str(e.reason)) from e


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


@dataclass
class FLWorker:
    coordinator_base_url: str
    api_token: str
    verify_ssl: bool = True
    worker_id_path: str = field(default_factory=_default_worker_id_path)
    allowed_image_prefixes: Tuple[str, ...] = ("registry.example.com/fl/", "docker.io/library/")
    chunk_size: int = 512 * 1024
    monitor: ResourceMonitor = field(default_factory=ResourceMonitor)

    def __post_init__(self) -> None:
        self._http = HttpClient(self.coordinator_base_url, self.api_token, self.verify_ssl)

    def _load_or_create_worker_id(self) -> str:
        if os.path.isfile(self.worker_id_path):
            with open(self.worker_id_path, encoding="utf-8") as f:
                wid = f.read().strip()
                if wid:
                    return wid
        wid = str(uuid.uuid4())
        with open(self.worker_id_path, "w", encoding="utf-8") as f:
            f.write(wid)
        os.chmod(self.worker_id_path, 0o600)
        return wid

    def heartbeat(self, labels: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        resources = self.monitor.to_dict()
        body: Dict[str, Any] = {
            "worker_id": self._load_or_create_worker_id(),
            "hostname": resources.get("hostname", ""),
            "resources": resources,
            "labels": labels or {},
        }
        code, data = self._http.post_json("/api/v1/heartbeat", body)
        if code != 200:
            raise RuntimeError(f"heartbeat failed: {code} {data}")
        if data.get("worker_id"):
            with open(self.worker_id_path, "w", encoding="utf-8") as f:
                f.write(data["worker_id"])
            os.chmod(self.worker_id_path, 0o600)
        return data

    def report_task_result(
        self,
        worker_id: str,
        round_id: int,
        task_id: str,
        status: str,
        stderr_tail: str = "",
        exit_code: Optional[int] = None,
    ) -> None:
        body = {
            "worker_id": worker_id,
            "round_id": round_id,
            "task_id": task_id,
            "status": status,
            "stderr_tail": stderr_tail[-8000:],
            "exit_code": exit_code,
        }
        code, data = self._http.post_json("/api/v1/task_result", body)
        if code != 200:
            raise RuntimeError(f"task_result failed: {code} {data}")

    def upload_artifact(
        self,
        file_path: str,
        round_id: int,
        worker_id: str,
    ) -> None:
        import requests

        file_size = os.path.getsize(file_path)
        digest = _file_sha256(file_path)
        url = self.coordinator_base_url.rstrip("/") + f"/api/v1/rounds/{round_id}/upload"
        headers = {"Authorization": f"Bearer {self.api_token}"}
        verify = self.verify_ssl
        parts: List[bytes] = []
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                parts.append(chunk)
        if not parts:
            parts = [b""]
        total = len(parts)
        for index, chunk in enumerate(parts):
            meta = {
                "worker_id": worker_id,
                "file_name": os.path.basename(file_path),
                "sha256": digest,
                "total_chunks": total,
                "chunk_index": index,
                "file_size": file_size,
            }
            files = {"chunk": (f"part_{index}", chunk)}
            data = {"meta": json.dumps(meta)}
            r = requests.post(url, headers=headers, data=data, files=files, timeout=self._http.timeout, verify=verify)
            if r.status_code not in (200, 202):
                raise RuntimeError(f"upload chunk {index} failed: {r.status_code} {r.text}")

    def _docker_allowed(self, image: str) -> bool:
        return any(image.startswith(p) for p in self.allowed_image_prefixes)

    def execute_local_step(
        self,
        task_spec: Dict[str, Any],
        workdir: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        timeout = int(task_spec.get("timeout_sec", 3600))
        docker_image = task_spec.get("docker_image")
        if docker_image:
            if not self._docker_allowed(docker_image):
                raise ValueError(f"docker image not allowed: {docker_image}")
            cmd_args = task_spec.get("command") or []
            if not isinstance(cmd_args, list):
                raise ValueError("task_spec.command must be a list of strings")
            inner = " ".join(shlex.quote(a) for a in cmd_args)
            cmd = ["docker", "run", "--rm", docker_image, "sh", "-c", inner]
        else:
            cmd = task_spec.get("command")
            if not isinstance(cmd, list) or not all(isinstance(x, str) for x in cmd):
                raise ValueError("task_spec.command must be a list of strings")
        return subprocess.run(
            cmd,
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=timeout,
        )


def run_pipeline(
    worker: FLWorker,
    labels: Optional[Dict[str, Any]] = None,
    artifact_paths: Optional[List[str]] = None,
) -> None:
    hb = worker.heartbeat(labels=labels)
    worker_id = hb["worker_id"]
    round_id = int(hb["round_id"])
    task = hb.get("task")
    task_id = str(hb.get("task_id", "default"))
    if not task:
        print(json.dumps({"msg": "no task assigned", "heartbeat": hb}, indent=2))
        return
    max_retries = int(task.get("max_retries", 2))
    workdir = task.get("workdir")
    if workdir:
        os.makedirs(workdir, exist_ok=True)
    delay = 1.0
    last_stderr = ""
    last_code: Optional[int] = None
    for attempt in range(max_retries + 1):
        try:
            proc = worker.execute_local_step(task, workdir=workdir)
        except Exception as e:
            last_stderr = str(e)
            worker.report_task_result(worker_id, round_id, task_id, "failed", stderr_tail=last_stderr, exit_code=-1)
            raise
        last_stderr = (proc.stderr or "") + (proc.stdout or "")
        last_code = proc.returncode
        if proc.returncode == 0:
            worker.report_task_result(worker_id, round_id, task_id, "ok", stderr_tail="", exit_code=0)
            break
        if attempt >= max_retries:
            worker.report_task_result(
                worker_id, round_id, task_id, "failed", stderr_tail=last_stderr, exit_code=proc.returncode
            )
            raise RuntimeError(f"task failed after retries: exit={proc.returncode}")
        time.sleep(delay)
        delay = min(delay * 2, 60.0)
    paths = artifact_paths or []
    out_dir = task.get("artifact_dir")
    if out_dir and os.path.isdir(out_dir):
        for name in os.listdir(out_dir):
            p = os.path.join(out_dir, name)
            if os.path.isfile(p):
                paths.append(p)
    for p in paths:
        if os.path.isfile(p):
            worker.upload_artifact(p, round_id, worker_id)
            print(f"uploaded {p}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="FL worker (consented nodes)")
    parser.add_argument("--coordinator", required=True, help="Base URL, e.g. http://127.0.0.1:8000")
    parser.add_argument("--token", default=os.environ.get("FL_API_TOKEN", ""), help="Bearer token (or set FL_API_TOKEN)")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verify for HTTPS")
    parser.add_argument("--dump-resources", action="store_true", help="Print ResourceMonitor JSON and exit")
    parser.add_argument("--artifact", action="append", default=[], help="Extra file to upload after task")
    args = parser.parse_args()
    if args.dump_resources:
        print(json.dumps(ResourceMonitor().to_dict(), indent=2))
        return
    if not args.token:
        print("FL_API_TOKEN or --token required", file=sys.stderr)
        sys.exit(1)
    w = FLWorker(
        coordinator_base_url=args.coordinator,
        api_token=args.token,
        verify_ssl=not args.insecure,
    )
    run_pipeline(w, artifact_paths=list(args.artifact))


if __name__ == "__main__":
    main()