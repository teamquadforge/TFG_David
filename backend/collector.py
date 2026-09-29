import os
import subprocess
import sys
import time
from pathlib import Path
from threading import Thread
from typing import Dict, Iterable, Optional

import requests

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000").rstrip("/")
LOG_SOURCES = [s.strip() for s in os.getenv("LOG_SOURCES", "host_auth,docker,vulnerable_demo_file").split(",") if s.strip()]
HOST_AUTH_LOG = os.getenv("HOST_AUTH_LOG", "/host/var/log/auth.log")
HOST_SYSLOG = os.getenv("HOST_SYSLOG", "/host/var/log/syslog")
DEMO_FILE = os.getenv("DEMO_FILE", "/app/logs.txt")
DOCKER_CONTAINER_NAME = os.getenv("DOCKER_CONTAINER_NAME", "mini_siem_vulnerable")


def post_log(line: str, source_type: str, source_name: Optional[str] = None, metadata: Optional[Dict] = None):
    line = line.strip()
    if not line:
        return
    try:
        res = requests.post(
            f"{BACKEND_URL}/ingest-log",
            json={"log": line, "source_type": source_type, "source_name": source_name, "metadata": metadata or {}},
            timeout=4,
        )
        if res.status_code >= 300:
            print(f"[collector] backend returned {res.status_code}: {res.text[:200]}", flush=True)
        else:
            print(f"[collector] sent {source_type}/{source_name}: {line[:120]}", flush=True)
    except Exception as exc:
        print(f"[collector] send error: {exc}", flush=True)


def wait_backend():
    while True:
        try:
            requests.get(f"{BACKEND_URL}/health", timeout=3)
            print("[collector] backend ready", flush=True)
            return
        except Exception as exc:
            print(f"[collector] waiting backend: {exc}", flush=True)
            time.sleep(2)


def tail_file(path: str, source_name: str, source_type: str = "host"):
    p = Path(path)
    if not p.exists():
        print(f"[collector] file not found, skipping: {path}", flush=True)
        return
    print(f"[collector] tailing {path}", flush=True)
    with p.open("r", errors="ignore") as fh:
        fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if not line:
                time.sleep(0.5)
                continue
            post_log(line, source_type=source_type, source_name=source_name, metadata={"path": path})


def replay_demo_file(path: str):
    p = Path(path)
    if not p.exists():
        print(f"[collector] demo file not found: {path}", flush=True)
        return
    print(f"[collector] replaying demo file once: {path}", flush=True)
    for line in p.read_text(errors="ignore").splitlines():
        post_log(line, source_type="demo", source_name="logs.txt", metadata={"path": path})
        time.sleep(0.5)


def docker_logs_sdk(container_name: str):
    try:
        import docker
    except Exception as exc:
        print(f"[collector] docker SDK unavailable: {exc}", flush=True)
        return

    while True:
        try:
            client = docker.from_env()
            containers = client.containers.list(all=True)
            target = None
            for c in containers:
                if container_name in c.name:
                    target = c
                    break
            if not target:
                print(f"[collector] docker container not found containing name '{container_name}', retrying...", flush=True)
                time.sleep(5)
                continue
            print(f"[collector] streaming docker logs from {target.name}", flush=True)
            for raw in target.logs(stream=True, follow=True, tail=0):
                line = raw.decode("utf-8", errors="ignore").strip()
                post_log(line, source_type="docker", source_name=target.name, metadata={"container_name": target.name})
        except Exception as exc:
            print(f"[collector] docker log error: {exc}", flush=True)
            time.sleep(5)


def journalctl_unit(unit: str):
    print(f"[collector] starting journalctl for {unit}", flush=True)
    process = subprocess.Popen(["journalctl", "-u", unit, "-f", "-n", "0"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert process.stdout is not None
    for line in process.stdout:
        post_log(line, source_type="journal", source_name=unit, metadata={"unit": unit})


def start_thread(fn, *args):
    t = Thread(target=fn, args=args, daemon=True)
    t.start()
    return t


def main():
    print(f"[collector] Mini-SIEM collector starting. BACKEND_URL={BACKEND_URL} LOG_SOURCES={LOG_SOURCES}", flush=True)
    wait_backend()
    threads = []

    if "host_auth" in LOG_SOURCES:
        threads.append(start_thread(tail_file, HOST_AUTH_LOG, "auth.log", "host"))
    if "host_syslog" in LOG_SOURCES:
        threads.append(start_thread(tail_file, HOST_SYSLOG, "syslog", "host"))
    if "docker" in LOG_SOURCES:
        threads.append(start_thread(docker_logs_sdk, DOCKER_CONTAINER_NAME))
    if "journal_ssh" in LOG_SOURCES:
        threads.append(start_thread(journalctl_unit, "ssh"))
    if "vulnerable_demo_file" in LOG_SOURCES:
        threads.append(start_thread(replay_demo_file, DEMO_FILE))

    if not threads:
        print("[collector] no enabled sources. Set LOG_SOURCES.", flush=True)
        sys.exit(1)

    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()
