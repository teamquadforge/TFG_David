import json
import os
import socket
import time
from datetime import datetime, timezone

import requests

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000").rstrip("/")
AGENT_TOKEN = os.getenv("WINDOWS_AGENT_TOKEN", os.getenv("AGENT_TOKEN", "dev-windows-agent-token"))
SYSLOG_HOST = os.getenv("SYSLOG_HOST", "0.0.0.0")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "5514"))
SOURCE_NAME = os.getenv("SOURCE_NAME", "router-syslog")


def post_log(raw: str, remote_ip: str):
    body = {
        "raw_log": raw,
        "remote_ip": remote_ip,
        "source_name": SOURCE_NAME,
        "transport": "udp_syslog",
        "received_at": datetime.now(timezone.utc).isoformat(),
        "metadata": {"collector": "network_collector_v15"},
    }
    r = requests.post(
        BACKEND_URL + "/ingest-network",
        headers={"X-Agent-Token": AGENT_TOKEN, "Content-Type": "application/json"},
        data=json.dumps(body),
        timeout=8,
    )
    r.raise_for_status()


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SYSLOG_HOST, SYSLOG_PORT))
    print(f"MiniSIEM network collector listening on UDP {SYSLOG_HOST}:{SYSLOG_PORT} -> {BACKEND_URL}", flush=True)
    while True:
        data, addr = sock.recvfrom(65535)
        raw = data.decode("utf-8", errors="replace").strip()
        try:
            post_log(raw, addr[0])
        except Exception as exc:
            print(f"failed to forward syslog from {addr[0]}: {exc}", flush=True)
            time.sleep(1)


if __name__ == "__main__":
    main()
