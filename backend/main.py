import ipaddress
import csv
import io
import json
import os
import re
import time
import unicodedata
import requests
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from fastapi import Depends, FastAPI, HTTPException, Query, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import StreamingResponse
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
DB_HOST = os.getenv("DB_HOST", "postgres")
DB_NAME = os.getenv("DB_NAME", "siem")
DB_USER = os.getenv("DB_USER", "siem")
DB_PASSWORD = os.getenv("DB_PASSWORD", "siem")
WINDOWS_AGENT_TOKEN = os.getenv("WINDOWS_AGENT_TOKEN", "dev-windows-agent-token")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
TELEGRAM_TIMEOUT_SECONDS = 8
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
THREAT_INTEL_ENABLED = os.getenv("THREAT_INTEL_ENABLED", "false").lower() in ("1", "true", "yes", "on")
THREAT_INTEL_TIMEOUT_SECONDS = int(os.getenv("THREAT_INTEL_TIMEOUT_SECONDS", "6"))


app = FastAPI(title="Mini-SIEM Sentinel v15", version="15.0")
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LogInput(BaseModel):
    log: str
    source_type: Optional[str] = "unknown"
    source_name: Optional[str] = None
    metadata: Dict[str, Any] = {}


class NLQueryInput(BaseModel):
    query: str
    limit: int = 100


class WatchlistInput(BaseModel):
    value: str
    ioc_type: str = "ip"
    label: str = ""
    severity: str = "high"


class AlertUpdateInput(BaseModel):
    status: str
    note: Optional[str] = None


class CaseInput(BaseModel):
    title: str
    description: str = ""
    severity: str = "medium"


class CaseUpdateInput(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None


class CaseAlertInput(BaseModel):
    alert_id: int


class RuleUpdateInput(BaseModel):
    enabled: bool


class WindowsEventInput(BaseModel):
    agent_id: str
    hostname: str
    os_version: Optional[str] = None
    log_name: str
    provider_name: Optional[str] = None
    event_id: int
    record_id: Optional[int] = None
    level: Optional[str] = None
    time_created: Optional[str] = None
    message: str = ""
    event_data: Dict[str, Any] = {}


class AgentHeartbeatInput(BaseModel):
    agent_id: str
    hostname: str
    os_type: str = "windows"
    os_version: Optional[str] = None
    version: str = "5.0"
    status: str = "online"
    metadata: Dict[str, Any] = {}


class NotificationSettingsInput(BaseModel):
    telegram_enabled: bool = False
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    telegram_min_severity: str = "critical"


class TelegramTestInput(BaseModel):
    message: str = "Prova Mini-SIEM Sentinel"


class EDRActionInput(BaseModel):
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    action_type: str
    target_path: Optional[str] = None
    target_hash: Optional[str] = None
    reason: str = ""
    alert_id: Optional[int] = None
    event_id: Optional[int] = None


class EDRActionResultInput(BaseModel):
    status: str
    result: str = ""
    quarantine_path: Optional[str] = None
    sha256: Optional[str] = None
    metadata: Dict[str, Any] = {}


class QuarantineRecordInput(BaseModel):
    agent_id: str
    hostname: str
    original_path: str
    quarantine_path: str
    sha256: Optional[str] = None
    reason: str = ""
    alert_id: Optional[int] = None
    event_id: Optional[int] = None
    status: str = "quarantined"
    metadata: Dict[str, Any] = {}



class AIChatInput(BaseModel):
    message: str
    page: str = "overview"
    alert_id: Optional[int] = None
    event_id: Optional[int] = None
    history: List[Dict[str, str]] = []

class AIPromptInput(BaseModel):
    question: str
    scope: str = "global"


class AIContextInput(BaseModel):
    question: str
    page: str = "overview"
    alert_id: Optional[int] = None
    event_id: Optional[int] = None



def connect_with_retry():
    while True:
        try:
            conn = psycopg2.connect(
                host=DB_HOST,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD,
            )
            conn.autocommit = False
            print("Connected to PostgreSQL")
            return conn
        except Exception as exc:
            print("Waiting for PostgreSQL...", exc)
            time.sleep(2)


conn = connect_with_retry()


def db_cursor():
    # Reconnect transparently if PostgreSQL restarted.
    global conn
    try:
        with conn.cursor() as c:
            c.execute("SELECT 1")
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        conn = connect_with_retry()
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def hash_password(password: str) -> str:
    return pwd_context.hash(password[:72])


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain[:72], hashed)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def audit(username: Optional[str], action: str, details: Dict[str, Any]):
    try:
        cur = db_cursor()
        cur.execute(
            "INSERT INTO audit_logs (username, action, details) VALUES (%s, %s, %s::jsonb)",
            (username, action, json.dumps(details)),
        )
        conn.commit()
    except Exception:
        conn.rollback()


def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    try:
        cur = db_cursor()
        cur.execute("SELECT value FROM settings WHERE key=%s", (key,))
        row = cur.fetchone()
        if row:
            return row["value"]
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
    return os.getenv(key.upper(), default)


def set_setting(key: str, value: str):
    cur = db_cursor()
    cur.execute(
        """
        INSERT INTO settings (key, value, updated_at) VALUES (%s,%s,NOW())
        ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()
        """,
        (key, value),
    )
    conn.commit()


def severity_at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get((severity or "info").lower(), 0) >= SEVERITY_ORDER.get((minimum or "critical").lower(), 4)


def mask_secret(value: Optional[str]) -> str:
    if not value:
        return ""
    if len(value) <= 12:
        return "********"
    return value[:6] + "…" + value[-4:]


def render_alert_notification(alert: Dict[str, Any]) -> str:
    rule = alert.get("rule_name") or "Alerta"
    severity = (alert.get("severity") or "unknown").upper()
    host = (alert.get("metadata") or {}).get("host") or alert.get("service") or "entorn monitoritzat"
    user = alert.get("user_name") or "-"
    ip = alert.get("src_ip") or "-"
    risk = alert.get("risk_score") or "-"
    mitre = alert.get("mitre_technique") or "-"
    description = (alert.get("description") or "")[:700]
    return (
        f"🚨 Mini-SIEM Sentinel · Alerta {severity}\n\n"
        f"Regla: {rule}\n"
        f"Host/servei: {host}\n"
        f"Usuari: {user}\n"
        f"IP: {ip}\n"
        f"Risc: {risk}/100\n"
        f"MITRE: {mitre}\n\n"
        f"Què ha passat?\n{description}\n\n"
        f"Acció recomanada: obre el SOC, revisa evidències, crea incident i aplica el playbook corresponent."
    )


def insert_notification_history(channel: str, severity: str, alert_id: Optional[int], title: str, status: str, destination: str = "", error: str = "", payload: Optional[Dict[str, Any]] = None):
    try:
        cur = db_cursor()
        cur.execute(
            """
            INSERT INTO notification_history (channel, severity, alert_id, title, status, destination, error, payload)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
            """,
            (channel, severity, alert_id, title, status, destination, error, json.dumps(payload or {})),
        )
        conn.commit()
    except Exception:
        conn.rollback()


def telegram_config() -> Dict[str, str]:
    return {
        "enabled": str(get_setting("telegram_enabled", os.getenv("TELEGRAM_ENABLED", "false"))).lower(),
        "bot_token": get_setting("telegram_bot_token", os.getenv("TELEGRAM_BOT_TOKEN", "")) or "",
        "chat_id": get_setting("telegram_chat_id", os.getenv("TELEGRAM_CHAT_ID", "")) or "",
        "min_severity": get_setting("telegram_min_severity", os.getenv("TELEGRAM_MIN_SEVERITY", "critical")) or "critical",
    }


def send_telegram_message(text: str, alert_id: Optional[int] = None, severity: str = "info", title: str = "Mini-SIEM") -> Dict[str, Any]:
    cfg = telegram_config()
    if cfg["enabled"] not in ("true", "1", "yes", "on"):
        return {"sent": False, "reason": "telegram_disabled"}
    if not cfg["bot_token"] or not cfg["chat_id"]:
        insert_notification_history("telegram", severity, alert_id, title, "failed", "", "Telegram token/chat_id missing", {})
        return {"sent": False, "reason": "missing_config"}
    url = f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage"
    payload = {"chat_id": cfg["chat_id"], "text": text[:3900], "disable_web_page_preview": True}
    try:
        r = requests.post(url, json=payload, timeout=TELEGRAM_TIMEOUT_SECONDS)
        ok = bool(r.ok and r.json().get("ok"))
        if ok:
            insert_notification_history("telegram", severity, alert_id, title, "sent", cfg["chat_id"], "", {"http_status": r.status_code})
            return {"sent": True, "status_code": r.status_code}
        err = r.text[:500]
        insert_notification_history("telegram", severity, alert_id, title, "failed", cfg["chat_id"], err, {"http_status": r.status_code})
        return {"sent": False, "status_code": r.status_code, "error": err}
    except Exception as exc:
        insert_notification_history("telegram", severity, alert_id, title, "failed", cfg["chat_id"], str(exc), {})
        return {"sent": False, "error": str(exc)}


def notify_alert_if_needed(alert: Dict[str, Any]):
    try:
        cfg = telegram_config()
        if cfg["enabled"] not in ("true", "1", "yes", "on"):
            return
        min_sev = cfg.get("min_severity") or "critical"
        if not severity_at_least(alert.get("severity", "info"), min_sev):
            return
        # Do not send closed/false positive or duplicate historical alerts.
        text = render_alert_notification(alert)
        send_telegram_message(text, alert_id=alert.get("id"), severity=alert.get("severity", "info"), title=alert.get("rule_name", "Alerta"))
    except Exception as exc:
        insert_notification_history("telegram", alert.get("severity", "info"), alert.get("id"), alert.get("rule_name", "Alerta"), "failed", "", f"notify exception: {exc}", {})


def is_private_ip(ip: Optional[str]) -> Optional[bool]:
    if not ip:
        return None
    try:
        if ip.startswith(("203.0.113.", "198.51.100.", "192.0.2.")):
            return False
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return None


def classify_ip(ip: Optional[str]) -> Dict[str, Any]:
    if not ip:
        return {"scope": "unknown", "is_private": None, "label": "no_ip"}
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_loopback:
            return {"scope": "loopback", "is_private": True, "label": "localhost"}
        if ip.startswith(("203.0.113.", "198.51.100.", "192.0.2.")):
            return {"scope": "documentation", "is_private": False, "label": "test_net_demo"}
        if obj.is_private:
            return {"scope": "private", "is_private": True, "label": "internal_network"}
        if obj.is_reserved:
            return {"scope": "reserved", "is_private": False, "label": "reserved_or_documentation"}
        return {"scope": "public", "is_private": False, "label": "internet"}
    except ValueError:
        return {"scope": "invalid", "is_private": None, "label": "invalid_ip"}


def risk_verdict(score: int) -> str:
    if score >= 85:
        return "investigar_ya"
    if score >= 60:
        return "alta_prioridad"
    if score >= 35:
        return "revisar"
    return "monitorizar"


def severity_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


SSH_FAILED_RE = re.compile(r"Failed password for (?:(invalid user) )?(?P<user>[A-Za-z0-9_.-]+) from (?P<ip>[0-9a-fA-F:.]+)")
SSH_ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>[A-Za-z0-9_.-]+) from (?P<ip>[0-9a-fA-F:.]+)")
SSH_INVALID_RE = re.compile(r"Invalid user (?P<user>[A-Za-z0-9_.-]+) from (?P<ip>[0-9a-fA-F:.]+)")
NGINX_ACCESS_RE = re.compile(r'(?P<ip>[0-9a-fA-F:.]+) - .*? "(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (?P<path>[^ ]+) [^\"]+" (?P<status>\d{3})')

SENSITIVE_PATHS = ("/.env", "/admin", "/wp-login.php", "/phpmyadmin", "/.git", "/config", "/server-status")


def normalize_log(raw: str, source_type: str = "unknown", source_name: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    metadata = metadata or {}
    raw = raw.strip()
    event = {
        "source_type": source_type or "unknown",
        "source_name": source_name,
        "event_category": "generic",
        "event_action": "log_observed",
        "severity": "info",
        "src_ip": None,
        "src_ip_is_private": None,
        "user_name": None,
        "service": metadata.get("service"),
        "message": raw[:500],
        "raw_log": raw,
        "tags": ["raw"],
        "risk_score_base": 5,
        "metadata": {**metadata},
    }
    if event.get("src_ip"):
        event["metadata"]["ip_context"] = classify_ip(event.get("src_ip"))

    if match := SSH_FAILED_RE.search(raw):
        user = match.group("user")
        ip = match.group("ip")
        score = 45
        tags = ["ssh", "auth", "failed_login"]
        if user == "root":
            score += 15
            tags.append("root")
        if match.group(1):
            tags.append("invalid_user")
        event.update(
            event_category="authentication",
            event_action="failed_login",
            severity=severity_from_score(score),
            src_ip=ip,
            src_ip_is_private=is_private_ip(ip),
            user_name=user,
            service="ssh",
            tags=tags,
            risk_score_base=score,
        )
        return event

    if match := SSH_ACCEPTED_RE.search(raw):
        ip = match.group("ip")
        event.update(
            event_category="authentication",
            event_action="successful_login",
            severity="low",
            src_ip=ip,
            src_ip_is_private=is_private_ip(ip),
            user_name=match.group("user"),
            service="ssh",
            tags=["ssh", "auth", "successful_login"],
            risk_score_base=20,
        )
        return event

    if match := SSH_INVALID_RE.search(raw):
        ip = match.group("ip")
        event.update(
            event_category="authentication",
            event_action="invalid_user",
            severity="medium",
            src_ip=ip,
            src_ip_is_private=is_private_ip(ip),
            user_name=match.group("user"),
            service="ssh",
            tags=["ssh", "auth", "invalid_user"],
            risk_score_base=40,
        )
        return event

    if match := NGINX_ACCESS_RE.search(raw):
        ip = match.group("ip")
        path = match.group("path")
        status = int(match.group("status"))
        score = 10
        tags = ["web", "http", f"status_{status}"]
        action = "web_request"
        if any(path.startswith(s) for s in SENSITIVE_PATHS):
            score = 55
            action = "sensitive_path_access"
            tags.append("sensitive_path")
        elif status == 404:
            score = 20
            action = "web_404"
        event.update(
            event_category="web",
            event_action=action,
            severity=severity_from_score(score),
            src_ip=ip,
            src_ip_is_private=is_private_ip(ip),
            service="nginx",
            tags=tags,
            risk_score_base=score,
            metadata={**metadata, "method": match.group("method"), "path": path, "status": status},
        )
        return event

    lowered = raw.lower()
    if any(word in lowered for word in ["error", "exception", "traceback", "critical", "panic"]):
        event.update(
            event_category="system",
            event_action="error_log",
            severity="medium",
            service=metadata.get("container_name") or metadata.get("service") or "unknown",
            tags=["error"],
            risk_score_base=35,
        )
        return event

    return event


def apply_common_enrichment(event: Dict[str, Any]) -> Dict[str, Any]:
    ip = event.get("src_ip")
    if ip:
        ctx = classify_ip(ip)
        event["src_ip_is_private"] = ctx.get("is_private")
        event.setdefault("metadata", {})["ip_context"] = ctx
        event.setdefault("metadata", {})["risk_verdict"] = risk_verdict(int(event.get("risk_score_base") or 0))
    # v15: optional threat-intel enrichment. Safe fallback if functions are not loaded yet.
    try:
        if globals().get("enrich_event_with_v15_intel"):
            event = enrich_event_with_v15_intel(event)
    except Exception as exc:
        event.setdefault("metadata", {})["threat_intel_error"] = str(exc)[:180]
    return event


def insert_event(event: Dict[str, Any]) -> int:
    event = apply_common_enrichment(event)
    cur = db_cursor()
    cur.execute(
        """
        INSERT INTO events (
            source_type, source_name, event_category, event_action, severity,
            src_ip, src_ip_is_private, user_name, service, message, raw_log,
            tags, risk_score_base, metadata
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s::jsonb)
        RETURNING id
        """,
        (
            event["source_type"], event.get("source_name"), event["event_category"], event["event_action"], event["severity"],
            event.get("src_ip"), event.get("src_ip_is_private"), event.get("user_name"), event.get("service"), event.get("message"),
            event["raw_log"], json.dumps(event.get("tags", [])), event.get("risk_score_base", 0), json.dumps(event.get("metadata", {})),
        ),
    )
    event_id = cur.fetchone()["id"]
    conn.commit()
    return event_id


def is_rule_enabled(rule_name: str) -> bool:
    try:
        cur = db_cursor()
        cur.execute("SELECT enabled FROM rules WHERE rule_name = %s", (rule_name,))
        row = cur.fetchone()
        return bool(row is None or row.get("enabled"))
    except Exception:
        conn.rollback()
        return True


def create_alert(rule_name: str, severity: str, risk_score: int, description: str, src_ip: Optional[str] = None,
                 user_name: Optional[str] = None, service: Optional[str] = None, event_count: int = 1,
                 first_seen: Optional[datetime] = None, last_seen: Optional[datetime] = None,
                 mitre_tactic: Optional[str] = None, mitre_technique: Optional[str] = None,
                 dedup_key: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
    dedup_key = dedup_key or f"{rule_name}:{src_ip}:{user_name}:{service}"
    metadata = metadata or {}
    if not is_rule_enabled(rule_name):
        return
    cur = db_cursor()
    cur.execute(
        """
        SELECT id FROM alerts
        WHERE dedup_key = %s AND alert_time > NOW() - INTERVAL '5 minutes'
        LIMIT 1
        """,
        (dedup_key,),
    )
    if cur.fetchone():
        conn.commit()
        return

    cur.execute(
        """
        INSERT INTO alerts (
            rule_name, severity, risk_score, src_ip, user_name, service, description,
            event_count, first_seen, last_seen, mitre_tactic, mitre_technique, dedup_key, metadata
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
        RETURNING id, alert_time, rule_name, severity, risk_score, src_ip, user_name, service, description, mitre_tactic, mitre_technique, metadata
        """,
        (rule_name, severity, risk_score, src_ip, user_name, service, description, event_count,
         first_seen, last_seen, mitre_tactic, mitre_technique, dedup_key, json.dumps(metadata)),
    )
    inserted_alert = cur.fetchone()
    conn.commit()
    if inserted_alert:
        notify_alert_if_needed(dict(inserted_alert))
    return inserted_alert.get("id") if inserted_alert else None


def run_detection(event: Dict[str, Any]):
    ip = event.get("src_ip")
    user = event.get("user_name")
    action = event.get("event_action")

    if ip:
        cur = db_cursor()
        cur.execute("SELECT value, label, severity FROM watchlist WHERE enabled = TRUE AND value = %s", (ip,))
        ioc = cur.fetchone()
        if ioc:
            sev = ioc.get("severity") or "high"
            create_alert(
                "IOC watchlist match", sev, 92,
                f"Event from watchlisted IP {ip}: {ioc.get('label') or 'local IOC'}",
                src_ip=ip, user_name=user, service=event.get("service"), event_count=1,
                mitre_tactic="Command and Control", mitre_technique="T1071 Application Layer Protocol",
                dedup_key=f"watchlist:{ip}", metadata={"ioc_label": ioc.get("label")}
            )

        if action in ("failed_login", "invalid_user", "web_request", "web_404", "sensitive_path_access") and is_private_ip(ip) is False:
            cur.execute(
                """
                SELECT COUNT(*) AS count, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
                FROM events
                WHERE src_ip = %s AND event_time > NOW() - INTERVAL '10 minutes'
                """,
                (ip,),
            )
            row = cur.fetchone()
            if row and row["count"] >= 25:
                create_alert(
                    "Many events from public IP", "medium", 58,
                    f"Public IP {ip} generated {row['count']} events in 10 minutes.",
                    src_ip=ip, service=event.get("service"), event_count=row["count"],
                    first_seen=row["first_seen"], last_seen=row["last_seen"],
                    mitre_tactic="Reconnaissance", mitre_technique="T1595 Active Scanning",
                    dedup_key=f"public_ip_burst:{ip}",
                )

    if action == "failed_login" and user == "root" and ip and is_private_ip(ip) is False:
        create_alert(
            "External root login attempt", "critical", 95,
            f"Public IP {ip} attempted SSH authentication as root.",
            src_ip=ip, user_name=user, service="ssh", event_count=1,
            mitre_tactic="Credential Access", mitre_technique="T1110 Brute Force",
            dedup_key=f"external_root:{ip}",
        )

    if action == "failed_login" and user == "root":
        create_alert(
            "Root login attempt", "medium", 60,
            f"SSH authentication attempt against root from {ip}.",
            src_ip=ip, user_name=user, service="ssh", event_count=1,
            mitre_tactic="Credential Access", mitre_technique="T1110 Brute Force",
            dedup_key=f"root_login:{ip}",
        )

    if action == "failed_login" and ip:
        cur = db_cursor()
        cur.execute(
            """
            SELECT COUNT(*) AS count, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
            FROM events
            WHERE src_ip = %s AND event_action = 'failed_login'
              AND event_time > NOW() - INTERVAL '10 minutes'
            """,
            (ip,),
        )
        row = cur.fetchone()
        count = row["count"]
        if count >= 10:
            create_alert(
                "SSH brute force", "high", 85,
                f"{count} failed SSH login attempts from {ip} in the last 10 minutes.",
                src_ip=ip, service="ssh", event_count=count,
                first_seen=row["first_seen"], last_seen=row["last_seen"],
                mitre_tactic="Credential Access", mitre_technique="T1110 Brute Force",
                dedup_key=f"ssh_bruteforce_high:{ip}",
            )
        elif count >= 5:
            create_alert(
                "SSH brute force", "medium", 65,
                f"{count} failed SSH login attempts from {ip} in the last 10 minutes.",
                src_ip=ip, service="ssh", event_count=count,
                first_seen=row["first_seen"], last_seen=row["last_seen"],
                mitre_tactic="Credential Access", mitre_technique="T1110 Brute Force",
                dedup_key=f"ssh_bruteforce_medium:{ip}",
            )

        cur.execute(
            """
            SELECT COUNT(DISTINCT user_name) AS users
            FROM events
            WHERE src_ip = %s AND event_action IN ('failed_login', 'invalid_user')
              AND event_time > NOW() - INTERVAL '15 minutes'
            """,
            (ip,),
        )
        users = cur.fetchone()["users"]
        if users >= 4:
            create_alert(
                "Password spraying candidate", "medium", 70,
                f"Source IP {ip} attempted authentication against {users} different users in 15 minutes.",
                src_ip=ip, service="ssh", event_count=users,
                mitre_tactic="Credential Access", mitre_technique="T1110.003 Password Spraying",
                dedup_key=f"password_spray:{ip}",
            )

    if action == "successful_login" and ip:
        cur = db_cursor()
        cur.execute(
            """
            SELECT COUNT(*) AS count, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
            FROM events
            WHERE src_ip = %s AND event_action = 'failed_login'
              AND event_time > NOW() - INTERVAL '30 minutes'
            """,
            (ip,),
        )
        row = cur.fetchone()
        if row["count"] >= 3:
            create_alert(
                "SSH login after failures", "high", 88,
                f"Successful SSH login for {user} from {ip} after {row['count']} failed attempts.",
                src_ip=ip, user_name=user, service="ssh", event_count=row["count"] + 1,
                first_seen=row["first_seen"], last_seen=datetime.now(timezone.utc),
                mitre_tactic="Initial Access", mitre_technique="T1078 Valid Accounts",
                dedup_key=f"success_after_failures:{ip}:{user}",
            )

    if action == "sensitive_path_access":
        create_alert(
            "Web sensitive path access", "medium", 55,
            f"Sensitive web path requested from {ip}: {event.get('metadata', {}).get('path')}",
            src_ip=ip, service="nginx", event_count=1,
            mitre_tactic="Reconnaissance", mitre_technique="T1595 Active Scanning",
            dedup_key=f"web_sensitive:{ip}:{event.get('metadata', {}).get('path')}",
        )

    if action == "web_404" and ip:
        cur = db_cursor()
        cur.execute(
            """
            SELECT COUNT(*) AS count, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
            FROM events
            WHERE src_ip = %s AND event_action = 'web_404'
              AND event_time > NOW() - INTERVAL '5 minutes'
            """,
            (ip,),
        )
        row = cur.fetchone()
        if row["count"] >= 20:
            create_alert(
                "Web scan - many 404", "medium", 60,
                f"{row['count']} HTTP 404 responses from {ip} in 5 minutes.",
                src_ip=ip, service="nginx", event_count=row["count"],
                first_seen=row["first_seen"], last_seen=row["last_seen"],
                mitre_tactic="Reconnaissance", mitre_technique="T1595 Active Scanning",
                dedup_key=f"web_404_scan:{ip}",
            )

    if action == "error_log":
        service = event.get("service") or "unknown"
        cur = db_cursor()
        cur.execute(
            """
            SELECT COUNT(*) AS count, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
            FROM events
            WHERE event_action = 'error_log' AND service = %s
              AND event_time > NOW() - INTERVAL '5 minutes'
            """,
            (service,),
        )
        row = cur.fetchone()
        if row["count"] >= 10:
            create_alert(
                "Container error burst", "medium", 50,
                f"{row['count']} error-like log entries for {service} in 5 minutes.",
                service=service, event_count=row["count"],
                first_seen=row["first_seen"], last_seen=row["last_seen"],
                mitre_tactic="Impact", mitre_technique="T1499 Endpoint Denial of Service",
                dedup_key=f"error_burst:{service}",
            )



WINDOWS_EVENT_MAP = {
    4625: ("authentication", "windows_failed_logon", "medium", 55, "windows", ["windows", "auth", "failed_logon"], "Credential Access", "T1110 Brute Force"),
    4624: ("authentication", "windows_successful_logon", "low", 20, "windows", ["windows", "auth", "successful_logon"], "Initial Access", "T1078 Valid Accounts"),
    4648: ("authentication", "windows_explicit_credentials", "medium", 45, "windows", ["windows", "auth", "explicit_credentials"], "Credential Access", "T1550 Use Alternate Authentication Material"),
    4672: ("privilege", "windows_special_privileges", "medium", 45, "windows", ["windows", "privilege", "admin"], "Privilege Escalation", "T1078 Valid Accounts"),
    4688: ("process", "windows_process_created", "info", 10, "windows", ["windows", "process"], "Execution", "T1059 Command and Scripting Interpreter"),
    4720: ("identity", "windows_user_created", "high", 70, "windows", ["windows", "account", "user_created"], "Persistence", "T1136 Create Account"),
    4726: ("identity", "windows_user_deleted", "medium", 50, "windows", ["windows", "account", "user_deleted"], "Impact", "T1531 Account Access Removal"),
    4732: ("identity", "windows_group_member_added", "high", 75, "windows", ["windows", "account", "group_change"], "Persistence", "T1098 Account Manipulation"),
    1102: ("defense_evasion", "windows_audit_log_cleared", "critical", 95, "windows", ["windows", "audit", "log_cleared"], "Defense Evasion", "T1070.001 Clear Windows Event Logs"),
    7045: ("persistence", "windows_service_installed", "high", 75, "windows", ["windows", "service", "persistence"], "Persistence", "T1543.003 Windows Service"),
    1116: ("malware", "defender_malware_detected", "critical", 90, "windows_defender", ["windows", "defender", "malware"], "Execution", "T1204 User Execution"),
    1117: ("malware", "defender_remediation_action", "medium", 45, "windows_defender", ["windows", "defender", "remediation"], "Defense Evasion", "T1562 Impair Defenses"),
    4104: ("script", "powershell_scriptblock", "low", 20, "powershell", ["windows", "powershell", "scriptblock"], "Execution", "T1059.001 PowerShell"),
    1: ("process", "sysmon_process_created", "info", 15, "sysmon", ["windows", "sysmon", "process"], "Execution", "T1059 Command and Scripting Interpreter"),
    3: ("network", "sysmon_network_connection", "low", 25, "sysmon", ["windows", "sysmon", "network"], "Command and Control", "T1071 Application Layer Protocol"),
    11: ("file", "sysmon_file_created", "info", 10, "sysmon", ["windows", "sysmon", "file"], "Collection", "T1005 Data from Local System"),
    90010: ("download", "download_archive_scan", "info", 15, "download_guard", ["windows", "download_guard", "archive"], "Initial Access", "T1204 User Execution"),
    90011: ("download", "download_executable_detected", "high", 70, "download_guard", ["windows", "download_guard", "executable"], "Initial Access", "T1204 User Execution"),
}

SUSPICIOUS_PROCESS_PATTERNS = [
    "mimikatz", "sekurlsa", "procdump", "lsass", "-enc", "encodedcommand", "downloadstring",
    "iex", "invoke-expression", "invoke-webrequest", "certutil", "urlcache", "bitsadmin",
    "rundll32", "regsvr32", "mshta", "wmic", "powershell.exe -nop", "cmd.exe /c whoami"
]

def _first_present(data: Dict[str, Any], keys: List[str]) -> Optional[str]:
    for k in keys:
        val = data.get(k)
        if val is not None and str(val).strip() not in ("", "-", "::1", "127.0.0.1"):
            return str(val).strip()
    return None



def _valid_ip_candidate(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = str(value).strip().strip('.,;()[]{}<>"\'')
    if not value or value in ("-", "::1", "127.0.0.1", "0.0.0.0", "localhost"):
        return None
    try:
        ipaddress.ip_address(value)
        return value
    except Exception:
        return None


def extract_ip_from_text(text: str) -> Optional[str]:
    text = text or ""
    # English + Spanish Windows Event Viewer labels.
    labels = [
        r"Source Network Address", r"Network Address", r"Source Address", r"Client Address",
        r"IpAddress", r"SourceIp", r"DestinationIp", r"Destination IP", r"Remote Address",
        r"Dirección de red de origen", r"Direccion de red de origen", r"Dirección IP de origen",
        r"Direccion IP de origen", r"Dirección de cliente", r"Direccion de cliente"
    ]
    for label in labels:
        m = re.search(label + r"\s*[:=]\s*([^\s,;]+)", text, flags=re.IGNORECASE)
        if m:
            ip = _valid_ip_candidate(m.group(1))
            if ip:
                return ip
    # Last-resort: any non-loopback IPv4/IPv6 in the message.
    for m in re.finditer(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", text):
        ip = _valid_ip_candidate(m.group(0))
        if ip:
            return ip
    return None


def extract_user_from_text(text: str) -> Optional[str]:
    text = text or ""
    labels = [
        r"Account Name", r"TargetUserName", r"SubjectUserName", r"User Name", r"User",
        r"Nombre de cuenta", r"Nombre de usuario", r"Cuenta"
    ]
    for label in labels:
        matches = re.findall(label + r"\s*[:=]\s*([^\r\n]+)", text, flags=re.IGNORECASE)
        # Windows messages can contain multiple Account Name fields; prefer the last non-machine value.
        for val in reversed(matches):
            val = str(val).strip().strip('.,;()[]{}<>"\'')
            if val and val not in ("-", "SYSTEM") and not val.endswith("$"):
                return val
    return None

def normalize_windows_event(data: WindowsEventInput) -> Dict[str, Any]:
    ed = data.event_data or {}
    event_id = int(data.event_id)
    category, action, severity, score, service, tags, tactic, technique = WINDOWS_EVENT_MAP.get(
        event_id,
        ("windows", f"windows_event_{event_id}", "info", 5, "windows", ["windows"], None, None),
    )
    provider = (data.provider_name or "").lower()
    log_name = (data.log_name or "").lower()
    if "sysmon" in provider or "sysmon" in log_name:
        sysmon_map = {
            1: ("process", "sysmon_process_created", "medium", 35, "sysmon", ["windows", "sysmon", "process"], "Execution", "T1059 Command and Scripting Interpreter"),
            3: ("network", "sysmon_network_connection", "low", 25, "sysmon", ["windows", "sysmon", "network"], "Command and Control", "T1071 Application Layer Protocol"),
            11: ("file", "sysmon_file_created", "info", 10, "sysmon", ["windows", "sysmon", "file"], "Collection", "T1005 Data from Local System"),
        }
        if event_id in sysmon_map:
            category, action, severity, score, service, tags, tactic, technique = sysmon_map[event_id]
    src_ip = _first_present(ed, ["IpAddress", "SourceNetworkAddress", "ClientAddress", "SourceIp", "DestinationIp", "DestinationIpAddress", "RemoteAddress"])
    user = _first_present(ed, ["TargetUserName", "SubjectUserName", "User", "AccountName", "MemberName", "TargetDomainName"])
    process = _first_present(ed, ["NewProcessName", "Image", "ProcessName", "CommandLine", "ParentImage"])
    command_line = _first_present(ed, ["CommandLine", "ScriptBlockText", "ImagePath"])
    raw = data.message or json.dumps({"event_id": event_id, "event_data": ed}, ensure_ascii=False)

    if event_id == 90010:
        try:
            suspicious_count = int(ed.get("suspicious_count") or 0)
        except Exception:
            suspicious_count = 0
        verdict = str(ed.get("verdict") or "clean").lower()
        if suspicious_count >= 3 or verdict in ("high", "malicious", "dangerous"):
            severity, score = "high", 78
        elif suspicious_count > 0 or verdict in ("medium", "suspicious"):
            severity, score = "medium", 55
        else:
            severity, score = "info", 15
    if event_id == 90011:
        severity, score = "high", 75

    # v10.3 fallback: many Windows localized messages include the IP/user only in the formatted message.
    if not src_ip:
        src_ip = extract_ip_from_text(raw)
    else:
        src_ip = _valid_ip_candidate(src_ip) or extract_ip_from_text(raw)
    if not user:
        user = extract_user_from_text(raw)
    msg = f"Windows {data.log_name} EventID {event_id} on {data.hostname}: {raw[:300]}"
    metadata = {"agent_id": data.agent_id, "hostname": data.hostname, "os_version": data.os_version, "log_name": data.log_name, "provider_name": data.provider_name, "event_id": event_id, "record_id": data.record_id, "level": data.level, "time_created": data.time_created, "event_data": ed, "mitre_tactic": tactic, "mitre_technique": technique}
    combined = " ".join([str(process or ""), str(command_line or ""), raw]).lower()
    if action in ("windows_process_created", "sysmon_process_created", "powershell_scriptblock") and any(p in combined for p in SUSPICIOUS_PROCESS_PATTERNS):
        action = "windows_suspicious_process"
        severity = "high"
        score = 82
        tags = list(set(tags + ["suspicious_process", "lolbin"]))
        tactic, technique = "Defense Evasion", "T1218 System Binary Proxy Execution"
        metadata["matched_suspicious_patterns"] = [p for p in SUSPICIOUS_PROCESS_PATTERNS if p in combined]
    if action == "powershell_scriptblock" and any(p in combined for p in ["encodedcommand", "frombase64string", "downloadstring", "iex", "invoke-expression"]):
        action = "windows_suspicious_powershell"
        severity = "high"
        score = 85
        tags = list(set(tags + ["powershell", "suspicious_script"]))
        tactic, technique = "Execution", "T1059.001 PowerShell"
        metadata["matched_suspicious_patterns"] = [p for p in ["encodedcommand", "frombase64string", "downloadstring", "iex", "invoke-expression"] if p in combined]
    metadata["mitre_tactic"] = tactic
    metadata["mitre_technique"] = technique
    return {"source_type": "windows_agent", "source_name": data.hostname, "event_category": category, "event_action": action, "severity": severity, "src_ip": src_ip, "src_ip_is_private": is_private_ip(src_ip), "user_name": user, "service": service, "message": msg, "raw_log": raw, "tags": tags, "risk_score_base": score, "metadata": metadata}

def validate_agent_token(x_agent_token: Optional[str]):
    if WINDOWS_AGENT_TOKEN and x_agent_token != WINDOWS_AGENT_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid Windows agent token")

def run_windows_detection(event: Dict[str, Any]):
    action = event.get("event_action")
    ip = event.get("src_ip")
    user = event.get("user_name")
    host = event.get("source_name")
    md = event.get("metadata") or {}
    event_id = md.get("event_id")
    if action == "windows_failed_logon" and ip:
        cur = db_cursor()
        cur.execute("""SELECT COUNT(*) AS count, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen FROM events WHERE source_type='windows_agent' AND src_ip=%s AND event_action='windows_failed_logon' AND event_time > NOW() - INTERVAL '10 minutes'""", (ip,))
        row = cur.fetchone()
        if row and row["count"] >= 5:
            create_alert("Windows failed logon burst", "high", 82, f"{row['count']} Windows failed logons from {ip} against {host} in 10 minutes.", src_ip=ip, user_name=user, service="windows", event_count=row["count"], first_seen=row["first_seen"], last_seen=row["last_seen"], mitre_tactic="Credential Access", mitre_technique="T1110 Brute Force", dedup_key=f"win_failed_logon:{host}:{ip}", metadata={"host": host, "event_id": event_id})
    if action == "windows_successful_logon" and ip:
        cur = db_cursor()
        cur.execute("""SELECT COUNT(*) AS count, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen FROM events WHERE source_type='windows_agent' AND src_ip=%s AND event_action='windows_failed_logon' AND event_time > NOW() - INTERVAL '30 minutes'""", (ip,))
        row = cur.fetchone()
        if row and row["count"] >= 3:
            create_alert("Windows logon after failures", "critical", 90, f"Successful Windows logon for {user} from {ip} after {row['count']} failed attempts.", src_ip=ip, user_name=user, service="windows", event_count=row["count"] + 1, first_seen=row["first_seen"], last_seen=datetime.now(timezone.utc), mitre_tactic="Initial Access", mitre_technique="T1078 Valid Accounts", dedup_key=f"win_success_after_fail:{host}:{ip}:{user}", metadata={"host": host})
    if action in ("windows_audit_log_cleared", "defender_malware_detected", "windows_group_member_added", "windows_user_created", "windows_service_installed", "windows_suspicious_process", "windows_suspicious_powershell"):
        rule_map = {
            "windows_audit_log_cleared": ("Windows audit log cleared", "critical", 96, "Windows security audit log was cleared. Possible anti-forensics activity.", "Defense Evasion", "T1070.001 Clear Windows Event Logs"),
            "defender_malware_detected": ("Microsoft Defender malware detected", "critical", 92, "Microsoft Defender detected malware on the Windows endpoint.", "Execution", "T1204 User Execution"),
            "windows_group_member_added": ("Windows privileged group change", "high", 88, "A member was added to a Windows security group.", "Persistence", "T1098 Account Manipulation"),
            "windows_user_created": ("Windows local account created", "high", 78, "A local/domain Windows account was created.", "Persistence", "T1136 Create Account"),
            "windows_service_installed": ("Windows service installed", "high", 78, "A new Windows service was installed.", "Persistence", "T1543.003 Windows Service"),
            "windows_suspicious_process": ("Windows suspicious process", "high", 84, "Suspicious Windows command, LOLBin or credential-access pattern observed.", "Defense Evasion", "T1218 System Binary Proxy Execution"),
            "windows_suspicious_powershell": ("Suspicious PowerShell activity", "high", 86, "Suspicious PowerShell script block or encoded command observed.", "Execution", "T1059.001 PowerShell"),
        }
        rule_name, sev, score, desc, tactic, technique = rule_map[action]
        create_alert(rule_name, sev, score, f"{desc} Host={host} User={user or '-'} IP={ip or '-'}", src_ip=ip, user_name=user, service=event.get("service"), event_count=1, mitre_tactic=tactic, mitre_technique=technique, dedup_key=f"{action}:{host}:{user}:{ip}:{event_id}", metadata={"host": host, "event_id": event_id, **md})

def local_ai_triage_from_alert(alert: Dict[str, Any], recent_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    severity = alert.get("severity") or "medium"
    score = int(alert.get("risk_score") or 50)
    rule = alert.get("rule_name") or "unknown"
    ip = alert.get("src_ip") or "sin IP"
    host = (alert.get("metadata") or {}).get("host") or alert.get("service") or "entorno monitorizado"
    priority = "P1" if severity == "critical" or score >= 90 else "P2" if severity == "high" or score >= 75 else "P3"
    evidence = [f"Regla disparada: {rule}", f"Severidad: {severity}", f"Riesgo: {score}", f"IP origen: {ip}", f"Eventos relacionados recientes: {len(recent_events)}"]
    if "Windows" in rule or "PowerShell" in rule or "Defender" in rule:
        recommendations = ["Aislar temporalmente el equipo si la alerta es crítica o hay ejecución sospechosa.", "Revisar eventos Windows relacionados por host, usuario e IP.", "Buscar persistencia: servicios nuevos, cuentas creadas, cambios de grupos y PowerShell 4104.", "Ejecutar análisis Microsoft Defender completo y conservar evidencias antes de limpiar.", "Abrir un incidente y vincular todas las alertas relacionadas."]
    elif "SSH" in rule or "login" in rule.lower():
        recommendations = ["Confirmar si hubo login correcto después de fallos.", "Bloquear IP origen si es pública y no esperada.", "Revisar usuarios atacados y rotar credenciales si procede.", "Deshabilitar root login y reforzar MFA/llaves SSH.", "Documentar timeline y cerrar como mitigado o escalar a incidente."]
    elif "Web" in rule or "scan" in rule.lower():
        recommendations = ["Listar rutas solicitadas y códigos HTTP.", "Comprobar si alguna ruta sensible devolvió 200/302.", "Añadir IP a watchlist y aplicar rate limiting o bloqueo si es real.", "Revisar logs de aplicación próximos al escaneo.", "Mantener evidencia para la memoria del TFG."]
    else:
        recommendations = ["Revisar eventos relacionados por IP, usuario y ventana temporal.", "Validar si el comportamiento era esperado.", "Añadir notas de triage en la alerta.", "Crear incidente si hay varias alertas correlacionadas.", "Cerrar como falso positivo solo si hay justificación."]
    return {"priority": priority, "summary": f"Alerta {rule} en {host}: riesgo {score}/100, origen {ip}. Requiere triage {priority}.", "evidence": evidence, "recommended_actions": recommendations}


@app.get("/")
def read_root():
    return {"status": "Mini-SIEM Sentinel v15 running", "mode": "real-log-ready", "windows_agent": "supported", "copilot": "contextual_local_soc_assistant"}


@app.get("/health")
def health():
    cur = db_cursor()
    cur.execute("SELECT 1 AS ok")
    return {"status": "ok", "db": cur.fetchone()["ok"]}


@app.post("/register")
def register(data: dict):
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        raise HTTPException(status_code=400, detail="Missing fields")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Password too short")
    if len(password) > 72:
        raise HTTPException(status_code=400, detail="Password too long")

    cur = db_cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, hash_password(password)),
        )
        conn.commit()
        audit(username, "register", {"username": username})
        return {"msg": "User created"}
    except Exception as exc:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/login")
def login(data: dict):
    username = data.get("username")
    password = data.get("password") or ""
    cur = db_cursor()
    cur.execute("SELECT password, role FROM users WHERE username=%s", (username,))
    user = cur.fetchone()
    if not user or not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = jwt.encode({"sub": username, "role": user["role"]}, SECRET_KEY, algorithm=ALGORITHM)
    audit(username, "login", {})
    return {"access_token": token, "token_type": "bearer", "role": user["role"]}


@app.post("/ingest-log")
def ingest_log(data: LogInput):
    event = normalize_log(data.log, data.source_type or "unknown", data.source_name, data.metadata)
    event_id = insert_event(event)
    run_detection(event)
    return {"status": "log processed", "event_id": event_id, "event_action": event["event_action"], "severity": event["severity"]}


@app.post("/event")
def create_event(event: dict):
    normalized = {
        "source_type": event.get("source_type", "api"),
        "source_name": event.get("source_name"),
        "event_category": event.get("category", event.get("event_category", "generic")),
        "event_action": event.get("action", event.get("event_action", "unknown")),
        "severity": event.get("severity", "info"),
        "src_ip": event.get("src_ip"),
        "src_ip_is_private": is_private_ip(event.get("src_ip")),
        "user_name": event.get("user", event.get("user_name")),
        "service": event.get("service"),
        "message": event.get("message", event.get("raw", "")),
        "raw_log": event.get("raw", event.get("raw_log", json.dumps(event))),
        "tags": event.get("tags", []),
        "risk_score_base": event.get("risk_score_base", 0),
        "metadata": event.get("metadata", {}),
    }
    event_id = insert_event(normalized)
    run_detection(normalized)
    return {"status": "event stored", "event_id": event_id}


@app.get("/events")
def get_events(
    user=Depends(verify_token),
    limit: int = Query(100, ge=1, le=500),
    src_ip: Optional[str] = None,
    severity: Optional[str] = None,
    action: Optional[str] = None,
    service: Optional[str] = None,
    min_risk: Optional[int] = None,
    interesting: bool = False,
):
    filters = []
    params: List[Any] = []
    if src_ip:
        filters.append("src_ip = %s")
        params.append(src_ip)
    if severity:
        filters.append("severity = %s")
        params.append(severity)
    if action:
        filters.append("event_action = %s")
        params.append(action)
    if service:
        filters.append("service = %s")
        params.append(service)
    if min_risk is not None:
        filters.append("risk_score_base >= %s")
        params.append(min_risk)
    if interesting:
        filters.append("(severity IN ('critical','high','medium') OR risk_score_base >= 35 OR event_action IN ('windows_failed_logon','windows_suspicious_process','windows_suspicious_powershell','download_archive_scan','download_executable_detected','defender_malware_detected'))")

    where = "WHERE " + " AND ".join(filters) if filters else ""
    cur = db_cursor()
    cur.execute(
        f"""
        SELECT id, event_time, source_type, source_name, event_category, event_action, severity,
               src_ip, src_ip_is_private, user_name, service, message, raw_log, tags, risk_score_base, metadata
        FROM events
        {where}
        ORDER BY event_time DESC
        LIMIT %s
        """,
        [*params, limit],
    )
    rows = cur.fetchall()
    audit(user.get("sub"), "list_events", {"limit": limit, "filters": {"src_ip": src_ip, "severity": severity, "action": action, "service": service, "interesting": interesting, "min_risk": min_risk}})
    return rows


@app.get("/alerts")
def get_alerts(user=Depends(verify_token), limit: int = Query(100, ge=1, le=500), status: Optional[str] = None):
    params: List[Any] = []
    where = ""
    if status:
        where = "WHERE status = %s"
        params.append(status)
    cur = db_cursor()
    cur.execute(
        f"""
        SELECT id, alert_time, rule_name, severity, risk_score, src_ip, user_name, service,
               description, event_count, first_seen, last_seen, mitre_tactic, mitre_technique, status, metadata
        FROM alerts
        {where}
        ORDER BY alert_time DESC
        LIMIT %s
        """,
        [*params, limit],
    )
    rows = cur.fetchall()
    audit(user.get("sub"), "list_alerts", {"limit": limit, "status": status})
    return rows


@app.get("/stats")
def get_stats(user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT COUNT(*) AS total FROM events")
    total_events = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) AS total FROM alerts")
    total_alerts = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) AS total FROM alerts WHERE status = 'open'")
    open_alerts = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) AS total FROM alerts WHERE severity IN ('critical', 'high') AND status = 'open'")
    high_open_alerts = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) AS total FROM events WHERE event_time > NOW() - INTERVAL '1 hour'")
    events_last_hour = cur.fetchone()["total"]
    cur.execute("SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity")
    alerts_by_severity = cur.fetchall()
    cur.execute("SELECT severity, COUNT(*) AS count FROM events GROUP BY severity")
    events_by_severity = cur.fetchall()
    cur.execute("SELECT event_action, COUNT(*) AS count FROM events GROUP BY event_action ORDER BY count DESC LIMIT 10")
    top_actions = cur.fetchall()
    cur.execute("SELECT src_ip, COUNT(*) AS count FROM events WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC LIMIT 10")
    top_ips = cur.fetchall()
    cur.execute("SELECT date_trunc('minute', event_time) AS bucket, COUNT(*) AS count FROM events WHERE event_time > NOW() - INTERVAL '1 hour' GROUP BY bucket ORDER BY bucket")
    timeline = cur.fetchall()
    cur.execute("SELECT user_name, COUNT(*) AS count FROM events WHERE user_name IS NOT NULL GROUP BY user_name ORDER BY count DESC LIMIT 10")
    top_users = cur.fetchall()
    cur.execute("SELECT service, COUNT(*) AS count FROM events WHERE service IS NOT NULL GROUP BY service ORDER BY count DESC LIMIT 10")
    top_services = cur.fetchall()
    cur.execute("SELECT COALESCE(src_ip_is_private::text, 'unknown') AS scope, COUNT(*) AS count FROM events GROUP BY src_ip_is_private")
    ip_scope = cur.fetchall()
    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "high_open_alerts": high_open_alerts,
        "events_last_hour": events_last_hour,
        "alerts_by_severity": alerts_by_severity,
        "events_by_severity": events_by_severity,
        "top_actions": top_actions,
        "top_ips": top_ips,
        "timeline": timeline,
        "top_users": top_users,
        "top_services": top_services,
        "ip_scope": ip_scope,
    }


@app.get("/rules")
def get_rules(user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT id, rule_name, description, severity, risk_score, enabled, mitre_tactic, mitre_technique FROM rules ORDER BY id")
    return cur.fetchall()


@app.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, data: AlertUpdateInput, user=Depends(verify_token)):
    allowed = {"open", "acknowledged", "closed", "false_positive"}
    if data.status not in allowed:
        raise HTTPException(status_code=400, detail="Invalid status")
    cur = db_cursor()
    cur.execute("UPDATE alerts SET status = %s WHERE id = %s RETURNING id", (data.status, alert_id))
    row = cur.fetchone()
    if not row:
        conn.rollback()
        raise HTTPException(status_code=404, detail="Alert not found")
    if data.note:
        cur.execute("INSERT INTO alert_notes (alert_id, username, note) VALUES (%s, %s, %s)", (alert_id, user.get("sub"), data.note))
    conn.commit()
    audit(user.get("sub"), "update_alert", {"alert_id": alert_id, "status": data.status})
    return {"status": "updated", "alert_id": alert_id}


@app.get("/alert-notes/{alert_id}")
def get_alert_notes(alert_id: int, user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT username, note, created_at FROM alert_notes WHERE alert_id = %s ORDER BY created_at DESC", (alert_id,))
    return cur.fetchall()


@app.get("/audit-logs")
def get_audit_logs(user=Depends(verify_token), limit: int = Query(50, ge=1, le=200)):
    cur = db_cursor()
    cur.execute("SELECT audit_time, username, action, details FROM audit_logs ORDER BY audit_time DESC LIMIT %s", (limit,))
    return cur.fetchall()


@app.get("/watchlist")
def list_watchlist(user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT id, value, ioc_type, label, severity, enabled, created_at FROM watchlist ORDER BY created_at DESC")
    return cur.fetchall()


@app.post("/watchlist")
def add_watchlist(item: WatchlistInput, user=Depends(verify_token)):
    value = item.value.strip()
    if not value:
        raise HTTPException(status_code=400, detail="Empty IOC")
    cur = db_cursor()
    cur.execute(
        "INSERT INTO watchlist (value, ioc_type, label, severity) VALUES (%s, %s, %s, %s) ON CONFLICT (value) DO UPDATE SET label = EXCLUDED.label, severity = EXCLUDED.severity, enabled = TRUE RETURNING id",
        (value, item.ioc_type, item.label, item.severity),
    )
    row = cur.fetchone()
    conn.commit()
    audit(user.get("sub"), "add_watchlist", {"value": value})
    return {"status": "stored", "id": row["id"]}


@app.delete("/watchlist/{item_id}")
def delete_watchlist(item_id: int, user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("UPDATE watchlist SET enabled = FALSE WHERE id = %s", (item_id,))
    conn.commit()
    audit(user.get("sub"), "disable_watchlist", {"item_id": item_id})
    return {"status": "disabled"}


@app.get("/ioc/lookup")
def ioc_lookup(value: str, user=Depends(verify_token)):
    ctx = classify_ip(value) if re.match(r"^[0-9a-fA-F:.]+$", value) else {"scope": "unknown", "label": "non_ip_indicator"}
    cur = db_cursor()
    cur.execute("SELECT COUNT(*) AS events FROM events WHERE src_ip = %s", (value,))
    events = cur.fetchone()["events"]
    cur.execute("SELECT COUNT(*) AS alerts FROM alerts WHERE src_ip = %s", (value,))
    alerts = cur.fetchone()["alerts"]
    cur.execute("SELECT id, label, severity, enabled FROM watchlist WHERE value = %s", (value,))
    watch = cur.fetchone()
    return {"value": value, "context": ctx, "seen_events": events, "seen_alerts": alerts, "watchlist": watch}


@app.get("/export/events.csv")
def export_events(user=Depends(verify_token), limit: int = Query(1000, ge=1, le=5000)):
    cur = db_cursor()
    cur.execute(
        "SELECT event_time, source_type, source_name, event_category, event_action, severity, src_ip, user_name, service, risk_score_base, raw_log FROM events ORDER BY event_time DESC LIMIT %s",
        (limit,),
    )
    rows = cur.fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["event_time", "source_type", "source_name", "event_category", "event_action", "severity", "src_ip", "user_name", "service", "risk_score_base", "raw_log"])
    for r in rows:
        writer.writerow([r.get("event_time"), r.get("source_type"), r.get("source_name"), r.get("event_category"), r.get("event_action"), r.get("severity"), r.get("src_ip"), r.get("user_name"), r.get("service"), r.get("risk_score_base"), r.get("raw_log")])
    output.seek(0)
    audit(user.get("sub"), "export_events_csv", {"limit": limit})
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=mini-siem-events.csv"})


@app.patch("/rules/{rule_id}")
def update_rule(rule_id: int, data: RuleUpdateInput, user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("UPDATE rules SET enabled = %s WHERE id = %s RETURNING id, rule_name", (data.enabled, rule_id))
    row = cur.fetchone()
    if not row:
        conn.rollback()
        raise HTTPException(status_code=404, detail="Rule not found")
    conn.commit()
    audit(user.get("sub"), "update_rule", {"rule_id": rule_id, "enabled": data.enabled})
    return {"status": "updated", "rule": row}


@app.get("/cases")
def list_cases(user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("""
        SELECT c.id, c.created_at, c.updated_at, c.title, c.description, c.severity, c.status, c.owner,
               COUNT(ca.alert_id) AS alerts
        FROM cases c
        LEFT JOIN case_alerts ca ON ca.case_id = c.id
        GROUP BY c.id
        ORDER BY c.updated_at DESC
    """)
    return cur.fetchall()


@app.post("/cases")
def create_case(data: CaseInput, user=Depends(verify_token)):
    if not data.title.strip():
        raise HTTPException(status_code=400, detail="Missing title")
    cur = db_cursor()
    cur.execute("""
        INSERT INTO cases (title, description, severity, status, owner)
        VALUES (%s, %s, %s, 'open', %s)
        RETURNING id
    """, (data.title.strip(), data.description, data.severity, user.get("sub")))
    case_id = cur.fetchone()["id"]
    conn.commit()
    audit(user.get("sub"), "create_case", {"case_id": case_id, "title": data.title})
    return {"status": "created", "id": case_id}


@app.patch("/cases/{case_id}")
def update_case(case_id: int, data: CaseUpdateInput, user=Depends(verify_token)):
    fields, params = [], []
    for key in ["status", "severity", "title", "description"]:
        value = getattr(data, key)
        if value is not None:
            fields.append(f"{key} = %s")
            params.append(value)
    if not fields:
        return {"status": "no_change"}
    params.append(case_id)
    cur = db_cursor()
    cur.execute(f"UPDATE cases SET {', '.join(fields)}, updated_at = NOW() WHERE id = %s RETURNING id", params)
    if not cur.fetchone():
        conn.rollback()
        raise HTTPException(status_code=404, detail="Case not found")
    conn.commit()
    audit(user.get("sub"), "update_case", {"case_id": case_id, "fields": fields})
    return {"status": "updated"}


@app.post("/cases/{case_id}/alerts")
def add_alert_to_case(case_id: int, data: CaseAlertInput, user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT id FROM cases WHERE id = %s", (case_id,))
    if not cur.fetchone():
        raise HTTPException(status_code=404, detail="Case not found")
    cur.execute("""
        INSERT INTO case_alerts (case_id, alert_id) VALUES (%s, %s)
        ON CONFLICT DO NOTHING
    """, (case_id, data.alert_id))
    cur.execute("UPDATE cases SET updated_at = NOW() WHERE id = %s", (case_id,))
    conn.commit()
    audit(user.get("sub"), "add_alert_to_case", {"case_id": case_id, "alert_id": data.alert_id})
    return {"status": "linked"}


@app.get("/cases/{case_id}/alerts")
def get_case_alerts(case_id: int, user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("""
        SELECT a.* FROM alerts a
        JOIN case_alerts ca ON ca.alert_id = a.id
        WHERE ca.case_id = %s
        ORDER BY a.alert_time DESC
    """, (case_id,))
    return cur.fetchall()


@app.get("/playbooks")
def get_playbooks(user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT id, name, trigger_rule, severity, steps FROM playbooks ORDER BY id")
    return cur.fetchall()


@app.get("/dashboard/health")
def dashboard_health(user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT COUNT(*) AS events FROM events WHERE event_time > NOW() - INTERVAL '10 minutes'")
    recent_events = cur.fetchone()["events"]
    cur.execute("SELECT COUNT(*) AS critical_open FROM alerts WHERE status='open' AND severity='critical'")
    critical_open = cur.fetchone()["critical_open"]
    cur.execute("SELECT COUNT(*) AS open_cases FROM cases WHERE status='open'")
    open_cases = cur.fetchone()["open_cases"]
    score = 100
    if critical_open:
        score -= min(50, critical_open * 20)
    if open_cases:
        score -= min(20, open_cases * 5)
    if recent_events == 0:
        score -= 15
    return {"health_score": max(score, 0), "recent_events_10m": recent_events, "critical_open": critical_open, "open_cases": open_cases}



def sanitize_windows_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Make the Windows endpoint tolerant to PowerShell JSON quirks.
    The agent runs on very different Windows/PowerShell versions, so the API
    accepts a permissive payload and normalizes types server-side instead of
    returning endless 400 responses.
    """
    payload = dict(payload or {})
    payload.setdefault("agent_id", payload.get("agentId") or "unknown-agent")
    payload.setdefault("hostname", payload.get("computer") or payload.get("host") or "unknown-host")
    payload.setdefault("os_version", payload.get("os") or "Windows")
    payload.setdefault("log_name", payload.get("channel") or "Windows")
    payload.setdefault("provider_name", payload.get("provider") or "")
    payload.setdefault("event_id", payload.get("id") or 0)
    payload.setdefault("record_id", payload.get("record") or None)
    payload.setdefault("level", payload.get("level_display") or "Information")
    payload.setdefault("time_created", payload.get("time") or datetime.now(timezone.utc).isoformat())
    payload.setdefault("message", payload.get("raw_log") or payload.get("description") or "")
    payload.setdefault("event_data", {})
    try:
        payload["event_id"] = int(payload.get("event_id") or 0)
    except Exception:
        payload["event_id"] = 0
    try:
        if payload.get("record_id") is not None:
            payload["record_id"] = int(payload.get("record_id"))
    except Exception:
        payload["record_id"] = None
    if not isinstance(payload.get("event_data"), dict):
        payload["event_data"] = {"raw_event_data": str(payload.get("event_data"))}
    # Pydantic/jsonb cannot store every exotic .NET object. Force simple strings where needed.
    cleaned = {}
    for k, v in payload["event_data"].items():
        if v is None or isinstance(v, (str, int, float, bool)):
            cleaned[str(k)] = v
        else:
            cleaned[str(k)] = str(v)
    payload["event_data"] = cleaned
    if payload.get("message") is None:
        payload["message"] = ""
    payload["message"] = str(payload.get("message"))[:6000]
    return payload


def process_windows_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    clean = sanitize_windows_payload(payload)
    data = WindowsEventInput(**clean)
    event = normalize_windows_event(data)
    event_id = insert_event(event)
    run_detection(event)
    run_windows_detection(event)
    cur = db_cursor()
    cur.execute("""INSERT INTO agents (agent_id, hostname, os_type, os_version, version, status, last_seen, metadata) VALUES (%s, %s, 'windows', %s, '10.3', 'online', NOW(), %s::jsonb) ON CONFLICT (agent_id) DO UPDATE SET hostname=EXCLUDED.hostname, os_version=EXCLUDED.os_version, version='10.3', status='online', last_seen=NOW(), metadata=agents.metadata || EXCLUDED.metadata""", (data.agent_id, data.hostname, data.os_version, json.dumps({"last_log_name": data.log_name, "last_event_id": data.event_id, "last_record_id": data.record_id})))
    conn.commit()
    return {"event_id": event_id, "event_action": event["event_action"], "severity": event["severity"]}


@app.post("/ingest-windows")
async def ingest_windows(request: Request, x_agent_token: Optional[str] = Header(default=None)):
    validate_agent_token(x_agent_token)
    raw = await request.body()
    try:
        text = raw.decode("utf-8-sig", errors="replace")
        payload = json.loads(text) if text.strip() else {}
    except Exception as exc:
        # Do not make the agent retry forever for a single malformed Windows event.
        # Store a compact diagnostic as an event and return 202.
        diag = {
            "agent_id": "unknown-agent",
            "hostname": "unknown-host",
            "log_name": "MiniSIEMAgent",
            "provider_name": "MiniSIEMAgent",
            "event_id": 0,
            "record_id": None,
            "level": "Warning",
            "time_created": datetime.now(timezone.utc).isoformat(),
            "message": f"Malformed Windows agent payload accepted and dropped: {exc}",
            "event_data": {"raw_prefix": raw[:200].decode('utf-8', errors='replace')},
        }
        try:
            result = process_windows_payload(diag)
            return {"status": "accepted_with_warning", "processed": 1, "result": result}
        except Exception:
            conn.rollback()
            return {"status": "dropped_malformed_payload", "processed": 0}

    items = payload.get("events") if isinstance(payload, dict) and isinstance(payload.get("events"), list) else [payload]
    results = []
    for item in items[:100]:
        if isinstance(item, dict):
            try:
                results.append(process_windows_payload(item))
            except Exception as exc:
                conn.rollback()
                # Keep the endpoint non-spammy: accept bad individual events and continue.
                results.append({"error": str(exc)[:300], "status": "event_dropped"})
    return {"status": "windows events accepted", "processed": len(results), "results": results[:10]}

@app.post("/agents/heartbeat")
def agent_heartbeat(data: AgentHeartbeatInput, x_agent_token: Optional[str] = Header(default=None)):
    validate_agent_token(x_agent_token)
    cur = db_cursor()
    cur.execute("""INSERT INTO agents (agent_id, hostname, os_type, os_version, version, status, last_seen, metadata) VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s::jsonb) ON CONFLICT (agent_id) DO UPDATE SET hostname=EXCLUDED.hostname, os_type=EXCLUDED.os_type, os_version=EXCLUDED.os_version, version=EXCLUDED.version, status=EXCLUDED.status, last_seen=NOW(), metadata=EXCLUDED.metadata""", (data.agent_id, data.hostname, data.os_type, data.os_version, data.version, data.status, json.dumps(data.metadata)))
    conn.commit()
    return {"status": "heartbeat stored"}

@app.get("/agents")
def list_agents(user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("""SELECT agent_id, hostname, os_type, os_version, version, status, last_seen, metadata, CASE WHEN last_seen > NOW() - INTERVAL '2 minutes' THEN true ELSE false END AS online FROM agents ORDER BY last_seen DESC NULLS LAST""")
    return cur.fetchall()

@app.get("/windows/summary")
def windows_summary(user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT COUNT(*) AS total FROM events WHERE source_type='windows_agent'")
    total = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) AS total FROM events WHERE source_type='windows_agent' AND event_time > NOW() - INTERVAL '1 hour'")
    last_hour = cur.fetchone()["total"]
    cur.execute("SELECT event_action, COUNT(*) AS count FROM events WHERE source_type='windows_agent' GROUP BY event_action ORDER BY count DESC LIMIT 12")
    actions = cur.fetchall()
    cur.execute("SELECT source_name AS hostname, COUNT(*) AS count FROM events WHERE source_type='windows_agent' GROUP BY source_name ORDER BY count DESC LIMIT 12")
    hosts = cur.fetchall()
    cur.execute("SELECT rule_name, COUNT(*) AS count FROM alerts WHERE rule_name ILIKE 'Windows%' OR rule_name ILIKE '%PowerShell%' OR rule_name ILIKE '%Defender%' GROUP BY rule_name ORDER BY count DESC LIMIT 12")
    alerts = cur.fetchall()
    return {"total_windows_events": total, "windows_events_last_hour": last_hour, "top_windows_actions": actions, "top_windows_hosts": hosts, "windows_alerts_by_rule": alerts}

@app.get("/ai/triage-alert/{alert_id}")
def ai_triage_alert(alert_id: int, user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT * FROM alerts WHERE id=%s", (alert_id,))
    alert = cur.fetchone()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    params = []
    conds = []
    if alert.get("src_ip"):
        conds.append("src_ip=%s")
        params.append(alert.get("src_ip"))
    if alert.get("user_name"):
        conds.append("user_name=%s")
        params.append(alert.get("user_name"))
    where = "WHERE " + " OR ".join(conds) if conds else ""
    cur.execute(f"SELECT id, event_time, event_action, severity, src_ip, user_name, service, source_name, raw_log FROM events {where} ORDER BY event_time DESC LIMIT 25", params)
    recent = cur.fetchall()
    result = local_ai_triage_from_alert(alert, recent)
    audit(user.get("sub"), "ai_triage_alert", {"alert_id": alert_id, "priority": result["priority"]})
    return result

@app.get("/ai/hunt-suggestions")
def ai_hunt_suggestions(user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT rule_name, severity, src_ip, user_name, service, description FROM alerts WHERE status='open' ORDER BY risk_score DESC, alert_time DESC LIMIT 10")
    alerts = cur.fetchall()
    suggestions = []
    for a in alerts:
        if a.get("src_ip"):
            suggestions.append(f"Buscar tots els esdeveniments de la IP {a['src_ip']} en las últimas 24 horas")
        if a.get("user_name"):
            suggestions.append(f"Revisar activitat de l’usuari {a['user_name']} y logons relacionados")
        if a.get("service") == "windows" or (a.get("rule_name") or "").lower().startswith("windows"):
            suggestions.append("Revisar esdeveniments Windows crítics: 1102, 4720, 4732, 7045, 4104 y Defender 1116")
    if not suggestions:
        suggestions = ["No hi ha alertes obertes. Valida que els agents estiguin vius i genera una prova controlada."]
    return {"suggestions": list(dict.fromkeys(suggestions))[:10], "based_on_open_alerts": len(alerts)}

@app.post("/ai/ask")
def ai_ask(data: AIPromptInput, user=Depends(verify_token)):
    q = data.question.lower()
    cur = db_cursor()
    cur.execute("SELECT COUNT(*) AS c FROM alerts WHERE status='open'")
    open_alerts = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM events WHERE source_type='windows_agent' AND event_time > NOW() - INTERVAL '1 hour'")
    win_hour = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM agents WHERE last_seen > NOW() - INTERVAL '2 minutes'")
    online_agents = cur.fetchone()["c"]
    if "windows" in q or "agente" in q:
        answer = f"Tens {online_agents} agents actius i {win_hour} esdeveniments Windows en l’última hora. Prioritza 4625/4624, 1102, 7045, 4720/4732, 4104 y Defender 1116."
    elif "prioridad" in q or "urgente" in q:
        answer = f"Hi ha {open_alerts} alertes obertes. Prioritza critical/high, especialmente Defender, audit log cleared, successful logon after failures y procesos sospechosos."
    else:
        answer = "Comença per alertes obertes high/critical, agrupa per IP/usuari/host, crea un incident si hi ha diverses senyals, executa el playbook i tanca amb nota d’evidència."
    audit(user.get("sub"), "ai_ask", {"question": data.question[:200]})
    return {"mode": "local_explainable_copilot", "answer": answer}


@app.post("/ai/context")
def ai_context(data: AIContextInput, user=Depends(verify_token)):
    """Copilot local contextual en català. No envia dades fora del servidor."""
    q = (data.question or "").strip().lower()
    cur = db_cursor()
    alert = None
    event = None
    recent = []
    if data.alert_id:
        cur.execute("SELECT * FROM alerts WHERE id=%s", (data.alert_id,))
        alert = cur.fetchone()
        if alert:
            params, conds = [], []
            if alert.get("src_ip"):
                conds.append("src_ip=%s"); params.append(alert.get("src_ip"))
            if alert.get("user_name"):
                conds.append("user_name=%s"); params.append(alert.get("user_name"))
            if alert.get("service"):
                conds.append("service=%s"); params.append(alert.get("service"))
            where = "WHERE " + " OR ".join(conds) if conds else ""
            cur.execute(f"SELECT id,event_time,event_action,severity,src_ip,user_name,service,source_name,raw_log,risk_score_base FROM events {where} ORDER BY event_time DESC LIMIT 12", params)
            recent = cur.fetchall()
    if data.event_id:
        cur.execute("SELECT * FROM events WHERE id=%s", (data.event_id,))
        event = cur.fetchone()
    cur.execute("SELECT COUNT(*) AS c FROM alerts WHERE status='open' AND severity IN ('critical','high')")
    high_open = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM agents WHERE last_seen > NOW() - INTERVAL '2 minutes'")
    agents_online = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM events WHERE event_time > NOW() - INTERVAL '1 hour'")
    events_hour = cur.fetchone()["c"]

    priority = "Baixa"
    verdict = "Ara mateix no sembla una emergència, però cal revisar el context."
    evidence = [f"Agents actius: {agents_online}", f"Esdeveniments última hora: {events_hour}", f"Alertes high/critical obertes: {high_open}"]
    actions = ["Revisa la línia temporal", "Filtra per host/usuari/IP", "Si hi ha més d'una alerta relacionada, crea un incident"]

    if alert:
        sev = (alert.get("severity") or "medium").lower()
        score = int(alert.get("risk_score") or 0)
        priority = "Crítica" if sev == "critical" or score >= 90 else ("Alta" if sev == "high" or score >= 70 else "Mitjana")
        verdict = f"Aquesta alerta s'ha de tractar amb prioritat {priority.lower()}. Regla: {alert.get('rule_name')}. Risc: {score}."
        evidence += [f"Regla: {alert.get('rule_name')}", f"Severitat: {sev}", f"Risc: {score}", f"IP: {alert.get('src_ip') or '-'}", f"Usuari: {alert.get('user_name') or '-'}", f"Esdeveniments relacionats: {len(recent)}"]
        rule = (alert.get("rule_name") or "").lower()
        if "download guard" in rule:
            actions = ["No executis el fitxer fins revisar-lo", "Obre Detalls i comprova extensions dins del ZIP", "Si conté .exe/.ps1/.bat/.js/.lnk/.scr, marca'l com a sospitós", "Crea un incident si l'usuari el va executar", "Calcula i guarda el hash SHA256 com a evidència"]
        elif "defender" in rule or "malware" in rule:
            actions = ["Prioritat immediata", "Comprova l'acció aplicada per Defender", "Revisa persistència: serveis, tasques i comptes", "Aïlla l'equip si hi ha execució confirmada", "Crea incident i conserva evidències"]
        elif "failed logon" in rule or "brute" in rule:
            actions = ["Busca logon correcte posterior", "Agrupa per IP i usuari", "Revisa si l'origen és extern o inesperat", "Bloqueja origen si aplica", "Documenta la finestra temporal"]
        elif "suspicious process" in rule or "powershell" in rule:
            actions = ["Revisa command line i procés pare", "Busca Sysmon 1/3 relacionats", "Comprova descàrregues recents", "Aïlla si hi ha credencials/LSASS/encoded command", "Vincula a un cas"]
    elif event:
        score = int(event.get("risk_score_base") or 0)
        priority = "Alta" if score >= 60 else ("Mitjana" if score >= 35 else "Baixa")
        verdict = f"Aquest esdeveniment té prioritat {priority.lower()} amb risc base {score}. Acció: {event.get('event_action')}."
        evidence += [f"Host/font: {event.get('source_name') or event.get('source_type')}", f"Servei: {event.get('service') or '-'}", f"IP: {event.get('src_ip') or '-'}", f"Usuari: {event.get('user_name') or '-'}"]
        actions = ["Correlaciona amb alertes obertes", "Filtra per host i usuari", "Revisa el raw log", "Crea watchlist si l'indicador és rellevant"]
    elif "què faig" in q or "preocupar" in q or "preocupar-me" in q or "priorit" in q:
        verdict = f"Comença per les {high_open} alertes high/critical obertes. Si n'hi ha de Windows, Defender, PowerShell o Download Guard, revisa-les primer."
        actions = ["Obre Alertes i ordena mentalment per risc", "Pregunta'm per una alerta concreta", "Crea un incident si hi ha més d'una evidència", "Tanca amb nota quan estigui justificat"]
    else:
        verdict = "Et puc ajudar a interpretar alertes, decidir prioritat, revisar descàrregues i proposar passos de resposta."

    return {"mode": "copilot_local_catala", "priority": priority, "verdict": verdict, "evidence": evidence, "actions": actions, "context": {"page": data.page, "alert_id": data.alert_id, "event_id": data.event_id}}

PAGE_GUIDE = {
    "overview": {
        "title": "Visió general",
        "explain": "Aquesta pantalla és el resum executiu del SIEM. Serveix per veure ràpidament volum d'esdeveniments, alertes obertes, severitats, activitat recent, IPs principals i salut del sistema.",
        "how": ["Comprova si hi ha alertes high/critical obertes", "Revisa la línia temporal per veure pics", "Si una IP apareix al Top IPs, obre Esdeveniments o IOC per investigar-la", "Si la salut baixa, revisa agents, backend i base de dades"],
    },
    "alerts": {
        "title": "Alertes",
        "explain": "Aquesta pantalla és la cua SOC. Mostra incidents generats pel motor de regles: Windows sospitós, serveis instal·lats, Defender, Download Guard, força bruta, PowerShell, etc. Des d'aquí fas triatge: reconèixer, tancar, marcar fals positiu o crear un incident.",
        "how": ["Prioritza critical/high", "Obre la alerta i mira regla, risc, host, usuari i MITRE", "Pregunta al Copilot si t'hauries de preocupar", "Si hi ha diverses alertes relacionades, crea un incident i vincula-les"],
    },
    "events": {
        "title": "Esdeveniments",
        "explain": "Aquesta pantalla mostra logs reals ja normalitzats. No són línies brutes soltes: el SIEM els transforma a acció, severitat, usuari, IP, servei, host, raw log i risc base. Per defecte es filtra soroll i es mostren esdeveniments interessants.",
        "how": ["Filtra per severitat, servei o IP", "Obre el raw log per conservar evidència", "Analitza un esdeveniment concret amb el Copilot", "Si hi ha IP/usuari sospitós, busca correlacions en Alertes i IOC"],
    },
    "agents": {
        "title": "Agents",
        "explain": "Aquesta pàgina controla els equips monitoritzats. Mostra agents Windows instal·lats, estat online/offline, versió, últim heartbeat i resum d'activitat Windows. També inclou Download Guard per revisar descàrregues i ZIPs.",
        "how": ["Verifica que el teu PC aparegui ONLINE", "Si no apareix, revisa la tasca programada MiniSIEMAgent i el token", "Revisa els top events Windows", "Descarrega l'agent des d'aquesta pàgina o la landing"],
    },
    "hunting": {
        "title": "Cerca guiada",
        "explain": "Aquesta pàgina permet fer consultes en llenguatge natural però sense executar SQL lliure. La frase es converteix a filtres segurs allowlist i SQL parametrat.",
        "how": ["Prova: mostra alertes high de Windows última hora", "Prova: failed login de la IP 1.2.3.4", "Usa suggeriments IA per hunting", "Exporta o documenta resultats si formen part d'un incident"],
    },
    "cases": {
        "title": "Incidents",
        "explain": "Serveix per agrupar alertes i evidències dins d'un cas SOC. És la part de gestió: què ha passat, quin impacte té, quines proves tens i com ho has tancat.",
        "how": ["Crea un incident quan hi ha diverses alertes relacionades", "Assigna severitat coherent", "Vincula alertes", "Tanca'l només quan hi hagi evidència i resolució"],
    },
    "ioc": {
        "title": "IOC / Watchlist",
        "explain": "Permet investigar indicadors: IPs, hashes o valors sospitosos. La watchlist local genera alertes quan un indicador torna a aparèixer en logs reals.",
        "how": ["Busca una IP sospitosa", "Afegeix-la a watchlist si vols monitoritzar-la", "Revisa si ja hi ha events o alertes vinculades", "Usa-ho com a evidència dins d'un incident"],
    },
    "rules": {
        "title": "Regles",
        "explain": "Mostra el catàleg de deteccions. Cada regla té severitat, risc, MITRE i estat activa/inactiva. És el motor que transforma events en alertes.",
        "how": ["Mantén actives les regles defensives principals", "Desactiva temporalment les sorolloses durant proves", "Justifica les regles a la memòria amb MITRE", "Revisa falsos positius i ajusta el risc"],
    },
    "playbooks": {
        "title": "Playbooks",
        "explain": "Són guies de resposta. Quan apareix una alerta, el playbook et diu passos de contenció, anàlisi, evidència i recuperació.",
        "how": ["Busca el playbook associat a la regla", "Segueix passos de triatge", "Documenta evidències", "Tanca l'alerta o escala a incident"],
    },
    "audit": {
        "title": "Auditoria",
        "explain": "Registra accions importants de l'usuari: consultes, triatge, canvis d'estat, ús del Copilot i accions SOC. Dona traçabilitat per al TFG.",
        "how": ["Revisa qui ha fet cada acció", "Usa-ho per demostrar traçabilitat", "Inclou captura a la memòria", "Comprova que no apareguin dades sensibles innecessàries"],
    },
}

EVENT_ID_GUIDE = {
    "4625": "4625 és un inici de sessió fallit. És rellevant si hi ha molts intents, origen extern o usuari privilegiat.",
    "4624": "4624 és un inici de sessió correcte. És crític si passa després de molts 4625 del mateix origen o usuari.",
    "4672": "4672 indica privilegis especials assignats a un logon. És normal per administradors, però sospitós si l'usuari no hauria de tenir privilegis.",
    "1102": "1102 indica que s'ha esborrat el registre d'auditoria. Això és d'alta prioritat perquè pot ser intent d'ocultar activitat.",
    "7045": "7045 indica instal·lació d'un servei Windows. Pot ser legítim, però també és tècnica habitual de persistència.",
    "4104": "4104 és PowerShell Script Block Logging. És molt útil per veure ordres PowerShell sospitoses, encoded commands o descàrregues.",
    "4688": "4688 és creació de procés si tens auditoria activada. Permet veure command line i processos potencialment maliciosos.",
    "1116": "1116 és detecció de malware per Microsoft Defender. S'ha de revisar acció aplicada i fitxer afectat.",
}

PROJECT_KNOWLEDGE = {
    "arquitectura": "Arquitectura: agents Windows/Linux/Docker -> API FastAPI -> PostgreSQL -> normalització -> enriquiment -> motor de regles -> alertes -> incidents/playbooks/auditoria -> dashboard i Copilot.",
    "siem": "Un SIEM centralitza esdeveniments de seguretat, els normalitza, aplica correlació/regles i ajuda a investigar incidents. Aquest projecte és una versió lleugera per entorns personals.",
    "agent": "L'agent Windows s'executa com a tasca programada, llegeix Event Viewer, Defender, PowerShell/Sysmon si existeix, envia heartbeats i events al backend, i revisa Descàrregues amb Download Guard.",
    "download": "Download Guard observa la carpeta Descàrregues, calcula SHA256 dels fitxers i inspecciona ZIPs per detectar executables, scripts, macros o dreceres sospitoses abans d'executar-los.",
    "privacitat": "El sistema treballa en local. El Copilot integrat no envia dades fora del servidor. Els logs poden contenir usuaris, rutes i IPs, així que cal explicar retenció i minimització a la memòria.",
    "demo": "Demo recomanada: 1) mostra landing, 2) login, 3) agent online, 4) genera event Windows real, 5) mostra alerta, 6) pregunta al Copilot, 7) crea incident, 8) mostra auditoria.",
    "ips": "No tots els events Windows tenen IP. Logons locals, serveis instal·lats i PowerShell sovint no porten IP. Les IPs apareixen més en RDP/SMB/logons de xarxa o quan el XML de Windows inclou IpAddress.",
}

def _safe_int(x, default=0):
    try:
        return int(x or default)
    except Exception:
        return default

def _snapshot(cur) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, sql in {
        "events_total": "SELECT COUNT(*) c FROM events",
        "events_hour": "SELECT COUNT(*) c FROM events WHERE event_time > NOW() - INTERVAL '1 hour'",
        "alerts_open": "SELECT COUNT(*) c FROM alerts WHERE status='open'",
        "alerts_high": "SELECT COUNT(*) c FROM alerts WHERE status='open' AND severity IN ('critical','high')",
        "agents_online": "SELECT COUNT(*) c FROM agents WHERE last_seen > NOW() - INTERVAL '2 minutes'",
        "windows_hour": "SELECT COUNT(*) c FROM events WHERE source_type='windows_agent' AND event_time > NOW() - INTERVAL '1 hour'",
    }.items():
        try:
            cur.execute(sql); out[key] = cur.fetchone()["c"]
        except Exception:
            out[key] = 0
    try:
        cur.execute("SELECT rule_name,severity,risk_score,description,src_ip,user_name,service FROM alerts WHERE status='open' ORDER BY risk_score DESC, alert_time DESC LIMIT 5")
        out["top_alerts"] = cur.fetchall()
    except Exception:
        out["top_alerts"] = []
    try:
        cur.execute("SELECT event_action, COUNT(*) count FROM events WHERE event_time > NOW() - INTERVAL '1 hour' GROUP BY event_action ORDER BY count DESC LIMIT 5")
        out["top_actions"] = cur.fetchall()
    except Exception:
        out["top_actions"] = []
    return out

def _answer_about_alert(alert: Dict[str, Any], recent: List[Dict[str, Any]], question: str) -> List[str]:
    sev = (alert.get("severity") or "medium").lower()
    score = _safe_int(alert.get("risk_score"))
    priority = "crítica" if sev == "critical" or score >= 90 else ("alta" if sev == "high" or score >= 70 else "mitjana" if score >= 40 else "baixa")
    lines = [
        f"Sí, aquesta alerta mereix atenció de prioritat **{priority}**.",
        f"Regla: **{alert.get('rule_name')}**. Severitat: **{sev}**. Risc: **{score}**.",
        f"Descripció: {alert.get('description') or '-'}",
        f"Context: host/servei **{alert.get('service') or '-'}**, IP **{alert.get('src_ip') or '-'}**, usuari **{alert.get('user_name') or '-'}**.",
    ]
    if recent:
        lines.append(f"He trobat **{len(recent)}** esdeveniments relacionats recents per correlacionar.")
    rule = (alert.get("rule_name") or "").lower()
    steps = []
    if "service installed" in rule or "servei" in rule:
        steps = ["Comprova el nom i ruta del servei instal·lat", "Verifica si l'has instal·lat tu o un software legítim", "Busca PowerShell/Process Creation al mateix minut", "Si és desconegut, crea incident i conserva evidències"]
    elif "powershell" in rule or "suspicious process" in rule:
        steps = ["Revisa command line completa", "Busca encoded command, descàrrega remota, LSASS, certutil o rundll32", "Comprova Descàrregues recents", "Si hi ha execució maliciosa, aïlla l'equip i obre incident"]
    elif "download" in rule or "zip" in rule:
        steps = ["No executis el fitxer", "Revisa el contingut del ZIP", "Comprova extensions executables/scripts/macros", "Guarda SHA256 com a evidència", "Analitza amb Defender abans d'obrir"]
    elif "defender" in rule or "malware" in rule:
        steps = ["Prioritat immediata", "Mira acció aplicada per Defender", "Executa anàlisi complet", "Revisa persistència", "Obre incident"]
    else:
        steps = ["Revisa events relacionats", "Agrupa per host/usuari/IP", "Comprova si hi ha repetició", "Aplica el playbook corresponent", "Tanca amb nota d'evidència"]
    lines.append("Passos recomanats:\n" + "\n".join([f"{i+1}. {s}" for i, s in enumerate(steps)]))
    return lines

def _answer_about_page(page: str, snap: Dict[str, Any]) -> List[str]:
    g = PAGE_GUIDE.get(page, PAGE_GUIDE["overview"])
    lines = [f"Estàs a **{g['title']}**.", g["explain"], "Què hauries de mirar aquí:"]
    lines += [f"- {x}" for x in g["how"]]
    lines.append(f"Estat actual: {snap.get('events_hour',0)} esdeveniments l'última hora, {snap.get('alerts_open',0)} alertes obertes, {snap.get('alerts_high',0)} high/critical i {snap.get('agents_online',0)} agents online.")
    return lines

def _keyword_answer(q: str, snap: Dict[str, Any], page: str) -> Optional[List[str]]:
    ql = q.lower()
    if any(k in ql for k in ["aquesta pàgina", "esta pagina", "esta página", "on estic", "donde estoy", "què fa", "que hace"]):
        return _answer_about_page(page, snap)
    for eid, txt in EVENT_ID_GUIDE.items():
        if eid in ql:
            return [txt, "Per decidir si és preocupant, mira host, usuari, hora, repetició i si hi ha alertes relacionades."]
    if any(k in ql for k in ["ip", "ips", "no veo ip", "no veig ip", "top ip"]):
        return [PROJECT_KNOWLEDGE["ips"], f"Ara mateix el SIEM veu {snap.get('events_hour',0)} esdeveniments l'última hora i {snap.get('alerts_open',0)} alertes obertes. Si Top IP surt '-', probablement els events recents són locals de Windows sense camp d'origen de xarxa.", "Per provar IPs reals, genera un logon de xarxa/RDP/SMB o revisa events 4625 que tinguin 'IpAddress' al XML."]
    if any(k in ql for k in ["arquitectura", "components", "como funciona", "com funciona"]):
        return [PROJECT_KNOWLEDGE["arquitectura"], "Flux: captura -> normalització -> enriquiment -> regles -> alertes -> incidents -> auditoria -> visualització."]
    if "siem" in ql:
        return [PROJECT_KNOWLEDGE["siem"], "En aquest TFG el valor és que està orientat a entorns personals, amb agent Windows real, Docker/Linux, Download Guard i consultes segures."]
    if any(k in ql for k in ["agent", "instal", "windows"]):
        return [PROJECT_KNOWLEDGE["agent"], f"Agents online ara mateix: {snap.get('agents_online',0)}. Events Windows l'última hora: {snap.get('windows_hour',0)}."]
    if any(k in ql for k in ["download", "descàrrega", "descarga", "zip", "rar"]):
        return [PROJECT_KNOWLEDGE["download"], "Limitació honesta: pot alertar i inspeccionar, però bloquejar al 100% abans d'executar requereix AppLocker, WDAC o integració més profunda amb Defender."]
    if any(k in ql for k in ["demo", "present", "defensa", "provar", "probar"]):
        return [PROJECT_KNOWLEDGE["demo"], "Per lluir-ho: pregunta'm durant la demo 'què fa aquesta pàgina?' i després selecciona una alerta i pregunta 'm'hauria de preocupar?'."]
    if any(k in ql for k in ["privacitat", "privacy", "rgpd", "datos", "dades"]):
        return [PROJECT_KNOWLEDGE["privacitat"], "Per al TFG, documenta minimització, retenció, execució local i no enviament de dades a serveis externs."]
    if any(k in ql for k in ["prioritat", "prioridad", "preocupar", "preocuparme", "preocupar-me", "què faig", "que hago"]):
        lines = [f"Ara mateix hi ha **{snap.get('alerts_high',0)}** alertes high/critical obertes i **{snap.get('alerts_open',0)}** obertes en total."]
        tas = snap.get("top_alerts") or []
        if tas:
            lines.append("Jo prioritzaria aquestes:")
            lines += [f"- {a.get('rule_name')} · {a.get('severity')} · risc {a.get('risk_score')} · {a.get('description')}" for a in tas[:3]]
        lines.append("Regla pràctica: primer critical/high, després Defender/PowerShell/servei instal·lat/Download Guard, després la resta.")
        return lines
    return None

@app.post("/ai/chat")
def ai_chat(data: AIChatInput, user=Depends(verify_token)):
    """Assistent conversacional local per al projecte. Respon en català i usa context real del SIEM."""
    q = (data.message or "").strip()
    if not q:
        raise HTTPException(status_code=400, detail="Missatge buit")
    cur = db_cursor()
    snap = _snapshot(cur)
    alert = None
    event = None
    recent: List[Dict[str, Any]] = []
    if data.alert_id:
        cur.execute("SELECT * FROM alerts WHERE id=%s", (data.alert_id,))
        alert = cur.fetchone()
        if alert:
            params, conds = [], []
            if alert.get("src_ip"):
                conds.append("src_ip=%s"); params.append(alert.get("src_ip"))
            if alert.get("user_name"):
                conds.append("user_name=%s"); params.append(alert.get("user_name"))
            if alert.get("service"):
                conds.append("service=%s"); params.append(alert.get("service"))
            where = "WHERE " + " OR ".join(conds) if conds else ""
            cur.execute(f"SELECT id,event_time,event_action,severity,src_ip,user_name,service,source_name,raw_log,risk_score_base FROM events {where} ORDER BY event_time DESC LIMIT 10", params)
            recent = cur.fetchall()
    if data.event_id:
        cur.execute("SELECT * FROM events WHERE id=%s", (data.event_id,))
        event = cur.fetchone()
    if alert and any(k in q.lower() for k in ["preocupar", "preocupar-me", "preocuparme", "analitza", "analiza", "què faig", "que hago", "risc", "riesgo", "prior"]):
        lines = _answer_about_alert(alert, recent, q)
    elif event and any(k in q.lower() for k in ["aquest", "este", "event", "esdeveniment", "preocupar", "analitza", "analiza", "què faig", "que hago"]):
        score = _safe_int(event.get("risk_score_base"))
        lines = [f"Aquest esdeveniment és **{event.get('event_action')}** amb risc base **{score}**.", f"Host/font: {event.get('source_name') or event.get('source_type')}. Servei: {event.get('service') or '-'}, usuari: {event.get('user_name') or '-'}, IP: {event.get('src_ip') or '-' }.", "Jo revisaria el raw log, buscaria events del mateix host/usuari en els minuts propers i comprovaria si ha generat alguna alerta."]
    else:
        lines = _keyword_answer(q, snap, data.page) or [
            "Et puc ajudar amb qualsevol part del projecte: arquitectura, agents, alertes, events, Download Guard, regles, playbooks, demo o memòria.",
            "Per exemple pregunta: 'què fa aquesta pàgina?', 'm'hauria de preocupar aquesta alerta?', 'per què no veig IPs?', 'com faig una demo?', o 'explica'm l'arquitectura'.",
            f"Context actual: pàgina **{PAGE_GUIDE.get(data.page, PAGE_GUIDE['overview'])['title']}**, {snap.get('events_hour',0)} events l'última hora, {snap.get('alerts_open',0)} alertes obertes i {snap.get('agents_online',0)} agents online.",
        ]
    audit(user.get("sub"), "ai_chat", {"question": q[:300], "page": data.page, "alert_id": data.alert_id, "event_id": data.event_id})
    return {
        "mode": "copilot_soc_conversacional_local",
        "language": "ca",
        "answer": "\n\n".join(lines),
        "context": {"page": data.page, "alert_id": data.alert_id, "event_id": data.event_id},
        "snapshot": snap,
        "suggested_questions": ["Què fa aquesta pàgina?", "M'hauria de preocupar?", "Per què no veig IPs?", "Com faig una demo per al TFG?", "Explica'm l'arquitectura"],
    }

NL_STOPWORDS = {
    "a", "al", "als", "amb", "and", "ara", "de", "del", "dels", "el", "els", "en", "es", "i", "la", "las", "les", "los", "o", "per", "por", "que", "the", "to", "un", "una", "y",
    "revisar", "revisa", "mostrar", "mostra", "muestra", "buscar", "busca", "ver", "veure", "quiero", "vull", "relacionado", "relacionados", "relacionades", "relacionats",
    "activitat", "actividad", "events", "eventos", "esdeveniments", "alertes", "alertas", "alert", "alerts", "ultims", "ultimas", "últims", "últimas", "ultimes", "últimes",
}

NL_SEVERITY_MAP = {
    "critical": "critical", "critica": "critical", "criticas": "critical", "critiques": "critical", "crític": "critical", "crítica": "critical", "critiques": "critical",
    "high": "high", "alta": "high", "alt": "high", "altes": "high", "altas": "high", "greu": "high", "graves": "high",
    "medium": "medium", "media": "medium", "mitja": "medium", "mitjana": "medium", "mitges": "medium",
    "low": "low", "baixa": "low", "baix": "low", "baixes": "low", "baja": "low", "bajas": "low",
    "info": "info", "informativa": "info", "informatiu": "info", "informativos": "info", "informatius": "info",
}

NL_EVENT_KEYWORDS = {
    "logon": [
        "logon", "logons", "login", "logins", "inicio sesion", "inici sessio", "autenticacio", "autenticacion",
        "windows_successful_logon", "windows_failed_logon", "4624", "4625", "5379", "4798", "4100",
    ],
    "failed_logon": ["fallido", "fallits", "fallides", "failed", "failed logon", "4625", "error login", "login fallit"],
    "successful_logon": ["correcte", "correctos", "exitos", "exitós", "successful", "4624", "login correcte"],
    "powershell": ["powershell", "scriptblock", "encodedcommand", "iex", "downloadstring", "4104", "4103", "4100"],
    "defender": ["defender", "malware", "virus", "threat", "amenaca", "amenaza", "1116"],
    "download_guard": ["download", "downloads", "descarrega", "descarregues", "descarga", "descargas", "zip", "ps1", "exe", "bat", "quarantena", "quarantine"],
    "fim": ["fim", "integritat", "integridad", "hosts", "fitxer sensible", "archivo sensible", "file integrity"],
    "network": ["xarxa", "network", "router", "firewall", "dns", "dhcp", "syslog", "tplink", "tp-link", "telemetria", "red"],
    "ssh": ["ssh", "sshd"],
    "web": ["web", "nginx", "http", "404", "tomcat", "apache"],
    "edr": ["edr", "delete_file", "quarantine_file", "quarantena", "quarantine", "eliminacio", "eliminacion"],
}

NL_SERVICE_MAP = {
    "windows": ["windows", "win", "microsoft"],
    "powershell": ["powershell", "scriptblock", "4104", "encodedcommand"],
    "windows_defender": ["defender", "malware", "1116"],
    "download_guard": ["download_guard", "download guard", "descarregues", "descargas", "downloads", "zip", "ps1", "exe", "bat"],
    "fim": ["fim", "integritat", "integridad"],
    "network": ["network", "xarxa", "router", "syslog", "dns", "dhcp", "firewall"],
    "ssh": ["ssh", "sshd"],
    "nginx": ["nginx", "web", "http", "404"],
}

NL_DESTRUCTIVE_PATTERNS = [
    r"\b(drop|truncate|insert|update|delete\s+from|alter|create\s+table|grant|revoke)\b",
    r"\b(elimina|eliminar|borra|borrar|esborra|esborrar|suprimeix|destrueix)\b.*\b(events|eventos|esdeveniments|alertes|alertas|taula|tabla|base de dades|database)\b",
]


def _nl_norm(text: str) -> str:
    text = (text or "").lower().replace("’", "'").replace("`", "'")
    text = unicodedata.normalize("NFD", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    text = re.sub(r"[^a-z0-9_.@:/\\' -]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _nl_contains(q: str, words: List[str]) -> bool:
    return any(_nl_norm(w) in q for w in words)


def _nl_is_destructive(q: str) -> bool:
    return any(re.search(p, q) for p in NL_DESTRUCTIVE_PATTERNS)


def _nl_target_table(q: str) -> str:
    alert_words = ["alerta", "alertes", "alertas", "alerts", "incidencia", "incident", "incidents", "soc queue", "cola"]
    event_words = ["event", "events", "evento", "eventos", "esdeveniment", "esdeveniments", "log", "logs", "raw"]
    if _nl_contains(q, alert_words) and not _nl_contains(q, event_words):
        return "alerts"
    return "events"


def _nl_extract_limit(q: str, default: int) -> int:
    m = re.search(r"\b(?:limit|limite|limitació|limitacio|top|primeros|primeres|ultimos|ultimes)\s+(\d{1,3})\b", q)
    if not m:
        m = re.search(r"\b(\d{1,3})\s+(?:resultats|resultados|events|eventos|alertes|alertas|logs)\b", q)
    if m:
        return max(1, min(int(m.group(1)), 200))
    return max(1, min(default, 200))


def _nl_time_filter(q: str) -> Optional[str]:
    if re.search(r"\b(5|cinc)\s*(min|minuts|minutos|minutes)\b", q):
        return "event_time > NOW() - INTERVAL '5 minutes'"
    if re.search(r"\b(10|deu|diez)\s*(min|minuts|minutos|minutes)\b", q):
        return "event_time > NOW() - INTERVAL '10 minutes'"
    if re.search(r"\b(15|quinze|quince)\s*(min|minuts|minutos|minutes)\b", q):
        return "event_time > NOW() - INTERVAL '15 minutes'"
    if re.search(r"\b(30|trenta|treinta)\s*(min|minuts|minutos|minutes)\b", q):
        return "event_time > NOW() - INTERVAL '30 minutes'"
    if any(x in q for x in ["ultima hora", "ultimas hora", "ultimes hora", "last hour", "darrera hora", "última hora"]):
        return "event_time > NOW() - INTERVAL '1 hour'"
    if re.search(r"\b(24|vint-i-quatre|veinticuatro)\s*(h|hores|horas|hours)\b", q) or any(x in q for x in ["ultimas 24", "ultimes 24", "ultims 24", "ultimos 24", "last 24"]):
        return "event_time > NOW() - INTERVAL '24 hours'"
    if any(x in q for x in ["avui", "hoy", "today"]):
        return "event_time >= date_trunc('day', NOW())"
    if any(x in q for x in ["ahir", "ayer", "yesterday"]):
        return "event_time >= date_trunc('day', NOW() - INTERVAL '1 day') AND event_time < date_trunc('day', NOW())"
    if any(x in q for x in ["setmana", "semana", "week", "7 dies", "7 dias", "7 days"]):
        return "event_time > NOW() - INTERVAL '7 days'"
    return None


def _nl_extract_user(q: str) -> Optional[str]:
    patterns = [
        r"\b(?:usuari|usuario|user|compte|cuenta|account)\s+([a-z0-9._@-]{2,64})\b",
        r"\b(?:de|del|dels|para|per)\s+(?:l'|el\s+|la\s+)?(?:usuari|usuario|user)\s+([a-z0-9._@-]{2,64})\b",
    ]
    for p in patterns:
        m = re.search(p, q)
        if m:
            val = m.group(1).strip(" .,:;'")
            if val and val not in NL_STOPWORDS:
                return val
    return None


def _nl_extract_host(q: str) -> Optional[str]:
    m = re.search(r"\b(?:host|hostname|equip|equipo|pc|maquina|màquina)\s+([a-z0-9._-]{3,80})\b", q)
    if m:
        val = m.group(1).strip(" .,:;'")
        if val and val not in NL_STOPWORDS:
            return val
    m = re.search(r"\b(desktop-[a-z0-9._-]+)\b", q)
    return m.group(1) if m else None


def _nl_add_text_search(q: str, filters: List[str], params: List[Any], table: str):
    quoted = re.findall(r"['\"]([^'\"]{3,120})['\"]", q)
    for phrase in quoted[:2]:
        term = f"%{phrase}%"
        if table == "alerts":
            filters.append("(rule_name ILIKE %s OR description ILIKE %s OR service ILIKE %s OR user_name ILIKE %s OR src_ip ILIKE %s)")
            params.extend([term, term, term, term, term])
        else:
            filters.append("(event_action ILIKE %s OR message ILIKE %s OR raw_log ILIKE %s OR service ILIKE %s OR user_name ILIKE %s OR src_ip ILIKE %s)")
            params.extend([term, term, term, term, term, term])


def _nl_build_filters(q: str, table: str):
    filters: List[str] = []
    params: List[Any] = []
    explanation: List[str] = []

    # Severitat
    for word, sev in NL_SEVERITY_MAP.items():
        if re.search(rf"\b{re.escape(word)}\b", q):
            filters.append("severity = %s")
            params.append(sev)
            explanation.append(f"severity={sev}")
            break

    # IP exacta
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", q)
    if ip_match:
        filters.append("src_ip = %s")
        params.append(ip_match.group(0))
        explanation.append(f"src_ip={ip_match.group(0)}")

    # Usuari
    user = _nl_extract_user(q)
    if user:
        term = f"%{user}%"
        if table == "alerts":
            filters.append("(user_name ILIKE %s OR description ILIKE %s)")
            params.extend([term, term])
        else:
            filters.append("(user_name ILIKE %s OR message ILIKE %s OR raw_log ILIKE %s)")
            params.extend([term, term, term])
        explanation.append(f"user~{user}")

    # Host/equip
    host = _nl_extract_host(q)
    if host:
        term = f"%{host}%"
        if table == "alerts":
            filters.append("(description ILIKE %s OR metadata::text ILIKE %s)")
            params.extend([term, term])
        else:
            filters.append("(source_name ILIKE %s OR raw_log ILIKE %s OR metadata::text ILIKE %s)")
            params.extend([term, term, term])
        explanation.append(f"host~{host}")

    # Temps
    tf = _nl_time_filter(q)
    if tf:
        filters.append(tf)
        explanation.append("time_window")

    # Serveis/fonts generals
    for service, words in NL_SERVICE_MAP.items():
        if _nl_contains(q, words):
            if table == "alerts":
                if service == "windows":
                    filters.append("(service ILIKE %s OR rule_name ILIKE %s OR description ILIKE %s)")
                    params.extend(["%windows%", "%windows%", "%windows%"])
                elif service == "network":
                    filters.append("(service ILIKE %s OR rule_name ILIKE %s OR description ILIKE %s)")
                    params.extend(["%network%", "%network%", "%router%"])
                else:
                    filters.append("(service ILIKE %s OR rule_name ILIKE %s OR description ILIKE %s)")
                    term = f"%{service}%"
                    params.extend([term, term, term])
            else:
                if service == "windows":
                    filters.append("(source_type = %s OR service ILIKE %s OR source_name ILIKE %s)")
                    params.extend(["windows_agent", "%windows%", "%windows%"])
                elif service == "network":
                    filters.append("(source_type ILIKE %s OR service ILIKE %s OR event_action ILIKE %s OR raw_log ILIKE %s)")
                    params.extend(["%network%", "%network%", "%router%", "%router%"])
                else:
                    filters.append("(service ILIKE %s OR event_action ILIKE %s OR raw_log ILIKE %s)")
                    term = f"%{service}%"
                    params.extend([term, term, term])
            explanation.append(f"service~{service}")
            break

    # Tipus d'esdeveniment / intenció SOC
    event_groups = []
    for group, words in NL_EVENT_KEYWORDS.items():
        if _nl_contains(q, words):
            event_groups.append(group)

    # Si diu logon/login, buscar tant accions conegudes com raw log de Windows
    if "logon" in event_groups:
        term = "%logon%"
        if table == "alerts":
            filters.append("(rule_name ILIKE %s OR description ILIKE %s OR service ILIKE %s)")
            params.extend([term, term, "%windows%"])
        else:
            filters.append("(event_action IN (%s,%s,%s,%s,%s,%s) OR event_action ILIKE %s OR message ILIKE %s OR raw_log ILIKE %s)")
            params.extend([
                "windows_successful_logon", "windows_failed_logon", "successful_login", "failed_login", "windows_event_4624", "windows_event_4625", "%logon%", "%logon%", "%logon%"
            ])
        explanation.append("logon_activity")
    elif "failed_logon" in event_groups:
        if table == "events":
            filters.append("(event_action IN (%s,%s,%s) OR message ILIKE %s OR raw_log ILIKE %s)")
            params.extend(["windows_failed_logon", "failed_login", "windows_event_4625", "%failed%", "%4625%"])
        else:
            filters.append("(rule_name ILIKE %s OR description ILIKE %s)")
            params.extend(["%failed%", "%4625%"])
        explanation.append("failed_logon")
    elif "successful_logon" in event_groups:
        if table == "events":
            filters.append("(event_action IN (%s,%s,%s) OR message ILIKE %s OR raw_log ILIKE %s)")
            params.extend(["windows_successful_logon", "successful_login", "windows_event_4624", "%successful%", "%4624%"])
        else:
            filters.append("(rule_name ILIKE %s OR description ILIKE %s)")
            params.extend(["%successful%", "%4624%"])
        explanation.append("successful_logon")
    else:
        # Altres grups
        group_to_terms = {
            "powershell": ["%powershell%", "%scriptblock%", "%encodedcommand%", "%4104%"],
            "defender": ["%defender%", "%malware%", "%1116%"],
            "download_guard": ["%download%", "%zip%", "%download_guard%"],
            "fim": ["%fim%", "%integrity%", "%hosts%"],
            "network": ["%router%", "%dns%", "%dhcp%", "%firewall%"],
            "ssh": ["%ssh%", "%sshd%"],
            "web": ["%nginx%", "%http%", "%404%"],
            "edr": ["%edr%", "%quarantine%", "%delete_file%"],
        }
        for group in event_groups:
            terms = group_to_terms.get(group)
            if not terms:
                continue
            if table == "alerts":
                filters.append("(rule_name ILIKE %s OR description ILIKE %s OR service ILIKE %s)")
                params.extend([terms[0], terms[1] if len(terms) > 1 else terms[0], terms[2] if len(terms) > 2 else terms[0]])
            else:
                filters.append("(event_action ILIKE %s OR service ILIKE %s OR message ILIKE %s OR raw_log ILIKE %s)")
                params.extend([terms[0], terms[0], terms[1] if len(terms) > 1 else terms[0], terms[2] if len(terms) > 2 else terms[0]])
            explanation.append(group)
            break

    _nl_add_text_search(q, filters, params, table)
    return filters, params, explanation


@app.post("/nl-query")
def nl_query(data: NLQueryInput, user=Depends(verify_token)):
    raw_query = data.query or ""
    q = _nl_norm(raw_query)
    limit = _nl_extract_limit(q, data.limit)

    if not q:
        raise HTTPException(status_code=400, detail="Consulta buida")

    if _nl_is_destructive(q):
        audit(user.get("sub"), "nl_query_blocked", {"query": raw_query[:300], "reason": "destructive_intent"})
        return {
            "mode": "blocked_safe_nl_query",
            "target": "none",
            "interpreted_filters": [],
            "sql_preview": "Consulta bloquejada: només es permeten consultes de lectura.",
            "results": [],
            "warnings": ["Entrada no permesa: el motor de llenguatge natural només genera consultes de lectura i no executa accions destructives."],
        }

    table = _nl_target_table(q)
    filters, params, explanation = _nl_build_filters(q, table)

    where = "WHERE " + " AND ".join(filters) if filters else ""
    cur = db_cursor()

    if table == "alerts":
        # Adaptar alertes al format que ja espera la taula del frontend.
        sql_preview = f"SELECT ... FROM alerts {where} ORDER BY alert_time DESC LIMIT {limit}"
        cur.execute(
            f"""
            SELECT id,
                   alert_time AS event_time,
                   rule_name AS event_action,
                   severity,
                   src_ip,
                   user_name,
                   service,
                   description AS message,
                   description AS raw_log,
                   risk_score AS risk_score_base,
                   status,
                   mitre_tactic,
                   mitre_technique
            FROM alerts
            {where}
            ORDER BY alert_time DESC
            LIMIT %s
            """,
            [*params, limit],
        )
    else:
        sql_preview = f"SELECT ... FROM events {where} ORDER BY event_time DESC LIMIT {limit}"
        cur.execute(
            f"""
            SELECT id, event_time, source_type, source_name, event_action, severity, src_ip, user_name, service, message, raw_log, risk_score_base, metadata
            FROM events
            {where}
            ORDER BY event_time DESC
            LIMIT %s
            """,
            [*params, limit],
        )

    rows = cur.fetchall()

    # Fallback útil: si el filtre ha estat massa estricte, fer una cerca més ampla però segura.
    fallback_used = False
    if not rows and filters:
        broad_filters: List[str] = []
        broad_params: List[Any] = []
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", q)
        user = _nl_extract_user(q)
        tf = _nl_time_filter(q)
        if ip_match:
            broad_filters.append("src_ip = %s")
            broad_params.append(ip_match.group(0))
        if user:
            term = f"%{user}%"
            if table == "alerts":
                broad_filters.append("(user_name ILIKE %s OR description ILIKE %s)")
                broad_params.extend([term, term])
            else:
                broad_filters.append("(user_name ILIKE %s OR message ILIKE %s OR raw_log ILIKE %s)")
                broad_params.extend([term, term, term])
        if tf:
            broad_filters.append(tf)
        broad_where = "WHERE " + " AND ".join(broad_filters) if broad_filters else ""
        if broad_where:
            fallback_used = True
            if table == "alerts":
                cur.execute(
                    f"""
                    SELECT id, alert_time AS event_time, rule_name AS event_action, severity, src_ip, user_name, service, description AS message, description AS raw_log, risk_score AS risk_score_base, status, mitre_tactic, mitre_technique
                    FROM alerts
                    {broad_where}
                    ORDER BY alert_time DESC
                    LIMIT %s
                    """,
                    [*broad_params, limit],
                )
            else:
                cur.execute(
                    f"""
                    SELECT id, event_time, source_type, source_name, event_action, severity, src_ip, user_name, service, message, raw_log, risk_score_base, metadata
                    FROM events
                    {broad_where}
                    ORDER BY event_time DESC
                    LIMIT %s
                    """,
                    [*broad_params, limit],
                )
            rows = cur.fetchall()
            if rows:
                sql_preview = sql_preview + "  /* fallback segur ampliat aplicat */"

    interpreted = explanation or ["consulta_general_segura"]
    warnings = []
    if fallback_used:
        warnings.append("El filtre inicial no retornava dades; s'ha aplicat una cerca segura més ampla mantenint els límits de lectura.")
    if not filters:
        warnings.append("No s'ha detectat cap filtre específic; s'han retornat els esdeveniments més recents de forma segura.")

    audit(user.get("sub"), "nl_query", {"query": raw_query[:300], "target": table, "sql_preview": sql_preview, "filters": interpreted})
    return {
        "mode": "safe_nl_query_v15_5",
        "target": table,
        "interpreted_filters": interpreted,
        "sql_preview": sql_preview,
        "results": rows,
        "warnings": warnings,
    }


# =============================
# Mini-SIEM Sentinel v15 additions


# Mini-SIEM Sentinel v15: EDR and real-time notifications.
@app.get("/notifications/settings")
def notification_settings(user=Depends(verify_token)):
    cfg = telegram_config()
    return {
        "telegram_enabled": cfg["enabled"] in ("true", "1", "yes", "on"),
        "telegram_bot_token_masked": mask_secret(cfg["bot_token"]),
        "telegram_chat_id": cfg["chat_id"],
        "telegram_min_severity": cfg["min_severity"],
        "security_note": "El token no es retorna complet per seguretat. Si el canvies, desa'l de nou.",
    }


@app.post("/notifications/settings")
def save_notification_settings(data: NotificationSettingsInput, user=Depends(verify_token)):
    if data.telegram_min_severity not in SEVERITY_ORDER:
        raise HTTPException(status_code=400, detail="Invalid severity")
    set_setting("telegram_enabled", "true" if data.telegram_enabled else "false")
    if data.telegram_bot_token is not None and data.telegram_bot_token.strip():
        set_setting("telegram_bot_token", data.telegram_bot_token.strip())
    if data.telegram_chat_id is not None and data.telegram_chat_id.strip():
        set_setting("telegram_chat_id", data.telegram_chat_id.strip())
    set_setting("telegram_min_severity", data.telegram_min_severity)
    audit(user.get("sub"), "save_notification_settings", {"telegram_enabled": data.telegram_enabled, "min_severity": data.telegram_min_severity})
    return {"status": "saved", "token_masked": mask_secret(telegram_config().get("bot_token"))}


@app.post("/notifications/test")
def notification_test(data: TelegramTestInput, user=Depends(verify_token)):
    result = send_telegram_message("🧪 Prova Mini-SIEM Sentinel v15\n\n" + data.message, severity="info", title="Prova notificació")
    audit(user.get("sub"), "telegram_test", {"result": result})
    return result


@app.get("/notifications/history")
def notification_history(user=Depends(verify_token), limit: int = Query(50, ge=1, le=200)):
    cur = db_cursor()
    cur.execute("SELECT id, created_at, channel, severity, alert_id, title, status, destination, error FROM notification_history ORDER BY created_at DESC LIMIT %s", (limit,))
    return cur.fetchall()


@app.get("/edr/summary")
def edr_summary(user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT COUNT(*) AS c FROM events WHERE event_action IN ('windows_suspicious_process','windows_suspicious_powershell','windows_service_installed','download_archive_scan','download_executable_detected','fim_hosts_modified','fim_autorun_candidate','fim_suspicious_file')")
    risky_events = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM quarantine_records")
    quarantined = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM edr_actions WHERE status IN ('pending','running')")
    pending = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM alerts WHERE status='open' AND severity IN ('critical','high')")
    high_open = cur.fetchone()["c"]
    return {
        "risky_events": risky_events,
        "quarantined_files": quarantined,
        "pending_actions": pending,
        "high_open_alerts": high_open,
        "safe_actions": ["quarantine_file", "add_hash_watchlist", "create_incident"],
        "dangerous_actions_not_automatic": ["kill_process", "block_ip", "isolate_host"],
    }


@app.get("/edr/actions")
def edr_actions(user=Depends(verify_token), limit: int = Query(100, ge=1, le=300)):
    cur = db_cursor()
    cur.execute("SELECT * FROM edr_actions ORDER BY created_at DESC LIMIT %s", (limit,))
    return cur.fetchall()


@app.post("/edr/actions")
def create_edr_action(data: EDRActionInput, user=Depends(verify_token)):
    allowed = {"quarantine_file", "delete_file", "add_hash_watchlist", "create_incident"}
    if data.action_type not in allowed:
        raise HTTPException(status_code=400, detail="Unsupported or unsafe EDR action")
    if data.action_type in ("quarantine_file", "delete_file") and not data.target_path:
        raise HTTPException(status_code=400, detail="target_path required")
    cur = db_cursor()
    cur.execute(
        """
        INSERT INTO edr_actions (requested_by, agent_id, hostname, action_type, target_path, target_hash, requested_reason, alert_id, event_id, status)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending')
        RETURNING id
        """,
        (user.get("sub"), data.agent_id, data.hostname, data.action_type, data.target_path, data.target_hash, data.reason, data.alert_id, data.event_id),
    )
    row = cur.fetchone()
    conn.commit()
    audit(user.get("sub"), "create_edr_action", {"id": row["id"], "action_type": data.action_type, "target_path": data.target_path, "hostname": data.hostname})
    return {"status": "queued", "action_id": row["id"]}


@app.get("/edr/actions/pending")
def pending_edr_actions(agent_id: str = Query(...), hostname: Optional[str] = None, x_agent_token: Optional[str] = Header(default=None)):
    validate_agent_token(x_agent_token)
    cur = db_cursor()
    cur.execute(
        """
        SELECT id, action_type, target_path, target_hash, requested_reason, alert_id, event_id, metadata
        FROM edr_actions
        WHERE status='pending' AND (agent_id=%s OR hostname=%s OR (agent_id IS NULL AND hostname IS NULL))
        ORDER BY created_at ASC
        LIMIT 5
        """,
        (agent_id, hostname),
    )
    rows = cur.fetchall()
    ids = [r["id"] for r in rows]
    if ids:
        cur.execute("UPDATE edr_actions SET status='running' WHERE id = ANY(%s)", (ids,))
        conn.commit()
    return rows


@app.post("/edr/actions/{action_id}/result")
def edr_action_result(action_id: int, data: EDRActionResultInput, x_agent_token: Optional[str] = Header(default=None)):
    validate_agent_token(x_agent_token)
    cur = db_cursor()
    cur.execute(
        """
        UPDATE edr_actions
        SET status=%s, result=%s, quarantine_path=%s, executed_at=NOW(), metadata=COALESCE(metadata,'{}'::jsonb) || %s::jsonb
        WHERE id=%s
        RETURNING id
        """,
        (data.status, data.result, data.quarantine_path, json.dumps({"agent_result": data.metadata, "sha256": data.sha256}), action_id),
    )
    row = cur.fetchone()
    conn.commit()
    return {"status": "updated" if row else "not_found", "action_id": action_id}


@app.get("/edr/quarantine")
def quarantine_list(user=Depends(verify_token), limit: int = Query(100, ge=1, le=300)):
    cur = db_cursor()
    cur.execute("SELECT * FROM quarantine_records ORDER BY created_at DESC LIMIT %s", (limit,))
    return cur.fetchall()


@app.post("/edr/quarantine")
def quarantine_record(data: QuarantineRecordInput, x_agent_token: Optional[str] = Header(default=None)):
    validate_agent_token(x_agent_token)
    cur = db_cursor()
    cur.execute(
        """
        INSERT INTO quarantine_records (agent_id, hostname, original_path, quarantine_path, sha256, reason, alert_id, event_id, status, metadata)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
        RETURNING id
        """,
        (data.agent_id, data.hostname, data.original_path, data.quarantine_path, data.sha256, data.reason, data.alert_id, data.event_id, data.status, json.dumps(data.metadata)),
    )
    row = cur.fetchone()
    conn.commit()
    return {"status": "stored", "id": row["id"]}



# Product-grade SOC features for the TFG: demo mode, posture, FIM, MITRE coverage,
# explainable alerts, retention controls and richer Download Guard.
# =============================

HUMAN_ACTION_LABELS = {
    "windows_failed_logon": "Inici de sessió fallit a Windows",
    "windows_successful_logon": "Inici de sessió correcte a Windows",
    "windows_explicit_credentials": "Ús de credencials explícites",
    "windows_special_privileges": "Privilegis especials assignats",
    "windows_process_created": "Procés creat a Windows",
    "windows_user_created": "Compte d'usuari creat",
    "windows_user_deleted": "Compte d'usuari eliminat",
    "windows_group_member_added": "Usuari afegit a grup privilegiat",
    "windows_audit_log_cleared": "Registre d'auditoria esborrat",
    "windows_service_installed": "Servei Windows instal·lat",
    "defender_malware_detected": "Microsoft Defender ha detectat malware",
    "defender_remediation_action": "Defender ha aplicat una acció",
    "powershell_scriptblock": "Bloc de script PowerShell registrat",
    "windows_suspicious_process": "Procés o LOLBin sospitós",
    "windows_suspicious_powershell": "PowerShell sospitós",
    "sysmon_process_created": "Sysmon: procés creat",
    "sysmon_network_connection": "Sysmon: connexió de xarxa",
    "sysmon_file_created": "Sysmon: fitxer creat",
    "download_archive_scan": "Download Guard: arxiu ZIP revisat",
    "download_executable_detected": "Download Guard: executable a Descàrregues",
    "download_dangerous_archive": "Download Guard: ZIP potencialment perillós",
    "fim_sensitive_file_changed": "Canvi en fitxer sensible",
    "fim_autorun_item_detected": "Element d'autoarrencada detectat",
    "fim_suspicious_file_created": "Fitxer sospitós creat",
    "failed_login": "Intent SSH fallit",
    "successful_login": "Inici de sessió SSH correcte",
    "sensitive_path_access": "Accés a ruta web sensible",
    "web_404": "Resposta HTTP 404",
    "error_log": "Error de servei o contenidor",
    "log_observed": "Log observat",
}

CRITICAL_WINDOWS_EVENT_IDS = {1102, 1116}
PERSISTENCE_EVENT_IDS = {7045, 4720, 4732}
FIM_EVENT_IDS = {90020, 90021, 90022, 90023}
DOWNLOAD_EVENT_IDS = {90010, 90011, 90012}

# Extend Windows event mapping at runtime. The original dictionary is kept for compatibility.
try:
    WINDOWS_EVENT_MAP.update({
        90012: ("download", "download_dangerous_archive", "high", 82, "download_guard", ["windows", "download_guard", "archive", "dangerous"], "Initial Access", "T1204 User Execution"),
        90020: ("file_integrity", "fim_sensitive_file_changed", "high", 80, "fim", ["windows", "fim", "sensitive_file"], "Defense Evasion", "T1565 Data Manipulation"),
        90021: ("persistence", "fim_autorun_item_detected", "high", 78, "fim", ["windows", "fim", "autorun", "persistence"], "Persistence", "T1060 Registry Run Keys / Startup Folder"),
        90022: ("file_integrity", "fim_suspicious_file_created", "medium", 55, "fim", ["windows", "fim", "suspicious_file"], "Execution", "T1204 User Execution"),
        90023: ("file_integrity", "fim_hosts_file_changed", "critical", 88, "fim", ["windows", "fim", "hosts_file"], "Defense Evasion", "T1565 Data Manipulation"),
    })
except Exception:
    pass


def human_action(action: Optional[str]) -> str:
    return HUMAN_ACTION_LABELS.get(action or "", action or "-")


def safe_metadata(obj: Any) -> Dict[str, Any]:
    if isinstance(obj, dict):
        return obj
    return {}


def explain_alert_object(a: Dict[str, Any]) -> Dict[str, Any]:
    sev = (a.get("severity") or "medium").lower()
    risk = int(a.get("risk_score") or 0)
    rule = a.get("rule_name") or "Alerta"
    meta = safe_metadata(a.get("metadata"))
    why = []
    if risk >= 85:
        why.append("El risc és molt alt i convé revisar-ho immediatament.")
    elif risk >= 60:
        why.append("El risc és alt i s'hauria d'investigar durant la sessió.")
    else:
        why.append("El risc és moderat o baix; cal revisar context i volum.")
    if a.get("mitre_technique"):
        why.append(f"La regla està associada a MITRE ATT&CK: {a.get('mitre_technique')}.")
    if a.get("src_ip"):
        why.append(f"S'ha identificat una IP origen: {a.get('src_ip')}.")
    if a.get("user_name"):
        why.append(f"Usuari relacionat: {a.get('user_name')}.")
    if "Download" in rule or "download" in str(meta).lower():
        why.append("La detecció està relacionada amb fitxers descarregats, un vector freqüent d'infecció en entorns personals.")
    if "PowerShell" in rule or "powershell" in str(meta).lower():
        why.append("PowerShell pot ser legítim, però també és molt utilitzat per malware i post-explotació.")
    if "service" in rule.lower() or "Servei" in rule:
        why.append("La instal·lació d'un servei pot indicar persistència si no és esperada.")
    steps = [
        "Validar si l'activitat és esperada per l'usuari.",
        "Revisar l'host, l'usuari, l'hora i l'evidència crua.",
        "Buscar esdeveniments relacionats en els 15 minuts anteriors i posteriors.",
        "Si hi ha fitxers o comandes sospitoses, no executar-los i conservar evidència.",
        "Crear o vincular un incident si hi ha més d'una alerta relacionada.",
    ]
    if sev in ("critical", "high"):
        steps.insert(0, "Prioritzar aquesta alerta abans que les informatives o de baix risc.")
    return {
        "title": rule,
        "summary": a.get("description"),
        "severity": sev,
        "risk_score": risk,
        "should_worry": risk >= 70 or sev in ("critical", "high"),
        "why": why,
        "evidence": {
            "src_ip": a.get("src_ip"),
            "user_name": a.get("user_name"),
            "service": a.get("service"),
            "event_count": a.get("event_count"),
            "mitre_tactic": a.get("mitre_tactic"),
            "mitre_technique": a.get("mitre_technique"),
            "metadata": meta,
        },
        "recommended_steps": steps,
    }


def explain_event_object(e: Dict[str, Any]) -> Dict[str, Any]:
    action = e.get("event_action")
    risk = int(e.get("risk_score_base") or 0)
    meta = safe_metadata(e.get("metadata"))
    summary = f"{human_action(action)} observat a {e.get('source_name') or e.get('source_type')}."
    why = []
    if risk >= 60:
        why.append("L'esdeveniment té risc elevat segons el motor d'enriquiment.")
    elif risk >= 35:
        why.append("L'esdeveniment és rellevant i pot formar part d'una investigació.")
    else:
        why.append("L'esdeveniment és principalment informatiu, però pot ser útil en correlació.")
    if e.get("src_ip"):
        why.append(f"Conté IP origen: {e.get('src_ip')}.")
    if e.get("user_name"):
        why.append(f"Conté usuari: {e.get('user_name')}.")
    if action in ("download_dangerous_archive", "download_executable_detected"):
        why.append("Implica un fitxer a Descàrregues; és un punt crític per a usuaris personals.")
    if action in ("fim_sensitive_file_changed", "fim_hosts_file_changed", "fim_autorun_item_detected"):
        why.append("Implica integritat de fitxers o persistència, que és una capacitat pròpia d'un SIEM/EDR.")
    return {
        "title": human_action(action),
        "summary": summary,
        "risk_score": risk,
        "severity": e.get("severity"),
        "why": why,
        "fields": {
            "time": str(e.get("event_time")),
            "source": e.get("source_name") or e.get("source_type"),
            "category": e.get("event_category"),
            "action": action,
            "src_ip": e.get("src_ip"),
            "user_name": e.get("user_name"),
            "service": e.get("service"),
            "metadata": meta,
        },
        "recommended_steps": [
            "Comparar amb altres esdeveniments del mateix host o usuari.",
            "Si el risc és alt, mirar si ja existeix una alerta associada.",
            "Conservar el raw log per a la memòria i proves del TFG.",
        ],
    }


_previous_run_detection_v13 = run_detection

def run_detection(event: Dict[str, Any]):
    """Run original detections plus v13 rules."""
    try:
        _previous_run_detection_v13(event)
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        print("previous detection failed", exc)

    action = event.get("event_action")
    meta = safe_metadata(event.get("metadata"))
    ed = safe_metadata(meta.get("event_data"))
    host = meta.get("hostname")
    user = event.get("user_name")
    ip = event.get("src_ip")
    score = int(event.get("risk_score_base") or 0)

    if action == "download_dangerous_archive":
        fname = ed.get("file_name") or ed.get("path") or "fitxer ZIP"
        suspicious = ed.get("suspicious_entries") or ed.get("suspicious_count") or "contingut sospitós"
        create_alert(
            "Download Guard dangerous archive", "high", max(82, score),
            f"El ZIP {fname} conté elements potencialment perillosos: {suspicious}.",
            user_name=user, service="download_guard", event_count=1,
            mitre_tactic="Initial Access", mitre_technique="T1204 User Execution",
            dedup_key=f"download_dangerous:{host}:{fname}", metadata={"event": event, "recommendation": "No executar el contingut i revisar origen."}
        )

    if action == "download_executable_detected":
        fname = ed.get("file_name") or ed.get("path") or "executable"
        create_alert(
            "Download Guard executable observed", "high", max(72, score),
            f"S'ha detectat un executable o script a Descàrregues: {fname}.",
            user_name=user, service="download_guard", event_count=1,
            mitre_tactic="Initial Access", mitre_technique="T1204 User Execution",
            dedup_key=f"download_exe:{host}:{fname}", metadata={"event": event}
        )

    if action == "fim_hosts_file_changed":
        create_alert(
            "Hosts file modified", "critical", max(88, score),
            f"El fitxer hosts del sistema ha canviat a {host}. Pot indicar manipulació de resolució DNS.",
            user_name=user, service="fim", event_count=1,
            mitre_tactic="Defense Evasion", mitre_technique="T1565 Data Manipulation",
            dedup_key=f"hosts_changed:{host}", metadata={"event": event}
        )

    if action == "fim_autorun_item_detected":
        path = ed.get("path") or ed.get("file_name") or "element d'autoarrencada"
        create_alert(
            "Autorun persistence candidate", "high", max(78, score),
            f"S'ha observat un element d'autoarrencada: {path}.",
            user_name=user, service="fim", event_count=1,
            mitre_tactic="Persistence", mitre_technique="T1060 Registry Run Keys / Startup Folder",
            dedup_key=f"autorun:{host}:{path}", metadata={"event": event}
        )

    if action == "fim_suspicious_file_created":
        path = ed.get("path") or ed.get("file_name") or "fitxer sospitós"
        create_alert(
            "Suspicious file created", "medium", max(55, score),
            f"S'ha detectat un fitxer potencialment executable o script en una carpeta monitorada: {path}.",
            user_name=user, service="fim", event_count=1,
            mitre_tactic="Execution", mitre_technique="T1204 User Execution",
            dedup_key=f"fim_file:{host}:{path}", metadata={"event": event}
        )


@app.get("/human/action-labels")
def get_human_labels(user=Depends(verify_token)):
    return HUMAN_ACTION_LABELS


@app.get("/alerts/{alert_id}/explain")
def explain_alert(alert_id: int, user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT * FROM alerts WHERE id = %s", (alert_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return explain_alert_object(dict(row))


@app.get("/events/{event_id}/explain")
def explain_event(event_id: int, user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT * FROM events WHERE id = %s", (event_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    return explain_event_object(dict(row))


@app.get("/mitre/coverage")
def mitre_coverage(user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("""
        SELECT mitre_technique, mitre_tactic, COUNT(*) AS rules
        FROM rules
        WHERE mitre_technique IS NOT NULL
        GROUP BY mitre_technique, mitre_tactic
        ORDER BY mitre_tactic, mitre_technique
    """)
    techniques = cur.fetchall()
    cur.execute("""
        SELECT mitre_technique, COUNT(*) AS alerts
        FROM alerts
        WHERE mitre_technique IS NOT NULL
        GROUP BY mitre_technique
    """)
    alert_counts = {r["mitre_technique"]: r["alerts"] for r in cur.fetchall()}
    return [{**dict(t), "alerts": int(alert_counts.get(t["mitre_technique"], 0))} for t in techniques]


@app.get("/device-posture")
def device_posture(user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT agent_id, hostname, os_type, os_version, version, status, last_seen, metadata FROM agents ORDER BY last_seen DESC")
    rows = cur.fetchall()
    out = []
    for r in rows:
        m = safe_metadata(r.get("metadata"))
        posture = safe_metadata(m.get("posture"))
        checks = []
        def add(name, ok, detail=""):
            checks.append({"name": name, "ok": bool(ok), "detail": detail})
        add("Microsoft Defender actiu", posture.get("defender_enabled", False), posture.get("defender_status", ""))
        add("Firewall actiu", posture.get("firewall_enabled", False), posture.get("firewall_profile", ""))
        add("BitLocker detectat", posture.get("bitlocker_enabled", False), posture.get("bitlocker_status", ""))
        add("UAC actiu", posture.get("uac_enabled", False), "Control de comptes d'usuari")
        add("PowerShell logging disponible", posture.get("powershell_logging", False), "Canal operacional PowerShell")
        add("Sysmon instal·lat", posture.get("sysmon_installed", False), "Millora telemetria de processos i xarxa")
        score = round((sum(1 for c in checks if c["ok"]) / max(1, len(checks))) * 100)
        out.append({"agent": dict(r), "score": score, "checks": checks, "recommendations": [c["name"] for c in checks if not c["ok"]]})
    return out


@app.get("/fim/observations")
def fim_observations(user=Depends(verify_token), limit: int = Query(100, ge=1, le=500)):
    cur = db_cursor()
    cur.execute("""
        SELECT id, event_time, source_name, event_action, severity, user_name, service, raw_log, metadata, risk_score_base
        FROM events
        WHERE event_action LIKE %s OR event_action LIKE %s
        ORDER BY event_time DESC
        LIMIT %s
    """, ("fim_%", "download_%", limit))
    return cur.fetchall()


@app.get("/cases/{case_id}/timeline")
def case_timeline(case_id: int, user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT * FROM cases WHERE id=%s", (case_id,))
    case = cur.fetchone()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    cur.execute("""
        SELECT a.* FROM alerts a
        JOIN case_alerts ca ON ca.alert_id = a.id
        WHERE ca.case_id = %s
        ORDER BY a.alert_time ASC
    """, (case_id,))
    alerts = cur.fetchall()
    timeline = []
    for a in alerts:
        timeline.append({"time": a["alert_time"], "type": "alert", "title": a["rule_name"], "severity": a["severity"], "description": a["description"], "mitre": a["mitre_technique"]})
    return {"case": case, "timeline": timeline}


@app.get("/architecture")
def architecture(user=Depends(verify_token)):
    return {
        "title": "Arquitectura Mini-SIEM Sentinel v15",
        "flow": [
            "Agent Windows / Collector Linux / Docker",
            "API FastAPI autenticada",
            "Normalització d'esdeveniments",
            "Enriquiment: IP, usuari, servei, risc i MITRE",
            "PostgreSQL com a persistència",
            "Motor de regles + correlació temporal",
            "Alertes, incidents, playbooks i auditoria",
            "Dashboard SOC i assistent contextual local",
        ],
        "security": [
            "No hi ha execució remota de comandes des del servidor cap a l'agent.",
            "El token de l'agent protegeix la ingesta.",
            "El motor NL no executa SQL lliure: aplica allowlist i paràmetres.",
            "Les dades es queden a l'entorn local desplegat per l'usuari.",
        ]
    }


@app.get("/manual")
def manual(user=Depends(verify_token)):
    return {
        "steps": [
            {"title": "Desplegar servidor", "body": "Executa docker compose up --build i obre http://localhost/login.html."},
            {"title": "Instal·lar agent Windows", "body": "Descarrega el ZIP de l'agent, executa Setup-MiniSIEMAgent.cmd com administrador i introdueix URL i token."},
            {"title": "Validar heartbeat", "body": "A la pestanya Agents comprova que el dispositiu surt EN LÍNIA."},
            {"title": "Generar prova", "body": "Utilitza el Mode demo TFG per crear una alerta crítica segura."},
            {"title": "Investigar", "body": "Obre l'alerta, llegeix l'explicació, pregunta a l'assistent i crea un incident si cal."},
        ],
        "demo_flow": ["Alerta crítica", "Detall explicable", "Incident", "Timeline", "Playbook", "Auditoria"],
    }


@app.get("/settings/retention")
def get_retention(user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT key, value FROM settings WHERE key LIKE 'retention_%' ORDER BY key")
    rows = cur.fetchall()
    return {r["key"]: r["value"] for r in rows}


class RetentionInput(BaseModel):
    events_days: int = 30
    audit_days: int = 90


@app.post("/settings/retention")
def set_retention(data: RetentionInput, user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("INSERT INTO settings (key,value) VALUES ('retention_events_days', %s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", (str(max(1, data.events_days)),))
    cur.execute("INSERT INTO settings (key,value) VALUES ('retention_audit_days', %s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", (str(max(1, data.audit_days)),))
    conn.commit()
    audit(user.get("sub"), "set_retention", {"events_days": data.events_days, "audit_days": data.audit_days})
    return {"status": "updated"}


@app.post("/settings/cleanup")
def cleanup_data(user=Depends(verify_token)):
    cur = db_cursor()
    cur.execute("SELECT value FROM settings WHERE key='retention_events_days'")
    events_days = int((cur.fetchone() or {"value": "30"})["value"])
    cur.execute("SELECT value FROM settings WHERE key='retention_audit_days'")
    audit_days = int((cur.fetchone() or {"value": "90"})["value"])
    cur.execute("DELETE FROM events WHERE event_time < NOW() - (%s || ' days')::interval RETURNING id", (events_days,))
    deleted_events = cur.rowcount
    cur.execute("DELETE FROM audit_logs WHERE audit_time < NOW() - (%s || ' days')::interval RETURNING id", (audit_days,))
    deleted_audit = cur.rowcount
    conn.commit()
    audit(user.get("sub"), "cleanup_data", {"deleted_events": deleted_events, "deleted_audit": deleted_audit})
    return {"deleted_events": deleted_events, "deleted_audit": deleted_audit}


def _demo_windows_event(event_id: int, message: str, event_data: Dict[str, Any], hostname: str = "DEMO-TFG", log_name: str = "Security", provider_name: str = "MiniSIEM Demo") -> int:
    """Create a safe demo Windows event and force the complete detection path.

    v13.1 hotfix: the previous demo endpoint inserted events correctly but some
    Windows-specific detections were only executed from /ingest-windows.
    For the TFG demo, demo events must behave exactly like real agent events.
    """
    payload = WindowsEventInput(
        agent_id="demo-tfg-agent",
        hostname=hostname,
        os_version="Windows demo TFG",
        log_name=log_name,
        provider_name=provider_name,
        event_id=event_id,
        record_id=int(time.time() * 1000) % 100000000,
        level="Warning",
        time_created=datetime.now(timezone.utc).isoformat(),
        message=message,
        event_data=event_data,
    )
    ev = normalize_windows_event(payload)
    ev["source_name"] = hostname
    ev_id = insert_event(ev)
    ev["id"] = ev_id

    # Run both the generic/v13 rules and the Windows-specific rules.
    run_detection(ev)
    run_windows_detection(ev)

    # Safety net for the defence demo: every high/critical demo event should
    # create an explainable alert, even if a dedup rule has already suppressed
    # a specific detector. This only applies to source DEMO-TFG.
    sev = (ev.get("severity") or "info").lower()
    if hostname == "DEMO-TFG" and sev in ("high", "critical"):
        action = ev.get("event_action") or "demo_event"
        title = f"DEMO · {human_action(action)}"
        create_alert(
            title,
            sev,
            max(int(ev.get("risk_score_base") or 0), 82 if sev == "high" else 92),
            f"Escenari segur generat pel Mode demo TFG: {human_action(action)}. Host={hostname} Usuari={ev.get('user_name') or '-'} Servei={ev.get('service') or '-'}.",
            src_ip=ev.get("src_ip"),
            user_name=ev.get("user_name"),
            service=ev.get("service"),
            event_count=1,
            mitre_tactic=safe_metadata(ev.get("metadata")).get("mitre_tactic"),
            mitre_technique=safe_metadata(ev.get("metadata")).get("mitre_technique"),
            dedup_key=f"demo_forced_alert:{ev_id}",
            metadata={"event_id": ev_id, "event": ev, "demo": True, "recommendation": "Revisar l'explicació de l'alerta, vincular-la a un incident i mostrar el playbook corresponent."},
        )
    return ev_id


@app.post("/demo/critical-defender")
def demo_critical_defender(user=Depends(verify_token)):
    eid = _demo_windows_event(1116, "Microsoft Defender Antivirus has detected malware. Name: Demo.TFG.Threat; Path: C:\\Users\\david\\Downloads\\factura.zip", {"ThreatName": "Demo.TFG.Threat", "Path": "C:\\Users\\david\\Downloads\\factura.zip", "User": user.get("sub")}, log_name="Microsoft-Windows-Windows Defender/Operational", provider_name="Microsoft-Windows-Windows Defender")
    audit(user.get("sub"), "demo_critical_defender", {"event_id": eid})
    return {"status": "generated", "event_id": eid}


@app.post("/demo/suspicious-powershell")
def demo_suspicious_powershell(user=Depends(verify_token)):
    eid = _demo_windows_event(4104, "ScriptBlockText: powershell.exe -NoProfile -EncodedCommand SQBFAFgA; Invoke-Expression; DownloadString", {"ScriptBlockText": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA; Invoke-Expression; DownloadString", "User": user.get("sub")}, log_name="Microsoft-Windows-PowerShell/Operational", provider_name="Microsoft-Windows-PowerShell")
    audit(user.get("sub"), "demo_suspicious_powershell", {"event_id": eid})
    return {"status": "generated", "event_id": eid}


@app.post("/demo/dangerous-download")
def demo_dangerous_download(user=Depends(verify_token)):
    ed = {"file_name": "factura_urgent.zip", "path": "C:\\Users\\david\\Downloads\\factura_urgent.zip", "sha256": "DEMO", "suspicious_entries": "factura.pdf.exe | install.ps1 | run.cmd", "suspicious_count": 3, "verdict": "high", "double_extension": True}
    eid = _demo_windows_event(90012, "Download Guard detected a dangerous archive factura_urgent.zip with executable/script content.", ed, log_name="MiniSIEM-DownloadGuard", provider_name="MiniSIEMAgent Download Guard")
    audit(user.get("sub"), "demo_dangerous_download", {"event_id": eid})
    return {"status": "generated", "event_id": eid}


@app.post("/demo/fim-hosts-change")
def demo_fim_hosts(user=Depends(verify_token)):
    ed = {"path": "C:\\Windows\\System32\\drivers\\etc\\hosts", "sha256": "DEMO", "change": "hash_changed", "previous_hash": "old", "new_hash": "new"}
    eid = _demo_windows_event(90023, "File Integrity Monitor detected modification of hosts file.", ed, log_name="MiniSIEM-FIM", provider_name="MiniSIEMAgent FIM")
    audit(user.get("sub"), "demo_fim_hosts", {"event_id": eid})
    return {"status": "generated", "event_id": eid}


@app.post("/demo/full-incident")
def demo_full_incident(user=Depends(verify_token)):
    events = []
    events.append(_demo_windows_event(90012, "Dangerous ZIP downloaded: factura_urgent.zip", {"file_name": "factura_urgent.zip", "path": "C:\\Users\\david\\Downloads\\factura_urgent.zip", "suspicious_entries": "factura.pdf.exe | install.ps1", "suspicious_count": 2, "verdict": "high"}, log_name="MiniSIEM-DownloadGuard", provider_name="MiniSIEMAgent Download Guard"))
    events.append(_demo_windows_event(4104, "ScriptBlockText: powershell.exe -EncodedCommand SQBFAFgA; Invoke-WebRequest; IEX", {"ScriptBlockText": "powershell.exe -EncodedCommand SQBFAFgA; Invoke-WebRequest; IEX", "User": user.get("sub")}, log_name="Microsoft-Windows-PowerShell/Operational", provider_name="Microsoft-Windows-PowerShell"))
    events.append(_demo_windows_event(7045, "A new service was installed in the system. Service Name: DemoUpdater", {"ServiceName": "DemoUpdater", "ImagePath": "C:\\Users\\david\\Downloads\\factura.pdf.exe"}, log_name="System", provider_name="Service Control Manager"))
    cur = db_cursor()
    cur.execute("INSERT INTO cases (title, description, severity, status, owner) VALUES (%s,%s,%s,'open',%s) RETURNING id", ("INC-DEMO · Possible execució maliciosa des de Descàrregues", "Incident generat pel Mode demo TFG: descàrrega sospitosa, PowerShell i persistència.", "critical", user.get("sub")))
    case_id = cur.fetchone()["id"]
    cur.execute("SELECT id FROM alerts ORDER BY alert_time DESC LIMIT 5")
    for a in cur.fetchall():
        cur.execute("INSERT INTO case_alerts (case_id, alert_id) VALUES (%s,%s) ON CONFLICT DO NOTHING", (case_id, a["id"]))
    conn.commit()
    audit(user.get("sub"), "demo_full_incident", {"events": events, "case_id": case_id})
    return {"status": "generated", "event_ids": events, "case_id": case_id}


@app.post("/demo/clear")
def demo_clear(user=Depends(verify_token)):
    """Remove only demo data and reset the demo scenario cleanly.

    v13.2: the previous cleanup removed events but did not always remove all
    demo-derived alert/case relationships. That could make the second demo run
    look empty or inconsistent. This version deletes demo case links, demo cases,
    demo alerts and demo events in a deterministic order.
    """
    cur = db_cursor()
    cur.execute("""
        DELETE FROM case_alerts
        WHERE case_id IN (
            SELECT id FROM cases
            WHERE title ILIKE %s OR description ILIKE %s
        )
    """, ("INC-DEMO%", "%Mode demo%"))
    deleted_links = cur.rowcount
    cur.execute("""
        DELETE FROM cases
        WHERE title ILIKE %s OR description ILIKE %s
    """, ("INC-DEMO%", "%Mode demo%"))
    deleted_cases = cur.rowcount
    cur.execute("""
        DELETE FROM alerts
        WHERE rule_name ILIKE %s
           OR description ILIKE %s
           OR metadata::text ILIKE %s
           OR metadata::text ILIKE %s
        RETURNING id
    """, ("DEMO ·%", "%Mode demo%", "%DEMO-TFG%", "%demo-tfg-agent%"))
    a = cur.rowcount
    cur.execute("""
        DELETE FROM events
        WHERE source_name = %s
           OR metadata::text ILIKE %s
           OR metadata::text ILIKE %s
        RETURNING id
    """, ("DEMO-TFG", "%DEMO-TFG%", "%demo-tfg-agent%"))
    e = cur.rowcount
    conn.commit()
    audit(user.get("sub"), "demo_clear", {"alerts": a, "events": e, "cases": deleted_cases, "case_links": deleted_links})
    return {"deleted_alerts": a, "deleted_events": e, "deleted_cases": deleted_cases, "deleted_case_links": deleted_links}


# Upgrade the assistant endpoint by replacing the handler when the same path is requested is not trivial in FastAPI.
# Instead expose a richer v13 endpoint used by the new UI.
@app.post("/ai/chat-v13")
@app.post("/ai/chat-v14")
def ai_chat_v13(data: AIChatInput, user=Depends(verify_token)):
    q = (data.message or "").lower()
    cur = db_cursor()
    cur.execute("SELECT COUNT(*) AS c FROM alerts WHERE status='open'")
    open_alerts = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM events WHERE event_time > NOW() - INTERVAL '1 hour'")
    last_hour = cur.fetchone()["c"]
    context_bits = [f"Context actual: pàgina {data.page}.", f"Alertes obertes: {open_alerts}.", f"Esdeveniments última hora: {last_hour}."]
    if data.alert_id:
        cur.execute("SELECT * FROM alerts WHERE id=%s", (data.alert_id,))
        a = cur.fetchone()
        if a:
            ex = explain_alert_object(dict(a))
            context_bits.append(f"Alerta seleccionada: {ex['title']} risc {ex['risk_score']} severitat {ex['severity']}. {ex['summary']}")
    if data.event_id:
        cur.execute("SELECT * FROM events WHERE id=%s", (data.event_id,))
        e = cur.fetchone()
        if e:
            ex = explain_event_object(dict(e))
            context_bits.append(f"Event seleccionat: {ex['title']} risc {ex['risk_score']}.")

    if any(x in q for x in ["què fa", "que fa", "aquesta pàgina", "pagina", "pàgina"]):
        page_help = {
            "overview": "La visió general resumeix salut del SIEM, alertes per severitat, activitat temporal, IPs i estat general.",
            "alerts": "Alertes mostra deteccions generades pel motor de regles. Des d'aquí pots fer ack, tancar, veure explicació o crear incidents.",
            "events": "Esdeveniments mostra logs normalitzats. Per defecte filtra soroll i prioritza el que té risc o valor d'investigació.",
            "agents": "Agents mostra equips Windows connectats, heartbeats, postura de seguretat i telemetria rebuda.",
            "posture": "Postura avalua configuracions defensives com Defender, Firewall, UAC, BitLocker, Sysmon i PowerShell logging.",
            "fim": "Integritat mostra canvis en descàrregues, fitxers sensibles i possibles punts de persistència.",
            "demo": "Mode demo genera escenaris segurs per defensar el TFG sense executar malware real.",
            "architecture": "Arquitectura explica el flux tècnic complet del SIEM: agent, API, normalització, regles, alertes i dashboard.",
        }
        answer = page_help.get(data.page, "Aquesta pàgina forma part del SOC personal i ajuda a investigar esdeveniments, alertes o configuració del SIEM.")
    elif any(x in q for x in ["preocupar", "preocupa", "greu", "urgent"]):
        if data.alert_id:
            cur.execute("SELECT * FROM alerts WHERE id=%s", (data.alert_id,))
            a = cur.fetchone()
            ex = explain_alert_object(dict(a)) if a else None
            if ex and ex["should_worry"]:
                answer = f"Sí, l'hauries de revisar. **{ex['title']}** té risc {ex['risk_score']} i severitat {ex['severity']}.\n\nPer què: " + " ".join(ex["why"]) + "\n\nPassos: " + " | ".join(ex["recommended_steps"][:4])
            else:
                answer = "No sembla crítica, però revisa context, usuari i hora. Si hi ha repetició o altres alertes relacionades, crea un incident."
        else:
            answer = "Puc valorar-ho millor si selecciones una alerta o un esdeveniment. Sense context: prioritza critical/high, Defender, PowerShell sospitós, FIM i Download Guard."
    elif any(x in q for x in ["demo", "defensa", "tfg"]):
        answer = "Flux recomanat de demo: 1) Mode demo → Incident complet. 2) Ves a Alertes i obre una high/critical. 3) Mostra explicació i MITRE. 4) Crea o obre l'incident. 5) Mostra timeline, playbook i auditoria. 6) Explica que tot és segur i reproduïble."
    elif "ip" in q:
        answer = "No tots els events Windows tenen IP. La IP apareix sobretot en logons remots, RDP, SMB, Sysmon Network Connection o logs web/SSH. Un servei instal·lat o un event local normalment no tindrà IP perquè és acció local del host."
    elif any(x in q for x in ["arquitectura", "funciona", "components"]):
        answer = "Arquitectura: l'agent Windows i collectors envien logs a FastAPI; el backend normalitza i enriqueix; PostgreSQL guarda events; el motor de regles correlaciona; les alertes es gestionen amb incidents, playbooks, auditoria i dashboard."
    else:
        answer = "Puc ajudar-te amb el projecte, la pàgina actual, alertes, esdeveniments, IPs, agent Windows, demo del TFG, Download Guard, FIM, MITRE, playbooks i arquitectura. Pregunta'm sobre un element concret o selecciona una alerta/esdeveniment."
    return {"answer": "\n".join(context_bits) + "\n\n" + answer}


# =============================
# v15 · Home Network Telemetry + real EDR Download Guard + threat intel
# =============================

class NetworkTelemetryInput(BaseModel):
    raw_log: str
    remote_ip: Optional[str] = None
    source_name: Optional[str] = "router"
    transport: Optional[str] = "udp_syslog"
    received_at: Optional[str] = None
    metadata: Dict[str, Any] = {}


def _maybe_int(value: Any) -> Optional[int]:
    try:
        if value is None or str(value).strip() == "":
            return None
        return int(value)
    except Exception:
        return None


def _extract_port(text: str, names: List[str]) -> Optional[int]:
    for name in names:
        m = re.search(r"(?:^|\s|,|;)" + re.escape(name) + r"\s*[=:]\s*(\d{1,5})", text, re.I)
        if m:
            p = _maybe_int(m.group(1))
            if p and 0 < p <= 65535:
                return p
    return None


def _extract_key_value(text: str, names: List[str]) -> Optional[str]:
    for name in names:
        m = re.search(r"(?:^|\s|,|;)" + re.escape(name) + r"\s*[=:]\s*([^\s,;]+)", text, re.I)
        if m:
            return m.group(1).strip().strip('"\'')
    return None


def _extract_mac(text: str) -> Optional[str]:
    m = re.search(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", text or "")
    return m.group(0).lower().replace('-', ':') if m else None


def normalize_network_telemetry(data: NetworkTelemetryInput) -> Dict[str, Any]:
    raw = data.raw_log or ""
    lower = raw.lower()
    src_ip = _extract_key_value(raw, ["src", "srcip", "src_ip", "source", "source_ip", "from", "client", "client_ip"])
    dst_ip = _extract_key_value(raw, ["dst", "dstip", "dst_ip", "destination", "destination_ip", "to"])
    # fallback: first IP is source, second IP is destination
    ips = re.findall(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", raw)
    ips = [ip for ip in ips if _valid_ip_candidate(ip)]
    if not src_ip and ips:
        src_ip = ips[0]
    if not dst_ip and len(ips) > 1:
        dst_ip = ips[1]
    src_ip = _valid_ip_candidate(src_ip) or None
    dst_ip = _valid_ip_candidate(dst_ip) or None
    src_port = _extract_port(raw, ["spt", "src_port", "sport", "source_port"])
    dst_port = _extract_port(raw, ["dpt", "dst_port", "dport", "destination_port", "port"])
    proto = (_extract_key_value(raw, ["proto", "protocol"]) or "").lower() or None
    mac = _extract_mac(raw)
    hostname = _extract_key_value(raw, ["hostname", "host", "client-hostname", "name"])
    category = "network"
    action = "router_syslog_event"
    severity = "info"
    score = 10
    tags = ["network", "router", "syslog"]
    tactic = None
    technique = None

    if any(k in lower for k in ["blocked", "deny", "denied", "drop", "dropped", "reject", "rejected", "firewall"]):
        action = "router_firewall_block"
        severity, score = "medium", 45
        tags += ["firewall", "blocked"]
        tactic, technique = "Reconnaissance", "T1595 Active Scanning"
    if any(k in lower for k in ["dhcp", "lease", "bound", "assigned", "new device", "nou dispositiu"]):
        action = "router_dhcp_lease"
        severity, score = "low", 20
        tags += ["dhcp", "asset"]
    if any(k in lower for k in ["login", "logged in", "authentication", "failed password", "invalid password", "admin login", "web login"]):
        action = "router_admin_login_activity"
        severity, score = "high", 72
        tags += ["router_admin", "auth"]
        tactic, technique = "Initial Access", "T1078 Valid Accounts"
    if any(k in lower for k in ["dns", "query", "domain"]):
        action = "dns_query_observed"
        severity, score = "info", 12
        tags += ["dns"]
    suspicious_domains = ["duckdns", "no-ip", "pastebin", "discordapp", "telegram", ".top", ".xyz", ".ru"]
    if action == "dns_query_observed" and any(d in lower for d in suspicious_domains):
        action = "dns_suspicious_query"
        severity, score = "medium", 55
        tags += ["suspicious_dns"]
        tactic, technique = "Command and Control", "T1071 Application Layer Protocol"
    if any(k in lower for k in ["port scan", "scan", "syn flood", "nmap"]):
        action = "network_scan_candidate"
        severity, score = "high", 78
        tags += ["scan"]
        tactic, technique = "Reconnaissance", "T1046 Network Service Discovery"

    metadata = {
        "router_raw": raw,
        "remote_ip": data.remote_ip,
        "transport": data.transport,
        "received_at": data.received_at,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": proto,
        "mac": mac,
        "device_hostname": hostname,
        "mitre_tactic": tactic,
        "mitre_technique": technique,
        **(data.metadata or {}),
    }
    msg = f"Router/syslog {data.source_name}: {raw[:300]}"
    return {
        "source_type": "network_device",
        "source_name": data.source_name or "router",
        "event_category": category,
        "event_action": action,
        "severity": severity,
        "src_ip": src_ip,
        "src_ip_is_private": is_private_ip(src_ip),
        "user_name": hostname,
        "service": "network",
        "message": msg,
        "raw_log": raw,
        "tags": tags,
        "risk_score_base": score,
        "metadata": metadata,
    }


def upsert_network_device(event: Dict[str, Any]):
    md = safe_metadata(event.get("metadata"))
    ip = event.get("src_ip") or md.get("dst_ip")
    mac = md.get("mac")
    hostname = md.get("device_hostname") or event.get("user_name")
    if not ip and not mac:
        return
    try:
        cur = db_cursor()
        cur.execute(
            """
            INSERT INTO network_devices (ip_address, mac_address, hostname, source_name, first_seen, last_seen, event_count, risk_score, metadata)
            VALUES (%s,%s,%s,%s,NOW(),NOW(),1,%s,%s::jsonb)
            ON CONFLICT (ip_address) DO UPDATE SET
                mac_address=COALESCE(EXCLUDED.mac_address, network_devices.mac_address),
                hostname=COALESCE(EXCLUDED.hostname, network_devices.hostname),
                source_name=COALESCE(EXCLUDED.source_name, network_devices.source_name),
                last_seen=NOW(),
                event_count=network_devices.event_count+1,
                risk_score=GREATEST(network_devices.risk_score, EXCLUDED.risk_score),
                metadata=network_devices.metadata || EXCLUDED.metadata
            """,
            (ip, mac, hostname, event.get("source_name"), int(event.get("risk_score_base") or 0), json.dumps(md)),
        )
        conn.commit()
    except Exception:
        conn.rollback()


def run_network_detection(event: Dict[str, Any]):
    action = event.get("event_action")
    ip = event.get("src_ip")
    host = event.get("source_name")
    md = safe_metadata(event.get("metadata"))
    dst = md.get("dst_ip")
    if action == "router_dhcp_lease" and ip:
        create_alert(
            "Network new device observed", "medium", 52,
            f"S'ha observat un dispositiu a la xarxa domèstica: IP={ip}, MAC={md.get('mac') or '-'}, host={md.get('device_hostname') or '-'}. Rellevant per descobrir dispositius nous com TV, IoT o mòbils.",
            src_ip=ip, service="network", mitre_tactic="Discovery", mitre_technique="T1016 System Network Configuration Discovery",
            dedup_key=f"network_new_device:{ip}:{md.get('mac')}", metadata={"event": event}
        )
    if action == "router_admin_login_activity":
        create_alert(
            "Router admin login activity", "high", 78,
            f"Activitat d'autenticació al router o equip de xarxa. Origen={ip or '-'} Router={host}.",
            src_ip=ip, service="network", mitre_tactic="Initial Access", mitre_technique="T1078 Valid Accounts",
            dedup_key=f"router_login:{host}:{ip}:{event.get('user_name')}", metadata={"event": event}
        )
    if action == "router_firewall_block" and ip:
        cur = db_cursor()
        cur.execute("""
            SELECT COUNT(*) AS count, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
            FROM events
            WHERE source_type='network_device' AND event_action='router_firewall_block' AND src_ip=%s
              AND event_time > NOW() - INTERVAL '10 minutes'
        """, (ip,))
        row = cur.fetchone()
        if row and row["count"] >= 10:
            create_alert(
                "Router firewall block burst", "high", 82,
                f"{row['count']} bloquejos de firewall des de {ip} en 10 minuts. Pot indicar escaneig, malware intern o dispositiu IoT comprometible.",
                src_ip=ip, service="network", event_count=row["count"], first_seen=row["first_seen"], last_seen=row["last_seen"],
                mitre_tactic="Reconnaissance", mitre_technique="T1595 Active Scanning", dedup_key=f"router_block_burst:{ip}", metadata={"dst_ip": dst}
            )
    if action in ("dns_suspicious_query", "network_scan_candidate"):
        rule = "DNS suspicious query" if action == "dns_suspicious_query" else "Network scan candidate"
        create_alert(
            rule, event.get("severity") or "medium", max(65, int(event.get("risk_score_base") or 0)),
            f"Telemetria de xarxa sospitosa: {event.get('raw_log')[:220]}",
            src_ip=ip, service="network", mitre_tactic=md.get("mitre_tactic"), mitre_technique=md.get("mitre_technique"),
            dedup_key=f"{action}:{host}:{ip}:{dst}", metadata={"event": event}
        )
    # Threat intel based on AbuseIPDB for public IPs.
    ti = safe_metadata(event.get("metadata")).get("threat_intel") or {}
    abuse = safe_metadata(ti.get("abuseipdb"))
    try:
        abuse_score = int(abuse.get("abuseConfidenceScore") or 0)
    except Exception:
        abuse_score = 0
    if abuse_score >= 75 and ip:
        create_alert(
            "AbuseIPDB high-risk IP observed", "critical" if abuse_score >= 90 else "high", min(100, 65 + abuse_score // 2),
            f"La IP pública {ip} té AbuseIPDB score {abuse_score}. S'ha observat a telemetria de xarxa.",
            src_ip=ip, service="threat_intel", mitre_tactic="Command and Control", mitre_technique="T1071 Application Layer Protocol",
            dedup_key=f"abuseipdb:{ip}", metadata={"event": event, "abuseipdb": abuse}
        )


def _ti_cache_get(kind: str, value: str) -> Optional[Dict[str, Any]]:
    if not value:
        return None
    try:
        cur = db_cursor()
        cur.execute("""
            SELECT result FROM threat_intel_cache
            WHERE kind=%s AND value=%s AND updated_at > NOW() - INTERVAL '12 hours'
        """, (kind, value))
        row = cur.fetchone()
        return safe_metadata(row.get("result")) if row else None
    except Exception:
        conn.rollback()
        return None


def _ti_cache_set(kind: str, value: str, result: Dict[str, Any]):
    try:
        cur = db_cursor()
        cur.execute("""
            INSERT INTO threat_intel_cache (kind, value, result, updated_at)
            VALUES (%s,%s,%s::jsonb,NOW())
            ON CONFLICT (kind, value) DO UPDATE SET result=EXCLUDED.result, updated_at=NOW()
        """, (kind, value, json.dumps(result)))
        conn.commit()
    except Exception:
        conn.rollback()


def virustotal_hash_lookup(sha256: Optional[str]) -> Optional[Dict[str, Any]]:
    if not (THREAT_INTEL_ENABLED and VIRUSTOTAL_API_KEY and sha256):
        return None
    sha256 = str(sha256).strip().lower()
    if not re.fullmatch(r"[a-f0-9]{64}", sha256):
        return None
    cached = _ti_cache_get("virustotal_hash", sha256)
    if cached:
        return cached
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=THREAT_INTEL_TIMEOUT_SECONDS,
        )
        if r.status_code == 404:
            result = {"found": False, "summary": "Hash no trobat a VirusTotal"}
        else:
            r.raise_for_status()
            j = r.json()
            stats = (((j.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {})
            result = {
                "found": True,
                "malicious": int(stats.get("malicious") or 0),
                "suspicious": int(stats.get("suspicious") or 0),
                "harmless": int(stats.get("harmless") or 0),
                "undetected": int(stats.get("undetected") or 0),
                "summary": f"VT malicious={stats.get('malicious',0)} suspicious={stats.get('suspicious',0)}",
            }
        _ti_cache_set("virustotal_hash", sha256, result)
        return result
    except Exception as exc:
        return {"error": str(exc)[:180]}


def abuseipdb_ip_lookup(ip: Optional[str]) -> Optional[Dict[str, Any]]:
    if not (THREAT_INTEL_ENABLED and ABUSEIPDB_API_KEY and ip):
        return None
    ip = _valid_ip_candidate(ip)
    if not ip or is_private_ip(ip):
        return None
    cached = _ti_cache_get("abuseipdb_ip", ip)
    if cached:
        return cached
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=THREAT_INTEL_TIMEOUT_SECONDS,
        )
        r.raise_for_status()
        data = (r.json().get("data") or {})
        result = {
            "ipAddress": data.get("ipAddress"),
            "abuseConfidenceScore": data.get("abuseConfidenceScore"),
            "countryCode": data.get("countryCode"),
            "usageType": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "totalReports": data.get("totalReports"),
        }
        _ti_cache_set("abuseipdb_ip", ip, result)
        return result
    except Exception as exc:
        return {"error": str(exc)[:180]}


def enrich_event_with_v15_intel(event: Dict[str, Any]) -> Dict[str, Any]:
    md = event.setdefault("metadata", {})
    ed = safe_metadata(md.get("event_data"))
    sha = ed.get("sha256") or md.get("sha256")
    if sha:
        vt = virustotal_hash_lookup(sha)
        if vt:
            md.setdefault("threat_intel", {})["virustotal"] = vt
            if int(vt.get("malicious") or 0) > 0:
                event["severity"] = "critical" if int(vt.get("malicious") or 0) >= 5 else "high"
                event["risk_score_base"] = max(int(event.get("risk_score_base") or 0), min(100, 75 + int(vt.get("malicious") or 0)))
    ip = event.get("src_ip")
    if ip:
        abuse = abuseipdb_ip_lookup(ip)
        if abuse:
            md.setdefault("threat_intel", {})["abuseipdb"] = abuse
            try:
                score = int(abuse.get("abuseConfidenceScore") or 0)
                if score >= 75:
                    event["severity"] = "critical" if score >= 90 else "high"
                    event["risk_score_base"] = max(int(event.get("risk_score_base") or 0), min(100, 50 + score // 2))
            except Exception:
                pass
    return event


@app.post("/ingest-network")
def ingest_network(data: NetworkTelemetryInput, x_agent_token: Optional[str] = Header(default=None)):
    validate_agent_token(x_agent_token)
    event = normalize_network_telemetry(data)
    event_id = insert_event(event)
    event["id"] = event_id
    upsert_network_device(event)
    run_detection(event)
    return {"status": "stored", "event_id": event_id, "event_action": event.get("event_action"), "src_ip": event.get("src_ip")}


@app.get("/network/events")
def network_events(user=Depends(verify_token), limit: int = Query(100, ge=1, le=500)):
    cur = db_cursor()
    cur.execute("""
        SELECT id, event_time, source_name, event_action, severity, src_ip, user_name, service, raw_log, risk_score_base, metadata
        FROM events
        WHERE source_type='network_device' OR service='network'
        ORDER BY event_time DESC
        LIMIT %s
    """, (limit,))
    return cur.fetchall()


@app.get("/network/devices")
def network_devices(user=Depends(verify_token), limit: int = Query(100, ge=1, le=500)):
    cur = db_cursor()
    cur.execute("SELECT * FROM network_devices ORDER BY last_seen DESC LIMIT %s", (limit,))
    return cur.fetchall()


@app.post("/network/demo")
def network_demo(user=Depends(verify_token)):
    samples = [
        "dnsmasq-dhcp[123]: DHCPACK(br-lan) 192.168.1.56 aa:bb:cc:dd:ee:ff Samsung-TV",
        "firewall: DROP IN=br-lan OUT=wan SRC=192.168.1.56 DST=8.8.8.8 PROTO=UDP SPT=53012 DPT=53",
        "router: admin login failed from 203.0.113.45 user=admin",
        "dnsmasq[55]: query[A] suspicious-domain.xyz from 192.168.1.56",
    ]
    ids = []
    for raw in samples:
        event = normalize_network_telemetry(NetworkTelemetryInput(raw_log=raw, remote_ip="127.0.0.1", source_name="ROUTER-DEMO", metadata={"demo": True}))
        eid = insert_event(event)
        event["id"] = eid
        upsert_network_device(event)
        run_detection(event)
        ids.append(eid)
    audit(user.get("sub"), "network_demo", {"events": ids})
    return {"status": "generated", "events": ids}


@app.get("/edr/downloads")
def edr_downloads(user=Depends(verify_token), limit: int = Query(100, ge=1, le=300)):
    cur = db_cursor()
    cur.execute("""
        SELECT id, event_time, source_name, event_action, severity, user_name, service, raw_log, metadata, risk_score_base
        FROM events
        WHERE event_action LIKE %s OR service='download_guard'
        ORDER BY event_time DESC
        LIMIT %s
    """, ("download_%", limit))
    return cur.fetchall()


@app.get("/threat-intel/hash/{sha256}")
def api_vt_hash(sha256: str, user=Depends(verify_token)):
    return virustotal_hash_lookup(sha256) or {"enabled": THREAT_INTEL_ENABLED, "configured": bool(VIRUSTOTAL_API_KEY), "message": "VirusTotal no configurat o hash no vàlid"}


@app.get("/threat-intel/ip/{ip}")
def api_abuse_ip(ip: str, user=Depends(verify_token)):
    return abuseipdb_ip_lookup(ip) or {"enabled": THREAT_INTEL_ENABLED, "configured": bool(ABUSEIPDB_API_KEY), "message": "AbuseIPDB no configurat, IP privada o IP no vàlida"}


@app.get("/threat-intel/status")
def threat_intel_status(user=Depends(verify_token)):
    return {
        "enabled": THREAT_INTEL_ENABLED,
        "virustotal_configured": bool(VIRUSTOTAL_API_KEY),
        "abuseipdb_configured": bool(ABUSEIPDB_API_KEY),
        "note": "Les consultes fan servir cache de 12 hores per evitar consumir quota. VirusTotal es consulta per SHA256 i AbuseIPDB per IP pública."
    }


# Extend human labels and project assistant knowledge after v15 features are loaded.
try:
    HUMAN_ACTION_LABELS.update({
        "router_syslog_event": "Router: event syslog",
        "router_firewall_block": "Router: connexió bloquejada",
        "router_dhcp_lease": "Xarxa: dispositiu detectat per DHCP",
        "router_admin_login_activity": "Router: activitat d'autenticació",
        "dns_query_observed": "DNS: consulta observada",
        "dns_suspicious_query": "DNS: consulta sospitosa",
        "network_scan_candidate": "Xarxa: possible escaneig",
    })
except Exception:
    pass

# Override run_detection once more so new network rules are included.
_previous_run_detection_v15 = run_detection

def run_detection(event: Dict[str, Any]):
    try:
        _previous_run_detection_v15(event)
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        print("previous v15 detection failed", exc)
    try:
        if event.get("source_type") == "network_device" or event.get("service") == "network":
            run_network_detection(event)
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        print("network detection failed", exc)
    # VT hit on a downloaded file should create an alert if malicious.
    try:
        md = safe_metadata(event.get("metadata"))
        ti = safe_metadata(md.get("threat_intel"))
        vt = safe_metadata(ti.get("virustotal"))
        if int(vt.get("malicious") or 0) > 0:
            ed = safe_metadata(md.get("event_data"))
            create_alert(
                "VirusTotal malicious hash observed", "critical", min(100, 90 + int(vt.get("malicious") or 0)),
                f"VirusTotal marca com maliciós el hash del fitxer {ed.get('file_name') or ed.get('path') or '-'}: {vt.get('summary')}",
                user_name=event.get("user_name"), service="threat_intel", mitre_tactic="Initial Access", mitre_technique="T1204 User Execution",
                dedup_key=f"vt_hash:{ed.get('sha256')}", metadata={"event": event, "virustotal": vt}
            )
    except Exception as exc:
        print("vt alert failed", exc)
