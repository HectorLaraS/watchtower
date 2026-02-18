import re
from datetime import datetime, timezone
from typing import Optional, Tuple


# RFC3164 típico: "<34>Oct 11 22:14:15 host app[123]: msg"
RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^\s:]+)"
    r"(?::\s*)?"
    r"(?P<msg>.*)$"
)

TAG_PID_RE = re.compile(r"^(?P<app>[A-Za-z0-9_.\-/]+)(?:\[(?P<pid>\d+)\])?$")


def pri_to_fac_sev(pri: int) -> Tuple[int, int]:
    # facility = pri // 8, severity = pri % 8
    return pri // 8, pri % 8


def parse_rfc3164_timestamp(ts: str) -> Optional[datetime]:
    """
    RFC3164 no trae año ni zona horaria.
    Tomamos el año actual y asumimos que el timestamp es local del emisor.
    Para no inventar TZ del emisor, lo guardamos como naive local->UTC best effort:
    - parsea como naive
    - le asigna año actual
    - lo marca como UTC (best-effort) para que tu DB tenga algo consistente
    (Luego podremos mejorar esto con TZ/host mapping.)
    """
    try:
        now = datetime.now(timezone.utc)
        # ejemplo: "Oct 11 22:14:15"
        dt = datetime.strptime(ts, "%b %d %H:%M:%S")
        dt = dt.replace(year=now.year)
        # best-effort: lo tratamos como UTC
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def parse_syslog_rsyslog(message: str) -> dict:
    """
    Parser estándar para mensajes de rsyslog (RFC3164-ish).
    Si no matchea, regresa campos None y deja message/raw intactos.
    """
    m = RFC3164_RE.match(message.strip())
    if not m:
        return {
            "pri": None,
            "facility": None,
            "severity": None,
            "timestamp": None,
            "timestamp_raw": None,
            "hostname": None,
            "app_name": None,
            "pid": None,
            "message": message.strip(),
            "raw": message,
        }

    pri = int(m.group("pri"))
    facility, severity = pri_to_fac_sev(pri)

    ts_raw = m.group("ts")
    ts = parse_rfc3164_timestamp(ts_raw)

    hostname = m.group("host")
    tag = m.group("tag")
    msg = m.group("msg")

    app_name = None
    pid = None
    tag_m = TAG_PID_RE.match(tag)
    if tag_m:
        app_name = tag_m.group("app")
        if tag_m.group("pid"):
            pid = int(tag_m.group("pid"))
    else:
        app_name = tag  # fallback

    return {
        "pri": pri,
        "facility": facility,
        "severity": severity,
        "timestamp": ts,
        "timestamp_raw": ts_raw,
        "hostname": hostname,
        "app_name": app_name,
        "pid": pid,
        "message": msg,
        "raw": message,
    }
