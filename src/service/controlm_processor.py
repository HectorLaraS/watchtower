import logging
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Callable

from src.domain.models import SyslogEvent


# -------------------------------------------------
# Helpers
# -------------------------------------------------

def _norm(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    s = s.strip()
    return s if s != "" else None


def _safe(val):
    return val if val not in (None, "", "None") else "-"


def _val_between(text: str, key: str, next_key: str) -> Optional[str]:
    pattern = rf"{re.escape(key)}:\s*(?P<val>.*?)\s+{re.escape(next_key)}:"
    m = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    return _norm(m.group("val"))


def _val_after(text: str, key: str) -> Optional[str]:
    pattern = rf"{re.escape(key)}:\s*(?P<val>.*)$"
    m = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    return _norm(m.group("val"))


def _date_value(text: str, key: str) -> Optional[str]:
    old_format = f"Detected Entry: {text}"
    pattern = rf"{re.escape(key)}:\s*(?P<dt>\d{{4}}-\d{{2}}-\d{{2}}\s+\d{{2}}:\d{{2}}:\d{{2}})"
    m = re.search(pattern, old_format, flags=re.IGNORECASE)
    if not m:
        return None
    return _norm(m.group("dt"))


def _text_between(text: str, start_key: str, end_key: str) -> Optional[str]:
    pattern = rf"{re.escape(start_key)}:\s*(?P<val>.*?)\s+{re.escape(end_key)}:"
    m = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    return _norm(m.group("val"))


def _string_to_date(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")


def _is_today(detected_entry: Optional[str]) -> bool:
    if not detected_entry:
        return False
    try:
        dt = _string_to_date(detected_entry)
        return dt.date() == datetime.now().date()
    except Exception:
        return False


def _ensure_file(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).touch(exist_ok=True)


def _need_alert_id(alert_id: Optional[str], ids_file: str) -> bool:
    if not alert_id:
        return False

    _ensure_file(ids_file)

    with open(ids_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if alert_id == line.strip():
                return False

    with open(ids_file, "a", encoding="utf-8", errors="replace") as f:
        f.write(f"{alert_id}\n")

    return True


def _assign_priority_from_sev(sev_num: Optional[int]) -> str:
    if sev_num == 3:
        return "Priority 2"
    if sev_num == 5:
        return "Priority 4"
    return "Priority 3"


# -------------------------------------------------
# Data class
# -------------------------------------------------

@dataclass(frozen=True)
class ControlMAlert:
    job_name: Optional[str]
    group_code: str
    group_name: Optional[str]
    incident_priority: str
    severity_letter: Optional[str]
    alert_id: Optional[str]
    detected_entry: Optional[str]
    dynatrace_line: str
    internal_line: str


# -------------------------------------------------
# Processor
# -------------------------------------------------

class ControlMProcessor:

    def __init__(
        self,
        ids_alerted_file: str = "logs/controlm/ids_alerted.log",
        alerts_to_work_file: str = "logs/controlm/alerts_to_work.log",
        internal_alerts_file: str = "logs/controlm/controlm_log_alerts.txt",
    ):
        self.ids_alerted_file = ids_alerted_file
        self.alerts_to_work_file = alerts_to_work_file
        self.internal_alerts_file = internal_alerts_file

        _ensure_file(self.ids_alerted_file)
        _ensure_file(self.alerts_to_work_file)
        _ensure_file(self.internal_alerts_file)

    def try_build_alert(
        self,
        event: SyslogEvent,
        router_name: str,
        job_lookup: Callable[[Optional[str]], Dict[str, Optional[object]]],
    ) -> Optional[ControlMAlert]:

        text = event.message

        detected_entry = _date_value(text, "Detected Entry")

        call_type = _val_between(text, "call_type", "alert_id")
        alert_id = _val_between(text, "alert_id", "data_center")
        data_center = _val_between(text, "data_center", "memname")
        memname = _val_between(text, "memname", "order_id")
        order_id = _val_between(text, "order_id", "severity")
        severity_letter = _val_between(text, "severity", "status")
        status = _val_between(text, "status", "send_time")
        send_time = _val_between(text, "send_time", "last_user")
        last_user = _val_between(text, "last_user", "last_time")
        last_time = _val_between(text, "last_time", "message")

        message = _text_between(text, "message", "run_as") or ""

        run_as = _val_between(text, "run_as", "sub_application")
        sub_application = _val_between(text, "sub_application", "application")
        application = _val_between(text, "application", "job_name")
        job_name = _val_between(text, "job_name", "host_id")

        host_id = _val_between(text, "host_id", "alert_type")
        alert_type = _val_between(text, "alert_type", "closed_from_em")
        closed_from_em = _val_between(text, "closed_from_em", "ticket_number")
        ticket_number = _val_between(text, "ticket_number", "run_counter")
        run_counter = _val_after(text, "run_counter")

        # Rule: only today
        if not _is_today(detected_entry):
            logging.info("[ControlM] Skip alert_id=%s (not today)", alert_id)
            return None

        # Rule: dedupe
        if not _need_alert_id(alert_id, self.ids_alerted_file):
            logging.info("[ControlM] Skip alert_id=%s (duplicate)", alert_id)
            return None

        # Rule: severity V only
        if (severity_letter or "").strip().upper() != "V":
            logging.info("[ControlM] Skip alert_id=%s (severity=%s)", alert_id, severity_letter)
            return None

        # DB lookup
        lookup = job_lookup(job_name)
        group_code = (lookup.get("group_code") if lookup else None) or "Z-HPO-00A-SEV4"
        group_name = (lookup.get("group_name") if lookup else None)
        sev_num = (lookup.get("sev_num") if lookup else None)

        try:
            sev_num = int(sev_num) if sev_num is not None else None
        except Exception:
            sev_num = None

        incident_priority = _assign_priority_from_sev(sev_num)

        # Special rule
        if "BSNAGT_MESSAGES_PULL" in text:
            incident_priority = "Priority 4"

        internal_line = (
            f"{_safe(event.hostname)},{_safe(job_name)},{_safe(detected_entry)},"
            f"alert_id:{_safe(alert_id)},"
            f"severity:{_safe(severity_letter)},"
            f"priority:{_safe(incident_priority)},"
            f"group:{_safe(group_code)},"
            f"message:{_safe(message)}"
        )

        dynatrace_line = (
            f"controlm_router:{_safe(router_name)},"
            f"controlm_server:{_safe(event.hostname)},"
            f"job_name:{_safe(job_name)},"
            f"detected_entry:{_safe(detected_entry)},"
            f"call_type:{_safe(call_type)},"
            f"alert_id:{_safe(alert_id)},"
            f"data_center:{_safe(data_center)},"
            f"memname:{_safe(memname)},"
            f"order_id:{_safe(order_id)},"
            f"severity:{_safe(severity_letter)},"
            f"status:{_safe(status)},"
            f"send_time:{_safe(send_time)},"
            f"last_user:{_safe(last_user)},"
            f"last_time:{_safe(last_time)},"
            f"message:{_safe(message)},"
            f"run_as:{_safe(run_as)},"
            f"sub_application:{_safe(sub_application)},"
            f"application:{_safe(application)},"
            f"host_id:{_safe(host_id)},"
            f"alert_type:{_safe(alert_type)},"
            f"closed_from_em:{_safe(closed_from_em)},"
            f"ticket_number:{_safe(ticket_number)},"
            f"run_counter:{_safe(run_counter)},"
            f"Incident_Priority:{_safe(incident_priority)},"
            f"AssignmentGroupCode:{_safe(group_code)}"
        )

        return ControlMAlert(
            job_name=job_name,
            group_code=group_code,
            group_name=group_name,
            incident_priority=incident_priority,
            severity_letter=severity_letter,
            alert_id=alert_id,
            detected_entry=detected_entry,
            dynatrace_line=dynatrace_line,
            internal_line=internal_line,
        )

    def write_alert(self, alert: ControlMAlert) -> None:
        with open(self.internal_alerts_file, "a", encoding="utf-8", errors="replace") as f:
            f.write(alert.internal_line + "\n")

        with open(self.alerts_to_work_file, "a", encoding="utf-8", errors="replace") as f:
            f.write(alert.dynatrace_line + "\n")
