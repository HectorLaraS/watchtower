from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class SyslogEvent:
    received_at_utc: datetime
    source_ip: str
    source_port: int

    pri: Optional[int]
    facility: Optional[int]
    severity: Optional[int]
    timestamp: Optional[datetime]
    timestamp_raw: Optional[str]
    hostname: Optional[str]
    app_name: Optional[str]
    pid: Optional[int]

    message: str
    raw: str
