from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class SyslogEvent:
    received_at_utc: datetime
    source_ip: str
    source_port: int

    # Estándar (best effort)
    pri: Optional[int]
    facility: Optional[int]
    severity: Optional[int]
    timestamp: Optional[datetime]   # viene sin año/tz en RFC3164, lo resolvemos best-effort
    timestamp_raw: Optional[str]
    hostname: Optional[str]
    app_name: Optional[str]
    pid: Optional[int]
    

    # Siempre
    message: str
    raw: str
