import os
import logging
from typing import Optional, Dict

import pyodbc
from dotenv import load_dotenv

from src.domain.models import SyslogEvent


class MSSQLWriter:
    """
    Writer para 2 DBs en el mismo servidor (misma credencial SQL Auth):
      - watchtower_logs: syslog_events
      - watchtower_controlm: ControlM_Router_Logs + lookup Jobs/Groups
    """

    def __init__(self):
        load_dotenv()

        self.driver = os.getenv("MSSQL_DRIVER", "ODBC Driver 18 for SQL Server")
        self.server = os.getenv("MSSQL_SERVER")
        self.db_logs = os.getenv("MSSQL_DB_LOGS", "watchtower_logs")
        self.db_controlm = os.getenv("MSSQL_DB_CONTROLM", "watchtower_controlm")
        self.user = os.getenv("MSSQL_USER")
        self.password = os.getenv("MSSQL_PASSWORD")

        if not all([self.server, self.user, self.password]):
            raise ValueError("Missing MSSQL env vars: MSSQL_SERVER, MSSQL_USER, MSSQL_PASSWORD")

        self.cs_logs = self._build_cs(self.db_logs)
        self.cs_controlm = self._build_cs(self.db_controlm)

    def _build_cs(self, database: str) -> str:
        # Driver name debe ir entre llaves: DRIVER={ODBC Driver 18 for SQL Server}
        return (
            f"DRIVER={{{self.driver}}};"
            f"SERVER={self.server};"
            f"DATABASE={database};"
            f"UID={self.user};"
            f"PWD={self.password};"
            "TrustServerCertificate=yes;"
        )

    # -------------------------
    # watchtower_logs
    # -------------------------
    def insert_syslog_event(self, event: SyslogEvent, router_name: str) -> None:
        try:
            with pyodbc.connect(self.cs_logs, timeout=5) as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO dbo.syslog_events (
                        received_at_utc, source_ip, source_port, router_name,
                        pri, facility, severity,
                        syslog_ts_utc, syslog_ts_raw,
                        hostname, app_name, pid,
                        message, raw
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                event.received_at_utc,
                event.source_ip,
                event.source_port,
                router_name,
                event.pri,
                event.facility,
                event.severity,
                event.timestamp,
                event.timestamp_raw,
                event.hostname,
                event.app_name,
                event.pid,
                event.message,
                event.raw
                )
                conn.commit()
        except Exception:
            logging.exception("DB insert failed (watchtower_logs.syslog_events)")

    # -------------------------
    # watchtower_controlm
    # -------------------------
    def insert_controlm_router_log(self, event: SyslogEvent, router_name: str) -> None:
        try:
            with pyodbc.connect(self.cs_controlm, timeout=5) as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO dbo.ControlM_Router_Logs (
                        received_at_utc, source_ip, source_port,
                        router_name, hostname, app_name,
                        pri, facility, severity,
                        syslog_ts_utc, syslog_ts_raw,
                        message, raw
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                event.received_at_utc,
                event.source_ip,
                event.source_port,
                router_name,
                event.hostname,
                event.app_name,
                event.pri,
                event.facility,
                event.severity,
                event.timestamp,
                event.timestamp_raw,
                event.message,
                event.raw
                )
                conn.commit()
        except Exception:
            logging.exception("DB insert failed (watchtower_controlm.ControlM_Router_Logs)")

    def lookup_controlm_job(self, job_name: Optional[str]) -> Dict[str, Optional[object]]:
        """
        Busca en watchtower_controlm:
          Jobs_information(JobName) -> GroupCode, Severity
          Groups(GroupCode) -> GroupName

        Returns:
          {"group_code": str|None, "group_name": str|None, "sev_num": int|None}
        """
        if not job_name:
            return {"group_code": None, "group_name": None, "sev_num": None}

        try:
            with pyodbc.connect(self.cs_controlm, timeout=5) as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT TOP 1
                        j.GroupCode,
                        g.GroupName,
                        j.Severity
                    FROM dbo.Jobs_information j
                    LEFT JOIN dbo.Groups g
                        ON g.GroupCode = j.GroupCode
                    WHERE j.JobName = ?
                """, job_name)

                row = cur.fetchone()
                if not row:
                    return {"group_code": None, "group_name": None, "sev_num": None}

                group_code = row[0]
                group_name = row[1]
                sev_num = int(row[2]) if row[2] is not None else None

                return {"group_code": group_code, "group_name": group_name, "sev_num": sev_num}

        except Exception:
            logging.exception("DB lookup failed (watchtower_controlm Jobs/Groups)")
            return {"group_code": None, "group_name": None, "sev_num": None}
