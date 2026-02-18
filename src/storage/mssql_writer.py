import os
import logging
import pyodbc
from dotenv import load_dotenv

from src.domain.models import SyslogEvent


class MSSQLWriter:
    def __init__(self):
        load_dotenv()

        self.server = os.getenv("MSSQL_SERVER")
        self.db_logs = os.getenv("MSSQL_DB_LOGS")
        self.user = os.getenv("MSSQL_USER")
        self.password = os.getenv("MSSQL_PASSWORD")

        if not all([self.server, self.db_logs, self.user, self.password]):
            raise ValueError("Missing MSSQL env vars: MSSQL_SERVER, MSSQL_DB_LOGS, MSSQL_USER, MSSQL_PASSWORD")

        self.cs_logs = (
            "DRIVER={ODBC Driver 18 for SQL Server};"
            f"SERVER={self.server};"
            f"DATABASE={self.db_logs};"
            f"UID={self.user};"
            f"PWD={self.password};"
            "TrustServerCertificate=yes;"
        )

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
            logging.exception("DB insert failed")
