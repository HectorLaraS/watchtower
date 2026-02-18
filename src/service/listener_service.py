import logging
import os
from pathlib import Path

from dotenv import load_dotenv

from src.core.syslog_listener import SyslogListener, SyslogPacket
from src.domain.models import SyslogEvent
from src.service.syslog_parser import parse_syslog_rsyslog
from src.service.routes_loader import load_routes, resolve_router
from src.storage.mssql_writer import MSSQLWriter


class ListenerService:
    def __init__(self, host="0.0.0.0", port=514):
        load_dotenv()

        self.host = host
        self.port = port

        self._setup_logging()

        # 🔹 Cargar rutas dinámicas
        routes_path = os.getenv("ROUTES_PATH", "docs/routes.json")
        self.routes_index = load_routes(routes_path)

        logging.info(
            "Routes loaded: version=%s default_router=%s",
            self.routes_index.version,
            self.routes_index.default_router
        )

        # 🔹 Inicializar writer MSSQL
        self.db_writer = MSSQLWriter()

        # 🔹 Inicializar listener
        self.listener = SyslogListener(
            host=self.host,
            port=self.port,
            on_message=self._on_message
        )

    def _setup_logging(self):
        Path("logs").mkdir(exist_ok=True)

        logger = logging.getLogger()
        logger.setLevel(logging.INFO)

        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s"
        )

        file_handler = logging.FileHandler(
            "logs/syslog_listener.log",
            encoding="utf-8"
        )
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        logger.handlers = []
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    def _on_message(self, packet: SyslogPacket):
        parsed = parse_syslog_rsyslog(packet.message)

        event = SyslogEvent(
            received_at_utc=packet.received_at_utc,
            source_ip=packet.source_ip,
            source_port=packet.source_port,
            pri=parsed["pri"],
            facility=parsed["facility"],
            severity=parsed["severity"],
            timestamp=parsed["timestamp"],
            timestamp_raw=parsed["timestamp_raw"],
            hostname=parsed["hostname"],
            app_name=parsed["app_name"],
            pid=parsed["pid"],
            message=parsed["message"],
            raw=parsed["raw"],
        )

        # 🔹 Routing dinámico
        router_name, reason = resolve_router(
            self.routes_index,
            event.source_ip,
            event.hostname
        )

        # 🔹 Insertar en MSSQL
        self.db_writer.insert_syslog_event(event, router_name)

        # 🔹 Logging limpio (sin errores de placeholders)
        logging.info(
            "[ROUTER=%s reason=%s] src=%s host=%s app=%s sev=%s fac=%s msg=%s",
            router_name,
            reason,
            event.source_ip,
            event.hostname,
            event.app_name,
            event.severity,
            event.facility,
            event.message.strip(),
        )

    def run_forever(self):
        logging.info(
            "ListenerService starting on %s:%s",
            self.host,
            self.port
        )

        try:
            self.listener.start()
        except KeyboardInterrupt:
            logging.info("ListenerService stopped by user (Ctrl+C)")
        finally:
            self.listener.stop()
            logging.info("ListenerService shutdown complete")
