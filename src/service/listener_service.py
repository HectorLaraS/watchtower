import logging
import os
from pathlib import Path

from dotenv import load_dotenv

from src.core.syslog_listener import SyslogListener, SyslogPacket
from src.domain.models import SyslogEvent
from src.service.syslog_parser import parse_syslog_rsyslog
from src.service.routes_loader import load_routes, resolve_router
from src.storage.mssql_writer import MSSQLWriter

from src.service.controlm_processor import ControlMProcessor


class ListenerService:
    def __init__(self, host="0.0.0.0", port=514):
        load_dotenv()

        self.host = host
        self.port = port

        # Flag para imprimir payload completo (opcional)
        self.print_raw = os.getenv("PRINT_RAW_SYSLOG", "0").strip() in ("1", "true", "True", "YES", "yes")

        self._setup_logging()

        # Routes dinámicas
        routes_path = os.getenv("ROUTES_PATH", "docs/routes.json")
        self.routes_index = load_routes(routes_path)

        logging.info(
            "Routes loaded: version=%s default_router=%s routes_path=%s",
            self.routes_index.version,
            self.routes_index.default_router,
            routes_path
        )

        # MSSQL writer (2 DBs)
        self.db_writer = MSSQLWriter()

        # Control-M processor
        self.controlm = ControlMProcessor(
            ids_alerted_file="logs/controlm/ids_alerted.log",
            alerts_to_work_file="logs/controlm/alerts_to_work.log",
            internal_alerts_file="logs/controlm/controlm_log_alerts.txt",
        )

        # Listener UDP
        self.listener = SyslogListener(
            host=self.host,
            port=self.port,
            on_message=self._on_message
        )

    def _setup_logging(self):
        Path("logs").mkdir(exist_ok=True)

        logger = logging.getLogger()
        logger.setLevel(logging.INFO)

        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        file_handler = logging.FileHandler("logs/syslog_listener.log", encoding="utf-8")
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        logger.handlers = []
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    def _on_message(self, packet: SyslogPacket):
        # Parse syslog estándar
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

        # Routing dinámico
        router_name, reason = resolve_router(
            self.routes_index,
            event.source_ip,
            event.hostname
        )

        # ✅ SIEMPRE imprime lo que llega (aunque sea raw)
        summary = (
            f"[INCOMING router={router_name} reason={reason}] "
            f"src={event.source_ip}:{event.source_port} "
            f"host={event.hostname or '-'} "
            f"app={event.app_name or '-'} "
            f"sev={event.severity if event.severity is not None else '-'} "
            f"msg={event.message.strip()}"
        )
        print(summary)
        logging.info(summary)

        # Opcional: imprimir el raw completo
        if self.print_raw:
            print(f"[RAW] {event.raw}")
            logging.info("[RAW] %s", event.raw)

        # 1) Siempre insertar a watchtower_logs
        self.db_writer.insert_syslog_event(event, router_name)

        # 3) Control-M pipeline (solo si NO es raw)
        if router_name != "raw":
            # 3.1 guardar también log crudo del router en watchtower_controlm
            self.db_writer.insert_controlm_router_log(event, router_name)

            # 3.2 aplicar reglas Control-M
            alert = self.controlm.try_build_alert(
                event=event,
                router_name=router_name,
                job_lookup=self.db_writer.lookup_controlm_job
            )

            if alert:
                self.controlm.write_alert(alert)
                logging.info(
                    "[ControlM] ALERT generated alert_id=%s job=%s group=%s priority=%s",
                    alert.alert_id,
                    alert.job_name,
                    alert.group_code,
                    alert.incident_priority
                )
            else:
                # 👇 útil para saber por qué "no ejecuta nada"
                logging.info("[ControlM] No alert generated for this message (rules not met)")

    def run_forever(self):
        logging.info("ListenerService starting on %s:%s", self.host, self.port)
        try:
            self.listener.start()
        except KeyboardInterrupt:
            logging.info("ListenerService stopped by user (Ctrl+C)")
        finally:
            self.listener.stop()
            logging.info("ListenerService shutdown complete")
