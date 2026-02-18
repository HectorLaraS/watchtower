import logging
from pathlib import Path

from src.core.syslog_listener import SyslogListener, SyslogPacket
from src.domain.models import SyslogEvent
from src.service.syslog_parser import parse_syslog_rsyslog


class ListenerService:
    def __init__(self, host="0.0.0.0", port=1514):
        self.host = host
        self.port = port

        self._setup_logging()
        self.listener = SyslogListener(host=self.host, port=self.port, on_message=self._on_message)

    def _setup_logging(self):
        Path("logs").mkdir(exist_ok=True)
        logging.basicConfig(
            filename="logs/syslog_listener.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )

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
            hostname=parsed["hostname"],
            app_name=parsed["app_name"],
            pid=parsed["pid"],
            message=parsed["message"],
            raw=parsed["raw"],
        )

        # v1: loggea lo más útil, pero sin depender de formato vendor
        logging.info(
            "src=%s app=%s sev=%s fac=%s host=%s msg=%s",
            event.source_ip,
            event.app_name,
            event.severity,
            event.facility,
            event.hostname,
            event.message.strip(),
        )

        # si quieres verlo en consola también:
        # print(f"{event.source_ip} {event.hostname} {event.app_name}[{event.pid}] sev={event.severity} | {event.message.strip()}")

    def run_forever(self):
        logging.info("ListenerService starting on %s:%s", self.host, self.port)
        try:
            self.listener.start()
        except KeyboardInterrupt:
            logging.info("ListenerService stopped by user (Ctrl+C)")
        finally:
            self.listener.stop()
            logging.info("ListenerService shutdown complete")
