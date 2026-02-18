import logging
from pathlib import Path

from src.core.syslog_listener import SyslogListener, SyslogPacket


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
        # v1: solo loggea
        print(f"SYSLOG {packet.source_ip}:{packet.source_port} | {packet.message.strip()}")

        logging.info(
            "SYSLOG from %s:%s | %s",
            packet.source_ip,
            packet.source_port,
            packet.message.strip()
        )

    def run_forever(self):
        logging.info("ListenerService starting on %s:%s", self.host, self.port)

        try:
            self.listener.start()
        except KeyboardInterrupt:
            logging.info("ListenerService stopped by user (Ctrl+C)")
        finally:
            self.listener.stop()
            logging.info("ListenerService shutdown complete")

