import socket
import threading
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional


@dataclass(frozen=True)
class SyslogPacket:
    received_at_utc: datetime
    source_ip: str
    source_port: int
    raw: bytes
    message: str


class SyslogListener:
    """
    Core UDP Syslog Listener
    - Recibe datagrams UDP
    - Decodifica a texto (no revienta)
    - Entrega paquetes a callback (service layer)
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 1514,
        buffer_size: int = 8192,
        on_message: Optional[Callable[[SyslogPacket], None]] = None,
    ):
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.on_message = on_message

        self._sock: Optional[socket.socket] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if self._sock is not None:
            raise RuntimeError("Listener already started")

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(1.0)

        while not self._stop_event.is_set():
            try:
                data, (ip, src_port) = self._sock.recvfrom(self.buffer_size)
            except socket.timeout:
                continue
            except OSError:
                break

            received_at = datetime.now(timezone.utc)
            msg = data.decode("utf-8", errors="replace")

            packet = SyslogPacket(
                received_at_utc=received_at,
                source_ip=ip,
                source_port=src_port,
                raw=data,
                message=msg,
            )

            if self.on_message:
                try:
                    self.on_message(packet)
                except Exception:
                    logging.exception("on_message handler failed")

        self._cleanup()

    def stop(self) -> None:
        self._stop_event.set()
        self._cleanup()

    def _cleanup(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
