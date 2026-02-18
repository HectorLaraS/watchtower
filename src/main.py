import os
from dotenv import load_dotenv

from src.service.listener_service import ListenerService


def main():
    load_dotenv()

    host = os.getenv("SYSLOG_HOST", "0.0.0.0")
    port = int(os.getenv("SYSLOG_PORT", 1514))

    service = ListenerService(host=host, port=port)
    service.run_forever()


if __name__ == "__main__":
    main()
