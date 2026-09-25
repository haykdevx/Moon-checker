import logging
import signal
import time

from django.core.management.base import BaseCommand
from django.db import close_old_connections

from checks import housekeeping

log = logging.getLogger("moon.worker")


class Command(BaseCommand):
    help = "Expires codes, marks abandoned checks, sends Discord notifications and applies data retention."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")
        parser.add_argument("--interval", type=int, default=10)

    def handle(self, once=False, interval=10, **opts):
        stop = {"flag": False}
        signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))
        last_purge = 0.0
        while not stop["flag"]:
            close_old_connections()
            try:
                expired, abandoned = housekeeping.expire_and_abandon()
                sent = housekeeping.send_notifications()
                if expired or abandoned or sent:
                    log.info("expired=%s abandoned=%s notified=%s", expired, abandoned, sent)
                if time.time() - last_purge > 3600:
                    purged = housekeeping.purge_old()
                    last_purge = time.time()
                    if purged:
                        log.info("retention purged %s checks", purged)
            except Exception:
                log.exception("worker iteration failed")
            if once:
                break
            for _ in range(interval):
                if stop["flag"]:
                    break
                time.sleep(1)
