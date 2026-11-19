"""
Background sweeper: times out ride offers nobody answered.

With push notifications there is no periodic client request that would trigger
`expire_all_stale_offers()`, so a daemon thread does it every RIDE_SWEEP_INTERVAL_SECONDS
(0 disables it, e.g. in tests). Expiry commits through the normal session, so the
"expired" / "withdrawn" events reach the rider's page and the driver's dashboard.
"""

from __future__ import annotations

import logging
import os
import threading
import time

log = logging.getLogger("rides.sweeper")

_thread: threading.Thread | None = None


def sweep_once(app) -> int:
    """Expire stale offers in an app context; returns the number of rides touched."""
    from extensions import db

    from . import matching

    with app.app_context():
        try:
            n = matching.expire_all_stale_offers()
            if n:
                db.session.commit()
                log.info("timed out offers on %d ride(s)", n)
            return n
        except Exception:  # noqa: BLE001 - never let the sweeper die
            db.session.rollback()
            log.exception("sweep failed")
            return 0
        finally:
            db.session.remove()


def start(app) -> bool:
    """Start the sweeper thread for this process (once). False when disabled / not started."""
    global _thread
    interval = float(app.config.get("RIDE_SWEEP_INTERVAL_SECONDS", 10) or 0)
    if interval <= 0 or app.testing:
        return False
    # Under the Werkzeug reloader the parent process only watches files; run in the child.
    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return False
    if _thread is not None and _thread.is_alive():
        return True

    def loop() -> None:
        while True:
            time.sleep(interval)
            sweep_once(app)

    _thread = threading.Thread(target=loop, name="ride-offer-sweeper", daemon=True)
    _thread.start()
    log.info("offer sweeper running every %.0fs", interval)
    return True
