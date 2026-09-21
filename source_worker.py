"""Single scheduler; each collection has a hard timeout and its own process group."""

import fcntl
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def main():
    from app import app, db
    from sources import sync_once

    if len(sys.argv) == 3 and sys.argv[1] == "--once":
        sync_once(app, db, int(sys.argv[2]))
        return
    lock = open(Path("instance") / "source_worker.lock", "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("Source worker is already running")
    while True:
        with app.app_context():
            pending = [dict(row) for row in db().execute("SELECT competition_id,revision FROM sources WHERE enabled=1 AND status!='needs_action' AND next_run<=? ORDER BY next_run", (int(time.time()),))]
        for source in pending:
            # No browser stderr/traces: these may contain session-bearing URLs.
            child = subprocess.Popen([sys.executable, __file__, "--once", str(source["competition_id"])], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            timed_out = False
            try:
                code = child.wait(timeout=900)
            except subprocess.TimeoutExpired:
                timed_out, code = True, -1
            finally:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
            if code:
                with app.app_context():
                    db().execute(
                        "UPDATE sources SET status=?,stage='',error=?,failures=failures+1,next_run=? WHERE competition_id=? AND revision=?",
                        ("incomplete" if timed_out else "error", "Обход превысил пятнадцать минут. Последние данные сохранены." if timed_out else "Обработчик был прерван. Последние данные сохранены.", int(time.time()) + 300, source["competition_id"], source["revision"]),
                    )
                    db().commit()
        time.sleep(5)


if __name__ == "__main__":
    main()
