"""One process consumes CTFd flag submissions strictly one at a time."""

import fcntl
import time
from pathlib import Path


def main():
    from app import app, db
    from flag_jobs import process_one, recover

    lock = open(Path("instance") / "flag_worker.lock", "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("Flag worker is already running")
    with app.app_context():
        recover(db())
    while True:
        if not process_one(app, db):
            time.sleep(0.1)


if __name__ == "__main__":
    main()
