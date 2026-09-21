"""Persistent, strictly serial CTFd flag submission queue."""

import base64
import fcntl
import hashlib
import hmac
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

from sources import AuthRequired, SourceError, submit_ctfd_flag


FINAL = {"correct", "incorrect", "partial", "ratelimited", "paused", "expired", "error"}
MAX_QUEUE_WAIT = 30
_process_lock = threading.Lock()


@contextmanager
def _serial_submission():
    """One outbound CTFd attempt across threads and accidental extra processes."""
    lock_path = Path(current_app.config["DATABASE"]).parent / "flag_submission.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _process_lock, lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _cipher():
    key = hmac.new(
        current_app.config["SECRET_KEY"].encode(),
        b"flagroom:queued-flag:v1",
        hashlib.sha256,
    ).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def enqueue(conn, task_id, user_id, submission):
    encrypted = _cipher().encrypt(submission.encode()).decode()
    timestamp = int(time.time())
    conn.execute("BEGIN IMMEDIATE")
    pending = conn.execute(
        "SELECT id FROM flag_jobs WHERE task_id=? AND user_id=? "
        "AND status IN ('queued','processing') ORDER BY id DESC LIMIT 1",
        (task_id, user_id),
    ).fetchone()
    if pending:
        conn.commit()
        return pending["id"], False
    result = conn.execute(
        "INSERT INTO flag_jobs(task_id,user_id,submission,status,created_at) "
        "VALUES(?,?,?,'queued',?)",
        (task_id, user_id, encrypted, timestamp),
    )
    conn.commit()
    return result.lastrowid, True


def public_job(conn, job_id, user_id):
    row = conn.execute(
        "SELECT id,task_id,status,result,message,created_at,finished_at "
        "FROM flag_jobs WHERE id=? AND user_id=?",
        (job_id, user_id),
    ).fetchone()
    return dict(row) if row else None


def recover(conn):
    conn.execute(
        "UPDATE flag_jobs SET status='queued',started_at=NULL "
        "WHERE status='processing'"
    )
    conn.execute(
        "DELETE FROM flag_jobs WHERE finished_at IS NOT NULL AND finished_at<?",
        (int(time.time()) - 86400,),
    )
    conn.commit()


def _claim(conn):
    conn.execute("BEGIN IMMEDIATE")
    timestamp = int(time.time())
    conn.execute(
        "UPDATE flag_jobs SET status='expired',result='expired',message=?,submission='',finished_at=? "
        "WHERE status='queued' AND created_at<?",
        (
            "Очередь перегружена: проверка не началась за 30 секунд. Отправьте флаг ещё раз.",
            timestamp,
            timestamp - MAX_QUEUE_WAIT,
        ),
    )
    row = conn.execute(
        "SELECT * FROM flag_jobs WHERE status='queued' ORDER BY id LIMIT 1"
    ).fetchone()
    if not row:
        conn.commit()
        return None
    changed = conn.execute(
        "UPDATE flag_jobs SET status='processing',started_at=? "
        "WHERE id=? AND status='queued'",
        (timestamp, row["id"]),
    ).rowcount
    conn.commit()
    return dict(row) if changed else None


def _finish(conn, job_id, result, message):
    conn.execute(
        "UPDATE flag_jobs SET status=?,result=?,message=?,submission='',finished_at=? "
        "WHERE id=?",
        (result if result in FINAL else "error", result, message, int(time.time()), job_id),
    )
    conn.commit()


def process_one(app, db):
    """Process at most one job. A single service calls this, preserving FIFO order."""
    with app.app_context():
        conn = db()
        job = _claim(conn)
        if not job:
            return False
        task = conn.execute(
            "SELECT status,competition_id,title FROM tasks WHERE id=?", (job["task_id"],)
        ).fetchone()
        user = conn.execute("SELECT name FROM users WHERE id=?", (job["user_id"],)).fetchone()
        if not task or not user:
            _finish(conn, job["id"], "error", "Задача или участник больше не существует.")
            return True
        if task["status"] == "solved":
            _finish(conn, job["id"], "correct", "Задача уже решена.")
            return True
        try:
            submission = _cipher().decrypt(job["submission"].encode()).decode()
        except (InvalidToken, UnicodeError):
            _finish(conn, job["id"], "error", "Не удалось прочитать флаг из очереди.")
            return True
        try:
            with _serial_submission():
                result = submit_ctfd_flag(conn, job["task_id"], submission)
        except (AuthRequired, SourceError) as error:
            _finish(conn, job["id"], "error", str(error))
            return True

        messages = {
            "incorrect": "Флаг неверный. Проверьте формат и попробуйте ещё раз.",
            "partial": "Флаг принят частично — нужны остальные флаги.",
            "ratelimited": "CTFd ограничила число попыток. Попробуйте позже.",
            "paused": "Приём флагов на CTFd временно приостановлен.",
        }
        if result not in ("correct", "already_solved"):
            _finish(conn, job["id"], result, messages.get(result, "CTFd не подтвердила флаг."))
            return True

        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute(
            "SELECT status,competition_id,title FROM tasks WHERE id=?", (job["task_id"],)
        ).fetchone()
        if current and current["status"] != "solved":
            conn.execute("DELETE FROM solutions WHERE task_id=?", (job["task_id"],))
            conn.execute(
                "INSERT INTO solutions(task_id,user_id) VALUES(?,?)",
                (job["task_id"], job["user_id"]),
            )
            conn.execute(
                "UPDATE tasks SET status='solved',updated_at=?,revision=revision+1 WHERE id=?",
                (int(time.time()), job["task_id"]),
            )
            conn.execute(
                "INSERT INTO events(competition_id,actor,body,created_at) VALUES(?,?,?,?)",
                (
                    current["competition_id"],
                    user["name"],
                    f"{user['name']} сдал флаг и решил {current['title']}",
                    int(time.time()),
                ),
            )
        conn.execute(
            "UPDATE flag_jobs SET status='correct',result='correct',message=?,submission='',finished_at=? WHERE id=?",
            ("Флаг принят — задача решена.", int(time.time()), job["id"]),
        )
        conn.commit()
        return True
