import threading
import time
from concurrent.futures import ThreadPoolExecutor

import app as mod
import flag_jobs
from test_app import H, env


def test_fifty_users_can_login_join_and_write_notes_concurrently(env):
    password = "load-test-password"
    password_hash = mod.generate_password_hash(password)
    with mod.app.app_context():
        conn = mod.db()
        for number in range(50):
            conn.execute(
                "INSERT INTO users(login,name,password,password_display,role,must_change) VALUES(?,?,?,?,?,0)",
                (
                    f"load-{number}",
                    f"Участник {number}",
                    password_hash,
                    mod.encrypt_password(password),
                    "member",
                ),
            )
            conn.execute(
                "INSERT INTO tasks(competition_id,title,category,points,updated_at) VALUES(1,?,'Misc',100,?)",
                (f"Нагрузочная задача {number}", mod.now()),
            )
        conn.commit()
        task_ids = [row["id"] for row in mod.rows("SELECT id FROM tasks ORDER BY id")]

    barrier = threading.Barrier(50)
    web_threads = threading.Semaphore(12)

    def participant(number):
        client = mod.app.test_client()
        barrier.wait(timeout=15)
        # Production Gunicorn admits 50 connections but executes 12 request
        # threads at once on the current VPS, keeping scrypt memory bounded.
        with web_threads:
            login = client.post(
                "/api/login",
                json={"login": f"load-{number}", "password": password},
                headers=H,
            )
            board = client.get("/api/board/1")
            joined = client.post(
                f"/api/tasks/{task_ids[number]}", json={"action": "join"}, headers=H
            )
            note = client.post(
                f"/api/tasks/{task_ids[number]}",
                json={"action": "progress", "progress": f"Заметка {number}"},
                headers=H,
            )
        return login.status_code, board.status_code, joined.status_code, note.status_code

    with ThreadPoolExecutor(max_workers=50) as pool:
        results = list(pool.map(participant, range(50)))
    assert results == [(200, 200, 200, 200)] * 50


def test_flag_jobs_remain_strictly_serial_with_multiple_consumers(env, monkeypatch):
    active = 0
    maximum = 0
    processed = []
    guard = threading.Lock()

    def external_submit(conn, task_id, submission):
        nonlocal active, maximum
        with guard:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.01)
        with guard:
            processed.append((task_id, submission))
            active -= 1
        return "incorrect"

    monkeypatch.setattr(flag_jobs, "submit_ctfd_flag", external_submit)
    with mod.app.app_context():
        conn = mod.db()
        task_ids = []
        for number in range(20):
            cursor = conn.execute(
                "INSERT INTO tasks(competition_id,title,category,points,updated_at) VALUES(1,?,'Misc',100,?)",
                (f"Flag task {number}", mod.now()),
            )
            task_ids.append(cursor.lastrowid)
        conn.commit()
        for number, task_id in enumerate(task_ids):
            flag_jobs.enqueue(conn, task_id, 1, f"flag{{{number}}}")

    def consume():
        while flag_jobs.process_one(mod.app, mod.db):
            pass

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda _: consume(), range(6)))
    assert maximum == 1
    assert len(processed) == 20
    with mod.app.app_context():
        jobs = mod.rows("SELECT status,submission FROM flag_jobs ORDER BY id")
    assert jobs == [{"status": "incorrect", "submission": ""}] * 20


def test_flag_job_expires_before_external_submission_after_thirty_seconds(env, monkeypatch):
    called = False

    def external_submit(*args):
        nonlocal called
        called = True
        return "correct"

    monkeypatch.setattr(flag_jobs, "submit_ctfd_flag", external_submit)
    with mod.app.app_context():
        conn = mod.db()
        task = conn.execute(
            "INSERT INTO tasks(competition_id,title,category,points,updated_at) VALUES(1,'Expired flag','Misc',100,?)",
            (mod.now(),),
        )
        conn.commit()
        job_id, _ = flag_jobs.enqueue(conn, task.lastrowid, 1, "flag{expired}")
        conn.execute("UPDATE flag_jobs SET created_at=? WHERE id=?", (mod.now() - 31, job_id))
        conn.commit()
    assert not flag_jobs.process_one(mod.app, mod.db)
    with mod.app.app_context():
        job = mod.rows("SELECT status,submission,message FROM flag_jobs WHERE id=?", (job_id,))[0]
    assert job["status"] == "expired" and job["submission"] == ""
    assert "30 секунд" in job["message"]
    assert not called
