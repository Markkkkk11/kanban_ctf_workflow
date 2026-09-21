import pytest
import app as mod
import flag_jobs

H = {"X-Requested-With": "CTFBoard"}


@pytest.fixture
def env(tmp_path):
    mod.app.config.update(TESTING=True, DATABASE=str(tmp_path / "test.db"), DATABASE_URL="", SOURCE_KEY_FILE=str(tmp_path / "source.key"), TASK_FILE_DIR=str(tmp_path / "task_files"), SOURCE_ALLOW_PRIVATE_TESTS=False)
    with mod.app.app_context():
        mod.init_db()
        mod.db().execute(
            "INSERT INTO users(login,name,password,role,must_change) VALUES(?,?,?,?,0)",
            (
                "admin",
                "Капитан",
                mod.generate_password_hash("a-secure-password"),
                "admin",
            ),
        )
        mod.db().execute("INSERT INTO competitions(name) VALUES('Test CTF')")
        mod.db().commit()
    c = mod.app.test_client()
    assert (
        c.post(
            "/api/login",
            json={"login": "admin", "password": "a-secure-password"},
            headers=H,
        ).status_code
        == 200
    )
    return c


def post(c, path, data):
    return c.post("/api" + path, json=data, headers=H)


def submit_and_process(client, tid, flag):
    queued = post(client, f"/tasks/{tid}/flag", {"flag": flag})
    assert queued.status_code == 202
    assert flag_jobs.process_one(mod.app, mod.db)
    return client.get(f"/api/flags/{queued.json['job_id']}")


def member(admin, role="member"):
    u = post(admin, "/admin/users", {"names": ["alice"], "role": role}).json[0]
    c = mod.app.test_client()
    post(c, "/login", u)
    assert c.get("/api/board/1").status_code == 403
    assert (
        post(
            c,
            "/password",
            {"current": u["password"], "password": "new-secure-password"},
        ).status_code
        == 200
    )
    return c


def task(c):
    return post(
        c,
        "/tasks",
        {
            "competition_id": 1,
            "title": "Cookie Monster",
            "category": "Web",
            "points": 250,
        },
    ).json["id"]


def test_auth_and_setup(env):
    anon = mod.app.test_client()
    assert anon.get("/api/board/1").status_code == 401
    assert (
        post(
            anon, "/setup", {"login": "oops", "password": "secure-password"}
        ).status_code
        == 404
    )
    assert anon.get("/api/setup").status_code == 404
    assert env.post("/api/tasks", json={}).status_code == 403
    c = member(env)
    for path in ["/admin/users", "/admin/stats/1"]:
        assert c.get("/api" + path).status_code == 403
    assert post(c, "/admin/users", {"count": 3}).status_code == 403
    assert post(c, "/import/1", {"tasks": []}).status_code == 403


def test_password_requires_at_least_eight_characters(env):
    response = post(
        env,
        "/password",
        {"current": "a-secure-password", "password": "1234567"},
    )
    assert response.status_code == 400
    assert response.json == {"error": "Минимум 8 символов"}
    assert post(
        env,
        "/password",
        {"current": "a-secure-password", "password": "12345678"},
    ).status_code == 200


@pytest.mark.parametrize("role", ["member", "captain"])
def test_platform_admin_only_controls(env, role):
    client = member(env, role=role)
    assert post(client, "/tasks", {"competition_id": 1, "title": "Forbidden"}).status_code == 403
    for path in ("/admin/users", "/admin/stats/1", "/admin/source/1"):
        assert client.get("/api" + path).status_code == 403
    assert env.get("/api/board/1").json["tasks"] == []


def test_admin_password_display_tracks_creation_change_and_reset(env):
    created = post(env, "/admin/users", {"names": ["Иванов"]}).json[0]
    entry = next(u for u in env.get("/api/admin/users").json if u["login"] == created["login"])
    uid = entry["id"]
    assert entry["password"] == created["password"]
    assert "no-store" in env.get("/api/admin/users").headers["Cache-Control"]
    client = mod.app.test_client()
    assert post(client, "/login", created).status_code == 200
    assert post(client, "/password", {"current": created["password"], "password": "new-secret-password"}).status_code == 200
    entry = next(u for u in env.get("/api/admin/users").json if u["id"] == uid)
    assert entry["password"] == "new-secret-password"
    with mod.app.app_context():
        stored = mod.rows("SELECT password,password_display FROM users WHERE id=?", (uid,))[0]
        assert "new-secret-password" not in str(stored)
        assert mod.check_password_hash(stored["password"], "new-secret-password")
    assert "password" not in str(client.get("/api/board/1").json)
    assert "password" not in str(client.get("/api/me").json)
    assert post(env, f"/admin/users/{uid}", {"name": "Петров", "role": "member", "active": True}).status_code == 200
    reset = post(env, f"/admin/users/{uid}", {"action": "reset"}).json["password"]
    entry = next(u for u in env.get("/api/admin/users").json if u["id"] == uid)
    assert entry["password"] == reset and entry["name"] == "Петров"
    assert post(client, "/login", {"login": created["login"], "password": "new-secret-password"}).status_code == 401
    assert post(client, "/login", {"login": created["login"], "password": reset}).status_code == 200


def test_legacy_password_display_populates_on_valid_login(env):
    with mod.app.app_context():
        mod.db().execute("UPDATE users SET password_display='' WHERE id=1")
        mod.db().commit()
        mod.init_db()
    assert env.get("/api/admin/users").json[0]["password"] is None
    client = mod.app.test_client()
    assert post(client, "/login", {"login": "admin", "password": "wrong"}).status_code == 401
    assert env.get("/api/admin/users").json[0]["password"] is None
    assert post(client, "/login", {"login": "admin", "password": "a-secure-password"}).status_code == 200
    assert env.get("/api/admin/users").json[0]["password"] == "a-secure-password"


def test_captain_stats_idle_first_and_competition_scoped(env, monkeypatch):
    monkeypatch.setattr(flag_jobs, "submit_ctfd_flag", lambda conn, tid, flag: "correct")
    idle = member(env)
    uid = idle.get("/api/me").json["id"]
    tid = task(env)
    post(env, f"/tasks/{tid}", {"action": "join"})
    assert submit_and_process(env, tid, "flag{admin}").json["status"] == "correct"
    active = post(env, "/tasks", {"competition_id": 1, "title": "Active"}).json["id"]
    post(env, f"/tasks/{active}", {"action": "join"})
    post(env, f"/tasks/{active}", {"action": "help", "progress": "Need help"})
    other = post(env, "/competitions", {"name": "Another CTF"}).json["id"]
    other_task = post(env, "/tasks", {"competition_id": other, "title": "Elsewhere", "points": 999}).json["id"]
    post(idle, f"/tasks/{other_task}", {"action": "join"})
    assert submit_and_process(idle, other_task, "flag{idle}").json["status"] == "correct"
    result = env.get("/api/admin/stats/1").json
    assert [u["id"] for u in result] == [uid, 1]
    assert result[0]["occupied"] == 0 and result[0]["working"] == 0 and result[0]["needs_help"] == 0 and result[0]["tasks"] == []
    assert result[1]["occupied"] == 1 and result[1]["working"] == 0 and result[1]["needs_help"] == 1
    assert result[1]["tasks"][0]["id"] == active
    assert result[0]["solved"] == 0 and result[0]["points"] == 0
    assert result[1]["solved"] == 1 and result[1]["points"] == 250
    assert env.get("/api/admin/stats/99999").status_code == 404


def test_task_lifecycle_and_shared_stats(env, monkeypatch):
    submitted = []
    def check_flag(conn, tid, flag):
        submitted.append((tid, flag))
        return "incorrect" if flag == "flag{wrong}" else "correct"
    monkeypatch.setattr(flag_jobs, "submit_ctfd_flag", check_flag)
    tid = task(env)
    c = member(env)
    uid = c.get("/api/me").json["id"]
    assert (
        post(
            c,
            f"/tasks/{tid}/flag",
            {"flag": "flag{correct}"},
        ).status_code
        == 403
    )
    assert post(c, f"/tasks/{tid}", {"action": "join"}).status_code == 200
    post(env, f"/tasks/{tid}", {"action": "join"})
    assert len(env.get("/api/board/1").json["tasks"][0]["members"]) == 2
    assert post(c, f"/tasks/{tid}", {"action": "progress", "progress": "Testing"}).status_code == 200
    assert post(c, f"/tasks/{tid}", {"action": "help"}).status_code == 200
    assert env.get("/api/board/1").json["tasks"][0]["status"] == "stuck"
    assert post(c, f"/tasks/{tid}", {"action": "work"}).status_code == 200
    wrong = submit_and_process(c, tid, "flag{wrong}")
    assert wrong.status_code == 200 and wrong.json["status"] == "incorrect"
    assert env.get("/api/board/1").json["tasks"][0]["status"] == "working"
    result = submit_and_process(c, tid, "flag{correct}")
    assert result.status_code == 200 and result.json["status"] == "correct"
    task_data = env.get("/api/board/1").json["tasks"][0]
    assert task_data["status"] == "solved"
    assert task_data["authors"] == [
        {"id": uid, "user_id": uid, "name": "alice"}
    ]
    assert len(task_data["members"]) == 2
    rating = env.get("/api/board/1").json["rating"]
    assert rating[0] == {"id": uid, "name": "alice", "solved": 1}
    assert rating[1] == {"id": 1, "name": "Капитан", "solved": 0}
    stats = env.get("/api/admin/stats/1").json
    member_stats = next(item for item in stats if item["id"] == uid)
    admin_stats = next(item for item in stats if item["id"] == 1)
    assert member_stats["solved"] == 1 and member_stats["points"] == 250
    assert admin_stats["solved"] == 0 and admin_stats["points"] == 0
    assert submitted == [(tid, "flag{wrong}"), (tid, "flag{correct}")]
    with mod.app.app_context():
        assert "flag{" not in str(mod.rows("SELECT * FROM events"))
        assert "flag{" not in str(mod.rows("SELECT * FROM solutions"))
    assert (
        post(env, f"/tasks/{tid}", {"action": "work"}).status_code
        == 400
    )


def test_rating_hides_configured_participants(env, monkeypatch):
    excluded = {
        "hidden-one": "Hidden One",
        "hidden-two": "Hidden Two",
    }
    monkeypatch.setattr(mod, "RATING_EXCLUDED_LOGINS", tuple(excluded))
    with mod.app.app_context():
        for login, name in excluded.items():
            mod.db().execute(
                "INSERT INTO users(login,name,password,role,must_change) "
                "VALUES(?,?,?,'member',0)",
                (login, name, mod.generate_password_hash("test-password")),
            )
        mod.db().commit()

    rating_names = {item["name"] for item in env.get("/api/board/1").json["rating"]}
    assert rating_names.isdisjoint(excluded.values())
    assert "Капитан" in rating_names


def test_user_can_have_only_two_working_tasks(env):
    client = member(env)
    task_ids = [
        post(
            env,
            "/tasks",
            {"competition_id": 1, "title": f"Task {number}", "points": 100},
        ).json["id"]
        for number in range(1, 4)
    ]
    first, second, third = task_ids

    assert post(client, f"/tasks/{first}", {"action": "join"}).status_code == 200
    assert post(client, f"/tasks/{second}", {"action": "join"}).status_code == 200
    blocked = post(client, f"/tasks/{third}", {"action": "join"})
    assert blocked.status_code == 409
    assert blocked.json["error"].startswith("У вас уже две задачи в работе")

    assert post(client, f"/tasks/{first}", {"action": "help"}).status_code == 200
    assert post(client, f"/tasks/{third}", {"action": "join"}).status_code == 200
    board = env.get("/api/board/1").json["tasks"]
    assert next(item for item in board if item["id"] == first)["status"] == "stuck"

    blocked = post(client, f"/tasks/{first}", {"action": "work"})
    assert blocked.status_code == 409
    assert post(client, f"/tasks/{second}", {"action": "help"}).status_code == 200
    assert post(client, f"/tasks/{first}", {"action": "work"}).status_code == 200


def test_private_chat_and_context(env, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    c = member(env)
    post(c, "/chat/1", {"message": "private message"})
    assert len(c.get("/api/chat/1").json) == 2
    assert env.get("/api/chat/1").json == []
    assert "password" not in str(c.get("/api/board/1").json)


def test_deepseek_context_excludes_sensitive_data(env, monkeypatch):
    c = member(env)
    task(env)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return b'{"choices":[{"message":{"content":"Test answer"}}]}'

    def urlopen(req, timeout):
        captured["body"] = mod.json.loads(req.data)
        return Response()

    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)
    assert post(c, "/chat/1", {"message": "What next?"}).status_code == 200
    text = str(captured["body"])
    assert "Cookie Monster" in text
    assert (
        "password" not in text
        and "test-key" not in text
        and "a-secure-password" not in text
    )


def test_import_preserves_work_and_is_atomic(env):
    tid = task(env)
    post(env, f"/tasks/{tid}", {"action": "join"})
    original = {
        "title": "Cookie Monster",
        "category": "Web",
        "points": 200,
        "solves": 40,
    }
    assert post(env, "/import/1", {"tasks": [original]}).status_code == 200
    t = env.get("/api/board/1").json["tasks"][0]
    assert t["points"] == 200 and len(t["members"]) == 1 and t["status"] == "working"
    assert (
        post(
            env,
            "/import/1",
            {"tasks": [dict(original, points=100), {"title": "Bad", "points": -1}]},
        ).status_code
        == 400
    )
    assert env.get("/api/board/1").json["tasks"][0]["points"] == 200


def test_hypotheses_permissions(env):
    tid = task(env)
    c = member(env)
    post(env, f"/tasks/{tid}/hypotheses", {"body": "Try parser confusion"})
    hid = env.get("/api/board/1").json["tasks"][0]["hypotheses"][0]["id"]
    assert post(c, f"/hypotheses/{hid}", {"status": "failed"}).status_code == 403
    assert (
        post(
            env,
            f"/hypotheses/{hid}",
            {"status": "failed", "result": "Checked both parsers"},
        ).status_code
        == 200
    )


def test_disabled_account_and_captain(env):
    c = member(env, "captain")
    uid = c.get("/api/me").json["id"]
    assert (
        post(
            c,
            "/tasks",
            {"title": "Captain task", "category": "Misc", "competition_id": 1},
        ).status_code
        == 403
    )
    assert c.get("/api/admin/stats/1").status_code == 403
    post(env, f"/admin/users/{uid}", {"role": "captain", "active": False})
    assert c.get("/api/board/1").status_code == 401


def test_multiple_competitions(env):
    task(env)
    cid = post(env, "/competitions", {"name": "Second CTF"}).json["id"]
    assert env.get(f"/api/board/{cid}").json["tasks"] == []
    assert env.get("/api/board/999").status_code == 404


def test_successful_team_logins_do_not_consume_failure_limit(env):
    for _ in range(25):
        assert (
            post(
                env, "/login", {"login": "admin", "password": "a-secure-password"}
            ).status_code
            == 200
        )


def test_stale_progress_cannot_overwrite_newer_work(env):
    tid = task(env)
    assert post(env, f"/tasks/{tid}", {"action": "progress", "progress": "No join"}).status_code == 403
    post(env, f"/tasks/{tid}", {"action": "join"})
    revision = env.get("/api/board/1").json["tasks"][0]["progress_revision"]
    assert (
        post(
            env,
            f"/tasks/{tid}",
            {
                "action": "progress",
                "progress": "First edit",
                "progress_revision": revision,
            },
        ).status_code
        == 200
    )
    assert (
        post(
            env,
            f"/tasks/{tid}",
            {
                "action": "progress",
                "progress": "Stale edit",
                "progress_revision": revision,
            },
        ).status_code
        == 409
    )
    assert env.get("/api/board/1").json["tasks"][0]["progress"] == "First edit"


def test_membership_and_status_changes_do_not_make_notes_stale(env):
    tid = task(env)
    second = member(env)
    post(env, f"/tasks/{tid}", {"action": "join"})
    task_data = env.get("/api/board/1").json["tasks"][0]
    note_revision = task_data["progress_revision"]
    general_revision = task_data["revision"]

    assert post(second, f"/tasks/{tid}", {"action": "join"}).status_code == 200
    assert post(second, f"/tasks/{tid}", {"action": "help"}).status_code == 200
    changed = env.get("/api/board/1").json["tasks"][0]
    assert changed["revision"] > general_revision
    assert changed["progress_revision"] == note_revision

    saved = post(
        env,
        f"/tasks/{tid}",
        {
            "action": "progress",
            "progress": "Не потерять эту заметку",
            "progress_revision": note_revision,
        },
    )
    assert saved.status_code == 200
    assert env.get("/api/board/1").json["tasks"][0]["progress"] == "Не потерять эту заметку"


def test_task_chat_is_private_per_task_and_shows_authors(env):
    first = task(env)
    second = post(
        env,
        "/tasks",
        {"competition_id": 1, "title": "Second task", "category": "Crypto"},
    ).json["id"]
    teammate = member(env)

    assert teammate.get(f"/api/tasks/{first}/chat").status_code == 403
    assert post(teammate, f"/tasks/{first}/chat", {"message": "Not joined"}).status_code == 403
    assert post(env, f"/tasks/{first}", {"action": "join"}).status_code == 200
    assert post(teammate, f"/tasks/{first}", {"action": "join"}).status_code == 200
    assert post(env, f"/tasks/{second}", {"action": "join"}).status_code == 200

    sent = post(teammate, f"/tasks/{first}/chat", {"message": "Нашёл endpoint"})
    assert sent.status_code == 200
    assert sent.json["author"] == "alice"
    assert sent.json["author_id"] == teammate.get("/api/me").json["id"]
    assert post(env, f"/tasks/{second}/chat", {"message": "Другая задача"}).status_code == 200

    first_chat = env.get(f"/api/tasks/{first}/chat").json
    second_chat = env.get(f"/api/tasks/{second}/chat").json
    assert [message["body"] for message in first_chat] == ["Нашёл endpoint"]
    assert [message["body"] for message in second_chat] == ["Другая задача"]
    assert first_chat[0]["author"] == "alice"


def test_existing_notes_migrate_to_task_chat_once(env):
    tid = task(env)
    assert post(env, f"/tasks/{tid}", {"action": "join"}).status_code == 200
    assert post(env, f"/tasks/{tid}", {"action": "progress", "progress": "Старая заметка"}).status_code == 200

    with mod.app.app_context():
        mod.init_db()
        mod.init_db()
        assert mod.rows("SELECT progress FROM tasks WHERE id=?", (tid,))[0]["progress"] == ""
        migrated = mod.rows(
            "SELECT author_id,body,legacy_key FROM task_messages WHERE task_id=?",
            (tid,),
        )
    assert migrated == [
        {"author_id": None, "body": "Старая заметка", "legacy_key": "progress-v1"}
    ]
    history = env.get(f"/api/tasks/{tid}/chat").json
    assert len(history) == 1
    assert history[0]["body"] == "Старая заметка"
    assert history[0]["author"] is None


def test_shared_summary_has_no_private_chat_and_is_cached(env, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    post(env, "/chat/1", {"message": "my private strategy"})
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    calls = []

    def provider(cid, tasks, recs, history, question, key):
        calls.append(history)
        return "Team summary"

    monkeypatch.setattr(mod, "ask_deepseek", provider)
    assert post(env, "/summary/1", {}).json["content"] == "Team summary"
    assert post(env, "/summary/1", {}).status_code == 200
    assert calls == [[]]
    assert env.get("/api/board/1").json["summary"][0]["content"] == "Team summary"


def test_cannot_create_or_promote_second_admin(env):
    assert (
        post(env, "/admin/users", {"names": ["second"], "role": "admin"}).status_code
        == 400
    )
    c = member(env)
    uid = c.get("/api/me").json["id"]
    assert (
        post(env, f"/admin/users/{uid}", {"role": "admin", "active": True}).status_code
        == 400
    )
    with mod.app.app_context():
        assert (
            mod.db()
            .execute("SELECT COUNT(*) FROM users WHERE role='admin'")
            .fetchone()[0]
            == 1
        )


def test_setup_unavailable_even_with_empty_database(env):
    with mod.app.app_context():
        mod.db().execute("DELETE FROM users")
        mod.db().commit()
    assert env.get("/api/setup").status_code == 404
    assert (
        post(
            env, "/setup", {"login": "new", "password": "new-admin-password"}
        ).status_code
        == 404
    )
