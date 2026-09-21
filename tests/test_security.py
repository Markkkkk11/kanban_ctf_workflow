import app as mod
from test_app import H, env, post, task


def test_anonymous_user_cannot_read_any_private_api_or_database(env):
    tid = task(env)
    anonymous = mod.app.test_client()
    private_gets = [
        "/api/me",
        "/api/competitions",
        "/api/board/1",
        "/api/flags/1",
        "/api/task-files/1",
        f"/api/tasks/{tid}/container",
        "/api/admin/users",
        "/api/admin/stats/1",
        "/api/admin/source/1",
        "/api/chat/1",
    ]
    for path in private_gets:
        response = anonymous.get(path)
        assert response.status_code == 401, (path, response.status_code, response.data)
        assert b"Cookie Monster" not in response.data

    private_posts = [
        ("/api/password", {}),
        ("/api/competitions", {}),
        ("/api/tasks", {}),
        (f"/api/tasks/{tid}", {"action": "join"}),
        (f"/api/tasks/{tid}/flag", {"flag": "flag{probe}"}),
        (f"/api/tasks/{tid}/container", {"action": "start"}),
        (f"/api/tasks/{tid}/hypotheses", {"body": "probe"}),
        ("/api/hypotheses/1", {}),
        ("/api/admin/users", {}),
        ("/api/admin/users/1", {}),
        ("/api/admin/source/1", {}),
        ("/api/import/1", {}),
        ("/api/summary/1", {}),
        ("/api/chat/1", {}),
    ]
    for path, body in private_posts:
        response = anonymous.post(path, json=body, headers=H)
        assert response.status_code == 401, (path, response.status_code, response.data)

    assert anonymous.get("/instance/board.db").status_code == 404
    assert anonymous.get("/static/../instance/board.db").status_code == 404
    assert b"Cookie Monster" not in anonymous.get("/").data


def test_forged_session_cookie_does_not_authorize(env):
    client = mod.app.test_client()
    client.set_cookie("session", "eyJ1aWQiOjF9.invalid-signature")
    assert client.get("/api/me").status_code == 401
    assert client.get("/api/board/1").status_code == 401


def test_login_rejects_sql_injection_and_non_string_values(env):
    payloads = [
        {"login": "' OR 1=1 --", "password": "anything"},
        {"login": "admin' UNION SELECT 1 --", "password": "anything"},
        {"login": ["admin"], "password": "a-secure-password"},
        {"login": "admin", "password": {"$ne": ""}},
        {"login": "admin\x00' OR 1=1 --", "password": "anything"},
        {"login": "a" * 101, "password": "anything"},
    ]
    for payload in payloads:
        client = mod.app.test_client()
        response = client.post("/api/login", json=payload, headers=H)
        assert response.status_code == 401
        assert response.json == {"error": "Неверный логин или пароль"}
        assert client.get("/api/board/1").status_code == 401
    with mod.app.app_context():
        assert mod.db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def test_bound_sql_parameters_store_metacharacters_as_plain_text(env):
    title = "x'); DROP TABLE users; --"
    response = post(
        env,
        "/tasks",
        {"competition_id": 1, "title": title, "category": "Misc", "points": 1},
    )
    assert response.status_code == 200
    board = env.get("/api/board/1").json
    assert board["tasks"][0]["title"] == title
    with mod.app.app_context():
        assert mod.db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def test_login_has_csrf_cookie_and_bruteforce_guards(env):
    client = mod.app.test_client()
    assert client.post(
        "/api/login", json={"login": "admin", "password": "a-secure-password"}
    ).status_code == 403
    response = client.post(
        "/api/login",
        json={"login": "admin", "password": "a-secure-password"},
        headers=H,
    )
    assert response.status_code == 200
    cookie = response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    secure_page = client.get("/", base_url="https://localhost")
    assert secure_page.headers["Strict-Transport-Security"] == "max-age=31536000"
    assert "Access-Control-Allow-Origin" not in secure_page.headers

    attacker = mod.app.test_client()
    for _ in range(10):
        assert attacker.post(
            "/api/login",
            json={"login": "victim", "password": "wrong-password"},
            headers=H,
        ).status_code == 401
    assert attacker.post(
        "/api/login",
        json={"login": "victim", "password": "wrong-password"},
        headers=H,
    ).status_code == 429
