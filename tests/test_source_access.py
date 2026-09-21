import json
import hashlib
import os
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import app as mod
import sources
from source_auth import decrypt, load_auth, save_session
from source_http import addresses, cookie_header, dial, download, download_attachment, socks_proxies
from test_app import env, post, member, task
from test_sources import configure, payload


def configure_password(client, **changes):
    configure(client, auth={"method": "password", "username": "ctf-user", "password": "site-password-PRIVATE"}, **changes)


def test_source_credentials_are_encrypted_write_only_and_preserved(env):
    configure_password(env)
    response = env.get('/api/admin/source/1').json
    assert response['has_credentials'] and response['auth_method'] == 'password'
    assert not any(key in response for key in ('payload', 'session', 'password', 'username', 'strategy'))
    assert 'PRIVATE' not in json.dumps(response)
    with mod.app.app_context():
        stored = dict(mod.db().execute('SELECT * FROM source_credentials').fetchone())
        assert 'ctf-user' not in stored['payload'] and 'PRIVATE' not in stored['payload']
        assert decrypt(stored['payload'])['username'] == 'ctf-user'
        assert Path(mod.app.config['SOURCE_KEY_FILE']).stat().st_mode & 0o777 == 0o600
    configure(env, auth={'method': 'password'})
    with mod.app.app_context():
        assert mod.db().execute('SELECT payload FROM source_credentials').fetchone()[0] == stored['payload']
    configure(env, auth={'method': 'password', 'password': 'replacement-PRIVATE'})
    with mod.app.app_context():
        row = mod.db().execute('SELECT * FROM sources').fetchone()
        auth = load_auth(mod.db(), row)
        assert auth['username'] == 'ctf-user' and auth['password'] == 'replacement-PRIVATE'
    assert post(member(env), '/admin/source/1', {'action': 'clear_auth'}).status_code == 403
    assert post(env, '/admin/source/1', {'action': 'clear_auth'}).status_code == 200
    assert env.get('/api/admin/source/1').json['has_credentials'] is False
    assert env.get('/api/admin/source/1').json['enabled'] == 0


def test_origin_change_drops_secrets_and_stale_login_cannot_restore_them(env):
    configure_password(env)
    with mod.app.app_context():
        old = dict(mod.db().execute('SELECT * FROM sources').fetchone())
    configure(env, url='https://other.example/tasks')
    with mod.app.app_context():
        save_session(mod.db(), old, {'cookies': [{'name': 'session', 'value': 'stale'}]})
        row = dict(mod.db().execute('SELECT * FROM source_credentials').fetchone())
        assert row['method'] == 'none' and not row['payload'] and not row['session']
    configure_password(env)
    response = post(env, '/admin/source/1', {'url': 'https://new.example', 'auth': {'method': 'password'}})
    assert response.status_code == 400
    assert env.get('/api/admin/source/1').json['url'] == 'https://ctf.example/challenges'
    assert env.get('/api/admin/source/1').json['has_credentials']


def test_auth_failure_pauses_until_explicit_retry(env, monkeypatch):
    configure_password(env)
    attempts = []
    def fail(source):
        attempts.append(True)
        raise sources.AuthRequired('Проверьте доступ')
    monkeypatch.setattr(sources, 'fetch_source', fail)
    assert not sources.sync_once(mod.app, mod.db, 1)
    assert env.get('/api/admin/source/1').json['status'] == 'needs_action'
    assert not sources.sync_once(mod.app, mod.db, 1)
    assert len(attempts) == 1
    configure(env, auth={'method': 'password'})
    assert not sources.sync_once(mod.app, mod.db, 1)
    assert len(attempts) == 2


def test_missing_encryption_key_does_not_silently_replace_it(env, monkeypatch):
    configure_password(env)
    Path(mod.app.config['SOURCE_KEY_FILE']).unlink()
    assert not sources.sync_once(mod.app, mod.db, 1)
    assert env.get('/api/admin/source/1').json['status'] == 'needs_action'
    assert not Path(mod.app.config['SOURCE_KEY_FILE']).exists()
    # Re-entering BOTH fields must allow recovery even if old ciphertext is lost.
    response = post(env, '/admin/source/1', {'url': 'https://ctf.example/challenges', 'auth': {'method': 'password', 'username': 'new-user', 'password': 'new-password'}})
    assert response.status_code == 200


def test_unknown_category_and_difficulty_preserve_local_members(env, monkeypatch):
    configure(env)
    monkeypatch.setattr(sources, 'download', lambda url: (payload(category='OSINT', difficulty='Hard'), 'application/json'))
    assert sources.sync_once(mod.app, mod.db, 1)
    t = env.get('/api/board/1').json['tasks'][0]
    tid = t['id']
    other = member(env)
    post(env, f'/tasks/{tid}', {'action': 'join'})
    post(other, f'/tasks/{tid}', {'action': 'join'})
    post(env, f'/tasks/{tid}', {'action': 'progress', 'progress': 'Local progress'})
    monkeypatch.setattr(sources, 'download', lambda url: (payload(category='OSINT', name='Renamed', difficulty='Medium'), 'application/json'))
    assert sources.sync_once(mod.app, mod.db, 1)
    t = env.get('/api/board/1').json['tasks'][0]
    assert t['id'] == tid and t['category'] == 'OSINT' and t['difficulty'] == 'Medium'
    assert len(t['members']) == 2 and t['progress'] == 'Local progress'
    assert post(env, '/import/1', {'tasks': [{'title': 'Manual', 'category': 'Steganography', 'difficulty': 'Easy', 'points': 100}]}).status_code == 200


def test_incomplete_batch_does_not_hide_or_overwrite_tasks(env, monkeypatch):
    configure(env)
    monkeypatch.setattr(sources, 'download', lambda url: (payload(), 'application/json'))
    assert sources.sync_once(mod.app, mod.db, 1)
    before = env.get('/api/board/1').json['tasks']
    def fail(source):
        raise sources.IncompleteSource('Неполный список')
    monkeypatch.setattr(sources, 'fetch_source', fail)
    assert not sources.sync_once(mod.app, mod.db, 1)
    assert env.get('/api/board/1').json['tasks'] == before
    assert env.get('/api/admin/source/1').json['status'] == 'incomplete'


def test_exception_details_never_leak_to_status_or_log(env, monkeypatch, caplog):
    configure_password(env)
    def fail(source):
        raise RuntimeError('Authorization: site-password-PRIVATE')
    monkeypatch.setattr(sources, 'fetch_source', fail)
    assert not sources.sync_once(mod.app, mod.db, 1)
    assert 'PRIVATE' not in json.dumps(env.get('/api/admin/source/1').json)
    assert 'PRIVATE' not in caplog.text


def test_ctfd_pagination_and_completeness():
    def read(url):
        page = 2 if 'page=2' in url else 1
        return json.dumps({'success': True, 'data': [{'id': page, 'name': f'Task {page}', 'category': 'Misc', 'value': 100, 'solves': None}], 'meta': {'pagination': {'page': page, 'pages': 2, 'total': 2}}}), 'application/json'
    tasks = sources.fetch_ctfd(read, 'https://ctf.example/api/v1/challenges')
    assert len(tasks) == 2 and all(t['difficulty'] is None for t in tasks)
    def truncated(url):
        return json.dumps({'success': True, 'data': [], 'meta': {'pagination': {'total': 2}}}), 'application/json'
    with pytest.raises(sources.IncompleteSource):
        sources.fetch_ctfd(truncated, 'https://ctf.example/api/v1/challenges')


def test_ctfd_csrf_variants():
    assert sources.ctfd_csrf('window.init = {"csrfNonce": "modern-token"}') == 'modern-token'
    assert sources.ctfd_csrf("var csrf_nonce = 'legacy-token';") == 'legacy-token'
    assert sources.ctfd_csrf('<html>no token</html>') == ''
    assert sources.ctfd_urls('https://ctf.example/api/v1/challenges/?page=2') == [
        'https://ctf.example/api/v1/challenges'
    ]


def test_not_started_is_temporary_source_error(env):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({"message": "Test CTF has not started yet"}).encode()
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        mod.app.config["SOURCE_ALLOW_PRIVATE_TESTS"] = True
        with mod.app.app_context(), pytest.raises(
            sources.CompetitionNotStarted,
            match="ещё не началось",
        ):
            download(f"http://127.0.0.1:{server.server_port}/api/v1/challenges")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_not_started_keeps_short_polling_without_failures(env, monkeypatch):
    configure(env, interval_seconds=120)

    def not_started(source):
        raise sources.CompetitionNotStarted(
            "Соревнование ещё не началось. Синхронизация повторится автоматически."
        )

    monkeypatch.setattr(sources, "fetch_source", not_started)
    assert not sources.sync_once(mod.app, mod.db, 1)
    state = env.get("/api/admin/source/1").json
    assert state["status"] == "queued"
    assert state["failures"] == 0
    assert "ещё не началось" in state["error"]
    assert 119 <= state["next_run"] - state["last_attempt"] <= 121


def test_attachment_redirect_never_forwards_source_credentials_to_cdn(env, tmp_path):
    seen = {}

    class CDN(BaseHTTPRequestHandler):
        def do_GET(self):
            seen["authorization"] = self.headers.get("Authorization")
            seen["cookie"] = self.headers.get("Cookie")
            body = b"safe attachment"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    cdn = ThreadingHTTPServer(("127.0.0.1", 0), CDN)

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            seen["origin_authorization"] = self.headers.get("Authorization")
            seen["origin_cookie"] = self.headers.get("Cookie")
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{cdn.server_port}/payload.bin")
            self.end_headers()

        def log_message(self, *args):
            pass

    origin_server = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    threads = [
        threading.Thread(target=cdn.serve_forever),
        threading.Thread(target=origin_server.serve_forever),
    ]
    for thread in threads:
        thread.start()
    try:
        mod.app.config["SOURCE_ALLOW_PRIVATE_TESTS"] = True
        url = f"http://127.0.0.1:{origin_server.server_port}/file"
        with mod.app.app_context():
            storage_name, size = download_attachment(
                url,
                {"token": "PRIVATE", "cookie": "session=PRIVATE"},
                sources.origin(url),
                tmp_path / "files",
            )
        assert size == len(b"safe attachment")
        assert (tmp_path / "files" / storage_name).read_bytes() == b"safe attachment"
        assert seen["origin_authorization"] == "Token PRIVATE"
        assert seen["origin_cookie"] == "session=PRIVATE"
        assert seen["authorization"] is None and seen["cookie"] is None
    finally:
        origin_server.shutdown()
        cdn.shutdown()
        origin_server.server_close()
        cdn.server_close()
        for thread in threads:
            thread.join(timeout=2)


def test_ctfd_flag_submission_uses_mapped_id_and_saved_account(env, monkeypatch):
    configure(env, auth={"method": "token", "token": "ctfd-token-PRIVATE"})
    monkeypatch.setattr(
        sources,
        "download",
        lambda url, auth=None: (payload(), "application/json"),
    )
    assert sources.sync_once(mod.app, mod.db, 1)
    board = env.get('/api/board/1').json
    task_data = board['tasks'][0]
    assert task_data['flag_submission'] is True
    captured = {}

    def submit(url, body, auth=None, csrf_token='', timeout=20):
        captured.update(url=url, body=body, auth=auth, csrf=csrf_token)
        return 200, json.dumps({"success": True, "data": {"status": "correct"}})

    monkeypatch.setattr('source_http.post_json', submit)
    with mod.app.app_context():
        result = sources.submit_ctfd_flag(mod.db(), task_data['id'], 'flag{PRIVATE}')
        stored = str(mod.rows('SELECT * FROM events')) + str(mod.rows('SELECT * FROM source_tasks'))
    assert result == 'correct'
    assert captured['url'] == 'https://ctf.example/api/v1/challenges/attempt'
    assert captured['body'] == {"challenge_id": 42, "submission": "flag{PRIVATE}"}
    assert captured['auth']['token'] == 'ctfd-token-PRIVATE'
    assert captured['csrf'] == ''
    assert 'flag{PRIVATE}' not in stored


def test_ctfd_attachments_are_cached_sanitized_and_require_login(env, monkeypatch):
    configure(env, mode="ctfd")
    calls = {"details": 0, "downloads": 0, "limits": []}

    def source_download(url, auth=None):
        if url.rstrip("/").endswith("/42"):
            calls["details"] += 1
            return json.dumps({
                "success": True,
                "data": {
                    "id": 42,
                    "name": "External task",
                    "type": "container",
                    "description": "Full task description",
                    "files": [
                        "/files/tool.zip?token=PRIVATE",
                        {"name": "../../payload.bin", "url": "/files/payload.bin"},
                    ],
                },
            }), "application/json"
        return payload(), "application/json"

    def attachment_download(url, auth, source_origin, directory, max_size=0):
        calls["downloads"] += 1
        calls["limits"].append(max_size)
        content = ("content:" + url.rsplit("/", 1)[-1].split("?", 1)[0]).encode()
        storage_name = hashlib.sha256(content).hexdigest()
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        (root / storage_name).write_bytes(content)
        return storage_name, len(content)

    monkeypatch.setattr(sources, "download", source_download)
    monkeypatch.setattr("source_http.download_attachment", attachment_download)
    assert sources.sync_once(mod.app, mod.db, 1)
    board = env.get("/api/board/1").json
    task_data = board["tasks"][0]
    assert task_data["description"] == "Full task description"
    assert task_data["container_enabled"] is True
    names = [item["filename"] for item in task_data["files"]]
    assert names[0] == "tool.zip" and names[1].endswith("payload.bin")
    assert all(".." not in name and "/" not in name and "\\" not in name for name in names)
    assert all(set(item) == {"id", "filename", "size"} for item in task_data["files"])

    first = task_data["files"][0]
    downloaded = env.get(f"/api/task-files/{first['id']}")
    assert downloaded.status_code == 200 and downloaded.data == b"content:tool.zip"
    assert "attachment" in downloaded.headers["Content-Disposition"]
    assert mod.app.test_client().get(f"/api/task-files/{first['id']}").status_code == 401

    # A normal two-minute source poll does not refetch challenge details or files.
    assert sources.sync_once(mod.app, mod.db, 1)
    assert calls == {
        "details": 1,
        "downloads": 2,
        "limits": [sources.MAX_ATTACHMENT_SIZE, sources.MAX_ATTACHMENT_SIZE],
    }

    # The 30-minute metadata refresh reuses unchanged content-addressed files.
    with mod.app.app_context():
        mod.db().execute("UPDATE sources SET attachments_checked=0 WHERE competition_id=1")
        mod.db().commit()
    assert sources.sync_once(mod.app, mod.db, 1)
    assert calls == {
        "details": 2,
        "downloads": 2,
        "limits": [sources.MAX_ATTACHMENT_SIZE, sources.MAX_ATTACHMENT_SIZE],
    }


def test_attachment_cache_preserves_disk_reserve(env, monkeypatch):
    source = {
        "_attachment_dir": str(Path(mod.app.config["TASK_FILE_DIR"])),
        "_known_attachments": {},
        "_auth": {},
    }
    tasks = [{
        "external_id": "42",
        "attachments": [{"url": "https://ctf.example/files/large.zip", "filename": "large.zip"}],
    }]
    monkeypatch.setattr(
        sources.shutil,
        "disk_usage",
        lambda _path: type("Usage", (), {"free": sources.MIN_FREE_STORAGE})(),
    )
    monkeypatch.setattr(
        "source_http.download_attachment",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("download started")),
    )
    with pytest.raises(sources.IncompleteSource, match="резерв 10 ГБ"):
        sources.cache_ctfd_attachments(source, tasks, "https://ctf.example/api/v1/challenges")


def test_cookie_scope_and_private_network_guard(monkeypatch):
    auth = {'storage': {'cookies': [{'name': 'session', 'value': 'SECRET', 'domain': 'ctf.example', 'path': '/tasks', 'secure': True, 'expires': -1}]}}
    assert cookie_header('https://ctf.example/tasks/1', auth) == 'session=SECRET'
    assert cookie_header('https://ctf.example/tasks-other', auth) == ''
    assert cookie_header('http://ctf.example/tasks', auth) == ''
    assert cookie_header('https://elsewhere.example/tasks', auth) == ''
    for ip in ('127.0.0.1', '169.254.169.254', '10.0.0.1', '::1'):
        monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 80))])
        with pytest.raises(sources.SourceError):
            addresses('ctf.example', 80)


def test_local_socks_failover_uses_validated_numeric_address(monkeypatch):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    requested = []

    def serve():
        connection, _ = listener.accept()
        with connection:
            assert connection.recv(3) == b'\x05\x01\x00'
            connection.sendall(b'\x05\x00')
            head = connection.recv(4)
            assert head == b'\x05\x01\x00\x01'
            address = socket.inet_ntoa(connection.recv(4))
            port = struct.unpack('!H', connection.recv(2))[0]
            requested.append((address, port))
            connection.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')

    thread = threading.Thread(target=serve)
    thread.start()
    monkeypatch.setattr('source_http.addresses', lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('198.51.100.10', 443))])
    monkeypatch.setenv('SOURCE_SOCKS_PROXIES', f'socks5://127.0.0.1:1,socks5://127.0.0.1:{listener.getsockname()[1]}')
    connection = dial('example.com', 443, timeout=1)
    connection.close()
    thread.join(timeout=2)
    listener.close()
    assert requested == [('198.51.100.10', 443)]


def test_socks_proxy_must_be_local(monkeypatch):
    monkeypatch.setenv('SOURCE_SOCKS_PROXIES', 'socks5://198.51.100.10:1080')
    with pytest.raises(sources.SourceError):
        socks_proxies()


def test_difficulty_must_be_in_source_evidence():
    item = dict(title='Task Alpha', category='Misc', points=250, solves=None, difficulty='Hard', external_id=None, evidence='Task Alpha 250')
    with pytest.raises(sources.SourceError):
        sources.validate_ai({'kind': 'tasks', 'tasks': [item]}, 'Task Alpha 250')
    assert sources.parse_ctfd(payload(tags=[{'value': 'Hard'}]))[0]['difficulty'] == 'Hard'
    assert sources.parse_ctfd(payload(tags=[{'value': 'Hard'}, {'value': 'Easy'}]))[0]['difficulty'] is None
