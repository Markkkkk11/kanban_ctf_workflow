"""Run browser workflows against an isolated, automatically cleaned database."""

import os
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request


class MockCTFd(BaseHTTPRequestHandler):
    container_started = False

    def do_GET(self):
        challenge = {
            "id": 901,
            "name": "Automatically imported",
            "category": "Web",
            "value": 333,
            "solves": 12,
        }
        if self.path == "/api/v1/challenges/901":
            body = json.dumps({"success": True, "data": {**challenge, "type": "container", "files": []}}).encode()
        elif self.path == "/api/v1/containers/info/901":
            body = json.dumps({
                "status": "running" if self.container_started else "not_found",
                "expires_at": int(time.time() * 1000) + 51 * 60 * 1000,
                "entrypoints": [{
                    "slug": "web",
                    "connection_type": "subdomain",
                    "urls": ["https://instance.tasks.example"],
                }] if self.container_started else [],
            }).encode()
        else:
            body = json.dumps({"success": True, "data": [challenge]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        type(self).container_started = True
        body = json.dumps({
            "status": "running",
            "expires_at": int(time.time() * 1000) + 51 * 60 * 1000,
            "entrypoints": [],
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), MockCTFd)
threading.Thread(target=fixture_server.serve_forever, daemon=True).start()

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="flagroom-test-") as temp:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = dict(
        os.environ,
        DATABASE=str(Path(temp) / "board.db"),
        PORT=str(port),
        HOST="127.0.0.1",
        DEEPSEEK_API_KEY="",
        COOKIE_SECURE="0",
    )
    subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            "-c",
            "from app import app, db, generate_password_hash; ctx=app.app_context(); ctx.push(); db().execute(\"INSERT INTO users(login,name,password,role,must_change) VALUES(?,?,?,?,0)\", ('browser-admin','captain',generate_password_hash('browser-test-password'),'admin')); db().execute(\"INSERT INTO competitions(name) VALUES('Test CTF')\"); db().commit()",
        ],
        cwd=ROOT,
        env=env,
        check=True,
    )
    with open(Path(temp) / "server.log", "w+") as log:
        server = subprocess.Popen(
            [str(ROOT / ".venv/bin/python"), "-c", "import os; from app import app, db; from sources import start_worker; app.config.update(TESTING=True, SOURCE_ALLOW_PRIVATE_TESTS=True); start_worker(app, db); app.run(host='127.0.0.1', port=int(os.environ['PORT']), threaded=True)"],
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=log,
        )
        try:
            url = f"http://127.0.0.1:{port}"
            for _ in range(100):
                try:
                    urllib.request.urlopen(url + "/", timeout=1).close()
                    break
                except OSError:
                    if server.poll() is not None:
                        raise RuntimeError("Test server stopped")
                    time.sleep(0.1)
            else:
                raise RuntimeError("Test server did not start")
            subprocess.run(
                ["node", "tests/browser.cjs"],
                cwd=ROOT,
                env=dict(
                    env,
                    TEST_URL=url,
                    TEST_SOURCE_URL=f"http://127.0.0.1:{fixture_server.server_port}/challenges",
                ),
                check=True,
                timeout=150,
            )
        except Exception:
            log.seek(0)
            print(log.read())
            raise
        finally:
            server.terminate()
            server.wait(timeout=10)
            fixture_server.shutdown()
