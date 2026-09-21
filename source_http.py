"""Public-only, DNS-pinned transport and browser egress proxy for untrusted sites."""

import http.client
import hashlib
import ipaddress
import json
import os
import select
import socket
import ssl
import struct
import threading
import time
import tempfile
from contextlib import contextmanager
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urljoin
from pathlib import Path

from flask import current_app, has_app_context

from sources import (
    AuthRequired, CompetitionNotStarted, SourceError, MAX_BODY, normalize_url,
    origin,
)


def test_network_allowed():
    return bool(has_app_context() and current_app.testing and current_app.config.get("SOURCE_ALLOW_PRIVATE_TESTS"))


def addresses(host, port, allow_private=False):
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not records or any(not ipaddress.ip_address(row[4][0]).is_global for row in records) and not allow_private:
            raise SourceError("Адрес площадки должен быть публичным. Локальные и служебные адреса недоступны.")
        return records
    except (socket.gaierror, ValueError):
        raise SourceError("Не удалось определить адрес площадки.") from None


def socks_proxies():
    """Return local SOCKS5 sidecars in failover order; never fall back to direct."""
    configured = os.getenv("SOURCE_SOCKS_PROXIES", "").strip()
    if not configured:
        return []
    proxies = []
    for value in configured.split(","):
        target = urlsplit(value.strip())
        try:
            address = ipaddress.ip_address(target.hostname or "")
            port = target.port
        except ValueError:
            raise SourceError("Исходящий SOCKS-прокси задан неверно.") from None
        if target.scheme != "socks5" or not address.is_loopback or not port or target.username or target.password or target.path not in ("", "/") or target.query or target.fragment:
            raise SourceError("Исходящий SOCKS-прокси должен быть локальным адресом socks5://127.0.0.1:PORT.")
        proxies.append((str(address), port))
    if len(proxies) > 8:
        raise SourceError("Задано слишком много исходящих прокси.")
    return proxies


def receive_exact(connection, length):
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise OSError("SOCKS proxy closed the connection")
        data.extend(chunk)
    return bytes(data)


def socks_dial(proxy, sockaddr, timeout):
    """Ask a local sidecar to connect to the already validated numeric IP."""
    proxy_host, proxy_port = proxy
    connection = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    connection.settimeout(timeout)
    try:
        connection.sendall(b"\x05\x01\x00")
        if receive_exact(connection, 2) != b"\x05\x00":
            raise OSError("SOCKS authentication rejected")
        address = ipaddress.ip_address(sockaddr[0])
        atyp = b"\x01" if address.version == 4 else b"\x04"
        connection.sendall(b"\x05\x01\x00" + atyp + address.packed + struct.pack("!H", sockaddr[1]))
        head = receive_exact(connection, 4)
        if head[:2] != b"\x05\x00":
            raise OSError("SOCKS connection rejected")
        if head[3] == 1:
            receive_exact(connection, 4)
        elif head[3] == 4:
            receive_exact(connection, 16)
        elif head[3] == 3:
            receive_exact(connection, receive_exact(connection, 1)[0])
        else:
            raise OSError("Invalid SOCKS response")
        receive_exact(connection, 2)
        return connection
    except Exception:
        connection.close()
        raise


def dial(host, port, allow_private=False, timeout=20):
    # Connect to the validated IP, never resolve the hostname again (DNS rebinding).
    records = addresses(host, port, allow_private)
    proxies = socks_proxies()
    for family, kind, proto, _, sockaddr in records:
        if proxies:
            for proxy in proxies:
                try:
                    return socks_dial(proxy, sockaddr, timeout)
                except OSError:
                    continue
            continue
        connection = socket.socket(family, kind, proto)
        connection.settimeout(timeout)
        try:
            connection.connect(sockaddr)
            return connection
        except OSError:
            connection.close()
    raise SourceError("Не удалось соединиться с площадкой.")


def cookie_header(url, auth):
    cookies = SimpleCookie()
    try:
        cookies.load(auth.get("cookie", ""))
    except CookieError:
        raise AuthRequired("Некорректные cookies. Вставьте значение заголовка Cookie заново.") from None
    target = urlsplit(url)
    for item in (auth.get("storage") or {}).get("cookies", []):
        domain = item.get("domain", "").lstrip(".")
        path = item.get("path", "/")
        requested = target.path or "/"
        path_matches = requested == path or requested.startswith(path if path.endswith("/") else path + "/")
        expires = item.get("expires", -1)
        if (target.hostname == domain or (item.get("domain", "").startswith(".") and target.hostname.endswith("." + domain))) and path_matches and (not item.get("secure") or target.scheme == "https") and (expires == -1 or expires > time.time()):
            cookies[item["name"]] = item["value"]
    return "; ".join(f"{key}={value.coded_value}" for key, value in cookies.items())


def download(url, auth=None, timeout=20):
    auth = auth or {}
    initial = origin(url)
    for _ in range(6):
        url = normalize_url(url)
        target = urlsplit(url)
        port = target.port or (443 if target.scheme == "https" else 80)
        headers = {"User-Agent": "Flagroom/2.0 (CTF task sync)", "Accept": "application/json,text/html", "Accept-Encoding": "identity"}
        if auth.get("token"):
            headers["Authorization"] = "Token " + auth["token"]
        cookies = cookie_header(url, auth)
        if cookies:
            headers["Cookie"] = cookies
        conn = http.client.HTTPConnection(target.hostname, port, timeout=timeout)
        try:
            conn.sock = dial(target.hostname, port, test_network_allowed(), timeout)
            if target.scheme == "https":
                conn.sock = ssl.create_default_context().wrap_socket(conn.sock, server_hostname=target.hostname)
            conn.request("GET", (target.path or "/") + ("?" + target.query if target.query else ""), headers=headers)
            response = conn.getresponse()
            if response.status == 403 and "json" in response.getheader("Content-Type", ""):
                raw = response.read(64 * 1024 + 1)
                try:
                    message = json.loads(raw.decode("utf-8-sig")).get("message", "")
                except (ValueError, UnicodeError, AttributeError):
                    message = ""
                if isinstance(message, str) and (
                    "has not started" in message.lower()
                    or "ещё не начал" in message.lower()
                    or "еще не начал" in message.lower()
                ):
                    raise CompetitionNotStarted(
                        "Соревнование ещё не началось. Синхронизация повторится автоматически."
                    )
                raise AuthRequired("Площадка требует вход или отклонила сохранённый доступ.")
            if response.status in (401, 403):
                raise AuthRequired("Площадка требует вход или отклонила сохранённый доступ.")
            if response.status in (301, 302, 303, 307, 308):
                destination = normalize_url(urljoin(url, response.getheader("Location", "")))
                if origin(destination) != initial:
                    raise AuthRequired("Площадка перенаправляет на другой адрес. Укажите конечный URL и настройте доступ для него.")
                url = destination
                continue
            if response.status >= 400:
                raise SourceError(f"Площадка вернула HTTP {response.status}.")
            raw = response.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                raise SourceError("Ответ площадки больше 2 МБ. Выгрузка не применена.")
            return raw.decode("utf-8-sig"), response.getheader("Content-Type", "text/html").split(";", 1)[0]
        except (OSError, http.client.HTTPException, UnicodeError):
            raise SourceError("Не удалось прочитать площадку: соединение, кодировка или тайм-аут.") from None
        finally:
            conn.close()
    raise SourceError("Слишком много перенаправлений площадки.")


def post_json(url, payload, auth=None, csrf_token="", timeout=20):
    """POST a small JSON payload to one pinned origin without following redirects."""
    auth = auth or {}
    url = normalize_url(url)
    target = urlsplit(url)
    port = target.port or (443 if target.scheme == "https" else 80)
    try:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError):
        raise SourceError("Не удалось подготовить запрос к площадке.") from None
    if len(body) > 16 * 1024:
        raise SourceError("Запрос к площадке слишком большой.")
    headers = {
        "User-Agent": "Flagroom/2.0 (CTF flag submit)",
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }
    if auth.get("token"):
        headers["Authorization"] = "Token " + auth["token"]
    cookies = cookie_header(url, auth)
    if cookies:
        headers["Cookie"] = cookies
    if csrf_token:
        headers["CSRF-Token"] = csrf_token
    conn = http.client.HTTPConnection(target.hostname, port, timeout=timeout)
    try:
        conn.sock = dial(target.hostname, port, test_network_allowed(), timeout)
        if target.scheme == "https":
            conn.sock = ssl.create_default_context().wrap_socket(
                conn.sock, server_hostname=target.hostname
            )
        path = (target.path or "/") + ("?" + target.query if target.query else "")
        conn.request("POST", path, body=body, headers=headers)
        response = conn.getresponse()
        raw = response.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise SourceError("Ответ проверки флага слишком большой.")
        return response.status, raw.decode("utf-8-sig")
    except (OSError, http.client.HTTPException, UnicodeError):
        raise SourceError("Не удалось отправить флаг: соединение или тайм-аут.") from None
    finally:
        conn.close()


def download_attachment(url, auth, source_origin, directory, max_size=2 * 1024 * 1024 * 1024):
    """Stream an attachment into content-addressed local storage without buffering it."""
    initial_scheme = urlsplit(url).scheme
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for _ in range(6):
        url = normalize_url(url)
        target = urlsplit(url)
        if initial_scheme == "https" and target.scheme != "https":
            raise SourceError("Файл перенаправляет на незащищённое соединение.")
        port = target.port or (443 if target.scheme == "https" else 80)
        headers = {
            "User-Agent": "Flagroom/2.0 (CTF attachment sync)",
            "Accept": "application/octet-stream,*/*",
            "Accept-Encoding": "identity",
        }
        if origin(url) == source_origin:
            if auth.get("token"):
                headers["Authorization"] = "Token " + auth["token"]
            cookies = cookie_header(url, auth)
            if cookies:
                headers["Cookie"] = cookies
        conn = http.client.HTTPConnection(target.hostname, port, timeout=30)
        temporary = None
        try:
            conn.sock = dial(target.hostname, port, test_network_allowed(), 30)
            if target.scheme == "https":
                conn.sock = ssl.create_default_context().wrap_socket(
                    conn.sock, server_hostname=target.hostname
                )
            path = (target.path or "/") + ("?" + target.query if target.query else "")
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                url = normalize_url(urljoin(url, response.getheader("Location", "")))
                continue
            if response.status in (401, 403):
                raise AuthRequired("CTFd не разрешила скачать файл задачи.")
            if response.status >= 400:
                raise SourceError(f"CTFd вернула HTTP {response.status} при скачивании файла.")
            try:
                length = int(response.getheader("Content-Length", "0"))
            except ValueError:
                length = 0
            if length < 0 or length > max_size:
                raise SourceError("Файл задачи превышает допустимый размер.")
            digest = hashlib.sha256()
            size = 0
            with tempfile.NamedTemporaryFile(dir=root, prefix=".download-", delete=False) as output:
                temporary = Path(output.name)
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > max_size:
                        raise SourceError("Файл задачи превышает допустимый размер.")
                    digest.update(chunk)
                    output.write(chunk)
            storage_name = digest.hexdigest()
            destination = root / storage_name
            if destination.exists():
                temporary.unlink(missing_ok=True)
            else:
                temporary.replace(destination)
                destination.chmod(0o600)
            return storage_name, size
        except (OSError, http.client.HTTPException):
            raise SourceError("Не удалось скачать файл задачи: соединение или тайм-аут.") from None
        finally:
            if temporary and temporary.exists():
                temporary.unlink(missing_ok=True)
            conn.close()
    raise SourceError("Слишком много перенаправлений при скачивании файла задачи.")


@contextmanager
def browser_proxy():
    """All Chromium destinations, including TLS/CDNs, use the same pinned-IP guard."""
    allow_private = test_network_allowed()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Request paths and auth headers must never reach logs.

        def tunnel(self, upstream):
            peers = (self.connection, upstream)
            end = time.monotonic() + 300
            while time.monotonic() < end:
                ready, _, _ = select.select(peers, [], [], 1)
                for incoming in ready:
                    data = incoming.recv(65536)
                    if not data:
                        return
                    (upstream if incoming is self.connection else self.connection).sendall(data)

        def do_CONNECT(self):
            try:
                target = urlsplit("//" + self.path)
                with dial(target.hostname, target.port or 443, allow_private) as upstream:
                    self.send_response(200)
                    self.end_headers()
                    self.tunnel(upstream)
            except (SourceError, OSError, ValueError):
                self.close_connection = True

        def forward(self):
            try:
                target = urlsplit(normalize_url(self.path))
                if target.scheme != "http":
                    raise ValueError()
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 1024 * 1024 or self.headers.get("Transfer-Encoding"):
                    raise ValueError()
                with dial(target.hostname, target.port or 80, allow_private) as upstream:
                    path = (target.path or "/") + ("?" + target.query if target.query else "")
                    lines = [f"{self.command} {path} HTTP/1.1"]
                    lines.extend(f"{key}: {value}" for key, value in self.headers.items() if key.lower() not in ("proxy-connection", "proxy-authorization", "connection", "host"))
                    lines.extend([f"Host: {target.netloc}", "Connection: close", "", ""])
                    upstream.sendall("\r\n".join(lines).encode("latin-1") + self.rfile.read(length))
                    while True:
                        data = upstream.recv(65536)
                        if not data:
                            break
                        self.connection.sendall(data)
            except (SourceError, OSError, ValueError):
                self.close_connection = True

        do_GET = do_POST = do_HEAD = do_OPTIONS = do_PUT = do_DELETE = do_PATCH = forward

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
