"""Per-source encrypted credentials. Public serializers never decrypt secrets."""

import json
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

from sources import AuthRequired, SourceError, normalize_url, origin

PUBLIC_COLUMNS = (
    "competition_id,url,mode,interval_seconds,enabled,revision,last_attempt,"
    "last_success,next_run,error,parser,failures,task_count,status,stage"
)
METHODS = {"password", "cookie", "token", "none", "server"}


def cipher(create=False):
    path = Path(current_app.config.get("SOURCE_KEY_FILE", "instance/source_credentials.key"))
    if not path.exists() and create:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(Fernet.generate_key())
            try:
                os.link(temporary, path)  # Atomic publication; concurrent writers keep the winner.
            except FileExistsError:
                pass
        finally:
            os.unlink(temporary)
    try:
        return Fernet(path.read_bytes().strip())
    except (OSError, ValueError):
        raise AuthRequired("Не удалось прочитать ключ доступа площадок. Восстановите ключ из резервной копии.") from None


def encrypt(value):
    return cipher(create=True).encrypt(json.dumps(value, ensure_ascii=False).encode()).decode()


def decrypt(value):
    try:
        return json.loads(cipher().decrypt(value.encode()))
    except (InvalidToken, ValueError, TypeError):
        raise AuthRequired("Сохранённый доступ не удалось расшифровать. Восстановите ключ или задайте доступ заново.") from None


def environment_auth(url):
    configured = os.getenv("SOURCE_AUTH_ORIGIN", "")
    if not configured or origin(normalize_url(configured)) != origin(url):
        return {"method": "none"}
    token, cookie = os.getenv("SOURCE_CTFD_TOKEN", ""), os.getenv("SOURCE_COOKIE", "")
    return {"method": "server", "token": token, "cookie": cookie}


def load_auth(conn, source):
    row = conn.execute("SELECT * FROM source_credentials WHERE competition_id=?", (source["competition_id"],)).fetchone()
    if not row:
        return environment_auth(source["url"])
    if row["method"] == "server":
        return environment_auth(source["url"])
    if row["method"] == "none":
        return {"method": "none"}
    result = decrypt(row["payload"])
    result["method"] = row["method"]
    if row["session"]:
        result["storage"] = decrypt(row["session"])
    return result


def public_source(conn, cid):
    row = conn.execute(f"SELECT {PUBLIC_COLUMNS} FROM sources WHERE competition_id=?", (cid,)).fetchone()
    result = dict(row) if row else dict(competition_id=cid, url="", mode="auto", enabled=0, interval_seconds=120, status="idle", stage="")
    auth = conn.execute("SELECT method,payload FROM source_credentials WHERE competition_id=?", (cid,)).fetchone()
    result["auth_method"] = auth["method"] if auth else "server" if row else "password"
    result["has_credentials"] = bool(auth and auth["payload"])
    if row and result["auth_method"] == "server":
        legacy = environment_auth(row["url"])
        result["has_credentials"] = bool(legacy.get("cookie") or legacy.get("token"))
    return result


def update_auth(conn, cid, old_url, new_url, data):
    """Caller owns the transaction. Omitted auth preserves; clear creates explicit none."""
    moved = bool(old_url and origin(old_url) != origin(new_url))
    if moved:
        conn.execute("DELETE FROM source_credentials WHERE competition_id=?", (cid,))
    if data.get("clear_auth"):
        auth = {"method": "none"}
    else:
        auth = data.get("auth")
    if auth is None:
        if moved:
            auth = {"method": "none"}
        else:
            return
    if not isinstance(auth, dict) or auth.get("method") not in METHODS:
        raise SourceError("Выберите способ доступа к площадке.")
    method = auth["method"]
    previous = conn.execute("SELECT method,payload FROM source_credentials WHERE competition_id=?", (cid,)).fetchone()
    fields = {"password": ("username", "password"), "cookie": ("cookie",), "token": ("token",)}.get(method, ())
    supplied = {key: auth[key] for key in fields if auth.get(key) not in (None, "")}
    if any(not isinstance(value, str) for value in supplied.values()):
        raise SourceError("Поля доступа должны быть строками.")
    if any(len(value) > (16384 if key == "cookie" else 4096) or "\x00" in value for key, value in supplied.items()):
        raise SourceError("Некорректный размер поля доступа.")
    if any("\n" in supplied.get(key, "") or "\r" in supplied.get(key, "") for key in ("token", "cookie")):
        raise SourceError("В токене или cookies не должно быть переносов строк.")
    if not supplied and previous and previous["method"] == method and not moved:
        return
    values = decrypt(previous["payload"]) if supplied and any(key not in supplied for key in fields) and previous and previous["method"] == method and previous["payload"] and not moved else {}
    values.update(supplied)
    if any(not values.get(key) for key in fields):
        raise SourceError("Заполните данные доступа. Для другого адреса введите их заново.")
    payload = encrypt(values) if fields else ""
    conn.execute(
        "INSERT INTO source_credentials(competition_id,method,payload,session) VALUES(?,?,?,'') "
        "ON CONFLICT(competition_id) DO UPDATE SET method=excluded.method,payload=excluded.payload,session=''",
        (cid, method, payload),
    )


def save_session(conn, source, storage):
    # A login finishing after credentials were edited must not resurrect an old session.
    conn.execute(
        "UPDATE source_credentials SET session=? WHERE competition_id=? AND EXISTS "
        "(SELECT 1 FROM sources WHERE competition_id=? AND revision=? AND enabled=1)",
        (encrypt(storage), source["competition_id"], source["competition_id"], source["revision"]),
    )
    conn.commit()


def redact(text, auth):
    """Remove known authentication values before page text reaches a model."""
    secrets = [auth.get(key, "") for key in ("username", "password", "cookie", "token")]
    storage = auth.get("storage") or {}
    secrets.extend(cookie.get("value", "") for cookie in storage.get("cookies", []))
    for entry in storage.get("origins", []):
        secrets.extend(item.get("value", "") for item in entry.get("localStorage", []))
    for value in sorted((x for x in secrets if isinstance(x, str) and x), key=len, reverse=True):
        text = text.replace(value, "[redacted]")
    return text
