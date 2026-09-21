import json
import pytest
import app as mod
import sources
from test_app import env, post, member, task


def configure(c, **changes):
    settings = dict(url="https://ctf.example/challenges", mode="auto", interval_seconds=60, enabled=True)
    settings.update(changes)
    response = post(
        c,
        "/admin/source/1",
        settings,
    )
    assert response.status_code == 200


def payload(**changes):
    item = dict(id=42, name="External task", category="web", value=300, solves=12)
    item.update(changes)
    return json.dumps({"success": True, "data": [item]})


def test_source_permissions_and_validation(env):
    c = member(env)
    assert c.get("/api/admin/source/1").status_code == 403
    assert post(c, "/admin/source/1", {"url": "https://ctf.example"}).status_code == 403
    for url in [
        "file:///etc/passwd",
        "https://user:password@ctf.example",
        "javascript:alert(1)",
    ]:
        assert post(env, "/admin/source/1", {"url": url}).status_code == 400
    configure(env)
    assert env.get("/api/admin/source/1").json["enabled"] == 1


def test_ctfd_sync_preserves_work_and_tracks_renames(env, monkeypatch):
    configure(env)
    monkeypatch.setattr(
        sources, "download", lambda url: (payload(), "application/json")
    )
    assert sources.sync_once(mod.app, mod.db, 1)
    t = env.get("/api/board/1").json["tasks"][0]
    tid = t["id"]
    post(env, f"/tasks/{tid}", {"action": "join"})
    post(
        env,
        f"/tasks/{tid}",
        {"action": "help", "progress": "Keep this"},
    )
    post(env, f"/tasks/{tid}/hypotheses", {"body": "Keep hypothesis"})
    monkeypatch.setattr(
        sources,
        "download",
        lambda url: (
            payload(name="Renamed task", value=200, solves=20),
            "application/json",
        ),
    )
    assert sources.sync_once(mod.app, mod.db, 1)
    t = env.get("/api/board/1").json["tasks"][0]
    assert t["id"] == tid and t["title"] == "Renamed task"
    assert t["points"] == 200 and t["solves"] == 20 and t["previous_solves"] == 12
    assert (
        t["progress"] == "Keep this"
        and t["status"] == "stuck"
        and len(t["members"]) == 1
        and len(t["hypotheses"]) == 1
    )
    assert t["updated_at"] == env.get("/api/board/1").json["tasks"][0]["updated_at"]


def test_failure_preserves_last_success_and_backs_off(env, monkeypatch):
    configure(env)
    monkeypatch.setattr(
        sources, "download", lambda url: (payload(), "application/json")
    )
    sources.sync_once(mod.app, mod.db, 1)
    previous = env.get("/api/admin/source/1").json["last_success"]

    def unavailable(source):
        raise sources.SourceError("Unavailable")

    monkeypatch.setattr(sources, "fetch_source", unavailable)
    assert not sources.sync_once(mod.app, mod.db, 1)
    status = env.get("/api/admin/source/1").json
    assert (
        status["last_success"] == previous
        and status["error"] == "Unavailable"
        and status["next_run"] > status["last_attempt"]
    )
    assert env.get("/api/board/1").json["tasks"][0]["solves"] == 12


def test_hidden_solves_and_missing_tasks_do_not_get_recommended(env, monkeypatch):
    configure(env)
    monkeypatch.setattr(
        sources, "download", lambda url: (payload(solves=None), "application/json")
    )
    sources.sync_once(mod.app, mod.db, 1)
    board = env.get("/api/board/1").json
    assert board["tasks"][0]["solves_known"] == 0 and not board["recommendations"]
    monkeypatch.setattr(
        sources,
        "download",
        lambda url: ('{"success":true,"data":[]}', "application/json"),
    )
    sources.sync_once(mod.app, mod.db, 1)
    assert env.get("/api/board/1").json["tasks"][0]["external_available"] == 0


def test_ai_evidence_validation():
    text = "Task Alpha points 250 solves 18 /challenge/7"
    item = dict(
        title="Task Alpha",
        points=250,
        solves=18,
        external_id="/challenge/7",
        category="Web",
        evidence=text,
    )
    parsed = {"kind": "tasks", "tasks": [item]}
    assert sources.validate_ai(parsed, text)[0]["solves"] == 18
    for change in [
        {"points": 999},
        {"title": "Invented task"},
        {"evidence": "Made up evidence"},
        {"external_id": "unknown-id"},
    ]:
        with pytest.raises(sources.SourceError):
            sources.validate_ai(
                {"kind": "tasks", "tasks": [dict(item, **change)]}, text
            )
    with pytest.raises(sources.SourceError):
        sources.validate_ai({"kind": "unsupported", "tasks": []}, text)


def test_explicit_ai_mode_excludes_scripts(env, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    configure(env, mode="ai")
    captured = {}

    def download(url):
        if url.endswith("/api/v1/challenges"):
            raise sources.SourceError("Not CTFd")
        return (
            "<script>PRIVATE_SCRIPT_SECRET</script><div>Task Alpha points 250 solves 18</div>",
            "text/html",
        )

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return json.dumps(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {
                                "content": json.dumps(
                                    {
                                        "kind": "tasks",
                                        "tasks": [
                                            dict(
                                                title="Task Alpha",
                                                points=250,
                                                solves=18,
                                                external_id=None,
                                                category="Web",
                                                evidence="Task Alpha points 250 solves 18",
                                            )
                                        ],
                                    }
                                )
                            },
                        }
                    ]
                }
            ).encode()

    def provider(req, timeout):
        captured.update(json.loads(req.data))
        return Response()

    monkeypatch.setattr(sources, "download", download)
    monkeypatch.setattr(sources.urllib.request, "urlopen", provider)
    assert sources.sync_once(mod.app, mod.db, 1)
    assert "PRIVATE_SCRIPT_SECRET" not in str(captured)
    assert env.get("/api/admin/source/1").json["parser"] == "ai"
    assert env.get("/api/board/1").json["tasks"][0]["title"] == "Task Alpha"


def test_settings_changed_during_fetch_discard_old_result(env, monkeypatch):
    configure(env)

    def fetch(source):
        with mod.app.app_context():
            mod.db().execute(
                "UPDATE sources SET revision=revision+1,enabled=0 WHERE competition_id=1"
            )
            mod.db().commit()
        return sources.parse_ctfd(payload()), "ctfd"

    monkeypatch.setattr(sources, "fetch_source", fetch)
    assert not sources.sync_once(mod.app, mod.db, 1)
    assert not env.get("/api/board/1").json["tasks"]
