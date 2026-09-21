import json

import app as mod
import sources
from test_app import env, member, post, task
from test_sources import configure


def container_task(client, container_enabled=1):
    configure(
        client,
        mode="ctfd",
        auth={"method": "token", "token": "ctfd-container-token-PRIVATE"},
    )
    tid = task(client)
    with mod.app.app_context():
        connection = mod.db()
        connection.execute(
            "UPDATE sources SET parser='ctfd',strategy=? WHERE competition_id=1",
            (json.dumps({"api_url": "https://ctf.example/api/v1/challenges"}),),
        )
        connection.execute(
            "INSERT INTO source_tasks(competition_id,source_url,external_id,task_id,evidence,container_enabled) "
            "VALUES(1,'https://ctf.example/challenges','42',?,'',?)",
            (tid, container_enabled),
        )
        connection.commit()
    return tid


def running_payload():
    return {
        "status": "running",
        "expires_at": 2_000_000_000_000,
        "entrypoints": [
            {
                "slug": "web",
                "connection_type": "subdomain",
                "host": None,
                "ports": None,
                "urls": ["https://instance.tasks.ctf.example"],
                "info": "Team instance",
            }
        ],
    }


def test_container_status_and_actions_use_mapped_challenge(env, monkeypatch):
    tid = container_task(env)
    participant = member(env)
    calls = []

    def source_download(url, auth=None):
        calls.append(("get", url, auth))
        return json.dumps(running_payload()), "application/json"

    def post_json(url, body, auth=None, csrf_token="", timeout=20):
        calls.append(("post", url, body, auth, csrf_token))
        return 200, json.dumps({"status": "requested"})

    monkeypatch.setattr(sources, "download", source_download)
    monkeypatch.setattr("source_http.post_json", post_json)

    board_task = env.get("/api/board/1").json["tasks"][0]
    assert board_task["container_enabled"] is True
    status = participant.get(f"/api/tasks/{tid}/container")
    assert status.status_code == 200
    assert status.json["entrypoints"][0]["urls"] == ["https://instance.tasks.ctf.example"]
    assert post(participant, f"/tasks/{tid}/container", {"action": "start"}).status_code == 403

    assert post(participant, f"/tasks/{tid}", {"action": "join"}).status_code == 200
    started = post(participant, f"/tasks/{tid}/container", {"action": "start"})
    assert started.status_code == 200 and started.json == {
        "status": "provisioning",
        "expires_at": None,
        "entrypoints": [],
    }
    request = next(call for call in calls if call[0] == "post")
    assert request[1] == "https://ctf.example/api/v1/containers/request"
    assert request[2] == {"challenge_id": 42}
    assert request[3]["token"] == "ctfd-container-token-PRIVATE"
    assert request[4] == ""
    with mod.app.app_context():
        assert mod.db().execute("SELECT COUNT(*) FROM container_operations").fetchone()[0] == 0


def test_container_action_is_serialized_and_non_container_is_rejected(env, monkeypatch):
    tid = container_task(env)
    participant = member(env)
    assert post(participant, f"/tasks/{tid}", {"action": "join"}).status_code == 200
    with mod.app.app_context():
        mod.db().execute(
            "INSERT INTO container_operations(task_id,user_id,action,started_at) VALUES(?,?,?,?)",
            (tid, participant.get("/api/me").json["id"], "start", mod.now()),
        )
        mod.db().commit()
    monkeypatch.setattr(
        sources,
        "ctfd_container",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("external call started")),
    )
    busy = post(participant, f"/tasks/{tid}/container", {"action": "start"})
    assert busy.status_code == 409 and "уже выполняется" in busy.json["error"]

    with mod.app.app_context():
        mod.db().execute("DELETE FROM container_operations")
        mod.db().execute("UPDATE source_tasks SET container_enabled=0 WHERE task_id=?", (tid,))
        mod.db().commit()
    unavailable = participant.get(f"/api/tasks/{tid}/container")
    assert unavailable.status_code == 502 and "не настроен" in unavailable.json["error"]


def test_container_start_keeps_real_ctfd_errors(env, monkeypatch):
    tid = container_task(env)
    assert post(env, f"/tasks/{tid}", {"action": "join"}).status_code == 200
    monkeypatch.setattr(
        "source_http.post_json",
        lambda *_args, **_kwargs: (200, json.dumps({"status": "requested", "error": "Start denied"})),
    )
    response = post(env, f"/tasks/{tid}/container", {"action": "start"})
    assert response.status_code == 502
    assert response.json["error"] == "Start denied"


def test_container_response_rejects_unsafe_connection_url():
    payload = running_payload()
    payload["entrypoints"][0]["urls"] = ["javascript:alert(1)"]
    try:
        sources.clean_container_response(payload)
    except sources.SourceError as error:
        assert "http" in str(error)
    else:
        raise AssertionError("unsafe URL was accepted")
