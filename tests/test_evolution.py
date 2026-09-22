import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.history import DecisionHistory


def _rule(**overrides):
    rule = {
        "id": "r1",
        "ver": 1,
        "source": "law",
        "priority": 0,
        "from": "2020-01-01T00:00:00Z",
        "to": None,
        "when": None,
        "result": "allow",
    }
    rule.update(overrides)
    return rule


@pytest.fixture
def client(tmp_path, monkeypatch):
    import regulation_policy_compiler.app as app_module

    history = DecisionHistory(str(tmp_path / "history.json"))
    monkeypatch.setattr(app_module, "H", history)
    return TestClient(app), history


def test_evolution_success_shape_and_order(client):
    test_client, history = client
    history.record("rec-1", "2021-03-01T00:00:00Z", {}, [_rule(result="mid")])
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="允许")])
    response = test_client.get(
        "/decisions/rec-1/evolution",
        params={"start": "2021-01-01T00:00:00Z", "end": "2021-12-31T00:00:00Z"},
    )
    assert response.status_code == 200
    data = response.json()
    assert list(data) == ["id", "start", "end", "entries"]
    assert data["id"] == "rec-1"
    assert data["start"] == "2021-01-01T00:00:00Z"
    assert data["end"] == "2021-12-31T00:00:00Z"
    assert [entry["at"] for entry in data["entries"]] == [
        "2021-01-01T00:00:00Z",
        "2021-03-01T00:00:00Z",
    ]
    for entry in data["entries"]:
        assert list(entry) == ["at", "decision", "trace", "basis", "changes"]
    assert data["entries"][0]["decision"] == "允许"
    assert data["entries"][0]["changes"] == []


def test_evolution_response_is_compact_utf8_without_trailing_newline(client):
    test_client, history = client
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="允许")])
    response = test_client.get(
        "/decisions/rec-1/evolution",
        params={"start": "2021-01-01T00:00:00Z", "end": "2021-02-01T00:00:00Z"},
    )
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw
    assert "允许" in raw and "\\u" not in raw


def test_evolution_serves_stored_snapshots(client):
    test_client, history = client
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="allow")])
    response = test_client.get(
        "/decisions/rec-1/evolution",
        params={"start": "2021-01-01T00:00:00Z", "end": "2021-01-01T00:00:00Z"},
    )
    assert response.status_code == 200
    entry = response.json()["entries"][0]
    assert entry["decision"] == "allow"
    assert entry["basis"]["result"] == "allow"


@pytest.mark.parametrize(
    "query",
    [
        "?end=2021-02-01T00:00:00Z",
        "?start=2021-01-01T00:00:00Z",
        "",
        "?start=2021-01-01T00:00:00Z&start=2021-01-01T00:00:00Z&end=2021-02-01T00:00:00Z",
        "?start=2021-01-01T00:00:00Z&end=2021-02-01T00:00:00Z&extra=1",
        "?start=&end=2021-02-01T00:00:00Z",
        "?start=bad&end=2021-02-01T00:00:00Z",
        "?start=2021-01-01T00:00:00Z&end=bad",
        "?start=2021-02-01T00:00:00Z&end=2021-01-01T00:00:00Z",
    ],
)
def test_evolution_invalid_query_is_422(client, query):
    test_client, _ = client
    response = test_client.get(f"/decisions/rec-1/evolution{query}")
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_evolution_empty_interval_is_404(client):
    test_client, history = client
    history.record("rec-1", "2021-06-01T00:00:00Z", {}, [])
    response = test_client.get(
        "/decisions/rec-1/evolution",
        params={"start": "2021-01-01T00:00:00Z", "end": "2021-02-01T00:00:00Z"},
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "record not found"}


def test_evolution_unknown_record_is_404(client):
    test_client, _ = client
    response = test_client.get(
        "/decisions/missing/evolution",
        params={"start": "2021-01-01T00:00:00Z", "end": "2021-02-01T00:00:00Z"},
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "record not found"}


def test_evolution_without_history_is_503(monkeypatch):
    import regulation_policy_compiler.app as app_module

    monkeypatch.setattr(app_module, "H", None)
    response = TestClient(app).get(
        "/decisions/rec-1/evolution",
        params={"start": "2021-01-01T00:00:00Z", "end": "2021-02-01T00:00:00Z"},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "history unavailable"}


def test_evolution_validates_query_before_checking_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    monkeypatch.setattr(app_module, "H", None)
    response = TestClient(app).get("/decisions/rec-1/evolution?extra=1")
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_evolution_os_error_is_503(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class FailingHistory:
        def evolution(self, *args, **kwargs):
            raise OSError("disk gone")

    monkeypatch.setattr(app_module, "H", FailingHistory())
    response = TestClient(app).get(
        "/decisions/rec-1/evolution",
        params={"start": "2021-01-01T00:00:00Z", "end": "2021-02-01T00:00:00Z"},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "history unavailable"}


def test_evolution_does_not_affect_other_decision_route(client):
    test_client, history = client
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="allow")])
    # /decisions/rec-1 (replay) still works and the evolution route must not
    # shadow it.
    response = test_client.get(
        "/decisions/rec-1", params={"at": "2021-01-01T00:00:00Z"}
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
