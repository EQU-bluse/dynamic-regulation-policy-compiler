import json

import pytest
from fastapi.testclient import TestClient

import regulation_policy_compiler.app as app_module
from regulation_policy_compiler.app import app
from regulation_policy_compiler.history import DecisionHistory

client = TestClient(app)


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


@pytest.fixture()
def history(tmp_path, monkeypatch):
    instance = DecisionHistory(str(tmp_path / "history.json"))
    monkeypatch.setattr(app_module, "H", instance)
    return instance


def test_evolution_success_compact_utf8(history):
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="允许")])
    history.record("rec-1", "2021-06-01T00:00:00Z", {}, [])
    response = client.get(
        "/decisions/rec-1/evolution?start=2021-01-01T00:00:00Z&end=2021-06-01T00:00:00Z"
    )
    assert response.status_code == 200
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw
    assert "允许" in raw and "\\u" not in raw
    data = json.loads(raw)
    assert list(data) == ["id", "start", "end", "entries"]
    assert data["id"] == "rec-1"
    assert [entry["at"] for entry in data["entries"]] == [
        "2021-01-01T00:00:00Z",
        "2021-06-01T00:00:00Z",
    ]
    assert [entry["changes"] for entry in data["entries"]] == [
        [],
        ["decision", "trace", "basis"],
    ]
    for entry in data["entries"]:
        assert list(entry) == ["at", "decision", "trace", "basis", "changes"]


def test_evolution_query_must_be_exactly_start_and_end(history):
    base = "/decisions/rec-1/evolution"
    good = "start=2021-01-01T00:00:00Z&end=2021-06-01T00:00:00Z"
    bad_queries = [
        "",
        "start=2021-01-01T00:00:00Z",
        "end=2021-06-01T00:00:00Z",
        good + "&extra=1",
        good + "&start=2021-01-01T00:00:00Z",
        good + "&end=2021-06-01T00:00:00Z",
        "start=bad&end=2021-06-01T00:00:00Z",
        "start=2021-01-01T00:00:00Z&end=bad",
        "start=2021-06-01T00:00:00Z&end=2021-01-01T00:00:00Z",
    ]
    for query in bad_queries:
        response = client.get(f"{base}?{query}")
        assert response.status_code == 422, query
        assert response.json() == {"detail": "invalid request"}


def test_evolution_empty_interval_is_404(history):
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [])
    response = client.get(
        "/decisions/rec-1/evolution?start=2022-01-01T00:00:00Z&end=2022-02-01T00:00:00Z"
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "record not found"}
    response = client.get(
        "/decisions/missing/evolution?start=2021-01-01T00:00:00Z&end=2021-06-01T00:00:00Z"
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "record not found"}


def test_evolution_history_unavailable(monkeypatch):
    monkeypatch.setattr(app_module, "H", None)
    response = client.get(
        "/decisions/rec-1/evolution?start=2021-01-01T00:00:00Z&end=2021-06-01T00:00:00Z"
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "history unavailable"}


def test_evolution_validation_precedes_history_check(monkeypatch):
    monkeypatch.setattr(app_module, "H", None)
    response = client.get("/decisions/rec-1/evolution?start=bad&end=2021-06-01T00:00:00Z")
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_evolution_oserror_is_503(monkeypatch):
    class ExplodingHistory:
        def evolution(self, *args, **kwargs):
            raise OSError("disk gone")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.get(
        "/decisions/rec-1/evolution?start=2021-01-01T00:00:00Z&end=2021-06-01T00:00:00Z"
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "history unavailable"}
