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


def _history(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    # "a": unchanged between the cutoffs (identical fields, different at).
    history.record("a", "2021-01-01T00:00:00Z", {}, [_rule(result="x")])
    history.record("a", "2021-03-01T00:00:00Z", {}, [_rule(result="x")])
    # "b": changed decision/trace/basis between the cutoffs.
    history.record("b", "2021-01-01T00:00:00Z", {}, [_rule(result="允许")])
    history.record("b", "2021-03-01T00:00:00Z", {}, [])
    # "é": introduced (first record after from_at).
    history.record("é", "2021-02-01T00:00:00Z", {}, [_rule(result="z")])
    return history


FROM = "2021-01-15T00:00:00Z"
TO = "2021-06-01T00:00:00Z"


@pytest.fixture
def client(tmp_path, monkeypatch):
    import regulation_policy_compiler.app as app_module

    history = _history(tmp_path)
    monkeypatch.setattr(app_module, "H", history)
    return TestClient(app), history


def test_replay_diff_shape_kinds_and_summary(tmp_path):
    history = _history(tmp_path)
    report = history.replay_diff(["é", "b", "a"], FROM, TO)
    assert list(report) == ["from", "to", "entries", "summary"]
    assert report["from"] == FROM
    assert report["to"] == TO
    assert [entry["id"] for entry in report["entries"]] == ["a", "b", "é"]
    for entry in report["entries"]:
        assert list(entry) == ["id", "kind", "before", "after", "changes"]
    first, second, third = report["entries"]
    assert first["kind"] == "unchanged"
    assert first["changes"] == []
    assert first["before"]["at"] == "2021-01-01T00:00:00Z"
    assert first["after"]["at"] == "2021-03-01T00:00:00Z"
    assert second["kind"] == "changed"
    assert second["changes"] == ["decision", "trace", "basis"]
    assert second["before"]["decision"] == "允许"
    assert second["after"]["decision"] is None
    assert third["kind"] == "introduced"
    assert third["before"] is None
    assert third["changes"] == []
    assert third["after"]["decision"] == "z"
    assert list(report["summary"]) == ["total", "introduced", "changed", "unchanged"]
    assert report["summary"] == {
        "total": 3,
        "introduced": 1,
        "changed": 1,
        "unchanged": 1,
    }


def test_replay_diff_before_after_keep_replay_record_shape(tmp_path):
    history = _history(tmp_path)
    report = history.replay_diff(["b"], FROM, TO)
    entry = report["entries"][0]
    for side in ("before", "after"):
        assert list(entry[side]) == ["id", "at", "decision", "trace", "basis"]
        assert entry[side]["id"] == "b"
    assert entry["before"]["basis"]["result"] == "允许"
    assert entry["after"]["basis"] is None


def test_replay_diff_is_order_independent_and_byte_stable(tmp_path):
    history = _history(tmp_path)
    first = history.replay_diff(["é", "b", "a"], FROM, TO)
    second = history.replay_diff(["a", "é", "b"], FROM, TO)
    text = json.dumps(first, ensure_ascii=False, separators=(",", ":"))
    assert text == json.dumps(second, ensure_ascii=False, separators=(",", ":"))
    assert "é" in text and "允许" in text and "\\u" not in text


def test_replay_diff_same_cutoff_is_all_unchanged(tmp_path):
    history = _history(tmp_path)
    report = history.replay_diff(["a", "b"], TO, TO)
    assert [entry["kind"] for entry in report["entries"]] == ["unchanged", "unchanged"]
    for entry in report["entries"]:
        assert entry["before"] == entry["after"]
        assert entry["changes"] == []
    assert report["summary"] == {
        "total": 2,
        "introduced": 0,
        "changed": 0,
        "unchanged": 2,
    }


def test_replay_diff_record_exactly_at_from_is_not_introduced(tmp_path):
    history = _history(tmp_path)
    report = history.replay_diff(["a"], "2021-01-01T00:00:00Z", TO)
    entry = report["entries"][0]
    assert entry["kind"] == "unchanged"
    assert entry["before"]["at"] == "2021-01-01T00:00:00Z"


def test_replay_diff_partial_field_changes_listed_in_fixed_order(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record(
        "rec",
        "2021-01-01T00:00:00Z",
        {"a": True},
        [_rule(id="win", priority=9, result="allow"), _rule(id="loser", result="deny", when={"a": True})],
    )
    history.record(
        "rec",
        "2021-02-01T00:00:00Z",
        {},
        [_rule(id="win", priority=9, result="allow"), _rule(id="loser", result="deny", when={"a": True})],
    )
    report = history.replay_diff(["rec"], "2021-01-15T00:00:00Z", "2021-03-01T00:00:00Z")
    entry = report["entries"][0]
    assert entry["kind"] == "changed"
    assert entry["changes"] == ["trace"]


def test_replay_diff_missing_record_raises_key_error_without_partial_result(tmp_path):
    history = _history(tmp_path)
    with pytest.raises(KeyError):
        history.replay_diff(["a", "missing"], FROM, TO)
    # An id whose first record is after to_at also fails the whole diff.
    with pytest.raises(KeyError):
        history.replay_diff(["a", "é"], FROM, "2021-01-31T00:00:00Z")


@pytest.mark.parametrize(
    "record_ids",
    [
        [],
        None,
        "a",
        {},
        ("a",),
        True,
        1,
        [""],
        [None],
        [1],
        ["a", 1],
        ["a", ""],
        ["a", "a"],
        ["a", "b", "a"],
    ],
)
def test_replay_diff_rejects_bad_record_ids(tmp_path, record_ids):
    history = _history(tmp_path)
    with pytest.raises(ValueError):
        history.replay_diff(record_ids, FROM, TO)


def test_replay_diff_rejects_bad_times(tmp_path):
    history = _history(tmp_path)
    with pytest.raises(ValueError):
        history.replay_diff(["a"], "bad", TO)
    with pytest.raises(ValueError):
        history.replay_diff(["a"], FROM, "bad")
    with pytest.raises(ValueError):
        history.replay_diff(["a"], TO, FROM)


def test_replay_diff_validates_before_reading(tmp_path):
    history = _history(tmp_path)
    # Duplicate ids raise ValueError even when the ids are also absent.
    with pytest.raises(ValueError):
        history.replay_diff(["nope", "nope"], FROM, TO)


def test_replay_diff_returns_deep_copies_and_does_not_mutate(tmp_path):
    history = _history(tmp_path)
    ids = ["b", "a"]
    ids_snapshot = list(ids)
    report = history.replay_diff(ids, FROM, TO)
    assert ids == ids_snapshot
    report["entries"][0]["after"]["decision"] = "tampered"
    report["entries"][0]["after"]["trace"].append("x@9")
    report["entries"][1]["before"]["basis"]["result"] = "tampered"
    again = history.replay_diff(["a", "b"], FROM, TO)
    assert again["entries"][0]["after"]["decision"] == "x"
    assert again["entries"][1]["before"]["decision"] == "允许"
    assert "x@9" not in again["entries"][0]["after"]["trace"]
    assert again["entries"][1]["before"]["basis"]["result"] == "允许"


def test_replay_diff_is_read_only(tmp_path):
    path = tmp_path / "history.json"
    history = _history(tmp_path)
    before = path.read_bytes()
    history.replay_diff(["a", "b", "é"], FROM, TO)
    with pytest.raises(KeyError):
        history.replay_diff(["zzz"], FROM, TO)
    assert path.read_bytes() == before


def test_http_replay_diff_success_shape_and_compact_utf8(client):
    test_client, _ = client
    response = test_client.post(
        "/history/replay-diff",
        json={"record_ids": ["é", "b", "a"], "from": FROM, "to": TO},
    )
    assert response.status_code == 200
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw
    assert "允许" in raw and "\\u" not in raw
    data = response.json()
    assert list(data) == ["from", "to", "entries", "summary"]
    assert [entry["id"] for entry in data["entries"]] == ["a", "b", "é"]
    assert [entry["kind"] for entry in data["entries"]] == [
        "unchanged",
        "changed",
        "introduced",
    ]
    assert data["summary"] == {
        "total": 3,
        "introduced": 1,
        "changed": 1,
        "unchanged": 1,
    }


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        {"record_ids": ["a"], "from": FROM},
        {"record_ids": ["a"], "from": FROM, "to": TO, "extra": 1},
        {"record_ids": [], "from": FROM, "to": TO},
        {"record_ids": "a", "from": FROM, "to": TO},
        {"record_ids": ["a", "a"], "from": FROM, "to": TO},
        {"record_ids": ["a", ""], "from": FROM, "to": TO},
        {"record_ids": ["a", 1], "from": FROM, "to": TO},
        {"record_ids": ["a"], "from": "bad", "to": TO},
        {"record_ids": ["a"], "from": FROM, "to": "bad"},
        {"record_ids": ["a"], "from": TO, "to": FROM},
    ],
)
def test_http_replay_diff_invalid_body_is_422(client, body):
    test_client, _ = client
    response = test_client.post(
        "/history/replay-diff",
        content=json.dumps(body),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_http_replay_diff_malformed_json_is_422(client):
    test_client, _ = client
    response = test_client.post(
        "/history/replay-diff",
        content=b"not json",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_http_replay_diff_missing_record_is_404(client):
    test_client, _ = client
    response = test_client.post(
        "/history/replay-diff",
        json={"record_ids": ["a", "missing"], "from": FROM, "to": TO},
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "record not found"}


def test_http_replay_diff_without_history_is_503(monkeypatch):
    import regulation_policy_compiler.app as app_module

    monkeypatch.setattr(app_module, "H", None)
    response = TestClient(app).post(
        "/history/replay-diff",
        json={"record_ids": ["a"], "from": FROM, "to": TO},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "history unavailable"}


def test_http_replay_diff_validates_body_before_checking_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    monkeypatch.setattr(app_module, "H", None)
    response = TestClient(app).post(
        "/history/replay-diff",
        json={"record_ids": ["a"], "from": TO, "to": FROM},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_http_replay_diff_os_error_is_503(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class FailingHistory:
        def replay_diff(self, *args, **kwargs):
            raise OSError("disk gone")

    monkeypatch.setattr(app_module, "H", FailingHistory())
    response = TestClient(app).post(
        "/history/replay-diff",
        json={"record_ids": ["a"], "from": FROM, "to": TO},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "history unavailable"}
