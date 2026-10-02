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
    # introduced: no record at/before from_at
    history.record("new", "2021-06-01T00:00:00Z", {}, [_rule(result="z")])
    # changed: decision differs
    history.record("chg", "2021-01-01T00:00:00Z", {}, [_rule(result="a")])
    history.record("chg", "2021-06-01T00:00:00Z", {}, [_rule(result="b")])
    # unchanged: same decision/trace/basis, only at differs
    history.record("same", "2021-01-01T00:00:00Z", {}, [_rule(result="x")])
    history.record("same", "2021-06-01T00:00:00Z", {}, [_rule(result="x")])
    # unchanged: one record before from_at, nothing after either cutoff
    history.record("late", "2021-01-15T00:00:00Z", {}, [_rule(result="q")])
    # record strictly after to_at: absent at both cutoffs -> KeyError
    history.record("future", "2021-09-01T00:00:00Z", {}, [])
    return history


FROM = "2021-03-01T00:00:00Z"
TO = "2021-08-01T00:00:00Z"


def test_diff_shape_and_kinds(tmp_path):
    history = _history(tmp_path)
    report = history.replay_diff(["late", "new", "chg", "same"], FROM, TO)
    assert list(report) == ["from", "to", "entries", "summary"]
    assert report["from"] == FROM
    assert report["to"] == TO
    assert [entry["id"] for entry in report["entries"]] == [
        "chg",
        "late",
        "new",
        "same",
    ]
    for entry in report["entries"]:
        assert list(entry) == ["id", "kind", "before", "after", "changes"]
    assert report["summary"] == {
        "total": 4,
        "introduced": 1,
        "changed": 1,
        "unchanged": 2,
    }
    assert list(report["summary"]) == ["total", "introduced", "changed", "unchanged"]
    kinds = {entry["id"]: entry["kind"] for entry in report["entries"]}
    assert kinds == {
        "chg": "changed",
        "late": "unchanged",
        "new": "introduced",
        "same": "unchanged",
    }


def test_diff_introduced_entry(tmp_path):
    history = _history(tmp_path)
    report = history.replay_diff(["new"], FROM, TO)
    entry = report["entries"][0]
    assert entry["kind"] == "introduced"
    assert entry["changes"] == []
    assert entry["before"] is None
    assert entry["after"]["at"] == "2021-06-01T00:00:00Z"
    assert entry["after"]["decision"] == "z"
    assert list(entry["after"]) == ["id", "at", "decision", "trace", "basis"]


def test_diff_changed_entry(tmp_path):
    history = _history(tmp_path)
    report = history.replay_diff(["chg"], FROM, TO)
    entry = report["entries"][0]
    assert entry["kind"] == "changed"
    assert entry["changes"] == ["decision", "basis"]
    assert entry["before"]["at"] == "2021-01-01T00:00:00Z"
    assert entry["before"]["decision"] == "a"
    assert entry["after"]["at"] == "2021-06-01T00:00:00Z"
    assert entry["after"]["decision"] == "b"


def test_diff_unchanged_when_only_at_differs(tmp_path):
    history = _history(tmp_path)
    report = history.replay_diff(["same"], FROM, TO)
    entry = report["entries"][0]
    assert entry["kind"] == "unchanged"
    assert entry["changes"] == []
    assert entry["before"]["at"] == "2021-01-01T00:00:00Z"
    assert entry["after"]["at"] == "2021-06-01T00:00:00Z"


def test_diff_uses_most_recent_record_at_or_before_each_cutoff(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("r", "2021-01-01T00:00:00Z", {}, [_rule(result="a")])
    history.record("r", "2021-04-01T00:00:00Z", {}, [_rule(result="b")])
    history.record("r", "2021-07-01T00:00:00Z", {}, [_rule(result="c")])
    report = history.replay_diff(
        ["r"], "2021-05-01T00:00:00Z", "2021-05-01T00:00:00Z"
    )
    entry = report["entries"][0]
    assert entry["before"] == entry["after"]
    assert entry["after"]["decision"] == "b"
    assert entry["kind"] == "unchanged"
    assert report["summary"] == {"total": 1, "introduced": 0, "changed": 0, "unchanged": 1}


def test_diff_record_existing_before_from_but_not_at_to_introduces_not(tmp_path):
    # A record at/before from_at but with no record in (from_at, to_at] is
    # unchanged: both snapshots resolve to the same stored record.
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("r", "2021-01-01T00:00:00Z", {}, [_rule(result="a")])
    report = history.replay_diff(
        ["r"], "2021-02-01T00:00:00Z", "2021-03-01T00:00:00Z"
    )
    entry = report["entries"][0]
    assert entry["kind"] == "unchanged"
    assert entry["before"]["at"] == entry["after"]["at"] == "2021-01-01T00:00:00Z"


def test_diff_missing_after_raises_key_error_without_partial_result(tmp_path):
    history = _history(tmp_path)
    with pytest.raises(KeyError):
        history.replay_diff(["chg", "ghost"], FROM, TO)
    # An id whose only record is strictly after to_at also fails.
    with pytest.raises(KeyError):
        history.replay_diff(["future"], FROM, TO)


def test_diff_validates_before_looking_up_records(tmp_path):
    history = _history(tmp_path)
    # Duplicate ids raise ValueError even when the id is also absent.
    with pytest.raises(ValueError):
        history.replay_diff(["nope", "nope"], FROM, TO)


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
def test_diff_rejects_bad_record_ids(tmp_path, record_ids):
    history = _history(tmp_path)
    with pytest.raises(ValueError):
        history.replay_diff(record_ids, FROM, TO)


def test_diff_rejects_bad_time_window(tmp_path):
    history = _history(tmp_path)
    with pytest.raises(ValueError):
        history.replay_diff(["chg"], "bad", TO)
    with pytest.raises(ValueError):
        history.replay_diff(["chg"], FROM, "bad")
    with pytest.raises(ValueError):
        history.replay_diff(["chg"], TO, FROM)


def test_diff_input_order_does_not_affect_result(tmp_path):
    history = _history(tmp_path)
    ids = ["same", "é", "new", "chg", "late"]
    history.record("é", "2021-06-01T00:00:00Z", {}, [_rule(result="é-résultat")])
    first = history.replay_diff(list(reversed(ids)), FROM, TO)
    second = history.replay_diff(["new", "late", "é", "same", "chg"], FROM, TO)
    text = json.dumps(first, ensure_ascii=False, separators=(",", ":"))
    assert text == json.dumps(second, ensure_ascii=False, separators=(",", ":"))
    assert [entry["id"] for entry in first["entries"]] == sorted(ids)
    assert "é" in text and "é-résultat" in text and "\\u" not in text


def test_diff_returns_deep_copies_and_does_not_share_history(tmp_path):
    history = _history(tmp_path)
    report = history.replay_diff(["chg", "new"], FROM, TO)
    changed = report["entries"][0]
    introduced = report["entries"][1]
    changed["before"]["decision"] = "tampered"
    changed["before"]["basis"]["result"] = "tampered"
    changed["after"]["trace"].append("x@9")
    introduced["after"]["decision"] = "tampered"
    again = history.replay_diff(["chg", "new"], FROM, TO)
    assert again["entries"][0]["before"]["decision"] == "a"
    assert again["entries"][0]["before"]["basis"]["result"] == "a"
    assert again["entries"][0]["after"]["trace"] == ["r1@1"]
    assert again["entries"][1]["after"]["decision"] == "z"
    # before/after must not share the same container even when equal.
    assert again["entries"][0]["before"] is not again["entries"][0]["after"]


def test_diff_is_read_only(tmp_path):
    path = tmp_path / "history.json"
    history = _history(tmp_path)
    before = path.read_bytes()
    history.replay_diff(["chg", "new", "same", "late"], FROM, TO)
    with pytest.raises(KeyError):
        history.replay_diff(["ghost"], FROM, TO)
    assert path.read_bytes() == before


@pytest.fixture
def client(tmp_path, monkeypatch):
    import regulation_policy_compiler.app as app_module

    history = _history(tmp_path)
    monkeypatch.setattr(app_module, "H", history)
    return TestClient(app), history


def test_http_success_shape_and_compact_utf8(client):
    test_client, _ = client
    response = test_client.post(
        "/history/replay-diff",
        json={"record_ids": ["new", "chg", "same", "late"], "from": FROM, "to": TO},
    )
    assert response.status_code == 200
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw
    data = response.json()
    assert list(data) == ["from", "to", "entries", "summary"]
    assert [entry["id"] for entry in data["entries"]] == [
        "chg",
        "late",
        "new",
        "same",
    ]
    assert data["summary"] == {
        "total": 4,
        "introduced": 1,
        "changed": 1,
        "unchanged": 2,
    }
    kinds = {entry["id"]: entry["kind"] for entry in data["entries"]}
    assert kinds == {
        "chg": "changed",
        "late": "unchanged",
        "new": "introduced",
        "same": "unchanged",
    }
    by_id = {entry["id"]: entry for entry in data["entries"]}
    assert by_id["chg"]["changes"] == ["decision", "basis"]
    assert by_id["new"]["before"] is None
    assert by_id["new"]["changes"] == []
    assert by_id["late"]["before"] is not None


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        [],
        {},
        {"record_ids": ["a"]},
        {"record_ids": ["a"], "from": FROM, "to": TO, "extra": 1},
        {"record_ids": [], "from": FROM, "to": TO},
        {"record_ids": "a", "from": FROM, "to": TO},
        {"record_ids": [""], "from": FROM, "to": TO},
        {"record_ids": ["a", "a"], "from": FROM, "to": TO},
        {"record_ids": [1], "from": FROM, "to": TO},
        {"record_ids": ["a"], "from": "bad", "to": TO},
        {"record_ids": ["a"], "from": FROM, "to": "bad"},
        {"record_ids": ["a"], "from": TO, "to": FROM},
    ],
)
def test_http_invalid_request_is_422(client, payload):
    test_client, _ = client
    response = test_client.post("/history/replay-diff", json=payload)
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_http_missing_record_is_404(client):
    test_client, _ = client
    response = test_client.post(
        "/history/replay-diff",
        json={"record_ids": ["chg", "ghost"], "from": FROM, "to": TO},
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "record not found"}


def test_http_without_history_is_503(monkeypatch):
    import regulation_policy_compiler.app as app_module

    monkeypatch.setattr(app_module, "H", None)
    response = TestClient(app).post(
        "/history/replay-diff",
        json={"record_ids": ["a"], "from": FROM, "to": TO},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "history unavailable"}


def test_http_validates_before_checking_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    monkeypatch.setattr(app_module, "H", None)
    response = TestClient(app).post(
        "/history/replay-diff",
        json={"record_ids": [], "from": FROM, "to": TO},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_http_os_error_is_503(monkeypatch):
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
