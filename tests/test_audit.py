import hashlib
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


def _expected_digest(previous, entry):
    payload = {key: entry[key] for key in ("at", "decision", "trace", "basis")}
    content = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(
        previous.encode("ascii") + content.encode("utf-8")
    ).hexdigest()


@pytest.fixture
def client(tmp_path, monkeypatch):
    import regulation_policy_compiler.app as app_module

    history = DecisionHistory(str(tmp_path / "history.json"))
    monkeypatch.setattr(app_module, "H", history)
    return TestClient(app), history


def test_audit_returns_chained_entries_in_closed_interval_ascending(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("rec-1", "2021-03-01T00:00:00Z", {}, [])
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="允许")])
    history.record("rec-1", "2021-06-01T00:00:00Z", {}, [_rule(result="second")])
    history.record("other", "2021-02-01T00:00:00Z", {}, [_rule(result="x")])
    report = history.audit("rec-1", "2021-01-01T00:00:00Z", "2021-06-01T00:00:00Z")
    assert list(report) == ["id", "start", "end", "root", "entries"]
    assert report["id"] == "rec-1"
    assert report["start"] == "2021-01-01T00:00:00Z"
    assert report["end"] == "2021-06-01T00:00:00Z"
    assert [entry["at"] for entry in report["entries"]] == [
        "2021-01-01T00:00:00Z",
        "2021-03-01T00:00:00Z",
        "2021-06-01T00:00:00Z",
    ]
    previous = "0" * 64
    for entry in report["entries"]:
        assert list(entry) == ["at", "decision", "trace", "basis", "previous", "digest"]
        assert entry["previous"] == previous
        assert entry["digest"] == _expected_digest(previous, entry)
        previous = entry["digest"]
    assert report["root"] == report["entries"][-1]["digest"]
    assert report["entries"][0]["decision"] == "允许"


def test_audit_interval_bounds_are_inclusive(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="a")])
    history.record("rec-1", "2021-02-01T00:00:00Z", {}, [_rule(result="b")])
    history.record("rec-1", "2021-03-01T00:00:00Z", {}, [_rule(result="c")])
    report = history.audit("rec-1", "2021-02-01T00:00:00Z", "2021-02-01T00:00:00Z")
    assert [entry["at"] for entry in report["entries"]] == ["2021-02-01T00:00:00Z"]
    entry = report["entries"][0]
    assert entry["decision"] == "b"
    assert entry["previous"] == "0" * 64
    assert report["root"] == entry["digest"]


def test_audit_chain_covers_only_selected_window(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="a")])
    history.record("rec-1", "2021-02-01T00:00:00Z", {}, [_rule(result="b")])
    history.record("rec-1", "2021-03-01T00:00:00Z", {}, [_rule(result="c")])
    report = history.audit("rec-1", "2021-02-01T00:00:00Z", "2021-03-01T00:00:00Z")
    # The chain restarts at the genesis previous for the selected window.
    assert report["entries"][0]["previous"] == "0" * 64
    assert report["entries"][1]["previous"] == report["entries"][0]["digest"]
    assert report["root"] == report["entries"][1]["digest"]


def test_audit_empty_interval_raises_key_error(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("rec-1", "2021-06-01T00:00:00Z", {}, [])
    with pytest.raises(KeyError):
        history.audit("rec-1", "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z")
    with pytest.raises(KeyError):
        history.audit("missing", "2021-01-01T00:00:00Z", "2022-01-01T00:00:00Z")


def test_audit_rejects_bad_arguments(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    with pytest.raises(ValueError):
        history.audit("", "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z")
    with pytest.raises(ValueError):
        history.audit(None, "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z")
    with pytest.raises(ValueError):
        history.audit("rec-1", "bad", "2021-02-01T00:00:00Z")
    with pytest.raises(ValueError):
        history.audit("rec-1", "2021-01-01T00:00:00Z", "bad")
    with pytest.raises(ValueError):
        history.audit("rec-1", "2021-02-01T00:00:00Z", "2021-01-01T00:00:00Z")


def test_audit_returns_deep_copies_and_does_not_mutate(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="a")])
    report = history.audit("rec-1", "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z")
    report["entries"][0]["decision"] = "tampered"
    report["entries"][0]["trace"].append("x@9")
    report["entries"][0]["basis"]["result"] = "tampered"
    again = history.audit("rec-1", "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z")
    assert again["entries"][0]["decision"] == "a"
    assert again["entries"][0]["trace"] == ["r1@1"]
    assert again["entries"][0]["basis"]["result"] == "a"
    assert again["entries"][0]["digest"] == report["entries"][0]["digest"]


def test_audit_is_read_only(tmp_path):
    path = tmp_path / "history.json"
    history = DecisionHistory(str(path))
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [])
    before = path.read_bytes()
    history.audit("rec-1", "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z")
    with pytest.raises(KeyError):
        history.audit("rec-1", "2022-01-01T00:00:00Z", "2022-02-01T00:00:00Z")
    assert path.read_bytes() == before


def test_audit_normalizes_basis_from_old_file_without_rewriting(tmp_path):
    path = tmp_path / "history.json"
    basis = {
        "result": "allow",
        "when": {"z": True, "a": False},
        "to": None,
        "from": "2020-01-01T00:00:00Z",
        "priority": 0,
        "source": "law",
        "ver": 1,
        "id": "r1",
    }
    record = {
        "id": "rec-1",
        "at": "2021-01-01T00:00:00Z",
        "decision": "allow",
        "trace": ["r1@1"],
        "basis": basis,
    }
    path.write_text(json.dumps({"records": [record]}) + "\n", encoding="utf-8")
    before = path.read_bytes()
    history = DecisionHistory(str(path))
    report = history.audit("rec-1", "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z")
    entry_basis = report["entries"][0]["basis"]
    assert list(entry_basis) == [
        "id",
        "ver",
        "source",
        "priority",
        "from",
        "to",
        "when",
        "result",
    ]
    assert list(entry_basis["when"]) == ["a", "z"]
    # The digest is computed over the canonical basis shape.
    assert report["entries"][0]["digest"] == _expected_digest(
        "0" * 64, report["entries"][0]
    )
    # Querying must not rewrite the old file.
    assert path.read_bytes() == before


def test_audit_http_success_shape_and_chain(client):
    test_client, history = client
    history.record("rec-1", "2021-03-01T00:00:00Z", {}, [_rule(result="mid")])
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="允许")])
    response = test_client.get(
        "/decisions/rec-1/audit",
        params={"start": "2021-01-01T00:00:00Z", "end": "2021-12-31T00:00:00Z"},
    )
    assert response.status_code == 200
    data = response.json()
    assert list(data) == ["id", "start", "end", "root", "entries"]
    assert [entry["at"] for entry in data["entries"]] == [
        "2021-01-01T00:00:00Z",
        "2021-03-01T00:00:00Z",
    ]
    previous = "0" * 64
    for entry in data["entries"]:
        assert list(entry) == ["at", "decision", "trace", "basis", "previous", "digest"]
        assert entry["previous"] == previous
        assert entry["digest"] == _expected_digest(previous, entry)
        previous = entry["digest"]
    assert data["root"] == data["entries"][-1]["digest"]


def test_audit_http_response_is_compact_utf8_without_trailing_newline(client):
    test_client, history = client
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="允许")])
    response = test_client.get(
        "/decisions/rec-1/audit",
        params={"start": "2021-01-01T00:00:00Z", "end": "2021-02-01T00:00:00Z"},
    )
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw
    assert "允许" in raw and "\\u" not in raw


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
def test_audit_http_invalid_query_is_422(client, query):
    test_client, _ = client
    response = test_client.get(f"/decisions/rec-1/audit{query}")
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_audit_http_empty_interval_is_404(client):
    test_client, history = client
    history.record("rec-1", "2021-06-01T00:00:00Z", {}, [])
    response = test_client.get(
        "/decisions/rec-1/audit",
        params={"start": "2021-01-01T00:00:00Z", "end": "2021-02-01T00:00:00Z"},
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "record not found"}


def test_audit_http_unknown_record_is_404(client):
    test_client, _ = client
    response = test_client.get(
        "/decisions/missing/audit",
        params={"start": "2021-01-01T00:00:00Z", "end": "2021-02-01T00:00:00Z"},
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "record not found"}


def test_audit_http_without_history_is_503(monkeypatch):
    import regulation_policy_compiler.app as app_module

    monkeypatch.setattr(app_module, "H", None)
    response = TestClient(app).get(
        "/decisions/rec-1/audit",
        params={"start": "2021-01-01T00:00:00Z", "end": "2021-02-01T00:00:00Z"},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "history unavailable"}


def test_audit_http_validates_query_before_checking_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    monkeypatch.setattr(app_module, "H", None)
    response = TestClient(app).get("/decisions/rec-1/audit?extra=1")
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_audit_http_os_error_is_503(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class FailingHistory:
        def audit(self, *args, **kwargs):
            raise OSError("disk gone")

    monkeypatch.setattr(app_module, "H", FailingHistory())
    response = TestClient(app).get(
        "/decisions/rec-1/audit",
        params={"start": "2021-01-01T00:00:00Z", "end": "2021-02-01T00:00:00Z"},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "history unavailable"}


def test_audit_http_does_not_affect_other_decision_routes(client):
    test_client, history = client
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="allow")])
    response = test_client.get(
        "/decisions/rec-1", params={"at": "2021-01-01T00:00:00Z"}
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
    response = test_client.get(
        "/decisions/rec-1/evolution",
        params={"start": "2021-01-01T00:00:00Z", "end": "2021-02-01T00:00:00Z"},
    )
    assert response.status_code == 200
    assert list(response.json()) == ["id", "start", "end", "entries"]
