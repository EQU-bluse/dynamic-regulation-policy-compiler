import json

from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app

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


def _payload(**overrides):
    payload = {"at": "2021-06-01T00:00:00Z", "facts": {}, "rules": []}
    payload.update(overrides)
    return payload


def test_no_match_returns_null_basis_and_empty_conflicts():
    response = client.post("/explanations", json=_payload())
    assert response.status_code == 200
    assert response.json() == {
        "at": "2021-06-01T00:00:00Z",
        "decision": None,
        "trace": [],
        "basis": None,
        "conflicts": [],
    }
    assert list(response.json()) == ["at", "decision", "trace", "basis", "conflicts"]


def test_match_returns_evaluate_outputs_and_basis_snapshot():
    rules = [_rule(when={"z": False, "a": True}, result="允许")]
    response = client.post(
        "/explanations", json=_payload(facts={"z": False, "a": True}, rules=rules)
    )
    assert response.status_code == 200
    data = response.json()
    assert data["at"] == "2021-06-01T00:00:00Z"
    assert data["decision"] == "允许"
    assert data["trace"] == ["r1@1"]
    assert data["basis"] == _rule(when={"z": False, "a": True}, result="允许")
    assert list(data["basis"]) == [
        "id",
        "ver",
        "source",
        "priority",
        "from",
        "to",
        "when",
        "result",
    ]
    assert list(data["basis"]["when"]) == ["a", "z"]
    assert data["conflicts"] == []


def test_conflicts_keep_only_entries_involving_basis_in_original_order():
    rules = [
        _rule(id="win", priority=9, result="allow"),
        _rule(id="other", source="org", priority=1, result="deny"),
        _rule(id="loser", priority=1, result="deny"),
    ]
    response = client.post("/explanations", json=_payload(rules=rules))
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "allow"
    assert data["basis"]["id"] == "win"
    # compile order is win (law p9), loser (law p1), other (org);
    # raw pairs: win-loser, win-other (loser-other share the same result).
    assert data["conflicts"] == [
        {"winner": ["law", "win", 1], "loser": ["law", "loser", 1]},
        {"winner": ["law", "win", 1], "loser": ["org", "other", 1]},
    ]
    for conflict in data["conflicts"]:
        assert list(conflict) == ["winner", "loser"]


def test_conflict_where_basis_is_loser_is_kept():
    rules = [
        _rule(id="top", priority=9, result="allow", when={"x": True}),
        _rule(id="base", priority=1, result="deny"),
    ]
    response = client.post("/explanations", json=_payload(facts={"x": False}, rules=rules))
    data = response.json()
    assert data["decision"] == "deny"
    assert data["basis"]["id"] == "base"
    assert data["trace"] == ["base@1"]
    assert data["conflicts"] == [
        {"winner": ["law", "top", 1], "loser": ["law", "base", 1]},
    ]


def test_winner_disambiguation_uses_source_not_just_trace_signature():
    # law r1@1 does not match; org r1@1 matches and wins. trace alone ("r1@1")
    # must not be misattributed to the law rule.
    rules = [
        _rule(id="r1", when={"a": True}),
        _rule(id="r1", source="org", priority=99, result="org-allow"),
    ]
    response = client.post("/explanations", json=_payload(facts={}, rules=rules))
    data = response.json()
    assert data["trace"] == ["r1@1"]
    assert data["basis"]["source"] == "org"
    assert data["decision"] == "org-allow"


def test_response_is_compact_utf8_without_trailing_newline():
    response = client.post(
        "/explanations", json=_payload(rules=[_rule(result="允许")])
    )
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw
    assert "允许" in raw and "\\u" not in raw


def test_basis_is_a_deep_copy():
    # The response is serialized from snapshots; mutating input structures
    # cannot change the shape, and the compiled snapshot has its own when dict.
    when = {"z": True, "a": False}
    rules = [_rule(when=when)]
    response = client.post(
        "/explanations", json=_payload(facts={"z": True, "a": False}, rules=rules)
    )
    assert response.json()["basis"]["when"] == {"a": False, "z": True}
    assert when == {"z": True, "a": False}


def test_invalid_bodies_are_422():
    bad_bodies = [
        b"not json",
        b"[]",
        b"null",
        b'"x"',
        b"{}",
        json.dumps(_payload(extra=1)).encode(),
        json.dumps({"at": "2021-06-01T00:00:00Z", "facts": {}}).encode(),
    ]
    for raw in bad_bodies:
        response = client.post("/explanations", content=raw, headers={"content-type": "application/json"})
        assert response.status_code == 422, raw
        assert response.json() == {"detail": "invalid request"}


def test_validation_failures_are_422():
    cases = [
        _payload(at="not-a-time"),
        _payload(facts={"x": 1}),
        _payload(facts=[]),
        _payload(rules={}),
        _payload(rules=[_rule(ver=0)]),
        _payload(rules=[_rule(), _rule()]),
        _payload(rules=[_rule(source="court")]),
    ]
    for payload in cases:
        response = client.post("/explanations", json=payload)
        assert response.status_code == 422, payload
        assert response.json() == {"detail": "invalid request"}


def test_endpoint_does_not_touch_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def record(self, *args, **kwargs):
            raise AssertionError("POST /explanations must not write history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post("/explanations", json=_payload(rules=[_rule()]))
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
