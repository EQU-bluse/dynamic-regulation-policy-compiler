import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    compile_rules,
    decision_attestation,
    explain,
)

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


AT = "2021-06-01T00:00:00Z"


def _payload(**overrides):
    payload = {"at": AT, "facts": {}, "rules": []}
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------- function


def test_top_level_key_order_and_value_shapes():
    rules = [_rule(when={"z": False, "a": True}, result="允许")]
    facts = {"z": False, "a": True}
    report = decision_attestation(AT, facts, rules)
    assert list(report) == ["at", "facts", "explanation", "policy", "digest"]
    assert report["at"] == AT
    assert list(report["facts"]) == ["a", "z"]
    assert report["facts"] == facts
    assert report["explanation"] == explain(AT, facts, rules)
    assert list(report["explanation"]) == [
        "at",
        "decision",
        "trace",
        "basis",
        "conflicts",
    ]
    assert report["policy"] == compile_rules(AT, rules)
    assert list(report["policy"]) == ["at", "rules", "conflicts"]


def test_policy_keeps_conflicts():
    rules = [
        _rule(id="win", priority=9, result="allow"),
        _rule(id="loser", priority=1, result="deny"),
    ]
    report = decision_attestation(AT, {}, rules)
    assert report["policy"]["conflicts"] == [
        {"winner": ["law", "win", 1], "loser": ["law", "loser", 1]},
    ]
    # The explanation only keeps conflicts involving the basis; the policy
    # in the attestation must retain the full compile_rules conflict list.
    assert report["explanation"]["conflicts"] == report["policy"]["conflicts"]


def test_digest_is_sha256_of_first_four_fields_compact_json():
    rules = [_rule(result="允许")]
    report = decision_attestation(AT, {"k": True}, rules)
    payload = {
        "at": report["at"],
        "facts": report["facts"],
        "explanation": report["explanation"],
        "policy": report["policy"],
    }
    expected = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert report["digest"] == expected
    assert len(report["digest"]) == 64
    assert report["digest"] == report["digest"].lower()


def test_input_key_order_does_not_change_byte_output():
    rules = [_rule(when={"z": False, "a": True}, result="允许")]
    first = decision_attestation(AT, {"z": False, "a": True}, rules)
    second = decision_attestation(AT, {"a": True, "z": False}, rules)
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == (
        json.dumps(second, ensure_ascii=False, separators=(",", ":"))
    )


def test_rule_input_order_within_lists_is_irrelevant_to_content():
    rules_a = [_rule(id="a", priority=1), _rule(id="b", priority=2)]
    rules_b = [_rule(id="b", priority=2), _rule(id="a", priority=1)]
    first = decision_attestation(AT, {}, rules_a)
    second = decision_attestation(AT, {}, rules_b)
    assert first == second


def test_empty_facts_empty_rules_and_no_match_attest_normally():
    report = decision_attestation(AT, {}, [])
    assert report["facts"] == {}
    assert report["explanation"] == {
        "at": AT,
        "decision": None,
        "trace": [],
        "basis": None,
        "conflicts": [],
    }
    assert report["policy"] == {"at": AT, "rules": [], "conflicts": []}
    assert len(report["digest"]) == 64


def test_result_branches_do_not_share_mutable_containers():
    facts = {"a": True}
    when = {"a": True}
    rules = [_rule(when=when)]
    first = decision_attestation(AT, facts, rules)
    second = decision_attestation(AT, facts, rules)
    assert first == second
    assert first is not second
    # Mutating the first result must not reach the inputs or later results.
    first["facts"]["b"] = False
    first["explanation"]["basis"]["when"]["x"] = False
    first["policy"]["rules"].append("injected")
    first["policy"]["conflicts"].append("injected")
    assert facts == {"a": True}
    assert when == {"a": True}
    assert second["facts"] == {"a": True}
    assert second["explanation"]["basis"]["when"] == {"a": True}
    assert second["policy"]["rules"] == compile_rules(AT, rules)["rules"]
    assert second["policy"]["conflicts"] == []


def test_inputs_are_not_mutated():
    facts = {"z": True, "a": False}
    facts_snapshot = copy.deepcopy(facts)
    rules = [_rule(when=dict(facts))]
    rules_snapshot = copy.deepcopy(rules)
    decision_attestation(AT, facts, rules)
    assert facts == facts_snapshot
    assert list(facts) == ["z", "a"]
    assert rules == rules_snapshot


@pytest.mark.parametrize(
    "kwargs",
    [
        {"at": "not-a-time", "facts": {}, "rules": []},
        {"at": AT, "facts": {"x": 1}, "rules": []},
        {"at": AT, "facts": [], "rules": []},
        {"at": AT, "facts": {}, "rules": {}},
        {"at": AT, "facts": {}, "rules": [_rule(ver=0)]},
        {"at": AT, "facts": {}, "rules": [_rule(), _rule()]},
        {"at": AT, "facts": {}, "rules": [_rule(source="court")]},
        {
            "at": AT,
            "facts": {},
            "rules": [
                _rule(**{"from": "2021-01-01T00:00:00Z", "to": "2020-01-01T00:00:00Z"})
            ],
        },
    ],
)
def test_invalid_inputs_raise_value_error(kwargs):
    with pytest.raises(ValueError):
        decision_attestation(**kwargs)


# ---------------------------------------------------------------- endpoint


def test_endpoint_success_body():
    rules = [_rule(when={"z": False, "a": True}, result="允许")]
    response = client.post(
        "/explanations/attest",
        json=_payload(facts={"z": False, "a": True}, rules=rules),
    )
    assert response.status_code == 200
    data = response.json()
    assert list(data) == ["at", "facts", "explanation", "policy", "digest"]
    assert list(data["facts"]) == ["a", "z"]
    assert data["explanation"]["decision"] == "允许"
    assert data["policy"]["rules"]


def test_endpoint_compact_utf8_no_trailing_newline():
    response = client.post(
        "/explanations/attest", json=_payload(rules=[_rule(result="允许")])
    )
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw
    assert "允许" in raw and "\\u" not in raw


def test_endpoint_digest_matches_recomputation():
    response = client.post(
        "/explanations/attest",
        json=_payload(facts={"a": True}, rules=[_rule(when={"a": True})]),
    )
    data = response.json()
    payload = {key: data[key] for key in ("at", "facts", "explanation", "policy")}
    digest = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert data["digest"] == digest


def test_endpoint_byte_identical_regardless_of_key_order():
    rules = [_rule(when={"z": False, "a": True})]
    first = client.post(
        "/explanations/attest",
        json=_payload(facts={"z": False, "a": True}, rules=rules),
    ).content
    second = client.post(
        "/explanations/attest",
        data=json.dumps(
            {"rules": rules, "at": AT, "facts": {"a": True, "z": False}},
            ensure_ascii=False,
        ).encode("utf-8"),
        headers={"content-type": "application/json"},
    ).content
    assert first == second


def test_endpoint_invalid_bodies_are_422():
    bad_bodies = [
        b"not json",
        b"[]",
        b"null",
        b'"x"',
        b"{}",
        json.dumps(_payload(extra=1)).encode(),
        json.dumps({"at": AT, "facts": {}}).encode(),
    ]
    for raw in bad_bodies:
        response = client.post(
            "/explanations/attest",
            content=raw,
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 422, raw
        assert response.content == json.dumps(
            {"detail": "invalid request"}, separators=(",", ":")
        ).encode("utf-8")


def test_endpoint_validation_failures_are_422():
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
        response = client.post("/explanations/attest", json=payload)
        assert response.status_code == 422, payload
        assert response.json() == {"detail": "invalid request"}


def test_endpoint_empty_inputs_succeed():
    response = client.post("/explanations/attest", json=_payload())
    assert response.status_code == 200
    data = response.json()
    assert data["explanation"]["decision"] is None
    assert data["policy"] == {"at": AT, "rules": [], "conflicts": []}


def test_endpoint_does_not_touch_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("POST /explanations/attest must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/explanations/attest", json=_payload(rules=[_rule()])
    )
    assert response.status_code == 200


def test_endpoint_works_without_history_configured(monkeypatch):
    import regulation_policy_compiler.app as app_module

    monkeypatch.setattr(app_module, "H", None)
    response = client.post(
        "/explanations/attest", json=_payload(rules=[_rule()])
    )
    assert response.status_code == 200
