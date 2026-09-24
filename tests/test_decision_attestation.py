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

AT = "2021-06-01T00:00:00Z"


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
    payload = {"at": AT, "facts": {}, "rules": []}
    payload.update(overrides)
    return payload


def _expected_digest(at, facts, rules):
    explanation = explain(at, facts, rules)
    policy = compile_rules(at, rules)
    canonical = json.dumps(
        {
            "at": at,
            "facts": {key: facts[key] for key in sorted(facts)},
            "explanation": explanation,
            "policy": policy,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- function


def test_top_level_keys_in_order():
    report = decision_attestation(AT, {}, [])
    assert list(report) == ["at", "facts", "explanation", "policy", "digest"]


def test_facts_sorted_canonical_and_deep_copied():
    facts = {"z": True, "a": False, "中": True}
    report = decision_attestation(AT, facts, [])
    assert list(report["facts"]) == ["a", "z", "中"]
    assert report["facts"] == {"a": False, "z": True, "中": True}
    assert report["facts"] is not facts
    # input keeps its original order
    assert list(facts) == ["z", "a", "中"]


def test_explanation_and_policy_match_existing_functions():
    facts = {"x": False}
    rules = [
        _rule(id="top", priority=9, result="allow", when={"x": True}),
        _rule(id="base", priority=1, result="deny"),
        _rule(id="org1", source="org", priority=1, result="允许"),
    ]
    report = decision_attestation(AT, facts, rules)
    assert report["at"] == AT
    assert report["explanation"] == explain(AT, facts, rules)
    assert report["policy"] == compile_rules(AT, rules)
    # policy must keep the conflicts in full
    assert report["policy"]["conflicts"] == compile_rules(AT, rules)["conflicts"]
    assert any(
        conflict["winner"][1] == "base" and conflict["loser"][1] == "org1"
        for conflict in report["policy"]["conflicts"]
    )
    # canonical orderings are preserved at every level
    assert list(report["explanation"]) == [
        "at",
        "decision",
        "trace",
        "basis",
        "conflicts",
    ]
    assert list(report["policy"]) == ["at", "rules", "conflicts"]


def test_digest_is_sha256_of_first_four_keys():
    facts = {"z": False, "a": True}
    rules = [_rule(when={"z": False, "a": True}, result="允许")]
    report = decision_attestation(AT, facts, rules)
    digest = report["digest"]
    assert isinstance(digest, str)
    assert len(digest) == 64
    assert digest == digest.lower()
    assert all(char in "0123456789abcdef" for char in digest)
    assert digest == _expected_digest(AT, facts, rules)


def test_digest_excludes_the_digest_field_itself():
    report = decision_attestation(AT, {}, [])
    payload = {key: report[key] for key in ("at", "facts", "explanation", "policy")}
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    assert report["digest"] == hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


def test_identical_values_yield_byte_identical_vouchers_regardless_of_order():
    rules_a = [_rule(when={"z": True, "a": False}, result="允许")]
    rules_b = [_rule(when={"a": False, "z": True}, result="允许")]
    facts_a = {"z": True, "a": False}
    facts_b = {"a": False, "z": True}
    left = decision_attestation(AT, facts_a, rules_a)
    right = decision_attestation(AT, facts_b, rules_b)
    encoded_left = json.dumps(left, ensure_ascii=False, separators=(",", ":"))
    encoded_right = json.dumps(right, ensure_ascii=False, separators=(",", ":"))
    assert encoded_left == encoded_right
    assert left == right
    assert left["digest"] == right["digest"]


def test_empty_facts_empty_rules_and_no_match_still_attest():
    report = decision_attestation(AT, {}, [])
    assert report["facts"] == {}
    assert report["explanation"]["decision"] is None
    assert report["explanation"]["trace"] == []
    assert report["explanation"]["basis"] is None
    assert report["explanation"]["conflicts"] == []
    assert report["policy"] == {"at": AT, "rules": [], "conflicts": []}
    assert len(report["digest"]) == 64

    # rules present but none match the facts
    report_no_match = decision_attestation(
        AT, {"x": False}, [_rule(when={"x": True})]
    )
    assert report_no_match["explanation"]["decision"] is None
    assert report_no_match["explanation"]["basis"] is None
    assert len(report_no_match["policy"]["rules"]) == 1


def test_result_branches_do_not_share_mutable_containers():
    facts = {"a": True}
    when = {"a": True}
    rules = [_rule(when=when, result="allow")]
    facts_before = copy.deepcopy(facts)
    rules_before = copy.deepcopy(rules)

    first = decision_attestation(AT, facts, rules)
    second = decision_attestation(AT, facts, rules)

    # distinct containers across calls
    assert first["facts"] is not second["facts"]
    assert first["explanation"] is not second["explanation"]
    assert first["policy"] is not second["policy"]
    assert first["explanation"]["basis"] is not second["explanation"]["basis"]
    assert (
        first["policy"]["rules"][0] is not second["policy"]["rules"][0]
    )

    # mutating a result must not affect later equal calls
    first["facts"]["a"] = False
    first["explanation"]["decision"] = "tampered"
    first["explanation"]["trace"].append("fake@9")
    first["policy"]["rules"][0]["result"] = "tampered"
    first["policy"]["conflicts"].append({"winner": ["law", "x", 1], "loser": ["law", "y", 1]})
    third = decision_attestation(AT, facts, rules)
    assert third == second
    assert third["explanation"]["decision"] == "allow"
    assert third["policy"]["rules"][0]["result"] == "allow"

    # inputs untouched throughout
    assert facts == facts_before
    assert rules == rules_before
    assert when == {"a": True}


@pytest.mark.parametrize(
    "at,facts,rules",
    [
        ("not-a-time", {}, []),
        ("2021-02-30T00:00:00Z", {}, []),
        (AT, {"x": 1}, []),
        (AT, [], []),
        (AT, "notdict", []),
        (AT, {}, {}),
        (AT, {}, [_rule(ver=0)]),
        (AT, {}, [_rule(), _rule()]),
        (AT, {}, [_rule(source="court")]),
        (AT, {}, [_rule(**{"from": "2022-01-01T00:00:00Z", "to": "2021-01-01T00:00:00Z"})]),
        (AT, {}, [{"id": "x"}]),
    ],
)
def test_invalid_inputs_raise_value_error(at, facts, rules):
    with pytest.raises(ValueError):
        decision_attestation(at, facts, rules)


def test_invalid_inputs_are_not_mutated():
    rules = [_rule(ver=0)]
    rules_before = copy.deepcopy(rules)
    with pytest.raises(ValueError):
        decision_attestation(AT, {"ok": True}, rules)
    assert rules == rules_before


# ---------------------------------------------------------------- endpoint


def test_endpoint_success_shape_and_compact_json():
    facts = {"z": False, "a": True}
    rules = [_rule(when={"z": False, "a": True}, result="允许")]
    response = client.post("/explanations/attest", json=_payload(facts=facts, rules=rules))
    assert response.status_code == 200
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw
    assert "允许" in raw and "\\u" not in raw

    data = json.loads(raw)
    assert list(data) == ["at", "facts", "explanation", "policy", "digest"]
    assert list(data["facts"]) == ["a", "z"]
    assert data["explanation"] == explain(AT, facts, rules)
    assert data["policy"] == compile_rules(AT, rules)
    assert data["digest"] == _expected_digest(AT, facts, rules)


def test_endpoint_empty_inputs():
    response = client.post("/explanations/attest", json=_payload())
    assert response.status_code == 200
    data = response.json()
    assert data["facts"] == {}
    assert data["explanation"]["decision"] is None
    assert data["policy"] == {"at": AT, "rules": [], "conflicts": []}
    assert len(data["digest"]) == 64


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        b"null",
        b'"x"',
        b"{}",
        json.dumps({"at": AT, "facts": {}}).encode(),
        json.dumps(_payload(extra=1)).encode(),
        json.dumps({"at": AT, "facts": {}, "rules": [], "policy": {}}).encode(),
    ],
)
def test_endpoint_bad_bodies_are_422(raw):
    response = client.post(
        "/explanations/attest",
        content=raw,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content.decode("utf-8") == json.dumps(
        {"detail": "invalid request"}, separators=(",", ":")
    )


@pytest.mark.parametrize(
    "payload",
    [
        _payload(at="not-a-time"),
        _payload(facts={"x": 1}),
        _payload(facts=[]),
        _payload(rules={}),
        _payload(rules=[_rule(ver=0)]),
        _payload(rules=[_rule(), _rule()]),
        _payload(rules=[_rule(source="court")]),
    ],
)
def test_endpoint_validation_failures_are_422(payload):
    response = client.post("/explanations/attest", json=payload)
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_endpoint_does_not_touch_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def record(self, *args, **kwargs):
            raise AssertionError("POST /explanations/attest must not write history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/explanations/attest", json=_payload(rules=[_rule()])
    )
    assert response.status_code == 200
    assert response.json()["explanation"]["decision"] == "allow"
