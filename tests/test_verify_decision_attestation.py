import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_attestation,
    verify_decision_attestation,
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


def _attest(facts=None, rules=None):
    return decision_attestation(AT, {} if facts is None else facts, rules or [])


def _expected(report):
    return {"at": report["at"], "digest": report["digest"]}


# ---------------------------------------------------------------- function


def test_verifies_genuine_reports():
    assert verify_decision_attestation(_attest(), _expected(_attest())) is True
    rules = [_rule(when={"z": False, "a": True}, result="允许")]
    report = _attest({"z": False, "a": True}, rules)
    assert verify_decision_attestation(report, _expected(report)) is True


def test_verifies_with_conflicts_and_non_matching_explanation():
    rules = [
        _rule(id="win", priority=9, result="allow"),
        _rule(id="lose", priority=1, result="deny"),
    ]
    report = _attest({}, rules)
    assert verify_decision_attestation(report, _expected(report)) is True
    # Facts satisfying neither rule: decision is null but policy conflicts remain.
    gated = [
        _rule(id="win", priority=9, when={"x": True}, result="allow"),
        _rule(id="lose", priority=1, when={"y": True}, result="deny"),
    ]
    report = _attest({}, gated)
    assert report["explanation"]["decision"] is None
    assert len(report["policy"]["conflicts"]) == 1
    assert verify_decision_attestation(report, _expected(report)) is True


def test_declared_digest_tampering_returns_false():
    report = _attest({"k": True}, [_rule()])
    report["digest"] = "f" * 64
    assert verify_decision_attestation(report, _expected(report)) is False


def test_expected_digest_mismatch_returns_false():
    report = _attest()
    expected = _expected(report)
    expected["digest"] = "0" * 64
    assert verify_decision_attestation(report, expected) is False


def test_expected_at_mismatch_returns_false():
    report = _attest()
    expected = _expected(report)
    expected["at"] = "2021-06-02T00:00:00Z"
    assert verify_decision_attestation(report, expected) is False


def test_fully_recomputed_forgery_fails_against_authentic_expected():
    # Add an unused fact: semantics are unchanged, so the forged report can
    # carry a self-consistent digest, yet it fails against the authentic one.
    report = _attest({"k": True}, [_rule(when=None)])
    authentic = report["digest"]
    report["facts"]["extra"] = False
    payload = {
        key: report[key] for key in ("at", "facts", "explanation", "policy")
    }
    report["digest"] = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    expected = {"at": report["at"], "digest": authentic}
    assert verify_decision_attestation(report, expected) is False


def test_recomputed_digest_ignores_input_key_order():
    rules = [_rule(when={"z": False, "a": True}, result="允许")]
    report = decision_attestation(AT, {"a": True, "z": False}, rules)
    # Rebuild the report dicts in scrambled order; verification canonicalizes.
    scrambled = {
        "digest": report["digest"],
        "policy": dict(reversed(list(report["policy"].items()))),
        "explanation": dict(reversed(list(report["explanation"].items()))),
        "facts": {"z": False, "a": True},
        "at": report["at"],
    }
    scrambled["policy"]["rules"] = [
        dict(reversed(list(rule.items()))) for rule in report["policy"]["rules"]
    ]
    assert verify_decision_attestation(scrambled, _expected(report)) is True


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.pop("digest"),
        lambda r: r.update(extra=1),
        lambda r: r.update(at="not-a-time"),
        lambda r: r.update(facts={"x": 1}),
        lambda r: r.update(facts={"": True}),
        lambda r: r.update(facts=[]),
        lambda r: r.update(digest="F" * 64),
        lambda r: r.update(digest="0" * 63),
        lambda r: r.update(policy=[]),
        lambda r: r.update(explanation=[]),
    ],
)
def test_bad_report_shapes_raise_value_error(mutate):
    report = _attest({"k": True}, [_rule()])
    mutate(report)
    with pytest.raises(ValueError):
        verify_decision_attestation(report, _expected(decision_attestation(AT, {"k": True}, [_rule()])))


def test_non_dict_report_raises_value_error():
    with pytest.raises(ValueError):
        verify_decision_attestation([], {"at": AT, "digest": "0" * 64})


def test_bad_policy_structures_raise_value_error():
    rules = [
        _rule(id="a", priority=2, result="allow"),
        _rule(id="b", priority=1, result="deny"),
    ]
    report = _attest({}, rules)

    bad = copy.deepcopy(report)
    bad["policy"]["at"] = "2021-06-02T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    bad["policy"]["rules"].reverse()
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    bad["policy"]["rules"].append(copy.deepcopy(bad["policy"]["rules"][0]))
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    bad["policy"]["rules"][0]["to"] = "2021-01-01T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    del bad["policy"]["conflicts"][0]
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    forged = {"winner": ["law", "a", 1], "loser": ["law", "a", 1]}
    bad["policy"]["conflicts"].append(forged)
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    bad["policy"]["conflicts"][0]["winner"].append(9)
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    bad["policy"].update(extra=1)
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report))


def test_bad_explanation_semantics_raise_value_error():
    rules = [
        _rule(id="win", priority=9, result="allow"),
        _rule(id="lose", priority=1, result="deny"),
    ]
    report = _attest({}, rules)

    bad = copy.deepcopy(report)
    bad["explanation"]["decision"] = "deny"
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    bad["explanation"]["trace"] = []
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    bad["explanation"]["trace"] = ["lose@1", "win@1"]
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    bad["explanation"]["basis"]["result"] = "deny"
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report))

    # A conflict not involving the basis must not appear in the explanation.
    rules_three = rules + [
        _rule(id="mid", priority=5, result="deny"),
        _rule(id="low", priority=1, result="allow"),
    ]
    report_three = _attest({}, rules_three)
    basis_id = report_three["explanation"]["basis"]["id"]
    unrelated = next(
        c
        for c in report_three["policy"]["conflicts"]
        if basis_id not in (c["winner"][1], c["loser"][1])
    )
    bad = copy.deepcopy(report_three)
    bad["explanation"]["conflicts"].append(unrelated)
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report_three))

    # No match: decision/basis null and trace/conflicts empty.
    gated = [
        _rule(id="g1", priority=9, when={"x": True}, result="allow"),
        _rule(id="g2", priority=1, when={"x": True}, result="deny"),
    ]
    no_match = _attest({}, gated)
    assert no_match["policy"]["conflicts"]
    bad = copy.deepcopy(no_match)
    bad["explanation"]["decision"] = "allow"
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(no_match))
    bad = copy.deepcopy(no_match)
    bad["explanation"]["basis"] = report["explanation"]["basis"]
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(no_match))
    bad = copy.deepcopy(no_match)
    bad["explanation"]["conflicts"] = copy.deepcopy(
        no_match["policy"]["conflicts"]
    )
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(no_match))

    bad = copy.deepcopy(report)
    bad["explanation"]["at"] = "2021-06-02T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    bad["explanation"].update(extra=1)
    with pytest.raises(ValueError):
        verify_decision_attestation(bad, _expected(report))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.clear(),
        lambda e: e.update(extra=1),
        lambda e: e.pop("digest"),
        lambda e: e.update(at="bad"),
        lambda e: e.update(digest="X" * 64),
        lambda e: e.update(digest=123),
    ],
)
def test_bad_expected_shapes_raise_value_error(mutate):
    report = _attest()
    expected = _expected(report)
    mutate(expected)
    with pytest.raises(ValueError):
        verify_decision_attestation(report, expected)


def test_structure_validated_before_value_comparison():
    # Invalid report raises even though expected.at/digest match the declared
    # values; a comparison must not short-circuit to False first.
    report = _attest()
    expected = _expected(report)
    report["facts"] = {"x": 1}
    with pytest.raises(ValueError):
        verify_decision_attestation(report, expected)


def test_does_not_mutate_inputs():
    rules = [_rule(when={"z": False, "a": True}, result="允许")]
    report = _attest({"z": False, "a": True}, rules)
    scrambled = {
        "digest": report["digest"],
        "policy": dict(reversed(list(report["policy"].items()))),
        "explanation": dict(reversed(list(report["explanation"].items()))),
        "facts": {"z": False, "a": True},
        "at": report["at"],
    }
    expected = _expected(report)
    report_before = copy.deepcopy(scrambled)
    expected_before = copy.deepcopy(expected)
    assert verify_decision_attestation(scrambled, expected) is True
    assert scrambled == report_before
    assert expected == expected_before
    # Original report and rules are untouched too.
    assert report == decision_attestation(AT, {"z": False, "a": True}, rules)


# ---------------------------------------------------------------- endpoint


def test_http_valid_report_is_200_compact_json(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    report = _attest({"a": True}, [_rule(when={"a": True})])
    response = client.post(
        "/explanations/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
    raw = response.content.decode("utf-8")
    assert raw == json.dumps({"valid": True}, separators=(",", ":"))
    assert not raw.endswith("\n")


def test_http_tampered_report_is_200_false(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    report = _attest()
    report["digest"] = "f" * 64
    response = client.post(
        "/explanations/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": False}


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b"null",
        b'"x"',
        b"{}",
        b'{"report": {}}',
        b'{"report": {}, "expected": {}}',
        b'{"report": {}, "expected": {}, "extra": 1}',
    ],
)
def test_http_bad_body_is_422(monkeypatch, body):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    response = client.post(
        "/explanations/attest/verify",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == json.dumps(
        {"detail": "invalid request"}, separators=(",", ":")
    ).encode("utf-8")


def test_http_value_error_in_function_is_422(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    report = _attest()
    report["facts"] = {"x": 1}
    response = client.post(
        "/explanations/attest/verify",
        json={"report": report, "expected": _expected(decision_attestation(AT, {}, []))},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_http_works_without_history_configured(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    report = _attest(rules=[_rule()])
    response = client.post(
        "/explanations/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
