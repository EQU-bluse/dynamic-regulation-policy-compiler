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
OTHER = "2022-06-01T00:00:00Z"


def _expected(report):
    return {"at": report["at"], "digest": report["digest"]}


def _conflicting_rules():
    return [
        _rule(id="win", priority=9, result="allow"),
        _rule(id="loser", priority=1, result="deny"),
        _rule(id="tie", priority=0, result="deny"),
    ]


# ---------------------------------------------------------------- valid cases


def test_valid_report_with_match_verifies():
    rules = _conflicting_rules()
    report = decision_attestation(AT, {"a": True}, rules)
    assert verify_decision_attestation(report, _expected(report)) is True


def test_valid_report_without_match_verifies():
    report = decision_attestation(AT, {}, [])
    assert verify_decision_attestation(report, _expected(report)) is True
    assert report["explanation"]["decision"] is None


def test_shuffled_key_orders_still_verify():
    rules = [_rule(when={"z": True, "a": False}, result="允许")]
    report = decision_attestation(AT, {"z": True, "a": False}, rules)
    shuffled = copy.deepcopy(report)
    shuffled["facts"] = {"z": True, "a": False}
    shuffled["explanation"]["basis"]["when"] = {"z": True, "a": False}
    shuffled["policy"]["rules"][0]["when"] = {"a": False, "z": True}
    assert verify_decision_attestation(shuffled, _expected(report)) is True


def test_non_ascii_content_round_trips():
    rules = [_rule(result="允许")]
    report = decision_attestation(AT, {"键": True}, rules)
    assert verify_decision_attestation(report, _expected(report)) is True


# ---------------------------------------------------------------- False cases


def test_declared_digest_mismatch_returns_false():
    report = decision_attestation(AT, {}, [_rule()])
    wrong = "f" * 64
    assert wrong != report["digest"]
    tampered = copy.deepcopy(report)
    tampered["digest"] = wrong
    # Even an expected matching the (wrong) declared digest cannot rescue it.
    assert verify_decision_attestation(tampered, {"at": AT, "digest": wrong}) is False


def test_expected_digest_mismatch_returns_false():
    report = decision_attestation(AT, {}, [_rule()])
    assert (
        verify_decision_attestation(report, {"at": AT, "digest": "0" * 64}) is False
    )


def test_expected_at_mismatch_returns_false():
    report = decision_attestation(AT, {}, [_rule()])
    assert (
        verify_decision_attestation(
            report, {"at": OTHER, "digest": report["digest"]}
        )
        is False
    )


def test_facts_tampered_breaks_explanation_semantics():
    report = decision_attestation(AT, {"a": True}, [_rule(when={"a": True})])
    tampered = copy.deepcopy(report)
    tampered["facts"] = {"a": False}
    # Rebuild the digest over the tampered payload so the declared digest is
    # internally consistent; the explanation semantics now disagree with the
    # facts, which is an illegal structure regardless of the digest.
    payload = {
        "at": tampered["at"],
        "facts": tampered["facts"],
        "explanation": tampered["explanation"],
        "policy": tampered["policy"],
    }
    tampered["digest"] = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(tampered))


# ----------------------------------------------------- structural ValueError


def test_report_must_be_dict_with_exact_keys():
    report = decision_attestation(AT, {}, [])
    for bad in (None, [], "x", 42):
        with pytest.raises(ValueError):
            verify_decision_attestation(bad, _expected(report))
    for key in ("at", "facts", "explanation", "policy", "digest"):
        missing = {k: report[k] for k in report if k != key}
        with pytest.raises(ValueError):
            verify_decision_attestation(missing, _expected(report))
    extra = copy.deepcopy(report)
    extra["nope"] = 1
    with pytest.raises(ValueError):
        verify_decision_attestation(extra, _expected(report))


def test_bad_report_at_raises():
    report = decision_attestation(AT, {}, [])
    tampered = copy.deepcopy(report)
    tampered["at"] = "not-a-time"
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))


def test_bad_facts_raise():
    report = decision_attestation(AT, {}, [])
    for bad_facts in ([], {"": True}, {"k": 1}, {"k": "yes"}, {1: True}):
        tampered = copy.deepcopy(report)
        tampered["facts"] = bad_facts
        with pytest.raises(ValueError):
            verify_decision_attestation(tampered, _expected(report))


def test_bad_digest_format_raises():
    report = decision_attestation(AT, {}, [])
    for bad in ("", "a" * 63, "A" * 64, "g" * 64, 123, None):
        tampered = copy.deepcopy(report)
        tampered["digest"] = bad
        with pytest.raises(ValueError):
            verify_decision_attestation(tampered, _expected(report))


def test_explanation_structure_violations_raise():
    report = decision_attestation(AT, {}, _conflicting_rules())
    base = copy.deepcopy(report)

    def with_explanation(**changes):
        tampered = copy.deepcopy(base)
        tampered["explanation"].update(changes)
        return tampered

    for key in ("at", "decision", "trace", "basis", "conflicts"):
        tampered = copy.deepcopy(base)
        del tampered["explanation"][key]
        with pytest.raises(ValueError):
            verify_decision_attestation(tampered, _expected(base))
    tampered = with_explanation(at="not-a-time")
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(base))
    tampered = with_explanation(decision=7)
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(base))
    tampered = with_explanation(trace=["nope"])
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(base))
    tampered = with_explanation(trace="win@1")
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(base))
    tampered = with_explanation(basis={"id": "win"})
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(base))
    tampered = with_explanation(conflicts=[{"winner": ["law", "win", 1]}])
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(base))


def test_policy_structure_violations_raise():
    report = decision_attestation(AT, {}, _conflicting_rules())
    for key in ("at", "rules", "conflicts"):
        tampered = copy.deepcopy(report)
        del tampered["policy"][key]
        with pytest.raises(ValueError):
            verify_decision_attestation(tampered, _expected(report))
    tampered = copy.deepcopy(report)
    tampered["policy"]["at"] = "not-a-time"
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))
    tampered = copy.deepcopy(report)
    tampered["policy"]["rules"] = [{"id": "x"}]
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))
    tampered = copy.deepcopy(report)
    tampered["policy"]["rules"][0]["ver"] = 0
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))
    tampered = copy.deepcopy(report)
    tampered["policy"]["conflicts"] = [{"winner": ["law", "win", 1], "loser": ["court", "x", 1]}]
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))


# ------------------------------------------------------- semantic ValueError


def test_policy_at_must_equal_report_at():
    report = decision_attestation(AT, {}, [_rule()])
    tampered = copy.deepcopy(report)
    tampered["policy"]["at"] = OTHER
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))


def test_explanation_at_must_equal_report_at():
    report = decision_attestation(AT, {}, [_rule()])
    tampered = copy.deepcopy(report)
    tampered["explanation"]["at"] = OTHER
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))


def test_rule_not_effective_raises():
    report = decision_attestation(AT, {}, [_rule()])
    tampered = copy.deepcopy(report)
    tampered["policy"]["rules"][0]["from"] = "2025-01-01T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))
    tampered = copy.deepcopy(report)
    tampered["policy"]["rules"][0]["to"] = "2020-06-01T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))


def test_duplicate_source_id_raises():
    report = decision_attestation(AT, {}, _conflicting_rules())
    tampered = copy.deepcopy(report)
    duplicate = copy.deepcopy(tampered["policy"]["rules"][0])
    duplicate["ver"] = 2
    tampered["policy"]["rules"].append(duplicate)
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))


def test_misordered_rules_raise():
    report = decision_attestation(AT, {}, _conflicting_rules())
    tampered = copy.deepcopy(report)
    rules = tampered["policy"]["rules"]
    rules[0], rules[1] = rules[1], rules[0]
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))


def test_conflict_missing_forged_duplicated_raise():
    report = decision_attestation(AT, {}, _conflicting_rules())

    tampered = copy.deepcopy(report)
    tampered["policy"]["conflicts"] = []
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))

    tampered = copy.deepcopy(report)
    tampered["policy"]["conflicts"].append(
        {"winner": ["law", "loser", 1], "loser": ["law", "tie", 1]}
    )
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))

    tampered = copy.deepcopy(report)
    conflicts = tampered["policy"]["conflicts"]
    conflicts.append(copy.deepcopy(conflicts[0]))
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))


def test_explanation_semantic_mismatches_raise():
    report = decision_attestation(AT, {}, _conflicting_rules())

    tampered = copy.deepcopy(report)
    tampered["explanation"]["decision"] = "deny"
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))

    tampered = copy.deepcopy(report)
    tampered["explanation"]["trace"] = []
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))

    tampered = copy.deepcopy(report)
    tampered["explanation"]["trace"] = ["loser@1", "win@1", "tie@1"]
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))

    tampered = copy.deepcopy(report)
    tampered["explanation"]["basis"]["priority"] = 1
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))

    tampered = copy.deepcopy(report)
    tampered["explanation"]["conflicts"] = []
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))

    tampered = copy.deepcopy(report)
    tampered["explanation"]["conflicts"].append(
        {"winner": ["law", "loser", 1], "loser": ["law", "tie", 1]}
    )
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))


def test_no_match_explanation_must_be_empty():
    report = decision_attestation(AT, {"a": True}, [_rule(when={"a": False})])
    assert report["explanation"]["decision"] is None
    tampered = copy.deepcopy(report)
    tampered["explanation"]["decision"] = "allow"
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))
    tampered = copy.deepcopy(report)
    tampered["explanation"]["trace"] = ["r1@1"]
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))
    tampered = copy.deepcopy(report)
    tampered["explanation"]["basis"] = report["policy"]["rules"][0]
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, _expected(report))


# ------------------------------------------------------------- expected shape


def test_expected_must_be_dict_with_exact_keys():
    report = decision_attestation(AT, {}, [])
    for bad in (None, [], 42):
        with pytest.raises(ValueError):
            verify_decision_attestation(report, bad)
    for key in ("at", "digest"):
        with pytest.raises(ValueError):
            verify_decision_attestation(
                report, {k: v for k, v in _expected(report).items() if k != key}
            )
    with pytest.raises(ValueError):
        verify_decision_attestation(
            report, {**_expected(report), "extra": 1}
        )
    with pytest.raises(ValueError):
        verify_decision_attestation(
            report, {"at": "bad", "digest": report["digest"]}
        )
    with pytest.raises(ValueError):
        verify_decision_attestation(report, {"at": AT, "digest": "X" * 64})


def test_validation_completes_before_comparison():
    # An invalid report must raise even when expected disagrees too: no
    # short-circuit returning False before the report is fully validated.
    report = decision_attestation(AT, {}, [])
    tampered = copy.deepcopy(report)
    del tampered["facts"]
    with pytest.raises(ValueError):
        verify_decision_attestation(tampered, {"at": OTHER, "digest": "0" * 64})
    # An invalid expected must raise even when it also disagrees on time.
    with pytest.raises(ValueError):
        verify_decision_attestation(report, {"at": OTHER, "nope": 1})


def test_inputs_are_not_mutated():
    report = decision_attestation(AT, {"z": True, "a": False}, _conflicting_rules())
    report_snapshot = copy.deepcopy(report)
    expected = _expected(report)
    expected_snapshot = copy.deepcopy(expected)
    verify_decision_attestation(report, expected)
    assert report == report_snapshot
    assert list(report["facts"]) == list(report_snapshot["facts"])
    assert expected == expected_snapshot


# ---------------------------------------------------------------- endpoint


def test_endpoint_valid_true():
    report = decision_attestation(AT, {"a": True}, _conflicting_rules())
    response = client.post(
        "/explanations/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}


def test_endpoint_valid_false():
    report = decision_attestation(AT, {}, [_rule()])
    response = client.post(
        "/explanations/attest/verify",
        json={"report": report, "expected": {"at": AT, "digest": "0" * 64}},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": False}


def test_endpoint_compact_utf8_no_trailing_newline():
    report = decision_attestation(AT, {}, [_rule(result="允许")])
    response = client.post(
        "/explanations/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    raw = response.content.decode("utf-8")
    assert raw == '{"valid":true}'
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw


def test_endpoint_invalid_bodies_are_422():
    report = decision_attestation(AT, {}, [])
    good = {"report": report, "expected": _expected(report)}
    bad_bodies = [
        b"not json",
        b"[]",
        b"null",
        b'"x"',
        b"{}",
        json.dumps({"report": report}).encode(),
        json.dumps({**good, "extra": 1}).encode(),
    ]
    for raw in bad_bodies:
        response = client.post(
            "/explanations/attest/verify",
            content=raw,
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 422, raw
        assert response.content == json.dumps(
            {"detail": "invalid request"}, separators=(",", ":")
        ).encode("utf-8")


def test_endpoint_validation_failures_are_422():
    report = decision_attestation(AT, {}, _conflicting_rules())

    tampered = copy.deepcopy(report)
    del tampered["facts"]
    cases = [
        {"report": tampered, "expected": _expected(report)},
        {"report": report, "expected": {"at": "bad", "digest": report["digest"]}},
        {"report": report, "expected": {"at": AT}},
    ]
    for payload in cases:
        response = client.post("/explanations/attest/verify", json=payload)
        assert response.status_code == 422, payload
        assert response.json() == {"detail": "invalid request"}


def test_endpoint_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("verify must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    report = decision_attestation(AT, {}, [_rule()])
    response = client.post(
        "/explanations/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
