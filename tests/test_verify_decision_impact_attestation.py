import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_impact_attestation,
    verify_decision_impact_attestation,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"


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


def _changing_rules():
    return [
        _rule(
            id="a",
            priority=5,
            **{"from": START},
            when={"x": True},
            result="允许",
        ),
        _rule(
            id="b",
            priority=1,
            **{"from": MID, "to": "2021-03-01T00:00:00Z"},
            result="deny",
        ),
    ]


def _attest(cases=None, rules=None, from_at=START, to_at=END):
    return decision_impact_attestation(
        from_at, to_at, [] if cases is None else cases, rules or []
    )


def _expected(report):
    return {"from": report["from"], "to": report["to"], "digest": report["digest"]}


def _rehash(report):
    payload = {
        key: report[key] for key in ("from", "to", "cases", "policy", "impact")
    }
    report["digest"] = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return report


# ---------------------------------------------------------------- function


def test_verifies_genuine_reports():
    assert verify_decision_impact_attestation(_attest(), _expected(_attest())) is True
    report = _attest([{"id": "c", "facts": {"x": True}}], _changing_rules(), to_at=MID)
    assert verify_decision_impact_attestation(report, _expected(report)) is True
    # A genuinely empty delta across the window is legal and verifies.
    report = _attest([{"id": "c", "facts": {"x": True}}], _changing_rules())
    assert report["policy"]["delta"]["rules"] == []
    assert verify_decision_impact_attestation(report, _expected(report)) is True


def test_verifies_with_multiple_cases_and_sorted_fact_keys():
    cases = [
        {"id": "c2", "facts": {"z": False, "a": True}},
        {"id": "c1", "facts": {"x": True}},
    ]
    report = _attest(cases, _changing_rules(), to_at=MID)
    assert [case["id"] for case in report["cases"]] == ["c1", "c2"]
    assert verify_decision_impact_attestation(report, _expected(report)) is True


def test_declared_digest_tampering_returns_false():
    report = _attest([{"id": "c", "facts": {}}], [_rule()])
    report["digest"] = "f" * 64
    assert verify_decision_impact_attestation(report, _expected(report)) is False


def test_expected_digest_mismatch_returns_false():
    report = _attest()
    expected = _expected(report)
    expected["digest"] = "0" * 64
    assert verify_decision_impact_attestation(report, expected) is False


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.update({"from": "2020-12-31T00:00:00Z"}),
        lambda e: e.update(to="2021-06-03T00:00:00Z"),
    ],
)
def test_expected_time_mismatch_returns_false(mutate):
    report = _attest()
    expected = _expected(report)
    mutate(expected)
    assert verify_decision_impact_attestation(report, expected) is False


def test_irrelevant_fact_forgery_rehashed_fails_against_authentic_expected():
    # An added fact that changes no decision keeps the rebuilt impact equal,
    # so this must surface as a digest mismatch (False), not an exception.
    report = _attest([{"id": "c", "facts": {"x": True}}], [_rule(when={"x": True})])
    authentic = report["digest"]
    report["cases"][0]["facts"]["extra"] = False
    _rehash(report)
    expected = {"from": report["from"], "to": report["to"], "digest": authentic}
    assert verify_decision_impact_attestation(report, expected) is False


def test_semantic_fact_forgery_raises_value_error():
    # Flipping a fact changes the decision; with the impact left untouched the
    # rebuilt explanations no longer match.
    report = _attest([{"id": "c", "facts": {"x": True}}], _changing_rules(), to_at=MID)
    report["cases"][0]["facts"]["x"] = False
    _rehash(report)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(report, _expected(report))


def test_policy_delta_forgery_raises_value_error():
    report = _attest([{"id": "c", "facts": {"x": True}}], _changing_rules(), to_at=MID)
    assert report["policy"]["delta"]["rules"]
    bad = copy.deepcopy(report)
    bad["policy"]["delta"]["rules"] = []
    bad["impact"]["policy"]["rules"] = []
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_policy_delta_conflict_forgery_raises_value_error():
    report = _attest([{"id": "c", "facts": {"x": True}}], _changing_rules(), to_at=MID)
    assert report["policy"]["delta"]["conflicts"]["added"]
    bad = copy.deepcopy(report)
    bad["policy"]["delta"]["conflicts"]["added"] = []
    bad["impact"]["policy"]["conflicts"]["added"] = []
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_snapshot_rule_reordering_raises_value_error():
    report = _attest([{"id": "c", "facts": {"x": True}}], _changing_rules(), to_at=MID)
    assert len(report["policy"]["after"]["rules"]) > 1
    bad = copy.deepcopy(report)
    bad["policy"]["after"]["rules"].reverse()
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_snapshot_conflict_forgery_raises_value_error():
    report = _attest([{"id": "c", "facts": {}}], _changing_rules())
    assert not report["policy"]["before"]["conflicts"]
    bad = copy.deepcopy(report)
    bad["policy"]["before"]["conflicts"].append(
        {"winner": ["law", "a", 1], "loser": ["law", "b", 1]}
    )
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_extra_effective_rule_in_snapshot_raises_value_error():
    # Structurally valid snapshot (the forged rule is effective and ranked
    # last), but the delta rebuilt from the snapshots no longer agrees.
    report = _attest([{"id": "c", "facts": {}}], [_rule()])
    bad = copy.deepcopy(report)
    bad["policy"]["before"]["rules"].append(
        {
            "id": "z",
            "ver": 1,
            "source": "org",
            "priority": -1,
            "from": "2020-01-01T00:00:00Z",
            "to": None,
            "when": None,
            "result": "other",
        }
    )
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_impact_explanation_forgery_raises_value_error():
    report = _attest([{"id": "c", "facts": {"x": True}}], _changing_rules(), to_at=MID)
    bad = copy.deepcopy(report)
    bad["impact"]["cases"][0]["before"]["decision"] = "forged"
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_impact_trace_forgery_raises_value_error():
    report = _attest([{"id": "c", "facts": {"x": True}}], _changing_rules(), to_at=MID)
    bad = copy.deepcopy(report)
    bad["impact"]["cases"][0]["before"]["trace"].append("z@9")
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_impact_changes_content_forgery_raises_value_error():
    report = _attest([{"id": "c", "facts": {"x": True}}], _changing_rules(), to_at=MID)
    changed = next(c for c in report["impact"]["cases"] if c["changes"])
    assert changed["changes"]
    bad = copy.deepcopy(report)
    bad["impact"]["cases"][0]["changes"] = []
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_impact_changes_order_forgery_raises_value_error():
    # At MID rule b starts matching the empty-facts case, so all four fields
    # change; reversing the declared order must be rejected.
    report = _attest([{"id": "c", "facts": {}}], _changing_rules(), to_at=MID)
    changed = next(c for c in report["impact"]["cases"] if c["changes"])
    assert changed["changes"] == ["decision", "trace", "basis", "conflicts"]
    bad = copy.deepcopy(report)
    bad["impact"]["cases"][0]["changes"] = list(
        reversed(bad["impact"]["cases"][0]["changes"])
    )
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_impact_policy_divergence_raises_value_error():
    report = _attest([{"id": "c", "facts": {"x": True}}], _changing_rules(), to_at=MID)
    bad = copy.deepcopy(report)
    bad["impact"]["policy"]["rules"] = []
    bad["impact"]["policy"]["conflicts"]["added"] = []
    bad["impact"]["policy"]["conflicts"]["removed"] = []
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_case_id_misalignment_raises_value_error():
    cases = [{"id": "c2", "facts": {}}, {"id": "c1", "facts": {"x": True}}]
    report = _attest(cases, _changing_rules(), to_at=MID)
    bad = copy.deepcopy(report)
    bad["impact"]["cases"].reverse()
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_recomputed_digest_ignores_input_key_order():
    cases = [{"id": "c2", "facts": {}}, {"id": "c1", "facts": {"x": True}}]
    report = _attest(cases, _changing_rules(), to_at=MID)
    # cases are stored ascending in the report; reverse every dict ordering
    # while keeping the ascending case list.
    scrambled = {
        "digest": report["digest"],
        "impact": dict(reversed(list(report["impact"].items()))),
        "policy": dict(reversed(list(report["policy"].items()))),
        "cases": [
            {"facts": case["facts"], "id": case["id"]} for case in report["cases"]
        ],
        "to": report["to"],
        "from": report["from"],
    }
    assert verify_decision_impact_attestation(scrambled, _expected(report)) is True


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.pop("digest"),
        lambda r: r.update(extra=1),
        lambda r: r.update({"from": "not-a-time"}),
        lambda r: r.update(to="not-a-time"),
        lambda r: r.update(to="2020-01-01T00:00:00Z"),
        lambda r: r.update(digest="F" * 64),
        lambda r: r.update(digest="0" * 63),
        lambda r: r.update(digest=123),
        lambda r: r.update(cases={}),
        lambda r: r.update(policy=[]),
        lambda r: r.update(impact=[]),
        lambda r: r.update(cases=[{"id": "a", "facts": {}},
                                  {"id": "a", "facts": {}}]),
        lambda r: r.update(cases=[{"id": "b", "facts": {}},
                                  {"id": "a", "facts": {}}]),
        lambda r: r.update(cases=[{"id": "", "facts": {}}]),
        lambda r: r.update(cases=[{"id": "a", "facts": {"x": 1}}]),
        lambda r: r.update(cases=[{"facts": {}}]),
    ],
)
def test_bad_report_shapes_raise_value_error(mutate):
    report = _attest(
        [{"id": "a", "facts": {}}, {"id": "b", "facts": {"k": True}}], [_rule()]
    )
    mutate(report)
    authentic = _attest(
        [{"id": "a", "facts": {}}, {"id": "b", "facts": {"k": True}}], [_rule()]
    )
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(report, _expected(authentic))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.clear(),
        lambda p: p.update(extra=1),
        lambda p: p.pop("delta"),
        lambda p: p.update(before=[]),
        lambda p: p.update(after=[]),
        lambda p: p.update(delta=[]),
    ],
)
def test_bad_policy_shapes_raise_value_error(mutate):
    report = _attest([{"id": "a", "facts": {}}], [_rule()])
    mutate(report["policy"])
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(report, _expected(report))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda i: i.clear(),
        lambda i: i.update(extra=1),
        lambda i: i.pop("cases"),
        lambda i: i.update(policy=[]),
        lambda i: i.update(cases=[]),
    ],
)
def test_bad_impact_shapes_raise_value_error(mutate):
    report = _attest([{"id": "a", "facts": {}}], [_rule()])
    mutate(report["impact"])
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(report, _expected(report))


def test_impact_case_shape_errors_raise_value_error():
    report = _attest([{"id": "a", "facts": {}}], [_rule()])
    bad = copy.deepcopy(report)
    bad["impact"]["cases"][0].update(extra=1)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))
    bad = copy.deepcopy(report)
    bad["impact"]["cases"][0]["changes"] = ["nope"]
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))
    bad = copy.deepcopy(report)
    bad["impact"]["cases"][0]["changes"] = ["decision", "decision"]
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))
    bad = copy.deepcopy(report)
    bad["impact"]["cases"][0]["before"]["at"] = MID
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))
    bad = copy.deepcopy(report)
    bad["impact"]["cases"].append(copy.deepcopy(bad["impact"]["cases"][0]))
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_snapshot_window_mismatch_raises_value_error():
    report = _attest()
    report["policy"]["before"]["at"] = "2020-12-31T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(report, _expected(report))


def test_delta_window_mismatch_raises_value_error():
    report = _attest([{"id": "c", "facts": {"x": True}}], _changing_rules(), to_at=MID)
    bad = copy.deepcopy(report)
    bad["policy"]["delta"]["from"] = MID
    bad["impact"]["policy"]["from"] = MID
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_impact_window_mismatch_raises_value_error():
    report = _attest()
    report["impact"]["to"] = "2021-06-02T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(report, _expected(report))


def test_non_dict_report_raises_value_error():
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(
            [], {"from": START, "to": END, "digest": "0" * 64}
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.clear(),
        lambda e: e.update(extra=1),
        lambda e: e.pop("digest"),
        lambda e: e.update({"from": "bad"}),
        lambda e: e.update(to="bad"),
        lambda e: e.__setitem__("to", "2020-01-01T00:00:00Z"),
        lambda e: e.update(digest="X" * 64),
        lambda e: e.update(digest=123),
        lambda e: e.update(root="x"),
    ],
)
def test_bad_expected_shapes_raise_value_error(mutate):
    report = _attest()
    expected = _expected(report)
    mutate(expected)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(report, expected)


def test_structure_validated_before_value_comparison():
    # Both inputs are structurally invalid; ValueError must win over the
    # from/digest comparisons (which would otherwise return False).
    report = _attest()
    expected = _expected(report)
    report["cases"] = {"x": 1}
    expected["from"] = "2020-12-31T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(report, expected)


def test_semantic_validation_uses_rebuilt_not_declared_digest():
    # A semantically forged but fully rehashed report still raises ValueError
    # even when expected matches its declared digest.
    report = _attest([{"id": "c", "facts": {"x": True}}], _changing_rules(), to_at=MID)
    bad = copy.deepcopy(report)
    bad["impact"]["cases"][0]["before"]["decision"] = "forged"
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_does_not_mutate_inputs():
    cases = [{"id": "c2", "facts": {}}, {"id": "c1", "facts": {"x": True}}]
    report = _attest(cases, _changing_rules(), to_at=MID)
    scrambled = {
        "digest": report["digest"],
        "impact": dict(reversed(list(report["impact"].items()))),
        "policy": dict(reversed(list(report["policy"].items()))),
        "cases": [
            {"facts": case["facts"], "id": case["id"]} for case in report["cases"]
        ],
        "to": report["to"],
        "from": report["from"],
    }
    expected = _expected(report)
    report_before = copy.deepcopy(scrambled)
    expected_before = copy.deepcopy(expected)
    assert verify_decision_impact_attestation(scrambled, expected) is True
    assert scrambled == report_before
    assert expected == expected_before
    assert report == _attest(cases, _changing_rules(), to_at=MID)


# ---------------------------------------------------------------- endpoint


def test_http_valid_report_is_200_compact_json(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    report = _attest([{"id": "a", "facts": {"x": True}}], [_rule(when={"x": True})])
    response = client.post(
        "/decision-impact/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_tampered_report_is_200_false(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    report = _attest()
    report["digest"] = "f" * 64
    response = client.post(
        "/decision-impact/attest/verify",
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
        "/decision-impact/attest/verify",
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
    report["cases"] = {"x": 1}
    response = client.post(
        "/decision-impact/attest/verify",
        json={"report": report, "expected": _expected(_attest())},
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
        "/decision-impact/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
