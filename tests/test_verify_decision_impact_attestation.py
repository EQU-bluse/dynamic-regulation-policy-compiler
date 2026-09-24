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
WITHIN = "2021-02-15T00:00:00Z"
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
            source="org",
            priority=1,
            **{"from": MID, "to": "2021-03-01T00:00:00Z"},
            result="deny",
        ),
    ]


def _cases():
    return [{"id": "c2", "facts": {}}, {"id": "c1", "facts": {"x": True}}]


def _attest(frm=START, to=END, cases=None, rules=None):
    return decision_impact_attestation(
        frm, to, _cases() if cases is None else cases, rules or []
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
    report = _attest(rules=_changing_rules())
    assert verify_decision_impact_attestation(report, _expected(report)) is True


def test_verifies_empty_cases():
    report = _attest(cases=[])
    assert verify_decision_impact_attestation(report, _expected(report)) is True


def test_verifies_same_timestamp():
    report = _attest(frm=MID, to=MID, rules=_changing_rules())
    assert verify_decision_impact_attestation(report, _expected(report)) is True
    assert report["policy"]["delta"]["rules"] == []
    assert all(entry["changes"] == [] for entry in report["impact"]["cases"])


def test_declared_digest_tampering_returns_false():
    report = _attest(rules=[_rule()])
    report["digest"] = "f" * 64
    assert verify_decision_impact_attestation(report, _expected(report)) is False


def test_expected_digest_mismatch_returns_false():
    report = _attest()
    expected = _expected(report)
    expected["digest"] = "0" * 64
    assert verify_decision_impact_attestation(report, expected) is False


@pytest.mark.parametrize("field", ["from", "to"])
def test_expected_time_mismatch_returns_false(field):
    report = _attest()
    expected = _expected(report)
    if field == "from":
        expected["from"] = "2020-12-31T00:00:00Z"
    else:
        expected["to"] = "2021-06-03T00:00:00Z"
    assert verify_decision_impact_attestation(report, expected) is False


def test_fully_recomputed_forgery_fails_against_authentic_expected():
    report = _attest(rules=[_rule(when={"x": True})])
    authentic = report["digest"]
    report["cases"][0]["facts"]["extra"] = False
    _rehash(report)
    expected = {"from": report["from"], "to": report["to"], "digest": authentic}
    assert verify_decision_impact_attestation(report, expected) is False


def test_recomputed_digest_ignores_input_key_order():
    report = _attest(rules=_changing_rules())
    scrambled = {
        "digest": report["digest"],
        "impact": dict(reversed(list(report["impact"].items()))),
        "policy": dict(reversed(list(report["policy"].items()))),
        "cases": report["cases"],
        "to": report["to"],
        "from": report["from"],
    }
    assert verify_decision_impact_attestation(scrambled, _expected(report)) is True


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.pop("digest"),
        lambda r: r.update(extra=1),
        lambda r: r.update(**{"from": "not-a-time"}),
        lambda r: r.update(to="not-a-time"),
        lambda r: r.update(**{"from": END, "to": START}),
        lambda r: r.update(cases={}),
        lambda r: r.update(policy=[]),
        lambda r: r.update(impact=[]),
        lambda r: r.update(digest="F" * 64),
        lambda r: r.update(digest="0" * 63),
        lambda r: r.update(digest=123),
    ],
)
def test_bad_report_shapes_raise_value_error(mutate):
    report = _attest()
    mutate(report)
    authentic = _attest()
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(report, _expected(authentic))


def test_non_dict_report_raises_value_error():
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(
            [], {"from": START, "to": END, "digest": "0" * 64}
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.clear(),
        lambda c: c.update(extra=1),
        lambda c: c.update(facts=[]),
        lambda c: c.update(facts={"x": 1}),
        lambda c: c.update(id=""),
        lambda c: c.update(id=123),
    ],
)
def test_bad_case_shapes_raise_value_error(mutate):
    report = _attest(cases=[{"id": "a", "facts": {}}])
    mutate(report["cases"][0])
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(report, _expected(report))


def test_case_ids_must_be_unique_and_strictly_ascending():
    # Forge structurally after attestation; the verifier must reject these
    # during basic structure validation before any semantic rebuild.
    authentic = _attest(cases=[{"id": "a", "facts": {}},
                               {"id": "b", "facts": {}}])

    duplicate = copy.deepcopy(authentic)
    duplicate["cases"][1]["id"] = "a"
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(duplicate, _expected(authentic))

    descending = copy.deepcopy(authentic)
    descending["cases"].reverse()
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(descending, _expected(authentic))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.clear(),
        lambda p: p.update(extra=1),
        lambda p: p.pop("delta"),
    ],
)
def test_bad_policy_shape_raises_value_error(mutate):
    report = _attest(rules=_changing_rules())
    mutate(report["policy"])
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(report, _expected(report))


def test_policy_snapshot_forgery_raises_value_error():
    report = _attest(to=WITHIN, rules=_changing_rules())
    assert len(report["policy"]["after"]["rules"]) > 1
    bad = copy.deepcopy(report)
    bad["policy"]["after"]["rules"].reverse()
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_policy_snapshot_conflict_forgery_raises_value_error():
    # Use an endpoint inside rule b's window so the after snapshot contains
    # the (a, b) conflict.
    within = "2021-02-15T00:00:00Z"
    report = _attest(to=within, rules=_changing_rules())
    assert report["policy"]["after"]["conflicts"]
    bad = copy.deepcopy(report)
    bad["policy"]["after"]["conflicts"] = []
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_snapshot_at_must_equal_endpoint_time():
    report = _attest(rules=_changing_rules())
    bad = copy.deepcopy(report)
    bad["policy"]["after"]["at"] = MID
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_forged_policy_delta_raises_value_error():
    within = "2021-02-15T00:00:00Z"
    report = _attest(to=within, rules=_changing_rules())
    assert report["policy"]["delta"]["rules"]
    bad = copy.deepcopy(report)
    bad["policy"]["delta"]["rules"] = []
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_delta_time_window_mismatch_raises_value_error():
    report = _attest(rules=_changing_rules())
    bad = copy.deepcopy(report)
    bad["policy"]["delta"]["to"] = MID
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_impact_policy_must_match_policy_delta():
    report = _attest(to=WITHIN, rules=_changing_rules())
    assert report["impact"]["policy"]["rules"]
    bad = copy.deepcopy(report)
    bad["impact"]["policy"]["rules"] = []
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_impact_window_mismatch_raises_value_error():
    report = _attest()
    bad = copy.deepcopy(report)
    bad["impact"]["to"] = MID
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_impact_case_forgery_raises_value_error():
    report = _attest(rules=_changing_rules())
    bad = copy.deepcopy(report)
    bad["impact"]["cases"][0]["decision"] = "forged"
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_impact_changes_forgery_raises_value_error():
    report = _attest(to=WITHIN, rules=_changing_rules())
    entry = next(e for e in report["impact"]["cases"] if e["changes"])
    bad = copy.deepcopy(report)
    target = next(e for e in bad["impact"]["cases"] if e["id"] == entry["id"])
    target["changes"] = []
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_impact_changes_duplicate_field_raises_value_error():
    report = _attest(rules=_changing_rules())
    bad = copy.deepcopy(report)
    bad["impact"]["cases"][0]["changes"] = ["decision", "decision"]
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_impact_case_id_pairing_must_match_cases():
    report = _attest(rules=_changing_rules())
    bad = copy.deepcopy(report)
    bad["impact"]["cases"].reverse()
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))

    bad = copy.deepcopy(report)
    bad["impact"]["cases"].pop()
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_extra_impact_case_raises_value_error():
    report = _attest(rules=_changing_rules())
    bad = copy.deepcopy(report)
    bad["impact"]["cases"].append(copy.deepcopy(bad["impact"]["cases"][0]))
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


def test_impact_entry_bad_shape_raises_value_error():
    report = _attest(rules=_changing_rules())
    bad = copy.deepcopy(report)
    bad["impact"]["cases"][0].pop("changes")
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad, _expected(bad))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.clear(),
        lambda e: e.update(extra=1),
        lambda e: e.pop("digest"),
        lambda e: e.update(**{"from": "bad"}),
        lambda e: e.update(to="bad"),
        lambda e: e.update(**{"from": END, "to": START}),
        lambda e: e.update(digest="X" * 64),
        lambda e: e.update(digest=123),
    ],
)
def test_bad_expected_shapes_raise_value_error(mutate):
    report = _attest()
    expected = _expected(report)
    mutate(expected)
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(report, expected)


def test_structure_validated_before_value_comparison():
    # A structurally bad expected must raise even when the report is fine.
    report = _attest()
    expected = _expected(report)
    expected.pop("digest")
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(report, expected)

    # And a structurally bad report must raise rather than return False.
    bad_report = _attest()
    bad_report["cases"] = {"x": True}
    with pytest.raises(ValueError):
        verify_decision_impact_attestation(bad_report, _expected(_attest()))


def test_does_not_mutate_inputs():
    report = _attest(rules=_changing_rules())
    scrambled = {
        "digest": report["digest"],
        "impact": dict(reversed(list(report["impact"].items()))),
        "policy": dict(reversed(list(report["policy"].items()))),
        "cases": copy.deepcopy(report["cases"]),
        "to": report["to"],
        "from": report["from"],
    }
    expected = _expected(report)
    report_before = copy.deepcopy(scrambled)
    expected_before = copy.deepcopy(expected)
    assert verify_decision_impact_attestation(scrambled, expected) is True
    assert scrambled == report_before
    assert expected == expected_before
    assert report == _attest(rules=_changing_rules())


# ---------------------------------------------------------------- endpoint


def test_http_valid_report_is_200_compact_json(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    report = _attest(rules=[_rule(when={"x": True})])
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
    report["cases"] = {"x": True}
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
