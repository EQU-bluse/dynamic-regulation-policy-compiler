import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_timeline_attestation,
    verify_decision_timeline_attestation,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
END = "2021-06-01T00:00:00Z"


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


def _rules():
    return [
        _rule(
            id="a",
            priority=5,
            when={"x": True},
            result="allow",
            **{"from": START, "to": "2021-03-01T00:00:00Z"},
        ),
        _rule(
            id="b",
            priority=1,
            when={"y": True},
            result="deny",
            **{"from": "2021-02-01T00:00:00Z", "to": None},
        ),
    ]


def _attest(facts=None, rules=None, start=START, end=END):
    return decision_timeline_attestation(
        start, end, {} if facts is None else facts, rules or []
    )


def _expected(report):
    return {"start": report["start"], "end": report["end"], "digest": report["digest"]}


# ---------------------------------------------------------------- function


def test_verifies_genuine_reports():
    assert verify_decision_timeline_attestation(_attest(), _expected(_attest())) is True
    report = _attest({"x": True, "y": True}, _rules())
    assert verify_decision_timeline_attestation(report, _expected(report)) is True


def test_verifies_report_whose_timeline_is_filtered():
    incompatible = [
        _rule(
            id="a",
            priority=5,
            when={"x": True},
            result="allow",
            **{"from": START, "to": "2021-03-01T00:00:00Z"},
        ),
        _rule(
            id="b",
            priority=1,
            when={"x": False},
            result="deny",
            **{"from": "2021-02-01T00:00:00Z", "to": None},
        ),
    ]
    report = _attest({"x": True}, incompatible)
    assert [point["at"] for point in report["timeline"]["points"]] == [
        START,
        "2021-03-01T00:00:00Z",
    ]
    assert verify_decision_timeline_attestation(report, _expected(report)) is True


def test_verifies_empty_report():
    report = _attest()
    assert verify_decision_timeline_attestation(report, _expected(report)) is True


def test_declared_digest_tampering_returns_false():
    report = _attest({"x": True}, _rules())
    report["digest"] = "f" * 64
    assert verify_decision_timeline_attestation(report, _expected(report)) is False


def test_broken_policy_hash_chain_returns_false():
    report = _attest({"x": True}, _rules())
    report["policy"]["points"][0]["digest"] = "0" * 64
    assert verify_decision_timeline_attestation(report, _expected(report)) is False


def test_broken_policy_root_returns_false():
    report = _attest({"x": True}, _rules())
    report["policy"]["root"] = "0" * 64
    assert verify_decision_timeline_attestation(report, _expected(report)) is False


def test_expected_mismatches_return_false():
    report = _attest({"x": True}, _rules())

    expected = _expected(report)
    expected["digest"] = "0" * 64
    assert verify_decision_timeline_attestation(report, expected) is False

    expected = _expected(report)
    expected["start"] = "2020-12-31T00:00:00Z"
    assert verify_decision_timeline_attestation(report, expected) is False

    expected = _expected(report)
    expected["end"] = "2021-06-02T00:00:00Z"
    assert verify_decision_timeline_attestation(report, expected) is False


def test_recomputed_digest_ignores_input_key_order():
    report = _attest({"x": True, "y": True}, _rules())
    scrambled = {
        "digest": report["digest"],
        "policy": dict(reversed(list(report["policy"].items()))),
        "timeline": dict(reversed(list(report["timeline"].items()))),
        "facts": {"y": True, "x": True},
        "end": report["end"],
        "start": report["start"],
    }
    assert verify_decision_timeline_attestation(scrambled, _expected(report)) is True


def test_self_consistent_forgery_fails_against_authentic_expected():
    # Forge an extra fact and re-seal every digest: structure and chain are
    # self-consistent, but it must fail against the authentic outer digest.
    report = _attest({"x": True}, _rules())
    authentic = report["digest"]
    report["facts"]["extra"] = False
    payload = {
        key: report[key]
        for key in ("start", "end", "facts", "timeline", "policy")
    }
    report["digest"] = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    expected = {"start": START, "end": END, "digest": authentic}
    assert verify_decision_timeline_attestation(report, expected) is False


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.pop("digest"),
        lambda r: r.pop("policy"),
        lambda r: r.update(extra=1),
        lambda r: r.update(start="not-a-time"),
        lambda r: r.update(end="not-a-time"),
        lambda r: r.update(facts={"x": 1}),
        lambda r: r.update(facts={"": True}),
        lambda r: r.update(facts=[]),
        lambda r: r.update(digest="F" * 64),
        lambda r: r.update(digest="0" * 63),
        lambda r: r.update(timeline=[]),
        lambda r: r.update(policy=[]),
    ],
)
def test_bad_report_shapes_raise_value_error(mutate):
    report = _attest({"x": True}, _rules())
    mutate(report)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            report,
            {"start": START, "end": END, "digest": "0" * 64},
        )


def test_non_dict_report_raises_value_error():
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            [], {"start": START, "end": END, "digest": "0" * 64}
        )


def test_bad_timeline_structures_raise_value_error():
    report = _attest({"x": True, "y": True}, _rules())

    bad = copy.deepcopy(report)
    bad["timeline"]["start"] = "2020-12-31T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    bad["timeline"]["points"] = []
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    first = bad["timeline"]["points"][0]
    first["at"] = "2021-01-02T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    bad["timeline"]["points"][0].pop("changes")
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    bad["timeline"]["points"][0]["changes"] = ["bogus"]
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    bad["timeline"]["points"][0]["decision"] = 5
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    bad["timeline"]["points"][0]["trace"] = "a@1"
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(bad, _expected(report))

    # Strictly increasing order is required.
    if len(report["timeline"]["points"]) > 1:
        bad = copy.deepcopy(report)
        bad["timeline"]["points"].reverse()
        with pytest.raises(ValueError):
            verify_decision_timeline_attestation(bad, _expected(report))


def test_forged_timeline_semantics_raise_value_error():
    report = _attest({"x": True, "y": True}, _rules())

    bad = copy.deepcopy(report)
    bad["timeline"]["points"][0]["decision"] = "forged"
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(bad, _expected(report))

    # Drop a real timeline point: the rebuild no longer matches.
    bad = copy.deepcopy(report)
    if len(bad["timeline"]["points"]) > 1:
        bad["timeline"]["points"].pop()
        with pytest.raises(ValueError):
            verify_decision_timeline_attestation(bad, _expected(report))

    # Fabricate an extra point: rebuild has no such point.
    bad = copy.deepcopy(report)
    forged = copy.deepcopy(bad["timeline"]["points"][-1])
    forged["at"] = "2021-05-01T00:00:00Z"
    forged["changes"] = ["decision"]
    bad["timeline"]["points"].append(forged)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(bad, _expected(report))


def test_bad_policy_semantics_raise_value_error():
    report = _attest({"x": True}, _rules())

    bad = copy.deepcopy(report)
    bad["policy"]["start"] = "2020-12-31T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    # The first point contains only one effective rule; tamper with a later
    # point whose rules are strictly ranked (a before b).
    later_rules = bad["policy"]["points"][1]["rules"]
    assert len(later_rules) > 1
    later_rules.reverse()
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(bad, _expected(report))

    bad = copy.deepcopy(report)
    del bad["policy"]["points"][-1]["delta"]
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(bad, _expected(report))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.clear(),
        lambda e: e.update(extra=1),
        lambda e: e.pop("digest"),
        lambda e: e.update(start="bad"),
        lambda e: e.update(end="bad"),
        lambda e: e.update(digest="X" * 64),
        lambda e: e.update(digest=123),
        lambda e: e.update(start=END, end=START),
    ],
)
def test_bad_expected_shapes_raise_value_error(mutate):
    report = _attest()
    expected = _expected(report)
    mutate(expected)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(report, expected)


def test_structure_validated_before_value_comparison():
    # Invalid report raises even though expected matches the declared values.
    report = _attest()
    expected = _expected(report)
    report["facts"] = {"x": 1}
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(report, expected)


def test_does_not_mutate_inputs():
    report = _attest({"x": True, "y": True}, _rules())
    scrambled = {
        "digest": report["digest"],
        "policy": dict(reversed(list(report["policy"].items()))),
        "timeline": dict(reversed(list(report["timeline"].items()))),
        "facts": {"y": True, "x": True},
        "end": report["end"],
        "start": report["start"],
    }
    expected = _expected(report)
    report_before = copy.deepcopy(scrambled)
    expected_before = copy.deepcopy(expected)
    assert verify_decision_timeline_attestation(scrambled, expected) is True
    assert scrambled == report_before
    assert expected == expected_before


# ---------------------------------------------------------------- endpoint


def test_http_valid_report_is_200_compact_json(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    report = _attest({"x": True}, _rules())
    response = client.post(
        "/decision-timeline/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
    raw = response.content.decode("utf-8")
    assert raw == json.dumps({"valid": True}, separators=(",", ":"))
    assert not raw.endswith("\n")


def test_http_tampered_report_is_200_false(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    report = _attest({"x": True}, _rules())
    report["digest"] = "f" * 64
    response = client.post(
        "/decision-timeline/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": False}


def test_http_broken_chain_is_200_false(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    report = _attest({"x": True}, _rules())
    report["policy"]["root"] = "0" * 64
    response = client.post(
        "/decision-timeline/attest/verify",
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
        "/decision-timeline/attest/verify",
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
        "/decision-timeline/attest/verify",
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
    report = _attest(rules=_rules())
    response = client.post(
        "/decision-timeline/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
