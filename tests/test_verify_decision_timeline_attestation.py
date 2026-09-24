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
            **{"from": "2021-01-01T00:00:00Z"},
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


def _attest(facts=None, rules=None, start=START, end=END):
    return decision_timeline_attestation(
        start, end, {} if facts is None else facts, rules or []
    )


def _expected(report):
    return {"start": report["start"], "end": report["end"], "digest": report["digest"]}


def _rehash(report):
    payload = {
        key: report[key]
        for key in ("start", "end", "facts", "timeline", "policy")
    }
    report["digest"] = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return report


# ---------------------------------------------------------------- function


def test_verifies_genuine_reports():
    assert verify_decision_timeline_attestation(_attest(), _expected(_attest())) is True
    report = _attest({"x": True}, _changing_rules())
    assert verify_decision_timeline_attestation(report, _expected(report)) is True


def test_verifies_when_timeline_is_filtered_subset_of_schedule():
    # The schedule keeps policy-only changes; the timeline drops the points
    # where no decision field changed. Verification rebuilds the full
    # timeline from the policy snapshots and must still accept the subset.
    rules = [
        _rule(id="base", result="allow"),
        _rule(
            id="gated",
            when={"x": True},
            result="allow",
            **{"from": MID, "to": "2021-03-01T00:00:00Z"},
        ),
    ]
    report = _attest({}, rules)
    assert len(report["timeline"]["points"]) == 1
    assert len(report["policy"]["points"]) == 3
    assert verify_decision_timeline_attestation(report, _expected(report)) is True


def test_declared_digest_tampering_returns_false():
    report = _attest({"k": True}, [_rule()])
    report["digest"] = "f" * 64
    assert verify_decision_timeline_attestation(report, _expected(report)) is False


def test_expected_digest_mismatch_returns_false():
    report = _attest()
    expected = _expected(report)
    expected["digest"] = "0" * 64
    assert verify_decision_timeline_attestation(report, expected) is False


def test_expected_time_mismatch_returns_false():
    report = _attest()
    expected = _expected(report)
    expected["start"] = "2020-12-31T00:00:00Z"
    assert verify_decision_timeline_attestation(report, expected) is False
    expected = _expected(report)
    expected["end"] = "2021-06-03T00:00:00Z"
    assert verify_decision_timeline_attestation(report, expected) is False


def test_fully_recomputed_forgery_fails_against_authentic_expected():
    report = _attest({"k": True}, [_rule(when=None)])
    authentic = report["digest"]
    report["facts"]["extra"] = False
    _rehash(report)
    expected = {
        "start": report["start"],
        "end": report["end"],
        "digest": authentic,
    }
    assert verify_decision_timeline_attestation(report, expected) is False


def test_broken_policy_chain_returns_false_even_with_rehashed_digest():
    report = _attest({"x": True}, _changing_rules())
    assert len(report["policy"]["points"]) > 1
    report["policy"]["points"][0]["digest"] = "f" * 64
    report["policy"]["points"][1]["previous"] = "f" * 64
    report["policy"]["root"] = "f" * 64
    _rehash(report)
    assert (
        verify_decision_timeline_attestation(
            report,
            {"start": report["start"], "end": report["end"], "digest": report["digest"]},
        )
        is False
    )


def test_policy_root_mismatch_returns_false():
    report = _attest({"x": True}, _changing_rules())
    report["policy"]["root"] = "f" * 64
    _rehash(report)
    assert (
        verify_decision_timeline_attestation(
            report,
            {"start": report["start"], "end": report["end"], "digest": report["digest"]},
        )
        is False
    )


def test_recomputed_digest_ignores_input_key_order():
    report = _attest({"x": True}, _changing_rules())
    scrambled = {
        "digest": report["digest"],
        "policy": dict(reversed(list(report["policy"].items()))),
        "timeline": dict(reversed(list(report["timeline"].items()))),
        "facts": {"x": True},
        "end": report["end"],
        "start": report["start"],
    }
    assert verify_decision_timeline_attestation(
        scrambled, _expected(report)
    ) is True


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.pop("digest"),
        lambda r: r.update(extra=1),
        lambda r: r.update(start="not-a-time"),
        lambda r: r.update(end="not-a-time"),
        lambda r: r.update(end="2020-01-01T00:00:00Z"),
        lambda r: r.update(facts={"x": 1}),
        lambda r: r.update(facts=[]),
        lambda r: r.update(digest="F" * 64),
        lambda r: r.update(digest="0" * 63),
        lambda r: r.update(policy=[]),
        lambda r: r.update(timeline=[]),
    ],
)
def test_bad_report_shapes_raise_value_error(mutate):
    report = _attest({"k": True}, [_rule()])
    mutate(report)
    authentic = _attest({"k": True}, [_rule()])
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(report, _expected(authentic))


def test_non_dict_report_raises_value_error():
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            [], {"start": START, "end": END, "digest": "0" * 64}
        )


def test_policy_window_mismatch_raises_value_error():
    report = _attest()
    report["policy"]["start"] = "2020-12-31T00:00:00Z"
    report["policy"]["points"][0]["at"] = "2020-12-31T00:00:00Z"
    _rehash(report)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            report,
            {"start": report["start"], "end": report["end"], "digest": report["digest"]},
        )


def test_policy_snapshot_forgery_raises_value_error():
    report = _attest({"x": True}, _changing_rules())
    # Reorder the policy rules at a point where both rules are effective: the
    # schedule semantic checks reject it before any timeline comparison.
    target = next(
        p for p in report["policy"]["points"] if len(p["rules"]) > 1
    )
    bad = copy.deepcopy(report)
    point = next(p for p in bad["policy"]["points"] if p["at"] == target["at"])
    point["rules"].reverse()
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            bad,
            {"start": bad["start"], "end": bad["end"], "digest": bad["digest"]},
        )


def test_timeline_window_mismatch_raises_value_error():
    report = _attest()
    report["timeline"]["end"] = "2021-06-02T00:00:00Z"
    _rehash(report)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            report,
            {"start": report["start"], "end": report["end"], "digest": report["digest"]},
        )


def test_timeline_point_order_and_shape_raise_value_error():
    report = _attest({"x": True}, _changing_rules())
    assert len(report["timeline"]["points"]) > 1

    bad = copy.deepcopy(report)
    bad["timeline"]["points"].reverse()
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            bad,
            {"start": bad["start"], "end": bad["end"], "digest": bad["digest"]},
        )

    bad = copy.deepcopy(report)
    bad["timeline"]["points"][0]["at"] = MID
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            bad,
            {"start": bad["start"], "end": bad["end"], "digest": bad["digest"]},
        )

    bad = copy.deepcopy(report)
    bad["timeline"]["points"][0].update(extra=1)
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            bad,
            {"start": bad["start"], "end": bad["end"], "digest": bad["digest"]},
        )

    bad = copy.deepcopy(report)
    bad["timeline"]["points"][0]["changes"] = ["decision"]
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            bad,
            {"start": bad["start"], "end": bad["end"], "digest": bad["digest"]},
        )

    bad = copy.deepcopy(report)
    bad["timeline"]["points"][1]["changes"] = ["decision", "decision"]
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            bad,
            {"start": bad["start"], "end": bad["end"], "digest": bad["digest"]},
        )

    bad = copy.deepcopy(report)
    bad["timeline"]["points"][1]["changes"] = ["nope"]
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            bad,
            {"start": bad["start"], "end": bad["end"], "digest": bad["digest"]},
        )


def test_timeline_explanation_forgery_raises_value_error():
    report = _attest({"x": True}, _changing_rules())
    bad = copy.deepcopy(report)
    bad["timeline"]["points"][0]["decision"] = "forged"
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            bad,
            {"start": bad["start"], "end": bad["end"], "digest": bad["digest"]},
        )


def test_missing_timeline_point_raises_value_error():
    report = _attest({"x": True}, _changing_rules())
    assert len(report["timeline"]["points"]) > 1
    bad = copy.deepcopy(report)
    bad["timeline"]["points"].pop()
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            bad,
            {"start": bad["start"], "end": bad["end"], "digest": bad["digest"]},
        )


def test_extra_timeline_point_raises_value_error():
    report = _attest({"x": True}, _changing_rules())
    bad = copy.deepcopy(report)
    first = copy.deepcopy(bad["timeline"]["points"][0])
    first["at"] = MID
    first["changes"] = ["decision"]
    bad["timeline"]["points"].append(first)
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            bad,
            {"start": bad["start"], "end": bad["end"], "digest": bad["digest"]},
        )


def test_changes_mismatch_raises_value_error():
    report = _attest({"x": True}, _changing_rules())
    target = next(p for p in report["timeline"]["points"] if p["changes"])
    bad = copy.deepcopy(report)
    point = next(p for p in bad["timeline"]["points"] if p["at"] == target["at"])
    point["changes"] = []
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(
            bad,
            {"start": bad["start"], "end": bad["end"], "digest": bad["digest"]},
        )


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
        lambda e: e.update(root="x"),
    ],
)
def test_bad_expected_shapes_raise_value_error(mutate):
    report = _attest()
    expected = _expected(report)
    mutate(expected)
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(report, expected)


def test_structure_validated_before_value_comparison():
    report = _attest()
    expected = _expected(report)
    report["facts"] = {"x": 1}
    with pytest.raises(ValueError):
        verify_decision_timeline_attestation(report, expected)


def test_does_not_mutate_inputs():
    report = _attest({"x": True}, _changing_rules())
    scrambled = {
        "digest": report["digest"],
        "policy": dict(reversed(list(report["policy"].items()))),
        "timeline": dict(reversed(list(report["timeline"].items()))),
        "facts": {"x": True},
        "end": report["end"],
        "start": report["start"],
    }
    expected = _expected(report)
    report_before = copy.deepcopy(scrambled)
    expected_before = copy.deepcopy(expected)
    assert verify_decision_timeline_attestation(scrambled, expected) is True
    assert scrambled == report_before
    assert expected == expected_before
    assert report == _attest({"x": True}, _changing_rules())


# ---------------------------------------------------------------- endpoint


def test_http_valid_report_is_200_compact_json(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    report = _attest({"a": True}, [_rule(when={"a": True})])
    response = client.post(
        "/decision-timeline/attest/verify",
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
    report = _attest(rules=[_rule()])
    response = client.post(
        "/decision-timeline/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
