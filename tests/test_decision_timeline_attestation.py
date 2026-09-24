import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_timeline,
    decision_timeline_attestation,
    policy_schedule_attestation,
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
            result="允许",
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


def _incompatible_rules():
    # Same boundaries, but b's condition contradicts a's: under x=True the
    # policy schedule still keeps 2021-02-01 (b becomes effective), while the
    # decision timeline drops it (the explanation is unchanged).
    return [
        _rule(
            id="a",
            priority=5,
            when={"x": True},
            result="允许",
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


def _payload(**overrides):
    payload = {"start": START, "end": END, "facts": {}, "rules": []}
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------- function


def test_top_level_key_order_and_value_shapes():
    rules = _rules()
    facts = {"z": False, "a": True, "x": True}
    report = decision_timeline_attestation(START, END, facts, rules)
    assert list(report) == [
        "start",
        "end",
        "facts",
        "timeline",
        "policy",
        "digest",
    ]
    assert report["start"] == START
    assert report["end"] == END
    assert list(report["facts"]) == ["a", "x", "z"]
    assert report["facts"] == facts
    assert report["timeline"] == decision_timeline(START, END, facts, rules)
    assert list(report["timeline"]) == ["start", "end", "points"]
    assert report["policy"] == policy_schedule_attestation(START, END, rules)
    assert list(report["policy"]) == ["start", "end", "root", "points"]
    assert report["policy"]["root"] == report["policy"]["points"][-1]["digest"]


def test_timeline_filters_points_that_do_not_change_decision():
    # With only x=True the second rule never matches: the schedule keeps the
    # 2021-02-01 boundary (b becomes effective) but the decision timeline drops
    # it, so the embedded timeline must be shorter than the policy schedule.
    report = decision_timeline_attestation(
        START, END, {"x": True}, _incompatible_rules()
    )
    timeline_ats = [point["at"] for point in report["timeline"]["points"]]
    schedule_ats = [point["at"] for point in report["policy"]["points"]]
    assert schedule_ats == [
        START,
        "2021-02-01T00:00:00Z",
        "2021-03-01T00:00:00Z",
    ]
    assert timeline_ats == [START, "2021-03-01T00:00:00Z"]
    assert report["timeline"]["points"][0]["changes"] == []
    assert report["timeline"]["points"][1]["changes"] == [
        "decision",
        "trace",
        "basis",
    ]


def test_digest_is_sha256_of_first_five_fields_compact_json():
    report = decision_timeline_attestation(START, END, {"k": True}, _rules())
    payload = {
        key: report[key]
        for key in ("start", "end", "facts", "timeline", "policy")
    }
    expected = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert report["digest"] == expected
    assert len(report["digest"]) == 64
    assert report["digest"] == report["digest"].lower()


def test_input_key_order_does_not_change_byte_output():
    rules = _rules()
    first = decision_timeline_attestation(
        START, END, {"x": True, "z": False}, rules
    )
    second = decision_timeline_attestation(
        START, END, {"z": False, "x": True}, rules
    )
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == (
        json.dumps(second, ensure_ascii=False, separators=(",", ":"))
    )


def test_empty_facts_empty_rules_attest_normally():
    report = decision_timeline_attestation(START, END, {}, [])
    assert report["facts"] == {}
    assert report["timeline"] == {
        "start": START,
        "end": END,
        "points": [
            {
                "at": START,
                "decision": None,
                "trace": [],
                "basis": None,
                "conflicts": [],
                "changes": [],
            }
        ],
    }
    assert report["policy"]["points"][0]["at"] == START
    assert len(report["policy"]["points"]) == 1
    assert len(report["digest"]) == 64


def test_result_branches_do_not_share_mutable_containers():
    facts = {"x": True}
    rules = _rules()
    first = decision_timeline_attestation(START, END, facts, rules)
    second = decision_timeline_attestation(START, END, facts, rules)
    assert first == second
    assert first is not second
    first["facts"]["b"] = False
    first["timeline"]["points"][0]["basis"]["when"]["q"] = False
    first["policy"]["points"][0]["rules"].append("injected")
    assert facts == {"x": True}
    assert second["facts"] == {"x": True}
    assert second["timeline"] == decision_timeline(START, END, facts, rules)
    assert second["policy"] == policy_schedule_attestation(START, END, rules)


def test_inputs_are_not_mutated():
    facts = {"z": True, "a": False, "x": True}
    facts_snapshot = copy.deepcopy(facts)
    rules = _rules()
    rules_snapshot = copy.deepcopy(rules)
    decision_timeline_attestation(START, END, facts, rules)
    assert facts == facts_snapshot
    assert list(facts) == ["z", "a", "x"]
    assert rules == rules_snapshot


@pytest.mark.parametrize(
    "kwargs",
    [
        {"start": "not-a-time", "end": END, "facts": {}, "rules": []},
        {"start": END, "end": START, "facts": {}, "rules": []},
        {"start": START, "end": END, "facts": {"x": 1}, "rules": []},
        {"start": START, "end": END, "facts": [], "rules": []},
        {"start": START, "end": END, "facts": {}, "rules": {}},
        {"start": START, "end": END, "facts": {}, "rules": [_rule(ver=0)]},
        {"start": START, "end": END, "facts": {}, "rules": [_rule(), _rule()]},
        {
            "start": START,
            "end": END,
            "facts": {},
            "rules": [
                _rule(**{"from": "2021-01-01T00:00:00Z", "to": "2020-01-01T00:00:00Z"})
            ],
        },
    ],
)
def test_invalid_inputs_raise_value_error(kwargs):
    with pytest.raises(ValueError):
        decision_timeline_attestation(**kwargs)


# ---------------------------------------------------------------- endpoint


def test_endpoint_success_body():
    response = client.post(
        "/decision-timeline/attest",
        json=_payload(facts={"x": True, "y": True}, rules=_rules()),
    )
    assert response.status_code == 200
    data = response.json()
    assert list(data) == ["start", "end", "facts", "timeline", "policy", "digest"]
    assert list(data["facts"]) == ["x", "y"]
    assert len(data["timeline"]["points"]) == 3
    assert data["policy"]["root"]


def test_endpoint_compact_utf8_no_trailing_newline():
    response = client.post(
        "/decision-timeline/attest",
        json=_payload(facts={"x": True}, rules=_rules()),
    )
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw
    assert "允许" in raw and "\\u" not in raw


def test_endpoint_digest_matches_recomputation():
    response = client.post(
        "/decision-timeline/attest",
        json=_payload(facts={"x": True}, rules=_rules()),
    )
    data = response.json()
    payload = {
        key: data[key] for key in ("start", "end", "facts", "timeline", "policy")
    }
    digest = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert data["digest"] == digest


def test_endpoint_byte_identical_regardless_of_key_order():
    rules = _rules()
    first = client.post(
        "/decision-timeline/attest",
        json=_payload(facts={"x": True}, rules=rules),
    ).content
    second = client.post(
        "/decision-timeline/attest",
        data=json.dumps(
            {
                "rules": rules,
                "end": END,
                "facts": {"x": True},
                "start": START,
            },
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
        json.dumps({"start": START, "end": END, "facts": {}}).encode(),
    ]
    for raw in bad_bodies:
        response = client.post(
            "/decision-timeline/attest",
            content=raw,
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 422, raw
        assert response.content == json.dumps(
            {"detail": "invalid request"}, separators=(",", ":")
        ).encode("utf-8")


def test_endpoint_validation_failures_are_422():
    cases = [
        _payload(start="not-a-time"),
        _payload(start=END, end=START),
        _payload(facts={"x": 1}),
        _payload(facts=[]),
        _payload(rules={}),
        _payload(rules=[_rule(ver=0)]),
        _payload(rules=[_rule(), _rule()]),
    ]
    for payload in cases:
        response = client.post("/decision-timeline/attest", json=payload)
        assert response.status_code == 422, payload
        assert response.json() == {"detail": "invalid request"}


def test_endpoint_empty_inputs_succeed():
    response = client.post("/decision-timeline/attest", json=_payload())
    assert response.status_code == 200
    data = response.json()
    assert data["timeline"]["points"][0]["decision"] is None
    assert len(data["policy"]["points"]) == 1


def test_endpoint_does_not_touch_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("POST /decision-timeline/attest must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/decision-timeline/attest", json=_payload(rules=_rules())
    )
    assert response.status_code == 200


def test_endpoint_works_without_history_configured(monkeypatch):
    import regulation_policy_compiler.app as app_module

    monkeypatch.setattr(app_module, "H", None)
    response = client.post(
        "/decision-timeline/attest", json=_payload(rules=_rules())
    )
    assert response.status_code == 200
