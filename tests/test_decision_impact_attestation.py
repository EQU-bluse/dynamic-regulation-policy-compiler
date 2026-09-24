import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    compile_rules,
    decision_impact,
    decision_impact_attestation,
    policy_delta,
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


def _payload(**overrides):
    payload = {"from": START, "to": END, "cases": _cases(), "rules": []}
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------- function


def test_top_level_key_order_and_value_shapes():
    rules = _changing_rules()
    report = _attest(rules=rules)
    assert list(report) == ["from", "to", "cases", "policy", "impact", "digest"]
    assert report["from"] == START
    assert report["to"] == END
    assert [case["id"] for case in report["cases"]] == ["c1", "c2"]
    assert all(list(case) == ["id", "facts"] for case in report["cases"])
    assert list(report["policy"]) == ["before", "after", "delta"]
    assert list(report["impact"]) == ["from", "to", "policy", "cases"]


def test_cases_sorted_with_fact_keys_sorted():
    cases = [
        {"id": "z", "facts": {"y": True, "a": False}},
        {"id": "a", "facts": {}},
    ]
    report = _attest(cases=cases, rules=[_rule()])
    assert [case["id"] for case in report["cases"]] == ["a", "z"]
    assert list(report["cases"][1]["facts"]) == ["a", "y"]


def test_policy_section_matches_snapshots_and_delta():
    rules = _changing_rules()
    report = _attest(rules=rules)
    assert report["policy"]["before"] == compile_rules(START, rules)
    assert report["policy"]["after"] == compile_rules(END, rules)
    assert report["policy"]["delta"] == policy_delta(START, END, rules)
    assert report["impact"] == decision_impact(START, END, _cases(), rules)
    assert report["impact"]["policy"] == report["policy"]["delta"]


def test_empty_cases_is_valid():
    report = _attest(cases=[])
    assert report["cases"] == []
    assert report["impact"]["cases"] == []
    assert len(report["digest"]) == 64


def test_changes_follow_public_compare_semantics():
    rules = _changing_rules()
    report = _attest(to=WITHIN, rules=rules)
    entries = {entry["id"]: entry for entry in report["impact"]["cases"]}
    # c2 has no facts: at MID rule b starts matching, so every comparison
    # field changes relative to the no-match start point.
    assert entries["c2"]["changes"] == ["decision", "trace", "basis", "conflicts"]
    # c1 satisfies rule a throughout: the decision and basis stay, but b's
    # arrival extends the trace and adds a conflict.
    assert entries["c1"]["changes"] == ["trace", "conflicts"]
    assert list(entries["c1"]["before"]) == ["at", "decision", "trace", "basis",
                                             "conflicts"]


def test_digest_is_sha256_of_first_five_fields_compact_json():
    report = _attest(rules=_changing_rules())
    payload = {
        key: report[key]
        for key in ("from", "to", "cases", "policy", "impact")
    }
    expected = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert report["digest"] == expected
    assert report["digest"] == report["digest"].lower()
    assert len(report["digest"]) == 64


def test_input_key_order_does_not_change_byte_output():
    rules = _changing_rules()
    first = decision_impact_attestation(
        START, END, list(reversed(_cases())), list(reversed(rules))
    )
    second = decision_impact_attestation(START, END, _cases(), rules)
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == (
        json.dumps(second, ensure_ascii=False, separators=(",", ":"))
    )


def test_result_branches_do_not_share_mutable_containers():
    rules = _changing_rules()
    cases = _cases()
    first = decision_impact_attestation(START, END, cases, rules)
    second = decision_impact_attestation(START, END, cases, rules)
    assert first == second
    assert first is not second
    first["cases"][0]["facts"]["injected"] = True
    first["policy"]["before"]["rules"].append("injected")
    first["impact"]["cases"][0]["before"]["basis"] = "injected"
    assert second["cases"][0]["facts"] == {"x": True}
    assert second["policy"]["before"] == compile_rules(START, rules)
    assert second["impact"] == decision_impact(START, END, cases, rules)


def test_policy_delta_and_impact_policy_do_not_share_containers():
    report = decision_impact_attestation(START, END, _cases(), _changing_rules())
    assert report["policy"]["delta"] == report["impact"]["policy"]
    assert report["policy"]["delta"] is not report["impact"]["policy"]
    report["policy"]["delta"]["rules"].append("injected")
    assert report["impact"]["policy"]["rules"] != ["injected"]
    assert all(
        isinstance(item, dict)
        for item in report["impact"]["policy"]["rules"]
    )


def test_inputs_are_not_mutated():
    rules = _changing_rules()
    rules_snapshot = copy.deepcopy(rules)
    cases = [{"id": "z", "facts": {"y": True, "a": False}},
             {"id": "a", "facts": {}}]
    cases_snapshot = copy.deepcopy(cases)
    decision_impact_attestation(START, END, cases, rules)
    assert rules == rules_snapshot
    assert cases == cases_snapshot
    assert list(cases[0]["facts"]) == ["y", "a"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"from_at": "not-a-time", "to_at": END, "cases": [], "rules": []},
        {"from_at": START, "to_at": "not-a-time", "cases": [], "rules": []},
        {"from_at": END, "to_at": START, "cases": [], "rules": []},
        {"from_at": START, "to_at": END, "cases": {}, "rules": []},
        {"from_at": START, "to_at": END, "cases": [{"id": "", "facts": {}}],
         "rules": []},
        {"from_at": START, "to_at": END, "cases": [{"id": "a", "facts": []}],
         "rules": []},
        {"from_at": START, "to_at": END,
         "cases": [{"id": "a", "facts": {"x": 1}}], "rules": []},
        {"from_at": START, "to_at": END,
         "cases": [{"id": "a"}, {"id": "a", "facts": {}}], "rules": []},
        {"from_at": START, "to_at": END,
         "cases": [{"id": "a", "facts": {}, "extra": 1}], "rules": []},
        {"from_at": START, "to_at": END, "cases": [], "rules": [_rule(ver=0)]},
    ],
)
def test_invalid_inputs_raise_value_error(kwargs):
    with pytest.raises(ValueError):
        decision_impact_attestation(**kwargs)


# ---------------------------------------------------------------- endpoint


def test_endpoint_success_body():
    response = client.post(
        "/decision-impact/attest", json=_payload(rules=_changing_rules())
    )
    assert response.status_code == 200
    data = response.json()
    assert list(data) == ["from", "to", "cases", "policy", "impact", "digest"]
    assert list(data["policy"]) == ["before", "after", "delta"]
    assert data["impact"]["policy"] == data["policy"]["delta"]


def test_endpoint_compact_utf8_no_trailing_newline():
    response = client.post(
        "/decision-impact/attest",
        json=_payload(rules=[_rule(result="允许")]),
    )
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw
    assert "允许" in raw and "\\u" not in raw


def test_endpoint_digest_matches_recomputation():
    response = client.post(
        "/decision-impact/attest",
        json=_payload(rules=_changing_rules()),
    )
    data = response.json()
    payload = {
        key: data[key] for key in ("from", "to", "cases", "policy", "impact")
    }
    digest = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert data["digest"] == digest


def test_endpoint_byte_identical_regardless_of_key_order():
    rules = _changing_rules()
    first = client.post(
        "/decision-impact/attest", json=_payload(rules=rules)
    ).content
    second = client.post(
        "/decision-impact/attest",
        data=json.dumps(
            {
                "rules": rules,
                "cases": list(reversed(_cases())),
                "to": END,
                "from": START,
            },
            ensure_ascii=False,
        ).encode("utf-8"),
        headers={"content-type": "application/json"},
    ).content
    assert first == second


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        b"null",
        b'"x"',
        b"{}",
        b'{"from": "2021-01-01T00:00:00Z"}',
        json.dumps(_payload(extra=1)).encode(),
        json.dumps({"from": START, "to": END, "cases": []}).encode(),
    ],
)
def test_endpoint_invalid_bodies_are_422(body):
    response = client.post(
        "/decision-impact/attest",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == json.dumps(
        {"detail": "invalid request"}, separators=(",", ":")
    ).encode("utf-8")


@pytest.mark.parametrize(
    "payload",
    [
        _payload(**{"from": "not-a-time"}),
        _payload(**{"from": END, "to": START}),
        _payload(cases={}),
        _payload(cases=[{"id": "a", "facts": {"x": 1}}]),
        _payload(rules=[_rule(ver=0)]),
        _payload(rules={}),
    ],
)
def test_endpoint_validation_failures_are_422(payload):
    response = client.post("/decision-impact/attest", json=payload)
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_endpoint_does_not_touch_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError(
                "POST /decision-impact/attest must not use history"
            )

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/decision-impact/attest", json=_payload(rules=[_rule()])
    )
    assert response.status_code == 200
