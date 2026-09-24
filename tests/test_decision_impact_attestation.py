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


def _payload(cases=None, rules=None, from_at=START, to_at=END, **overrides):
    payload = {"from": from_at, "to": to_at,
               "cases": [] if cases is None else cases, "rules": rules or []}
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------- function


def test_top_level_key_order_and_value_shapes():
    rules = _changing_rules()
    cases = [
        {"id": "c2", "facts": {"z": True, "a": False}},
        {"id": "c1", "facts": {"x": True}},
    ]
    report = decision_impact_attestation(START, END, cases, rules)
    assert list(report) == ["from", "to", "cases", "policy", "impact", "digest"]
    assert report["from"] == START
    assert report["to"] == END
    assert [case["id"] for case in report["cases"]] == ["c1", "c2"]
    assert list(report["cases"][1]) == ["id", "facts"]
    assert list(report["cases"][1]["facts"]) == ["a", "z"]
    assert list(report["policy"]) == ["before", "after", "delta"]
    assert report["policy"]["before"] == compile_rules(START, rules)
    assert report["policy"]["after"] == compile_rules(END, rules)
    assert report["policy"]["delta"] == policy_delta(START, END, rules)
    assert report["impact"] == decision_impact(START, END, cases, rules)
    assert list(report["impact"]) == ["from", "to", "policy", "cases"]


def test_policy_delta_inside_impact_is_the_existing_delta():
    rules = _changing_rules()
    report = _attest([{"id": "c", "facts": {}}], rules)
    assert report["impact"]["policy"] == report["policy"]["delta"]
    assert report["impact"]["policy"] == policy_delta(START, END, rules)


def test_impact_keeps_case_order_explanations_and_changes():
    rules = _changing_rules()
    cases = [{"id": "b", "facts": {}}, {"id": "a", "facts": {"x": True}}]
    report = decision_impact_attestation(START, MID, cases, rules)
    assert [entry["id"] for entry in report["impact"]["cases"]] == ["a", "b"]
    # The empty-facts case flips fully when rule b becomes effective.
    flipped = next(entry for entry in report["impact"]["cases"] if entry["id"] == "b")
    assert list(flipped) == ["id", "changes", "before", "after"]
    assert flipped["changes"] == ["decision", "trace", "basis", "conflicts"]
    assert flipped["before"] == report["impact"]["cases"][1]["before"]
    # The x=True case keeps a's decision but now traces and conflicts with b.
    partial = next(entry for entry in report["impact"]["cases"] if entry["id"] == "a")
    assert partial["changes"] == ["trace", "conflicts"]


def test_digest_is_sha256_of_first_five_fields_compact_json():
    report = _attest([{"id": "c", "facts": {"k": True}}], [_rule(result="允许")])
    payload = {key: report[key] for key in ("from", "to", "cases", "policy", "impact")}
    expected = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert report["digest"] == expected
    assert len(report["digest"]) == 64
    assert report["digest"] == report["digest"].lower()


def test_equal_inputs_are_byte_identical_regardless_of_order():
    rules = _changing_rules()
    cases = [
        {"id": "c2", "facts": {"z": True, "a": False}},
        {"id": "c1", "facts": {"x": True}},
    ]
    first = decision_impact_attestation(START, END, cases, rules)
    second = decision_impact_attestation(START, END, list(reversed(cases)), rules)
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == (
        json.dumps(second, ensure_ascii=False, separators=(",", ":"))
    )
    # Fact-key order is normalized too.
    third = decision_impact_attestation(
        START,
        END,
        [{"id": "c1", "facts": {"x": True}}, {"id": "c2", "facts": {"a": False, "z": True}}],
        rules,
    )
    assert first == third


def test_empty_cases_are_valid():
    report = _attest([], _changing_rules())
    assert report["cases"] == []
    assert report["impact"]["cases"] == []
    assert list(report) == ["from", "to", "cases", "policy", "impact", "digest"]


def test_empty_rules_attest_normally():
    report = _attest([{"id": "c", "facts": {}}], [])
    assert report["policy"]["before"] == {"at": START, "rules": [], "conflicts": []}
    assert report["policy"]["after"] == {"at": END, "rules": [], "conflicts": []}
    assert report["policy"]["delta"]["rules"] == []
    assert report["impact"]["cases"][0]["before"]["decision"] is None


def test_result_branches_do_not_share_mutable_containers():
    when = {"x": True}
    rules = [_rule(when=when)]
    facts = {"x": True}
    cases = [{"id": "c", "facts": facts}]
    first = _attest(cases, rules)
    second = _attest(cases, rules)
    assert first == second and first is not second
    first["cases"][0]["facts"]["y"] = False
    first["policy"]["before"]["rules"].append("injected")
    first["policy"]["delta"]["rules"].append("injected")
    first["impact"]["cases"][0]["before"]["trace"].append("z@9")
    assert facts == {"x": True}
    assert when == {"x": True}
    assert second["cases"][0]["facts"] == {"x": True}
    assert second["policy"]["before"]["rules"] == compile_rules(START, rules)["rules"]
    assert second["policy"]["delta"]["rules"] == []
    assert second["impact"]["cases"][0]["before"]["trace"] == ["r1@1"]


def test_inputs_are_not_mutated():
    cases = [
        {"id": "c2", "facts": {"z": True, "a": False}},
        {"id": "c1", "facts": {"x": True}},
    ]
    cases_snapshot = copy.deepcopy(cases)
    rules = _changing_rules()
    rules_snapshot = copy.deepcopy(rules)
    decision_impact_attestation(START, END, cases, rules)
    assert cases == cases_snapshot
    assert [case["id"] for case in cases] == ["c2", "c1"]
    assert list(cases[0]["facts"]) == ["z", "a"]
    assert rules == rules_snapshot


@pytest.mark.parametrize(
    "kwargs",
    [
        {"from_at": "not-a-time", "to_at": END, "cases": [], "rules": []},
        {"from_at": START, "to_at": "not-a-time", "cases": [], "rules": []},
        {"from_at": END, "to_at": START, "cases": [], "rules": []},
        {"from_at": START, "to_at": END, "cases": {}, "rules": []},
        {"from_at": START, "to_at": END, "cases": [{}], "rules": []},
        {"from_at": START, "to_at": END, "cases": [{"id": "", "facts": {}}], "rules": []},
        {"from_at": START, "to_at": END, "cases": [{"id": "a"}], "rules": []},
        {
            "from_at": START,
            "to_at": END,
            "cases": [{"id": "a", "facts": {}}, {"id": "a", "facts": {}}],
            "rules": [],
        },
        {
            "from_at": START,
            "to_at": END,
            "cases": [{"id": "a", "facts": {"x": 1}}],
            "rules": [],
        },
        {"from_at": START, "to_at": END, "cases": [{"id": "a", "facts": []}], "rules": []},
        {"from_at": START, "to_at": END, "cases": [], "rules": {}},
        {"from_at": START, "to_at": END, "cases": [], "rules": [_rule(ver=0)]},
    ],
)
def test_invalid_inputs_raise_value_error(kwargs):
    with pytest.raises(ValueError):
        decision_impact_attestation(**kwargs)


# ---------------------------------------------------------------- endpoint


def test_endpoint_success_body():
    response = client.post(
        "/decision-impact/attest",
        json=_payload(
            cases=[{"id": "c", "facts": {"x": True}}], rules=_changing_rules()
        ),
    )
    assert response.status_code == 200
    data = response.json()
    assert list(data) == ["from", "to", "cases", "policy", "impact", "digest"]
    assert list(data["policy"]) == ["before", "after", "delta"]
    assert list(data["impact"]) == ["from", "to", "policy", "cases"]
    assert data["impact"] == decision_impact(
        START, END, [{"id": "c", "facts": {"x": True}}], _changing_rules()
    )


def test_endpoint_compact_utf8_no_trailing_newline():
    response = client.post(
        "/decision-impact/attest",
        json=_payload(cases=[{"id": "c", "facts": {}}], rules=[_rule(result="允许")]),
    )
    raw = response.content.decode("utf-8")
    assert response.status_code == 200
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw
    assert "允许" in raw and "\\u" not in raw


def test_endpoint_byte_identical_regardless_of_key_order():
    rules = _changing_rules()
    cases = [{"id": "c2", "facts": {}}, {"id": "c1", "facts": {"x": True}}]
    first = client.post(
        "/decision-impact/attest", json=_payload(cases=cases, rules=rules)
    ).content
    second = client.post(
        "/decision-impact/attest",
        data=json.dumps(
            {"rules": rules, "cases": list(reversed(cases)), "to": END, "from": START},
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
        json.dumps({"from": START, "to": END, "cases": []}).encode(),
        json.dumps(_payload(extra=1)).encode(),
    ],
)
def test_endpoint_bad_bodies_are_422(body):
    response = client.post(
        "/decision-impact/attest",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == json.dumps(
        {"detail": "invalid request"}, separators=(",", ":")
    ).encode("utf-8")


def test_endpoint_validation_failures_are_422():
    bad_payloads = [
        _payload(from_at="not-a-time"),
        _payload(to_at="2020-01-01T00:00:00Z"),
        _payload(cases=[{}]),
        _payload(cases=[{"id": "a"}, {"id": "a", "facts": {}}]),
        _payload(cases=[{"id": "a", "facts": {"x": 1}}]),
        _payload(rules=[_rule(ver=0)]),
    ]
    for payload in bad_payloads:
        response = client.post("/decision-impact/attest", json=payload)
        assert response.status_code == 422, payload
        assert response.json() == {"detail": "invalid request"}


def test_endpoint_does_not_touch_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("POST /decision-impact/attest must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/decision-impact/attest", json=_payload(rules=[_rule()])
    )
    assert response.status_code == 200
