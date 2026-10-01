import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import policy_coverage

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
    payload = {"at": AT, "fact_keys": [], "rules": []}
    payload.update(overrides)
    return payload


def test_empty_fact_keys_and_empty_rules_single_undecided_case():
    report = policy_coverage(AT, [], [])
    assert list(report) == ["at", "fact_keys", "cases", "summary"]
    assert report["at"] == AT
    assert report["fact_keys"] == []
    assert len(report["cases"]) == 1
    case = report["cases"][0]
    assert list(case) == ["facts", "explanation"]
    assert case["facts"] == {}
    assert case["explanation"] == {
        "at": AT,
        "decision": None,
        "trace": [],
        "basis": None,
        "conflicts": [],
    }
    assert report["summary"] == {
        "total": 1,
        "decided": 0,
        "undecided": 1,
        "winners": [],
        "shadowed": [],
    }
    assert list(report["summary"]) == [
        "total",
        "decided",
        "undecided",
        "winners",
        "shadowed",
    ]


def test_fact_keys_normalized_to_code_point_order():
    report = policy_coverage(AT, ["b", "A", "a"], [])
    assert report["fact_keys"] == ["A", "a", "b"]
    assert [list(case["facts"]) for case in report["cases"]] == [
        ["A", "a", "b"]
    ] * 8


def test_enumeration_order_false_before_true_per_key():
    report = policy_coverage(AT, ["x", "y"], [])
    assert [case["facts"] for case in report["cases"]] == [
        {"x": False, "y": False},
        {"x": False, "y": True},
        {"x": True, "y": False},
        {"x": True, "y": True},
    ]


def test_winners_and_shadowed_follow_compiled_rule_order():
    # Higher priority ranks first: never(3), when-x(2), always(1).
    rules = [
        _rule(id="always", priority=1, result="allow"),
        _rule(id="when-x", priority=2, when={"x": True}, result="deny"),
        _rule(id="never", priority=3, when={"x": False}, result="allow"),
    ]
    report = policy_coverage(AT, ["x"], rules)
    assert report["summary"]["total"] == 2
    assert report["summary"]["decided"] == 2
    assert report["summary"]["undecided"] == 0
    # x=False is won by "never", x=True by "when-x"; the unconditional
    # lowest-priority "always" never becomes basis.
    assert report["summary"]["winners"] == [
        ["law", "never", 1],
        ["law", "when-x", 1],
    ]
    assert report["summary"]["shadowed"] == [["law", "always", 1]]
    assert report["cases"][0]["explanation"]["decision"] == "allow"
    assert report["cases"][1]["explanation"]["decision"] == "deny"


def test_shadowed_rule_that_wins_one_case_is_a_winner():
    rules = [
        _rule(id="top", priority=2, when={"x": True}, result="deny"),
        _rule(id="fallback", priority=1, result="allow"),
    ]
    report = policy_coverage(AT, ["x"], rules)
    assert report["summary"]["winners"] == [
        ["law", "top", 1],
        ["law", "fallback", 1],
    ]
    assert report["summary"]["shadowed"] == []
    assert report["cases"][0]["explanation"]["decision"] == "allow"
    assert report["cases"][1]["explanation"]["decision"] == "deny"


def test_when_referencing_key_outside_domain_raises():
    rules = [_rule(when={"y": True})]
    with pytest.raises(ValueError):
        policy_coverage(AT, ["x"], rules)


def test_when_of_non_effective_rule_is_not_checked():
    rules = [
        _rule(id="old", ver=1, when={"y": True}),
        _rule(id="old", ver=2, when={"x": True}, result="new"),
    ]
    report = policy_coverage(AT, ["x"], rules)
    assert report["summary"]["winners"] == [["law", "old", 2]]


@pytest.mark.parametrize(
    "fact_keys",
    [
        "x",
        None,
        {"x": True},
        [""],
        ["x", "x"],
        [1],
        [True],
        [None],
        [f"k{i}" for i in range(13)],
    ],
)
def test_invalid_fact_keys_raise(fact_keys):
    with pytest.raises(ValueError):
        policy_coverage(AT, fact_keys, [])


def test_twelve_keys_are_accepted():
    report = policy_coverage(AT, [f"k{i:02d}" for i in range(12)], [])
    assert report["summary"]["total"] == 4096


def test_invalid_at_and_rules_still_raise():
    with pytest.raises(ValueError):
        policy_coverage("not-a-time", [], [])
    with pytest.raises(ValueError):
        policy_coverage(AT, [], [{"id": "broken"}])


def test_inputs_are_not_mutated():
    rules = [_rule(when={"x": True})]
    fact_keys = ["x"]
    rules_snapshot = copy.deepcopy(rules)
    fact_keys_snapshot = list(fact_keys)
    policy_coverage(AT, fact_keys, rules)
    assert rules == rules_snapshot
    assert fact_keys == fact_keys_snapshot


def test_result_is_deep_copy_and_byte_identical_for_reordered_inputs():
    rules = [_rule(id="b", priority=2, when={"x": True}, result="deny"),
             _rule(id="a", priority=1, result="allow")]
    first = policy_coverage(AT, ["x"], rules)
    reordered_rules = [
        {k: rule[k] for k in reversed(list(rule))} for rule in reversed(rules)
    ]
    second = policy_coverage(AT, ["x"], reordered_rules)
    dump = lambda r: json.dumps(r, ensure_ascii=False, separators=(",", ":"))
    assert dump(first) == dump(second)
    # Mutating the result must not affect a fresh call.
    first["cases"][0]["facts"]["x"] = "mutated"
    first["cases"][0]["explanation"]["trace"].append("mutated")
    third = policy_coverage(AT, ["x"], rules)
    assert dump(third) == dump(second)


def test_explanation_keeps_existing_contract_key_order():
    rules = [_rule(when={"x": True}, result="允许")]
    report = policy_coverage(AT, ["x"], rules)
    explanation = report["cases"][1]["explanation"]
    assert list(explanation) == ["at", "decision", "trace", "basis", "conflicts"]
    assert explanation["decision"] == "允许"
    assert list(explanation["basis"]) == [
        "id",
        "ver",
        "source",
        "priority",
        "from",
        "to",
        "when",
        "result",
    ]


def test_endpoint_success_compact_utf8_no_trailing_newline():
    rules = [_rule(when={"x": True}, result="允许")]
    response = client.post(
        "/rules/coverage", json=_payload(fact_keys=["x"], rules=rules)
    )
    assert response.status_code == 200
    raw = response.content
    assert not raw.endswith(b"\n")
    assert "允许".encode("utf-8") in raw
    assert b"\\u" not in raw
    data = response.json()
    assert list(data) == ["at", "fact_keys", "cases", "summary"]
    assert data["summary"]["winners"] == [["law", "r1", 1]]


def test_endpoint_reorders_fact_keys_and_dict_keys_deterministically():
    rules = [_rule(when={"b": True, "a": False})]
    first = client.post(
        "/rules/coverage", json=_payload(fact_keys=["b", "a"], rules=rules)
    )
    second = client.post(
        "/rules/coverage", json=_payload(fact_keys=["a", "b"], rules=rules)
    )
    assert first.status_code == second.status_code == 200
    assert first.content == second.content


@pytest.mark.parametrize(
    "body",
    [
        _payload(fact_keys=["x", "x"]),
        _payload(fact_keys=[f"k{i}" for i in range(13)]),
        _payload(fact_keys=["x"], rules=[_rule(when={"y": True})]),
        _payload(at="bad"),
    ],
)
def test_endpoint_domain_and_value_errors_are_422(body):
    response = client.post("/rules/coverage", json=body)
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_endpoint_requires_exact_key_set():
    valid = _payload(fact_keys=["x"])
    for mutated in (
        {k: v for k, v in valid.items() if k != "rules"},
        {**valid, "extra": 1},
    ):
        response = client.post("/rules/coverage", json=mutated)
        assert response.status_code == 422
        assert response.json() == {"detail": "invalid request"}


def test_endpoint_unparseable_body_is_422():
    response = client.post(
        "/rules/coverage",
        content=b"{not json",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}
