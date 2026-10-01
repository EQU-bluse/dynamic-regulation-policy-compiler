import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import explain, policy_coverage

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


def test_empty_fact_keys_and_empty_rules():
    report = policy_coverage(AT, [], [])
    assert list(report) == ["at", "fact_keys", "cases", "summary"]
    assert report["at"] == AT
    assert report["fact_keys"] == []
    assert len(report["cases"]) == 1
    case = report["cases"][0]
    assert list(case) == ["facts", "explanation"]
    assert case["facts"] == {}
    assert case["explanation"] == explain(AT, {}, [])
    assert case["explanation"]["decision"] is None
    assert report["summary"] == {
        "total": 1,
        "decided": 0,
        "undecided": 1,
        "winners": [],
        "shadowed": [],
    }


def test_enumeration_order_false_before_true():
    report = policy_coverage(AT, ["b", "a"], [])
    assert report["fact_keys"] == ["a", "b"]
    assert [case["facts"] for case in report["cases"]] == [
        {"a": False, "b": False},
        {"a": False, "b": True},
        {"a": True, "b": False},
        {"a": True, "b": True},
    ]
    assert report["summary"]["total"] == 4
    assert report["summary"]["undecided"] == 4


def test_winners_and_shadowed_follow_compiled_order():
    rules = [
        _rule(id="win", priority=9, when={"x": True}, result="yes"),
        _rule(id="shadow", priority=1, when={"x": True}, result="no"),
        _rule(id="other", source="org", priority=5, when=None, result="org"),
    ]
    report = policy_coverage(AT, ["x"], rules)
    summary = report["summary"]
    assert summary["total"] == 2
    assert summary["decided"] == 2
    assert summary["undecided"] == 0
    # law rules rank before org; "shadow" never wins because "win" matches
    # the same assignments and ranks higher, while "other" wins x=False.
    assert summary["winners"] == [["law", "win", 1], ["org", "other", 1]]
    assert summary["shadowed"] == [["law", "shadow", 1]]
    case_false = report["cases"][0]
    assert case_false["facts"] == {"x": False}
    assert case_false["explanation"]["basis"]["id"] == "other"


def test_explanations_match_explain():
    rules = [_rule(id="a", when={"x": True}, result="hit")]
    report = policy_coverage(AT, ["x"], rules)
    for case in report["cases"]:
        assert case["explanation"] == explain(AT, case["facts"], rules)
        assert list(case["explanation"]) == [
            "at",
            "decision",
            "trace",
            "basis",
            "conflicts",
        ]


def test_fact_keys_validation():
    rules = [_rule()]
    with pytest.raises(ValueError):
        policy_coverage(AT, "x", rules)
    with pytest.raises(ValueError):
        policy_coverage(AT, [""], rules)
    with pytest.raises(ValueError):
        policy_coverage(AT, [None], rules)
    with pytest.raises(ValueError):
        policy_coverage(AT, [True], rules)
    with pytest.raises(ValueError):
        policy_coverage(AT, ["x", "x"], rules)
    with pytest.raises(ValueError):
        policy_coverage(AT, [f"k{i}" for i in range(13)], rules)
    # twelve keys are accepted
    report = policy_coverage(AT, [f"k{i}" for i in range(12)], rules)
    assert report["summary"]["total"] == 4096


def test_at_and_rules_validation_matches_compile():
    with pytest.raises(ValueError):
        policy_coverage("not-a-time", [], [])
    with pytest.raises(ValueError):
        policy_coverage(AT, [], "not-a-list")
    with pytest.raises(ValueError):
        policy_coverage(AT, [], [_rule(ver=0)])


def test_selected_rule_when_outside_domain_raises():
    rules = [_rule(id="a", when={"y": True}, result="hit")]
    with pytest.raises(ValueError):
        policy_coverage(AT, ["x"], rules)


def test_non_selected_rule_may_reference_outside_keys():
    rules = [
        _rule(id="a", ver=1, when={"y": True}, result="old"),
        _rule(id="a", ver=2, when=None, result="new"),
        _rule(
            id="b",
            **{
                "from": "2022-01-01T00:00:00Z",
                "when": {"z": True},
                "result": "future",
            },
        ),
    ]
    report = policy_coverage(AT, ["x"], rules)
    assert report["summary"]["winners"] == [["law", "a", 2]]


def test_inputs_are_not_mutated():
    rules = [_rule(id="a", when={"x": True}, result="hit")]
    fact_keys = ["x"]
    snapshot = copy.deepcopy((fact_keys, rules))
    policy_coverage(AT, fact_keys, rules)
    assert (fact_keys, rules) == snapshot


def test_result_is_deep_copy():
    rules = [_rule(id="a", when={"x": True}, result="hit")]
    report = policy_coverage(AT, ["x"], rules)
    report["cases"][0]["facts"]["x"] = "mutated"
    again = policy_coverage(AT, ["x"], rules)
    assert again["cases"][0]["facts"] == {"x": False}


def test_equal_inputs_yield_byte_identical_json():
    rules_a = [
        _rule(id="a", when={"x": True, "y": False}, result="hit"),
        _rule(id="b", source="org", priority=3, result="org"),
    ]
    rules_b = [dict(reversed(list(r.items()))) for r in rules_a]
    first = policy_coverage(AT, ["y", "x"], rules_a)
    second = policy_coverage(AT, ["x", "y"], rules_b)
    dump = lambda v: json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    assert dump(first) == dump(second)


def _post(body):
    return TestClient(app).post(
        "/rules/coverage",
        content=json.dumps(body),
        headers={"Content-Type": "application/json"},
    )


def test_endpoint_success_compact_utf8():
    rules = [_rule(id="régle", when={"clé": True}, result="oui")]
    response = _post({"at": AT, "fact_keys": ["clé"], "rules": rules})
    assert response.status_code == 200
    raw = response.content
    assert not raw.endswith(b"\n")
    assert "régle".encode("utf-8") in raw  # non-ASCII not escaped
    assert b"\\u" not in raw
    assert b", " not in raw and b": " not in raw  # compact separators
    payload = json.loads(raw)
    assert list(payload) == ["at", "fact_keys", "cases", "summary"]
    assert payload["summary"]["winners"] == [["law", "régle", 1]]


def test_endpoint_rejects_bad_requests():
    client = TestClient(app)
    bad = client.post(
        "/rules/coverage", content=b"{not json",
        headers={"Content-Type": "application/json"},
    )
    assert bad.status_code == 422
    assert bad.json() == {"detail": "invalid request"}

    for body in (
        [],
        {"at": AT, "fact_keys": []},  # missing rules
        {"at": AT, "fact_keys": [], "rules": [], "extra": 1},
        {"at": AT, "fact_keys": ["x", "x"], "rules": []},
        {"at": AT, "fact_keys": ["", ], "rules": []},
        {"at": AT, "fact_keys": [f"k{i}" for i in range(13)], "rules": []},
        {"at": "bad", "fact_keys": [], "rules": []},
        {
            "at": AT,
            "fact_keys": ["x"],
            "rules": [_rule(id="a", when={"y": True}, result="hit")],
        },
    ):
        response = _post(body)
        assert response.status_code == 422
        assert response.json() == {"detail": "invalid request"}
