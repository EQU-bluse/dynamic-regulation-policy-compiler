import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import policy_coverage, policy_shadow_report

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
    report = policy_shadow_report(AT, [], [])
    assert list(report) == ["at", "fact_keys", "total_cases", "rules"]
    assert report == {
        "at": AT,
        "fact_keys": [],
        "total_cases": 1,
        "rules": [],
    }


def test_total_cases_without_rules():
    report = policy_shadow_report(AT, ["b", "a"], [])
    assert report["fact_keys"] == ["a", "b"]
    assert report["total_cases"] == 4
    assert report["rules"] == []


def test_rule_entries_include_all_selected_rules_in_compiled_order():
    rules = [
        _rule(id="shadow", priority=1, when={"x": True}, result="no"),
        _rule(id="win", priority=9, when={"x": True}, result="yes"),
        _rule(id="other", source="org", priority=5, when=None, result="org"),
    ]
    report = policy_shadow_report(AT, ["x"], rules)
    assert [entry["rule"]["id"] for entry in report["rules"]] == [
        "win",
        "shadow",
        "other",
    ]
    for entry in report["rules"]:
        assert list(entry) == ["rule", "matched", "won", "blockers"]
        assert list(entry["rule"]) == [
            "id",
            "ver",
            "source",
            "priority",
            "from",
            "to",
            "when",
            "result",
        ]


def test_blockers_explain_basis_even_with_equal_result():
    rules = [
        _rule(id="win", priority=9, when={"x": True}, result="same"),
        _rule(id="shadow", priority=1, when={"x": True}, result="same"),
    ]
    report = policy_shadow_report(AT, ["x"], rules)
    win, shadow = report["rules"]
    assert win["matched"] == 1
    assert win["won"] == 1
    assert win["blockers"] == []
    assert shadow["matched"] == 1
    assert shadow["won"] == 0
    assert shadow["blockers"] == [
        {"rule": ["law", "win", 1], "cases": 1, "witness": {"x": True}}
    ]
    for blocker in shadow["blockers"]:
        assert list(blocker) == ["rule", "cases", "witness"]


def test_blocker_cases_and_witness_enumeration_order():
    rules = [
        _rule(id="win", priority=5, when={"x": True}, result="yes"),
        _rule(id="shadow", priority=1, when={"x": True}, result="no"),
    ]
    report = policy_shadow_report(AT, ["x", "y"], rules)
    win, shadow = report["rules"]
    assert win["matched"] == 2
    assert win["won"] == 2
    assert shadow["matched"] == 2
    assert shadow["won"] == 0
    assert shadow["blockers"] == [
        {
            "rule": ["law", "win", 1],
            "cases": 2,
            "witness": {"x": True, "y": False},
        }
    ]


def test_blockers_deduplicated_in_compiled_order():
    rules = [
        _rule(id="top", priority=9, when=None, result="top"),
        _rule(id="mid", priority=5, when={"x": True}, result="mid"),
        _rule(id="low", priority=1, when={"x": True}, result="low"),
    ]
    report = policy_shadow_report(AT, ["x"], rules)
    low = report["rules"][2]
    # "low" only matches x=True where "top" also matches and wins; "mid"
    # never blocks it.
    assert low["blockers"] == [
        {"rule": ["law", "top", 1], "cases": 1, "witness": {"x": True}}
    ]
    mid = report["rules"][1]
    assert mid["won"] == 0
    assert mid["blockers"] == [
        {"rule": ["law", "top", 1], "cases": 1, "witness": {"x": True}}
    ]


def test_won_plus_blocker_cases_equals_matched():
    rules = [
        _rule(id="top", priority=9, when=None, result="top"),
        _rule(id="a", priority=5, when={"x": True}, result="a"),
        _rule(id="b", source="org", priority=2, when=None, result="b"),
    ]
    report = policy_shadow_report(AT, ["x", "y"], rules)
    assert report["total_cases"] == 4
    for entry in report["rules"]:
        blocked = sum(blocker["cases"] for blocker in entry["blockers"])
        assert entry["won"] + blocked == entry["matched"]


def test_agrees_with_policy_coverage_counts():
    rules = [
        _rule(id="win", priority=9, when={"x": True}, result="yes"),
        _rule(id="shadow", priority=1, when={"x": True}, result="no"),
        _rule(id="other", source="org", priority=5, when=None, result="org"),
    ]
    coverage = policy_coverage(AT, ["x"], rules)
    report = policy_shadow_report(AT, ["x"], rules)
    assert report["total_cases"] == coverage["summary"]["total"]
    winner_keys = {tuple(item) for item in coverage["summary"]["winners"]}
    for entry in report["rules"]:
        identity = (
            entry["rule"]["source"],
            entry["rule"]["id"],
            entry["rule"]["ver"],
        )
        if identity in winner_keys:
            assert entry["won"] >= 1
        else:
            assert entry["won"] == 0
            assert entry["matched"] >= 1


def test_fact_keys_normalization_and_enumeration_match_coverage():
    report = policy_shadow_report(AT, ["b", "a"], [])
    assert report["fact_keys"] == ["a", "b"]
    assert report["total_cases"] == 4


def test_validation_matches_policy_coverage():
    rules = [_rule()]
    with pytest.raises(ValueError):
        policy_shadow_report(AT, "x", rules)
    with pytest.raises(ValueError):
        policy_shadow_report(AT, [""], rules)
    with pytest.raises(ValueError):
        policy_shadow_report(AT, ["x", "x"], rules)
    with pytest.raises(ValueError):
        policy_shadow_report(AT, [f"k{i}" for i in range(13)], rules)
    with pytest.raises(ValueError):
        policy_shadow_report("not-a-time", [], [])
    with pytest.raises(ValueError):
        policy_shadow_report(AT, [], "not-a-list")
    with pytest.raises(ValueError):
        policy_shadow_report(AT, [], [_rule(ver=0)])
    with pytest.raises(ValueError):
        policy_shadow_report(AT, ["x"], [_rule(when={"y": True})])


def test_inputs_are_not_mutated():
    rules = [
        _rule(id="win", priority=9, when={"x": True}, result="yes"),
        _rule(id="shadow", priority=1, when={"x": True}, result="no"),
    ]
    fact_keys = ["x"]
    snapshot = copy.deepcopy((fact_keys, rules))
    policy_shadow_report(AT, fact_keys, rules)
    assert (fact_keys, rules) == snapshot


def test_result_does_not_share_containers():
    rules = [
        _rule(id="win", priority=9, when={"x": True}, result="yes"),
        _rule(id="shadow", priority=1, when={"x": True}, result="no"),
    ]
    report = policy_shadow_report(AT, ["x"], rules)
    report["rules"][0]["rule"]["result"] = "mutated"
    report["rules"][1]["blockers"][0]["witness"]["x"] = "mutated"
    again = policy_shadow_report(AT, ["x"], rules)
    assert again["rules"][0]["rule"]["result"] == "yes"
    assert again["rules"][1]["blockers"][0]["witness"] == {"x": True}


def test_equal_inputs_yield_byte_identical_json():
    rules_a = [
        _rule(id="a", priority=5, when={"x": True, "y": False}, result="hit"),
        _rule(id="b", source="org", priority=3, when=None, result="org"),
    ]
    rules_b = [dict(reversed(list(r.items()))) for r in rules_a]
    first = policy_shadow_report(AT, ["y", "x"], rules_a)
    second = policy_shadow_report(AT, ["x", "y"], rules_b)
    dump = lambda v: json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    assert dump(first) == dump(second)


def _post(body):
    return TestClient(app).post(
        "/rules/shadows",
        content=json.dumps(body),
        headers={"Content-Type": "application/json"},
    )


def test_endpoint_success_compact_utf8():
    rules = [_rule(id="régle", when={"clé": True}, result="oui")]
    response = _post({"at": AT, "fact_keys": ["clé"], "rules": rules})
    assert response.status_code == 200
    raw = response.content
    assert not raw.endswith(b"\n")
    assert "régle".encode("utf-8") in raw
    assert b"\\u" not in raw
    assert b", " not in raw and b": " not in raw
    payload = json.loads(raw)
    assert list(payload) == ["at", "fact_keys", "total_cases", "rules"]
    assert payload["rules"][0]["matched"] == 1
    assert payload["rules"][0]["won"] == 1


def test_endpoint_rejects_bad_requests():
    client = TestClient(app)
    bad = client.post(
        "/rules/shadows",
        content=b"{not json",
        headers={"Content-Type": "application/json"},
    )
    assert bad.status_code == 422
    assert bad.json() == {"detail": "invalid request"}

    for body in (
        [],
        {"at": AT, "fact_keys": []},  # missing rules
        {"at": AT, "fact_keys": [], "rules": [], "extra": 1},
        {"at": AT, "fact_keys": ["x", "x"], "rules": []},
        {"at": AT, "fact_keys": [""], "rules": []},
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
