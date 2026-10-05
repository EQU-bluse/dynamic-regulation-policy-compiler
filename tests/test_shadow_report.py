import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import compile_rules, policy_coverage, policy_shadow_report

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


def test_top_level_contract():
    report = policy_shadow_report(AT, [], [])
    assert list(report) == ["at", "fact_keys", "total_cases", "rules"]
    assert report == {"at": AT, "fact_keys": [], "total_cases": 1, "rules": []}


def test_empty_rules_total_cases_still_enumerated():
    report = policy_shadow_report(AT, ["b", "a"], [])
    assert report["fact_keys"] == ["a", "b"]
    assert report["total_cases"] == 4
    assert report["rules"] == []


def test_entries_follow_compiled_order_with_full_snapshots():
    rules = [
        _rule(id="b", priority=1, when={"x": True}, result="no"),
        _rule(id="a", priority=9, when={"x": True}, result="yes"),
        _rule(id="o", source="org", priority=5, when=None, result="org"),
    ]
    report = policy_shadow_report(AT, ["x"], rules)
    compiled_ids = [r["id"] for r in compile_rules(AT, rules)["rules"]]
    assert [entry["rule"]["id"] for entry in report["rules"]] == compiled_ids
    assert compiled_ids == ["a", "b", "o"]
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
    assert report["rules"][0]["rule"]["when"] == {"x": True}
    assert report["rules"][2]["rule"]["when"] is None


def test_blocker_is_actual_basis_including_same_result():
    rules = [
        _rule(id="a", priority=9, when={"x": True}, result="yes"),
        _rule(id="b", priority=1, when={"x": True}, result="no"),
        _rule(id="c", priority=0, when=None, result="yes"),
    ]
    report = policy_shadow_report(AT, ["x"], rules)
    by_id = {entry["rule"]["id"]: entry for entry in report["rules"]}

    assert by_id["a"]["matched"] == 1
    assert by_id["a"]["won"] == 1
    assert by_id["a"]["blockers"] == []

    assert by_id["b"]["matched"] == 1
    assert by_id["b"]["won"] == 0
    assert by_id["b"]["blockers"] == [
        {"rule": ["law", "a", 1], "cases": 1, "witness": {"x": True}}
    ]

    # c always matches; on x=True the basis is a, whose result equals c's.
    # The same-result blocker is still recorded; the basis explains the rule.
    assert by_id["c"]["matched"] == 2
    assert by_id["c"]["won"] == 1
    assert by_id["c"]["blockers"] == [
        {"rule": ["law", "a", 1], "cases": 1, "witness": {"x": True}}
    ]

    for entry in report["rules"]:
        assert entry["won"] + sum(b["cases"] for b in entry["blockers"]) == entry["matched"]


def test_blocker_cases_and_witness_follow_enumeration_order():
    rules = [
        _rule(id="a", priority=9, when={"x": True}, result="A"),
        _rule(id="c", priority=0, when=None, result="C"),
    ]
    report = policy_shadow_report(AT, ["y", "x"], rules)
    by_id = {entry["rule"]["id"]: entry for entry in report["rules"]}
    assert report["fact_keys"] == ["x", "y"]
    assert by_id["a"]["matched"] == 2
    assert by_id["a"]["won"] == 2
    assert by_id["a"]["blockers"] == []
    assert by_id["c"]["matched"] == 4
    assert by_id["c"]["won"] == 2
    assert by_id["c"]["blockers"] == [
        {
            "rule": ["law", "a", 1],
            "cases": 2,
            "witness": {"x": True, "y": False},
        }
    ]
    assert by_id["c"]["won"] + 2 == by_id["c"]["matched"]


def test_multiple_blockers_deduplicated_in_compiled_order():
    rules = [
        _rule(id="a", priority=9, when={"x": True}, result="A"),
        _rule(id="d", priority=8, when={"y": True}, result="D"),
        _rule(id="c", priority=0, when=None, result="C"),
    ]
    report = policy_shadow_report(AT, ["x", "y"], rules)
    by_id = {entry["rule"]["id"]: entry for entry in report["rules"]}

    # F,F -> c wins; F,T -> d wins, c blocked by d;
    # T,F -> a wins, c blocked by a; T,T -> a wins, d and c blocked by a.
    assert by_id["a"]["matched"] == 2
    assert by_id["a"]["won"] == 2
    assert by_id["a"]["blockers"] == []

    assert by_id["d"]["matched"] == 2
    assert by_id["d"]["won"] == 1
    assert by_id["d"]["blockers"] == [
        {
            "rule": ["law", "a", 1],
            "cases": 1,
            "witness": {"x": True, "y": True},
        }
    ]

    assert by_id["c"]["matched"] == 4
    assert by_id["c"]["won"] == 1
    assert [list(b) for b in by_id["c"]["blockers"]] == [
        ["rule", "cases", "witness"],
        ["rule", "cases", "witness"],
    ]
    assert by_id["c"]["blockers"] == [
        {
            "rule": ["law", "a", 1],
            "cases": 2,
            "witness": {"x": True, "y": False},
        },
        {
            "rule": ["law", "d", 1],
            "cases": 1,
            "witness": {"x": False, "y": True},
        },
    ]
    assert by_id["c"]["won"] + 3 == by_id["c"]["matched"]


def test_non_matching_rules_have_no_blockers():
    rules = [
        _rule(id="a", priority=9, when={"x": True}, result="A"),
        _rule(id="never", priority=8, when={"x": False, "y": True}, result="N"),
    ]
    report = policy_shadow_report(AT, ["x", "y"], rules)
    by_id = {entry["rule"]["id"]: entry for entry in report["rules"]}
    assert by_id["never"]["matched"] == 1
    assert by_id["never"]["won"] == 1
    assert by_id["never"]["blockers"] == []
    assert by_id["a"]["blockers"] == []


def test_counts_agree_with_coverage():
    rules = [
        _rule(id="a", priority=9, when={"x": True}, result="A"),
        _rule(id="d", priority=8, when={"y": True}, result="D"),
        _rule(id="c", priority=0, when=None, result="C"),
    ]
    coverage = policy_coverage(AT, ["x", "y"], rules)
    shadows = policy_shadow_report(AT, ["x", "y"], rules)
    assert shadows["total_cases"] == coverage["summary"]["total"]
    basis_counts = {tuple(r): 0 for r in coverage["summary"]["winners"]}
    for case in coverage["cases"]:
        basis = case["explanation"]["basis"]
        if basis is not None:
            basis_counts[(basis["source"], basis["id"], basis["ver"])] += 1
    for entry in shadows["rules"]:
        identity = (
            entry["rule"]["source"],
            entry["rule"]["id"],
            entry["rule"]["ver"],
        )
        assert entry["won"] == basis_counts[identity]
        assert entry["won"] + sum(b["cases"] for b in entry["blockers"]) == entry["matched"]


def test_empty_fact_keys_single_empty_assignment():
    rules = [_rule(id="a", when=None, result="yes")]
    report = policy_shadow_report(AT, [], rules)
    assert report["total_cases"] == 1
    entry = report["rules"][0]
    assert entry["matched"] == 1
    assert entry["won"] == 1
    assert entry["blockers"] == []


def test_effective_version_selection_and_window_reused():
    rules = [
        _rule(id="a", ver=1, when={"x": True}, result="old"),
        _rule(id="a", ver=2, when={"x": True}, result="new"),
        _rule(
            id="future",
            **{"from": "2022-01-01T00:00:00Z", "when": None, "result": "later"},
        ),
    ]
    report = policy_shadow_report(AT, ["x"], rules)
    assert [entry["rule"]["id"] for entry in report["rules"]] == ["a"]
    assert report["rules"][0]["rule"]["ver"] == 2
    assert report["rules"][0]["matched"] == 1
    assert report["rules"][0]["won"] == 1


def test_validation_matches_coverage():
    rules = [_rule()]
    with pytest.raises(ValueError):
        policy_shadow_report(AT, "x", rules)
    with pytest.raises(ValueError):
        policy_shadow_report(AT, [""], rules)
    with pytest.raises(ValueError):
        policy_shadow_report(AT, [None], rules)
    with pytest.raises(ValueError):
        policy_shadow_report(AT, [True], rules)
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
        policy_shadow_report(AT, ["x"], [_rule(id="a", when={"y": True})])
    report = policy_shadow_report(AT, [f"k{i}" for i in range(12)], rules)
    assert report["total_cases"] == 4096
    assert report["rules"][0]["matched"] == 4096


def test_inputs_are_not_mutated():
    rules = [
        _rule(id="a", priority=9, when={"x": True, "y": False}, result="A"),
        _rule(id="c", priority=0, when=None, result="C"),
    ]
    fact_keys = ["y", "x"]
    snapshot = copy.deepcopy((fact_keys, rules))
    policy_shadow_report(AT, fact_keys, rules)
    assert (fact_keys, rules) == snapshot


def test_result_is_independent_deep_copy():
    rules = [
        _rule(id="a", when={"x": True}, result="hit"),
        _rule(id="c", when=None, result="fallback"),
    ]
    report = policy_shadow_report(AT, ["x"], rules)
    report["rules"][0]["rule"]["result"] = "mutated"
    report["rules"][1]["blockers"][0]["witness"]["x"] = "mutated"
    again = policy_shadow_report(AT, ["x"], rules)
    assert again["rules"][0]["rule"]["result"] == "hit"
    assert again["rules"][1]["blockers"][0]["witness"] == {"x": True}


def test_equal_inputs_yield_byte_identical_json():
    rules_a = [
        _rule(id="a", when={"x": True, "y": False}, result="hit"),
        _rule(id="b", source="org", priority=3, result="org"),
    ]
    rules_b = [dict(reversed(list(r.items()))) for r in reversed(rules_a)]
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
    rules = [
        _rule(id="régle", priority=9, when={"clé": True}, result="oui"),
        _rule(id="repli", when=None, result="non"),
    ]
    response = _post({"at": AT, "fact_keys": ["clé"], "rules": rules})
    assert response.status_code == 200
    raw = response.content
    assert not raw.endswith(b"\n")
    assert "régle".encode("utf-8") in raw
    assert "clé".encode("utf-8") in raw
    assert b"\\u" not in raw
    assert b", " not in raw and b": " not in raw
    payload = json.loads(raw)
    assert list(payload) == ["at", "fact_keys", "total_cases", "rules"]
    assert payload["fact_keys"] == ["clé"]
    assert payload["total_cases"] == 2
    entries = {entry["rule"]["id"]: entry for entry in payload["rules"]}
    assert entries["régle"]["won"] == 1
    assert entries["repli"]["blockers"] == [
        {"rule": ["law", "régle", 1], "cases": 1, "witness": {"clé": True}}
    ]


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
        {"at": AT, "rules": []},  # missing fact_keys
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
