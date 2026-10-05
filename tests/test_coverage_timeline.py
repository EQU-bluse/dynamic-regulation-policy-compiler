import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    compile_rules,
    policy_coverage,
    policy_coverage_timeline,
)

START = "2021-01-01T00:00:00Z"
MID = "2021-03-01T00:00:00Z"
LATE = "2021-04-01T00:00:00Z"
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


def test_empty_fact_keys_and_empty_rules():
    report = policy_coverage_timeline(START, END, [], [])
    assert list(report) == ["start", "end", "fact_keys", "points", "gaps"]
    assert report["start"] == START
    assert report["end"] == END
    assert report["fact_keys"] == []
    assert len(report["points"]) == 1
    point = report["points"][0]
    assert list(point) == ["at", "policy", "coverage", "changes"]
    assert point["at"] == START
    assert point["policy"] == compile_rules(START, [])
    assert point["coverage"] == policy_coverage(START, [], [])
    assert point["changes"] == []
    assert report["gaps"] == [{"facts": {}, "from": START, "to": END}]


def test_start_equals_end_single_snapshot():
    rules = [_rule(id="a", when={"x": True}, result="hit")]
    report = policy_coverage_timeline(START, START, ["x"], rules)
    assert [point["at"] for point in report["points"]] == [START]
    assert report["gaps"] == [
        {"facts": {"x": False}, "from": START, "to": START}
    ]
    decided = policy_coverage_timeline(START, START, [], [_rule(id="b")])
    assert decided["gaps"] == []


def test_gap_closes_at_recovery_point():
    rules = [_rule(id="a", **{"from": MID}, when={"x": True}, result="yes")]
    report = policy_coverage_timeline(START, END, ["x"], rules)
    assert [point["at"] for point in report["points"]] == [START, MID]
    first, second = report["points"]
    assert first["changes"] == []
    assert first["coverage"]["summary"]["undecided"] == 2
    assert second["changes"] == [{"x": True}]
    assert second["policy"] == compile_rules(MID, rules)
    assert second["coverage"] == policy_coverage(MID, ["x"], rules)
    assert report["gaps"] == [
        {"facts": {"x": False}, "from": START, "to": END},
        {"facts": {"x": True}, "from": START, "to": MID},
    ]


def test_multiple_gaps_per_combination():
    rules = [_rule(id="a", **{"from": MID, "to": LATE}, result="ok")]
    report = policy_coverage_timeline(START, END, [], rules)
    assert [point["at"] for point in report["points"]] == [START, MID, LATE]
    assert report["gaps"] == [
        {"facts": {}, "from": START, "to": MID},
        {"facts": {}, "from": LATE, "to": END},
    ]


def test_gaps_follow_combination_enumeration_order():
    rules = [
        _rule(id="a", **{"from": MID}, when={"x": True}, result="yes"),
        _rule(
            id="b",
            source="org",
            **{"from": LATE},
            when={"y": True},
            result="oui",
        ),
    ]
    report = policy_coverage_timeline(START, END, ["x", "y"], rules)
    assert [gap["facts"] for gap in report["gaps"]] == [
        {"x": False, "y": False},
        {"x": False, "y": True},
        {"x": True, "y": False},
        {"x": True, "y": True},
    ]
    assert report["gaps"][0]["to"] == END
    assert report["gaps"][1]["to"] == LATE
    assert report["gaps"][2]["to"] == MID
    assert report["gaps"][3]["to"] == MID


def test_unchanged_candidate_is_dropped():
    rules = [
        _rule(id="a", ver=2, result="new"),
        _rule(id="a", ver=1, **{"from": MID}, result="old"),
    ]
    report = policy_coverage_timeline(START, END, [], rules)
    # ver 2 stays the retained version at MID, so nothing changes there.
    assert [point["at"] for point in report["points"]] == [START]
    assert report["gaps"] == []


def test_version_change_keeps_point():
    rules = [
        _rule(id="a", ver=1, result="old", **{"to": MID}),
        _rule(id="a", ver=2, **{"from": MID}, result="new"),
    ]
    report = policy_coverage_timeline(START, END, [], rules)
    assert [point["at"] for point in report["points"]] == [START, MID]
    assert report["points"][1]["policy"]["rules"][0]["ver"] == 2


def test_changes_follow_combination_enumeration_order():
    rules = [_rule(id="a", **{"from": MID}, result="ok")]
    report = policy_coverage_timeline(START, END, ["b", "a"], rules)
    assert report["fact_keys"] == ["a", "b"]
    second = report["points"][1]
    assert second["changes"] == [
        {"a": False, "b": False},
        {"a": False, "b": True},
        {"a": True, "b": False},
        {"a": True, "b": True},
    ]


def test_validation():
    rules = [_rule()]
    with pytest.raises(ValueError):
        policy_coverage_timeline("bad", END, [], rules)
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, "bad", [], rules)
    with pytest.raises(ValueError):
        policy_coverage_timeline(END, START, [], rules)
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, "x", rules)
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, ["x", "x"], rules)
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, [""], rules)
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, [f"k{i}" for i in range(13)], rules)
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, [], "not-a-list")
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, [], [_rule(ver=0)])


def test_selected_rule_when_outside_domain_raises():
    rules = [_rule(id="a", **{"from": MID}, when={"y": True}, result="hit")]
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, ["x"], rules)


def test_never_selected_rule_may_reference_outside_keys():
    rules = [
        _rule(id="a", result="ok"),
        _rule(
            id="b",
            **{"from": "2030-01-01T00:00:00Z"},
            when={"z": True},
            result="future",
        ),
    ]
    report = policy_coverage_timeline(START, END, ["x"], rules)
    assert report["gaps"] == []


def test_inputs_are_not_mutated():
    rules = [_rule(id="a", **{"from": MID}, when={"x": True}, result="hit")]
    fact_keys = ["x"]
    snapshot = copy.deepcopy((fact_keys, rules))
    policy_coverage_timeline(START, END, fact_keys, rules)
    assert (fact_keys, rules) == snapshot


def test_result_containers_are_not_shared():
    rules = [_rule(id="a", **{"from": MID}, when={"x": True}, result="hit")]
    report = policy_coverage_timeline(START, END, ["x"], rules)
    report["points"][1]["coverage"]["cases"][0]["facts"]["x"] = "mutated"
    report["points"][1]["changes"][0]["x"] = "mutated"
    report["gaps"][0]["facts"]["x"] = "mutated"
    again = policy_coverage_timeline(START, END, ["x"], rules)
    assert again["points"][1]["coverage"]["cases"][0]["facts"] == {"x": False}
    assert again["points"][1]["changes"] == [{"x": True}]
    assert again["gaps"][0]["facts"] == {"x": False}


def test_equal_inputs_yield_byte_identical_json():
    rules_a = [
        _rule(id="a", **{"from": MID}, when={"x": True, "y": False}, result="hit"),
        _rule(id="b", source="org", priority=3, result="org"),
    ]
    rules_b = [dict(reversed(list(r.items()))) for r in reversed(rules_a)]
    first = policy_coverage_timeline(START, END, ["y", "x"], rules_a)
    second = policy_coverage_timeline(START, END, ["x", "y"], rules_b)
    dump = lambda v: json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    assert dump(first) == dump(second)


def _post(body):
    return TestClient(app).post(
        "/rules/coverage/timeline",
        content=json.dumps(body),
        headers={"Content-Type": "application/json"},
    )


def test_endpoint_success_compact_utf8():
    rules = [_rule(id="régle", **{"from": MID}, when={"clé": True}, result="oui")]
    response = _post(
        {"start": START, "end": END, "fact_keys": ["clé"], "rules": rules}
    )
    assert response.status_code == 200
    raw = response.content
    assert not raw.endswith(b"\n")
    assert "régle".encode("utf-8") in raw  # non-ASCII not escaped
    assert b"\\u" not in raw
    assert b", " not in raw and b": " not in raw  # compact separators
    payload = json.loads(raw)
    assert list(payload) == ["start", "end", "fact_keys", "points", "gaps"]
    assert [point["at"] for point in payload["points"]] == [START, MID]
    assert payload["gaps"] == [
        {"facts": {"clé": False}, "from": START, "to": END},
        {"facts": {"clé": True}, "from": START, "to": MID},
    ]


def test_endpoint_rejects_bad_requests():
    client = TestClient(app)
    bad = client.post(
        "/rules/coverage/timeline", content=b"{not json",
        headers={"Content-Type": "application/json"},
    )
    assert bad.status_code == 422
    assert bad.json() == {"detail": "invalid request"}

    for body in (
        [],
        {"start": START, "end": END, "fact_keys": []},  # missing rules
        {
            "start": START,
            "end": END,
            "fact_keys": [],
            "rules": [],
            "extra": 1,
        },
        {"start": END, "end": START, "fact_keys": [], "rules": []},
        {"start": START, "end": END, "fact_keys": ["x", "x"], "rules": []},
        {"start": "bad", "end": END, "fact_keys": [], "rules": []},
        {
            "start": START,
            "end": END,
            "fact_keys": ["x"],
            "rules": [_rule(id="a", when={"y": True}, result="hit")],
        },
    ):
        response = _post(body)
        assert response.status_code == 422
        assert response.json() == {"detail": "invalid request"}
