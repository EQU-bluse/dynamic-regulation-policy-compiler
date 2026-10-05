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

START = "2020-06-01T00:00:00Z"
MID_OUT = "2021-01-01T00:00:00Z"
MID_IN = "2021-06-01T00:00:00Z"
LATE_OUT = "2021-09-01T00:00:00Z"
END = "2022-01-01T00:00:00Z"


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


def _window_rules():
    return [
        _rule(id="r1", to=MID_OUT, when={"x": True}, result="allow"),
        _rule(id="r2", **{"from": MID_IN}, when=None, result="allow"),
    ]


def test_top_level_and_point_key_order():
    report = policy_coverage_timeline(START, END, ["x"], _window_rules())
    assert list(report) == ["start", "end", "fact_keys", "points", "gaps"]
    assert report["start"] == START
    assert report["end"] == END
    assert report["fact_keys"] == ["x"]
    for point in report["points"]:
        assert list(point) == ["at", "policy", "coverage", "changes"]
    for gap in report["gaps"]:
        assert list(gap) == ["facts", "from", "to"]


def test_points_policy_and_coverage_match_single_shot_functions():
    rules = _window_rules()
    report = policy_coverage_timeline(START, END, ["x"], rules)
    assert [point["at"] for point in report["points"]] == [START, MID_OUT, MID_IN]
    for point in report["points"]:
        assert point["policy"] == compile_rules(point["at"], rules)
        assert point["coverage"] == policy_coverage(point["at"], ["x"], rules)


def test_changes_list_changed_facts_in_enumeration_order():
    report = policy_coverage_timeline(START, END, ["x"], _window_rules())
    first, second, third = report["points"]
    assert first["changes"] == []
    # r1 expires: only the x=True combination changes (allow -> null).
    assert second["changes"] == [{"x": True}]
    # r2 appears: both combinations change (null -> allow).
    assert third["changes"] == [{"x": False}, {"x": True}]


def test_changes_follow_full_enumeration_order_with_two_keys():
    rules = [_rule(to=MID_OUT, when={"a": True}, result="allow")]
    report = policy_coverage_timeline(START, END, ["a", "b"], rules)
    assert [point["at"] for point in report["points"]] == [START, MID_OUT]
    assert report["points"][1]["changes"] == [
        {"a": True, "b": False},
        {"a": True, "b": True},
    ]


def test_gaps_report_null_decision_intervals():
    report = policy_coverage_timeline(START, END, ["x"], _window_rules())
    assert report["gaps"] == [
        # x=False is undecided until r2 appears at MID_IN.
        {"facts": {"x": False}, "from": START, "to": MID_IN},
        # x=True loses its decision when r1 expires, regains it at MID_IN.
        {"facts": {"x": True}, "from": MID_OUT, "to": MID_IN},
    ]


def test_gaps_ordered_by_combination_then_from_and_closed_at_end():
    rules = [
        _rule(id="r1", to=MID_OUT, when={"x": True}, result="allow"),
        _rule(
            id="r2",
            **{"from": MID_IN, "to": LATE_OUT},
            when={"x": True},
            result="allow",
        ),
    ]
    report = policy_coverage_timeline(START, END, ["x"], rules)
    assert report["gaps"] == [
        # x=False is never decided: the gap runs to end (inclusive).
        {"facts": {"x": False}, "from": START, "to": END},
        {"facts": {"x": True}, "from": MID_OUT, "to": MID_IN},
        {"facts": {"x": True}, "from": LATE_OUT, "to": END},
    ]


def test_unchanged_candidate_point_is_dropped():
    rules = [
        _rule(id="a", ver=1, **{"from": "2019-01-01T00:00:00Z", "to": MID_IN},
              result="old"),
        _rule(id="a", ver=2, result="new"),
    ]
    # a@1's `to` is a candidate, but a@2 supersedes it throughout the range,
    # so nothing changes at MID_IN and the point is dropped.
    report = policy_coverage_timeline(START, END, ["x"], rules)
    assert [point["at"] for point in report["points"]] == [START]
    assert report["gaps"] == []


def test_start_equals_end_yields_single_snapshot():
    report = policy_coverage_timeline(START, START, ["x"], [])
    assert [point["at"] for point in report["points"]] == [START]
    assert report["points"][0]["changes"] == []
    assert report["gaps"] == [
        {"facts": {"x": False}, "from": START, "to": START},
        {"facts": {"x": True}, "from": START, "to": START},
    ]


def test_empty_fact_keys_and_empty_rules():
    report = policy_coverage_timeline(START, END, [], [])
    assert report["fact_keys"] == []
    assert len(report["points"]) == 1
    point = report["points"][0]
    assert point["at"] == START
    assert len(point["coverage"]["cases"]) == 1
    assert point["coverage"]["cases"][0]["facts"] == {}
    assert report["gaps"] == [{"facts": {}, "from": START, "to": END}]


def test_empty_rules_produce_full_range_gap():
    report = policy_coverage_timeline(START, END, ["x"], [])
    assert report["gaps"] == [
        {"facts": {"x": False}, "from": START, "to": END},
        {"facts": {"x": True}, "from": START, "to": END},
    ]


def test_time_and_ordering_validation():
    rules = _window_rules()
    with pytest.raises(ValueError):
        policy_coverage_timeline("not-a-time", END, ["x"], rules)
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, "2021-13-01T00:00:00Z", ["x"], rules)
    with pytest.raises(ValueError):
        policy_coverage_timeline(END, START, ["x"], rules)


def test_fact_keys_validation():
    rules = _window_rules()
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, "x", rules)
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, [""], rules)
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, [None], rules)
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, ["x", "x"], rules)
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, [f"k{i}" for i in range(13)], rules)
    # twelve keys are accepted
    report = policy_coverage_timeline(
        START, END, [f"k{i}" for i in range(12)], [_rule()]
    )
    assert report["points"][0]["coverage"]["summary"]["total"] == 4096


def test_rules_validation_matches_compile_rules():
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, [], "not-a-list")
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, [], [_rule(ver=0)])
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, [], [_rule(), _rule()])


def test_selected_rule_when_outside_domain_raises():
    rules = [_rule(id="a", when={"y": True}, result="hit")]
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, ["x"], rules)


def test_rule_selected_only_mid_range_when_outside_domain_raises():
    rules = [
        _rule(id="a", **{"from": MID_IN}, when={"y": True}, result="hit"),
    ]
    with pytest.raises(ValueError):
        policy_coverage_timeline(START, END, ["x"], rules)


def test_never_selected_rule_may_reference_outside_keys():
    rules = [
        _rule(id="a", ver=1, when={"y": True}, result="old"),
        _rule(id="a", ver=2, when=None, result="new"),
        _rule(
            id="b",
            **{"from": "2023-01-01T00:00:00Z"},
            when={"z": True},
            result="future",
        ),
    ]
    report = policy_coverage_timeline(START, END, ["x"], rules)
    assert report["points"][0]["policy"]["rules"][0]["id"] == "a"
    assert report["gaps"] == []


def test_inputs_are_not_mutated():
    rules = _window_rules()
    fact_keys = ["x"]
    snapshot = copy.deepcopy((fact_keys, rules))
    policy_coverage_timeline(START, END, fact_keys, rules)
    assert (fact_keys, rules) == snapshot


def test_result_containers_are_not_shared():
    rules = _window_rules()
    report = policy_coverage_timeline(START, END, ["x"], rules)
    again = policy_coverage_timeline(START, END, ["x"], rules)
    # Mutating the report must not leak into a fresh call...
    report["points"][1]["changes"][0]["x"] = "mutated"
    report["gaps"][0]["facts"]["x"] = "mutated"
    report["points"][0]["coverage"]["cases"][0]["facts"]["x"] = "mutated"
    fresh = policy_coverage_timeline(START, END, ["x"], rules)
    assert fresh == again
    # ...and the changes/gaps facts must not alias the coverage case facts.
    point = again["points"][1]
    assert point["changes"][0] == {"x": True}
    assert point["coverage"]["cases"][1]["facts"] == {"x": True}
    assert again["gaps"][0]["facts"] == {"x": False}


def test_equal_inputs_yield_byte_identical_json():
    rules_a = [
        _rule(id="r1", to=MID_OUT, when={"x": True, "y": False}, result="hit"),
        _rule(id="r2", source="org", priority=3, **{"from": MID_IN}),
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
    rules = [_rule(id="régle", when={"clé": True}, result="oui")]
    body = {"start": START, "end": END, "fact_keys": ["clé"], "rules": rules}
    response = _post(body)
    assert response.status_code == 200
    raw = response.content
    assert not raw.endswith(b"\n")
    assert "régle".encode("utf-8") in raw  # non-ASCII not escaped
    assert b"\\u" not in raw
    assert b", " not in raw and b": " not in raw  # compact separators
    payload = json.loads(raw)
    assert list(payload) == ["start", "end", "fact_keys", "points", "gaps"]
    assert payload["fact_keys"] == ["clé"]
    assert payload["gaps"] == [
        {"facts": {"clé": False}, "from": START, "to": END}
    ]


def test_endpoint_rejects_bad_requests():
    client = TestClient(app)
    bad = client.post(
        "/rules/coverage/timeline", content=b"{not json",
        headers={"Content-Type": "application/json"},
    )
    assert bad.status_code == 422
    assert bad.json() == {"detail": "invalid request"}

    valid = {"start": START, "end": END, "fact_keys": ["x"], "rules": []}
    bodies = [
        [],
        {"start": START, "end": END, "fact_keys": ["x"]},  # missing rules
        valid | {"extra": 1},
        valid | {"end": START, "start": END},  # start after end
        valid | {"fact_keys": ["x", "x"]},
        valid | {"fact_keys": [f"k{i}" for i in range(13)]},
        valid | {"start": "bad"},
        valid
        | {"rules": [_rule(id="a", when={"y": True}, result="hit")]},
    ]
    for body in bodies:
        response = _post(body)
        assert response.status_code == 422
        assert response.json() == {"detail": "invalid request"}
