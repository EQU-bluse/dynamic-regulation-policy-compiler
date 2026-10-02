import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import decision_journey, explain

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


def _event(at, set_map=None, unset=None):
    return {"at": at, "set": set_map or {}, "unset": unset or []}


def _payload(**overrides):
    payload = {
        "start": START,
        "end": END,
        "initial_facts": {},
        "events": [],
        "rules": [],
    }
    payload.update(overrides)
    return payload


def test_empty_events_and_rules_are_valid():
    report = decision_journey(START, END, {}, [], [])
    assert report == {
        "start": START,
        "end": END,
        "initial_facts": {},
        "points": [
            {
                "at": START,
                "facts": {},
                "decision": None,
                "trace": [],
                "basis": None,
                "conflicts": [],
                "causes": ["start"],
                "changes": {"facts": [], "explanation": []},
            }
        ],
    }


def test_event_updates_facts_and_decision():
    rules = [
        _rule(id="a", priority=5, when={"x": True}, result="允许"),
        _rule(id="b", priority=1, result="deny"),
    ]
    report = decision_journey(
        START, END, {}, [_event(MID, {"x": True})], rules
    )
    assert [point["at"] for point in report["points"]] == [START, MID]
    first, second = report["points"]
    assert first["decision"] == "deny"
    assert first["causes"] == ["start"]
    assert first["changes"] == {"facts": [], "explanation": []}
    assert second["facts"] == {"x": True}
    assert second["decision"] == "允许"
    assert second["causes"] == ["facts"]
    assert second["changes"] == {
        "facts": ["x"],
        "explanation": ["decision", "trace", "basis"],
    }


def test_unset_removes_facts():
    rules = [_rule(id="a", when={"y": False}, result="hit")]
    events = [_event(MID, {"y": False}, ["x"])]
    report = decision_journey(
        START, END, {"x": True, "z": True}, events, rules
    )
    assert [point["at"] for point in report["points"]] == [START, MID]
    second = report["points"][1]
    assert second["facts"] == {"y": False, "z": True}
    assert second["decision"] == "hit"
    assert second["changes"]["facts"] == ["x", "y"]


def test_rule_boundaries_and_events_coincide():
    rules = [
        _rule(id="a", **{"from": MID}, when={"x": True}, result="hit"),
    ]
    report = decision_journey(START, END, {}, [_event(MID, {"x": True})], rules)
    assert [point["at"] for point in report["points"]] == [START, MID]
    second = report["points"][1]
    assert second["causes"] == ["facts", "rules"]
    assert second["decision"] == "hit"


def test_rule_only_boundary_has_rules_cause():
    rules = [
        _rule(id="a", result="first"),
        _rule(id="b", priority=9, **{"from": MID}, result="second"),
    ]
    report = decision_journey(START, END, {}, [], rules)
    assert [point["at"] for point in report["points"]] == [START, MID]
    assert report["points"][1]["causes"] == ["rules"]
    assert report["points"][1]["decision"] == "second"
    assert report["points"][1]["changes"] == {
        "facts": [],
        "explanation": ["decision", "trace", "basis", "conflicts"],
    }


def test_no_change_candidates_are_omitted():
    rules = [
        _rule(id="a", result="same"),
        # Becomes effective at MID but never matches and ties a's result,
        # so the explanation is untouched; the event re-sets an equal fact.
        _rule(id="b", priority=1, **{"from": MID}, when={"q": True}, result="same"),
    ]
    report = decision_journey(
        START, END, {"x": True}, [_event(MID, {"x": True})], rules
    )
    assert [point["at"] for point in report["points"]] == [START]


def test_change_is_measured_against_previously_kept_point():
    rules = [_rule(id="a", when={"x": True}, result="hit")]
    t1 = "2021-01-15T00:00:00Z"
    t2 = "2021-02-15T00:00:00Z"
    events = [_event(t1, {"x": True}), _event(t2, {}, ["x"])]
    report = decision_journey(START, END, {}, events, rules)
    assert [point["at"] for point in report["points"]] == [START, t1, t2]
    assert report["points"][2]["decision"] is None
    assert report["points"][2]["changes"] == {
        "facts": ["x"],
        "explanation": ["decision", "trace", "basis"],
    }


def test_fact_keys_sorted_by_code_point():
    report = decision_journey(
        START, END, {"b": True, "A": False, "a": True}, [], []
    )
    assert list(report["initial_facts"]) == ["A", "a", "b"]
    assert list(report["points"][0]["facts"]) == ["A", "a", "b"]


def test_explanation_fields_match_explain():
    rules = [
        _rule(id="a", priority=5, when={"x": True}, result="hit"),
        _rule(id="b", priority=1, result="deny"),
    ]
    facts = {"x": True}
    report = decision_journey(START, END, facts, [], rules)
    point = report["points"][0]
    expected = explain(START, facts, rules)
    for field in ("decision", "trace", "basis", "conflicts"):
        assert point[field] == expected[field]


def test_inputs_are_not_mutated():
    facts = {"x": True}
    events = [_event(MID, {"y": False}, ["x"])]
    rules = [_rule(id="a", when={"y": False}, result="hit")]
    snapshot = copy.deepcopy((facts, events, rules))
    decision_journey(START, END, facts, events, rules)
    assert (facts, events, rules) == snapshot


def test_equal_inputs_ignore_original_order():
    rules_a = [
        _rule(id="a", priority=5, when={"x": True}, result="hit"),
        _rule(id="b", priority=1, result="deny"),
    ]
    rules_b = list(reversed(rules_a))
    events_a = [
        _event("2021-01-15T00:00:00Z", {"x": True}),
        _event("2021-02-15T00:00:00Z", {"y": False}),
    ]
    events_b = list(reversed(events_a))
    first = decision_journey(START, END, {"z": True, "m": False}, events_a, rules_a)
    second = decision_journey(START, END, {"m": False, "z": True}, events_b, rules_b)
    assert json.dumps(first, ensure_ascii=False, sort_keys=False) == json.dumps(
        second, ensure_ascii=False, sort_keys=False
    )


@pytest.mark.parametrize(
    "start,end",
    [("not-a-time", END), (START, "2021-13-01T00:00:00Z"), (END, START)],
)
def test_invalid_time_range_raises(start, end):
    with pytest.raises(ValueError):
        decision_journey(start, end, {}, [], [])


@pytest.mark.parametrize(
    "events",
    [
        "not-a-list",
        [{"at": MID, "set": {}}],  # missing unset
        [{"at": MID, "set": {}, "unset": [], "extra": 1}],
        [{"at": START, "set": {}, "unset": []}],  # at not in (start, end]
        [{"at": "2021-05-01T00:00:00Z", "set": {}, "unset": []}],  # after end
        [{"at": "bad", "set": {}, "unset": []}],
        [  # duplicate at
            {"at": MID, "set": {}, "unset": []},
            {"at": MID, "set": {}, "unset": []},
        ],
        [{"at": MID, "set": {"x": "yes"}, "unset": []}],  # non-bool value
        [{"at": MID, "set": {"": True}, "unset": []}],  # empty key
        [{"at": MID, "set": [], "unset": []}],  # set not a dict
        [{"at": MID, "set": {}, "unset": "x"}],  # unset not a list
        [{"at": MID, "set": {}, "unset": [""]}],  # empty unset key
        [{"at": MID, "set": {}, "unset": ["x", "x"]}],  # duplicate unset
        [{"at": MID, "set": {"x": True}, "unset": ["x"]}],  # overlapping keys
    ],
)
def test_invalid_events_raise(events):
    with pytest.raises(ValueError):
        decision_journey(START, END, {}, events, [])


def test_invalid_facts_and_rules_raise():
    with pytest.raises(ValueError):
        decision_journey(START, END, {"x": 1}, [], [])
    with pytest.raises(ValueError):
        decision_journey(START, END, {}, [], [{"id": "broken"}])


def test_endpoint_success_compact_utf8():
    payload = _payload(
        initial_facts={"x": True},
        rules=[_rule(id="a", when={"x": True}, result="允许")],
    )
    response = client.post("/decision-journey", json=payload)
    assert response.status_code == 200
    body = response.content.decode("utf-8")
    assert "允许" in body  # non-ASCII is not escaped
    assert not body.endswith("\n")
    assert '":' in body and '": ' not in body  # compact separators
    report = response.json()
    assert list(report) == ["start", "end", "initial_facts", "points"]
    assert list(report["points"][0]) == [
        "at",
        "facts",
        "decision",
        "trace",
        "basis",
        "conflicts",
        "causes",
        "changes",
    ]


def test_endpoint_matches_function():
    payload = _payload(
        initial_facts={"x": True},
        events=[_event(MID, {}, ["x"])],
        rules=[_rule(id="a", when={"x": True}, result="hit")],
    )
    response = client.post("/decision-journey", json=payload)
    assert response.status_code == 200
    assert response.json() == decision_journey(
        START, END, {"x": True}, [_event(MID, {}, ["x"])], payload["rules"]
    )


@pytest.mark.parametrize(
    "body",
    [
        "not json",
        {},
        _payload(extra=1),
        {k: v for k, v in _payload().items() if k != "events"},
        _payload(start="bad"),
        _payload(events=[{"at": MID, "set": {}, "unset": [], "x": 1}]),
        _payload(events="nope"),
        _payload(initial_facts={"x": 1}),
        _payload(rules={}),
    ],
)
def test_endpoint_invalid_request(body):
    response = client.post(
        "/decision-journey",
        content=body if isinstance(body, str) else json.dumps(body),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}
