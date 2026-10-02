import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import decision_journey, explain

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
LATE = "2021-03-01T00:00:00Z"
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


def _journey_rules():
    return [
        _rule(
            id="a",
            priority=5,
            **{"from": START},
            when={"x": True},
            result="允许",
        ),
        _rule(id="b", priority=1, **{"from": MID, "to": LATE}, result="deny"),
    ]


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


# ---------------------------------------------------------------- function


def test_top_level_and_point_key_order():
    report = decision_journey(START, END, {"x": True}, [], _journey_rules())
    assert list(report) == ["start", "end", "initial_facts", "points"]
    assert report["start"] == START
    assert report["end"] == END
    assert report["initial_facts"] == {"x": True}
    for point in report["points"]:
        assert list(point) == [
            "at",
            "facts",
            "decision",
            "trace",
            "basis",
            "conflicts",
            "causes",
            "changes",
        ]
        assert list(point["changes"]) == ["facts", "explanation"]


def test_empty_events_and_rules_are_valid():
    report = decision_journey(START, END, {}, [], [])
    assert report["points"] == [
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
    ]


def test_journey_across_events_and_rule_boundaries():
    rules = _journey_rules()
    events = [
        {"at": "2021-01-15T00:00:00Z", "set": {"y": False}, "unset": ["x"]},
    ]
    report = decision_journey(START, END, {"x": True}, events, rules)

    points = report["points"]
    assert [point["at"] for point in points] == [
        START,
        "2021-01-15T00:00:00Z",
        MID,
        LATE,
    ]

    first = points[0]
    assert first["facts"] == {"x": True}
    assert first["decision"] == "允许"
    assert first["trace"] == ["a@1"]
    assert first["basis"]["id"] == "a"
    assert first["causes"] == ["start"]
    assert first["changes"] == {"facts": [], "explanation": []}

    event_point = points[1]
    assert event_point["facts"] == {"y": False}
    assert event_point["decision"] is None
    assert event_point["trace"] == []
    assert event_point["basis"] is None
    assert event_point["causes"] == ["facts"]
    assert event_point["changes"] == {
        "facts": ["x", "y"],
        "explanation": ["decision", "trace", "basis"],
    }

    boundary = points[2]
    assert boundary["decision"] == "deny"
    assert boundary["trace"] == ["b@1"]
    assert boundary["causes"] == ["rules"]
    assert boundary["changes"] == {
        "facts": [],
        "explanation": ["decision", "trace", "basis", "conflicts"],
    }

    expiry = points[3]
    assert expiry["decision"] is None
    assert expiry["causes"] == ["rules"]
    assert expiry["changes"]["explanation"] == ["decision", "trace", "basis", "conflicts"]


def test_event_and_boundary_coincidence_lists_both_causes():
    rules = _journey_rules()
    events = [{"at": MID, "set": {"z": True}, "unset": []}]
    report = decision_journey(START, END, {}, events, rules)
    point = report["points"][1]
    assert point["at"] == MID
    assert point["causes"] == ["facts", "rules"]
    assert point["changes"]["facts"] == ["z"]
    assert point["decision"] == "deny"


def test_noop_event_point_is_omitted():
    rules = [_rule()]
    events = [{"at": MID, "set": {"x": True}, "unset": ["missing"]}]
    report = decision_journey(START, END, {"x": True}, events, rules)
    assert [point["at"] for point in report["points"]] == [START]


def test_unchanged_rule_boundary_point_is_omitted():
    rules = [
        _rule(id="a", **{"from": "2020-01-01T00:00:00Z"}),
        _rule(id="b", **{"from": MID}, result="allow"),
    ]
    report = decision_journey(START, END, {}, [], rules)
    # b matches too from MID on, so the trace changes and the point stays.
    assert [point["at"] for point in report["points"]] == [START, MID]
    # With b absent from the candidate range nothing else appears.
    report = decision_journey(START, MID, {}, [], [_rule()])
    assert [point["at"] for point in report["points"]] == [START]


def test_explanation_fields_match_explain():
    rules = _journey_rules()
    facts = {"x": True}
    report = decision_journey(START, END, facts, [], rules)
    for point in report["points"]:
        current = explain(point["at"], point["facts"], rules)
        for field in ("at", "decision", "trace", "basis", "conflicts"):
            assert point[field] == current[field]


def test_fact_keys_sorted_by_code_point():
    report = decision_journey(
        START, END, {"b": True, "A": False, "ä": True}, [], []
    )
    assert list(report["initial_facts"]) == ["A", "b", "ä"]
    assert list(report["points"][0]["facts"]) == ["A", "b", "ä"]


def test_equal_inputs_ignore_key_rule_and_event_order():
    rules = _journey_rules()
    events = [
        {"at": "2021-01-15T00:00:00Z", "set": {"y": False}, "unset": ["x"]},
        {"at": MID, "set": {"z": True}, "unset": []},
    ]
    base = decision_journey(START, END, {"x": True}, events, rules)
    shuffled = decision_journey(
        START,
        END,
        {"x": True},
        list(reversed(events)),
        list(reversed(rules)),
    )
    assert base == shuffled


def test_inputs_are_not_mutated():
    rules = _journey_rules()
    events = [
        {"at": "2021-01-15T00:00:00Z", "set": {"y": False}, "unset": ["x"]},
    ]
    facts = {"x": True}
    snapshot = copy.deepcopy((rules, events, facts))
    decision_journey(START, END, facts, events, rules)
    assert (rules, events, facts) == snapshot


def test_result_is_a_deep_copy():
    rules = _journey_rules()
    report = decision_journey(START, END, {"x": True}, [], rules)
    report["points"][0]["facts"]["x"] = False
    report["points"][0]["basis"]["id"] = "mutated"
    again = decision_journey(START, END, {"x": True}, [], rules)
    assert again["points"][0]["facts"] == {"x": True}
    assert again["points"][0]["basis"]["id"] == "a"


# ------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "start, end",
    [
        ("not-a-time", END),
        (START, "2021-13-01T00:00:00Z"),
        (END, START),
    ],
)
def test_invalid_time_range_rejected(start, end):
    with pytest.raises(ValueError):
        decision_journey(start, end, {}, [], [])


@pytest.mark.parametrize(
    "events",
    [
        "not-a-list",
        [{"at": MID, "set": {}}],
        [{"at": MID, "set": {}, "unset": [], "extra": 1}],
        [{"at": START, "set": {}, "unset": []}],
        [{"at": "2020-12-31T23:59:59Z", "set": {}, "unset": []}],
        [{"at": "2021-04-01T00:00:01Z", "set": {}, "unset": []}],
        [{"at": "not-a-time", "set": {}, "unset": []}],
        [
            {"at": MID, "set": {}, "unset": []},
            {"at": MID, "set": {}, "unset": []},
        ],
        [{"at": MID, "set": {"x": "yes"}, "unset": []}],
        [{"at": MID, "set": {"": True}, "unset": []}],
        [{"at": MID, "set": "nope", "unset": []}],
        [{"at": MID, "set": {}, "unset": "x"}],
        [{"at": MID, "set": {}, "unset": [""]}],
        [{"at": MID, "set": {}, "unset": [1]}],
        [{"at": MID, "set": {}, "unset": ["x", "x"]}],
        [{"at": MID, "set": {"x": True}, "unset": ["x"]}],
    ],
)
def test_invalid_events_rejected(events):
    with pytest.raises(ValueError):
        decision_journey(START, END, {}, events, [])


def test_invalid_facts_and_rules_rejected():
    with pytest.raises(ValueError):
        decision_journey(START, END, {"x": 1}, [], [])
    with pytest.raises(ValueError):
        decision_journey(START, END, {}, [], [{"id": "broken"}])


def test_event_at_end_is_allowed():
    report = decision_journey(
        START,
        END,
        {},
        [{"at": END, "set": {"x": True}, "unset": []}],
        [],
    )
    assert [point["at"] for point in report["points"]] == [START, END]
    assert report["points"][1]["causes"] == ["facts"]


# ---------------------------------------------------------------- endpoint


def test_endpoint_round_trip_compact_utf8():
    payload = _payload(
        initial_facts={"x": True},
        events=[{"at": "2021-01-15T00:00:00Z", "set": {"y": False}, "unset": ["x"]}],
        rules=_journey_rules(),
    )
    response = client.post("/decision-journey", json=payload)
    assert response.status_code == 200
    body = response.content
    assert not body.endswith(b"\n")
    assert "允许".encode("utf-8") in body
    expected = decision_journey(
        START,
        END,
        {"x": True},
        [{"at": "2021-01-15T00:00:00Z", "set": {"y": False}, "unset": ["x"]}],
        _journey_rules(),
    )
    assert body == json.dumps(
        expected, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        _payload(extra=1),
        _payload(start="nope"),
        _payload(end="2020-01-01T00:00:00Z"),
        _payload(initial_facts={"x": 1}),
        _payload(events=[{"at": MID, "set": {}, "unset": [], "x": 1}]),
        _payload(events=[{"at": MID, "set": {}, "unset": ["a", "a"]}]),
        _payload(rules=[{"id": "broken"}]),
    ],
)
def test_endpoint_invalid_payloads_422(payload):
    response = client.post("/decision-journey", json=payload)
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_endpoint_malformed_json_422():
    response = client.post(
        "/decision-journey",
        content=b"{not json",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}
