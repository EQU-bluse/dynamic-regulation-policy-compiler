import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import decision_counterfactual, explain

AT = "2021-06-01T00:00:00Z"

client = TestClient(app)


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
    payload = {"at": AT, "facts": {}, "target": "allow", "rules": []}
    payload.update(overrides)
    return payload


def test_top_level_key_order_and_current_explanation():
    rules = [_rule(when={"a": True}, result="允许")]
    report = decision_counterfactual(AT, {"a": True}, "允许", rules)
    assert list(report) == [
        "at",
        "facts",
        "target",
        "explanation",
        "distance",
        "counterfactuals",
    ]
    assert report["at"] == AT
    assert report["facts"] == {"a": True}
    assert report["target"] == "允许"
    assert report["explanation"] == explain(AT, {"a": True}, rules)


def test_current_decision_equals_target_returns_single_no_change_plan():
    rules = [_rule(result="允许")]
    report = decision_counterfactual(AT, {"z": True, "a": False}, "允许", rules)
    assert report["distance"] == 0
    assert report["counterfactuals"] == [
        {
            "changes": [],
            "facts": {"a": False, "z": True},
            "explanation": explain(AT, {"a": False, "z": True}, rules),
        }
    ]


def test_null_target_when_already_undecided():
    report = decision_counterfactual(AT, {}, None, [])
    assert report["distance"] == 0
    assert report["counterfactuals"] == [
        {"changes": [], "facts": {}, "explanation": explain(AT, {}, [])}
    ]


def test_missing_key_can_be_set_false_or_true_with_state_order():
    rules = [_rule(when={"x": True}, result="deny")]
    report = decision_counterfactual(AT, {}, "deny", rules)
    assert report["distance"] == 1
    (plan,) = report["counterfactuals"]
    assert list(plan) == ["changes", "facts", "explanation"]
    assert plan["changes"] == [{"key": "x", "before": None, "after": True}]
    assert plan["facts"] == {"x": True}
    assert plan["explanation"] == explain(AT, {"x": True}, rules)


def test_existing_key_can_be_deleted_or_flipped_with_null_before_false_true_order():
    rules = [_rule(when={"x": True}, result="allow")]
    report = decision_counterfactual(AT, {"x": True}, None, rules)
    assert report["distance"] == 1
    assert [plan["changes"] for plan in report["counterfactuals"]] == [
        [{"key": "x", "before": True, "after": None}],
        [{"key": "x", "before": True, "after": False}],
    ]
    assert report["counterfactuals"][0]["facts"] == {}
    assert report["counterfactuals"][1]["facts"] == {"x": False}
    for plan in report["counterfactuals"]:
        assert list(plan["changes"][0]) == ["key", "before", "after"]
        assert plan["explanation"]["decision"] is None


def test_all_minimal_plans_returned_and_ordered_by_key_code_point():
    rules = [
        _rule(id="ry", when={"y": True}, result="deny"),
        _rule(id="rx", when={"x": True}, result="deny"),
    ]
    report = decision_counterfactual(AT, {}, "deny", rules)
    assert report["distance"] == 1
    assert [plan["changes"] for plan in report["counterfactuals"]] == [
        [{"key": "x", "before": None, "after": True}],
        [{"key": "y", "before": None, "after": True}],
    ]


def test_changes_sorted_by_code_point_and_only_minimum_plans_kept():
    # Neither single edit reaches "deny": x and y must both be true; any
    # assignment setting both (plus arbitrary extra states) is distance 2.
    rules = [_rule(when={"x": True, "y": True}, result="deny")]
    report = decision_counterfactual(AT, {"x": False}, "deny", rules)
    assert report["distance"] == 2
    change_sets = [
        [(c["key"], c["before"], c["after"]) for c in plan["changes"]]
        for plan in report["counterfactuals"]
    ]
    assert change_sets == [
        [("x", False, True), ("y", None, True)]
    ]
    for plan in report["counterfactuals"]:
        keys = [c["key"] for c in plan["changes"]]
        assert keys == sorted(keys)
        assert plan["explanation"]["decision"] == "deny"


def test_unreachable_target_has_null_distance_and_empty_plans():
    # Unconditional allow always wins over the lower-priority deny.
    rules = [_rule(result="allow"), _rule(id="d", priority=-1, when={"x": True}, result="deny")]
    report = decision_counterfactual(AT, {}, "deny", rules)
    assert report["distance"] is None
    assert report["counterfactuals"] == []


def test_non_editable_facts_are_preserved_and_excluded_from_changes():
    rules = [_rule(when={"x": True}, result="deny")]
    report = decision_counterfactual(AT, {"x": True, "keep": False}, None, rules)
    assert report["facts"] == {"keep": False, "x": True}
    for plan in report["counterfactuals"]:
        assert plan["facts"].get("keep") is False
        assert all(c["key"] == "x" for c in plan["changes"])


def test_editable_keys_come_only_from_selected_rules_whens():
    # Only the latest version of r1 is selected; the older when key and
    # the out-of-window rule key are not editable.
    rules = [
        _rule(id="r1", ver=2, when={"x": True}, result="deny"),
        _rule(id="r1", ver=1, when={"old": True}, result="deny"),
        _rule(
            id="future",
            when={"later": True},
            result="deny",
            **{"from": "2030-01-01T00:00:00Z"},
        ),
    ]
    report = decision_counterfactual(AT, {"old": True}, "deny", rules)
    # Setting old cannot help: only x is editable. One-step plan sets x.
    assert report["distance"] == 1
    assert report["counterfactuals"][0]["changes"] == [
        {"key": "x", "before": None, "after": True}
    ]
    assert report["counterfactuals"][0]["facts"] == {"old": True, "x": True}


def test_inputs_are_not_mutated():
    facts = {"z": True, "a": False}
    facts_snapshot = copy.deepcopy(facts)
    rules = [_rule(when={"a": True}, result="deny")]
    rules_snapshot = copy.deepcopy(rules)
    decision_counterfactual(AT, facts, "deny", rules)
    assert facts == facts_snapshot
    assert rules == rules_snapshot


def test_equal_inputs_identical_regardless_of_dict_order():
    rules = [
        _rule(id="b", when={"z": True, "a": False}, result="deny"),
    ]
    r1 = decision_counterfactual(AT, {"z": True}, "deny", rules)
    r2 = decision_counterfactual(AT, {"z": True}, "deny", copy.deepcopy(rules))
    assert json.dumps(r1, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        r2, ensure_ascii=False, separators=(",", ":")
    )


def test_more_than_twelve_editable_keys_raises():
    rules = [
        _rule(id=f"r{i}", when={f"k{i}": True}, result="deny") for i in range(13)
    ]
    with pytest.raises(ValueError):
        decision_counterfactual(AT, {}, "deny", rules)


def test_matches_independent_brute_force_ternary_enumeration():
    import itertools

    from regulation_policy_compiler.policy import explain

    # Independent reference: enumerate the full ternary space directly and
    # verify the function returns exactly the minimum-distance plans.
    rules = [
        _rule(id="a", priority=2, when={"a": True}, result="allow"),
        _rule(id="b", priority=1, when={"a": False, "b": True}, result="deny"),
        _rule(id="c", source="org", priority=9, when={"b": False}, result="允许"),
    ]
    keys = ["a", "b", "c"]
    for target in ("allow", "deny", "允许", "never", None):
        for initial_tuple in itertools.product((None, False, True), repeat=3):
            initial = {
                key: value
                for key, value in zip(keys, initial_tuple)
                if value is not None
            }
            # Add a non-editable fact that must be carried through.
            initial_facts = dict(initial)
            initial_facts["zz"] = True
            report = decision_counterfactual(AT, initial_facts, target, rules)

            expected: dict[tuple, dict] = {}
            minimum = None
            for states in itertools.product((None, False, True), repeat=3):
                changed = sum(
                    1 for old, new in zip(initial_tuple, states) if old is not new
                )
                candidate = {
                    key: value
                    for key, value in zip(keys, states)
                    if value is not None
                }
                candidate["zz"] = True
                decision = explain(AT, candidate, rules)["decision"]
                if decision != target:
                    continue
                if minimum is None or changed < minimum:
                    minimum = changed
                expected.setdefault(changed, []).append(states)

            assert report["distance"] == minimum
            if minimum is None:
                assert report["counterfactuals"] == []
                continue
            got_states = []
            for plan in report["counterfactuals"]:
                by_key = {change["key"]: change for change in plan["changes"]}
                got = tuple(
                    by_key[key]["after"] if key in by_key else initial_tuple[i]
                    for i, key in enumerate(keys)
                )
                got_states.append(got)
                assert plan["explanation"] == explain(
                    AT, plan["facts"], rules
                )
                assert plan["facts"] == {
                    key: value
                    for key, value in zip(keys, got)
                    if value is not None
                } | {"zz": True}
            assert set(got_states) == set(expected[minimum])
            assert len(got_states) == len(set(got_states))


def test_twelve_editable_keys_is_allowed():
    rules = [
        _rule(id=f"r{i}", when={f"k{i}": True}, result="deny") for i in range(12)
    ]
    report = decision_counterfactual(AT, {}, "deny", rules)
    assert report["distance"] == 1


@pytest.mark.parametrize("target", ["", 1, True, False, [], {}])
def test_invalid_target_raises(target):
    with pytest.raises(ValueError):
        decision_counterfactual(AT, {}, target, [_rule()])


@pytest.mark.parametrize(
    "kwargs",
    [
        {"at": "not-a-time"},
        {"facts": {"x": 1}},
        {"facts": []},
        {"rules": {}},
        {"rules": [_rule(ver=0)]},
        {"rules": [_rule(), _rule()]},
        {"rules": [_rule(source="court")]},
    ],
)
def test_invalid_at_facts_rules_raise(kwargs):
    defaults = {"at": AT, "facts": {}, "target": "allow", "rules": [_rule()]}
    defaults.update(kwargs)
    with pytest.raises(ValueError):
        decision_counterfactual(**defaults)


def test_endpoint_success_compact_utf8():
    rules = [_rule(when={"x": True}, result="允许")]
    response = client.post(
        "/decision-counterfactual",
        json=_payload(facts={"x": True}, target=None, rules=rules),
    )
    assert response.status_code == 200
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw
    assert "允许" in raw and "\\u" not in raw
    data = response.json()
    assert list(data) == [
        "at",
        "facts",
        "target",
        "explanation",
        "distance",
        "counterfactuals",
    ]
    assert data["distance"] == 1


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        b"null",
        b'"x"',
        b"{}",
        json.dumps(_payload(extra=1)).encode(),
        json.dumps({"at": AT, "facts": {}, "rules": []}).encode(),
    ],
)
def test_endpoint_bad_bodies_are_422(raw):
    response = client.post(
        "/decision-counterfactual",
        content=raw,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


@pytest.mark.parametrize(
    "payload",
    [
        _payload(at="not-a-time"),
        _payload(facts={"x": 1}),
        _payload(rules=[_rule(ver=0)]),
        _payload(target=""),
        _payload(target=1),
        _payload(
            target="deny",
            rules=[
                _rule(id=f"r{i}", when={f"k{i}": True}, result="deny")
                for i in range(13)
            ],
        ),
    ],
)
def test_endpoint_value_errors_are_422(payload):
    response = client.post("/decision-counterfactual", json=payload)
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_endpoint_does_not_touch_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def record(self, *args, **kwargs):
            raise AssertionError("POST /decision-counterfactual must not write history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/decision-counterfactual", json=_payload(rules=[_rule()])
    )
    assert response.status_code == 200
    assert response.json()["distance"] == 0
