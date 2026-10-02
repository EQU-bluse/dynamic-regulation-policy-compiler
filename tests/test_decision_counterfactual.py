import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import decision_counterfactual, explain

client = TestClient(app)

AT = "2021-06-01T00:00:00Z"
FROM = "2020-01-01T00:00:00Z"


def _rule(**overrides):
    rule = {
        "id": "r1",
        "ver": 1,
        "source": "law",
        "priority": 0,
        "from": FROM,
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


def test_zero_distance_returns_single_no_change_scheme():
    rules = [_rule(result="允许")]
    report = decision_counterfactual(AT, {}, "允许", rules)
    assert list(report) == [
        "at",
        "facts",
        "target",
        "explanation",
        "distance",
        "counterfactuals",
    ]
    assert report["at"] == AT
    assert report["facts"] == {}
    assert report["target"] == "允许"
    assert report["distance"] == 0
    assert report["explanation"] == explain(AT, {}, rules)
    assert len(report["counterfactuals"]) == 1
    scheme = report["counterfactuals"][0]
    assert list(scheme) == ["changes", "facts", "explanation"]
    assert scheme["changes"] == []
    assert scheme["facts"] == {}
    assert scheme["explanation"]["decision"] == "允许"


def test_null_target_already_undecided_is_zero_distance():
    report = decision_counterfactual(AT, {}, None, [])
    assert report["distance"] == 0
    assert report["counterfactuals"] == [
        {"changes": [], "facts": {}, "explanation": explain(AT, {}, [])}
    ]
    assert report["explanation"]["decision"] is None


def test_one_step_set_missing_key_to_true():
    rules = [
        _rule(id="allow", priority=10, when={"a": True}, result="allow"),
        _rule(id="deny", priority=1, result="deny"),
    ]
    report = decision_counterfactual(AT, {}, "allow", rules)
    assert report["distance"] == 1
    assert len(report["counterfactuals"]) == 1
    scheme = report["counterfactuals"][0]
    assert scheme["changes"] == [{"key": "a", "before": None, "after": True}]
    assert [list(change) for change in scheme["changes"]] == [
        ["key", "before", "after"]
    ]
    assert scheme["facts"] == {"a": True}
    assert scheme["explanation"] == explain(AT, {"a": True}, rules)
    assert scheme["explanation"]["decision"] == "allow"


def test_flip_or_delete_same_key_ordered_null_then_false():
    rules = [
        _rule(id="allow", priority=10, when={"a": True}, result="allow"),
        _rule(id="deny", priority=1, result="deny"),
    ]
    report = decision_counterfactual(AT, {"a": True}, "deny", rules)
    assert report["distance"] == 1
    assert [scheme["changes"] for scheme in report["counterfactuals"]] == [
        [{"key": "a", "before": True, "after": None}],
        [{"key": "a", "before": True, "after": False}],
    ]


def test_reaching_undecided_by_flip_or_delete():
    rules = [_rule(when={"a": True}, result="allow")]
    report = decision_counterfactual(AT, {"a": True}, None, rules)
    assert report["distance"] == 1
    assert [scheme["changes"] for scheme in report["counterfactuals"]] == [
        [{"key": "a", "before": True, "after": None}],
        [{"key": "a", "before": True, "after": False}],
    ]
    for scheme in report["counterfactuals"]:
        assert scheme["explanation"]["decision"] is None


def test_multiple_minimal_schemes_ordered_by_key_then_tristate():
    rules = [
        _rule(id="a", priority=10, when={"a": True}, result="allow"),
        _rule(id="b", priority=9, when={"b": True}, result="allow"),
        _rule(id="base", priority=1, result="deny"),
    ]
    report = decision_counterfactual(AT, {}, "allow", rules)
    assert report["distance"] == 1
    assert [scheme["changes"] for scheme in report["counterfactuals"]] == [
        [{"key": "a", "before": None, "after": True}],
        [{"key": "b", "before": None, "after": True}],
    ]
    # facts and a full explanation accompany each scheme
    assert report["counterfactuals"][0]["facts"] == {"a": True}
    assert report["counterfactuals"][1]["facts"] == {"b": True}
    assert report["counterfactuals"][0]["explanation"]["basis"]["id"] == "a"
    assert report["counterfactuals"][1]["explanation"]["basis"]["id"] == "b"


def test_multi_change_schemes_ordered_by_first_key_then_rest():
    # Neither one-key change can reach "allow" when both gates must hold;
    # the unique two-step scheme is a=true and b=true.
    rules = [
        _rule(id="both", priority=10, when={"a": True, "b": True}, result="allow"),
        _rule(id="base", priority=1, result="deny"),
    ]
    report = decision_counterfactual(AT, {}, "allow", rules)
    assert report["distance"] == 2
    assert [scheme["changes"] for scheme in report["counterfactuals"]] == [
        [
            {"key": "a", "before": None, "after": True},
            {"key": "b", "before": None, "after": True},
        ]
    ]


def test_longer_schemes_are_excluded_when_a_shorter_one_exists():
    rules = [
        _rule(id="a", priority=10, when={"a": True}, result="allow"),
        _rule(id="bc", priority=9, when={"b": True, "c": True}, result="allow"),
        _rule(id="base", priority=1, result="deny"),
    ]
    report = decision_counterfactual(AT, {}, "allow", rules)
    assert report["distance"] == 1
    assert [scheme["changes"] for scheme in report["counterfactuals"]] == [
        [{"key": "a", "before": None, "after": True}]
    ]


def test_unreachable_target_has_null_distance_and_empty_schemes():
    rules = [_rule(result="deny")]
    report = decision_counterfactual(AT, {}, "allow", rules)
    assert report["explanation"]["decision"] == "deny"
    assert report["distance"] is None
    assert report["counterfactuals"] == []


def test_undecided_unreachable_with_unconditional_rule():
    rules = [_rule(result="deny")]
    report = decision_counterfactual(AT, {}, None, rules)
    assert report["distance"] is None
    assert report["counterfactuals"] == []


def test_non_editable_facts_are_kept_untouched():
    rules = [
        _rule(id="allow", priority=10, when={"a": True}, result="allow"),
        _rule(id="deny", priority=1, result="deny"),
    ]
    facts = {"z": True, "a": False, "keep": False}
    report = decision_counterfactual(AT, facts, "allow", rules)
    assert report["distance"] == 1
    scheme = report["counterfactuals"][0]
    assert scheme["changes"] == [{"key": "a", "before": False, "after": True}]
    assert scheme["facts"] == {"a": True, "keep": False, "z": True}
    assert report["facts"] == {"a": False, "keep": False, "z": True}
    # input untouched
    assert facts == {"z": True, "a": False, "keep": False}


def test_setting_missing_key_to_false_can_matter():
    # Rule matches only when a is absent-or-false and the base rule needs a.
    rules = [
        _rule(id="need-a", priority=10, when={"a": True}, result="deny"),
        _rule(id="default", priority=1, result="allow"),
    ]
    # With a present and true, deny wins; setting a=false lets default win.
    report = decision_counterfactual(AT, {"a": True}, "allow", rules)
    assert report["distance"] == 1
    assert report["counterfactuals"][0]["changes"] == [
        {"key": "a", "before": True, "after": None}
    ]
    # And from undecided facts, setting the missing key false changes matching
    # when a rule requires a == false explicitly.
    rules2 = [
        _rule(id="need-false", priority=10, when={"a": False}, result="allow"),
        _rule(id="default", priority=1, result="deny"),
    ]
    report2 = decision_counterfactual(AT, {}, "allow", rules2)
    assert report2["distance"] == 1
    # before null: after false (rank 1) sorts before after true (rank 2),
    # and only after=false reaches the target.
    assert report2["counterfactuals"][0]["changes"] == [
        {"key": "a", "before": None, "after": False}
    ]


def test_editable_keys_come_only_from_selected_rules():
    rules = [
        _rule(id="r1", ver=1, priority=10, when={"a": True}, result="allow"),
        _rule(id="r1", ver=2, priority=10, when={"b": True}, result="allow"),
        _rule(id="base", result="deny"),
    ]
    # Only r1@2 is selected; flipping "a" must not produce a scheme.
    report = decision_counterfactual(AT, {}, "allow", rules)
    assert report["distance"] == 1
    assert report["counterfactuals"][0]["changes"] == [
        {"key": "b", "before": None, "after": True}
    ]


def test_more_than_twelve_editable_keys_raises():
    when = {f"k{i:02d}": True for i in range(13)}
    rules = [_rule(when=when)]
    with pytest.raises(ValueError):
        decision_counterfactual(AT, {}, "allow", rules)


def test_twelve_editable_keys_is_allowed():
    when = {f"k{i:02d}": True for i in range(12)}
    rules = [
        _rule(id="gated", priority=10, when=when, result="allow"),
        _rule(id="base", result="deny"),
    ]
    report = decision_counterfactual(AT, {}, "allow", rules)
    assert report["distance"] == 12


def test_invalid_target_raises():
    for bad in ("", 1, True, [], {}):
        with pytest.raises(ValueError):
            decision_counterfactual(AT, {}, bad, [])


def test_invalid_time_facts_and_rules_raise():
    with pytest.raises(ValueError):
        decision_counterfactual("not-a-time", {}, "allow", [])
    with pytest.raises(ValueError):
        decision_counterfactual(AT, {"a": 1}, "allow", [])
    with pytest.raises(ValueError):
        decision_counterfactual(AT, {}, "allow", {})
    with pytest.raises(ValueError):
        decision_counterfactual(AT, {}, "allow", [_rule(ver=0)])


def test_inputs_are_not_mutated():
    rules = [
        _rule(id="allow", priority=10, when={"z": True, "a": False}, result="允许"),
        _rule(id="deny", priority=1, result="deny"),
    ]
    facts = {"z": False, "a": True}
    rules_snapshot = json.loads(json.dumps(rules))
    facts_snapshot = dict(facts)
    report = decision_counterfactual(AT, facts, "允许", rules)
    assert rules == rules_snapshot
    assert facts == facts_snapshot
    # result is an independent deep copy
    report["counterfactuals"][0]["explanation"]["basis"]["id"] = "tampered"
    assert rules[0]["id"] == "allow"


def test_equal_inputs_yield_identical_json_regardless_of_dict_order():
    rules = [
        _rule(id="a", priority=10, when={"a": True}, result="x"),
        _rule(id="b", priority=9, when={"b": True}, result="x"),
        _rule(id="base", priority=1, result="y"),
    ]
    one = decision_counterfactual(AT, {}, "x", rules)
    two = decision_counterfactual(AT, {}, "x", list(reversed(rules)))
    text_one = json.dumps(one, ensure_ascii=False, separators=(",", ":"))
    text_two = json.dumps(two, ensure_ascii=False, separators=(",", ":"))
    assert text_one == text_two
    facts_one = {"z": True, "a": False, "m": True}
    facts_two = {"m": True, "a": False, "z": True}
    text_a = json.dumps(
        decision_counterfactual(AT, facts_one, "x", rules),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    text_b = json.dumps(
        decision_counterfactual(AT, facts_two, "x", rules),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    assert text_a == text_b


# --- HTTP endpoint -------------------------------------------------------


def test_endpoint_zero_distance():
    response = client.post(
        "/decision-counterfactual", json=_payload(rules=[_rule()])
    )
    assert response.status_code == 200
    data = response.json()
    assert data["distance"] == 0
    assert list(data) == [
        "at",
        "facts",
        "target",
        "explanation",
        "distance",
        "counterfactuals",
    ]
    assert data["counterfactuals"][0]["changes"] == []


def test_endpoint_null_target():
    response = client.post(
        "/decision-counterfactual",
        json=_payload(target=None, facts={"a": True}, rules=[_rule(when={"a": True})]),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["target"] is None
    assert data["distance"] == 1
    assert data["counterfactuals"][0]["explanation"]["decision"] is None


def test_endpoint_compact_utf8_without_trailing_newline():
    response = client.post(
        "/decision-counterfactual", json=_payload(rules=[_rule(result="允许")])
    )
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw
    assert "允许" in raw and "\\u" not in raw


def test_endpoint_bad_bodies_are_422():
    bad_bodies = [
        b"not json",
        b"[]",
        b"null",
        b'"x"',
        b"{}",
        json.dumps(_payload(extra=1)).encode(),
        json.dumps({"at": AT, "facts": {}, "rules": []}).encode(),
        json.dumps({"at": AT, "facts": {}, "target": "allow"}).encode(),
    ]
    for raw in bad_bodies:
        response = client.post(
            "/decision-counterfactual",
            content=raw,
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 422, raw
        assert response.json() == {"detail": "invalid request"}


def test_endpoint_validation_failures_are_422():
    cases = [
        _payload(at="not-a-time"),
        _payload(facts={"x": 1}),
        _payload(target=""),
        _payload(target=1),
        _payload(rules={}),
        _payload(rules=[_rule(when={f"k{i}": True for i in range(13)})]),
    ]
    for payload in cases:
        response = client.post("/decision-counterfactual", json=payload)
        assert response.status_code == 422, payload
        assert response.json() == {"detail": "invalid request"}


def test_endpoint_does_not_touch_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def record(self, *args, **kwargs):
            raise AssertionError("counterfactual must not write history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/decision-counterfactual", json=_payload(rules=[_rule()])
    )
    assert response.status_code == 200
    assert response.json()["distance"] == 0
