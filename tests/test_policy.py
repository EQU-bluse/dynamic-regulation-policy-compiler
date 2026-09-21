import pytest

from regulation_policy_compiler.policy import evaluate


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


def test_no_match_returns_none_and_empty_trace():
    assert evaluate("2021-06-01T00:00:00Z", {}, []) == (None, [])


def test_interval_is_half_open():
    rules = [_rule(**{"from": "2021-01-01T00:00:00Z", "to": "2022-01-01T00:00:00Z"})]
    assert evaluate("2021-01-01T00:00:00Z", {}, rules)[0] == "allow"
    assert evaluate("2022-01-01T00:00:00Z", {}, rules) == (None, [])
    assert evaluate("2020-12-31T23:59:59Z", {}, rules) == (None, [])


def test_latest_version_wins_per_source_and_id():
    rules = [
        _rule(ver=1, result="old"),
        _rule(ver=2, result="new"),
        _rule(id="r1", ver=3, source="org", result="org-new", priority=99),
    ]
    decision, trace = evaluate("2021-06-01T00:00:00Z", {}, rules)
    assert decision == "new"  # law ranks before org
    assert trace == ["r1@2", "r1@3"]


def test_when_requires_all_keys_matching():
    rules = [
        _rule(id="a", when={"x": True}, result="a", priority=1),
        _rule(id="b", when={"x": False}, result="b", priority=2),
        _rule(id="c", when={"missing": True}, result="c", priority=3),
    ]
    decision, trace = evaluate("2021-06-01T00:00:00Z", {"x": True}, rules)
    assert decision == "a"
    assert trace == ["a@1"]


def test_ordering_priority_from_id_ver():
    rules = [
        _rule(id="b", priority=5, result="b"),
        _rule(id="a", priority=5, result="a"),
        _rule(id="c", priority=9, result="c", **{"from": "2020-06-01T00:00:00Z"}),
        _rule(id="d", priority=9, result="d", **{"from": "2021-01-01T00:00:00Z"}),
        _rule(id="e", source="org", priority=99, result="e"),
    ]
    decision, trace = evaluate("2021-06-01T00:00:00Z", {}, rules)
    assert decision == "d"
    assert trace == ["d@1", "c@1", "a@1", "b@1", "e@1"]


@pytest.mark.parametrize(
    "at",
    [
        "2021-6-1T00:00:00Z",
        "2021-06-01 00:00:00Z",
        "2021-06-01T00:00:00+00:00",
        "2021-02-30T00:00:00Z",
        "2021-13-01T00:00:00Z",
        "2021-06-01T24:00:00Z",
        "",
        123,
        None,
    ],
)
def test_invalid_at_raises(at):
    with pytest.raises(ValueError):
        evaluate(at, {}, [])


@pytest.mark.parametrize(
    "facts",
    [
        {"": True},
        {"x": 1},
        {"x": None},
        {1: True},
        ["x"],
    ],
)
def test_invalid_facts_raise(facts):
    with pytest.raises(ValueError):
        evaluate("2021-06-01T00:00:00Z", facts, [])


@pytest.mark.parametrize(
    "rule",
    [
        _rule(id=""),
        _rule(result=""),
        _rule(ver=0),
        _rule(ver=True),
        _rule(priority=1.5),
        _rule(priority=False),
        _rule(source="court"),
        _rule(**{"from": "2021-01-01"}),
        _rule(to="not-a-time"),
        _rule(**{"from": "2022-01-01T00:00:00Z", "to": "2022-01-01T00:00:00Z"}),
        _rule(**{"from": "2023-01-01T00:00:00Z", "to": "2022-01-01T00:00:00Z"}),
        _rule(when={"": True}),
        _rule(when={"x": 1}),
        _rule(when="x"),
    ],
)
def test_invalid_rule_fields_raise(rule):
    with pytest.raises(ValueError):
        evaluate("2021-06-01T00:00:00Z", {}, [rule])


def test_rule_key_set_must_be_exact():
    with pytest.raises(ValueError):
        evaluate("2021-06-01T00:00:00Z", {}, [_rule(extra=1)])
    incomplete = _rule()
    del incomplete["ver"]
    with pytest.raises(ValueError):
        evaluate("2021-06-01T00:00:00Z", {}, [incomplete])


def test_duplicate_source_id_ver_raises():
    with pytest.raises(ValueError):
        evaluate("2021-06-01T00:00:00Z", {}, [_rule(), _rule()])
    # Same id/ver but different source is allowed.
    rules = [_rule(), _rule(source="org")]
    decision, _ = evaluate("2021-06-01T00:00:00Z", {}, rules)
    assert decision == "allow"


def test_rules_must_be_a_list():
    with pytest.raises(ValueError):
        evaluate("2021-06-01T00:00:00Z", {}, {})
