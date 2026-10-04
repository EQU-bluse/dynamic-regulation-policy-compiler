"""Deterministic public-contract tests for versioned rule compile and decision.

These tests exercise only the published entries (``evaluate``, ``explain``,
``compile_rules``, ``DecisionHistory`` and the HTTP adapter) with fixed UTC
timestamps. They pin down that:

* equivalent inputs (rule loading order, object key order, JSON whitespace,
  repeated compilation) yield value-identical products, hit sets, decisions
  and explanations;
* effective-window boundaries, conflict priority and history replay combine
  according to the existing public semantics;
* the exception contract stays the unique documented one (``ValueError`` for
  invalid input, deterministic results otherwise);
* explanations agree with the actual decision path;
* constrained generated scenarios re-check compile idempotence, input
  permutation invariance and record/replay agreement, keeping a directly
  reproducible seed and input on failure.
"""

import copy
import json
import random

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.history import DecisionHistory
from regulation_policy_compiler.policy import compile_rules, evaluate, explain

client = TestClient(app)

# Fixed timestamps; no test reads the current time.
T0 = "2020-01-01T00:00:00Z"
T1 = "2021-01-01T00:00:00Z"
T1_MINUS_1 = "2020-12-31T23:59:59Z"
T2 = "2022-01-01T00:00:00Z"
T2_MINUS_1 = "2021-12-31T23:59:59Z"
T3 = "2023-01-01T00:00:00Z"
MID = "2021-06-01T00:00:00Z"


def _rule(**overrides):
    rule = {
        "id": "r1",
        "ver": 1,
        "source": "law",
        "priority": 0,
        "from": T0,
        "to": None,
        "when": None,
        "result": "allow",
    }
    rule.update(overrides)
    return rule


def _canon(value):
    """Serialize a result value for byte-stability comparison."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _reorderings(rules):
    """Deterministic re-orderings of the same rule list."""
    return [
        list(reversed(rules)),
        rules[2:] + rules[:2],
        sorted(rules, key=lambda r: (r["id"], r["ver"]), reverse=True),
    ]


def _scenario_rules():
    """A fixed rule set mixing versions, sources, windows and conditions."""
    return [
        _rule(id="win", ver=1, priority=5, when={"a": True}, result="old",
              **{"from": T0, "to": T1}),
        _rule(id="win", ver=2, priority=5, when={"a": True}, result="allow",
              **{"from": T1}),
        _rule(id="lose", priority=1, when={"a": True}, result="deny"),
        _rule(id="orgx", source="org", priority=9, when={"a": True}, result="deny"),
        _rule(id="far", priority=9, when={"a": False}, result="far"),
        _rule(id="future", priority=9, result="future", **{"from": T3}),
    ]


class TestEquivalentInputs:
    """Equivalent inputs must produce value-identical public outputs."""

    def test_rule_loading_order_does_not_change_compiled_product(self):
        rules = _scenario_rules()
        expected = compile_rules(MID, rules)
        for permuted in _reorderings(rules):
            compiled = compile_rules(MID, permuted)
            assert compiled == expected
            assert _canon(compiled) == _canon(expected)

    def test_rule_loading_order_does_not_change_decision_or_explanation(self):
        rules = _scenario_rules()
        facts = {"a": True}
        expected_decision = evaluate(MID, facts, rules)
        expected_explanation = explain(MID, facts, rules)
        for permuted in _reorderings(rules):
            assert evaluate(MID, facts, permuted) == expected_decision
            explanation = explain(MID, facts, permuted)
            assert explanation == expected_explanation
            assert _canon(explanation) == _canon(expected_explanation)

    def test_object_key_order_does_not_change_outputs(self):
        base = _rule(id="win", ver=2, priority=5, when={"a": True, "z": False},
                     result="allow", **{"from": T1})
        reordered = {key: base[key] for key in reversed(list(base))}
        reordered["when"] = {"z": False, "a": True}
        shadowed = _rule(id="win", ver=1, result="old", **{"from": T0, "to": T1})
        other = _rule(id="lose", priority=1, when={"a": True}, result="deny")
        rules_a = [base, shadowed, other]
        rules_b = [reordered, shadowed, other]
        facts_a = {"a": True, "z": False}
        facts_b = {"z": False, "a": True}
        assert _canon(compile_rules(MID, rules_a)) == _canon(compile_rules(MID, rules_b))
        assert _canon(explain(MID, facts_a, rules_a)) == _canon(explain(MID, facts_b, rules_b))
        assert evaluate(MID, facts_a, rules_a) == evaluate(MID, facts_b, rules_b)

    def test_repeated_compile_and_explain_are_idempotent_and_do_not_mutate(self):
        rules = _scenario_rules()
        facts = {"a": True}
        rules_snapshot = copy.deepcopy(rules)
        facts_snapshot = copy.deepcopy(facts)
        compiled_first = compile_rules(MID, rules)
        compiled_second = compile_rules(MID, rules)
        assert compiled_first == compiled_second
        assert _canon(compiled_first) == _canon(compiled_second)
        explained_first = explain(MID, facts, rules)
        explained_second = explain(MID, facts, rules)
        assert explained_first == explained_second
        assert _canon(explained_first) == _canon(explained_second)
        # Returned products are deep copies: corrupting them must not poison
        # later calls over the same inputs.
        compiled_first["rules"].append({"junk": True})
        explained_first["trace"].append("junk@1")
        assert compile_rules(MID, rules) == compiled_second
        assert explain(MID, facts, rules) == explained_second
        assert rules == rules_snapshot
        assert facts == facts_snapshot

    def test_http_equivalent_bodies_produce_byte_identical_explanations(self):
        rules = [
            _rule(id="win", ver=2, priority=5, when={"a": True}, result="允许",
                  **{"from": T1}),
            _rule(id="lose", priority=1, when={"a": True}, result="拒绝"),
        ]
        payload = {"at": MID, "facts": {"a": True}, "rules": rules}
        bodies = [
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            json.dumps(payload, ensure_ascii=False, indent=2),
            json.dumps(payload, ensure_ascii=True),
            json.dumps(
                {"rules": payload["rules"], "facts": payload["facts"], "at": payload["at"]},
                ensure_ascii=False,
            ),
            " \n" + json.dumps(payload, ensure_ascii=False) + "\n\n",
        ]
        responses = [
            client.post(
                "/explanations",
                content=body.encode("utf-8"),
                headers={"content-type": "application/json"},
            )
            for body in bodies
        ]
        assert all(response.status_code == 200 for response in responses)
        first = responses[0].content
        assert first
        for response in responses[1:]:
            assert response.content == first

    def test_http_equivalent_bodies_produce_byte_identical_compiles(self):
        payload = {"at": MID, "rules": _scenario_rules()}
        bodies = [
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            json.dumps(payload, ensure_ascii=False, indent=4),
            json.dumps({"rules": payload["rules"], "at": payload["at"]},
                       ensure_ascii=True),
            "\t" + json.dumps(payload, ensure_ascii=False) + "\r\n",
        ]
        responses = [
            client.post(
                "/rules/compile",
                content=body.encode("utf-8"),
                headers={"content-type": "application/json"},
            )
            for body in bodies
        ]
        assert all(response.status_code == 200 for response in responses)
        first = responses[0].content
        assert first
        for response in responses[1:]:
            assert response.content == first


class TestEffectiveBoundaries:
    """Every version is checked just before, exactly at, and past its window."""

    @pytest.mark.parametrize(
        "at, expected_decision, expected_present",
        [
            (T1_MINUS_1, None, False),
            (T1, "allow", True),
            (T2_MINUS_1, "allow", True),
            (T2, None, False),
        ],
    )
    def test_half_open_window_boundaries(self, at, expected_decision, expected_present):
        rules = [_rule(**{"from": T1, "to": T2})]
        decision, trace = evaluate(at, {}, rules)
        assert decision == expected_decision
        assert trace == (["r1@1"] if expected_present else [])
        compiled = compile_rules(at, rules)
        assert [rule["id"] for rule in compiled["rules"]] == (
            ["r1"] if expected_present else []
        )
        assert compiled["conflicts"] == []
        explanation = explain(at, {}, rules)
        assert explanation["decision"] == expected_decision
        assert explanation["trace"] == trace
        assert (explanation["basis"] is not None) == expected_present
        assert explanation["conflicts"] == []

    @pytest.mark.parametrize(
        "at, expected_result, expected_ver",
        [
            (T1_MINUS_1, None, None),
            (T1, "v1", 1),
            (T2_MINUS_1, "v1", 1),
            (T2, "v2", 2),
            (T3, "v2", 2),
        ],
    )
    def test_version_handover_at_window_boundary(self, at, expected_result, expected_ver):
        rules = [
            _rule(ver=1, result="v1", **{"from": T1, "to": T2}),
            _rule(ver=2, result="v2", **{"from": T2, "to": None}),
        ]
        decision, trace = evaluate(at, {}, rules)
        assert decision == expected_result
        assert trace == ([f"r1@{expected_ver}"] if expected_ver else [])
        compiled = compile_rules(at, rules)
        assert [rule["ver"] for rule in compiled["rules"]] == (
            [expected_ver] if expected_ver else []
        )

    def test_open_ended_window_stays_effective(self):
        rules = [_rule(**{"from": T1, "to": None})]
        for at in (T1_MINUS_1,):
            assert evaluate(at, {}, rules) == (None, [])
        for at in (T1, MID, T2, T3):
            assert evaluate(at, {}, rules)[0] == "allow"


class TestConflictPriority:
    """Existing priority semantics select one unique conclusion."""

    def test_same_source_higher_priority_wins(self):
        rules = [
            _rule(id="low", priority=1, result="low"),
            _rule(id="high", priority=9, result="high"),
        ]
        decision, trace = evaluate(MID, {}, rules)
        assert decision == "high"
        assert trace == ["high@1", "low@1"]
        explanation = explain(MID, {}, rules)
        assert explanation["basis"]["id"] == "high"
        assert explanation["conflicts"] == [
            {"winner": ["law", "high", 1], "loser": ["law", "low", 1]}
        ]

    def test_law_outranks_org_regardless_of_priority(self):
        rules = [
            _rule(id="lx", source="law", priority=0, result="law-result"),
            _rule(id="ox", source="org", priority=99, result="org-result"),
        ]
        decision, trace = evaluate(MID, {}, rules)
        assert decision == "law-result"
        assert trace == ["lx@1", "ox@1"]
        explanation = explain(MID, {}, rules)
        assert explanation["basis"]["source"] == "law"
        assert explanation["conflicts"] == [
            {"winner": ["law", "lx", 1], "loser": ["org", "ox", 1]}
        ]

    def test_same_priority_tie_breaks_are_deterministic(self):
        # Same source and priority: later `from` wins, then smaller id.
        by_from = [
            _rule(id="x", priority=7, result="older", **{"from": T0}),
            _rule(id="y", priority=7, result="newer", **{"from": T1}),
        ]
        assert evaluate(MID, {}, by_from)[0] == "newer"
        assert evaluate(MID, {}, list(reversed(by_from)))[0] == "newer"
        by_id = [
            _rule(id="b", priority=7, result="B"),
            _rule(id="a", priority=7, result="A"),
        ]
        decision, trace = evaluate(MID, {}, by_id)
        assert decision == "A"
        assert trace == ["a@1", "b@1"]
        assert evaluate(MID, {}, list(reversed(by_id))) == (decision, trace)
        explanation = explain(MID, {}, by_id)
        assert explanation["conflicts"] == [
            {"winner": ["law", "a", 1], "loser": ["law", "b", 1]}
        ]

    def test_unrelated_rules_stay_out_of_hit_set_and_explanation(self):
        rules = _scenario_rules()
        facts = {"a": True}
        decision, trace = evaluate(MID, facts, rules)
        assert decision == "allow"
        assert trace == ["win@2", "lose@1", "orgx@1"]
        explanation = explain(MID, facts, rules)
        # Shadowed version, non-matching and not-yet-effective rules must not
        # be referenced anywhere in the explanation.
        serialized = _canon(explanation)
        assert "old" not in serialized
        assert "far" not in serialized
        assert "future" not in serialized
        compiled = compile_rules(MID, rules)
        compiled_ids = [(rule["source"], rule["id"], rule["ver"]) for rule in compiled["rules"]]
        assert ("law", "win", 1) not in compiled_ids
        assert ("law", "future", 1) not in compiled_ids


class TestHistoryReplay:
    """Replay uses the record visible at the requested decision time."""

    def test_decision_time_selects_versions_visible_then(self):
        rules = [
            _rule(ver=1, result="old", **{"from": T1, "to": T2}),
            _rule(ver=2, result="new", **{"from": T2, "to": None}),
        ]
        assert evaluate(MID, {}, rules)[0] == "old"
        assert evaluate(T2, {}, rules)[0] == "new"
        assert evaluate(T3, {}, rules)[0] == "new"

    def test_later_records_do_not_rewrite_earlier_replay(self, tmp_path):
        history = DecisionHistory(str(tmp_path / "history.json"))
        rules_v1 = [_rule(ver=1, result="old", **{"from": T1, "to": T2})]
        # Later the rule is replaced: ver 1 revoked at T2, ver 2 takes over.
        rules_v2 = rules_v1 + [_rule(ver=2, result="new", **{"from": T2, "to": None})]
        history.record("case", MID, {}, rules_v1)
        history.record("case", T3, {}, rules_v2)
        early = history.replay("case", MID)
        assert early["decision"] == "old"
        assert early["trace"] == ["r1@1"]
        assert early["basis"]["ver"] == 1
        # A replay between the two records still sees the first snapshot.
        between = history.replay("case", T2)
        assert between["decision"] == "old"
        late = history.replay("case", T3)
        assert late["decision"] == "new"
        assert late["basis"]["ver"] == 2

    def test_permuted_rule_order_records_the_same_conclusion(self, tmp_path):
        rules = _scenario_rules()
        facts = {"a": True}
        history_a = DecisionHistory(str(tmp_path / "a.json"))
        history_b = DecisionHistory(str(tmp_path / "b.json"))
        history_a.record("case", MID, facts, rules)
        history_b.record("case", MID, facts, list(reversed(rules)))
        replayed_a = history_a.replay("case", MID)
        replayed_b = history_b.replay("case", MID)
        assert replayed_a == replayed_b
        assert replayed_a["decision"] == "allow"
        assert replayed_a["trace"] == ["win@2", "lose@1", "orgx@1"]

    def test_replay_before_any_record_raises_key_error(self, tmp_path):
        history = DecisionHistory(str(tmp_path / "history.json"))
        history.record("case", T2, {}, [_rule()])
        with pytest.raises(KeyError):
            history.replay("case", T1)

    def test_duplicate_record_identity_raises_value_error(self, tmp_path):
        history = DecisionHistory(str(tmp_path / "history.json"))
        history.record("case", MID, {}, [_rule()])
        with pytest.raises(ValueError):
            history.record("case", MID, {}, [_rule()])

    def test_http_record_and_replay_honor_request_decision_time(
        self, tmp_path, monkeypatch
    ):
        import regulation_policy_compiler.app as app_module

        history = DecisionHistory(str(tmp_path / "history.json"))
        monkeypatch.setattr(app_module, "H", history)
        rules = [
            _rule(ver=1, result="old", **{"from": T1, "to": T2}),
            _rule(ver=2, result="new", **{"from": T2, "to": None}),
        ]
        early = client.post(
            "/decisions/case", json={"at": MID, "facts": {}, "rules": rules}
        )
        assert early.status_code == 200
        assert early.json()["decision"] == "old"
        late = client.post(
            "/decisions/case", json={"at": T3, "facts": {}, "rules": rules}
        )
        assert late.status_code == 200
        assert late.json()["decision"] == "new"
        replay_early = client.get("/decisions/case", params={"at": MID})
        assert replay_early.status_code == 200
        assert replay_early.json()["decision"] == "old"
        assert replay_early.json()["basis"]["ver"] == 1
        replay_between = client.get("/decisions/case", params={"at": T2})
        assert replay_between.json()["decision"] == "old"
        replay_late = client.get("/decisions/case", params={"at": T3})
        assert replay_late.json()["decision"] == "new"
        # The same historical request with permuted rule sources agrees.
        permuted = client.post(
            "/decisions/case-permuted",
            json={"at": MID, "facts": {}, "rules": list(reversed(rules))},
        )
        assert permuted.status_code == 200
        for field in ("decision", "trace", "basis"):
            assert permuted.json()[field] == early.json()[field]


class TestExceptionContract:
    """Only the documented exception type or deterministic result is allowed."""

    @pytest.mark.parametrize(
        "bad_at",
        [
            "2021-6-1T00:00:00Z",
            "2021-06-01 00:00:00Z",
            "2021-06-01T00:00:00+00:00",
            "2021-02-30T00:00:00Z",
            "",
            "not-a-time",
            None,
            123,
        ],
    )
    def test_unparseable_time_raises_value_error(self, bad_at):
        with pytest.raises(ValueError):
            evaluate(bad_at, {}, [])
        with pytest.raises(ValueError):
            explain(bad_at, {}, [])
        with pytest.raises(ValueError):
            compile_rules(bad_at, [])

    def test_duplicate_version_identity_raises_value_error(self):
        rules = [_rule(), _rule()]
        with pytest.raises(ValueError):
            evaluate(MID, {}, rules)
        with pytest.raises(ValueError):
            explain(MID, {}, rules)
        with pytest.raises(ValueError):
            compile_rules(MID, rules)
        # Distinct versions of the same (source, id) remain legal.
        decision, _ = evaluate(MID, {}, [_rule(ver=1), _rule(ver=2)])
        assert decision == "allow"

    @pytest.mark.parametrize(
        "window",
        [
            {"from": T1, "to": T1},
            {"from": T2, "to": T1},
            {"from": "not-a-time", "to": T2},
            {"from": T1, "to": "not-a-time"},
        ],
    )
    def test_invalid_effective_window_raises_value_error(self, window):
        rules = [_rule(**window)]
        with pytest.raises(ValueError):
            evaluate(MID, {}, rules)
        with pytest.raises(ValueError):
            explain(MID, {}, rules)
        with pytest.raises(ValueError):
            compile_rules(MID, rules)

    def test_no_applicable_version_is_a_deterministic_empty_result(self):
        rules = [_rule(**{"from": T3})]
        assert evaluate(MID, {}, rules) == (None, [])
        assert explain(MID, {}, rules) == {
            "at": MID,
            "decision": None,
            "trace": [],
            "basis": None,
            "conflicts": [],
        }
        assert compile_rules(MID, rules) == {"at": MID, "rules": [], "conflicts": []}

    def test_invalid_inputs_raise_without_mutating(self):
        rules = [_rule(**{"from": T2, "to": T1})]
        facts = {"a": True}
        rules_snapshot = copy.deepcopy(rules)
        facts_snapshot = copy.deepcopy(facts)
        for call in (
            lambda: evaluate(MID, facts, rules),
            lambda: explain(MID, facts, rules),
            lambda: compile_rules(MID, rules),
        ):
            with pytest.raises(ValueError):
                call()
        assert rules == rules_snapshot
        assert facts == facts_snapshot


class TestExplanationConsistency:
    """The explanation must correspond to the actual decision path."""

    def test_basis_identifies_winner_version_source_window_and_priority(self):
        rules = _scenario_rules()
        explanation = explain(MID, {"a": True}, rules)
        basis = explanation["basis"]
        assert basis["id"] == "win"
        assert basis["ver"] == 2
        assert basis["source"] == "law"
        assert basis["priority"] == 5
        assert basis["from"] == T1
        assert basis["to"] is None
        assert explanation["decision"] == basis["result"] == "allow"
        assert explanation["trace"][0] == "win@2"

    def test_non_matching_candidates_are_not_described_as_basis(self):
        rules = [
            _rule(id="top", priority=9, when={"x": True}, result="allow"),
            _rule(id="base", priority=1, result="deny"),
        ]
        explanation = explain(MID, {"x": False}, rules)
        assert explanation["decision"] == "deny"
        assert explanation["basis"]["id"] == "base"
        assert explanation["trace"] == ["base@1"]
        # The non-matching higher-priority rule is only referenced as the
        # conflict winner that would override the basis, never as the basis.
        assert explanation["conflicts"] == [
            {"winner": ["law", "top", 1], "loser": ["law", "base", 1]}
        ]

    def test_overridden_candidates_match_conflict_losers(self):
        rules = _scenario_rules()
        facts = {"a": True}
        explanation = explain(MID, facts, rules)
        compiled = compile_rules(MID, rules)
        basis_key = [
            explanation["basis"]["source"],
            explanation["basis"]["id"],
            explanation["basis"]["ver"],
        ]
        # Every explained conflict involves the basis, in compile order.
        expected = [
            conflict
            for conflict in compiled["conflicts"]
            if conflict["winner"] == basis_key or conflict["loser"] == basis_key
        ]
        assert explanation["conflicts"] == expected
        assert explanation["conflicts"] == [
            {"winner": ["law", "win", 2], "loser": ["law", "lose", 1]},
            {"winner": ["law", "win", 2], "loser": ["org", "orgx", 1]},
        ]
        # The eliminated matching candidates are exactly the conflict losers.
        losers = {tuple(conflict["loser"]) for conflict in explanation["conflicts"]}
        assert losers == {("law", "lose", 1), ("org", "orgx", 1)}

    def test_explanation_agrees_with_evaluate_and_compile(self):
        rules = _scenario_rules()
        facts = {"a": True}
        decision, trace = evaluate(MID, facts, rules)
        explanation = explain(MID, facts, rules)
        compiled = compile_rules(MID, rules)
        assert explanation["at"] == compiled["at"] == MID
        assert explanation["decision"] == decision
        assert explanation["trace"] == trace
        compiled_identities = {
            (rule["source"], rule["id"], rule["ver"]) for rule in compiled["rules"]
        }
        basis = explanation["basis"]
        assert (basis["source"], basis["id"], basis["ver"]) in compiled_identities


class TestGeneratedScenarios:
    """Constrained generated rule combinations, replayed deterministically."""

    _FACT_KEYS = ("a", "b", "c")
    _RESULTS = ("allow", "deny", "review")
    _RULE_IDS = ("r1", "r2", "r3")
    _TIME_POOL = (
        "2019-06-01T00:00:00Z",
        "2020-01-01T00:00:00Z",
        "2020-07-01T00:00:00Z",
        "2021-01-01T00:00:00Z",
        "2021-06-01T00:00:00Z",
        "2022-01-01T00:00:00Z",
        "2023-01-01T00:00:00Z",
    )
    _SEEDS = tuple(range(20240101, 20240141))

    @classmethod
    def _generate(cls, seed):
        rng = random.Random(seed)
        used_identities = set()
        rules = []
        for _ in range(rng.randint(1, 6)):
            source = rng.choice(("law", "org"))
            rule_id = rng.choice(cls._RULE_IDS)
            ver = rng.randint(1, 3)
            while (source, rule_id, ver) in used_identities:
                ver += 1
            used_identities.add((source, rule_id, ver))
            frm = rng.choice(cls._TIME_POOL[:-1])
            later = [t for t in cls._TIME_POOL if t > frm]
            to = rng.choice(later + [None, None])
            when = None
            if rng.random() < 0.7:
                keys = rng.sample(cls._FACT_KEYS, rng.randint(1, 2))
                when = {key: rng.choice((True, False)) for key in keys}
            rules.append(
                {
                    "id": rule_id,
                    "ver": ver,
                    "source": source,
                    "priority": rng.randint(0, 3),
                    "from": frm,
                    "to": to,
                    "when": when,
                    "result": rng.choice(cls._RESULTS),
                }
            )
        facts = {
            key: rng.choice((True, False))
            for key in cls._FACT_KEYS
            if rng.random() < 0.8
        }
        candidates = list(cls._TIME_POOL)
        for rule in rules:
            candidates.append(rule["from"])
            if rule["to"] is not None:
                candidates.append(rule["to"])
        return {"at": rng.choice(candidates), "facts": facts, "rules": rules}

    @staticmethod
    def _reshuffle_keys(value, rng):
        if isinstance(value, dict):
            items = list(value.items())
            rng.shuffle(items)
            return {key: TestGeneratedScenarios._reshuffle_keys(item, rng) for key, item in items}
        if isinstance(value, list):
            return [TestGeneratedScenarios._reshuffle_keys(item, rng) for item in value]
        return value

    def test_generated_scenarios_are_deterministic_and_replayable(self, tmp_path):
        for seed in self._SEEDS:
            scenario = self._generate(seed)
            label = "seed={} scenario={}".format(
                seed, json.dumps(scenario, ensure_ascii=False, sort_keys=True)
            )
            at = scenario["at"]
            facts = scenario["facts"]
            rules = scenario["rules"]
            rules_snapshot = copy.deepcopy(rules)
            facts_snapshot = copy.deepcopy(facts)

            # Compilation is idempotent.
            compiled_first = compile_rules(at, rules)
            compiled_second = compile_rules(at, rules)
            assert compiled_first == compiled_second, label
            assert _canon(compiled_first) == _canon(compiled_second), label

            # Rule order and object key order are irrelevant.
            rng = random.Random(seed + 1)
            permuted = list(rules)
            rng.shuffle(permuted)
            assert _canon(compile_rules(at, permuted)) == _canon(compiled_first), label
            reshuffled = self._reshuffle_keys(rules, rng)
            assert _canon(compile_rules(at, reshuffled)) == _canon(compiled_first), label

            # Decision and explanation agree across equivalent inputs.
            decision, trace = evaluate(at, facts, rules)
            explanation = explain(at, facts, rules)
            assert evaluate(at, facts, permuted) == (decision, trace), label
            assert _canon(explain(at, facts, permuted)) == _canon(explanation), label
            assert explanation["decision"] == decision, label
            assert explanation["trace"] == trace, label

            # The explanation matches the compiled product and the decision.
            basis = explanation["basis"]
            if basis is None:
                assert decision is None, label
                assert trace == [], label
                assert explanation["conflicts"] == [], label
            else:
                assert decision == basis["result"], label
                assert trace[0] == f"{basis['id']}@{basis['ver']}", label
                identities = {
                    (rule["source"], rule["id"], rule["ver"])
                    for rule in compiled_first["rules"]
                }
                assert (basis["source"], basis["id"], basis["ver"]) in identities, label
                basis_key = [basis["source"], basis["id"], basis["ver"]]
                expected_conflicts = [
                    conflict
                    for conflict in compiled_first["conflicts"]
                    if conflict["winner"] == basis_key or conflict["loser"] == basis_key
                ]
                assert explanation["conflicts"] == expected_conflicts, label

            # A decision recorded now replays identically at the same time,
            # and permuting the rule sources does not change the conclusion.
            history_a = DecisionHistory(str(tmp_path / f"case-{seed}-a.json"))
            recorded = history_a.record("case", at, facts, rules)
            assert recorded["decision"] == decision, label
            assert recorded["trace"] == trace, label
            replayed = history_a.replay("case", at)
            assert replayed["decision"] == decision, label
            assert replayed["trace"] == trace, label
            assert replayed["basis"] == basis, label
            history_b = DecisionHistory(str(tmp_path / f"case-{seed}-b.json"))
            history_b.record("case", at, facts, permuted)
            assert history_b.replay("case", at) == replayed, label

            # No call mutated the scenario inputs.
            assert rules == rules_snapshot, label
            assert facts == facts_snapshot, label
