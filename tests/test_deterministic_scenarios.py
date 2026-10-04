"""Deterministic scenario tests for versioned rule compilation and decisions.

These tests treat one rule set, one explicit decision time, and one fact map
as a complete scenario and pin down the public contract only:

* rule loading order, object key order, equivalent JSON whitespace, and
  repeated compilation must not change the compiled artifact or the verdict;
* the effective/expiry boundary of every version;
* the unique-winner priority semantics inside one source and across sources;
* history replay of a fixed point in time is immune to later rule changes and
  to rule-source ordering;
* the single public exception type / determined result for each failure mode;
* explanations describe exactly the winning path, never an unmatched rule.

A final constrained generator re-checks the same properties on many legal
rule combinations and shrinks any counterexample to a minimal literal input.

Everything uses fixed UTC timestamps and fixed seeds: no current time, no
random environment, no file traversal order, and no machine-specific paths
appear in an assertion.
"""

import copy
import hashlib
import itertools
import json
import random

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.history import DecisionHistory
from regulation_policy_compiler.policy import (
    compile_rules,
    evaluate,
    explain,
    policy_attestation,
)

client = TestClient(app)

# --- Fixed scenario time line -------------------------------------------------

F1 = "2024-01-01T00:00:00Z"
C1 = "2024-06-01T00:00:00Z"
F2 = "2024-07-01T00:00:00Z"
Y2 = "2025-01-01T00:00:00Z"
T0 = "2023-12-31T23:59:59Z"
EVE = "2024-05-31T23:59:59Z"
MID = "2024-06-15T12:00:00Z"
NYE = "2024-12-31T23:59:59Z"


def _rule(**overrides):
    rule = {
        "id": "r1",
        "ver": 1,
        "source": "law",
        "priority": 0,
        "from": F1,
        "to": None,
        "when": None,
        "result": "allow",
    }
    rule.update(overrides)
    return rule


# Two independently versioned laws, one with adjacent windows and one whose
# versions overlap for half a year (the higher ver must win while both are
# effective, and version selection -- not conflict resolution -- suppresses
# the older version).
def versioned_rules():
    return [
        _rule(id="speed", ver=1, **{"from": F1, "to": C1}, result="speed-60"),
        _rule(id="speed", ver=2, **{"from": C1, "to": None}, result="speed-30"),
        _rule(id="tax", ver=1, **{"from": F1, "to": Y2}, result="tax-10"),
        _rule(id="tax", ver=2, **{"from": F2, "to": None}, result="tax-20"),
    ]


# Conflict arena: one conditional law, six org rules, plus expired/future and
# incompatible-when distractors. All windows start at F1 unless stated.
def conflict_rules():
    return [
        _rule(id="ex", priority=1, **{"from": "2020-01-01T00:00:00Z",
                                      "to": "2021-01-01T00:00:00Z"},
              result="expired"),
        _rule(id="fu", priority=1, **{"from": "2030-01-01T00:00:00Z"},
              result="future"),
        _rule(id="la", priority=5, when={"x": True}, result="legal-allow"),
        _rule(id="oh", source="org", priority=99, when={"x": True},
              result="org-deny"),
        _rule(id="nw", source="org", priority=9, when={"x": True},
              result="org-new"),
        _rule(id="an", source="org", priority=9,
              **{"from": "2023-01-01T00:00:00Z"}, when={"x": True},
              result="org-old"),
        _rule(id="al", source="org", priority=5, when={"x": True},
              result="org-x-allow"),
        _rule(id="om", source="org", priority=5, when={"y": False},
              result="org-review"),
        _rule(id="zz", source="org", priority=1, when={"x": False},
              result="org-off"),
    ]


CONFLICT_FACTS = {"x": True, "y": False}


# --- Canonical (de)serialization helpers -------------------------------------

def _canon(obj):
    """Canonical compact JSON text of a public result (its key order is part
    of the contract, so keys are not re-sorted here)."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _bytes(obj):
    return _canon(obj).encode("utf-8")


def _value_fingerprint(obj):
    """Order-insensitive fingerprint of an *input* value."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _reversed_keys(value):
    """Deep copy with every dict's insertion order reversed."""
    if isinstance(value, dict):
        return {k: _reversed_keys(value[k]) for k in reversed(list(value))}
    if isinstance(value, list):
        return [_reversed_keys(item) for item in value]
    return value


def _identities(compiled):
    return {
        (rule["source"], rule["id"], rule["ver"])
        for rule in compiled["rules"]
    }


def _documented_rank_before(winner, loser):
    """The public total order: source (law<org), priority desc, from desc,
    id code point asc, ver desc."""
    if winner["source"] != loser["source"]:
        return winner["source"] == "law"
    if winner["priority"] != loser["priority"]:
        return winner["priority"] > loser["priority"]
    if winner["from"] != loser["from"]:
        return winner["from"] > loser["from"]
    if winner["id"] != loser["id"]:
        return winner["id"] < loser["id"]
    return winner["ver"] > loser["ver"]


# -----------------------------------------------------------------------------
# Determinism: load order, key order, whitespace, recompilation
# -----------------------------------------------------------------------------

def test_compile_is_invariant_to_rule_array_permutation():
    rules = versioned_rules() + conflict_rules()
    reference = _bytes(compile_rules(C1, rules))
    # Several fixed permutations, including reverse and rotations.
    for perm in (rules[::-1], rules[3:] + rules[:3], rules[1::2] + rules[::2]):
        assert perm is not rules
        assert _bytes(compile_rules(C1, copy.deepcopy(perm))) == reference
    # Every distinct permutation of the small versioned set as well.
    seen_permutations = {
        tuple((r["id"], r["ver"]) for r in perm)
        for perm in itertools.permutations(versioned_rules())
    }
    assert len(seen_permutations) == 24  # 4 distinct rules -> 4! orderings
    for perm in itertools.permutations(versioned_rules()):
        assert _bytes(compile_rules(C1, [copy.deepcopy(r) for r in perm])) == \
            _bytes(compile_rules(C1, versioned_rules()))


def test_compile_evaluate_and_explain_are_invariant_to_object_key_order():
    rules = versioned_rules() + conflict_rules()
    facts = CONFLICT_FACTS

    shuffled = list(reversed(rules))
    reversed_rules = [_reversed_keys(rule) for rule in shuffled]
    reversed_facts = {k: facts[k] for k in reversed(list(facts))}

    assert compile_rules(C1, reversed_rules) == compile_rules(C1, rules)
    assert _bytes(compile_rules(C1, reversed_rules)) == _bytes(compile_rules(C1, rules))
    assert evaluate(C1, reversed_facts, reversed_rules) == evaluate(C1, facts, rules)
    assert explain(C1, reversed_facts, reversed_rules) == explain(C1, facts, rules)
    assert _bytes(explain(C1, reversed_facts, reversed_rules)) == _bytes(
        explain(C1, facts, rules)
    )


def test_http_equivalent_whitespace_and_repeated_requests_are_byte_identical():
    payload = {
        "at": C1,
        "facts": {"x": True, "y": False},
        "rules": conflict_rules(),
    }
    compact = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    pretty = json.dumps(payload, ensure_ascii=False, indent=2)
    padded = "\n\t " + pretty.replace("\n", "\n  ") + "\n"
    assert compact != pretty  # sanity: the bodies really differ textually

    first = client.post("/explanations", content=compact,
                        headers={"content-type": "application/json"})
    second = client.post("/explanations", content=padded,
                         headers={"content-type": "application/json"})
    third = client.post("/explanations", content=pretty,
                        headers={"content-type": "application/json"})
    assert first.status_code == second.status_code == third.status_code == 200
    assert first.content == second.content == third.content
    # Repeated compilation with the same compact body is byte-stable too.
    compile_body = json.dumps(
        {"at": C1, "rules": conflict_rules()},
        ensure_ascii=False, separators=(",", ":"),
    )
    c1 = client.post("/rules/compile", content=compile_body,
                     headers={"content-type": "application/json"})
    c2 = client.post("/rules/compile", content=compile_body,
                     headers={"content-type": "application/json"})
    assert c1.status_code == 200 and c1.content == c2.content
    # Non-ASCII results travel as raw UTF-8, never as \uXXXX escapes.
    uni = {"at": C1, "rules": [_rule(result="允许")]}
    response = client.post("/rules/compile", json=uni)
    assert response.status_code == 200
    assert "允许".encode("utf-8") in response.content
    assert b"\\u" not in response.content
    assert not response.content.endswith(b"\n")


def test_repeated_compilation_is_idempotent_and_does_not_mutate_input():
    rules = versioned_rules() + conflict_rules()
    fingerprint = _value_fingerprint(rules)

    first = compile_rules(C1, rules)
    second = compile_rules(C1, rules)
    third = compile_rules(C1, copy.deepcopy(rules))
    assert first == second == third
    assert _bytes(first) == _bytes(second) == _bytes(third)
    assert _value_fingerprint(rules) == fingerprint  # input untouched

    # Mutating a returned artifact must not change later compilations.
    first["rules"].clear()
    first["conflicts"].append({"winner": ["org", "zz", 1],
                               "loser": ["law", "la", 1]})
    again = compile_rules(C1, rules)
    assert again == second
    assert again is not second and again["rules"] is not second["rules"]


def test_attestation_digest_stable_across_equivalent_inputs():
    rules = versioned_rules() + conflict_rules()
    reference = policy_attestation(C1, rules)

    reordered = policy_attestation(C1, [_reversed_keys(r) for r in rules[::-1]])
    assert reordered == reference
    assert reordered["digest"] == reference["digest"]

    # The digest is the documented SHA-256 of the canonical policy bytes.
    expected = hashlib.sha256(_bytes(reference["policy"])).hexdigest()
    assert reference["digest"] == expected
    assert len(reference["digest"]) == 64


def test_repeated_explanations_are_isolated_deep_copies():
    first = explain(C1, CONFLICT_FACTS, conflict_rules())
    second = explain(C1, CONFLICT_FACTS, conflict_rules())
    assert first == second and _bytes(first) == _bytes(second)
    first["basis"]["result"] = "tampered"
    first["trace"].append("zz@1")
    assert explain(C1, CONFLICT_FACTS, conflict_rules()) == second


# -----------------------------------------------------------------------------
# Effective boundaries of every version
# -----------------------------------------------------------------------------

@pytest.mark.parametrize(
    "at, expected_identities, expected_decision",
    [
        (T0, frozenset(), None),
        (F1, frozenset({("law", "speed", 1), ("law", "tax", 1)}), "speed-60"),
        (EVE, frozenset({("law", "speed", 1), ("law", "tax", 1)}), "speed-60"),
        (C1, frozenset({("law", "speed", 2), ("law", "tax", 1)}), "speed-30"),
        (MID, frozenset({("law", "speed", 2), ("law", "tax", 1)}), "speed-30"),
        (F2, frozenset({("law", "speed", 2), ("law", "tax", 2)}), "tax-20"),
        (NYE, frozenset({("law", "speed", 2), ("law", "tax", 2)}), "tax-20"),
        (Y2, frozenset({("law", "speed", 2), ("law", "tax", 2)}), "tax-20"),
    ],
)
def test_version_boundaries_select_exactly_one_winner(
    at, expected_identities, expected_decision
):
    rules = versioned_rules()
    compiled = compile_rules(at, rules)
    assert _identities(compiled) == expected_identities
    decision, trace = evaluate(at, {}, rules)
    assert decision == expected_decision
    if expected_decision is None:
        assert trace == []
        assert explain(at, {}, rules) == {
            "at": at, "decision": None, "trace": [],
            "basis": None, "conflicts": [],
        }
    else:
        assert len(trace) == len(expected_identities)  # when=None rules all match
        assert trace[0].split("@", 1)[0] in ("speed", "tax")
    # Snapshot ordering follows the documented ranking for every boundary.
    snapshots = compiled["rules"]
    for earlier, later in zip(snapshots, snapshots[1:]):
        assert _documented_rank_before(earlier, later)


def test_half_open_window_at_each_individual_boundary():
    rules = versioned_rules()
    # One second before speed v1 / at its from / at its to.
    assert evaluate(T0, {}, rules) == (None, [])
    assert evaluate(F1, {}, rules)[0] == "speed-60"
    assert evaluate(EVE, {}, rules)[0] == "speed-60"
    assert evaluate(C1, {}, rules)[0] == "speed-30"  # v1 dead exactly at C1
    # Overlapping versions: the higher ver suppresses the lower one without
    # producing a conflict pair or a second trace entry.
    compiled_f2 = compile_rules(F2, rules)
    assert ("law", "tax", 1) not in _identities(compiled_f2)
    decision, trace = evaluate(F2, {}, rules)
    assert trace == ["tax@2", "speed@2"]
    assert decision == "tax-20"
    # Same facts evaluated at the boundary from both sides differ only there.
    assert evaluate(EVE, {}, rules)[0] != evaluate(C1, {}, rules)[0]


def test_compiled_snapshots_actually_cover_the_decision_time():
    for at in (F1, EVE, C1, F2, NYE, Y2):
        for rule in compile_rules(at, versioned_rules())["rules"]:
            assert rule["from"] <= at
            assert rule["to"] is None or at < rule["to"]


# -----------------------------------------------------------------------------
# Conflict priority, inside one source and across sources
# -----------------------------------------------------------------------------

def test_law_beats_higher_priority_org_rule_that_also_matches():
    decision, trace = evaluate(C1, CONFLICT_FACTS, conflict_rules())
    assert decision == "legal-allow"
    assert trace == ["la@1", "oh@1", "nw@1", "an@1", "al@1", "om@1"]


def test_org_decides_when_the_law_does_not_match():
    # x is false: the conditional law and all x=true org rules are silent.
    decision, trace = evaluate(C1, {"x": False, "y": True}, conflict_rules())
    assert decision == "org-off"
    assert trace == ["zz@1"]
    # y=false keeps om ahead of zz even though the law is silent.
    decision, trace = evaluate(C1, {"x": False, "y": False}, conflict_rules())
    assert decision == "org-review"
    assert trace == ["om@1", "zz@1"]


def test_intra_source_tie_breaks_are_unique_and_order_independent():
    # Equal source/priority/from: id code point order breaks the tie.
    tie = [
        _rule(id="om", source="org", priority=5, when={"y": False},
              result="org-review"),
        _rule(id="al", source="org", priority=5, when={"x": True},
              result="org-x-allow"),
    ]
    facts = {"x": True, "y": False}
    for perm in itertools.permutations(tie):
        decision, trace = evaluate(C1, facts, list(perm))
        assert decision == "org-x-allow"
        assert trace == ["al@1", "om@1"]

    # Equal source/priority with different from: the later from wins.
    from_tie = [r for r in conflict_rules() if r["id"] in ("nw", "an")]
    for perm in itertools.permutations(from_tie):
        decision, trace = evaluate(C1, {"x": True}, list(perm))
        assert decision == "org-new"
        assert trace == ["nw@1", "an@1"]


def test_conflict_pair_marks_winner_and_loser_and_excludes_irrelevant():
    compiled = compile_rules(C1, conflict_rules())
    pair = {
        "winner": ["law", "la", 1],
        "loser": ["org", "oh", 1],
    }
    assert pair in compiled["conflicts"]
    # Expired/future rules and the x=false rule never form a pair with la:
    # their when is either irrelevant or incompatible with la's when.
    involved = {
        tuple(c["winner"]) for c in compiled["conflicts"]
    } | {tuple(c["loser"]) for c in compiled["conflicts"]}
    for absent in (("law", "ex", 1), ("law", "fu", 1)):
        assert absent not in involved
    la_zz = {"winner": ["law", "la", 1], "loser": ["org", "zz", 1]}
    assert la_zz not in compiled["conflicts"]  # x=true vs x=false incompatible

    # org-only arena: priority 99 takes over, and conflicts are re-rooted.
    org_rules = [r for r in conflict_rules() if r["source"] == "org"]
    org_explain = explain(C1, CONFLICT_FACTS, org_rules)
    assert org_explain["decision"] == "org-deny"
    assert org_explain["basis"]["id"] == "oh"
    assert org_explain["conflicts"] == [
        {"winner": ["org", "oh", 1], "loser": ["org", "nw", 1]},
        {"winner": ["org", "oh", 1], "loser": ["org", "an", 1]},
        {"winner": ["org", "oh", 1], "loser": ["org", "al", 1]},
        {"winner": ["org", "oh", 1], "loser": ["org", "om", 1]},
    ]


def test_same_priority_candidates_resolve_to_one_stable_winner_not_an_error():
    # Two distinct (source, id) candidates can never be fully tied, because
    # the id code point is part of the ranking. This is a determined result,
    # not an exception, regardless of input ordering.
    rules = [
        _rule(id="b", source="org", priority=0, result="B"),
        _rule(id="a", source="org", priority=0, result="A"),
    ]
    for perm in (rules, rules[::-1]):
        assert evaluate(C1, {}, perm) == ("A", ["a@1", "b@1"])
        assert compile_rules(C1, perm)["conflicts"] == [
            {"winner": ["org", "a", 1], "loser": ["org", "b", 1]},
        ]


# -----------------------------------------------------------------------------
# Explanations must describe exactly the actual winning path
# -----------------------------------------------------------------------------

def test_explanation_matches_the_actual_verdict():
    rules = conflict_rules()
    decision, trace = evaluate(C1, CONFLICT_FACTS, rules)
    report = explain(C1, CONFLICT_FACTS, rules)

    assert report["decision"] is decision
    assert report["trace"] == trace
    basis = report["basis"]
    assert [basis["source"], basis["id"], basis["ver"]] == ["law", "la", 1]
    assert trace[0] == "la@1"
    assert basis["result"] == decision
    # The basis was effective at the decision time and actually matched.
    assert basis["from"] <= C1 and (basis["to"] is None or C1 < basis["to"])
    assert all(CONFLICT_FACTS[k] is v for k, v in basis["when"].items())

    # Every trace entry points at a rule that really matched; no unmatched
    # rule is described as a basis.
    matched_ids = {entry.split("@")[0] for entry in trace}
    assert "zz" not in matched_ids
    assert report["basis"]["id"] in matched_ids


def test_explanation_conflicts_subset_preserves_order_and_covering_relation():
    rules = conflict_rules()
    compiled = compile_rules(C1, rules)
    report = explain(C1, CONFLICT_FACTS, rules)
    basis_key = ["law", "la", 1]

    # Subset of the compiled conflicts, in exactly the compiled order, and
    # every kept pair involves the basis.
    kept = report["conflicts"]
    assert kept == [c for c in compiled["conflicts"]
                    if c["winner"] == basis_key or c["loser"] == basis_key]
    assert kept == [
        {"winner": ["law", "la", 1], "loser": ["org", "oh", 1]},
        {"winner": ["law", "la", 1], "loser": ["org", "nw", 1]},
        {"winner": ["law", "la", 1], "loser": ["org", "an", 1]},
        {"winner": ["law", "la", 1], "loser": ["org", "al", 1]},
        {"winner": ["law", "la", 1], "loser": ["org", "om", 1]},
    ]
    # The covered candidates are the ones that lost on priority; their
    # results differ from the conclusion and they all sit below the basis.
    compiled_order = [(r["source"], r["id"], r["ver"]) for r in compiled["rules"]]
    basis_pos = compiled_order.index(("law", "la", 1))
    for conflict in kept:
        loser = tuple(conflict["loser"])
        assert conflict["winner"] == basis_key
        assert compiled_order.index(loser) > basis_pos


def test_basis_can_be_the_loser_of_a_compiled_conflict():
    # With x=false, y=true only zz matches; the static om>zz conflict is kept
    # with zz on the loser side, still consistent with the verdict.
    report = explain(C1, {"x": False, "y": True}, conflict_rules())
    assert report["decision"] == "org-off"
    assert report["trace"] == ["zz@1"]
    assert [report["basis"]["source"], report["basis"]["id"],
            report["basis"]["ver"]] == ["org", "zz", 1]
    assert report["conflicts"] == [
        {"winner": ["org", "om", 1], "loser": ["org", "zz", 1]},
    ]


# -----------------------------------------------------------------------------
# History replay: fixed points in time, later rules never rewrite the past
# -----------------------------------------------------------------------------

def _replay_rule_set():
    return [
        _rule(id="speed", ver=1, **{"from": F1, "to": C1}, result="speed-60"),
        _rule(id="speed", ver=2, **{"from": C1, "to": Y2}, result="speed-30"),
        _rule(id="speed", ver=3, **{"from": Y2, "to": None}, result="speed-90"),
    ]


def _record_three_eras(history):
    t1, t2, t3 = "2024-03-01T00:00:00Z", "2024-09-01T00:00:00Z", "2025-03-01T00:00:00Z"
    history.record("subject", t1, {}, _replay_rule_set())
    history.record("subject", t2, {}, _replay_rule_set())
    history.record("subject", t3, {}, _replay_rule_set())
    return t1, t2, t3


def test_replay_uses_recorded_snapshot_and_ignores_later_rule_changes(tmp_path):
    history = DecisionHistory(str(tmp_path / "h.json"))
    t1, t2, t3 = _record_three_eras(history)

    # A "current" rule set in which v1 has been shortened and v3 replaced
    # does not exist for replay: stored snapshots are returned verbatim.
    later_rules = [
        _rule(id="speed", ver=1, **{"from": F1, "to": F2}, result="rewritten"),
        _rule(id="speed", ver=3, **{"from": Y2, "to": "2026-01-01T00:00:00Z"},
              result="rewritten"),
        _rule(id="speed", ver=4, **{"from": t3, "to": None}, result="speed-0"),
    ]
    history.record("subject", "2025-06-01T00:00:00Z", {}, later_rules)

    first = history.replay("subject", t1)
    assert first["decision"] == "speed-60"
    assert first["at"] == t1
    assert first["basis"]["ver"] == 1
    assert first["basis"]["to"] == C1  # the snapshot as recorded, not rewritten
    assert history.replay("subject", t2)["decision"] == "speed-30"
    assert history.replay("subject", t3)["decision"] == "speed-90"

    # Even a store whose later records never mention v1 keeps the old answer.
    revoked = DecisionHistory(str(tmp_path / "revoked.json"))
    revoked.record("subject", t1, {}, [_replay_rule_set()[0]])
    revoked.record("subject", t2, {}, [
        _rule(id="speed", ver=2, **{"from": C1, "to": None}, result="speed-30"),
    ])
    old = revoked.replay("subject", t1)
    assert old["decision"] == "speed-60" and old["basis"]["ver"] == 1


def test_replay_boundaries_are_nearest_at_or_before(tmp_path):
    history = DecisionHistory(str(tmp_path / "h.json"))
    t1, t2, t3 = _record_three_eras(history)

    assert history.replay("subject", t1)["at"] == t1          # exact record
    assert history.replay("subject", "2024-12-31T23:59:59Z")["at"] == t2
    assert history.replay("subject", "2026-01-01T00:00:00Z")["at"] == t3
    with pytest.raises(KeyError):
        history.replay("subject", "2024-01-01T00:00:00Z")  # before first
    with pytest.raises(KeyError):
        history.replay("missing", t2)


def test_permuted_rule_source_order_yields_identical_history(tmp_path):
    rng = random.Random(20240601)
    path_a = tmp_path / "a.json"
    path_b = tmp_path / "b.json"
    ha = DecisionHistory(str(path_a))
    hb = DecisionHistory(str(path_b))
    t1, t2, t3 = _record_three_eras(ha)

    for at in (t1, t2, t3):
        rules = _replay_rule_set()
        rng.shuffle(rules)
        hb.record("subject", at, {}, [_reversed_keys(r) for r in rules])

    # Replay at every cut point is value- and byte-identical regardless of
    # the order rules were sourced in at recording time.
    for cut in (t1, "2024-06-01T00:00:00Z", t2, "2025-01-01T00:00:00Z", t3):
        ra, rb = ha.replay("subject", cut), hb.replay("subject", cut)
        assert ra == rb
        assert _bytes(ra) == _bytes(rb)

    assert ha.evolution("subject", t1, t3) == hb.evolution("subject", t1, t3)
    audit_a, audit_b = (ha.audit("subject", t1, t3),
                        hb.audit("subject", t1, t3))
    assert audit_a == audit_b
    assert audit_a["root"] == audit_b["root"]
    # Persisted bytes are deterministic too (sorted records, canonical basis).
    assert path_a.read_bytes() == path_b.read_bytes()


def test_replay_returns_independent_copies(tmp_path):
    history = DecisionHistory(str(tmp_path / "h.json"))
    t1, _, _ = _record_three_eras(history)
    first = history.replay("subject", t1)
    first["basis"]["result"] = "tampered"
    first["trace"].append("speed@9")
    again = history.replay("subject", t1)
    assert again["decision"] == "speed-60"
    assert again["trace"] == ["speed@1"]


# -----------------------------------------------------------------------------
# Public failure contract: single exception types / determined results only
# -----------------------------------------------------------------------------

def test_no_applicable_version_is_a_determined_none_not_an_error():
    rules = versioned_rules()
    assert evaluate(T0, {}, rules) == (None, [])
    compiled = compile_rules(T0, rules)
    assert compiled == {"at": T0, "rules": [], "conflicts": []}
    assert explain(T0, {}, rules)["basis"] is None


_INVALID_TIME = "not-a-time"
_INVALID_CASES = [
    {"name": "unparseable at",
     "at": "not-a-time", "facts": {}, "rules": []},
    {"name": "duplicate (source, id, ver)",
     "at": C1, "facts": {}, "rules": [_rule(), _rule()]},
    {"name": "empty interval (from == to)",
     "at": C1, "facts": {}, "rules": [_rule(**{"from": F1, "to": F1})]},
    {"name": "reversed interval",
     "at": C1, "facts": {}, "rules": [_rule(**{"from": C1, "to": F1})]},
    {"name": "bad source",
     "at": C1, "facts": {}, "rules": [_rule(source="edict")]},
    {"name": "non-positive ver",
     "at": C1, "facts": {}, "rules": [_rule(ver=0)]},
    {"name": "bool as ver",
     "at": C1, "facts": {}, "rules": [_rule(ver=True)]},
    {"name": "wrong rule key set",
     "at": C1, "facts": {}, "rules": [{"id": "z", "ver": 1, "source": "law",
                                     "priority": 0, "from": F1, "to": None,
                                     "when": None}]},
]
_INVALID_FACT_CASES = [
    {"name": "non-boolean fact value",
     "at": C1, "facts": {"x": "yes"}, "rules": []},
    {"name": "non-string fact key",
     "at": C1, "facts": {1: True}, "rules": []},
]


@pytest.mark.parametrize("case", _INVALID_CASES, ids=lambda c: c["name"])
def test_invalid_inputs_raise_value_error_only(case):
    at, facts, rules = case["at"], case["facts"], case["rules"]
    # Only the exception type is part of the contract.
    with pytest.raises(ValueError):
        evaluate(at, facts, rules)
    with pytest.raises(ValueError):
        compile_rules(at, rules)
    with pytest.raises(ValueError):
        explain(at, facts, rules)


@pytest.mark.parametrize("case", _INVALID_FACT_CASES, ids=lambda c: c["name"])
def test_invalid_facts_raise_value_error_only(case):
    at, facts, rules = case["at"], case["facts"], case["rules"]
    with pytest.raises(ValueError):
        evaluate(at, facts, rules)
    with pytest.raises(ValueError):
        explain(at, facts, rules)


def test_invalid_input_is_not_mutated_by_failed_compilation():
    rules = [_rule(**{"from": C1, "to": F1})]
    fingerprint = _value_fingerprint(rules)
    with pytest.raises(ValueError):
        compile_rules(C1, rules)
    assert _value_fingerprint(rules) == fingerprint
    assert rules[0]["from"] == C1 and rules[0]["to"] == F1


def test_history_error_types_follow_the_public_contract(tmp_path):
    history = DecisionHistory(str(tmp_path / "h.json"))
    with pytest.raises(ValueError):
        history.replay("subject", _INVALID_TIME)
    with pytest.raises(ValueError):
        history.evolution("subject", C1, F1)   # start > end
    with pytest.raises(ValueError):
        history.audit("subject", F1, "bad")
    # No stored record -> KeyError, distinct from validation errors.
    with pytest.raises(KeyError):
        history.replay("subject", C1)
    with pytest.raises(KeyError):
        history.evolution("subject", F1, C1)
    t1, _, _ = _record_three_eras(history)
    with pytest.raises(ValueError):  # duplicate (record_id, at)
        history.record("subject", t1, {}, _replay_rule_set())


def test_http_maps_every_validation_failure_to_422_contract():
    bad_bodies = [
        b"{",  # malformed JSON
        json.dumps({"at": C1, "rules": []}),  # missing facts on /explanations
        json.dumps({"at": C1, "facts": {}, "rules": [], "extra": 1}),
        json.dumps({"at": C1, "rules": [_rule(**{"from": C1, "to": F1})]}),
        json.dumps({"at": 5, "facts": {}, "rules": []}),
        "[]",
    ]
    for body in bad_bodies:
        response = client.post("/explanations", content=body,
                               headers={"content-type": "application/json"})
        assert response.status_code == 422
        assert response.json() == {"detail": "invalid request"}

    response = client.post(
        "/rules/compile",
        content=json.dumps({"at": _INVALID_TIME, "rules": []}),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


# -----------------------------------------------------------------------------
# Constrained generator: legal rule combinations, shrinking on failure
# -----------------------------------------------------------------------------

_BOUNDS = [f"2024-{month:02d}-01T00:00:00Z" for month in range(1, 13)] + [
    "2025-01-01T00:00:00Z"
]
_CHOICE_TIMES = sorted(set(_BOUNDS + [
    f"2024-{month:02d}-15T12:00:00Z" for month in range(1, 13)
]))
_FACT_KEYS = ("f1", "f2")
_RESULTS = ("approve", "reject")
_IDS = ("a", "b", "c", "d")
_SOURCES = ("law", "org")
_GENERATOR_CASES = 240
_GENERATOR_SEED = 20240601


def _generate_case(seed):
    rng = random.Random(seed)
    identities = []
    pool = [(source, rule_id) for source in _SOURCES for rule_id in _IDS]
    rng.shuffle(pool)
    for source, rule_id in pool[: rng.randrange(2, 5)]:
        identities.append((source, rule_id))

    rules = []
    for source, rule_id in identities:
        priority = rng.randrange(0, 4)
        versions = rng.randrange(1, 4)
        for ver in range(1, versions + 1):
            start_index = rng.randrange(0, len(_BOUNDS) - 2)
            end_choice = rng.randrange(start_index + 1, len(_BOUNDS))
            to = None if rng.random() < 0.4 else _BOUNDS[end_choice]
            when = None
            if rng.random() < 0.6:
                keys = rng.sample(list(_FACT_KEYS), rng.randrange(1, 3))
                when = {key: rng.choice([True, False]) for key in keys}
            rules.append(_rule(
                id=rule_id, ver=ver, source=source, priority=priority,
                **{"from": _BOUNDS[start_index], "to": to},
                when=when, result=rng.choice(_RESULTS),
            ))
    facts = {}
    for key in _FACT_KEYS:
        if rng.random() < 0.7:
            facts[key] = rng.choice([True, False])
    at = rng.choice(_CHOICE_TIMES)
    rng.shuffle(rules)
    return {"at": at, "facts": facts, "rules": rules}


def _conditions_compatible(when_a, when_b):
    if when_a is None or when_b is None:
        return True
    return all(
        key not in when_b or when_b[key] is value
        for key, value in when_a.items()
    )


def _check_case(case, tmp_path, tag):
    """Return a list of contract violations (empty means the case passes)."""
    at, facts, rules = case["at"], case["facts"], case["rules"]
    failures = []

    def expect(condition, label):
        if not condition:
            failures.append(label)

    # --- Equivalent inputs (permutation, key order, recompilation) ----------
    ordered = [_reversed_keys(rule) for rule in rules[::-1]]
    c1 = compile_rules(at, rules)
    c2 = compile_rules(at, ordered)
    expect(c1 == c2, "compile value differs across equivalent input")
    expect(_bytes(c1) == _bytes(c2), "compile bytes differ across equivalent input")
    expect(compile_rules(at, copy.deepcopy(rules)) == c1,
           "repeated compilation is not idempotent")

    e1 = evaluate(at, facts, rules)
    e2 = evaluate(at, dict(reversed(list(facts.items()))), ordered)
    expect(e1 == e2, "evaluate differs across equivalent input")
    x1 = explain(at, facts, rules)
    x2 = explain(at, dict(reversed(list(facts.items()))), ordered)
    expect(x1 == x2, "explain differs across equivalent input")
    expect(_bytes(x1) == _bytes(x2), "explain bytes differ across equivalent input")

    attest = policy_attestation(at, rules)
    expect(attest["digest"] == hashlib.sha256(_bytes(c1)).hexdigest(),
           "attestation digest does not match the canonical policy bytes")
    expect(policy_attestation(at, ordered)["digest"] == attest["digest"],
           "attestation digest differs across equivalent input")

    # --- Effective window, uniqueness, documented ordering ------------------
    seen = set()
    snapshots = c1["rules"]
    for rule in snapshots:
        identity = (rule["source"], rule["id"], rule["ver"])
        expect(identity not in seen, "duplicate (source, id) selected")
        seen.add(identity)
        expect(rule["from"] <= at and (rule["to"] is None or at < rule["to"]),
               "selected rule is outside its [from, to) window")
    for winner, loser in zip(snapshots, snapshots[1:]):
        expect(_documented_rank_before(winner, loser),
               "compiled rules violate the documented ordering")

    # --- Conflict reconstruction from the public snapshots ------------------
    rebuilt = []
    for i, winner in enumerate(snapshots):
        for loser in snapshots[i + 1:]:
            if winner["result"] != loser["result"] and _conditions_compatible(
                winner["when"], loser["when"]
            ):
                rebuilt.append({
                    "winner": [winner["source"], winner["id"], winner["ver"]],
                    "loser": [loser["source"], loser["id"], loser["ver"]],
                })
    expect(c1["conflicts"] == rebuilt, "conflicts do not match reconstruction")

    # --- Explanation / verdict coherence ------------------------------------
    expect((x1["decision"], x1["trace"]) == e1,
           "explain decision/trace disagree with evaluate")
    if x1["basis"] is None:
        expect(x1["trace"] == [] and x1["conflicts"] == [],
               "null basis with non-empty trace/conflicts")
    else:
        basis = x1["basis"]
        basis_key = [basis["source"], basis["id"], basis["ver"]]
        expect(x1["trace"][0] == f"{basis['id']}@{basis['ver']}",
               "basis does not correspond to trace[0]")
        expect(basis["result"] == x1["decision"],
               "basis result differs from decision")
        expect(basis["from"] <= at and (basis["to"] is None or at < basis["to"]),
               "basis is outside its effective window")
        matched = [
            rule for rule in snapshots
            if rule["when"] is None
            or all(key in facts and facts[key] is value
                   for key, value in rule["when"].items())
        ]
        expect(x1["trace"] == [f"{r['id']}@{r['ver']}" for r in matched],
               "trace is not exactly the set of matching rules")
        expect(basis_key == [matched[0]["source"], matched[0]["id"],
                             matched[0]["ver"]],
               "basis is not the top-ranked matching rule")
        related = [c for c in c1["conflicts"]
                   if c["winner"] == basis_key or c["loser"] == basis_key]
        expect(x1["conflicts"] == related,
               "explain conflicts are not the basis-related compiled subset")

    # --- Current decision equals same-point history replay ------------------
    file_a = tmp_path / f"gen-{tag}.json"
    file_b = tmp_path / f"gen-{tag}-perm.json"
    ha = DecisionHistory(str(file_a))
    hb = DecisionHistory(str(file_b))
    ha.record("g", at, facts, copy.deepcopy(rules))
    hb.record("g", at, facts, copy.deepcopy(ordered))
    record_a = ha.replay("g", at)
    record_b = hb.replay("g", at)
    expect(record_a == record_b, "replay differs under permuted source order")
    expect(record_a["decision"] == e1[0], "replayed decision differs")
    expect(record_a["trace"] == e1[1], "replayed trace differs")
    if x1["basis"] is None:
        expect(record_a["basis"] is None, "replayed basis differs (null)")
    else:
        expect(record_a["basis"] == x1["basis"],
               "replayed basis snapshot differs from explain basis")
    expect(file_a.read_bytes() == file_b.read_bytes(),
           "persisted history bytes differ under permuted source order")
    return failures


def _shrink_case(case, tmp_path):
    """Greedily drop rules and fact keys while violations remain."""
    shrunk = copy.deepcopy(case)
    counter = itertools.count()

    def still_fails(candidate):
        tag = f"shrink-{next(counter)}"
        return bool(_check_case(candidate, tmp_path, tag))

    changed = True
    while changed:
        changed = False
        for index in range(len(shrunk["rules"])):
            trial = copy.deepcopy(shrunk)
            del trial["rules"][index]
            if still_fails(trial):
                shrunk = trial
                changed = True
                break
        if changed:
            continue
        for key in list(shrunk["facts"]):
            trial = copy.deepcopy(shrunk)
            del trial["facts"][key]
            if still_fails(trial):
                shrunk = trial
                changed = True
                break
    return shrunk


def test_generated_scenarios_obey_determinism_contracts(tmp_path):
    for index in range(_GENERATOR_CASES):
        case = _generate_case(_GENERATOR_SEED + index)
        failures = _check_case(case, tmp_path, f"case-{index}")
        if failures:
            minimal = _shrink_case(case, tmp_path)
            pytest.fail(
                "deterministic contract violation(s): " + ", ".join(failures)
                + "\nminimal reproducible input:\n"
                + json.dumps(minimal, ensure_ascii=False, indent=2)
            )
