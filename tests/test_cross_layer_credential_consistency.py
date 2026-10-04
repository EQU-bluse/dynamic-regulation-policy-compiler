"""Cross-layer credential consistency regression tests.

The six credential layers — decision matrix attestation bundles, matrix
bundle evolutions, evolution checkpoints, evolution checkpoint bundles,
checkpoint chains, and checkpoint chain checkpoints — are normalized and
recomputed by the shared value engine, which reuses one verified node for
every type-and-value-identical occurrence of a deep credential.  These
tests pin down that this internal reuse never changes a public result:

* equal-valued inputs (dicts inserted in a different key order, and
  inputs repeating one deep credential in several members) produce
  byte-identical compact UTF-8 JSON results, leave their inputs
  untouched, and verify ``True`` against the published expected
  summaries;
* mutating one returned branch never leaks into sibling branches, the
  input objects, or later equal-valued calls;
* a structurally legal but untruthful digest, chain link, root, or
  expected value yields ``False`` — never a reused ``True``;
* an illegal key set, type, time order, or value domain raises
  ``ValueError`` — never a ``TypeError`` — even when an equal-text legal
  twin was verified earlier in the same structure: a facts key changed
  from the string ``"1"`` to the integer ``1`` in a later repeated
  occurrence, or a tuple where a list is required, is always rejected;
* generators raise ``ValueError`` on structurally legal but untruthful
  embedded proofs instead of returning partial results.

Everything is pure in-memory computation: no files, no history, no
network, no randomness, no timing assumptions.
"""

import copy
import json

import pytest

from regulation_policy_compiler.policy import (
    checkpoint_chain,
    checkpoint_chain_checkpoint,
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    evolution_checkpoint,
    evolution_checkpoint_bundle,
    matrix_bundle_evolution,
    verify_checkpoint_chain,
    verify_checkpoint_chain_checkpoint,
    verify_decision_matrix_attestation_bundle,
    verify_evolution_checkpoint,
    verify_evolution_checkpoint_bundle,
    verify_matrix_bundle_evolution,
)

START = "2021-01-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"
AT1 = "2021-05-01T00:00:00Z"
AT2 = "2021-06-01T00:00:00Z"
AT3 = "2021-07-01T00:00:00Z"
AT_BETWEEN = "2021-06-15T00:00:00Z"
RT1 = "2021-08-01T00:00:00Z"
RT2 = "2021-09-01T00:00:00Z"
RT3 = "2021-10-01T00:00:00Z"
RT_BETWEEN = "2021-09-15T00:00:00Z"
FORGE = "f" * 64


# ------------------------------------------------------------------ helpers


def _compact_bytes(value):
    """The publicly contracted compact UTF-8 JSON form, with no newline."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def _snapshot(value):
    """A type-faithful deep copy usable as a before/after equality witness.

    Unlike ``copy.deepcopy`` on the canonical result dicts (which copies
    through JSON and would fold an integer dict key to a string), this
    walk preserves key types and tuples, so a tampered input is compared
    against exactly what was passed in.
    """
    if isinstance(value, dict):
        return {key: _snapshot(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_snapshot(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_snapshot(item) for item in value)
    return value


def _reverse_key_order(value):
    """Rebuild every dict with reversed insertion order; values unchanged."""
    if isinstance(value, dict):
        return {
            key: _reverse_key_order(value[key])
            for key in reversed(list(value))
        }
    if isinstance(value, list):
        return [_reverse_key_order(item) for item in value]
    return value


def _int_fact_key(node):
    """Rewrite every string facts key ``"1"`` to the integer ``1``.

    Returns the number of rewrites so tests can prove the tamper landed.
    """
    count = 0
    if isinstance(node, dict):
        facts = node.get("facts")
        if isinstance(facts, dict) and "1" in facts:
            facts[1] = facts.pop("1")
            count += 1
        for value in node.values():
            count += _int_fact_key(value)
    elif isinstance(node, list):
        for value in node:
            count += _int_fact_key(value)
    return count


def _tuple_trace(node):
    """Replace every ``trace`` list with a tuple; returns the count."""
    count = 0
    if isinstance(node, dict):
        trace = node.get("trace")
        if isinstance(trace, list):
            node["trace"] = tuple(trace)
            count += 1
        for value in node.values():
            count += _tuple_trace(value)
    elif isinstance(node, list):
        for value in node:
            count += _tuple_trace(value)
    return count


# ----------------------------------------------------------------- builders


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


def _report_a():
    # The fact and condition key is the string "1": an equal-text twin
    # carrying the integer key 1 serializes identically but is illegal.
    return decision_matrix_attestation(
        START,
        END,
        [{"id": "c1", "facts": {"1": True}}],
        [_rule(when={"1": True}, result="允许")],
    )


def _report_b():
    return decision_matrix_attestation(
        START, END, [{"id": "c2", "facts": {}}], [_rule(result="z")]
    )


def _matrix_items():
    # The same deep credential occurs under two member ids.
    report = _report_a()
    return [
        {"id": "a", "report": report},
        {"id": "b", "report": copy.deepcopy(report)},
    ]


def _matrix_items_alt():
    return [
        {"id": "a", "report": _report_a()},
        {"id": "c", "report": _report_b()},
    ]


def _matrix_bundle():
    return decision_matrix_attestation_bundle(_matrix_items())


def _matrix_bundle_alt():
    return decision_matrix_attestation_bundle(_matrix_items_alt())


def _evolution_stages():
    # The same bundle subtree occurs in two consecutive stages.
    bundle = _matrix_bundle()
    return [
        {"at": AT1, "bundle": bundle},
        {"at": AT2, "bundle": copy.deepcopy(bundle)},
        {"at": AT3, "bundle": _matrix_bundle_alt()},
    ]


def _evolution():
    return matrix_bundle_evolution(_evolution_stages())


def _checkpoint_proof():
    # A non-head window: the anchor is the preceding stage digest and the
    # first window stage carries its front-side diff.
    return evolution_checkpoint(_evolution(), AT2, AT3)


def _checkpoint_proof_head():
    return evolution_checkpoint(_evolution(), AT1, AT1)


def _checkpoint_items():
    # The same window proof occurs under two member ids.
    span = _checkpoint_proof()
    return [
        {"id": "m", "proof": span},
        {"id": "w", "proof": _checkpoint_proof_head()},
        {"id": "z", "proof": copy.deepcopy(span)},
    ]


def _checkpoint_bundle():
    return evolution_checkpoint_bundle(_checkpoint_items())


def _checkpoint_bundle_alt():
    span = _checkpoint_proof()
    return evolution_checkpoint_bundle(
        [
            {"id": "m", "proof": span},
            {"id": "z", "proof": copy.deepcopy(span)},
        ]
    )


def _chain_stages():
    # The same checkpoint bundle subtree occurs in two consecutive stages.
    bundle = _checkpoint_bundle()
    return [
        {"at": RT1, "bundle": bundle},
        {"at": RT2, "bundle": copy.deepcopy(bundle)},
        {"at": RT3, "bundle": _checkpoint_bundle_alt()},
    ]


def _chain():
    return checkpoint_chain(_chain_stages())


def _chain_proof():
    return checkpoint_chain_checkpoint(_chain(), RT2, RT3)


# --------------------------------------------------------- expected summaries


def _bundle_expected(bundle):
    return {
        "root": bundle["root"],
        "report_ids": [member["id"] for member in bundle["reports"]],
    }


def _evolution_expected(report):
    return {
        "root": report["root"],
        "stages": [
            {"at": stage["at"], "root": stage["bundle"]["root"]}
            for stage in report["stages"]
        ],
    }


def _window_expected(proof):
    return {
        "start": proof["start"],
        "end": proof["end"],
        "anchor": proof["anchor"],
        "commitment": proof["commitment"],
    }


def _checkpoint_bundle_expected(bundle):
    return {
        "root": bundle["root"],
        "proof_ids": [member["id"] for member in bundle["proofs"]],
    }


def _chain_expected(report):
    return {
        "root": report["root"],
        "stages": [
            {
                "at": stage["at"],
                "bundle_root": stage["bundle"]["root"],
                "diff_digest": (
                    stage["diff"]["digest"] if stage["diff"] is not None else None
                ),
            }
            for stage in report["stages"]
        ],
    }


# ------------------------------------------------------------- layer registry

LAYERS = (
    "bundle",
    "evolution",
    "checkpoint",
    "checkpoint_bundle",
    "chain",
    "chain_checkpoint",
)

GENERATORS = {
    "bundle": decision_matrix_attestation_bundle,
    "evolution": matrix_bundle_evolution,
    "checkpoint": evolution_checkpoint,
    "checkpoint_bundle": evolution_checkpoint_bundle,
    "chain": checkpoint_chain,
    "chain_checkpoint": checkpoint_chain_checkpoint,
}

VERIFIERS = {
    "bundle": verify_decision_matrix_attestation_bundle,
    "evolution": verify_matrix_bundle_evolution,
    "checkpoint": verify_evolution_checkpoint,
    "checkpoint_bundle": verify_evolution_checkpoint_bundle,
    "chain": verify_checkpoint_chain,
    "chain_checkpoint": verify_checkpoint_chain_checkpoint,
}

EXPECTED_BUILDERS = {
    "bundle": _bundle_expected,
    "evolution": _evolution_expected,
    "checkpoint": _window_expected,
    "checkpoint_bundle": _checkpoint_bundle_expected,
    "chain": _chain_expected,
    "chain_checkpoint": _window_expected,
}


def _layer_args(layer):
    if layer == "bundle":
        return (_matrix_items(),)
    if layer == "evolution":
        return (_evolution_stages(),)
    if layer == "checkpoint":
        return (_evolution(), AT2, AT3)
    if layer == "checkpoint_bundle":
        return (_checkpoint_items(),)
    if layer == "chain":
        return (_chain_stages(),)
    return (_chain(), RT2, RT3)


# --------------------------------------------------------------- happy path


def test_full_ladder_generates_and_verifies_true_at_every_layer():
    # Layer 1: decision matrix attestation bundle.
    items = _matrix_items()
    items_snapshot = _snapshot(items)
    bundle = decision_matrix_attestation_bundle(items)
    assert items == items_snapshot
    assert (
        verify_decision_matrix_attestation_bundle(bundle, _bundle_expected(bundle))
        is True
    )

    # Layer 2: matrix bundle evolution.
    stages = [
        {"at": AT1, "bundle": bundle},
        {"at": AT2, "bundle": copy.deepcopy(bundle)},
        {"at": AT3, "bundle": _matrix_bundle_alt()},
    ]
    stages_snapshot = _snapshot(stages)
    evolution = matrix_bundle_evolution(stages)
    assert stages == stages_snapshot
    assert (
        verify_matrix_bundle_evolution(evolution, _evolution_expected(evolution))
        is True
    )

    # Layer 3: evolution checkpoint (non-head window).
    evolution_snapshot = _snapshot(evolution)
    proof = evolution_checkpoint(evolution, AT2, AT3)
    assert evolution == evolution_snapshot
    assert verify_evolution_checkpoint(proof, _window_expected(proof)) is True

    # Layer 4: evolution checkpoint bundle.
    proof_items = [
        {"id": "m", "proof": proof},
        {"id": "w", "proof": evolution_checkpoint(evolution, AT1, AT1)},
        {"id": "z", "proof": copy.deepcopy(proof)},
    ]
    proof_items_snapshot = _snapshot(proof_items)
    checkpoint_bundle = evolution_checkpoint_bundle(proof_items)
    assert proof_items == proof_items_snapshot
    assert (
        verify_evolution_checkpoint_bundle(
            checkpoint_bundle, _checkpoint_bundle_expected(checkpoint_bundle)
        )
        is True
    )

    # Layer 5: checkpoint chain.
    chain_stages = [
        {"at": RT1, "bundle": checkpoint_bundle},
        {"at": RT2, "bundle": copy.deepcopy(checkpoint_bundle)},
        {
            "at": RT3,
            "bundle": evolution_checkpoint_bundle(
                [
                    {"id": "m", "proof": proof},
                    {"id": "z", "proof": copy.deepcopy(proof)},
                ]
            ),
        },
    ]
    chain_stages_snapshot = _snapshot(chain_stages)
    chain = checkpoint_chain(chain_stages)
    assert chain_stages == chain_stages_snapshot
    assert verify_checkpoint_chain(chain, _chain_expected(chain)) is True

    # Layer 6: checkpoint chain checkpoint (non-head window).
    chain_snapshot = _snapshot(chain)
    chain_proof = checkpoint_chain_checkpoint(chain, RT2, RT3)
    assert chain == chain_snapshot
    assert (
        verify_checkpoint_chain_checkpoint(chain_proof, _window_expected(chain_proof))
        is True
    )


@pytest.mark.parametrize("layer", LAYERS)
def test_equal_valued_inputs_produce_byte_identical_results(layer):
    args = _layer_args(layer)
    first = GENERATORS[layer](*args)
    second = GENERATORS[layer](*_snapshot(args))
    assert _compact_bytes(first) == _compact_bytes(second)


@pytest.mark.parametrize("layer", LAYERS)
def test_dict_insertion_order_does_not_change_result_or_verdict(layer):
    args = _layer_args(layer)
    reference = GENERATORS[layer](*_snapshot(args))
    reordered = GENERATORS[layer](*[_reverse_key_order(arg) for arg in args])
    assert _compact_bytes(reference) == _compact_bytes(reordered)
    verifier = VERIFIERS[layer]
    assert verifier(reordered, EXPECTED_BUILDERS[layer](reordered)) is True
    # A key-reordered expected summary verifies the reference result too.
    assert (
        verifier(
            reference,
            _reverse_key_order(EXPECTED_BUILDERS[layer](reference)),
        )
        is True
    )


@pytest.mark.parametrize("layer", LAYERS)
def test_generate_does_not_mutate_inputs(layer):
    args = _layer_args(layer)
    snapshot = _snapshot(args)
    GENERATORS[layer](*args)
    assert args == snapshot


@pytest.mark.parametrize("layer", LAYERS)
def test_verify_does_not_mutate_inputs(layer):
    result = GENERATORS[layer](*_layer_args(layer))
    expected = EXPECTED_BUILDERS[layer](result)
    snapshot = _snapshot((result, expected))
    assert VERIFIERS[layer](result, expected) is True
    assert (result, expected) == snapshot


# ----------------------------------------------------------- repeated subtrees


def test_repeated_matrix_report_is_value_equal_but_not_shared():
    bundle = _matrix_bundle()
    assert (
        verify_decision_matrix_attestation_bundle(bundle, _bundle_expected(bundle))
        is True
    )
    first = bundle["reports"][0]["report"]
    second = bundle["reports"][1]["report"]
    assert first == second
    assert first is not second
    first["digest"] = "mutated"
    assert second["digest"] != "mutated"


def test_repeated_evolution_stage_bundle_is_value_equal_but_not_shared():
    evolution = _evolution()
    assert (
        verify_matrix_bundle_evolution(evolution, _evolution_expected(evolution))
        is True
    )
    first = evolution["stages"][0]["bundle"]
    second = evolution["stages"][1]["bundle"]
    assert first == second
    assert first is not second
    first["root"] = "mutated"
    assert second["root"] != "mutated"


def test_repeated_checkpoint_proof_is_value_equal_but_not_shared():
    bundle = _checkpoint_bundle()
    assert (
        verify_evolution_checkpoint_bundle(
            bundle, _checkpoint_bundle_expected(bundle)
        )
        is True
    )
    # Members are ordered by id: m, w, z; the span proof occurs under m and z.
    first = bundle["proofs"][0]["proof"]
    second = bundle["proofs"][2]["proof"]
    assert first == second
    assert first is not second
    first["commitment"] = "mutated"
    assert second["commitment"] != "mutated"


def test_repeated_chain_stage_bundle_is_value_equal_but_not_shared():
    chain = _chain()
    assert verify_checkpoint_chain(chain, _chain_expected(chain)) is True
    first = chain["stages"][0]["bundle"]
    second = chain["stages"][1]["bundle"]
    assert first == second
    assert first is not second
    first["root"] = "mutated"
    assert second["root"] != "mutated"


# --------------------------------------------------------- mutation isolation


def _branches(layer, result):
    if layer == "bundle":
        return result["reports"]
    if layer == "checkpoint_bundle":
        return result["proofs"]
    return result["stages"]


def _mutate_first_branch(layer, result):
    branch = _branches(layer, result)[0]
    if layer == "bundle":
        branch["report"]["digest"] = "mutated"
        branch["digest"] = "mutated"
    elif layer == "checkpoint_bundle":
        branch["proof"]["commitment"] = "mutated"
        branch["digest"] = "mutated"
    else:
        branch["bundle"]["root"] = "mutated"
        branch["digest"] = "mutated"


@pytest.mark.parametrize("layer", LAYERS)
def test_mutating_one_returned_branch_isolates_everything_else(layer):
    args = _layer_args(layer)
    snapshot = _snapshot(args)
    generate = GENERATORS[layer]
    result = generate(*args)
    reference = generate(*_snapshot(args))
    _mutate_first_branch(layer, result)
    # The mutation landed, but no sibling branch moved with it.
    assert _branches(layer, result)[0] != _branches(layer, reference)[0]
    assert _branches(layer, result)[1:] == _branches(layer, reference)[1:]
    # The input objects are untouched ...
    assert args == snapshot
    # ... and a later equal-valued call still produces the same bytes.
    assert _compact_bytes(generate(*args)) == _compact_bytes(reference)


# ------------------------------------------- legal structure, untrue content


def _false_bundle_member_digest(result, expected):
    result["reports"][0]["digest"] = FORGE


def _false_bundle_member_previous(result, expected):
    result["reports"][1]["previous"] = FORGE


def _false_bundle_root(result, expected):
    result["root"] = FORGE


def _false_bundle_expected_root(result, expected):
    expected["root"] = FORGE


def _false_bundle_expected_ids(result, expected):
    expected["report_ids"] = ["a", "zz"]


def _false_evolution_stage_digest(result, expected):
    result["stages"][1]["digest"] = FORGE


def _false_evolution_stage_previous(result, expected):
    result["stages"][1]["previous"] = FORGE


def _false_evolution_root(result, expected):
    result["root"] = FORGE


def _false_evolution_expected_stage_root(result, expected):
    expected["stages"][0]["root"] = FORGE


def _false_evolution_expected_root(result, expected):
    expected["root"] = FORGE


def _false_checkpoint_commitment(result, expected):
    result["commitment"] = FORGE


def _false_checkpoint_anchor(result, expected):
    result["anchor"] = FORGE


def _false_checkpoint_stage_digest(result, expected):
    result["stages"][1]["digest"] = FORGE


def _false_checkpoint_expected_commitment(result, expected):
    expected["commitment"] = FORGE


def _false_checkpoint_bundle_member_digest(result, expected):
    result["proofs"][0]["digest"] = FORGE


def _false_checkpoint_bundle_member_previous(result, expected):
    result["proofs"][1]["previous"] = FORGE


def _false_checkpoint_bundle_root(result, expected):
    result["root"] = FORGE


def _false_checkpoint_bundle_expected_ids(result, expected):
    expected["proof_ids"] = ["m", "zz"]


def _false_chain_stage_digest(result, expected):
    result["stages"][1]["digest"] = FORGE


def _false_chain_root(result, expected):
    result["root"] = FORGE


def _false_chain_expected_diff_digest(result, expected):
    expected["stages"][1]["diff_digest"] = FORGE


def _false_chain_expected_bundle_root(result, expected):
    expected["stages"][0]["bundle_root"] = FORGE


def _false_chain_checkpoint_commitment(result, expected):
    result["commitment"] = FORGE


def _false_chain_checkpoint_anchor(result, expected):
    result["anchor"] = FORGE


def _false_chain_checkpoint_stage_previous(result, expected):
    result["stages"][1]["previous"] = FORGE


def _false_chain_checkpoint_expected_anchor(result, expected):
    expected["anchor"] = FORGE


FALSE_CASES = [
    ("bundle", _false_bundle_member_digest),
    ("bundle", _false_bundle_member_previous),
    ("bundle", _false_bundle_root),
    ("bundle", _false_bundle_expected_root),
    ("bundle", _false_bundle_expected_ids),
    ("evolution", _false_evolution_stage_digest),
    ("evolution", _false_evolution_stage_previous),
    ("evolution", _false_evolution_root),
    ("evolution", _false_evolution_expected_stage_root),
    ("evolution", _false_evolution_expected_root),
    ("checkpoint", _false_checkpoint_commitment),
    ("checkpoint", _false_checkpoint_anchor),
    ("checkpoint", _false_checkpoint_stage_digest),
    ("checkpoint", _false_checkpoint_expected_commitment),
    ("checkpoint_bundle", _false_checkpoint_bundle_member_digest),
    ("checkpoint_bundle", _false_checkpoint_bundle_member_previous),
    ("checkpoint_bundle", _false_checkpoint_bundle_root),
    ("checkpoint_bundle", _false_checkpoint_bundle_expected_ids),
    ("chain", _false_chain_stage_digest),
    ("chain", _false_chain_root),
    ("chain", _false_chain_expected_diff_digest),
    ("chain", _false_chain_expected_bundle_root),
    ("chain_checkpoint", _false_chain_checkpoint_commitment),
    ("chain_checkpoint", _false_chain_checkpoint_anchor),
    ("chain_checkpoint", _false_chain_checkpoint_stage_previous),
    ("chain_checkpoint", _false_chain_checkpoint_expected_anchor),
]


@pytest.mark.parametrize("layer,tamper", FALSE_CASES)
def test_verify_returns_false_for_untruthful_but_legal_content(layer, tamper):
    result = GENERATORS[layer](*_layer_args(layer))
    expected = EXPECTED_BUILDERS[layer](result)
    assert VERIFIERS[layer](result, copy.deepcopy(expected)) is True
    tamper(result, expected)
    snapshot = _snapshot((result, expected))
    assert VERIFIERS[layer](result, expected) is False
    assert (result, expected) == snapshot


# ------------------------------------------------------- illegal structure


def _struct_bundle_drop_root(result, expected):
    del result["root"]


def _struct_bundle_extra_key(result, expected):
    result["extra"] = 1


def _struct_bundle_member_drop_digest(result, expected):
    del result["reports"][0]["digest"]


def _struct_bundle_member_extra_key(result, expected):
    result["reports"][0]["extra"] = 1


def _struct_bundle_member_id_not_str(result, expected):
    result["reports"][0]["id"] = 1


def _struct_bundle_root_not_hex(result, expected):
    result["root"] = "z" * 64


def _struct_bundle_reports_tuple(result, expected):
    result["reports"] = tuple(result["reports"])


def _struct_bundle_expected_drop_ids(result, expected):
    del expected["report_ids"]


def _struct_bundle_expected_extra_key(result, expected):
    expected["extra"] = 1


def _struct_bundle_expected_ids_tuple(result, expected):
    expected["report_ids"] = tuple(expected["report_ids"])


def _struct_evolution_drop_stages(result, expected):
    del result["stages"]


def _struct_evolution_stage_drop_at(result, expected):
    del result["stages"][0]["at"]


def _struct_evolution_stage_extra_key(result, expected):
    result["stages"][0]["extra"] = 1


def _struct_evolution_duplicate_at(result, expected):
    result["stages"][1]["at"] = result["stages"][0]["at"]


def _struct_evolution_reversed_at(result, expected):
    first, second = result["stages"][0], result["stages"][1]
    first["at"], second["at"] = second["at"], first["at"]


def _struct_evolution_bad_time(result, expected):
    result["stages"][0]["at"] = "not-a-time"


def _struct_evolution_stages_tuple(result, expected):
    result["stages"] = tuple(result["stages"])


def _struct_evolution_expected_stage_extra_key(result, expected):
    expected["stages"][0]["extra"] = 1


def _struct_evolution_expected_duplicate_at(result, expected):
    expected["stages"][1]["at"] = expected["stages"][0]["at"]


def _struct_checkpoint_drop_anchor(result, expected):
    del result["anchor"]


def _struct_checkpoint_extra_key(result, expected):
    result["extra"] = 1


def _struct_checkpoint_stage_drop_digest(result, expected):
    del result["stages"][0]["digest"]


def _struct_checkpoint_duplicate_at(result, expected):
    result["stages"][1]["at"] = result["stages"][0]["at"]


def _struct_checkpoint_reversed_window(result, expected):
    result["start"], result["end"] = result["end"], result["start"]


def _struct_checkpoint_stages_tuple(result, expected):
    result["stages"] = tuple(result["stages"])


def _struct_checkpoint_expected_extra_key(result, expected):
    expected["extra"] = 1


def _struct_checkpoint_expected_bad_time(result, expected):
    expected["end"] = "not-a-time"


def _struct_checkpoint_bundle_drop_proofs(result, expected):
    del result["proofs"]


def _struct_checkpoint_bundle_member_drop_previous(result, expected):
    del result["proofs"][0]["previous"]


def _struct_checkpoint_bundle_member_extra_key(result, expected):
    result["proofs"][0]["extra"] = 1


def _struct_checkpoint_bundle_proofs_tuple(result, expected):
    result["proofs"] = tuple(result["proofs"])


def _struct_checkpoint_bundle_expected_drop_ids(result, expected):
    del expected["proof_ids"]


def _struct_checkpoint_bundle_expected_ids_tuple(result, expected):
    expected["proof_ids"] = tuple(expected["proof_ids"])


def _struct_chain_stage_drop_previous(result, expected):
    del result["stages"][1]["previous"]


def _struct_chain_stage_extra_key(result, expected):
    result["stages"][1]["extra"] = 1


def _struct_chain_duplicate_at(result, expected):
    result["stages"][1]["at"] = result["stages"][0]["at"]


def _struct_chain_reversed_at(result, expected):
    first, second = result["stages"][1], result["stages"][2]
    first["at"], second["at"] = second["at"], first["at"]


def _struct_chain_stages_tuple(result, expected):
    result["stages"] = tuple(result["stages"])


def _struct_chain_expected_stage_drop_diff_digest(result, expected):
    del expected["stages"][1]["diff_digest"]


def _struct_chain_expected_first_diff_digest_not_null(result, expected):
    expected["stages"][0]["diff_digest"] = FORGE


def _struct_chain_expected_stages_tuple(result, expected):
    expected["stages"] = tuple(expected["stages"])


def _struct_chain_checkpoint_drop_commitment(result, expected):
    del result["commitment"]


def _struct_chain_checkpoint_extra_key(result, expected):
    result["extra"] = 1


def _struct_chain_checkpoint_stage_drop_bundle(result, expected):
    del result["stages"][0]["bundle"]


def _struct_chain_checkpoint_duplicate_at(result, expected):
    result["stages"][1]["at"] = result["stages"][0]["at"]


def _struct_chain_checkpoint_anchor_not_hex(result, expected):
    result["anchor"] = "zz"


def _struct_chain_checkpoint_stages_tuple(result, expected):
    result["stages"] = tuple(result["stages"])


def _struct_chain_checkpoint_expected_drop_anchor(result, expected):
    del expected["anchor"]


STRUCTURAL_CASES = [
    ("bundle", _struct_bundle_drop_root),
    ("bundle", _struct_bundle_extra_key),
    ("bundle", _struct_bundle_member_drop_digest),
    ("bundle", _struct_bundle_member_extra_key),
    ("bundle", _struct_bundle_member_id_not_str),
    ("bundle", _struct_bundle_root_not_hex),
    ("bundle", _struct_bundle_reports_tuple),
    ("bundle", _struct_bundle_expected_drop_ids),
    ("bundle", _struct_bundle_expected_extra_key),
    ("bundle", _struct_bundle_expected_ids_tuple),
    ("evolution", _struct_evolution_drop_stages),
    ("evolution", _struct_evolution_stage_drop_at),
    ("evolution", _struct_evolution_stage_extra_key),
    ("evolution", _struct_evolution_duplicate_at),
    ("evolution", _struct_evolution_reversed_at),
    ("evolution", _struct_evolution_bad_time),
    ("evolution", _struct_evolution_stages_tuple),
    ("evolution", _struct_evolution_expected_stage_extra_key),
    ("evolution", _struct_evolution_expected_duplicate_at),
    ("checkpoint", _struct_checkpoint_drop_anchor),
    ("checkpoint", _struct_checkpoint_extra_key),
    ("checkpoint", _struct_checkpoint_stage_drop_digest),
    ("checkpoint", _struct_checkpoint_duplicate_at),
    ("checkpoint", _struct_checkpoint_reversed_window),
    ("checkpoint", _struct_checkpoint_stages_tuple),
    ("checkpoint", _struct_checkpoint_expected_extra_key),
    ("checkpoint", _struct_checkpoint_expected_bad_time),
    ("checkpoint_bundle", _struct_checkpoint_bundle_drop_proofs),
    ("checkpoint_bundle", _struct_checkpoint_bundle_member_drop_previous),
    ("checkpoint_bundle", _struct_checkpoint_bundle_member_extra_key),
    ("checkpoint_bundle", _struct_checkpoint_bundle_proofs_tuple),
    ("checkpoint_bundle", _struct_checkpoint_bundle_expected_drop_ids),
    ("checkpoint_bundle", _struct_checkpoint_bundle_expected_ids_tuple),
    ("chain", _struct_chain_stage_drop_previous),
    ("chain", _struct_chain_stage_extra_key),
    ("chain", _struct_chain_duplicate_at),
    ("chain", _struct_chain_reversed_at),
    ("chain", _struct_chain_stages_tuple),
    ("chain", _struct_chain_expected_stage_drop_diff_digest),
    ("chain", _struct_chain_expected_first_diff_digest_not_null),
    ("chain", _struct_chain_expected_stages_tuple),
    ("chain_checkpoint", _struct_chain_checkpoint_drop_commitment),
    ("chain_checkpoint", _struct_chain_checkpoint_extra_key),
    ("chain_checkpoint", _struct_chain_checkpoint_stage_drop_bundle),
    ("chain_checkpoint", _struct_chain_checkpoint_duplicate_at),
    ("chain_checkpoint", _struct_chain_checkpoint_anchor_not_hex),
    ("chain_checkpoint", _struct_chain_checkpoint_stages_tuple),
    ("chain_checkpoint", _struct_chain_checkpoint_expected_drop_anchor),
]


@pytest.mark.parametrize("layer,tamper", STRUCTURAL_CASES)
def test_verify_raises_value_error_for_illegal_structure(layer, tamper):
    result = GENERATORS[layer](*_layer_args(layer))
    expected = EXPECTED_BUILDERS[layer](result)
    tamper(result, expected)
    snapshot = _snapshot((result, expected))
    # A TypeError leaking out of the shared engine would fail this test.
    with pytest.raises(ValueError):
        VERIFIERS[layer](result, expected)
    assert (result, expected) == snapshot


# ------------------------------------------- illegal generator inputs


def test_evolution_generate_rejects_duplicate_stage_time():
    stages = _evolution_stages()
    stages[1]["at"] = stages[0]["at"]
    snapshot = _snapshot(stages)
    with pytest.raises(ValueError):
        matrix_bundle_evolution(stages)
    assert stages == snapshot


def test_evolution_generate_rejects_reversed_stage_times():
    stages = _evolution_stages()
    stages[0]["at"], stages[1]["at"] = stages[1]["at"], stages[0]["at"]
    snapshot = _snapshot(stages)
    with pytest.raises(ValueError):
        matrix_bundle_evolution(stages)
    assert stages == snapshot


def test_chain_generate_rejects_duplicate_stage_time():
    stages = _chain_stages()
    stages[1]["at"] = stages[0]["at"]
    snapshot = _snapshot(stages)
    with pytest.raises(ValueError):
        checkpoint_chain(stages)
    assert stages == snapshot


def test_chain_generate_rejects_reversed_stage_times():
    stages = _chain_stages()
    stages[0]["at"], stages[1]["at"] = stages[1]["at"], stages[0]["at"]
    snapshot = _snapshot(stages)
    with pytest.raises(ValueError):
        checkpoint_chain(stages)
    assert stages == snapshot


TUPLE_GENERATE_CASES = [
    (decision_matrix_attestation_bundle, _matrix_items),
    (matrix_bundle_evolution, _evolution_stages),
    (evolution_checkpoint_bundle, _checkpoint_items),
    (checkpoint_chain, _chain_stages),
]


@pytest.mark.parametrize(
    "generate,make_input",
    TUPLE_GENERATE_CASES,
    ids=[generate.__name__ for generate, _ in TUPLE_GENERATE_CASES],
)
def test_generate_rejects_tuple_where_list_is_required(generate, make_input):
    bad = tuple(make_input())
    snapshot = _snapshot(bad)
    with pytest.raises(ValueError):
        generate(bad)
    assert bad == snapshot


@pytest.mark.parametrize("start,end", [(AT3, AT2), (AT2, AT_BETWEEN)])
def test_checkpoint_generate_rejects_invalid_window(start, end):
    evolution = _evolution()
    snapshot = _snapshot(evolution)
    with pytest.raises(ValueError):
        evolution_checkpoint(evolution, start, end)
    assert evolution == snapshot


@pytest.mark.parametrize("start,end", [(RT3, RT2), (RT2, RT_BETWEEN)])
def test_chain_checkpoint_generate_rejects_invalid_window(start, end):
    chain = _chain()
    snapshot = _snapshot(chain)
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint(chain, start, end)
    assert chain == snapshot


# --------------------------- untruthful embedded credentials at generate time


def test_bundle_generate_rejects_untruthful_embedded_report():
    items = _matrix_items()
    items[0]["report"]["digest"] = FORGE
    snapshot = _snapshot(items)
    with pytest.raises(ValueError):
        decision_matrix_attestation_bundle(items)
    assert items == snapshot


def test_evolution_generate_rejects_untruthful_embedded_bundle():
    stages = _evolution_stages()
    stages[0]["bundle"]["root"] = FORGE
    snapshot = _snapshot(stages)
    with pytest.raises(ValueError):
        matrix_bundle_evolution(stages)
    assert stages == snapshot


def test_checkpoint_generate_rejects_untruthful_embedded_evolution():
    evolution = _evolution()
    evolution["stages"][1]["digest"] = FORGE
    snapshot = _snapshot(evolution)
    with pytest.raises(ValueError):
        evolution_checkpoint(evolution, AT2, AT3)
    assert evolution == snapshot


def test_checkpoint_bundle_generate_rejects_untruthful_embedded_proof():
    items = _checkpoint_items()
    items[0]["proof"]["commitment"] = FORGE
    snapshot = _snapshot(items)
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle(items)
    assert items == snapshot


def test_chain_generate_rejects_untruthful_embedded_bundle():
    stages = _chain_stages()
    stages[0]["bundle"]["proofs"][0]["digest"] = FORGE
    snapshot = _snapshot(stages)
    with pytest.raises(ValueError):
        checkpoint_chain(stages)
    assert stages == snapshot


def test_chain_checkpoint_generate_rejects_untruthful_embedded_chain():
    chain = _chain()
    chain["root"] = FORGE
    snapshot = _snapshot(chain)
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint(chain, RT2, RT3)
    assert chain == snapshot


# ------------------------------------------- type collisions in repeated subtrees


def test_bundle_generate_rejects_int_fact_key_in_later_twin():
    legal = _report_a()
    impostor = copy.deepcopy(legal)
    assert _int_fact_key(impostor) > 0
    items = [
        {"id": "a", "report": legal},
        {"id": "b", "report": impostor},
    ]
    snapshot = _snapshot(items)
    with pytest.raises(ValueError):
        decision_matrix_attestation_bundle(items)
    assert items == snapshot


def test_bundle_verify_rejects_int_fact_key_in_later_twin():
    bundle = _matrix_bundle()
    expected = _bundle_expected(bundle)
    # The legal structure verifies first; the equal-text impostor parsed
    # after its legal twin must still not reuse that verdict.
    assert verify_decision_matrix_attestation_bundle(bundle, expected) is True
    assert _int_fact_key(bundle["reports"][1]["report"]) > 0
    snapshot = _snapshot(bundle)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, expected)
    assert bundle == snapshot


def test_checkpoint_bundle_generate_rejects_int_fact_key_in_later_twin():
    items = _checkpoint_items()
    # Caller order m, w, z: the legal span proof under m is parsed before
    # its impostor twin under z.
    assert _int_fact_key(items[2]["proof"]) > 0
    snapshot = _snapshot(items)
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle(items)
    assert items == snapshot


def test_checkpoint_bundle_verify_rejects_int_fact_key_in_later_twin():
    bundle = _checkpoint_bundle()
    expected = _checkpoint_bundle_expected(bundle)
    assert verify_evolution_checkpoint_bundle(bundle, expected) is True
    # Members are ordered m, w, z; tamper the later span-proof occurrence.
    assert _int_fact_key(bundle["proofs"][2]["proof"]) > 0
    snapshot = _snapshot(bundle)
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(bundle, expected)
    assert bundle == snapshot


def test_chain_generate_rejects_int_fact_key_in_later_stage_bundle():
    stages = _chain_stages()
    # Stage 2 repeats stage 1's bundle subtree; tamper the later one.
    assert _int_fact_key(stages[1]["bundle"]) > 0
    snapshot = _snapshot(stages)
    with pytest.raises(ValueError):
        checkpoint_chain(stages)
    assert stages == snapshot


def test_chain_verify_rejects_int_fact_key_in_later_stage_bundle():
    chain = _chain()
    expected = _chain_expected(chain)
    assert verify_checkpoint_chain(chain, expected) is True
    assert _int_fact_key(chain["stages"][1]["bundle"]) > 0
    snapshot = _snapshot(chain)
    with pytest.raises(ValueError):
        verify_checkpoint_chain(chain, expected)
    assert chain == snapshot


def test_chain_checkpoint_verify_rejects_int_fact_key_in_later_twin():
    proof = _chain_proof()
    expected = _window_expected(proof)
    assert verify_checkpoint_chain_checkpoint(proof, expected) is True
    # The span proof occurs under members m and z of the stage bundle;
    # tamper the later occurrence.
    target = proof["stages"][0]["bundle"]["proofs"][2]["proof"]
    assert _int_fact_key(target) > 0
    snapshot = _snapshot(proof)
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, expected)
    assert proof == snapshot


def test_chain_checkpoint_verify_rejects_tuple_trace_in_later_twin():
    proof = _chain_proof()
    expected = _window_expected(proof)
    assert verify_checkpoint_chain_checkpoint(proof, expected) is True
    target = proof["stages"][0]["bundle"]["proofs"][2]["proof"]
    assert _tuple_trace(target) > 0
    snapshot = _snapshot(proof)
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, expected)
    assert proof == snapshot
