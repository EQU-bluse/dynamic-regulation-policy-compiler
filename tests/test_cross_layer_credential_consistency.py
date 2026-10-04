"""Cross-layer credential consistency regression tests.

The deep credential layers are all produced by the shared normalization
engine, which reuses one verified node for every type-and-value-identical
occurrence of a subtree.  These tests pin down, across the whole public
ladder

    decision_matrix_attestation_bundle
    -> matrix_bundle_evolution
    -> evolution_checkpoint
    -> evolution_checkpoint_bundle
    -> checkpoint_chain
    -> checkpoint_chain_checkpoint

that this internal reuse never changes a public result:

* every layer's generator, verifier, and expected summary agree on one
  minimal legal sample, and equal-valued inputs (dict insertion order
  permuted, the same deep credential repeated in several members) yield
  byte-identical compact UTF-8 JSON while the inputs stay untouched;
* mutating one returned branch never affects sibling branches, the input
  objects, or later equal-valued calls;
* single-point forgeries behave exactly as contracted: a format-valid but
  false digest, link, root, or expected value yields ``False``; an illegal
  key set, type, time order, or value domain raises ``ValueError`` — a
  tuple where a list is required and an integer fact key ``1`` where the
  string ``"1"`` was already verified in a repeated subtree included —
  without ever leaking ``TypeError`` or reusing a merely similar validated
  result;
* generators reject structurally legal but untruthful embedded proofs
  with ``ValueError`` and return no partial result.

Every failing assertion also confirms the inputs were not mutated.  The
tests are pure-function only: no files, history, network, randomness, or
timing dependence.
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
RT1 = "2021-08-01T00:00:00Z"
RT2 = "2021-09-01T00:00:00Z"
RT3 = "2021-10-01T00:00:00Z"
GENESIS = "0" * 64
FALSE64 = "f" * 64


# ------------------------------------------------------------------ builders


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


def _report_c():
    return decision_matrix_attestation(
        START, END, [{"id": "c3", "facts": {"y": False}}], [_rule(result="q")]
    )


def _matrix_bundle_one():
    return decision_matrix_attestation_bundle([{"id": "a", "report": _report_a()}])


def _matrix_bundle_two_items():
    # The same deep credential appears in two members.
    return [
        {"id": "é", "report": _report_a()},
        {"id": "b", "report": _report_b()},
        {"id": "a", "report": _report_a()},
    ]


def _matrix_bundle_two():
    return decision_matrix_attestation_bundle(_matrix_bundle_two_items())


def _matrix_bundle_three():
    return decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": _report_a()},
            {"id": "b", "report": _report_b()},
            {"id": "c", "report": _report_c()},
        ]
    )


def _evolution_stages():
    return [
        {"at": AT1, "bundle": _matrix_bundle_one()},
        {"at": AT2, "bundle": _matrix_bundle_two()},
        {"at": AT3, "bundle": _matrix_bundle_three()},
    ]


def _evolution():
    return matrix_bundle_evolution(_evolution_stages())


def _checkpoint_proofs():
    evolution = _evolution()
    return {
        "head": evolution_checkpoint(evolution, AT1, AT1),
        "mid": evolution_checkpoint(evolution, AT2, AT2),
        "tail": evolution_checkpoint(evolution, AT3, AT3),
        "span": evolution_checkpoint(evolution, AT1, AT2),
    }


def _checkpoint_bundle_items():
    proofs = _checkpoint_proofs()
    return [
        {"id": "beta", "proof": proofs["span"]},
        {"id": "alpha", "proof": proofs["head"]},
        # The same window proof appears in two members.
        {"id": "伽马", "proof": proofs["span"]},
    ]


def _checkpoint_bundle():
    return evolution_checkpoint_bundle(_checkpoint_bundle_items())


def _chain_stages():
    proofs = _checkpoint_proofs()
    # The "span" proof recurs in every stage bundle.
    return [
        {
            "at": RT1,
            "bundle": evolution_checkpoint_bundle(
                [
                    {"id": "a", "proof": proofs["head"]},
                    {"id": "z", "proof": proofs["span"]},
                ]
            ),
        },
        {
            "at": RT2,
            "bundle": evolution_checkpoint_bundle(
                [
                    {"id": "a", "proof": proofs["mid"]},
                    {"id": "z", "proof": proofs["span"]},
                ]
            ),
        },
        {
            "at": RT3,
            "bundle": evolution_checkpoint_bundle(
                [
                    {"id": "a", "proof": proofs["tail"]},
                    {"id": "b", "proof": proofs["mid"]},
                    {"id": "z", "proof": proofs["span"]},
                ]
            ),
        },
    ]


def _chain():
    return checkpoint_chain(_chain_stages())


def _window_proof(start, end):
    return checkpoint_chain_checkpoint(_chain(), start, end)


# ------------------------------------------------------------- expected forms


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


def _chain_expected(chain):
    return {
        "root": chain["root"],
        "stages": [
            {
                "at": stage["at"],
                "bundle_root": stage["bundle"]["root"],
                "diff_digest": (
                    None if stage["diff"] is None else stage["diff"]["digest"]
                ),
            }
            for stage in chain["stages"]
        ],
    }


# ------------------------------------------------------------------- helpers


def _compact(value):
    """The publicly contracted compact UTF-8 JSON form."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def _reordered(value):
    """Deep copy with every dict's insertion order reversed."""
    if isinstance(value, dict):
        return {key: _reordered(item) for key, item in reversed(list(value.items()))}
    if isinstance(value, list):
        return [_reordered(item) for item in value]
    return value


def _int_fact_key(node):
    """Replace every facts key "1" with the integer 1, in place."""
    if isinstance(node, dict):
        facts = node.get("facts")
        if isinstance(facts, dict) and "1" in facts:
            facts[1] = facts.pop("1")
        for value in node.values():
            _int_fact_key(value)
    elif isinstance(node, list):
        for value in node:
            _int_fact_key(value)


def _freeze(value):
    """A type-faithful, hashable snapshot of an arbitrary JSON-like value.

    Unlike ``copy.deepcopy`` — whose fast path on the returned credential
    dicts round-trips through JSON and would silently convert a tuple to a
    list or an integer dict key to a string — this snapshot keeps every
    container and key type distinct, so "the call did not mutate its input"
    is checked without masking the very type collisions under test.
    """
    if isinstance(value, dict):
        return ("dict", frozenset((key, _freeze(item)) for key, item in value.items()))
    if isinstance(value, list):
        return ("list", tuple(_freeze(item) for item in value))
    if isinstance(value, tuple):
        return ("tuple", tuple(_freeze(item) for item in value))
    return value


def _assert_false_unmutated(verify, report, expected):
    """The call returns False and neither argument is mutated."""
    report_snapshot = _freeze(report)
    expected_snapshot = _freeze(expected)
    assert verify(report, expected) is False
    assert _freeze(report) == report_snapshot
    assert _freeze(expected) == expected_snapshot


def _assert_raises_unmutated(call, *watched):
    """The call raises ValueError and every watched object is unmutated."""
    snapshots = [_freeze(item) for item in watched]
    with pytest.raises(ValueError):
        call()
    for item, snapshot in zip(watched, snapshots):
        assert _freeze(item) == snapshot


# --------------------------------------------------------- layer parametrization
#
# Each entry exposes fresh-input factories plus one result-branch mutation
# whose sibling branch must stay untouched, so the uniform checks below run
# identically against every layer of the ladder.


def _layers():
    return [
        {
            "name": "decision_matrix_attestation_bundle",
            "inputs": _matrix_bundle_two_items,
            "generate": decision_matrix_attestation_bundle,
            "verify": verify_decision_matrix_attestation_bundle,
            "expected": _bundle_expected,
            # Member "a" and member "é" carry the same credential.
            "tamper": lambda r: r["reports"][0]["report"].__setitem__(
                "digest", FALSE64
            ),
            "unaffected": lambda r: r["reports"][2]["report"],
        },
        {
            "name": "matrix_bundle_evolution",
            "inputs": _evolution_stages,
            "generate": matrix_bundle_evolution,
            "verify": verify_matrix_bundle_evolution,
            "expected": _evolution_expected,
            "tamper": lambda r: r["stages"][0]["bundle"].__setitem__(
                "root", FALSE64
            ),
            "unaffected": lambda r: r["stages"][1]["bundle"],
        },
        {
            "name": "evolution_checkpoint",
            "inputs": lambda: {"report": _evolution(), "start": AT2, "end": AT3},
            "generate": lambda i: evolution_checkpoint(
                i["report"], i["start"], i["end"]
            ),
            "verify": verify_evolution_checkpoint,
            "expected": _window_expected,
            "tamper": lambda r: r["stages"][0]["bundle"].__setitem__(
                "root", FALSE64
            ),
            "unaffected": lambda r: r["stages"][1]["bundle"],
        },
        {
            "name": "evolution_checkpoint_bundle",
            "inputs": _checkpoint_bundle_items,
            "generate": evolution_checkpoint_bundle,
            "verify": verify_evolution_checkpoint_bundle,
            "expected": _checkpoint_bundle_expected,
            # Members "beta" and "伽马" carry the same window proof.
            "tamper": lambda r: r["proofs"][1]["proof"]["stages"][0].__setitem__(
                "digest", FALSE64
            ),
            "unaffected": lambda r: r["proofs"][2]["proof"],
        },
        {
            "name": "checkpoint_chain",
            "inputs": _chain_stages,
            "generate": checkpoint_chain,
            "verify": verify_checkpoint_chain,
            "expected": _chain_expected,
            "tamper": lambda r: r["stages"][0]["bundle"]["proofs"][1][
                "proof"
            ].__setitem__("commitment", FALSE64),
            # The repeated "span" proof inside the last stage's bundle.
            "unaffected": lambda r: r["stages"][2]["bundle"]["proofs"][2]["proof"],
        },
        {
            "name": "checkpoint_chain_checkpoint",
            "inputs": lambda: {"report": _chain(), "start": RT2, "end": RT3},
            "generate": lambda i: checkpoint_chain_checkpoint(
                i["report"], i["start"], i["end"]
            ),
            "verify": verify_checkpoint_chain_checkpoint,
            "expected": _window_expected,
            "tamper": lambda r: r["stages"][0]["bundle"].__setitem__(
                "root", FALSE64
            ),
            "unaffected": lambda r: r["stages"][1]["bundle"],
        },
    ]


LAYERS = _layers()
LAYER_IDS = [layer["name"] for layer in LAYERS]


# ------------------------------------------------------- cross-layer consistency


def test_full_ladder_cross_layer_consistency():
    # Layer 1: the minimal legal matrix attestation bundle.
    bundle = _matrix_bundle_two()
    assert list(bundle) == ["root", "reports"]
    assert [member["id"] for member in bundle["reports"]] == ["a", "b", "é"]
    assert bundle["root"] == bundle["reports"][-1]["digest"]
    assert bundle["reports"][0]["previous"] == GENESIS
    # The repeated credential is equal in both members but not shared.
    assert bundle["reports"][0]["report"] == bundle["reports"][2]["report"]
    assert bundle["reports"][0]["report"] is not bundle["reports"][2]["report"]
    assert (
        verify_decision_matrix_attestation_bundle(bundle, _bundle_expected(bundle))
        is True
    )

    # Layer 2: the evolution chain embeds exactly the input bundles.
    evolution = _evolution()
    assert list(evolution) == ["root", "stages"]
    assert [stage["at"] for stage in evolution["stages"]] == [AT1, AT2, AT3]
    assert evolution["stages"][0]["bundle"] == _matrix_bundle_one()
    assert evolution["stages"][1]["bundle"] == bundle
    assert evolution["stages"][2]["bundle"] == _matrix_bundle_three()
    assert evolution["stages"][0]["diff"] is None
    assert evolution["stages"][0]["previous"] == GENESIS
    for index in (1, 2):
        stage = evolution["stages"][index]
        assert stage["previous"] == evolution["stages"][index - 1]["digest"]
        assert stage["diff"]["before_root"] == (
            evolution["stages"][index - 1]["bundle"]["root"]
        )
        assert stage["diff"]["after_root"] == stage["bundle"]["root"]
    assert evolution["root"] == evolution["stages"][-1]["digest"]
    expected = _evolution_expected(evolution)
    assert [stage["root"] for stage in expected["stages"]] == [
        _matrix_bundle_one()["root"],
        bundle["root"],
        _matrix_bundle_three()["root"],
    ]
    assert verify_matrix_bundle_evolution(evolution, expected) is True

    # Layer 3: a window proof cut out of the evolution report.
    proof = evolution_checkpoint(evolution, AT2, AT3)
    assert list(proof) == ["start", "end", "anchor", "stages", "commitment"]
    assert proof["anchor"] == evolution["stages"][0]["digest"]
    assert proof["stages"] == evolution["stages"][1:]
    assert proof["commitment"] == evolution["stages"][2]["digest"]
    assert proof["commitment"] == evolution["root"]
    assert verify_evolution_checkpoint(proof, _window_expected(proof)) is True

    # Layer 4: the checkpoint bundle embeds exactly the input proofs.
    proofs = _checkpoint_proofs()
    checkpoint_bundle = _checkpoint_bundle()
    assert list(checkpoint_bundle) == ["root", "proofs"]
    assert [member["id"] for member in checkpoint_bundle["proofs"]] == [
        "alpha",
        "beta",
        "伽马",
    ]
    assert checkpoint_bundle["proofs"][0]["proof"] == proofs["head"]
    assert checkpoint_bundle["proofs"][1]["proof"] == proofs["span"]
    # The repeated proof is equal in both members but not shared.
    assert checkpoint_bundle["proofs"][1]["proof"] == (
        checkpoint_bundle["proofs"][2]["proof"]
    )
    assert checkpoint_bundle["proofs"][1]["proof"] is not (
        checkpoint_bundle["proofs"][2]["proof"]
    )
    assert checkpoint_bundle["root"] == checkpoint_bundle["proofs"][-1]["digest"]
    assert (
        verify_evolution_checkpoint_bundle(
            checkpoint_bundle, _checkpoint_bundle_expected(checkpoint_bundle)
        )
        is True
    )

    # Layer 5: the checkpoint chain embeds exactly the input bundles.
    chain = _chain()
    assert list(chain) == ["root", "stages"]
    assert [stage["at"] for stage in chain["stages"]] == [RT1, RT2, RT3]
    for stage, stage_input in zip(chain["stages"], _chain_stages()):
        assert stage["bundle"] == stage_input["bundle"]
    assert chain["stages"][0]["diff"] is None
    assert chain["stages"][0]["previous"] == GENESIS
    for index in (1, 2):
        stage = chain["stages"][index]
        assert stage["previous"] == chain["stages"][index - 1]["digest"]
        assert stage["diff"]["before_root"] == (
            chain["stages"][index - 1]["bundle"]["root"]
        )
        assert stage["diff"]["after_root"] == stage["bundle"]["root"]
    assert chain["root"] == chain["stages"][-1]["digest"]
    chain_expected = _chain_expected(chain)
    assert [stage["diff_digest"] for stage in chain_expected["stages"]] == [
        None,
        chain["stages"][1]["diff"]["digest"],
        chain["stages"][2]["diff"]["digest"],
    ]
    assert verify_checkpoint_chain(chain, chain_expected) is True

    # Layer 6: a window proof cut out of the checkpoint chain.
    window = checkpoint_chain_checkpoint(chain, RT1, RT3)
    assert list(window) == ["start", "end", "anchor", "stages", "commitment"]
    assert window["anchor"] == GENESIS
    assert window["stages"] == chain["stages"]
    assert window["commitment"] == chain["root"]
    assert verify_checkpoint_chain_checkpoint(window, _window_expected(window)) is True

    # A mid-chain single-stage window anchors on the preceding stage digest.
    single = checkpoint_chain_checkpoint(chain, RT2, RT2)
    assert single["anchor"] == chain["stages"][0]["digest"]
    assert single["stages"] == chain["stages"][1:2]
    assert single["commitment"] == chain["stages"][1]["digest"]
    assert verify_checkpoint_chain_checkpoint(single, _window_expected(single)) is True


def test_window_proof_is_independent_of_source_report():
    evolution = _evolution()
    proof = evolution_checkpoint(evolution, AT2, AT3)
    proof["stages"][0]["bundle"]["root"] = FALSE64
    proof["stages"][1]["digest"] = FALSE64
    # The source report is untouched and still verifies.
    assert evolution["stages"][1]["bundle"]["root"] != FALSE64
    assert evolution["stages"][2]["digest"] != FALSE64
    assert verify_matrix_bundle_evolution(evolution, _evolution_expected(evolution)) is True

    chain = _chain()
    window = checkpoint_chain_checkpoint(chain, RT1, RT3)
    window["stages"][0]["bundle"]["root"] = FALSE64
    assert chain["stages"][0]["bundle"]["root"] != FALSE64
    assert verify_checkpoint_chain(chain, _chain_expected(chain)) is True


# ------------------------------------------------------- uniform layer behavior


@pytest.mark.parametrize("layer", LAYERS, ids=LAYER_IDS)
def test_genuine_roundtrip_verifies_true_and_inputs_untouched(layer):
    inputs = layer["inputs"]()
    snapshot = copy.deepcopy(inputs)
    result = layer["generate"](inputs)
    assert inputs == snapshot
    expected = layer["expected"](result)
    assert layer["verify"](result, expected) is True
    assert inputs == snapshot
    # Verification does not mutate its own arguments either.
    result_snapshot = copy.deepcopy(result)
    expected_snapshot = copy.deepcopy(expected)
    layer["verify"](result, expected)
    assert result == result_snapshot
    assert expected == expected_snapshot


@pytest.mark.parametrize("layer", LAYERS, ids=LAYER_IDS)
def test_equal_valued_reordered_inputs_are_byte_identical(layer):
    first = layer["generate"](layer["inputs"]())
    second = layer["generate"](_reordered(layer["inputs"]()))
    assert first == second
    assert _compact(first) == _compact(second)


@pytest.mark.parametrize("layer", LAYERS, ids=LAYER_IDS)
def test_mutating_one_returned_branch_isolates_everything_else(layer):
    inputs = layer["inputs"]()
    inputs_snapshot = copy.deepcopy(inputs)
    result = layer["generate"](inputs)
    fresh = layer["generate"](layer["inputs"]())
    preserved = copy.deepcopy(layer["unaffected"](result))

    layer["tamper"](result)

    # Sibling branches of the same result are unaffected...
    assert layer["unaffected"](result) == preserved
    assert layer["unaffected"](result) == layer["unaffected"](fresh)
    # ...the input objects are untouched...
    assert inputs == inputs_snapshot
    # ...and a later equal-valued call still reproduces the genuine result.
    assert layer["generate"](layer["inputs"]()) == fresh
    assert layer["verify"](fresh, layer["expected"](fresh)) is True


# -------------------------------------------- false summaries, never exceptions


def test_false_member_or_stage_links_return_false():
    bundle = _matrix_bundle_two()
    expected = _bundle_expected(bundle)
    tampered = copy.deepcopy(bundle)
    tampered["reports"][1]["digest"] = FALSE64
    _assert_false_unmutated(verify_decision_matrix_attestation_bundle, tampered, expected)
    tampered = copy.deepcopy(bundle)
    tampered["reports"][2]["previous"] = FALSE64
    _assert_false_unmutated(verify_decision_matrix_attestation_bundle, tampered, expected)

    evolution = _evolution()
    expected = _evolution_expected(evolution)
    tampered = copy.deepcopy(evolution)
    tampered["stages"][1]["digest"] = FALSE64
    _assert_false_unmutated(verify_matrix_bundle_evolution, tampered, expected)
    tampered = copy.deepcopy(evolution)
    tampered["stages"][2]["previous"] = FALSE64
    _assert_false_unmutated(verify_matrix_bundle_evolution, tampered, expected)

    proof = evolution_checkpoint(_evolution(), AT1, AT3)
    expected = _window_expected(proof)
    tampered = copy.deepcopy(proof)
    tampered["stages"][1]["previous"] = FALSE64
    _assert_false_unmutated(verify_evolution_checkpoint, tampered, expected)

    checkpoint_bundle = _checkpoint_bundle()
    expected = _checkpoint_bundle_expected(checkpoint_bundle)
    tampered = copy.deepcopy(checkpoint_bundle)
    tampered["proofs"][1]["digest"] = FALSE64
    _assert_false_unmutated(verify_evolution_checkpoint_bundle, tampered, expected)
    tampered = copy.deepcopy(checkpoint_bundle)
    tampered["proofs"][2]["previous"] = FALSE64
    _assert_false_unmutated(verify_evolution_checkpoint_bundle, tampered, expected)

    chain = _chain()
    expected = _chain_expected(chain)
    tampered = copy.deepcopy(chain)
    tampered["stages"][2]["digest"] = FALSE64
    _assert_false_unmutated(verify_checkpoint_chain, tampered, expected)
    tampered = copy.deepcopy(chain)
    tampered["stages"][1]["previous"] = FALSE64
    _assert_false_unmutated(verify_checkpoint_chain, tampered, expected)

    window = _window_proof(RT1, RT3)
    expected = _window_expected(window)
    tampered = copy.deepcopy(window)
    tampered["stages"][1]["digest"] = FALSE64
    _assert_false_unmutated(verify_checkpoint_chain_checkpoint, tampered, expected)


def test_false_roots_anchors_and_commitments_return_false():
    bundle = _matrix_bundle_two()
    tampered = copy.deepcopy(bundle)
    tampered["root"] = FALSE64
    _assert_false_unmutated(
        verify_decision_matrix_attestation_bundle, tampered, _bundle_expected(bundle)
    )

    evolution = _evolution()
    tampered = copy.deepcopy(evolution)
    tampered["root"] = FALSE64
    _assert_false_unmutated(
        verify_matrix_bundle_evolution, tampered, _evolution_expected(evolution)
    )

    proof = evolution_checkpoint(_evolution(), AT1, AT3)
    tampered = copy.deepcopy(proof)
    tampered["commitment"] = FALSE64
    _assert_false_unmutated(
        verify_evolution_checkpoint, tampered, _window_expected(proof)
    )
    tampered = copy.deepcopy(proof)
    tampered["anchor"] = FALSE64
    _assert_false_unmutated(
        verify_evolution_checkpoint, tampered, _window_expected(proof)
    )

    checkpoint_bundle = _checkpoint_bundle()
    tampered = copy.deepcopy(checkpoint_bundle)
    tampered["root"] = FALSE64
    _assert_false_unmutated(
        verify_evolution_checkpoint_bundle,
        tampered,
        _checkpoint_bundle_expected(checkpoint_bundle),
    )

    chain = _chain()
    tampered = copy.deepcopy(chain)
    tampered["root"] = FALSE64
    _assert_false_unmutated(verify_checkpoint_chain, tampered, _chain_expected(chain))

    window = _window_proof(RT1, RT3)
    tampered = copy.deepcopy(window)
    tampered["commitment"] = FALSE64
    _assert_false_unmutated(
        verify_checkpoint_chain_checkpoint, tampered, _window_expected(window)
    )
    tampered = copy.deepcopy(window)
    tampered["anchor"] = FALSE64
    _assert_false_unmutated(
        verify_checkpoint_chain_checkpoint, tampered, _window_expected(window)
    )


def test_wrong_expected_summaries_return_false():
    bundle = _matrix_bundle_two()
    expected = _bundle_expected(bundle)
    expected["root"] = FALSE64
    _assert_false_unmutated(
        verify_decision_matrix_attestation_bundle, bundle, expected
    )
    expected = _bundle_expected(bundle)
    expected["report_ids"] = expected["report_ids"][:2]
    _assert_false_unmutated(
        verify_decision_matrix_attestation_bundle, bundle, expected
    )

    evolution = _evolution()
    expected = _evolution_expected(evolution)
    expected["stages"][1]["root"] = FALSE64
    _assert_false_unmutated(verify_matrix_bundle_evolution, evolution, expected)
    expected = _evolution_expected(evolution)
    # A legal, strictly increasing but wrong timestamp disagrees as data.
    expected["stages"][1]["at"] = "2021-06-15T00:00:00Z"
    _assert_false_unmutated(verify_matrix_bundle_evolution, evolution, expected)

    proof = evolution_checkpoint(_evolution(), AT2, AT3)
    expected = _window_expected(proof)
    expected["anchor"] = FALSE64
    _assert_false_unmutated(verify_evolution_checkpoint, proof, expected)

    checkpoint_bundle = _checkpoint_bundle()
    expected = _checkpoint_bundle_expected(checkpoint_bundle)
    expected["proof_ids"] = expected["proof_ids"] + ["missing"]
    _assert_false_unmutated(
        verify_evolution_checkpoint_bundle, checkpoint_bundle, expected
    )

    chain = _chain()
    expected = _chain_expected(chain)
    expected["stages"][1]["diff_digest"] = FALSE64
    _assert_false_unmutated(verify_checkpoint_chain, chain, expected)
    expected = _chain_expected(chain)
    expected["stages"][2]["bundle_root"] = FALSE64
    _assert_false_unmutated(verify_checkpoint_chain, chain, expected)

    window = _window_proof(RT1, RT3)
    expected = _window_expected(window)
    expected["commitment"] = FALSE64
    _assert_false_unmutated(verify_checkpoint_chain_checkpoint, window, expected)


# ------------------------------------------------------------- structural errors


def _layer_result_and_expected():
    return {
        "decision_matrix_attestation_bundle": (
            verify_decision_matrix_attestation_bundle,
            _matrix_bundle_two,
            _bundle_expected,
        ),
        "matrix_bundle_evolution": (
            verify_matrix_bundle_evolution,
            _evolution,
            _evolution_expected,
        ),
        "evolution_checkpoint": (
            verify_evolution_checkpoint,
            lambda: evolution_checkpoint(_evolution(), AT2, AT3),
            _window_expected,
        ),
        "evolution_checkpoint_bundle": (
            verify_evolution_checkpoint_bundle,
            _checkpoint_bundle,
            _checkpoint_bundle_expected,
        ),
        "checkpoint_chain": (
            verify_checkpoint_chain,
            _chain,
            _chain_expected,
        ),
        "checkpoint_chain_checkpoint": (
            verify_checkpoint_chain_checkpoint,
            lambda: _window_proof(RT2, RT3),
            _window_expected,
        ),
    }


@pytest.mark.parametrize("layer_name", list(_layer_result_and_expected()))
def test_missing_top_level_key_raises(layer_name):
    verify, make, make_expected = _layer_result_and_expected()[layer_name]
    result = make()
    expected = make_expected(result)
    for key in list(result):
        tampered = copy.deepcopy(result)
        del tampered[key]
        snapshot = copy.deepcopy(tampered)
        with pytest.raises(ValueError):
            verify(tampered, expected)
        assert tampered == snapshot


@pytest.mark.parametrize("layer_name", list(_layer_result_and_expected()))
def test_extra_top_level_key_raises(layer_name):
    verify, make, make_expected = _layer_result_and_expected()[layer_name]
    result = make()
    expected = make_expected(result)
    result["zz_extra"] = 1
    snapshot = copy.deepcopy(result)
    with pytest.raises(ValueError):
        verify(result, expected)
    assert result == snapshot


def test_nested_key_set_violations_raise():
    bundle = _matrix_bundle_two()
    expected = _bundle_expected(bundle)
    tampered = copy.deepcopy(bundle)
    del tampered["reports"][0]["digest"]
    _assert_raises_unmutated(
        lambda: verify_decision_matrix_attestation_bundle(tampered, expected),
        tampered,
        expected,
    )
    tampered = copy.deepcopy(bundle)
    tampered["reports"][1]["extra"] = 1
    _assert_raises_unmutated(
        lambda: verify_decision_matrix_attestation_bundle(tampered, expected),
        tampered,
        expected,
    )

    evolution = _evolution()
    expected = _evolution_expected(evolution)
    tampered = copy.deepcopy(evolution)
    tampered["stages"][0]["extra"] = 1
    _assert_raises_unmutated(
        lambda: verify_matrix_bundle_evolution(tampered, expected), tampered, expected
    )

    chain = _chain()
    expected = _chain_expected(chain)
    tampered = copy.deepcopy(chain)
    del tampered["stages"][1]["diff"]
    _assert_raises_unmutated(
        lambda: verify_checkpoint_chain(tampered, expected), tampered, expected
    )

    window = _window_proof(RT1, RT3)
    expected = _window_expected(window)
    tampered = copy.deepcopy(window)
    del tampered["anchor"]
    _assert_raises_unmutated(
        lambda: verify_checkpoint_chain_checkpoint(tampered, expected),
        tampered,
        expected,
    )

    # The expected summary's key set is enforced just as strictly.
    bad_expected = _chain_expected(chain)
    bad_expected["stages"][0]["extra"] = 1
    _assert_raises_unmutated(
        lambda: verify_checkpoint_chain(chain, bad_expected), chain, bad_expected
    )


def test_duplicate_or_reversed_stage_times_raise():
    # Generators reject duplicate and reversed stage timestamps.
    stages = _evolution_stages()
    stages[2]["at"] = AT2
    _assert_raises_unmutated(lambda: matrix_bundle_evolution(stages), stages)
    stages = _evolution_stages()
    stages[1], stages[2] = stages[2], stages[1]
    _assert_raises_unmutated(lambda: matrix_bundle_evolution(stages), stages)

    stages = _chain_stages()
    stages[1]["at"] = RT1
    _assert_raises_unmutated(lambda: checkpoint_chain(stages), stages)
    stages = _chain_stages()
    stages[0], stages[1] = stages[1], stages[0]
    _assert_raises_unmutated(lambda: checkpoint_chain(stages), stages)

    # Verifiers reject them inside reports, proofs, and expected summaries.
    evolution = _evolution()
    expected = _evolution_expected(evolution)
    tampered = copy.deepcopy(evolution)
    tampered["stages"][1]["at"] = AT1
    _assert_raises_unmutated(
        lambda: verify_matrix_bundle_evolution(tampered, expected), tampered, expected
    )

    proof = evolution_checkpoint(_evolution(), AT1, AT3)
    expected = _window_expected(proof)
    tampered = copy.deepcopy(proof)
    tampered["stages"][2]["at"] = AT2
    _assert_raises_unmutated(
        lambda: verify_evolution_checkpoint(tampered, expected), tampered, expected
    )

    chain = _chain()
    expected = _chain_expected(chain)
    tampered = copy.deepcopy(chain)
    tampered["stages"][2]["at"] = RT2
    _assert_raises_unmutated(
        lambda: verify_checkpoint_chain(tampered, expected), tampered, expected
    )
    bad_expected = _chain_expected(chain)
    bad_expected["stages"][2]["at"] = RT1
    _assert_raises_unmutated(
        lambda: verify_checkpoint_chain(chain, bad_expected), chain, bad_expected
    )

    window = _window_proof(RT1, RT3)
    expected = _window_expected(window)
    tampered = copy.deepcopy(window)
    tampered["stages"][1]["at"] = RT1
    _assert_raises_unmutated(
        lambda: verify_checkpoint_chain_checkpoint(tampered, expected),
        tampered,
        expected,
    )


def test_tuple_where_list_required_raises_value_error_not_type_error():
    # A tuple can never pose as the contracted list, however similar its
    # items look; the failure is a ValueError, never a leaked TypeError.
    items = tuple(_matrix_bundle_two_items())
    _assert_raises_unmutated(lambda: decision_matrix_attestation_bundle(items))
    stages = tuple(_evolution_stages())
    _assert_raises_unmutated(lambda: matrix_bundle_evolution(stages))
    items = tuple(_checkpoint_bundle_items())
    _assert_raises_unmutated(lambda: evolution_checkpoint_bundle(items))
    stages = tuple(_chain_stages())
    _assert_raises_unmutated(lambda: checkpoint_chain(stages))

    bundle = _matrix_bundle_two()
    expected = _bundle_expected(bundle)
    bundle["reports"] = tuple(bundle["reports"])
    _assert_raises_unmutated(
        lambda: verify_decision_matrix_attestation_bundle(bundle, expected),
        bundle,
        expected,
    )

    evolution = _evolution()
    expected = _evolution_expected(evolution)
    evolution["stages"] = tuple(evolution["stages"])
    _assert_raises_unmutated(
        lambda: verify_matrix_bundle_evolution(evolution, expected),
        evolution,
        expected,
    )

    proof = evolution_checkpoint(_evolution(), AT1, AT3)
    expected = _window_expected(proof)
    proof["stages"] = tuple(proof["stages"])
    _assert_raises_unmutated(
        lambda: verify_evolution_checkpoint(proof, expected), proof, expected
    )

    checkpoint_bundle = _checkpoint_bundle()
    expected = _checkpoint_bundle_expected(checkpoint_bundle)
    checkpoint_bundle["proofs"] = tuple(checkpoint_bundle["proofs"])
    _assert_raises_unmutated(
        lambda: verify_evolution_checkpoint_bundle(checkpoint_bundle, expected),
        checkpoint_bundle,
        expected,
    )

    chain = _chain()
    expected = _chain_expected(chain)
    chain["stages"] = tuple(chain["stages"])
    _assert_raises_unmutated(
        lambda: verify_checkpoint_chain(chain, expected), chain, expected
    )

    window = _window_proof(RT1, RT3)
    expected = _window_expected(window)
    window["stages"] = tuple(window["stages"])
    _assert_raises_unmutated(
        lambda: verify_checkpoint_chain_checkpoint(window, expected), window, expected
    )


# --------------------------------------- type collisions inside repeated subtrees


def test_int_fact_key_in_repeated_subtree_raises_on_generate():
    # matrix_bundle_evolution: the legal twin is parsed in the first stage
    # and again as member "a" of the second bundle; the impostor appears
    # only afterwards as member "é" of the same bundle.
    bundle_two = _matrix_bundle_two()
    _int_fact_key(bundle_two["reports"][2]["report"])
    stages = [
        {"at": AT1, "bundle": _matrix_bundle_one()},
        {"at": AT2, "bundle": bundle_two},
    ]
    _assert_raises_unmutated(lambda: matrix_bundle_evolution(stages), stages)

    # evolution_checkpoint: the impostor sits in the last stage's bundle,
    # behind two fully legal occurrences of the same credential.
    evolution = _evolution()
    _int_fact_key(evolution["stages"][2]["bundle"]["reports"][0]["report"])
    _assert_raises_unmutated(
        lambda: evolution_checkpoint(evolution, AT1, AT3), evolution
    )

    # evolution_checkpoint_bundle: member "alpha" carries the legal proof,
    # member "beta" the equal-text impostor.
    proofs = _checkpoint_proofs()
    impostor = copy.deepcopy(proofs["span"])
    _int_fact_key(impostor)
    items = [
        {"id": "alpha", "proof": proofs["span"]},
        {"id": "beta", "proof": impostor},
    ]
    _assert_raises_unmutated(lambda: evolution_checkpoint_bundle(items), items)

    # checkpoint_chain: the repeated "span" proof is legal in the first
    # stage's bundle and tampered in the second stage's bundle.
    stages = _chain_stages()
    _int_fact_key(stages[1]["bundle"]["proofs"][1]["proof"])
    _assert_raises_unmutated(lambda: checkpoint_chain(stages), stages)

    # checkpoint_chain_checkpoint: the impostor sits in the last stage of
    # the chain report the window is cut from.
    chain = _chain()
    _int_fact_key(chain["stages"][2]["bundle"]["proofs"][2]["proof"])
    _assert_raises_unmutated(
        lambda: checkpoint_chain_checkpoint(chain, RT1, RT3), chain
    )


def test_int_fact_key_in_repeated_subtree_raises_on_verify():
    bundle = _matrix_bundle_two()
    expected = _bundle_expected(bundle)
    _int_fact_key(bundle["reports"][2]["report"])
    _assert_raises_unmutated(
        lambda: verify_decision_matrix_attestation_bundle(bundle, expected),
        bundle,
        expected,
    )

    evolution = _evolution()
    expected = _evolution_expected(evolution)
    _int_fact_key(evolution["stages"][2]["bundle"]["reports"][0]["report"])
    _assert_raises_unmutated(
        lambda: verify_matrix_bundle_evolution(evolution, expected),
        evolution,
        expected,
    )

    checkpoint_bundle = _checkpoint_bundle()
    expected = _checkpoint_bundle_expected(checkpoint_bundle)
    _int_fact_key(checkpoint_bundle["proofs"][2]["proof"])
    _assert_raises_unmutated(
        lambda: verify_evolution_checkpoint_bundle(checkpoint_bundle, expected),
        checkpoint_bundle,
        expected,
    )

    chain = _chain()
    expected = _chain_expected(chain)
    _int_fact_key(chain["stages"][2]["bundle"]["proofs"][2]["proof"])
    _assert_raises_unmutated(
        lambda: verify_checkpoint_chain(chain, expected), chain, expected
    )

    window = _window_proof(RT1, RT3)
    expected = _window_expected(window)
    _int_fact_key(window["stages"][2]["bundle"]["proofs"][2]["proof"])
    _assert_raises_unmutated(
        lambda: verify_checkpoint_chain_checkpoint(window, expected), window, expected
    )


def test_legal_repeated_subtrees_still_verify_true():
    # The genuine samples repeat the same credential across members and
    # stages; reuse of those legal occurrences must keep verifying True.
    bundle = _matrix_bundle_two()
    assert (
        verify_decision_matrix_attestation_bundle(bundle, _bundle_expected(bundle))
        is True
    )
    checkpoint_bundle = _checkpoint_bundle()
    assert (
        verify_evolution_checkpoint_bundle(
            checkpoint_bundle, _checkpoint_bundle_expected(checkpoint_bundle)
        )
        is True
    )
    chain = _chain()
    assert verify_checkpoint_chain(chain, _chain_expected(chain)) is True


# --------------------------- untruthful embedded credentials in generation


def test_generators_reject_untruthful_embedded_credentials():
    # A false sub-report digest inside an otherwise legal bundle member.
    items = _matrix_bundle_two_items()
    items[0]["report"]["digest"] = FALSE64
    _assert_raises_unmutated(
        lambda: decision_matrix_attestation_bundle(items), items
    )

    # A false member digest inside an evolution stage bundle.
    stages = _evolution_stages()
    stages[1]["bundle"]["reports"][0]["digest"] = FALSE64
    _assert_raises_unmutated(lambda: matrix_bundle_evolution(stages), stages)

    # A false stage digest inside the report a window is cut from.
    evolution = _evolution()
    evolution["stages"][1]["digest"] = FALSE64
    _assert_raises_unmutated(
        lambda: evolution_checkpoint(evolution, AT1, AT2), evolution
    )

    # A false commitment inside an embedded window proof.
    items = _checkpoint_bundle_items()
    items[0]["proof"]["commitment"] = FALSE64
    _assert_raises_unmutated(lambda: evolution_checkpoint_bundle(items), items)

    # A false bundle root inside a checkpoint chain stage.
    stages = _chain_stages()
    stages[2]["bundle"]["root"] = FALSE64
    _assert_raises_unmutated(lambda: checkpoint_chain(stages), stages)

    # A false chain root in the report a window is cut from.
    chain = _chain()
    chain["root"] = FALSE64
    _assert_raises_unmutated(
        lambda: checkpoint_chain_checkpoint(chain, RT1, RT2), chain
    )


def test_window_boundary_errors_raise():
    evolution = _evolution()
    _assert_raises_unmutated(lambda: evolution_checkpoint(evolution, AT3, AT1))
    _assert_raises_unmutated(
        lambda: evolution_checkpoint(evolution, "2021-06-15T00:00:00Z", AT3)
    )
    _assert_raises_unmutated(
        lambda: evolution_checkpoint(evolution, AT1, "2021-06-15T00:00:00Z")
    )

    chain = _chain()
    _assert_raises_unmutated(lambda: checkpoint_chain_checkpoint(chain, RT2, RT1))
    _assert_raises_unmutated(
        lambda: checkpoint_chain_checkpoint(chain, RT1, "2021-09-15T00:00:00Z")
    )
    _assert_raises_unmutated(
        lambda: checkpoint_chain_checkpoint(chain, "2021-09-15T00:00:00Z", RT3)
    )
