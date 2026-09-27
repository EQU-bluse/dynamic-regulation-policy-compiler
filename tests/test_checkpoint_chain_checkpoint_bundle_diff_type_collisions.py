"""Type-collision regression tests for the window proof bundle diff chain.

The value engine reuses a verified leaf credential when a later occurrence
is equal in both type and value.  These tests pin down that a credential
whose compact JSON text merely *looks* like an already-verified one — an
integer fact or condition key where the same digits were verified as a
string, or a tuple where the contract requires a list — can never reuse
the legal credential's result: both the diff generator and the diff
verifier must reject it with ``ValueError``.
"""

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    checkpoint_chain,
    checkpoint_chain_checkpoint,
    checkpoint_chain_checkpoint_bundle,
    checkpoint_chain_checkpoint_bundle_diff,
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    evolution_checkpoint,
    evolution_checkpoint_bundle,
    matrix_bundle_evolution,
    verify_checkpoint_chain_checkpoint_bundle_diff,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"
AT1 = "2021-05-01T00:00:00Z"
AT2 = "2021-06-01T00:00:00Z"
RT1 = "2021-08-01T00:00:00Z"
RT2 = "2021-09-01T00:00:00Z"

GENERATE_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/diff"
)
VERIFY_PATH = GENERATE_PATH + "/verify"


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


def _chain():
    bundle_one = decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()}]
    )
    bundle_two = decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": _report_a()},
            {"id": "b", "report": _report_b()},
        ]
    )
    evolution = matrix_bundle_evolution(
        [
            {"at": AT1, "bundle": bundle_one},
            {"at": AT2, "bundle": bundle_two},
        ]
    )
    proof_one = evolution_checkpoint(evolution, AT1, AT1)
    proof_two = evolution_checkpoint(evolution, AT1, AT2)
    return checkpoint_chain(
        [
            {
                "at": RT1,
                "bundle": evolution_checkpoint_bundle(
                    [{"id": "a", "proof": proof_one}]
                ),
            },
            {
                "at": RT2,
                "bundle": evolution_checkpoint_bundle(
                    [{"id": "a", "proof": proof_two}]
                ),
            },
        ]
    )


def _window_proof(start, end):
    return checkpoint_chain_checkpoint(_chain(), start, end)


def _bundle_before():
    return checkpoint_chain_checkpoint_bundle(
        [{"id": "alpha", "proof": _window_proof(RT1, RT1)}]
    )


def _bundle_after():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(RT1, RT1)},
            {"id": "beta", "proof": _window_proof(RT2, RT2)},
        ]
    )


def _diff():
    return checkpoint_chain_checkpoint_bundle_diff(_bundle_before(), _bundle_after())


def _expected(report):
    return {
        "before_root": report["before_root"],
        "after_root": report["after_root"],
        "before_ids": [member["id"] for member in report["before"]["proofs"]],
        "after_ids": [member["id"] for member in report["after"]["proofs"]],
        "digest": report["digest"],
    }


def _int_fact_key(node):
    if isinstance(node, dict):
        facts = node.get("facts")
        if isinstance(facts, dict) and "1" in facts:
            facts[1] = facts.pop("1")
        for value in node.values():
            _int_fact_key(value)
    elif isinstance(node, list):
        for value in node:
            _int_fact_key(value)


def _int_when_key(node):
    if isinstance(node, dict):
        when = node.get("when")
        if isinstance(when, dict) and "1" in when:
            when[1] = when.pop("1")
        for value in node.values():
            _int_when_key(value)
    elif isinstance(node, list):
        for value in node:
            _int_when_key(value)


def _tuple_trace(node):
    if isinstance(node, dict):
        trace = node.get("trace")
        if isinstance(trace, list):
            node["trace"] = tuple(trace)
        for value in node.values():
            _tuple_trace(value)
    elif isinstance(node, list):
        for value in node:
            _tuple_trace(value)


def _tamper_after_alpha(report, tamper):
    # Only the after bundle's first member is tampered: its legal twin in
    # the before bundle is parsed first, so a type-folding reuse identity
    # would let the impostor skip validation entirely.
    tamper(report["after"]["proofs"][0])
    return report


@pytest.mark.parametrize(
    "tamper", [_int_fact_key, _int_when_key, _tuple_trace]
)
def test_verify_rejects_equal_text_type_collision(tamper):
    report = _tamper_after_alpha(_diff(), tamper)
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


@pytest.mark.parametrize(
    "tamper", [_int_fact_key, _int_when_key, _tuple_trace]
)
def test_generate_rejects_equal_text_type_collision(tamper):
    after = _bundle_after()
    tamper(after["proofs"][0])
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint_bundle_diff(_bundle_before(), after)


@pytest.mark.parametrize(
    "tamper", [_int_fact_key, _int_when_key, _tuple_trace]
)
def test_illegal_first_occurrence_also_raises(tamper):
    # Order does not matter: an impostor that appears before its legal
    # twin is rejected by its own validation.
    report = _diff()
    tamper(report["before"]["proofs"][0])
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_legal_twin_still_reuses_and_verifies():
    # Type-and-value-identical occurrences still share one recomputation:
    # the genuine diff verifies True and regenerates byte-identically.
    report = _diff()
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report)
    ) is True
    again = checkpoint_chain_checkpoint_bundle_diff(_bundle_before(), _bundle_after())
    assert again == report


def test_http_untruthful_but_legal_is_200_valid_false():
    # A structurally legal report whose digest does not recompute is a
    # truthfulness failure, not a structural one: 200 with valid=false.
    report = _diff()
    report["digest"] = "0" * 64
    response = client.post(
        VERIFY_PATH, json={"report": report, "expected": _expected(report)}
    )
    assert response.status_code == 200
    assert response.json() == {"valid": False}
