import copy

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    checkpoint_chain,
    checkpoint_chain_checkpoint,
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    evolution_checkpoint,
    evolution_checkpoint_bundle,
    matrix_bundle_evolution,
    verify_checkpoint_chain_checkpoint,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"
AT1 = "2021-05-01T00:00:00Z"
AT2 = "2021-06-01T00:00:00Z"
AT3 = "2021-07-01T00:00:00Z"
RT1 = "2021-08-01T00:00:00Z"
RT2 = "2021-09-01T00:00:00Z"
RT3 = "2021-10-01T00:00:00Z"

VERIFY_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/verify"
)


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


def _changing_rules():
    return [
        _rule(id="a", priority=5, **{"from": START}, when={"x": True}, result="允许"),
        _rule(
            id="b",
            priority=1,
            **{"from": MID, "to": "2021-03-01T00:00:00Z"},
            result="deny",
        ),
    ]


def _report_a():
    return decision_matrix_attestation(
        START, END, [{"id": "c1", "facts": {"x": True}}], _changing_rules()
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


def _matrix_bundle_two():
    return decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()}, {"id": "b", "report": _report_b()}]
    )


def _matrix_bundle_three():
    return decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": _report_a()},
            {"id": "b", "report": _report_b()},
            {"id": "c", "report": _report_c()},
        ]
    )


def _checkpoint_proofs():
    evolution = matrix_bundle_evolution(
        [
            {"at": AT1, "bundle": _matrix_bundle_one()},
            {"at": AT2, "bundle": _matrix_bundle_two()},
            {"at": AT3, "bundle": _matrix_bundle_three()},
        ]
    )
    return {
        "head": evolution_checkpoint(evolution, AT1, AT1),
        "mid": evolution_checkpoint(evolution, AT2, AT2),
        "tail": evolution_checkpoint(evolution, AT3, AT3),
        "span": evolution_checkpoint(evolution, AT1, AT2),
    }


def _chain():
    proofs = _checkpoint_proofs()
    bundle_one = evolution_checkpoint_bundle(
        [{"id": "a", "proof": proofs["head"]}, {"id": "z", "proof": proofs["span"]}]
    )
    bundle_two = evolution_checkpoint_bundle(
        [{"id": "a", "proof": proofs["mid"]}, {"id": "z", "proof": proofs["span"]}]
    )
    bundle_three = evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": proofs["tail"]},
            {"id": "b", "proof": proofs["mid"]},
            {"id": "z", "proof": proofs["span"]},
        ]
    )
    return checkpoint_chain(
        [
            {"at": RT1, "bundle": bundle_one},
            {"at": RT2, "bundle": bundle_two},
            {"at": RT3, "bundle": bundle_three},
        ]
    )


def _proof(start, end):
    return checkpoint_chain_checkpoint(_chain(), start, end)


def _expected(proof):
    return {
        "start": proof["start"],
        "end": proof["end"],
        "anchor": proof["anchor"],
        "commitment": proof["commitment"],
    }


# ---------------------------------------------------------------- genuine


@pytest.mark.parametrize(
    "start,end",
    [(RT1, RT3), (RT1, RT1), (RT1, RT2), (RT2, RT3), (RT2, RT2), (RT3, RT3)],
)
def test_verifies_genuine_windows(start, end):
    proof = _proof(start, end)
    assert verify_checkpoint_chain_checkpoint(proof, _expected(proof)) is True


def test_genuine_proof_without_outside_chain():
    # A middle single-stage window must verify using only its proof object:
    # the carried diff brings the front-side bundle.
    proof = _proof(RT2, RT2)
    assert verify_checkpoint_chain_checkpoint(proof, _expected(proof)) is True


def test_verification_does_not_mutate_inputs():
    proof = _proof(RT2, RT3)
    proof_snapshot = copy.deepcopy(proof)
    expected = _expected(proof)
    expected_snapshot = copy.deepcopy(expected)
    assert verify_checkpoint_chain_checkpoint(proof, expected) is True
    assert proof == proof_snapshot
    assert expected == expected_snapshot


# ------------------------------------------------------- structural failures


def test_proof_not_a_dict_raises():
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint([], _expected(_proof(RT1, RT1)))


def test_proof_wrong_top_level_keys_raises():
    proof = dict(_proof(RT1, RT1))
    proof["extra"] = 1
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, _expected(_proof(RT1, RT1)))


def test_proof_missing_top_level_key_raises():
    proof = dict(_proof(RT2, RT3))
    del proof["anchor"]
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


def test_proof_bad_time_raises():
    proof = dict(_proof(RT2, RT3))
    proof["start"] = "not-a-time"
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


def test_proof_reversed_window_raises():
    proof = dict(_proof(RT2, RT3))
    proof["start"], proof["end"] = proof["end"], proof["start"]
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


def test_proof_bad_anchor_format_raises():
    proof = dict(_proof(RT2, RT3))
    proof["anchor"] = "Z" * 64
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


def test_proof_bad_commitment_format_raises():
    proof = dict(_proof(RT2, RT3))
    proof["commitment"] = "a" * 63
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


def test_empty_stages_raises():
    proof = dict(_proof(RT2, RT3))
    proof["stages"] = []
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


def test_stage_wrong_keys_raises():
    proof = _proof(RT2, RT3)
    proof["stages"][0] = dict(proof["stages"][0])
    del proof["stages"][0]["bundle"]
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


def test_disordered_stages_raise():
    proof = dict(_proof(RT1, RT3))
    proof["stages"] = [proof["stages"][1], proof["stages"][0]]
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


def test_genesis_first_stage_must_have_null_diff():
    proof = dict(_proof(RT1, RT2))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["diff"] = stages[1]["diff"]
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


def test_carried_first_stage_diff_wrong_after_root_raises():
    proof = dict(_proof(RT2, RT3))
    stages = copy.deepcopy(proof["stages"])
    forged = copy.deepcopy(stages[0]["diff"])
    forged["after_root"] = forged["before_root"]
    stages[0]["diff"] = forged
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


def test_carried_first_stage_diff_illegal_change_raises():
    proof = dict(_proof(RT2, RT2))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["diff"]["changes"][0]["kind"] = "bogus"
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


def test_inner_diff_illegal_change_raises():
    proof = dict(_proof(RT1, RT3))
    stages = copy.deepcopy(proof["stages"])
    stages[2]["diff"]["changes"][0]["kind"] = "bogus"
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


def test_adjacent_diff_must_correspond_to_neighbors():
    proof = dict(_proof(RT1, RT3))
    # The third stage's diff must describe bundle2 -> bundle3; swapping in
    # the diff from the second position breaks correspondence.
    other = _proof(RT2, RT3)
    stages = copy.deepcopy(proof["stages"])
    stages[2] = copy.deepcopy(stages[2])
    stages[2]["diff"] = other["stages"][0]["diff"]
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


def test_bad_hex_inside_stage_raises():
    proof = dict(_proof(RT2, RT3))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["previous"] = "g" * 64
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


def test_invalid_embedded_bundle_raises():
    proof = dict(_proof(RT2, RT3))
    stages = copy.deepcopy(proof["stages"])
    del stages[0]["bundle"]["proofs"][0]["proof"]["commitment"]
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, {})


# ------------------------------------------------- expected structural failures


def test_expected_not_a_dict_raises():
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(_proof(RT1, RT1), [])


def test_expected_wrong_keys_raises():
    proof = _proof(RT1, RT1)
    expected = dict(_expected(proof))
    expected["root"] = expected["commitment"]
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, expected)


def test_expected_missing_key_raises():
    proof = _proof(RT1, RT1)
    expected = dict(_expected(proof))
    del expected["anchor"]
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, expected)


def test_expected_bad_time_raises():
    proof = _proof(RT1, RT1)
    expected = dict(_expected(proof))
    expected["start"] = "x"
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, expected)


def test_expected_bad_hex_raises():
    proof = _proof(RT1, RT1)
    expected = dict(_expected(proof))
    expected["anchor"] = "0" * 63
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint(proof, expected)


# ---------------------------------------------------------- False after legality


def test_wrong_anchor_returns_false():
    proof = _proof(RT2, RT3)
    expected = _expected(proof)
    expected["anchor"] = "f" * 64
    assert verify_checkpoint_chain_checkpoint(proof, expected) is False


def test_wrong_commitment_in_expected_returns_false():
    proof = _proof(RT2, RT3)
    expected = _expected(proof)
    expected["commitment"] = "f" * 64
    assert verify_checkpoint_chain_checkpoint(proof, expected) is False


def test_wrong_start_in_expected_returns_false():
    proof = _proof(RT2, RT3)
    expected = _expected(proof)
    expected["start"] = RT1
    assert verify_checkpoint_chain_checkpoint(proof, expected) is False


def test_wrong_end_in_expected_returns_false():
    proof = _proof(RT2, RT3)
    expected = _expected(proof)
    expected["end"] = RT2
    assert verify_checkpoint_chain_checkpoint(proof, expected) is False


def test_declared_commitment_false_returns_false():
    proof = dict(_proof(RT2, RT3))
    proof["commitment"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint(proof, _expected(_proof(RT2, RT3)))
        is False
    )


def test_broken_stage_previous_returns_false():
    proof = dict(_proof(RT2, RT3))
    stages = copy.deepcopy(proof["stages"])
    stages[1]["previous"] = "f" * 64
    proof["stages"] = stages
    assert (
        verify_checkpoint_chain_checkpoint(proof, _expected(_proof(RT2, RT3)))
        is False
    )


def test_false_stage_digest_returns_false():
    proof = dict(_proof(RT1, RT3))
    stages = copy.deepcopy(proof["stages"])
    stages[1]["digest"] = "f" * 64
    proof["stages"] = stages
    assert (
        verify_checkpoint_chain_checkpoint(proof, _expected(_proof(RT1, RT3)))
        is False
    )


def test_false_bundle_member_digest_returns_false():
    proof = dict(_proof(RT2, RT3))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["bundle"]["proofs"][0]["digest"] = "f" * 64
    proof["stages"] = stages
    assert (
        verify_checkpoint_chain_checkpoint(proof, _expected(_proof(RT2, RT3)))
        is False
    )


def test_false_bundle_root_returns_false():
    # In a head single-stage window there is no adjacent diff binding the
    # bundle root, so the wrong root stays structurally legal and surfaces as
    # a false summary rather than a ValueError.
    proof = dict(_proof(RT1, RT1))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["bundle"]["root"] = "f" * 64
    proof["stages"] = stages
    assert (
        verify_checkpoint_chain_checkpoint(proof, _expected(_proof(RT1, RT1)))
        is False
    )


def test_false_carried_diff_bundle_summary_returns_false():
    proof = dict(_proof(RT2, RT2))
    stages = copy.deepcopy(proof["stages"])
    # Corrupt only a hex summary of the front-side bundle carried inside the
    # first-stage diff. The structures stay legal but the before bundle no
    # longer chains, so its truthfulness recomputation fails.
    stages[0]["diff"]["before"]["proofs"][0]["digest"] = "f" * 64
    proof["stages"] = stages
    assert (
        verify_checkpoint_chain_checkpoint(proof, _expected(_proof(RT2, RT2)))
        is False
    )


def test_false_carried_diff_digest_returns_false():
    proof = dict(_proof(RT2, RT2))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["diff"]["digest"] = "f" * 64
    proof["stages"] = stages
    assert (
        verify_checkpoint_chain_checkpoint(proof, _expected(_proof(RT2, RT2)))
        is False
    )


def test_carried_diff_incomplete_changes_returns_false():
    # A structurally legal change list that omits the one real change is not
    # a ValueError: it yields False only after all structures validate.
    proof = dict(_proof(RT2, RT2))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["diff"]["changes"] = []
    proof["stages"] = stages
    assert (
        verify_checkpoint_chain_checkpoint(proof, _expected(_proof(RT2, RT2)))
        is False
    )


def test_inner_diff_incomplete_changes_returns_false():
    proof = dict(_proof(RT1, RT3))
    stages = copy.deepcopy(proof["stages"])
    stages[1]["diff"]["changes"] = []
    proof["stages"] = stages
    assert (
        verify_checkpoint_chain_checkpoint(proof, _expected(_proof(RT1, RT3)))
        is False
    )


def test_inner_diff_extra_change_returns_false():
    # A legal change entry for "z", a member present and unchanged on both
    # sides, is structurally valid but makes the legal change list
    # incomplete, so it yields False rather than ValueError.
    proof = dict(_proof(RT2, RT2))
    stages = copy.deepcopy(proof["stages"])
    z_proof = stages[0]["diff"]["after"]["proofs"][1]["proof"]
    assert stages[0]["diff"]["after"]["proofs"][1]["id"] == "z"
    stages[0]["diff"]["changes"].append(
        {
            "id": "z",
            "kind": "changed",
            "before": copy.deepcopy(z_proof),
            "after": copy.deepcopy(z_proof),
        }
    )
    proof["stages"] = stages
    assert (
        verify_checkpoint_chain_checkpoint(proof, _expected(_proof(RT2, RT2)))
        is False
    )


def test_false_inner_diff_digest_returns_false():
    proof = dict(_proof(RT1, RT3))
    stages = copy.deepcopy(proof["stages"])
    stages[1]["diff"]["digest"] = "f" * 64
    proof["stages"] = stages
    assert (
        verify_checkpoint_chain_checkpoint(proof, _expected(_proof(RT1, RT3)))
        is False
    )


def test_boundary_mismatch_start_returns_false():
    proof = dict(_proof(RT2, RT3))
    proof["start"] = RT1
    expected = {
        "start": RT1,
        "end": RT3,
        "anchor": proof["anchor"],
        "commitment": proof["commitment"],
    }
    assert verify_checkpoint_chain_checkpoint(proof, expected) is False


def test_boundary_mismatch_end_returns_false():
    proof = dict(_proof(RT2, RT3))
    proof["end"] = RT2
    expected = {
        "start": RT2,
        "end": RT2,
        "anchor": proof["anchor"],
        "commitment": proof["commitment"],
    }
    assert verify_checkpoint_chain_checkpoint(proof, expected) is False


def test_skipped_stage_returns_false():
    # Dropping the head stage leaves a structurally legal non-head window
    # (the surviving head stage carries its front-side diff and zero
    # previous), but its anchor/stage set no longer matches the claimed
    # boundary window that expected describes, so recomputation fails.
    genuine = _proof(RT1, RT3)
    proof = dict(_proof(RT2, RT3))
    assert len(proof["stages"]) == 2
    assert (
        verify_checkpoint_chain_checkpoint(proof, _expected(genuine))
        is False
    )


# ---------------------------------------------------------------- endpoint


def test_http_verify_genuine_returns_true_compact_json():
    proof = _proof(RT2, RT3)
    response = client.post(
        VERIFY_PATH, json={"proof": proof, "expected": _expected(proof)}
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'


def test_http_verify_false_summary_returns_200_false():
    proof = dict(_proof(RT2, RT3))
    proof["commitment"] = "f" * 64
    response = client.post(
        VERIFY_PATH, json={"proof": proof, "expected": _expected(_proof(RT2, RT3))}
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":false}'


def test_http_verify_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    proof = _proof(RT1, RT1)
    response = client.post(
        VERIFY_PATH, json={"proof": proof, "expected": _expected(proof)}
    )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b'"x"',
        b"null",
        b"{}",
        b'{"proof": null}',
        b'{"proof": {}, "expected": {}}',
        b'{"proof": {}, "expected": {}, "extra": 1}',
        b'{"proof": {}, "expected": {}, "report": {}}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        VERIFY_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
