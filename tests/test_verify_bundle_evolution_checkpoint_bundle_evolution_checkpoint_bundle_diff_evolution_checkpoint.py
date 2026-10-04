import copy
import functools

import pytest
from fastapi.testclient import TestClient

import test_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff as fx
from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution as evolve,
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution_checkpoint as checkpoint,
    verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution_checkpoint as verify,
)

client = TestClient(app)

FT1 = "2022-05-01T00:00:00Z"
FT2 = "2022-06-01T00:00:00Z"
FT3 = "2022-07-01T00:00:00Z"

VERIFY_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/"
    "checkpoint/bundle/diff/evolution/checkpoint/verify"
)


def _bundle_one():
    return copy.deepcopy(fx._b1())


def _bundle_two():
    return copy.deepcopy(fx._b2())


def _bundle_three():
    return copy.deepcopy(fx._b3())


@functools.lru_cache(maxsize=1)
def _evolution_raw():
    return evolve(
        [
            {"at": FT1, "bundle": _bundle_one()},
            {"at": FT2, "bundle": _bundle_two()},
            {"at": FT3, "bundle": _bundle_three()},
        ]
    )


def _evolution():
    return copy.deepcopy(_evolution_raw())


def _proof(start, end):
    return checkpoint(_evolution(), start, end)


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
    [(FT1, FT3), (FT1, FT1), (FT1, FT2), (FT2, FT3), (FT2, FT2), (FT3, FT3)],
)
def test_verifies_genuine_windows(start, end):
    proof = _proof(start, end)
    assert verify(proof, _expected(proof)) is True


def test_genuine_proof_without_outside_report():
    # A middle single-stage window must verify using only its proof object:
    # the carried diff brings the front-side bundle.
    proof = _proof(FT2, FT2)
    assert verify(proof, _expected(proof)) is True


def test_verification_does_not_mutate_inputs():
    proof = _proof(FT2, FT3)
    proof_snapshot = copy.deepcopy(proof)
    expected = _expected(proof)
    expected_snapshot = copy.deepcopy(expected)
    assert verify(proof, expected) is True
    assert proof == proof_snapshot
    assert expected == expected_snapshot


# ------------------------------------------------------- structural failures


def test_proof_not_a_dict_raises():
    with pytest.raises(ValueError):
        verify([], _expected(_proof(FT1, FT1)))


def test_proof_wrong_top_level_keys_raises():
    proof = dict(_proof(FT1, FT1))
    proof["extra"] = 1
    with pytest.raises(ValueError):
        verify(proof, _expected(_proof(FT1, FT1)))


def test_proof_missing_top_level_key_raises():
    proof = dict(_proof(FT2, FT3))
    del proof["anchor"]
    with pytest.raises(ValueError):
        verify(proof, {})


def test_proof_bad_time_raises():
    proof = dict(_proof(FT2, FT3))
    proof["start"] = "not-a-time"
    with pytest.raises(ValueError):
        verify(proof, {})


def test_proof_reversed_window_raises():
    proof = dict(_proof(FT2, FT3))
    proof["start"], proof["end"] = proof["end"], proof["start"]
    with pytest.raises(ValueError):
        verify(proof, {})


def test_proof_bad_anchor_format_raises():
    proof = dict(_proof(FT2, FT3))
    proof["anchor"] = "Z" * 64
    with pytest.raises(ValueError):
        verify(proof, {})


def test_proof_bad_commitment_format_raises():
    proof = dict(_proof(FT2, FT3))
    proof["commitment"] = "a" * 63
    with pytest.raises(ValueError):
        verify(proof, {})


def test_empty_stages_raises():
    proof = dict(_proof(FT2, FT3))
    proof["stages"] = []
    with pytest.raises(ValueError):
        verify(proof, {})


def test_stage_wrong_keys_raises():
    proof = _proof(FT2, FT3)
    proof["stages"][0] = dict(proof["stages"][0])
    del proof["stages"][0]["bundle"]
    with pytest.raises(ValueError):
        verify(proof, {})


def test_disordered_stages_raise():
    proof = dict(_proof(FT1, FT3))
    proof["stages"] = [proof["stages"][1], proof["stages"][0]]
    with pytest.raises(ValueError):
        verify(proof, {})


def test_genesis_first_stage_must_have_null_diff():
    proof = dict(_proof(FT1, FT2))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["diff"] = stages[1]["diff"]
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify(proof, {})


def test_carried_first_stage_diff_wrong_after_root_raises():
    proof = dict(_proof(FT2, FT3))
    stages = copy.deepcopy(proof["stages"])
    forged = copy.deepcopy(stages[0]["diff"])
    forged["after_root"] = forged["before_root"]
    stages[0]["diff"] = forged
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify(proof, {})


def test_carried_first_stage_diff_illegal_change_raises():
    proof = dict(_proof(FT2, FT2))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["diff"]["changes"][0]["kind"] = "bogus"
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify(proof, {})


def test_inner_diff_illegal_change_raises():
    proof = dict(_proof(FT1, FT3))
    stages = copy.deepcopy(proof["stages"])
    stages[2]["diff"]["changes"][0]["kind"] = "bogus"
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify(proof, {})


def test_adjacent_diff_must_correspond_to_neighbors():
    proof = dict(_proof(FT1, FT3))
    # The third stage's diff must describe bundle2 -> bundle3; swapping in
    # the diff from the second position breaks correspondence.
    other = _proof(FT2, FT3)
    stages = copy.deepcopy(proof["stages"])
    stages[2] = copy.deepcopy(stages[2])
    stages[2]["diff"] = other["stages"][0]["diff"]
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify(proof, {})


def test_bad_hex_inside_stage_raises():
    proof = dict(_proof(FT2, FT3))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["previous"] = "g" * 64
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify(proof, {})


def test_invalid_embedded_bundle_raises():
    proof = dict(_proof(FT2, FT3))
    stages = copy.deepcopy(proof["stages"])
    del stages[0]["bundle"]["proofs"][0]["proof"]["commitment"]
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify(proof, {})


# ------------------------------------------- expected structural failures


def test_expected_not_a_dict_raises():
    with pytest.raises(ValueError):
        verify(_proof(FT1, FT1), [])


def test_expected_wrong_keys_raises():
    proof = _proof(FT1, FT1)
    expected = dict(_expected(proof))
    expected["root"] = expected["commitment"]
    with pytest.raises(ValueError):
        verify(proof, expected)


def test_expected_missing_key_raises():
    proof = _proof(FT1, FT1)
    expected = dict(_expected(proof))
    del expected["anchor"]
    with pytest.raises(ValueError):
        verify(proof, expected)


def test_expected_bad_time_raises():
    proof = _proof(FT1, FT1)
    expected = dict(_expected(proof))
    expected["start"] = "x"
    with pytest.raises(ValueError):
        verify(proof, expected)


def test_expected_bad_hex_raises():
    proof = _proof(FT1, FT1)
    expected = dict(_expected(proof))
    expected["anchor"] = "0" * 63
    with pytest.raises(ValueError):
        verify(proof, expected)


def test_expected_reversed_window_raises():
    proof = _proof(FT2, FT3)
    expected = dict(_expected(proof))
    expected["start"], expected["end"] = expected["end"], expected["start"]
    with pytest.raises(ValueError):
        verify(proof, expected)


# ---------------------------------------------------------- False after legality


def test_wrong_anchor_returns_false():
    proof = _proof(FT2, FT3)
    expected = _expected(proof)
    expected["anchor"] = "f" * 64
    assert verify(proof, expected) is False


def test_wrong_commitment_in_expected_returns_false():
    proof = _proof(FT2, FT3)
    expected = _expected(proof)
    expected["commitment"] = "f" * 64
    assert verify(proof, expected) is False


def test_wrong_start_in_expected_returns_false():
    proof = _proof(FT2, FT3)
    expected = _expected(proof)
    expected["start"] = FT1
    assert verify(proof, expected) is False


def test_wrong_end_in_expected_returns_false():
    proof = _proof(FT2, FT3)
    expected = _expected(proof)
    expected["end"] = FT2
    assert verify(proof, expected) is False


def test_declared_commitment_false_returns_false():
    proof = dict(_proof(FT2, FT3))
    proof["commitment"] = "f" * 64
    assert verify(proof, _expected(_proof(FT2, FT3))) is False


def test_broken_stage_previous_returns_false():
    proof = dict(_proof(FT2, FT3))
    stages = copy.deepcopy(proof["stages"])
    stages[1]["previous"] = "f" * 64
    proof["stages"] = stages
    assert verify(proof, _expected(_proof(FT2, FT3))) is False


def test_false_stage_digest_returns_false():
    proof = dict(_proof(FT1, FT3))
    stages = copy.deepcopy(proof["stages"])
    stages[1]["digest"] = "f" * 64
    proof["stages"] = stages
    assert verify(proof, _expected(_proof(FT1, FT3))) is False


def test_false_bundle_member_digest_returns_false():
    proof = dict(_proof(FT2, FT3))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["bundle"]["proofs"][0]["digest"] = "f" * 64
    proof["stages"] = stages
    assert verify(proof, _expected(_proof(FT2, FT3))) is False


def test_false_bundle_root_returns_false():
    # In a head single-stage window there is no adjacent diff binding the
    # bundle root, so the wrong root stays structurally legal and surfaces as
    # a false summary rather than a ValueError.
    proof = dict(_proof(FT1, FT1))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["bundle"]["root"] = "f" * 64
    proof["stages"] = stages
    assert verify(proof, _expected(_proof(FT1, FT1))) is False


def test_false_carried_diff_bundle_summary_returns_false():
    proof = dict(_proof(FT2, FT2))
    stages = copy.deepcopy(proof["stages"])
    # Corrupt only a hex summary of the front-side bundle carried inside the
    # first-stage diff. The structures stay legal but the before bundle no
    # longer chains, so its truthfulness recomputation fails.
    stages[0]["diff"]["before"]["proofs"][0]["digest"] = "f" * 64
    proof["stages"] = stages
    assert verify(proof, _expected(_proof(FT2, FT2))) is False


def test_false_carried_diff_digest_returns_false():
    proof = dict(_proof(FT2, FT2))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["diff"]["digest"] = "f" * 64
    proof["stages"] = stages
    assert verify(proof, _expected(_proof(FT2, FT2))) is False


def test_carried_diff_incomplete_changes_returns_false():
    # A structurally legal change list that omits the real changes is not a
    # ValueError: it yields False only after all structures validate.
    proof = dict(_proof(FT2, FT2))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["diff"]["changes"] = []
    proof["stages"] = stages
    assert verify(proof, _expected(_proof(FT2, FT2))) is False


def test_inner_diff_incomplete_changes_returns_false():
    proof = dict(_proof(FT1, FT3))
    stages = copy.deepcopy(proof["stages"])
    stages[1]["diff"]["changes"] = []
    proof["stages"] = stages
    assert verify(proof, _expected(_proof(FT1, FT3))) is False


def test_false_inner_diff_digest_returns_false():
    proof = dict(_proof(FT1, FT3))
    stages = copy.deepcopy(proof["stages"])
    stages[1]["diff"]["digest"] = "f" * 64
    proof["stages"] = stages
    assert verify(proof, _expected(_proof(FT1, FT3))) is False


def test_boundary_mismatch_start_returns_false():
    proof = dict(_proof(FT2, FT3))
    proof["start"] = FT1
    expected = {
        "start": FT1,
        "end": FT3,
        "anchor": proof["anchor"],
        "commitment": proof["commitment"],
    }
    assert verify(proof, expected) is False


def test_boundary_mismatch_end_returns_false():
    proof = dict(_proof(FT2, FT3))
    proof["end"] = FT2
    expected = {
        "start": FT2,
        "end": FT2,
        "anchor": proof["anchor"],
        "commitment": proof["commitment"],
    }
    assert verify(proof, expected) is False


def test_skipped_stage_returns_false():
    # Dropping the head stage leaves a structurally legal non-head window
    # (the surviving head stage carries its front-side diff and non-zero
    # previous), but its anchor/stage set no longer matches the claimed
    # boundary window that expected describes, so recomputation fails.
    genuine = _proof(FT1, FT3)
    proof = _proof(FT2, FT3)
    assert len(proof["stages"]) == 2
    assert verify(proof, _expected(genuine)) is False


# ---------------------------------------------------------------- endpoint


def test_http_verify_genuine_returns_true_compact_json():
    proof = _proof(FT2, FT3)
    response = client.post(
        VERIFY_PATH, json={"proof": proof, "expected": _expected(proof)}
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'


def test_http_verify_false_summary_returns_200_false():
    proof = dict(_proof(FT2, FT3))
    proof["commitment"] = "f" * 64
    response = client.post(
        VERIFY_PATH,
        json={"proof": proof, "expected": _expected(_proof(FT2, FT3))},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":false}'


def test_http_verify_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    proof = _proof(FT1, FT1)
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
