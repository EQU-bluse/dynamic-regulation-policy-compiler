import copy

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    evolution_checkpoint,
    matrix_bundle_evolution,
    verify_evolution_checkpoint,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"
AT1 = "2021-05-01T00:00:00Z"
AT2 = "2021-06-01T00:00:00Z"
AT3 = "2021-07-01T00:00:00Z"


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


def _bundle_one():
    return decision_matrix_attestation_bundle([{"id": "a", "report": _report_a()}])


def _bundle_two():
    return decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()}, {"id": "b", "report": _report_b()}]
    )


def _bundle_three():
    return decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": _report_a()},
            {"id": "b", "report": _report_b()},
            {"id": "c", "report": _report_c()},
        ]
    )


def _stage_inputs():
    return [
        {"at": AT1, "bundle": _bundle_one()},
        {"at": AT2, "bundle": _bundle_two()},
        {"at": AT3, "bundle": _bundle_three()},
    ]


def _evolution():
    return matrix_bundle_evolution(_stage_inputs())


def _proof(start, end):
    return evolution_checkpoint(_evolution(), start, end)


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
    [(AT1, AT3), (AT1, AT1), (AT1, AT2), (AT2, AT3), (AT2, AT2), (AT3, AT3)],
)
def test_verifies_genuine_windows(start, end):
    proof = _proof(start, end)
    assert verify_evolution_checkpoint(proof, _expected(proof)) is True


def test_genuine_proof_without_outside_report():
    # A middle single-stage window must verify using only its proof object:
    # the carried diff brings the front-side bundle.
    proof = _proof(AT2, AT2)
    assert verify_evolution_checkpoint(proof, _expected(proof)) is True


def test_verification_does_not_mutate_inputs():
    proof = _proof(AT2, AT3)
    proof_snapshot = copy.deepcopy(proof)
    expected = _expected(proof)
    expected_snapshot = copy.deepcopy(expected)
    assert verify_evolution_checkpoint(proof, expected) is True
    assert proof == proof_snapshot
    assert expected == expected_snapshot


# ------------------------------------------------------- structural failures


def test_proof_not_a_dict_raises():
    with pytest.raises(ValueError):
        verify_evolution_checkpoint([], _expected(_proof(AT1, AT1)))


def test_proof_wrong_top_level_keys_raises():
    proof = _proof(AT1, AT1)
    proof = dict(proof)
    proof["extra"] = 1
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, _expected(_proof(AT1, AT1)))


def test_proof_missing_top_level_key_raises():
    proof = dict(_proof(AT2, AT3))
    del proof["anchor"]
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, {})


def test_proof_bad_time_raises():
    proof = dict(_proof(AT2, AT3))
    proof["start"] = "not-a-time"
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, _expected(_proof(AT2, AT3)))


def test_proof_reversed_window_raises():
    proof = dict(_proof(AT2, AT3))
    proof["start"], proof["end"] = proof["end"], proof["start"]
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, {})


def test_proof_bad_anchor_format_raises():
    proof = dict(_proof(AT2, AT3))
    proof["anchor"] = "Z" * 64
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, {})


def test_proof_bad_commitment_format_raises():
    proof = dict(_proof(AT2, AT3))
    proof["commitment"] = "a" * 63
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, {})


def test_empty_stages_raises():
    proof = dict(_proof(AT2, AT3))
    proof["stages"] = []
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, {})


def test_stage_wrong_keys_raises():
    proof = _proof(AT2, AT3)
    proof["stages"][0] = dict(proof["stages"][0])
    del proof["stages"][0]["bundle"]
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, {})


def test_disordered_stages_raise():
    proof = dict(_proof(AT1, AT3))
    proof["stages"] = [proof["stages"][1], proof["stages"][0]]
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, {})


def test_genesis_first_stage_must_have_null_diff():
    proof = dict(_proof(AT1, AT2))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["diff"] = stages[1]["diff"]
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, {})


def test_carried_first_stage_diff_must_reproduce_its_after_bundle():
    proof = dict(_proof(AT2, AT3))
    forged = copy.deepcopy(proof["stages"][0]["diff"])
    # Semantic forgery inside the carried after bundle must be rejected
    # structurally when the diff is normalized.
    forged["after"]["reports"][0]["report"]["matrix"]["points"][0]["cases"][0][
        "decision"
    ] = "forged"
    stages = copy.deepcopy(proof["stages"])
    stages[0]["diff"] = forged
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, {})


def test_carried_first_stage_diff_wrong_after_bundle_raises():
    proof = dict(_proof(AT2, AT3))
    forged = copy.deepcopy(proof["stages"][0]["diff"])
    forged["after_root"] = forged["before_root"]
    stages = copy.deepcopy(proof["stages"])
    stages[0]["diff"] = forged
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, {})


def test_adjacent_diff_must_correspond_to_neighbors():
    proof = dict(_proof(AT1, AT3))
    # The second stage's diff must describe bundle1 -> bundle2; swapping in
    # the diff from another position breaks correspondence.
    other = _proof(AT2, AT3)
    stages = copy.deepcopy(proof["stages"])
    stages[1] = copy.deepcopy(stages[1])
    stages[1]["diff"] = other["stages"][-1]["diff"]
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, {})


def test_semantic_forgery_in_stage_bundle_raises():
    proof = dict(_proof(AT2, AT3))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["bundle"]["reports"][0]["report"]["matrix"]["points"][0]["cases"][0][
        "decision"
    ] = "forged"
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, {})


def test_bad_hex_inside_stage_raises():
    proof = dict(_proof(AT2, AT3))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["previous"] = "g" * 64
    proof["stages"] = stages
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, {})


# ------------------------------------------------- expected structural failures


def test_expected_not_a_dict_raises():
    proof = _proof(AT1, AT1)
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, [])


def test_expected_wrong_keys_raises():
    proof = _proof(AT1, AT1)
    expected = dict(_expected(proof))
    expected["root"] = expected["commitment"]
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, expected)


def test_expected_missing_key_raises():
    proof = _proof(AT1, AT1)
    expected = dict(_expected(proof))
    del expected["anchor"]
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, expected)


def test_expected_bad_time_raises():
    proof = _proof(AT1, AT1)
    expected = dict(_expected(proof))
    expected["start"] = "x"
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, expected)


def test_expected_bad_hex_raises():
    proof = _proof(AT1, AT1)
    expected = dict(_expected(proof))
    expected["anchor"] = "0" * 63
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, expected)


# ---------------------------------------------------------- False after legality


def test_wrong_anchor_returns_false():
    proof = _proof(AT2, AT3)
    expected = _expected(proof)
    expected["anchor"] = "f" * 64
    assert verify_evolution_checkpoint(proof, expected) is False


def test_wrong_commitment_in_expected_returns_false():
    proof = _proof(AT2, AT3)
    expected = _expected(proof)
    expected["commitment"] = "f" * 64
    assert verify_evolution_checkpoint(proof, expected) is False


def test_wrong_start_in_expected_returns_false():
    proof = _proof(AT2, AT3)
    expected = _expected(proof)
    expected["start"] = AT1
    assert verify_evolution_checkpoint(proof, expected) is False


def test_wrong_end_in_expected_returns_false():
    proof = _proof(AT2, AT3)
    expected = _expected(proof)
    expected["end"] = AT2
    assert verify_evolution_checkpoint(proof, expected) is False


def test_declared_commitment_false_returns_false():
    proof = dict(_proof(AT2, AT3))
    proof["commitment"] = "f" * 64
    assert verify_evolution_checkpoint(proof, _expected(_proof(AT2, AT3))) is False


def test_broken_stage_previous_returns_false():
    proof = dict(_proof(AT2, AT3))
    stages = copy.deepcopy(proof["stages"])
    stages[1]["previous"] = "f" * 64
    proof["stages"] = stages
    assert verify_evolution_checkpoint(proof, _expected(_proof(AT2, AT3))) is False


def test_false_stage_digest_returns_false():
    proof = dict(_proof(AT1, AT3))
    stages = copy.deepcopy(proof["stages"])
    stages[1]["digest"] = "f" * 64
    proof["stages"] = stages
    # commitment stays the declared last digest; the broken middle link must
    # still be detected.
    assert verify_evolution_checkpoint(proof, _expected(_proof(AT1, AT3))) is False


def test_false_bundle_member_digest_returns_false():
    proof = dict(_proof(AT2, AT3))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["bundle"]["reports"][0]["digest"] = "f" * 64
    proof["stages"] = stages
    assert verify_evolution_checkpoint(proof, _expected(_proof(AT2, AT3))) is False


def test_false_bundle_root_returns_false():
    # In a head single-stage window there is no adjacent diff binding the
    # bundle root, so the wrong root stays structurally legal and surfaces as
    # a false summary rather than a ValueError.
    proof = dict(_proof(AT1, AT1))
    stages = copy.deepcopy(proof["stages"])
    stages[0]["bundle"]["root"] = "f" * 64
    proof["stages"] = stages
    expected = _expected(_proof(AT1, AT1))
    assert verify_evolution_checkpoint(proof, expected) is False


def test_false_carried_diff_bundle_summary_returns_false():
    proof = dict(_proof(AT2, AT2))
    stages = copy.deepcopy(proof["stages"])
    # Corrupt only a hex summary of the front-side bundle carried inside the
    # first-stage diff. The structures stay legal but the before bundle no
    # longer chains, so its truthfulness recomputation fails.
    stages[0]["diff"]["before"]["reports"][0]["digest"] = "f" * 64
    proof["stages"] = stages
    assert verify_evolution_checkpoint(proof, _expected(_proof(AT2, AT2))) is False


def test_boundary_mismatch_start_returns_false():
    proof = dict(_proof(AT2, AT3))
    proof["start"] = AT1
    # expected stays consistent with the declared anchor/commitment; only the
    # boundary lies.
    expected = {
        "start": AT1,
        "end": AT3,
        "anchor": proof["anchor"],
        "commitment": proof["commitment"],
    }
    assert verify_evolution_checkpoint(proof, expected) is False


def test_boundary_mismatch_end_returns_false():
    proof = dict(_proof(AT1, AT2))
    proof["end"] = AT3
    expected = {
        "start": AT1,
        "end": AT3,
        "anchor": proof["anchor"],
        "commitment": proof["commitment"],
    }
    assert verify_evolution_checkpoint(proof, expected) is False


# ---------------------------------------------------------------- endpoint


def test_http_verify_genuine_returns_true_compact_json():
    proof = _proof(AT2, AT3)
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/verify",
        json={"proof": proof, "expected": _expected(proof)},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_verify_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("checkpoint verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    proof = _proof(AT2, AT2)
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/verify",
        json={"proof": proof, "expected": _expected(proof)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b'"x"',
        b"null",
        b"{}",
        b'{"proof": {}}',
        b'{"proof": {}, "expected": {}, "extra": 1}',
        b'{"proof": {}, "report": {}}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/verify",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_structurally_invalid_proof_is_422():
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/verify",
        json={"proof": {"start": "x"}, "expected": {}},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_false_but_legal_proof_is_200_false():
    proof = _proof(AT2, AT3)
    expected = _expected(proof)
    expected["anchor"] = "f" * 64
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/verify",
        json={"proof": proof, "expected": expected},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":false}'
