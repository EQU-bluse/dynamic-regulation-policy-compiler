import copy
import json

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
AT4 = "2021-08-01T00:00:00Z"


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
    return decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()}]
    )


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


def _evolution():
    return matrix_bundle_evolution(
        [
            {"at": AT1, "bundle": _bundle_one()},
            {"at": AT2, "bundle": _bundle_two()},
            {"at": AT3, "bundle": _bundle_three()},
        ]
    )


def _expected(proof):
    return {key: proof[key] for key in ("start", "end", "anchor", "commitment")}


@pytest.fixture(
    params=[
        (AT1, AT3),
        (AT1, AT1),
        (AT1, AT2),
        (AT2, AT2),
        (AT2, AT3),
        (AT3, AT3),
    ]
)
def proof(request):
    return evolution_checkpoint(_evolution(), *request.param)


# ------------------------------------------------------------------- accepts


def test_generated_proof_verifies(proof):
    assert verify_evolution_checkpoint(proof, _expected(proof)) is True


def test_full_window_commitment_equals_original_root():
    proof = evolution_checkpoint(_evolution(), AT1, AT3)
    assert proof["commitment"] == _evolution()["root"]
    assert verify_evolution_checkpoint(proof, _expected(proof)) is True


def test_single_middle_stage_verifies_standalone():
    proof = evolution_checkpoint(_evolution(), AT2, AT2)
    assert verify_evolution_checkpoint(proof, _expected(proof)) is True


def test_does_not_mutate_inputs(proof):
    proof_snapshot = copy.deepcopy(proof)
    expected = _expected(proof)
    expected_snapshot = copy.deepcopy(expected)
    verify_evolution_checkpoint(proof, expected)
    assert proof == proof_snapshot
    assert expected == expected_snapshot


# --------------------------------------------------------- false -> returns


def test_false_commitment_returns_false(proof):
    tampered = copy.deepcopy(proof)
    tampered["commitment"] = "f" * 64
    assert verify_evolution_checkpoint(tampered, _expected(tampered)) is False


def test_false_stage_digest_returns_false(proof):
    tampered = copy.deepcopy(proof)
    tampered["stages"][-1]["digest"] = "f" * 64
    assert verify_evolution_checkpoint(tampered, _expected(proof)) is False


def test_false_previous_returns_false(proof):
    if len(proof["stages"]) < 2:
        pytest.skip("needs a multi-stage window")
    tampered = copy.deepcopy(proof)
    tampered["stages"][1]["previous"] = "f" * 64
    assert verify_evolution_checkpoint(tampered, _expected(proof)) is False


def test_wrong_expected_anchor_returns_false(proof):
    expected = _expected(proof)
    expected["anchor"] = (
        "0" * 64 if proof["anchor"] != "0" * 64 else "a" * 64
    )
    assert verify_evolution_checkpoint(proof, expected) is False


def test_wrong_expected_commitment_returns_false(proof):
    expected = _expected(proof)
    expected["commitment"] = "f" * 64
    assert verify_evolution_checkpoint(proof, expected) is False


def test_wrong_expected_boundaries_return_false():
    proof = evolution_checkpoint(_evolution(), AT2, AT3)
    expected = _expected(proof)
    expected["end"] = AT4
    assert verify_evolution_checkpoint(proof, expected) is False
    expected = _expected(proof)
    expected["start"] = AT1
    assert verify_evolution_checkpoint(proof, expected) is False


def test_false_bundle_summary_returns_false(proof):
    tampered = copy.deepcopy(proof)
    member = tampered["stages"][0]["bundle"]["reports"][0]
    member["digest"] = "f" * 64
    # The neighboring diff no longer embeds the same bundle on the first
    # middle stage; windows where the tampered stage's diff stays consistent
    # still return False via the recomputed member chain.
    try:
        result = verify_evolution_checkpoint(tampered, _expected(proof))
    except ValueError:
        return
    assert result is False


# ------------------------------------------------------- structural errors


@pytest.mark.parametrize(
    "bad_proof",
    [
        None,
        "x",
        [],
        {},
        {"start": AT1},
        {"start": AT1, "end": AT1, "anchor": "0" * 64, "stages": [], "commitment": "0" * 64},
        {
            "start": AT1,
            "end": AT1,
            "anchor": "0" * 64,
            "stages": [],
            "commitment": "0" * 64,
            "extra": 1,
        },
    ],
)
def test_malformed_proof_raises(bad_proof):
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(bad_proof, {
            "start": AT1,
            "end": AT1,
            "anchor": "0" * 64,
            "commitment": "0" * 64,
        })


def test_bad_time_raises():
    proof = evolution_checkpoint(_evolution(), AT2, AT2)
    tampered = copy.deepcopy(proof)
    tampered["start"] = "not-a-time"
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(tampered, _expected(proof))


def test_reversed_boundaries_raise():
    proof = evolution_checkpoint(_evolution(), AT2, AT3)
    tampered = copy.deepcopy(proof)
    tampered["start"] = AT3
    tampered["end"] = AT2
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(tampered, _expected(proof))


def test_bad_hex_raises():
    proof = evolution_checkpoint(_evolution(), AT2, AT2)
    tampered = copy.deepcopy(proof)
    tampered["anchor"] = "ZZ" + "0" * 62
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(tampered, _expected(proof))


def test_first_stage_at_must_equal_start():
    proof = evolution_checkpoint(_evolution(), AT2, AT3)
    tampered = copy.deepcopy(proof)
    tampered["stages"][0]["at"] = AT1
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(tampered, _expected(proof))


def test_last_stage_at_must_equal_end():
    proof = evolution_checkpoint(_evolution(), AT2, AT3)
    tampered = copy.deepcopy(proof)
    tampered["stages"][-1]["at"] = AT4
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(tampered, _expected(proof))


def test_disordered_stages_raise():
    proof = evolution_checkpoint(_evolution(), AT1, AT3)
    tampered = copy.deepcopy(proof)
    tampered["stages"][0]["at"], tampered["stages"][1]["at"] = AT2, AT1
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(tampered, _expected(proof))


def test_first_middle_stage_must_keep_diff():
    proof = evolution_checkpoint(_evolution(), AT2, AT2)
    tampered = copy.deepcopy(proof)
    tampered["stages"][0]["diff"] = None
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(tampered, _expected(proof))


def test_genesis_first_stage_with_diff_raises():
    proof = evolution_checkpoint(_evolution(), AT1, AT2)
    tampered = copy.deepcopy(proof)
    tampered["stages"][0]["diff"] = tampered["stages"][1]["diff"]
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(tampered, _expected(proof))


def test_later_null_diff_raises():
    proof = evolution_checkpoint(_evolution(), AT1, AT3)
    tampered = copy.deepcopy(proof)
    tampered["stages"][1]["diff"] = None
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(tampered, _expected(proof))


def test_diff_with_wrong_after_bundle_raises():
    proof = evolution_checkpoint(_evolution(), AT2, AT3)
    tampered = copy.deepcopy(proof)
    tampered["stages"][0]["diff"]["after_root"] = "f" * 64
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(tampered, _expected(proof))


def test_non_adjacent_diff_raises():
    proof = evolution_checkpoint(_evolution(), AT2, AT3)
    tampered = copy.deepcopy(proof)
    # The second window stage's diff before side must equal the first window
    # stage's bundle; pointing it at a non-adjacent bundle must raise.
    other = _evolution()
    tampered["stages"][1]["diff"]["before"] = copy.deepcopy(
        other["stages"][2]["bundle"]
    )
    tampered["stages"][1]["diff"]["before_root"] = other["stages"][2]["bundle"][
        "root"
    ]
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(tampered, _expected(proof))


def test_extra_stage_key_raises():
    proof = evolution_checkpoint(_evolution(), AT2, AT2)
    tampered = copy.deepcopy(proof)
    tampered["stages"][0]["extra"] = 1
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(tampered, _expected(proof))


def test_semantic_forgery_in_bundle_raises():
    proof = evolution_checkpoint(_evolution(), AT2, AT2)
    tampered = copy.deepcopy(proof)
    tampered["stages"][0]["bundle"]["reports"][0]["report"]["matrix"]["points"][0][
        "cases"
    ][0]["decision"] = "forged"
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(tampered, _expected(proof))


# ---------------------------------------------------------------- expected


@pytest.mark.parametrize(
    "bad_expected",
    [
        None,
        "x",
        [],
        {},
        {"start": AT2, "end": AT2, "anchor": "0" * 64},
        {"start": AT2, "end": AT2, "anchor": "0" * 64, "commitment": "0" * 64, "x": 1},
    ],
)
def test_malformed_expected_raises(bad_expected):
    proof = evolution_checkpoint(_evolution(), AT2, AT2)
    with pytest.raises(ValueError):
        verify_evolution_checkpoint(proof, bad_expected)


# ---------------------------------------------------------------- endpoint


URL = "/decision-matrix/attest/bundle/evolution/checkpoint/verify"


def test_http_verify_returns_true():
    proof = evolution_checkpoint(_evolution(), AT2, AT3)
    response = client.post(URL, json={"proof": proof, "expected": _expected(proof)})
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_verify_false_commitment():
    proof = evolution_checkpoint(_evolution(), AT2, AT2)
    proof["commitment"] = "f" * 64
    response = client.post(URL, json={"proof": proof, "expected": _expected(proof)})
    assert response.status_code == 200
    assert response.content == b'{"valid":false}'


def test_http_verify_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    proof = evolution_checkpoint(_evolution(), AT3, AT3)
    response = client.post(URL, json={"proof": proof, "expected": _expected(proof)})
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
        b'{"expected": {}}',
        b'{"report": {}, "expected": {}}',
        b'{"proof": {}, "expected": {}, "extra": 1}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        URL,
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_function_value_error_is_422():
    proof = evolution_checkpoint(_evolution(), AT2, AT2)
    proof["stages"][0]["diff"] = None
    response = client.post(URL, json={"proof": proof, "expected": _expected(proof)})
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_round_trip_with_checkpoint_endpoint():
    generated = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint",
        json={"report": _evolution(), "start": AT2, "end": AT3},
    )
    assert generated.status_code == 200
    proof = json.loads(generated.content)
    response = client.post(URL, json={"proof": proof, "expected": _expected(proof)})
    assert response.status_code == 200
    assert response.json() == {"valid": True}
