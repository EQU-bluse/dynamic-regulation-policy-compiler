import copy
import json

import pytest
from fastapi.testclient import TestClient

import test_bundle_evolution_checkpoint_bundle_evolution_checkpoint as fx
from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle as bind,
    verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle as verify,
)

client = TestClient(app)

VERIFY_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/"
    "checkpoint/bundle/verify"
)


def _proof(start, end):
    return fx._proof(start, end)


def _bundle():
    return bind(
        [
            {"id": "z", "proof": _proof(fx.ET2, fx.ET3)},
            {"id": "a", "proof": _proof(fx.ET1, fx.ET2)},
        ]
    )


def _expected(bundle, ids=("a", "z")):
    return {"root": bundle["root"], "proof_ids": list(ids)}


# ---------------------------------------------------------------- true cases


def test_verifies_genuine_bundle():
    bundle = _bundle()
    assert verify(bundle, _expected(bundle)) is True


def test_verifies_without_evolution_report_or_history():
    bundle = _bundle()
    expected = _expected(bundle)
    # Only the cut window proofs inside the bundle are needed.
    assert verify(copy.deepcopy(bundle), copy.deepcopy(expected)) is True


def test_expected_proof_ids_caller_order_is_arbitrary():
    bundle = _bundle()
    assert verify(bundle, _expected(bundle, ("z", "a"))) is True
    assert verify(bundle, _expected(bundle, ("a", "z"))) is True


def test_verification_does_not_mutate_inputs():
    bundle = _bundle()
    expected = _expected(bundle)
    bundle_snapshot = copy.deepcopy(bundle)
    expected_snapshot = copy.deepcopy(expected)
    assert verify(bundle, expected) is True
    assert bundle == bundle_snapshot
    assert expected == expected_snapshot


# ----------------------------------------------------- structural ValueError


def test_report_not_a_dict_raises():
    with pytest.raises(ValueError):
        verify([], _expected(_bundle()))


def test_report_wrong_top_level_keys_raises():
    bundle = _bundle()
    bundle["extra"] = 1
    with pytest.raises(ValueError):
        verify(bundle, _expected(bundle))


def test_report_missing_top_level_key_raises():
    bundle = _bundle()
    del bundle["root"]
    with pytest.raises(ValueError):
        verify(bundle, {"proof_ids": ["a"]})


def test_report_root_bad_hex_raises():
    bundle = _bundle()
    bundle["root"] = "x" * 64
    with pytest.raises(ValueError):
        verify(bundle, _expected(bundle))


def test_proofs_must_be_non_empty_list():
    bundle = _bundle()
    bundle["proofs"] = []
    with pytest.raises(ValueError):
        verify(bundle, _expected(bundle))


def test_member_wrong_keys_raises():
    bundle = _bundle()
    del bundle["proofs"][0]["digest"]
    with pytest.raises(ValueError):
        verify(bundle, _expected(bundle))


def test_member_extra_key_raises():
    bundle = _bundle()
    bundle["proofs"][0]["extra"] = 1
    with pytest.raises(ValueError):
        verify(bundle, _expected(bundle))


def test_member_id_must_be_non_empty_string():
    bundle = _bundle()
    bundle["proofs"][0]["id"] = ""
    with pytest.raises(ValueError):
        verify(bundle, _expected(bundle))


def test_duplicate_member_ids_raise():
    bundle = _bundle()
    bundle["proofs"][1]["id"] = "a"
    with pytest.raises(ValueError):
        verify(bundle, _expected(bundle))


def test_disordered_members_raise():
    bundle = _bundle()
    bundle["proofs"] = list(reversed(bundle["proofs"]))
    with pytest.raises(ValueError):
        verify(bundle, _expected(bundle))


def test_member_previous_bad_hex_raises():
    bundle = _bundle()
    bundle["proofs"][0]["previous"] = "x" * 64
    with pytest.raises(ValueError):
        verify(bundle, _expected(bundle))


def test_member_digest_bad_hex_raises():
    bundle = _bundle()
    bundle["proofs"][0]["digest"] = "x" * 64
    with pytest.raises(ValueError):
        verify(bundle, _expected(bundle))


def test_structurally_invalid_embedded_proof_raises():
    bundle = _bundle()
    bundle["proofs"][0]["proof"] = {"start": fx.ET1}
    with pytest.raises(ValueError):
        verify(bundle, _expected(bundle))


def test_embedded_proof_bad_time_raises():
    bundle = _bundle()
    bundle["proofs"][0]["proof"]["start"] = "not-a-time"
    with pytest.raises(ValueError):
        verify(bundle, _expected(bundle))


def test_embedded_proof_disordered_stages_raise():
    bundle = _bundle()
    stages = bundle["proofs"][1]["proof"]["stages"]
    stages[0], stages[1] = stages[1], stages[0]
    with pytest.raises(ValueError):
        verify(bundle, _expected(bundle))


# --------------------------------------------------- expected-key ValueErrors


def test_expected_not_a_dict_raises():
    with pytest.raises(ValueError):
        verify(_bundle(), [])


def test_expected_wrong_keys_raises():
    bundle = _bundle()
    with pytest.raises(ValueError):
        verify(bundle, {"root": bundle["root"], "proof_ids": ["a"], "x": 1})


def test_expected_missing_key_raises():
    with pytest.raises(ValueError):
        verify(_bundle(), {"root": "0" * 64})


def test_expected_root_bad_hex_raises():
    bundle = _bundle()
    with pytest.raises(ValueError):
        verify(bundle, {"root": "z" * 64, "proof_ids": ["a", "z"]})


@pytest.mark.parametrize(
    "proof_ids",
    [
        None,
        [],
        ["", "a"],
        ["a", 1],
        ["a", "a"],
    ],
)
def test_expected_proof_ids_invalid_raise(proof_ids):
    bundle = _bundle()
    with pytest.raises(ValueError):
        verify(bundle, {"root": bundle["root"], "proof_ids": proof_ids})


def test_all_structure_checks_precede_false_comparisons():
    # A false declared digest must not short-circuit a structural error
    # elsewhere in the same report.
    bundle = _bundle()
    bundle["root"] = "1" * 64
    bundle["proofs"] = list(reversed(bundle["proofs"]))
    with pytest.raises(ValueError):
        verify(bundle, _expected(bundle))


# ------------------------------------------------------------------ False row


def test_wrong_root_in_report_returns_false():
    bundle = _bundle()
    bundle["root"] = "1" * 64
    assert verify(bundle, _expected(bundle)) is False


def test_wrong_expected_root_returns_false():
    bundle = _bundle()
    expected = _expected(bundle)
    expected["root"] = "1" * 64
    assert verify(bundle, expected) is False


def test_broken_member_previous_returns_false():
    bundle = _bundle()
    bundle["proofs"][1]["previous"] = "1" * 64
    assert verify(bundle, _expected(bundle)) is False


def test_false_member_digest_returns_false():
    bundle = _bundle()
    bundle["proofs"][0]["digest"] = "1" * 64
    assert verify(bundle, _expected(bundle)) is False


def test_tampered_embedded_proof_returns_false():
    bundle = _bundle()
    bundle["proofs"][0]["proof"]["commitment"] = "1" * 64
    assert verify(bundle, _expected(bundle)) is False


def test_tampered_embedded_stage_returns_false():
    bundle = _bundle()
    bundle["proofs"][1]["proof"]["stages"][1]["digest"] = "1" * 64
    assert verify(bundle, _expected(bundle)) is False


def test_missing_expected_id_returns_false():
    bundle = _bundle()
    assert verify(bundle, {"root": bundle["root"], "proof_ids": ["a"]}) is False


def test_extra_expected_id_returns_false():
    bundle = _bundle()
    assert verify(
        bundle, {"root": bundle["root"], "proof_ids": ["a", "z", "q"]}
    ) is False


def test_wrong_expected_id_returns_false():
    bundle = _bundle()
    assert verify(
        bundle, {"root": bundle["root"], "proof_ids": ["a", "q"]}
    ) is False


def test_false_inputs_do_not_mutate():
    bundle = _bundle()
    bundle["root"] = "1" * 64
    snapshot = copy.deepcopy(bundle)
    assert verify(bundle, _expected(bundle)) is False
    assert bundle == snapshot


# ---------------------------------------------------------------- endpoint


def test_http_verify_genuine_returns_true_compact_json():
    bundle = _bundle()
    response = client.post(
        VERIFY_PATH, json={"report": bundle, "expected": _expected(bundle)}
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_verify_false_summary_returns_200_false():
    bundle = _bundle()
    bundle["root"] = "1" * 64
    response = client.post(
        VERIFY_PATH, json={"report": bundle, "expected": _expected(bundle)}
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":false}'


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b'"x"',
        b"null",
        b"{}",
        b'{"report": {}}',
        b'{"expected": {}}',
        b'{"report": {}, "expected": {}, "extra": 1}',
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


def test_http_structurally_invalid_report_is_422():
    bundle = _bundle()
    bundle["proofs"] = list(reversed(bundle["proofs"]))
    response = client.post(
        VERIFY_PATH, json={"report": bundle, "expected": _expected(bundle)}
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    bundle = _bundle()
    response = client.post(
        VERIFY_PATH, json={"report": bundle, "expected": _expected(bundle)}
    )
    assert response.status_code == 200
    assert json.loads(response.content) == {"valid": True}
