import copy

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    bundle_evolution_checkpoint,
    bundle_evolution_checkpoint_bundle,
    checkpoint_chain,
    checkpoint_chain_checkpoint,
    checkpoint_chain_checkpoint_bundle,
    checkpoint_chain_checkpoint_bundle_evolution,
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    evolution_checkpoint,
    evolution_checkpoint_bundle,
    matrix_bundle_evolution,
    verify_bundle_evolution_checkpoint_bundle,
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
DT1 = "2021-11-01T00:00:00Z"
DT2 = "2021-12-01T00:00:00Z"
DT3 = "2022-01-01T00:00:00Z"

VERIFY_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution/checkpoint/bundle/verify"
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


def _window_proof(start, end):
    return checkpoint_chain_checkpoint(_chain(), start, end)


def _bundle_one():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(RT1, RT1)},
            {"id": "beta", "proof": _window_proof(RT2, RT3)},
        ]
    )


def _bundle_two():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(RT1, RT1)},
            {"id": "beta", "proof": _window_proof(RT2, RT2)},
            {"id": "伽马", "proof": _window_proof(RT3, RT3)},
        ]
    )


def _bundle_three():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(RT1, RT2)},
            {"id": "伽马", "proof": _window_proof(RT3, RT3)},
        ]
    )


def _evolution():
    return checkpoint_chain_checkpoint_bundle_evolution(
        [
            {"at": DT1, "bundle": _bundle_one()},
            {"at": DT2, "bundle": _bundle_two()},
            {"at": DT3, "bundle": _bundle_three()},
        ]
    )


def _proof(start, end):
    return bundle_evolution_checkpoint(_evolution(), start, end)


def _items():
    return [
        {"id": "beta", "proof": _proof(DT2, DT3)},
        {"id": "alpha", "proof": _proof(DT1, DT1)},
        {"id": "伽马", "proof": _proof(DT3, DT3)},
    ]


def _bundle():
    return bundle_evolution_checkpoint_bundle(_items())


def _expected(bundle, ids=None):
    return {
        "root": bundle["root"],
        "proof_ids": [member["id"] for member in bundle["proofs"]]
        if ids is None
        else ids,
    }


# ---------------------------------------------------------------- genuine


def test_verifies_genuine_bundle():
    bundle = _bundle()
    assert (
        verify_bundle_evolution_checkpoint_bundle(bundle, _expected(bundle)) is True
    )


def test_verifies_without_outside_report_or_history():
    # Every embedded window proof (including a middle single-stage window
    # carrying only a front-side diff) self-verifies from the bundle alone.
    bundle = bundle_evolution_checkpoint_bundle(
        [{"id": "solo", "proof": _proof(DT2, DT2)}]
    )
    assert (
        verify_bundle_evolution_checkpoint_bundle(bundle, _expected(bundle)) is True
    )


def test_expected_proof_ids_caller_order_is_arbitrary():
    bundle = _bundle()
    ids = [member["id"] for member in bundle["proofs"]]
    assert (
        verify_bundle_evolution_checkpoint_bundle(
            bundle, {"root": bundle["root"], "proof_ids": list(reversed(ids))}
        )
        is True
    )
    assert (
        verify_bundle_evolution_checkpoint_bundle(
            bundle, {"root": bundle["root"], "proof_ids": ["伽马", "alpha", "beta"]}
        )
        is True
    )


def test_verification_does_not_mutate_inputs():
    bundle = _bundle()
    bundle_snapshot = copy.deepcopy(bundle)
    expected = {"root": bundle["root"], "proof_ids": ["伽马", "beta", "alpha"]}
    expected_snapshot = copy.deepcopy(expected)
    assert verify_bundle_evolution_checkpoint_bundle(bundle, expected) is True
    assert bundle == bundle_snapshot
    assert expected == expected_snapshot


# ------------------------------------------------------- report structural


def test_report_not_a_dict_raises():
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle([], _expected(_bundle()))


def test_report_wrong_top_level_keys_raises():
    bundle = dict(_bundle())
    bundle["extra"] = 1
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, _expected(_bundle()))


def test_report_missing_top_level_key_raises():
    bundle = dict(_bundle())
    del bundle["root"]
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, {})


def test_report_root_bad_hex_raises():
    bundle = dict(_bundle())
    bundle["root"] = "Z" * 64
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, {})


def test_proofs_must_be_non_empty_list():
    bundle = dict(_bundle())
    bundle["proofs"] = []
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, {})


def test_member_wrong_keys_raises():
    bundle = dict(_bundle())
    proofs = copy.deepcopy(bundle["proofs"])
    del proofs[0]["digest"]
    bundle["proofs"] = proofs
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, {})


def test_member_extra_key_raises():
    bundle = dict(_bundle())
    proofs = copy.deepcopy(bundle["proofs"])
    proofs[0]["extra"] = 1
    bundle["proofs"] = proofs
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, {})


def test_member_id_must_be_non_empty_string():
    bundle = dict(_bundle())
    proofs = copy.deepcopy(bundle["proofs"])
    proofs[0]["id"] = ""
    bundle["proofs"] = proofs
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, {})


def test_duplicate_member_ids_raise():
    bundle = dict(_bundle())
    proofs = copy.deepcopy(bundle["proofs"])
    proofs[1] = dict(proofs[1])
    proofs[1]["id"] = proofs[0]["id"]
    # Duplication alone must raise; no reorder adjustment is attempted.
    bundle["proofs"] = proofs
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, {})


def test_disordered_members_raise():
    bundle = dict(_bundle())
    bundle["proofs"] = list(reversed(bundle["proofs"]))
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, {})


def test_member_previous_bad_hex_raises():
    bundle = dict(_bundle())
    proofs = copy.deepcopy(bundle["proofs"])
    proofs[0]["previous"] = "g" * 64
    bundle["proofs"] = proofs
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, {})


def test_member_digest_bad_hex_raises():
    bundle = dict(_bundle())
    proofs = copy.deepcopy(bundle["proofs"])
    proofs[0]["digest"] = "a" * 63
    bundle["proofs"] = proofs
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, {})


def test_structurally_invalid_embedded_proof_raises():
    bundle = dict(_bundle())
    proofs = copy.deepcopy(bundle["proofs"])
    del proofs[0]["proof"]["commitment"]
    bundle["proofs"] = proofs
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, {})


def test_embedded_proof_bad_time_raises():
    bundle = dict(_bundle())
    proofs = copy.deepcopy(bundle["proofs"])
    proofs[0]["proof"]["start"] = "not-a-time"
    bundle["proofs"] = proofs
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, {})


def test_embedded_proof_disordered_stages_raise():
    proof = _proof(DT1, DT3)
    forged = dict(proof)
    forged["stages"] = [proof["stages"][1], proof["stages"][0]]
    bundle = {
        "root": "0" * 64,
        "proofs": [
            {
                "id": "a",
                "proof": forged,
                "previous": "0" * 64,
                "digest": "0" * 64,
            }
        ],
    }
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(
            bundle, {"root": "0" * 64, "proof_ids": ["a"]}
        )


# ----------------------------------------------------- expected structural


def test_expected_not_a_dict_raises():
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(_bundle(), [])


def test_expected_wrong_keys_raises():
    bundle = _bundle()
    expected = dict(_expected(bundle))
    expected["commitment"] = bundle["root"]
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, expected)


def test_expected_missing_key_raises():
    bundle = _bundle()
    expected = dict(_expected(bundle))
    del expected["proof_ids"]
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, expected)


def test_expected_root_bad_hex_raises():
    bundle = _bundle()
    expected = dict(_expected(bundle))
    expected["root"] = "0" * 63
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(bundle, expected)


@pytest.mark.parametrize(
    "proof_ids",
    [
        None,
        [],
        ["a", "a"],
        ["", "b"],
        [1, 2],
        "ab",
    ],
)
def test_expected_proof_ids_invalid_raise(proof_ids):
    bundle = _bundle()
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(
            bundle, {"root": bundle["root"], "proof_ids": proof_ids}
        )


def test_basic_validation_completes_before_any_false_comparison():
    # Both structures are illegal; the call must raise rather than return
    # False even though the declared summaries also disagree.
    bundle = dict(_bundle())
    bundle["extra"] = 1
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle(
            bundle, {"root": "f" * 64, "proof_ids": []}
        )


# ---------------------------------------------------------- False cases


def test_wrong_root_in_report_returns_false():
    bundle = dict(_bundle())
    bundle["root"] = "f" * 64
    assert (
        verify_bundle_evolution_checkpoint_bundle(bundle, _expected(_bundle()))
        is False
    )


def test_wrong_expected_root_returns_false():
    bundle = _bundle()
    expected = dict(_expected(bundle))
    expected["root"] = "f" * 64
    assert verify_bundle_evolution_checkpoint_bundle(bundle, expected) is False


def test_broken_member_previous_returns_false():
    bundle = dict(_bundle())
    proofs = copy.deepcopy(bundle["proofs"])
    proofs[1]["previous"] = "f" * 64
    bundle["proofs"] = proofs
    assert (
        verify_bundle_evolution_checkpoint_bundle(bundle, _expected(_bundle()))
        is False
    )


def test_false_member_digest_returns_false():
    bundle = dict(_bundle())
    proofs = copy.deepcopy(bundle["proofs"])
    proofs[0]["digest"] = "f" * 64
    bundle["proofs"] = proofs
    assert (
        verify_bundle_evolution_checkpoint_bundle(bundle, _expected(_bundle()))
        is False
    )


def test_tampered_embedded_proof_returns_false():
    bundle = dict(_bundle())
    proofs = copy.deepcopy(bundle["proofs"])
    proofs[0]["proof"]["commitment"] = "f" * 64
    bundle["proofs"] = proofs
    assert (
        verify_bundle_evolution_checkpoint_bundle(bundle, _expected(_bundle()))
        is False
    )


def test_tampered_embedded_stage_returns_false():
    bundle = dict(_bundle())
    proofs = copy.deepcopy(bundle["proofs"])
    proofs[0]["proof"]["stages"][0]["digest"] = "f" * 64
    bundle["proofs"] = proofs
    assert (
        verify_bundle_evolution_checkpoint_bundle(bundle, _expected(_bundle()))
        is False
    )


def test_tampered_embedded_bundle_summary_returns_false():
    bundle = dict(_bundle())
    proofs = copy.deepcopy(bundle["proofs"])
    proofs[0]["proof"]["stages"][0]["bundle"]["proofs"][0]["digest"] = "f" * 64
    bundle["proofs"] = proofs
    assert (
        verify_bundle_evolution_checkpoint_bundle(bundle, _expected(_bundle()))
        is False
    )


def test_missing_expected_id_returns_false():
    bundle = _bundle()
    ids = [member["id"] for member in bundle["proofs"]]
    expected = {"root": bundle["root"], "proof_ids": ids[:-1]}
    assert verify_bundle_evolution_checkpoint_bundle(bundle, expected) is False


def test_extra_expected_id_returns_false():
    bundle = _bundle()
    ids = [member["id"] for member in bundle["proofs"]]
    expected = {"root": bundle["root"], "proof_ids": ids + ["omega"]}
    assert verify_bundle_evolution_checkpoint_bundle(bundle, expected) is False


def test_wrong_expected_id_returns_false():
    bundle = _bundle()
    expected = {
        "root": bundle["root"],
        "proof_ids": [
            "other" if member["id"] == "alpha" else member["id"]
            for member in bundle["proofs"]
        ],
    }
    assert verify_bundle_evolution_checkpoint_bundle(bundle, expected) is False


def test_false_inputs_do_not_mutate():
    bundle = dict(_bundle())
    proofs = copy.deepcopy(bundle["proofs"])
    proofs[1]["previous"] = "f" * 64
    bundle["proofs"] = proofs
    snapshot = copy.deepcopy(bundle)
    assert (
        verify_bundle_evolution_checkpoint_bundle(bundle, _expected(_bundle()))
        is False
    )
    assert bundle == snapshot


# ---------------------------------------------------------------- endpoint


def test_http_verify_genuine_returns_true_compact_json():
    bundle = _bundle()
    response = client.post(
        VERIFY_PATH,
        json={
            "report": bundle,
            "expected": {"root": bundle["root"], "proof_ids": ["伽马", "alpha", "beta"]},
        },
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'


def test_http_verify_false_summary_returns_200_false():
    bundle = dict(_bundle())
    bundle["root"] = "f" * 64
    response = client.post(
        VERIFY_PATH, json={"report": bundle, "expected": _expected(_bundle())}
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":false}'


def test_http_verify_works_without_history(monkeypatch):
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


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b'"x"',
        b"null",
        b"{}",
        b'{"report": null}',
        b'{"report": {}, "expected": {}}',
        b'{"report": {}, "expected": {}, "extra": 1}',
        b'{"report": {}, "expected": {}, "proof": {}}',
        b'{"report": {"root": "0", "proofs": []}, "expected": {}}',
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
