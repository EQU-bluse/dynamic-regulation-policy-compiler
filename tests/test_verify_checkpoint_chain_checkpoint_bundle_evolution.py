import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    checkpoint_chain,
    checkpoint_chain_checkpoint,
    checkpoint_chain_checkpoint_bundle,
    checkpoint_chain_checkpoint_bundle_evolution,
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    evolution_checkpoint,
    evolution_checkpoint_bundle,
    matrix_bundle_evolution,
    verify_checkpoint_chain_checkpoint_bundle_evolution,
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
E1 = "2021-11-01T00:00:00Z"
E2 = "2021-12-01T00:00:00Z"
E3 = "2022-01-01T00:00:00Z"

VERIFY_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution/verify"
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
        [{"id": "alpha", "proof": _window_proof(RT1, RT1)}]
    )


def _report():
    return checkpoint_chain_checkpoint_bundle_evolution(
        [
            {"at": E1, "bundle": _bundle_one()},
            {"at": E2, "bundle": _bundle_two()},
            {"at": E3, "bundle": _bundle_three()},
        ]
    )


def _expected(report):
    return {
        "root": report["root"],
        "stages": [
            {
                "at": stage["at"],
                "bundle_root": stage["bundle"]["root"],
                "diff_digest": (
                    None if stage["diff"] is None else stage["diff"]["digest"]
                ),
            }
            for stage in report["stages"]
        ],
    }


# ------------------------------------------------------------------ genuine


def test_verifies_genuine_report():
    report = _report()
    assert verify_checkpoint_chain_checkpoint_bundle_evolution(
        report, _expected(report)
    ) is True


def test_verifies_single_stage_report():
    report = checkpoint_chain_checkpoint_bundle_evolution(
        [{"at": E1, "bundle": _bundle_one()}]
    )
    assert verify_checkpoint_chain_checkpoint_bundle_evolution(
        report, _expected(report)
    ) is True


def test_verifies_report_with_identical_adjacent_bundles():
    report = checkpoint_chain_checkpoint_bundle_evolution(
        [
            {"at": E1, "bundle": _bundle_one()},
            {"at": E2, "bundle": _bundle_one()},
        ]
    )
    assert verify_checkpoint_chain_checkpoint_bundle_evolution(
        report, _expected(report)
    ) is True


def test_does_not_mutate_inputs():
    report = _report()
    expected = _expected(report)
    snapshot = (copy.deepcopy(report), copy.deepcopy(expected))
    verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
    assert (report, expected) == snapshot


# ------------------------------------------------------------------ tamper


def test_forged_root_value_returns_false():
    report = _report()
    expected = _expected(report)
    report["root"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_forged_stage_digest_returns_false():
    report = _report()
    expected = _expected(report)
    report["stages"][1]["digest"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_forged_stage_previous_returns_false():
    report = _report()
    expected = _expected(report)
    report["stages"][2]["previous"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_forged_bundle_member_digest_returns_false():
    report = _report()
    expected = _expected(report)
    report["stages"][0]["bundle"]["proofs"][0]["digest"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_forged_embedded_window_proof_returns_false():
    report = _report()
    expected = _expected(report)
    report["stages"][0]["bundle"]["proofs"][0]["proof"]["commitment"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_forged_diff_digest_returns_false():
    report = _report()
    expected = _expected(report)
    report["stages"][1]["diff"]["digest"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_incomplete_change_list_returns_false():
    report = _report()
    expected = _expected(report)
    # Dropping a change keeps the list structurally legal but incomplete.
    report["stages"][1]["diff"]["changes"] = []
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_wrong_expected_root_returns_false():
    report = _report()
    expected = _expected(report)
    expected["root"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_wrong_expected_bundle_root_returns_false():
    report = _report()
    expected = _expected(report)
    expected["stages"][0]["bundle_root"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_wrong_expected_diff_digest_returns_false():
    report = _report()
    expected = _expected(report)
    expected["stages"][1]["diff_digest"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_wrong_expected_at_returns_false():
    report = _report()
    expected = _expected(report)
    expected["stages"][1]["at"] = "2021-11-15T00:00:00Z"
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_expected_stage_count_mismatch_returns_false():
    report = _report()
    expected = _expected(report)
    expected["stages"] = expected["stages"][:2]
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


# --------------------------------------------------------------- structural


@pytest.mark.parametrize(
    "report",
    [
        None,
        "x",
        [],
        {},
        {"root": "f" * 64},
        {"stages": []},
        {"root": "f" * 64, "stages": [], "extra": 1},
        {"root": "bad", "stages": [{"x": 1}]},
        {"root": "f" * 64, "stages": []},
        {"root": "f" * 64, "stages": None},
    ],
)
def test_invalid_report_shape_raises(report):
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, {"root": "f" * 64, "stages": [{"x": 1}]}
        )


def test_report_stage_key_set_raises():
    report = _report()
    del report["stages"][0]["diff"]
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_report())
        )


def test_report_stage_extra_key_raises():
    report = _report()
    report["stages"][0]["extra"] = 1
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_report())
        )


def test_report_non_hex_digest_raises():
    report = _report()
    report["stages"][0]["digest"] = "z" * 64
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_report())
        )


def test_report_non_increasing_stage_times_raise():
    report = _report()
    report["stages"][2]["at"] = E2
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_report())
        )


def test_report_first_stage_diff_not_null_raises():
    report = _report()
    report["stages"][0]["diff"] = report["stages"][1]["diff"]
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_report())
        )


def test_report_diff_before_root_mismatch_raises():
    report = _report()
    report["stages"][1]["diff"]["before_root"] = "f" * 64
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_report())
        )


def test_report_diff_after_root_mismatch_raises():
    report = _report()
    report["stages"][1]["diff"]["after_root"] = "f" * 64
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_report())
        )


def test_report_diff_before_not_reproducing_bundle_raises():
    report = _report()
    # Swap in the other stage's embedded before-bundle: structurally valid
    # but it does not reproduce the preceding stage bundle.
    report["stages"][1]["diff"]["before"] = copy.deepcopy(
        report["stages"][2]["diff"]["before"]
    )
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_report())
        )


def test_report_diff_change_side_not_matching_member_raises():
    report = _report()
    change = report["stages"][1]["diff"]["changes"][0]
    side = "before" if change["before"] is not None else "after"
    # A semantic change (not a mere summary): the side no longer reproduces
    # the corresponding bundle member's window proof.
    change[side]["stages"][0]["at"] = AT1
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_report())
        )


@pytest.mark.parametrize(
    "expected",
    [
        None,
        "x",
        [],
        {},
        {"root": "f" * 64},
        {"stages": []},
        {"root": "bad", "stages": []},
        {"root": "f" * 64, "stages": [], "extra": 1},
        {"root": "f" * 64, "stages": None},
    ],
)
def test_invalid_expected_shape_raises(expected):
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(_report(), expected)


def test_expected_stage_key_set_raises():
    report = _report()
    expected = _expected(report)
    del expected["stages"][0]["diff_digest"]
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)


def test_expected_stage_extra_key_raises():
    report = _report()
    expected = _expected(report)
    expected["stages"][0]["extra"] = 1
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)


def test_expected_first_diff_digest_not_null_raises():
    report = _report()
    expected = _expected(report)
    expected["stages"][0]["diff_digest"] = "f" * 64
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)


def test_expected_later_diff_digest_null_raises():
    report = _report()
    expected = _expected(report)
    expected["stages"][1]["diff_digest"] = None
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)


def test_expected_non_increasing_times_raise():
    report = _report()
    expected = _expected(report)
    expected["stages"][2]["at"] = E1
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)


def test_expected_bad_hex_raises():
    report = _report()
    expected = _expected(report)
    expected["stages"][0]["bundle_root"] = "z" * 64
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)


# ----------------------------------------------------------------- endpoint


def test_http_verify_returns_200_true():
    report = _report()
    response = client.post(
        VERIFY_PATH, json={"report": report, "expected": _expected(report)}
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_verify_returns_200_false():
    report = _report()
    expected = _expected(report)
    expected["root"] = "f" * 64
    response = client.post(
        VERIFY_PATH, json={"report": report, "expected": expected}
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":false}'


def test_http_verify_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    report = _report()
    response = client.post(
        VERIFY_PATH, json={"report": report, "expected": _expected(report)}
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
        b'{"report": {}}',
        b'{"expected": {}}',
        b'{"report": {}, "expected": {}, "extra": 1}',
        b'{"report": null, "expected": null}',
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
    report = _report()
    report["stages"][0]["diff"] = report["stages"][1]["diff"]
    response = client.post(
        VERIFY_PATH, json={"report": report, "expected": _expected(_report())}
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
