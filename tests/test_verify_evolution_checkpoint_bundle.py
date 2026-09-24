import copy

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    evolution_checkpoint,
    evolution_checkpoint_bundle,
    matrix_bundle_evolution,
    verify_evolution_checkpoint_bundle,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"
AT1 = "2021-05-01T00:00:00Z"
AT2 = "2021-06-01T00:00:00Z"
AT3 = "2021-07-01T00:00:00Z"
GENESIS = "0" * 64


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


def _evolution():
    return matrix_bundle_evolution(
        [
            {"at": AT1, "bundle": _bundle_one()},
            {"at": AT2, "bundle": _bundle_two()},
            {"at": AT3, "bundle": _bundle_three()},
        ]
    )


def _bundle():
    return evolution_checkpoint_bundle(
        [
            {"id": "beta", "proof": evolution_checkpoint(_evolution(), AT2, AT3)},
            {"id": "alpha", "proof": evolution_checkpoint(_evolution(), AT1, AT2)},
            {"id": "伽马", "proof": evolution_checkpoint(_evolution(), AT3, AT3)},
        ]
    )


def _expected(report):
    return {
        "root": report["root"],
        "proof_ids": [member["id"] for member in report["proofs"]],
    }


# ----------------------------------------------------------------- genuine


def test_genuine_bundle_is_valid():
    report = _bundle()
    assert verify_evolution_checkpoint_bundle(report, _expected(report)) is True


def test_expected_proof_ids_order_is_arbitrary():
    report = _bundle()
    expected = _expected(report)
    expected["proof_ids"] = list(reversed(expected["proof_ids"]))
    assert verify_evolution_checkpoint_bundle(report, expected) is True


def test_single_member_bundle_is_valid():
    report = evolution_checkpoint_bundle(
        [{"id": "only", "proof": evolution_checkpoint(_evolution(), AT1, AT1)}]
    )
    assert verify_evolution_checkpoint_bundle(report, _expected(report)) is True


def test_inputs_are_not_mutated():
    report = _bundle()
    expected = _expected(report)
    report_snapshot = copy.deepcopy(report)
    expected_snapshot = copy.deepcopy(expected)
    verify_evolution_checkpoint_bundle(report, expected)
    assert report == report_snapshot
    assert expected == expected_snapshot


# ------------------------------------------------------------------ forgery


def test_forged_member_digest_is_false():
    report = _bundle()
    report["proofs"][1]["digest"] = "f" * 64
    assert verify_evolution_checkpoint_bundle(report, _expected(report)) is False


def test_broken_previous_link_is_false():
    report = _bundle()
    report["proofs"][1]["previous"] = "f" * 64
    assert verify_evolution_checkpoint_bundle(report, _expected(report)) is False


def test_wrong_root_is_false():
    report = _bundle()
    report["root"] = "f" * 64
    expected = _expected(report)
    assert verify_evolution_checkpoint_bundle(report, expected) is False


def test_wrong_expected_root_is_false():
    report = _bundle()
    expected = _expected(report)
    expected["root"] = "f" * 64
    assert verify_evolution_checkpoint_bundle(report, expected) is False


def test_expected_proof_ids_mismatch_is_false():
    report = _bundle()
    expected = _expected(report)
    expected["proof_ids"] = ["alpha", "beta", "other"]
    assert verify_evolution_checkpoint_bundle(report, expected) is False
    expected["proof_ids"] = ["alpha", "beta"]
    assert verify_evolution_checkpoint_bundle(report, expected) is False


def test_forged_proof_stage_digest_is_false():
    report = _bundle()
    report["proofs"][0]["proof"]["stages"][0]["digest"] = "f" * 64
    assert verify_evolution_checkpoint_bundle(report, _expected(report)) is False


def test_forged_proof_content_raises():
    report = _bundle()
    report["proofs"][0]["proof"]["stages"][0]["bundle"]["reports"][0]["report"][
        "matrix"
    ]["points"][0]["cases"][0]["decision"] = "forged"
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(report, _expected(report))


def test_false_declared_sub_digest_is_false():
    report = _bundle()
    report["proofs"][0]["proof"]["stages"][0]["bundle"]["reports"][0]["report"][
        "digest"
    ] = "f" * 64
    assert verify_evolution_checkpoint_bundle(report, _expected(report)) is False


def test_swapped_member_proofs_are_false():
    report = _bundle()
    first, second = report["proofs"][0], report["proofs"][1]
    first["proof"], second["proof"] = second["proof"], first["proof"]
    assert verify_evolution_checkpoint_bundle(report, _expected(report)) is False


# --------------------------------------------------------------- structural


@pytest.mark.parametrize(
    "report",
    [
        None,
        [],
        "x",
        {},
        {"root": "0" * 64},
        {"proofs": []},
        {"root": "0" * 64, "proofs": [], "extra": 1},
        {"root": "not-hex", "proofs": [{"id": "a"}]},
        {"root": "0" * 64, "proofs": None},
        {"root": "0" * 64, "proofs": []},
        {"root": "0" * 64, "proofs": [{"proof": {}, "previous": "0" * 64}]},
        {
            "root": "0" * 64,
            "proofs": [{"id": "a", "proof": {}, "previous": "0" * 64}],
        },
        {
            "root": "0" * 64,
            "proofs": [
                {
                    "id": "a",
                    "proof": {},
                    "previous": "0" * 64,
                    "digest": "0" * 64,
                    "extra": 1,
                }
            ],
        },
    ],
)
def test_structurally_invalid_reports_raise(report):
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(report, _expected(_bundle()))


def test_unordered_members_raise():
    report = _bundle()
    report["proofs"] = list(reversed(report["proofs"]))
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(report, _expected(report))


def test_duplicate_member_ids_raise():
    report = _bundle()
    duplicate = copy.deepcopy(report["proofs"][0])
    report["proofs"][1] = duplicate
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(report, _expected(report))


def test_bad_member_digest_format_raises():
    report = _bundle()
    report["proofs"][0]["digest"] = "not-hex"
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(report, _expected(report))


def test_structurally_invalid_proof_raises():
    report = _bundle()
    report["proofs"][0]["proof"] = {"root": "0" * 64}
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(report, _expected(report))


@pytest.mark.parametrize(
    "expected",
    [
        None,
        [],
        {},
        {"root": "0" * 64},
        {"proof_ids": ["alpha"]},
        {"root": "0" * 64, "proof_ids": ["alpha"], "extra": 1},
        {"root": "not-hex", "proof_ids": ["alpha"]},
        {"root": "0" * 64, "proof_ids": None},
        {"root": "0" * 64, "proof_ids": []},
        {"root": "0" * 64, "proof_ids": ["alpha", "alpha"]},
        {"root": "0" * 64, "proof_ids": ["alpha", ""]},
        {"root": "0" * 64, "proof_ids": ["alpha", 1]},
    ],
)
def test_invalid_expected_raises(expected):
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(_bundle(), expected)


# ----------------------------------------------------------------- endpoint


def test_http_verify_true():
    report = _bundle()
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'


def test_http_verify_false():
    report = _bundle()
    report["proofs"][0]["digest"] = "f" * 64
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":false}'


def test_http_verify_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    report = _bundle()
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'


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
        b'{"report": {"root": "0"}, "expected": {"root": "0", "proof_ids": []}}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/verify",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
