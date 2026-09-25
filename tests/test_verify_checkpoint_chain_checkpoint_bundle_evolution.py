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
DT1 = "2021-11-01T00:00:00Z"
DT2 = "2021-12-01T00:00:00Z"
DT3 = "2022-01-01T00:00:00Z"

EVOLUTION_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution"
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


def _stage_inputs():
    return [
        {"at": DT1, "bundle": _bundle_one()},
        {"at": DT2, "bundle": _bundle_two()},
        {"at": DT3, "bundle": _bundle_three()},
    ]


def _evolution():
    return checkpoint_chain_checkpoint_bundle_evolution(_stage_inputs())


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


# ---------------------------------------------------------------- genuine


def test_verifies_genuine_evolution():
    report = _evolution()
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(report)
        )
        is True
    )


def test_verifies_single_stage_evolution():
    report = checkpoint_chain_checkpoint_bundle_evolution(
        [{"at": DT1, "bundle": _bundle_one()}]
    )
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(report)
        )
        is True
    )


def test_does_not_mutate_inputs():
    report = _evolution()
    expected = _expected(report)
    report_snapshot = copy.deepcopy(report)
    expected_snapshot = copy.deepcopy(expected)
    verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
    assert report == report_snapshot
    assert expected == expected_snapshot


# -------------------------------------------------------- False, not error


def test_false_stage_digest_returns_false():
    report = _evolution()
    report["stages"][1]["digest"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(report)
        )
        is False
    )


def test_false_stage_previous_returns_false():
    report = _evolution()
    report["stages"][2]["previous"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(report)
        )
        is False
    )


def test_false_root_returns_false():
    report = _evolution()
    report["root"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(report)
        )
        is False
    )


def test_false_bundle_root_in_report_returns_false():
    # A single-stage evolution has no adjacent diff, so a format-valid but
    # false bundle root survives structural validation and must be caught by
    # the recomputation phase as False rather than ValueError.
    report = checkpoint_chain_checkpoint_bundle_evolution(
        [{"at": DT1, "bundle": _bundle_one()}]
    )
    report["stages"][0]["bundle"]["root"] = "f" * 64
    import hashlib

    payload = {
        "at": report["stages"][0]["at"],
        "bundle": report["stages"][0]["bundle"],
        "diff": None,
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    report["stages"][0]["digest"] = hashlib.sha256(
        ("0" * 64).encode("ascii") + canonical.encode("utf-8")
    ).hexdigest()
    report["root"] = report["stages"][0]["digest"]
    expected = {
        "root": report["root"],
        "stages": [
            {"at": DT1, "bundle_root": "f" * 64, "diff_digest": None}
        ],
    }
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_false_diff_digest_returns_false():
    report = _evolution()
    report["stages"][1]["diff"]["digest"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(report)
        )
        is False
    )


def test_incomplete_change_list_returns_false():
    # A structurally legal change list that drops an expected change no longer
    # equals the freshly recomputed adjacent diff, so it yields False.
    report = _evolution()
    report["stages"][1]["diff"]["changes"] = report["stages"][1]["diff"][
        "changes"
    ][:1]
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(report)
        )
        is False
    )


def test_wrong_expected_root_returns_false():
    report = _evolution()
    expected = _expected(report)
    expected["root"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_wrong_expected_stage_bundle_root_returns_false():
    report = _evolution()
    expected = _expected(report)
    expected["stages"][1]["bundle_root"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_wrong_expected_diff_digest_returns_false():
    report = _evolution()
    expected = _expected(report)
    expected["stages"][1]["diff_digest"] = "f" * 64
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_wrong_expected_at_returns_false():
    report = _evolution()
    expected = _expected(report)
    expected["stages"][1]["at"] = "2021-12-15T00:00:00Z"
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


def test_expected_stage_count_mismatch_returns_false():
    report = _evolution()
    expected = _expected(report)
    expected["stages"] = expected["stages"][:2]
    assert (
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)
        is False
    )


# ---------------------------------------------------------------- ValueError


@pytest.mark.parametrize(
    "report",
    [
        None,
        "x",
        [],
        {},
        {"root": "0" * 64},
        {"stages": []},
        {"root": "0" * 64, "stages": []},
        {"root": "0" * 64, "stages": [{}]},
    ],
)
def test_bad_report_shape_raises(report):
    good = _evolution()
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(good)
        )


def test_bad_root_format_raises():
    report = copy.deepcopy(_evolution())
    report["root"] = "ABC"
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_evolution())
        )


def test_non_increasing_stage_at_raises():
    report = copy.deepcopy(_evolution())
    report["stages"][1]["at"] = DT1
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_evolution())
        )


def test_first_stage_diff_must_be_null():
    report = copy.deepcopy(_evolution())
    report["stages"][0]["diff"] = report["stages"][1]["diff"]
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_evolution())
        )


def test_later_stage_diff_must_not_be_null():
    report = copy.deepcopy(_evolution())
    report["stages"][1]["diff"] = None
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_evolution())
        )


def test_diff_between_wrong_neighbors_raises():
    report = copy.deepcopy(_evolution())
    report["stages"][1]["bundle"] = copy.deepcopy(report["stages"][2]["bundle"])
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_evolution())
        )


def test_malformed_nested_bundle_raises():
    report = copy.deepcopy(_evolution())
    report["stages"][0]["bundle"] = {"root": "0" * 64}
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(
            report, _expected(_evolution())
        )


@pytest.mark.parametrize(
    "expected",
    [
        None,
        "x",
        {},
        {"root": "0" * 64},
        {"stages": []},
        {"root": "0" * 64, "stages": []},
        {"root": "0" * 64, "stages": [{}]},
        {"root": "0" * 64, "stages": [{"at": DT1}]},
        {"root": "0" * 64, "stages": [{"bundle_root": "0" * 64}]},
        {
            "root": "0" * 64,
            "stages": [
                {"at": DT1, "bundle_root": "0" * 64, "diff_digest": None, "x": 1}
            ],
        },
        {"root": "0" * 64, "stages": "x"},
        {
            "root": "0" * 64,
            "stages": [
                {"at": DT1, "bundle_root": "0" * 64, "diff_digest": None},
                {"at": DT2, "bundle_root": "0" * 64, "diff_digest": None},
            ],
        },
    ],
)
def test_bad_expected_shape_raises(expected):
    report = _evolution()
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)


def test_expected_non_increasing_at_raises():
    report = _evolution()
    expected = _expected(report)
    expected["stages"][2]["at"] = DT2
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_evolution(report, expected)


# ---------------------------------------------------------------- endpoint


def test_http_verify_genuine_is_true():
    report = _evolution()
    response = client.post(
        EVOLUTION_PATH + "/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_verify_false_summary_is_200_false():
    report = _evolution()
    report["root"] = "f" * 64
    response = client.post(
        EVOLUTION_PATH + "/verify",
        json={"report": report, "expected": _expected(_evolution())},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":false}'


def test_http_verify_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    report = _evolution()
    response = client.post(
        EVOLUTION_PATH + "/verify",
        json={"report": report, "expected": _expected(report)},
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
        b'{"report": {}, "expected": {}, "extra": 1}',
        b'{"r": {}, "expected": {}}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        EVOLUTION_PATH + "/verify",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_value_error_in_function_is_422():
    report = _evolution()
    response = client.post(
        EVOLUTION_PATH + "/verify",
        json={
            "report": {"root": "0" * 64, "stages": []},
            "expected": _expected(report),
        },
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
