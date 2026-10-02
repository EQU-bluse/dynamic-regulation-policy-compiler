import copy
import functools
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

import test_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff as fx
from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution as evolve,
    verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution as verify,
)

client = TestClient(app)

FT1 = "2022-05-01T00:00:00Z"
FT2 = "2022-06-01T00:00:00Z"
FT3 = "2022-07-01T00:00:00Z"

EVOLUTION_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/"
    "checkpoint/bundle/diff/evolution"
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
    assert verify(report, _expected(report)) is True


def test_verifies_single_stage_evolution():
    report = evolve([{"at": FT1, "bundle": _bundle_one()}])
    assert verify(report, _expected(report)) is True


def test_does_not_mutate_inputs():
    report = _evolution()
    expected = _expected(report)
    report_snapshot = copy.deepcopy(report)
    expected_snapshot = copy.deepcopy(expected)
    verify(report, expected)
    assert report == report_snapshot
    assert expected == expected_snapshot


# -------------------------------------------------------- False, not error


def test_false_stage_digest_returns_false():
    report = _evolution()
    report["stages"][1]["digest"] = "f" * 64
    assert verify(report, _expected(report)) is False


def test_false_stage_previous_returns_false():
    report = _evolution()
    report["stages"][2]["previous"] = "f" * 64
    assert verify(report, _expected(report)) is False


def test_false_root_returns_false():
    report = _evolution()
    report["root"] = "f" * 64
    assert verify(report, _expected(report)) is False


def test_false_bundle_root_in_report_returns_false():
    # A single-stage evolution has no adjacent diff, so a format-valid but
    # false bundle root survives structural validation and must be caught by
    # the recomputation phase as False rather than ValueError.
    report = evolve([{"at": FT1, "bundle": _bundle_one()}])
    report["stages"][0]["bundle"]["root"] = "f" * 64
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
            {"at": FT1, "bundle_root": "f" * 64, "diff_digest": None}
        ],
    }
    assert verify(report, expected) is False


def test_false_diff_digest_returns_false():
    report = _evolution()
    report["stages"][1]["diff"]["digest"] = "f" * 64
    assert verify(report, _expected(report)) is False


def test_incomplete_change_list_returns_false():
    # A structurally legal change list that drops an expected change no longer
    # equals the freshly recomputed adjacent diff, so it yields False.
    report = _evolution()
    report["stages"][1]["diff"]["changes"] = report["stages"][1]["diff"][
        "changes"
    ][:1]
    assert verify(report, _expected(report)) is False


def test_false_member_chain_in_embedded_bundle_returns_false():
    report = _evolution()
    report["stages"][0]["bundle"]["proofs"][0]["previous"] = "f" * 64
    assert verify(report, _expected(report)) is False


def test_wrong_expected_root_returns_false():
    report = _evolution()
    expected = _expected(report)
    expected["root"] = "f" * 64
    assert verify(report, expected) is False


def test_wrong_expected_stage_bundle_root_returns_false():
    report = _evolution()
    expected = _expected(report)
    expected["stages"][1]["bundle_root"] = "f" * 64
    assert verify(report, expected) is False


def test_wrong_expected_diff_digest_returns_false():
    report = _evolution()
    expected = _expected(report)
    expected["stages"][1]["diff_digest"] = "f" * 64
    assert verify(report, expected) is False


def test_wrong_expected_at_returns_false():
    report = _evolution()
    expected = _expected(report)
    expected["stages"][1]["at"] = "2022-06-15T00:00:00Z"
    assert verify(report, expected) is False


def test_expected_stage_count_mismatch_returns_false():
    report = _evolution()
    expected = _expected(report)
    expected["stages"] = expected["stages"][:2]
    assert verify(report, expected) is False


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
        verify(report, _expected(good))


def test_bad_root_format_raises():
    report = _evolution()
    report["root"] = "ABC"
    with pytest.raises(ValueError):
        verify(report, _expected(_evolution()))


def test_non_increasing_stage_at_raises():
    report = _evolution()
    report["stages"][1]["at"] = FT1
    with pytest.raises(ValueError):
        verify(report, _expected(_evolution()))


def test_first_stage_diff_must_be_null():
    report = _evolution()
    report["stages"][0]["diff"] = report["stages"][1]["diff"]
    with pytest.raises(ValueError):
        verify(report, _expected(_evolution()))


def test_later_stage_diff_must_not_be_null():
    report = _evolution()
    report["stages"][1]["diff"] = None
    with pytest.raises(ValueError):
        verify(report, _expected(_evolution()))


def test_diff_between_wrong_neighbors_raises():
    report = _evolution()
    report["stages"][1]["bundle"] = copy.deepcopy(report["stages"][2]["bundle"])
    with pytest.raises(ValueError):
        verify(report, _expected(_evolution()))


def test_malformed_nested_bundle_raises():
    report = _evolution()
    report["stages"][0]["bundle"] = {"root": "0" * 64}
    with pytest.raises(ValueError):
        verify(report, _expected(_evolution()))


def test_structurally_invalid_embedded_proof_raises():
    report = _evolution()
    report["stages"][0]["bundle"]["proofs"][0]["proof"] = {"start": FT1}
    with pytest.raises(ValueError):
        verify(report, _expected(_evolution()))


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
        {"root": "0" * 64, "stages": [{"at": FT1}]},
        {"root": "0" * 64, "stages": [{"bundle_root": "0" * 64}]},
        {
            "root": "0" * 64,
            "stages": [
                {"at": FT1, "bundle_root": "0" * 64, "diff_digest": None, "x": 1}
            ],
        },
        {"root": "0" * 64, "stages": "x"},
        {
            "root": "0" * 64,
            "stages": [
                {"at": FT1, "bundle_root": "0" * 64, "diff_digest": None},
                {"at": FT2, "bundle_root": "0" * 64, "diff_digest": None},
            ],
        },
    ],
)
def test_bad_expected_shape_raises(expected):
    report = _evolution()
    with pytest.raises(ValueError):
        verify(report, expected)


def test_expected_non_increasing_at_raises():
    report = _evolution()
    expected = _expected(report)
    expected["stages"][2]["at"] = FT2
    with pytest.raises(ValueError):
        verify(report, expected)


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
