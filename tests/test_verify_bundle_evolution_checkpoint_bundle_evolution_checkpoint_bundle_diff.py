import copy
import functools
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

import test_bundle_evolution_checkpoint_bundle_evolution_checkpoint as fx
from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle as bind,
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff as diff,
    verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff as vdiff,
)

client = TestClient(app)

VERIFY_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/"
    "checkpoint/bundle/diff/verify"
)

# Delivery-stage window proofs are four credential levels deep, so build the
# canonical reports once per module; tests mutate deep copies only. X is the
# head window, Y a carried-diff window; both are single-stage windows.


@functools.lru_cache(maxsize=1)
def _x():
    return fx._proof(fx.ET1, fx.ET1)


@functools.lru_cache(maxsize=1)
def _y():
    return fx._proof(fx.ET2, fx.ET2)


@functools.lru_cache(maxsize=1)
def _b1():
    return bind([{"id": "a", "proof": _x()}])


@functools.lru_cache(maxsize=1)
def _b2():
    # Main after: a changed X->Y, b and CJK 中 added with the same proof X
    # (equal proofs share one normalized node within a single call).
    return bind(
        [
            {"id": "a", "proof": _y()},
            {"id": "b", "proof": _x()},
            {"id": "中", "proof": _x()},
        ]
    )


@functools.lru_cache(maxsize=1)
def _b3():
    # Shared two members; against _b4 only c is added (a and b unchanged).
    return bind(
        [
            {"id": "a", "proof": _x()},
            {"id": "b", "proof": _y()},
        ]
    )


@functools.lru_cache(maxsize=1)
def _b4():
    return bind(
        [
            {"id": "a", "proof": _x()},
            {"id": "b", "proof": _y()},
            {"id": "c", "proof": _x()},
        ]
    )


@functools.lru_cache(maxsize=1)
def _main_report():
    return diff(_b1(), _b2())


@functools.lru_cache(maxsize=1)
def _added_only_report():
    return diff(_b3(), _b4())


def _report():
    return copy.deepcopy(_main_report())


def _added_only():
    return copy.deepcopy(_added_only_report())


def _expected(report):
    return {
        "before_root": report["before_root"],
        "after_root": report["after_root"],
        "before_ids": sorted(m["id"] for m in report["before"]["proofs"]),
        "after_ids": sorted(m["id"] for m in report["after"]["proofs"]),
        "digest": report["digest"],
    }


def _redigest(report):
    payload = {
        "before_root": report["before_root"],
        "after_root": report["after_root"],
        "before": report["before"],
        "after": report["after"],
        "changes": report["changes"],
    }
    report["digest"] = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


# ----------------------------------------------------------------- happy path


def test_generated_report_verifies():
    report = _main_report()
    assert vdiff(report, _expected(report)) is True


def test_identical_bundles_report_verifies():
    report = diff(_b1(), _b1())
    assert vdiff(report, _expected(report)) is True


def test_expected_id_arrays_accept_arbitrary_order():
    report = _main_report()
    expected = _expected(report)
    expected["before_ids"] = list(reversed(expected["before_ids"]))
    expected["after_ids"] = list(reversed(expected["after_ids"]))
    assert vdiff(report, expected) is True


def test_does_not_mutate_inputs():
    report = _report()
    expected = _expected(report)
    report_snapshot = copy.deepcopy(report)
    expected_snapshot = copy.deepcopy(expected)
    vdiff(report, expected)
    assert report == report_snapshot
    assert expected == expected_snapshot


# --------------------------------------------------------- false => False


def test_false_diff_digest_returns_false():
    report = _report()
    report["digest"] = "f" * 64
    assert vdiff(report, _expected(report)) is False


def test_false_before_root_returns_false():
    report = _report()
    expected = _expected(report)
    report["before_root"] = report["before"]["root"] = "f" * 64
    expected["before_root"] = "f" * 64
    assert vdiff(report, expected) is False


def test_false_after_root_returns_false():
    report = _report()
    expected = _expected(report)
    report["after_root"] = report["after"]["root"] = "f" * 64
    expected["after_root"] = "f" * 64
    assert vdiff(report, expected) is False


def test_false_member_digest_returns_false():
    report = _report()
    report["before"]["proofs"][0]["digest"] = "e" * 64
    _redigest(report)
    assert vdiff(report, _expected(report)) is False


def test_broken_member_chain_link_returns_false():
    report = _report()
    report["after"]["proofs"][1]["previous"] = "e" * 64
    _redigest(report)
    assert vdiff(report, _expected(report)) is False


def test_false_window_proof_commitment_returns_false():
    report = _report()
    report["after"]["proofs"][0]["proof"]["commitment"] = "e" * 64
    _redigest(report)
    assert vdiff(report, _expected(report)) is False


def test_tampered_change_side_proof_returns_false():
    report = _report()
    changed = next(c for c in report["changes"] if c["kind"] == "changed")
    changed["after"]["commitment"] = "e" * 64
    _redigest(report)
    assert vdiff(report, _expected(report)) is False


def test_expected_digest_mismatch_returns_false():
    report = _report()
    expected = _expected(report)
    expected["digest"] = "f" * 64
    assert vdiff(report, expected) is False


def test_expected_root_mismatch_returns_false():
    report = _report()
    expected = _expected(report)
    expected["after_root"] = "f" * 64
    assert vdiff(report, expected) is False


def test_expected_id_set_mismatch_returns_false():
    report = _report()
    expected = _expected(report)
    expected["after_ids"].append("zzz")
    assert vdiff(report, expected) is False


def test_missing_expected_change_returns_false():
    # Structurally legal list (every listed change is valid) but it omits the
    # changed a member.
    report = _report()
    report["changes"] = [c for c in report["changes"] if c["id"] != "a"]
    _redigest(report)
    assert vdiff(report, _expected(report)) is False


def test_extra_unchanged_member_listed_returns_false():
    # Structurally legal list (a exists unchanged in both bundles and both
    # sides reproduce the bundle members) but it lists a as changed; the
    # reconstructed full change set rejects it with False after validation.
    report = _added_only()
    a_before = report["before"]["proofs"][0]["proof"]
    a_after = report["after"]["proofs"][0]["proof"]
    report["changes"] = [
        {
            "id": "a",
            "kind": "changed",
            "before": copy.deepcopy(a_before),
            "after": copy.deepcopy(a_after),
        }
    ] + report["changes"]
    _redigest(report)
    assert vdiff(report, _expected(report)) is False


# ------------------------------------------------------------- ValueError


@pytest.mark.parametrize(
    "report",
    [
        None,
        "x",
        [],
        {},
        {"root": "0" * 64},
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before": {},
            "after": {},
            "changes": [],
            "digest": "0" * 64,
        },
    ],
)
def test_bad_report_shape_raises(report):
    with pytest.raises(ValueError):
        vdiff(
            report,
            {
                "before_root": "0" * 64,
                "after_root": "0" * 64,
                "before_ids": ["a"],
                "after_ids": ["a"],
                "digest": "0" * 64,
            },
        )


def test_bad_expected_key_set_raises():
    with pytest.raises(ValueError):
        vdiff(_main_report(), {"before_root": _main_report()["before_root"]})


def test_duplicate_change_id_raises():
    report = _report()
    change = copy.deepcopy(report["changes"][0])
    report["changes"] = [change, copy.deepcopy(change)]
    with pytest.raises(ValueError):
        vdiff(report, _expected(report))


def test_unsorted_change_ids_raise():
    report = _report()
    report["changes"] = list(reversed(report["changes"]))
    with pytest.raises(ValueError):
        vdiff(report, _expected(report))


def test_bad_kind_raises():
    report = _report()
    report["changes"][0]["kind"] = "updated"
    with pytest.raises(ValueError):
        vdiff(report, _expected(report))


def test_added_with_non_null_before_raises():
    report = _report()
    added = next(c for c in report["changes"] if c["kind"] == "added")
    added["before"] = copy.deepcopy(added["after"])
    with pytest.raises(ValueError):
        vdiff(report, _expected(report))


def test_added_id_missing_from_after_bundle_raises():
    report = _report()
    added = next(c for c in report["changes"] if c["kind"] == "added")
    added["id"] = "ghost"
    with pytest.raises(ValueError):
        vdiff(report, _expected(report))


def test_change_side_not_equal_to_bundle_member_raises():
    report = _report()
    changed = next(c for c in report["changes"] if c["kind"] == "changed")
    # Structurally legal window (start <= end, all stages intact) whose
    # semantic projection no longer equals the before bundle's member.
    changed["before"]["end"] = fx.ET2
    with pytest.raises(ValueError):
        vdiff(report, _expected(report))


def test_root_not_matching_embedded_bundle_raises():
    report = _report()
    report["before_root"] = "f" * 64
    with pytest.raises(ValueError):
        vdiff(report, _expected(report))


@pytest.mark.parametrize(
    "expected",
    [
        None,
        "x",
        {},
        {"before_root": "0" * 64},
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before_ids": ["a"],
            "after_ids": ["a"],
            "digest": "nope",
        },
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before_ids": [],
            "after_ids": ["a"],
            "digest": "0" * 64,
        },
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before_ids": ["a", "a"],
            "after_ids": ["a"],
            "digest": "0" * 64,
        },
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before_ids": ["a"],
            "after_ids": ["a"],
            "digest": "0" * 64,
            "extra": 1,
        },
    ],
)
def test_bad_expected_shape_raises(expected):
    with pytest.raises(ValueError):
        vdiff(_main_report(), expected)


def test_second_input_still_validated_when_first_is_false():
    # A format-valid but false report must not short-circuit expected checks.
    report = _report()
    report["digest"] = "f" * 64
    with pytest.raises(ValueError):
        vdiff(report, {"before_root": "0" * 64})


# ---------------------------------------------------------------- endpoint


def test_http_verify_true_returns_compact_json():
    response = client.post(
        VERIFY_PATH,
        json={"report": _report(), "expected": _expected(_main_report())},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_verify_false_is_still_200():
    expected = _expected(_main_report())
    expected["digest"] = "f" * 64
    response = client.post(
        VERIFY_PATH, json={"report": _report(), "expected": expected}
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":false}'


def test_http_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        VERIFY_PATH,
        json={"report": _report(), "expected": _expected(_main_report())},
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
        b'{"proof": {}, "expected": {}}',
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


def test_http_value_error_in_function_is_422():
    response = client.post(
        VERIFY_PATH,
        json={"report": {"root": "0" * 64}, "expected": _expected(_main_report())},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
