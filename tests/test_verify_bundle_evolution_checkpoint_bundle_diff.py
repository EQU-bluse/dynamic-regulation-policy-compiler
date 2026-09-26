import copy
import functools
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    bundle_evolution_checkpoint,
    bundle_evolution_checkpoint_bundle,
    bundle_evolution_checkpoint_bundle_diff,
    checkpoint_chain,
    checkpoint_chain_checkpoint,
    checkpoint_chain_checkpoint_bundle,
    checkpoint_chain_checkpoint_bundle_evolution,
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    evolution_checkpoint,
    evolution_checkpoint_bundle,
    matrix_bundle_evolution,
    verify_bundle_evolution_checkpoint_bundle_diff,
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
    "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/verify"
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


@functools.lru_cache(maxsize=1)
def _chain_cached():
    return _chain()


def _chain_window_proof(start, end):
    return checkpoint_chain_checkpoint(_chain_cached(), start, end)


@functools.lru_cache(maxsize=1)
def _delivery_bundle_one_raw():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _chain_window_proof(RT1, RT1)},
            {"id": "beta", "proof": _chain_window_proof(RT2, RT3)},
        ]
    )


@functools.lru_cache(maxsize=1)
def _delivery_bundle_two_raw():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _chain_window_proof(RT1, RT1)},
            {"id": "beta", "proof": _chain_window_proof(RT2, RT2)},
            {"id": "伽马", "proof": _chain_window_proof(RT3, RT3)},
        ]
    )


@functools.lru_cache(maxsize=1)
def _delivery_bundle_three_raw():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _chain_window_proof(RT1, RT2)},
            {"id": "伽马", "proof": _chain_window_proof(RT3, RT3)},
        ]
    )


def _delivery_bundle_one():
    return copy.deepcopy(_delivery_bundle_one_raw())


def _delivery_bundle_two():
    return copy.deepcopy(_delivery_bundle_two_raw())


def _delivery_bundle_three():
    return copy.deepcopy(_delivery_bundle_three_raw())


@functools.lru_cache(maxsize=1)
def _delivery_evolution_raw():
    return checkpoint_chain_checkpoint_bundle_evolution(
        [
            {"at": DT1, "bundle": _delivery_bundle_one()},
            {"at": DT2, "bundle": _delivery_bundle_two()},
            {"at": DT3, "bundle": _delivery_bundle_three()},
        ]
    )


def _delivery_evolution():
    return copy.deepcopy(_delivery_evolution_raw())


@functools.lru_cache(maxsize=None)
def _window_proof_raw(start, end):
    return bundle_evolution_checkpoint(_delivery_evolution_raw(), start, end)


def _window_proof(start, end):
    return copy.deepcopy(_window_proof_raw(start, end))


@functools.lru_cache(maxsize=1)
def _bundle_before_raw():
    return bundle_evolution_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(DT1, DT2)},
            {"id": "beta", "proof": _window_proof(DT2, DT3)},
        ]
    )


@functools.lru_cache(maxsize=1)
def _bundle_after_raw():
    return bundle_evolution_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(DT1, DT2)},
            {"id": "beta", "proof": _window_proof(DT3, DT3)},
            {"id": "伽马", "proof": _window_proof(DT1, DT3)},
        ]
    )


def _bundle_before():
    return copy.deepcopy(_bundle_before_raw())


def _bundle_after():
    return copy.deepcopy(_bundle_after_raw())


@functools.lru_cache(maxsize=1)
def _diff_raw():
    return bundle_evolution_checkpoint_bundle_diff(
        _bundle_before_raw(), _bundle_after_raw()
    )


def _diff():
    return copy.deepcopy(_diff_raw())


def _expected(report):
    return {
        "before_root": report["before_root"],
        "after_root": report["after_root"],
        "before_ids": sorted(
            member["id"] for member in report["before"]["proofs"]
        ),
        "after_ids": sorted(member["id"] for member in report["after"]["proofs"]),
        "digest": report["digest"],
    }


# ----------------------------------------------------------------- happy path


def test_generated_report_verifies():
    report = _diff()
    assert verify_bundle_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_identical_bundles_report_verifies():
    bundle = _bundle_before()
    report = bundle_evolution_checkpoint_bundle_diff(bundle, bundle)
    assert verify_bundle_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_expected_id_arrays_accept_arbitrary_order():
    report = _diff()
    expected = _expected(report)
    expected["before_ids"] = list(reversed(expected["before_ids"]))
    expected["after_ids"] = list(reversed(expected["after_ids"]))
    assert verify_bundle_evolution_checkpoint_bundle_diff(report, expected)


def test_does_not_mutate_inputs():
    report = _diff()
    expected = _expected(report)
    report_snapshot = copy.deepcopy(report)
    expected_snapshot = copy.deepcopy(expected)
    verify_bundle_evolution_checkpoint_bundle_diff(report, expected)
    assert report == report_snapshot
    assert expected == expected_snapshot


# --------------------------------------------------------- false => False


def test_false_diff_digest_returns_false():
    report = _diff()
    report["digest"] = "f" * 64
    assert not verify_bundle_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    )


def test_false_before_root_returns_false():
    report = _diff()
    expected = _expected(report)
    report["before_root"] = report["before"]["root"] = "f" * 64
    expected["before_root"] = "f" * 64
    assert not verify_bundle_evolution_checkpoint_bundle_diff(report, expected)


def test_false_after_root_returns_false():
    report = _diff()
    expected = _expected(report)
    report["after_root"] = report["after"]["root"] = "f" * 64
    expected["after_root"] = "f" * 64
    assert not verify_bundle_evolution_checkpoint_bundle_diff(report, expected)


def test_false_member_digest_returns_false():
    report = _diff()
    report["before"]["proofs"][0]["digest"] = "e" * 64
    assert not verify_bundle_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    )


def test_broken_member_chain_link_returns_false():
    report = _diff()
    report["after"]["proofs"][1]["previous"] = "e" * 64
    assert not verify_bundle_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    )


def test_false_window_proof_commitment_returns_false():
    report = _diff()
    report["after"]["proofs"][0]["proof"]["commitment"] = "e" * 64
    assert not verify_bundle_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    )


def test_tampered_change_side_proof_returns_false():
    report = _diff()
    changed = next(c for c in report["changes"] if c["kind"] == "changed")
    changed["after"]["commitment"] = "e" * 64
    assert not verify_bundle_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    )


def test_expected_digest_mismatch_returns_false():
    report = _diff()
    expected = _expected(report)
    expected["digest"] = "f" * 64
    assert not verify_bundle_evolution_checkpoint_bundle_diff(report, expected)


def test_expected_root_mismatch_returns_false():
    report = _diff()
    expected = _expected(report)
    expected["after_root"] = "f" * 64
    assert not verify_bundle_evolution_checkpoint_bundle_diff(report, expected)


def test_expected_id_set_mismatch_returns_false():
    report = _diff()
    expected = _expected(report)
    expected["after_ids"].append("zzz")
    assert not verify_bundle_evolution_checkpoint_bundle_diff(report, expected)


def test_missing_expected_change_returns_false():
    # Structurally legal list (every listed change is valid) but it omits the
    # changed beta member.
    report = _diff()
    report["changes"] = [
        change
        for change in report["changes"]
        if change["id"] != "beta"
    ]
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
    assert not verify_bundle_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    )


def test_extra_unchanged_member_listed_returns_false():
    # Structurally legal list (alpha exists in both bundles and both sides
    # reproduce the bundle members) but it lists an unchanged member; the
    # reconstructed full change set rejects it with False after validation.
    report = _diff()
    alpha_before = report["before"]["proofs"][0]["proof"]
    alpha_after = report["after"]["proofs"][0]["proof"]
    report["changes"] = [
        {
            "id": "alpha",
            "kind": "changed",
            "before": copy.deepcopy(alpha_before),
            "after": copy.deepcopy(alpha_after),
        }
    ] + report["changes"]
    assert not verify_bundle_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    )


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
        verify_bundle_evolution_checkpoint_bundle_diff(
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
    report = _diff()
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle_diff(
            report, {"before_root": report["before_root"]}
        )


def test_duplicate_change_id_raises():
    report = _diff()
    change = copy.deepcopy(report["changes"][0])
    report["changes"] = [change, copy.deepcopy(change)]
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_unsorted_change_ids_raise():
    report = _diff()
    report["changes"] = list(reversed(report["changes"]))
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_bad_kind_raises():
    report = _diff()
    report["changes"][0]["kind"] = "updated"
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_added_with_non_null_before_raises():
    report = _diff()
    added = next(c for c in report["changes"] if c["kind"] == "added")
    added["before"] = copy.deepcopy(added["after"])
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_added_id_missing_from_after_bundle_raises():
    report = _diff()
    added = next(c for c in report["changes"] if c["kind"] == "added")
    added["id"] = "ghost"
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_change_side_not_equal_to_bundle_member_raises():
    report = _diff()
    changed = next(c for c in report["changes"] if c["kind"] == "changed")
    changed["before"]["start"] = DT1
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_second_input_still_validated_when_first_is_false():
    # A format-valid but false report must not short-circuit expected checks.
    report = _diff()
    report["digest"] = "f" * 64
    with pytest.raises(ValueError):
        verify_bundle_evolution_checkpoint_bundle_diff(
            report, {"before_root": "0" * 64}
        )


# ---------------------------------------------------------------- endpoint


def test_http_verify_true_returns_compact_json():
    report = _diff()
    response = client.post(
        VERIFY_PATH, json={"report": report, "expected": _expected(report)}
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_verify_false_is_still_200():
    report = _diff()
    expected = _expected(report)
    expected["digest"] = "f" * 64
    response = client.post(
        VERIFY_PATH, json={"report": report, "expected": expected}
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
        VERIFY_PATH, json={"report": _diff(), "expected": _expected(_diff())}
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
        json={"report": {"root": "0" * 64}, "expected": _expected(_diff())},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
