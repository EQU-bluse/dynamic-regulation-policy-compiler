import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    checkpoint_chain,
    checkpoint_chain_checkpoint,
    checkpoint_chain_checkpoint_bundle,
    checkpoint_chain_checkpoint_bundle_diff,
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    evolution_checkpoint,
    evolution_checkpoint_bundle,
    matrix_bundle_evolution,
    verify_checkpoint_chain_checkpoint_bundle_diff,
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

VERIFY_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/diff/verify"
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


def _bundle_before():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(RT1, RT1)},
            {"id": "beta", "proof": _window_proof(RT2, RT3)},
        ]
    )


def _bundle_after():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(RT1, RT1)},
            {"id": "beta", "proof": _window_proof(RT2, RT2)},
            {"id": "伽马", "proof": _window_proof(RT3, RT3)},
        ]
    )


def _bundle_removed():
    # beta is removed relative to _bundle_before(); alpha stays unchanged.
    return checkpoint_chain_checkpoint_bundle(
        [{"id": "alpha", "proof": _window_proof(RT1, RT1)}]
    )


def _diff():
    return checkpoint_chain_checkpoint_bundle_diff(_bundle_before(), _bundle_after())


def _expected(report, before_ids=None, after_ids=None):
    if before_ids is None:
        before_ids = [member["id"] for member in report["before"]["proofs"]]
    if after_ids is None:
        after_ids = [member["id"] for member in report["after"]["proofs"]]
    return {
        "before_root": report["before_root"],
        "after_root": report["after_root"],
        "before_ids": before_ids,
        "after_ids": after_ids,
        "digest": report["digest"],
    }


# ---------------------------------------------------------------- genuine


def test_verifies_genuine_diff():
    report = _diff()
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report)
    ) is True


def test_verifies_empty_change_diff():
    bundle = _bundle_before()
    report = checkpoint_chain_checkpoint_bundle_diff(bundle, bundle)
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report)
    ) is True


def test_verifies_removed_change_diff():
    report = checkpoint_chain_checkpoint_bundle_diff(
        _bundle_before(), _bundle_removed()
    )
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report)
    ) is True


def test_expected_id_arrays_accept_arbitrary_order():
    report = _diff()
    expected = _expected(
        report, before_ids=["beta", "alpha"], after_ids=["伽马", "beta", "alpha"]
    )
    assert verify_checkpoint_chain_checkpoint_bundle_diff(report, expected) is True


def test_does_not_mutate_inputs():
    report = _diff()
    expected = _expected(report)
    report_before = copy.deepcopy(report)
    expected_before = copy.deepcopy(expected)
    verify_checkpoint_chain_checkpoint_bundle_diff(report, expected)
    assert report == report_before
    assert expected == expected_before


# ------------------------------------------------------------- false -> bool


def test_tampered_diff_digest_returns_false():
    report = _diff()
    report["digest"] = "f" * 64
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_wrong_before_root_returns_false():
    report = _diff()
    expected = _expected(report)
    expected["before_root"] = "f" * 64
    assert verify_checkpoint_chain_checkpoint_bundle_diff(report, expected) is False


def test_wrong_after_root_returns_false():
    report = _diff()
    expected = _expected(report)
    expected["after_root"] = "f" * 64
    assert verify_checkpoint_chain_checkpoint_bundle_diff(report, expected) is False


def test_expected_digest_mismatch_returns_false():
    report = _diff()
    expected = _expected(report)
    expected["digest"] = "f" * 64
    assert verify_checkpoint_chain_checkpoint_bundle_diff(report, expected) is False


def test_expected_before_id_set_mismatch_returns_false():
    report = _diff()
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report, before_ids=["alpha"])
    ) is False
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report, before_ids=["alpha", "beta", "伽马"])
    ) is False


def test_expected_after_id_set_mismatch_returns_false():
    report = _diff()
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report, after_ids=["alpha", "beta"])
    ) is False
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report, after_ids=["alpha", "beta", "x", "伽马"])
    ) is False


def test_false_member_window_proof_in_before_bundle_returns_false():
    report = _diff()
    report["before"]["proofs"][0]["proof"]["stages"][0]["digest"] = "e" * 64
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_false_bundle_member_link_returns_false():
    report = _diff()
    report["after"]["proofs"][1]["previous"] = "f" * 64
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_false_bundle_member_digest_returns_false():
    report = _diff()
    report["after"]["proofs"][0]["digest"] = "d" * 64
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_false_bundle_root_returns_false():
    report = _diff()
    report["before"]["root"] = "f" * 64
    # Keep the top-level before_root consistent with the tampered bundle so
    # only the unsupported root is at stake.
    report["before_root"] = "f" * 64
    expected = _expected(report)
    expected["before_root"] = "f" * 64
    assert verify_checkpoint_chain_checkpoint_bundle_diff(report, expected) is False


def test_false_change_proof_stage_chain_returns_false():
    report = _diff()
    added = next(change for change in report["changes"] if change["id"] == "伽马")
    added["after"]["stages"][0]["digest"] = "f" * 64
    # Structure still validates; only the recomputed stage chain disagrees.
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_false_change_proof_commitment_returns_false():
    report = _diff()
    report["changes"][0]["after"]["commitment"] = "f" * 64
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_false_change_proof_anchor_returns_false():
    # The added single-stage window anchors at a real prior stage digest;
    # replace it with an unsupported but format-valid value.
    report = _diff()
    added = next(change for change in report["changes"] if change["id"] == "伽马")
    added["after"]["anchor"] = "f" * 64
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_tampered_bundle_embedded_in_diff_returns_false():
    report = _diff()
    # An unsupported declared member digest that keeps every structural
    # check intact reaches the recompute stage and yields False.
    members = report["after"]["proofs"]
    members[0]["digest"] = "d" * 64
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_missing_change_returns_false():
    report = _diff()
    report["changes"] = []
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_extra_unchanged_member_change_returns_false():
    report = _diff()
    unchanged = next(
        member for member in report["after"]["proofs"] if member["id"] == "alpha"
    )
    # Inserted in code point order so the list stays structurally legal;
    # listing an unchanged member is a completeness failure, not a shape one.
    report["changes"].insert(
        0,
        {
            "id": "alpha",
            "kind": "changed",
            "before": copy.deepcopy(unchanged["proof"]),
            "after": copy.deepcopy(unchanged["proof"]),
        },
    )
    assert verify_checkpoint_chain_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


# ------------------------------------------------------------- invalid shape


def test_root_mismatch_with_embedded_bundle_raises():
    report = _diff()
    report["before_root"] = "f" * 64
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_non_dict_report_raises():
    for bad in (None, [], "x", 42):
        with pytest.raises(ValueError):
            verify_checkpoint_chain_checkpoint_bundle_diff(bad, _expected(_diff()))


@pytest.mark.parametrize(
    "report",
    [
        {},
        {"before_root": "0" * 64},
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before": {},
            "after": {},
            "changes": [],
            "digest": "0" * 64,
            "extra": 1,
        },
    ],
)
def test_bad_report_key_set_raises(report):
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(_diff()))


@pytest.mark.parametrize("field", ["before_root", "after_root", "digest"])
def test_bad_digest_format_raises(field):
    report = _diff()
    report[field] = "x"
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_structurally_invalid_embedded_bundle_raises():
    report = _diff()
    report["before"] = {"root": "0" * 64, "proofs": []}
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_reordered_embedded_members_raise():
    report = _diff()
    report["after"]["proofs"].reverse()
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_semantic_forgery_in_embedded_window_proof_raises():
    report = _diff()
    report["before"]["proofs"][0]["proof"]["stages"][0]["bundle"]["proofs"][0][
        "proof"
    ]["stages"][0]["bundle"]["reports"][0]["report"]["matrix"]["points"][0][
        "cases"
    ][0]["decision"] = "forged"
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_changes_not_a_list_raises():
    report = _diff()
    report["changes"] = {}
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_bad_change_key_set_raises():
    report = _diff()
    report["changes"][0]["kind"] = "nope"
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))
    report = _diff()
    del report["changes"][0]["kind"]
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_change_with_bad_kind_raises():
    report = _diff()
    report["changes"][0]["kind"] = "updated"
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_duplicate_change_id_raises():
    report = _diff()
    report["changes"].append(copy.deepcopy(report["changes"][0]))
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_unsorted_change_ids_raise():
    report = _diff()
    assert [c["id"] for c in report["changes"]] == ["beta", "伽马"]
    report["changes"].reverse()
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_added_change_with_non_null_before_raises():
    report = _diff()
    added = next(change for change in report["changes"] if change["id"] == "伽马")
    added["before"] = _window_proof(RT1, RT1)
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_added_change_with_null_after_raises():
    report = _diff()
    added = next(change for change in report["changes"] if change["id"] == "伽马")
    added["after"] = None
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_changed_change_with_null_side_raises():
    report = _diff()
    report["changes"][0]["after"] = None
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_change_proof_not_equal_to_bundle_member_raises():
    report = _diff()
    added = next(change for change in report["changes"] if change["id"] == "伽马")
    # The added after-side proof must reproduce member 伽马's proof; substitute
    # a different but structurally valid window proof.
    added["after"] = copy.deepcopy(_window_proof(RT1, RT1))
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_wrong_kind_for_member_presence_raises():
    # beta is present in both bundles with different window proofs, i.e.
    # changed, not removed.
    report = _diff()
    changed = next(change for change in report["changes"] if change["id"] == "beta")
    changed["kind"] = "removed"
    changed["after"] = None
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_extra_unchanged_member_in_wrong_order_raises():
    report = _diff()
    unchanged = next(
        member for member in report["after"]["proofs"] if member["id"] == "alpha"
    )
    # Appended out of code point order: the ordering violation is structural.
    report["changes"].append(
        {
            "id": "alpha",
            "kind": "changed",
            "before": copy.deepcopy(unchanged["proof"]),
            "after": copy.deepcopy(unchanged["proof"]),
        }
    )
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_change_for_unknown_id_raises():
    report = _diff()
    change = copy.deepcopy(next(c for c in report["changes"] if c["id"] == "伽马"))
    change["id"] = "zzz"
    # Insert in code point order (ASCII sorts before CJK) so the presence
    # check — not ordering — is what fails.
    report["changes"].insert(1, change)
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


def test_invalid_proof_inside_change_raises():
    report = _diff()
    added = next(change for change in report["changes"] if change["id"] == "伽马")
    added["after"] = {"start": RT3}
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(report))


@pytest.mark.parametrize(
    "expected",
    [
        None,
        [],
        {},
        {"before_root": "0" * 64},
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before_ids": ["a"],
            "after_ids": ["a"],
        },
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before_ids": ["a"],
            "after_ids": ["a"],
            "digest": "0" * 64,
            "extra": 1,
        },
        {
            "before_root": "x",
            "after_root": "0" * 64,
            "before_ids": ["a"],
            "after_ids": ["a"],
            "digest": "0" * 64,
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
            "before_ids": ["a"],
            "after_ids": ["a", "a"],
            "digest": "0" * 64,
        },
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before_ids": ["a", ""],
            "after_ids": ["a"],
            "digest": "0" * 64,
        },
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before_ids": ["a"],
            "after_ids": "a",
            "digest": "0" * 64,
        },
    ],
)
def test_bad_expected_shape_raises(expected):
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(_diff(), expected)


def test_structure_validated_before_value_comparison():
    # A bad change entry raises even if every digest field lines up.
    report = _diff()
    added = next(change for change in report["changes"] if change["id"] == "伽马")
    added["after"] = None
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(_diff()))
    # A bad expected raises against an otherwise genuine report.
    good = _diff()
    expected = _expected(good)
    expected["after_ids"] = []
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(good, expected)
    # An invalid change proof must raise even when its side is otherwise null
    # consistent, rather than being hidden behind a False digest.
    report = _diff()
    added = next(change for change in report["changes"] if change["id"] == "伽马")
    added["after"] = {"root": "0" * 64}
    with pytest.raises(ValueError):
        verify_checkpoint_chain_checkpoint_bundle_diff(report, _expected(_diff()))


# ---------------------------------------------------------------- endpoint


def test_http_valid_diff_is_200_compact_json():
    report = _diff()
    response = client.post(
        VERIFY_PATH, json={"report": report, "expected": _expected(report)}
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_false_diff_is_200_false():
    report = _diff()
    report["digest"] = "f" * 64
    response = client.post(
        VERIFY_PATH,
        json={"report": report, "expected": _expected(_diff())},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": False}


def test_http_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("diff verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    report = _diff()
    response = client.post(
        VERIFY_PATH, json={"report": report, "expected": _expected(report)}
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
        b'{"report": {}}',
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


def test_http_value_error_in_function_is_422():
    report = _diff()
    report["changes"][0]["kind"] = "nope"
    response = client.post(
        VERIFY_PATH,
        json={"report": report, "expected": _expected(_diff())},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
