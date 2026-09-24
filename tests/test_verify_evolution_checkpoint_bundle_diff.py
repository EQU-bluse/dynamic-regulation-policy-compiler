import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    evolution_checkpoint,
    evolution_checkpoint_bundle,
    evolution_checkpoint_bundle_diff,
    matrix_bundle_evolution,
    verify_evolution_checkpoint_bundle_diff,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"
AT1 = "2021-05-01T00:00:00Z"
AT2 = "2021-06-01T00:00:00Z"
AT3 = "2021-07-01T00:00:00Z"


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


def _proof_head():
    return evolution_checkpoint(_evolution(), AT1, AT2)


def _proof_middle():
    return evolution_checkpoint(_evolution(), AT2, AT3)


def _proof_single():
    return evolution_checkpoint(_evolution(), AT3, AT3)


def _proof_full():
    return evolution_checkpoint(_evolution(), AT1, AT3)


def _bundle_before():
    return evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": _proof_head()},
            {"id": "b", "proof": _proof_middle()},
        ]
    )


def _bundle_after():
    return evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": _proof_head()},
            {"id": "b", "proof": _proof_middle()},
            {"id": "c", "proof": _proof_single()},
        ]
    )


def _diff():
    return evolution_checkpoint_bundle_diff(_bundle_before(), _bundle_after())


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
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    ) is True


def test_verifies_empty_change_diff():
    bundle = _bundle_before()
    report = evolution_checkpoint_bundle_diff(bundle, bundle)
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    ) is True


def test_verifies_changed_change_diff():
    after = evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": _proof_head()},
            {"id": "b", "proof": _proof_full()},
        ]
    )
    report = evolution_checkpoint_bundle_diff(_bundle_before(), after)
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    ) is True


def test_expected_id_arrays_accept_arbitrary_order():
    report = _diff()
    expected = _expected(
        report, before_ids=["b", "a"], after_ids=["c", "b", "a"]
    )
    assert verify_evolution_checkpoint_bundle_diff(report, expected) is True


def test_does_not_mutate_inputs():
    report = _diff()
    expected = _expected(report)
    report_before = copy.deepcopy(report)
    expected_before = copy.deepcopy(expected)
    verify_evolution_checkpoint_bundle_diff(report, expected)
    assert report == report_before
    assert expected == expected_before


# ------------------------------------------------------------- false -> bool


def test_tampered_diff_digest_returns_false():
    report = _diff()
    report["digest"] = "f" * 64
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_wrong_before_root_returns_false():
    report = _diff()
    expected = _expected(report)
    expected["before_root"] = "f" * 64
    assert verify_evolution_checkpoint_bundle_diff(report, expected) is False


def test_wrong_after_root_returns_false():
    report = _diff()
    expected = _expected(report)
    expected["after_root"] = "f" * 64
    assert verify_evolution_checkpoint_bundle_diff(report, expected) is False


def test_expected_digest_mismatch_returns_false():
    report = _diff()
    expected = _expected(report)
    expected["digest"] = "f" * 64
    assert verify_evolution_checkpoint_bundle_diff(report, expected) is False


def test_expected_before_id_set_mismatch_returns_false():
    report = _diff()
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report, before_ids=["a"])
    ) is False
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report, before_ids=["a", "b", "c"])
    ) is False


def test_expected_after_id_set_mismatch_returns_false():
    report = _diff()
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report, after_ids=["a", "b"])
    ) is False
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report, after_ids=["a", "b", "x"])
    ) is False


def test_false_member_proof_in_before_bundle_returns_false():
    report = _diff()
    report["before"]["proofs"][0]["proof"]["stages"][0]["digest"] = "e" * 64
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_false_bundle_member_link_returns_false():
    report = _diff()
    report["after"]["proofs"][1]["previous"] = "f" * 64
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_false_bundle_member_digest_returns_false():
    report = _diff()
    report["after"]["proofs"][0]["digest"] = "d" * 64
    assert verify_evolution_checkpoint_bundle_diff(
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
    assert verify_evolution_checkpoint_bundle_diff(report, expected) is False


def test_false_change_proof_stage_chain_returns_false():
    report = _diff()
    point = report["changes"][0]["after"]["stages"][0]
    point["digest"] = "f" * 64
    # Structure still validates; only the recomputed stage chain disagrees.
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_false_change_proof_commitment_returns_false():
    report = _diff()
    report["changes"][0]["after"]["commitment"] = "f" * 64
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_false_change_proof_anchor_returns_false():
    # The added single-stage proof anchors at a real prior stage digest;
    # replace it with an unsupported but format-valid value.
    report = _diff()
    report["changes"][0]["after"]["anchor"] = "f" * 64
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


def test_tampered_bundle_embedded_in_diff_returns_false():
    report = _diff()
    # An unsupported declared member digest that keeps every structural
    # check intact reaches the recompute stage and yields False.
    members = report["after"]["proofs"]
    members[0]["digest"] = "d" * 64
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report)
    ) is False


# ------------------------------------------------------------- invalid shape


def test_root_mismatch_with_embedded_bundle_raises():
    report = _diff()
    report["before_root"] = "f" * 64
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_non_dict_report_raises():
    for bad in (None, [], "x", 42):
        with pytest.raises(ValueError):
            verify_evolution_checkpoint_bundle_diff(bad, _expected(_diff()))


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
        verify_evolution_checkpoint_bundle_diff(report, _expected(_diff()))


@pytest.mark.parametrize("field", ["before_root", "after_root", "digest"])
def test_bad_digest_format_raises(field):
    report = _diff()
    report[field] = "x"
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_structurally_invalid_embedded_bundle_raises():
    report = _diff()
    report["before"] = {"root": "0" * 64, "proofs": []}
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_reordered_embedded_members_raise():
    report = _diff()
    report["after"]["proofs"].reverse()
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_semantic_forgery_in_embedded_proof_raises():
    report = _diff()
    report["before"]["proofs"][0]["proof"]["stages"][0]["bundle"]["reports"][0][
        "report"
    ]["matrix"]["points"][0]["cases"][0]["decision"] = "forged"
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_changes_not_a_list_raises():
    report = _diff()
    report["changes"] = {}
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_bad_change_key_set_raises():
    report = _diff()
    report["changes"][0]["kind"] = "nope"
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))
    report = _diff()
    del report["changes"][0]["kind"]
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_change_with_bad_kind_raises():
    after = evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": _proof_head()},
            {"id": "b", "proof": _proof_full()},
        ]
    )
    report = evolution_checkpoint_bundle_diff(_bundle_before(), after)
    report["changes"][0]["kind"] = "updated"
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_duplicate_change_id_raises():
    report = _diff()
    report["changes"].append(copy.deepcopy(report["changes"][0]))
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_unsorted_change_ids_raise():
    before = evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": _proof_head()},
            {"id": "b", "proof": _proof_middle()},
        ]
    )
    after = evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": _proof_head()},
            {"id": "c", "proof": _proof_single()},
        ]
    )
    report = evolution_checkpoint_bundle_diff(before, after)
    assert [c["id"] for c in report["changes"]] == ["b", "c"]
    report["changes"].reverse()
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_added_change_with_non_null_before_raises():
    report = _diff()
    report["changes"][0]["before"] = _proof_head()
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_added_change_with_null_after_raises():
    report = _diff()
    report["changes"][0]["after"] = None
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_changed_change_with_null_side_raises():
    after = evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": _proof_head()},
            {"id": "b", "proof": _proof_full()},
        ]
    )
    report = evolution_checkpoint_bundle_diff(_bundle_before(), after)
    report["changes"][0]["after"] = None
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_change_proof_not_equal_to_bundle_member_raises():
    report = _diff()
    # The added after-side proof must reproduce member c's proof; substitute
    # a different but structurally valid proof.
    report["changes"][0]["after"] = copy.deepcopy(_proof_head())
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_wrong_kind_for_member_presence_raises():
    # Member b is present in both bundles with different proofs in the
    # changed setup, not removed.
    after = evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": _proof_head()},
            {"id": "b", "proof": _proof_full()},
        ]
    )
    report = evolution_checkpoint_bundle_diff(_bundle_before(), after)
    change = report["changes"][0]
    change["kind"] = "removed"
    change["after"] = None
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_change_for_unchanged_member_raises():
    report = _diff()
    unchanged = next(
        member for member in report["after"]["proofs"] if member["id"] == "a"
    )
    report["changes"].append(
        {
            "id": "a",
            "kind": "changed",
            "before": copy.deepcopy(unchanged["proof"]),
            "after": copy.deepcopy(unchanged["proof"]),
        }
    )
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_missing_change_returns_false():
    report = _diff()
    report["changes"] = []
    assert verify_evolution_checkpoint_bundle_diff(report, _expected(report)) is False


def test_change_for_unknown_id_raises():
    report = _diff()
    change = copy.deepcopy(report["changes"][0])
    change["id"] = "zzz"
    report["changes"].append(change)
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_invalid_proof_inside_change_raises():
    report = _diff()
    report["changes"][0]["after"] = {"start": AT1}
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


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
        verify_evolution_checkpoint_bundle_diff(_diff(), expected)


def test_structure_validated_before_value_comparison():
    # A bad change entry raises even if every digest field lines up.
    report = _diff()
    report["changes"][0] = {"id": "x", "kind": "added", "before": None, "after": None}
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(_diff()))
    # A bad expected raises against an otherwise genuine report.
    good = _diff()
    expected = _expected(good)
    expected["after_ids"] = []
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(good, expected)
    # An invalid change proof must raise even when its side is otherwise null
    # consistent, rather than being hidden behind a False digest.
    report = _diff()
    report["changes"][0]["after"] = {"root": "0" * 64}
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(_diff()))


# ---------------------------------------------------------------- endpoint


def test_http_valid_diff_is_200_compact_json():
    report = _diff()
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_false_diff_is_200_false():
    report = _diff()
    report["digest"] = "f" * 64
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/verify",
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
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/verify",
        json={"report": report, "expected": _expected(report)},
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
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/verify",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_value_error_in_function_is_422():
    report = _diff()
    report["changes"][0]["kind"] = "nope"
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/verify",
        json={"report": report, "expected": _expected(_diff())},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
