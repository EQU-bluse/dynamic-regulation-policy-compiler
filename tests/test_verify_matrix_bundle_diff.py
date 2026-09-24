import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    matrix_bundle_diff,
    verify_matrix_bundle_diff,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"


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


def _report_b_variant():
    return decision_matrix_attestation(
        START, END, [{"id": "c2", "facts": {}}], [_rule(result="zz")]
    )


def _report_c():
    return decision_matrix_attestation(
        START, END, [{"id": "c3", "facts": {"y": False}}], [_rule(result="q")]
    )


def _bundle_before():
    return decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()}, {"id": "b", "report": _report_b()}]
    )


def _bundle_after():
    return decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": _report_a()},
            {"id": "b", "report": _report_b()},
            {"id": "c", "report": _report_c()},
        ]
    )


def _diff():
    return matrix_bundle_diff(_bundle_before(), _bundle_after())


def _expected(report, before_ids=None, after_ids=None):
    if before_ids is None:
        before_ids = [member["id"] for member in report["before"]["reports"]]
    if after_ids is None:
        after_ids = [member["id"] for member in report["after"]["reports"]]
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
    assert verify_matrix_bundle_diff(report, _expected(report)) is True


def test_verifies_empty_change_diff():
    bundle = _bundle_before()
    report = matrix_bundle_diff(bundle, bundle)
    assert verify_matrix_bundle_diff(report, _expected(report)) is True


def test_expected_id_arrays_accept_arbitrary_order():
    report = _diff()
    expected = _expected(
        report, before_ids=["b", "a"], after_ids=["c", "b", "a"]
    )
    assert verify_matrix_bundle_diff(report, expected) is True


def test_does_not_mutate_inputs():
    report = _diff()
    expected = _expected(report)
    report_before = copy.deepcopy(report)
    expected_before = copy.deepcopy(expected)
    verify_matrix_bundle_diff(report, expected)
    assert report == report_before
    assert expected == expected_before


# ------------------------------------------------------------- false -> bool


def test_tampered_diff_digest_returns_false():
    report = _diff()
    report["digest"] = "f" * 64
    assert verify_matrix_bundle_diff(report, _expected(report)) is False


def test_wrong_before_root_returns_false():
    report = _diff()
    expected = _expected(report)
    expected["before_root"] = "f" * 64
    assert verify_matrix_bundle_diff(report, expected) is False


def test_wrong_after_root_returns_false():
    report = _diff()
    expected = _expected(report)
    expected["after_root"] = "f" * 64
    assert verify_matrix_bundle_diff(report, expected) is False


def test_expected_digest_mismatch_returns_false():
    report = _diff()
    expected = _expected(report)
    expected["digest"] = "f" * 64
    assert verify_matrix_bundle_diff(report, expected) is False


def test_expected_before_id_set_mismatch_returns_false():
    report = _diff()
    assert verify_matrix_bundle_diff(
        report, _expected(report, before_ids=["a"])
    ) is False
    assert verify_matrix_bundle_diff(
        report, _expected(report, before_ids=["a", "b", "c"])
    ) is False


def test_expected_after_id_set_mismatch_returns_false():
    report = _diff()
    assert verify_matrix_bundle_diff(
        report, _expected(report, after_ids=["a", "b"])
    ) is False
    assert verify_matrix_bundle_diff(
        report, _expected(report, after_ids=["a", "b", "x"])
    ) is False


def test_false_sub_report_digest_in_before_bundle_returns_false():
    report = _diff()
    report["before"]["reports"][0]["report"]["digest"] = "e" * 64
    assert verify_matrix_bundle_diff(report, _expected(report)) is False


def test_false_bundle_member_link_returns_false():
    report = _diff()
    report["after"]["reports"][1]["previous"] = "f" * 64
    assert verify_matrix_bundle_diff(report, _expected(report)) is False


def test_false_bundle_root_returns_false():
    report = _diff()
    report["before"]["root"] = "f" * 64
    # Keep the top-level before_root consistent with the tampered bundle so
    # only the unsupported root is at stake.
    report["before_root"] = "f" * 64
    expected = _expected(report)
    expected["before_root"] = "f" * 64
    assert verify_matrix_bundle_diff(report, expected) is False


def test_false_embedded_policy_chain_in_change_credential_returns_false():
    before = _bundle_before()
    after = decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": _report_a()},
            {"id": "b", "report": _report_b_variant()},
        ]
    )
    report = matrix_bundle_diff(before, after)
    point = report["changes"][0]["after"]["policy"]["points"][-1]
    point["digest"] = "f" * 64
    # Structure still validates; only the recomputed embedded chain disagrees.
    assert verify_matrix_bundle_diff(report, _expected(report)) is False


def test_false_change_credential_digest_returns_false():
    before = _bundle_before()
    after = decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": _report_a()},
            {"id": "b", "report": _report_b_variant()},
        ]
    )
    report = matrix_bundle_diff(before, after)
    report["changes"][0]["after"]["digest"] = "f" * 64
    assert verify_matrix_bundle_diff(report, _expected(report)) is False


def test_tampered_bundle_embedded_in_diff_returns_false():
    report = _diff()
    # An unsupported declared bundle root that keeps the top-level field
    # consistent reaches the recompute stage and yields False.
    members = report["after"]["reports"]
    members[0]["report"]["digest"] = "d" * 64  # format-valid but false
    assert verify_matrix_bundle_diff(report, _expected(report)) is False


# ------------------------------------------------------------- invalid shape


def test_root_mismatch_with_embedded_bundle_raises():
    report = _diff()
    report["before_root"] = "f" * 64
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_non_dict_report_raises():
    for bad in (None, [], "x", 42):
        with pytest.raises(ValueError):
            verify_matrix_bundle_diff(bad, _expected(_diff()))


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
        verify_matrix_bundle_diff(report, _expected(_diff()))


@pytest.mark.parametrize("field", ["before_root", "after_root", "digest"])
def test_bad_digest_format_raises(field):
    report = _diff()
    report[field] = "x"
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_structurally_invalid_embedded_bundle_raises():
    report = _diff()
    report["before"] = {"root": "0" * 64, "reports": []}
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_reordered_embedded_members_raise():
    report = _diff()
    report["after"]["reports"].reverse()
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_semantic_forgery_in_embedded_credential_raises():
    report = _diff()
    report["before"]["reports"][0]["report"]["matrix"]["points"][0]["cases"][0][
        "decision"
    ] = "forged"
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_changes_not_a_list_raises():
    report = _diff()
    report["changes"] = {}
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_bad_change_key_set_raises():
    report = _diff()
    report["changes"][0]["kind"] = "nope"
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))
    report = _diff()
    del report["changes"][0]["kind"]
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_change_with_bad_kind_raises():
    before = _bundle_before()
    after = decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": _report_a()},
            {"id": "b", "report": _report_b_variant()},
        ]
    )
    report = matrix_bundle_diff(before, after)
    report["changes"][0]["kind"] = "updated"
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_duplicate_change_id_raises():
    report = _diff()
    report["changes"].append(copy.deepcopy(report["changes"][0]))
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_unsorted_change_ids_raise():
    before = decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()}, {"id": "b", "report": _report_b()}]
    )
    after = decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()}, {"id": "c", "report": _report_c()}]
    )
    report = matrix_bundle_diff(before, after)
    assert [c["id"] for c in report["changes"]] == ["b", "c"]
    report["changes"].reverse()
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_added_change_with_non_null_before_raises():
    report = _diff()
    report["changes"][0]["before"] = _report_a()
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_added_change_with_null_after_raises():
    report = _diff()
    report["changes"][0]["after"] = None
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_changed_change_with_null_side_raises():
    before = _bundle_before()
    after = decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": _report_a()},
            {"id": "b", "report": _report_b_variant()},
        ]
    )
    report = matrix_bundle_diff(before, after)
    report["changes"][0]["after"] = None
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_change_credential_not_equal_to_bundle_member_raises():
    before = _bundle_before()
    after = decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": _report_a()},
            {"id": "b", "report": _report_b_variant()},
        ]
    )
    report = matrix_bundle_diff(before, after)
    # The after-side credential must reproduce the after bundle member;
    # substitute the before variant instead.
    report["changes"][0]["after"] = copy.deepcopy(report["changes"][0]["before"])
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_wrong_kind_for_member_presence_raises():
    # Member b is changed between the bundles, not removed.
    before = _bundle_before()
    after = decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": _report_a()},
            {"id": "b", "report": _report_b_variant()},
        ]
    )
    report = matrix_bundle_diff(before, after)
    change = report["changes"][0]
    change["kind"] = "removed"
    change["after"] = None
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_change_for_unchanged_member_raises():
    report = _diff()
    unchanged = next(
        member for member in report["after"]["reports"] if member["id"] == "a"
    )
    report["changes"].append(
        {
            "id": "a",
            "kind": "changed",
            "before": copy.deepcopy(unchanged["report"]),
            "after": copy.deepcopy(unchanged["report"]),
        }
    )
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_missing_change_raises():
    report = _diff()
    report["changes"] = []
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_change_for_unknown_id_raises():
    report = _diff()
    change = copy.deepcopy(report["changes"][0])
    change["id"] = "zzz"
    report["changes"].append(change)
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


def test_invalid_credential_inside_change_raises():
    report = _diff()
    report["changes"][0]["after"] = {"start": START}
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(report))


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
        verify_matrix_bundle_diff(_diff(), expected)


def test_structure_validated_before_value_comparison():
    # Bad change content raises even if every digest field lines up.
    report = _diff()
    saved = copy.deepcopy(report["changes"][0])
    report["changes"][0] = {"id": "x", "kind": "added", "before": None, "after": None}
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(_diff()))
    # A bad expected raises against an otherwise genuine report.
    good = _diff()
    expected = _expected(good)
    expected["after_ids"] = []
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(good, expected)
    # Both changes must be validated together.
    report = _diff()
    report["changes"][0] = saved
    report["changes"][0]["id"] = "zzz"
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(_diff()))


# ---------------------------------------------------------------- endpoint


def test_http_valid_diff_is_200_compact_json():
    report = _diff()
    response = client.post(
        "/decision-matrix/attest/bundle/diff/verify",
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
        "/decision-matrix/attest/bundle/diff/verify",
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
        "/decision-matrix/attest/bundle/diff/verify",
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
        "/decision-matrix/attest/bundle/diff/verify",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_value_error_in_function_is_422():
    report = _diff()
    report["changes"] = []
    response = client.post(
        "/decision-matrix/attest/bundle/diff/verify",
        json={"report": report, "expected": _expected(_diff())},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
