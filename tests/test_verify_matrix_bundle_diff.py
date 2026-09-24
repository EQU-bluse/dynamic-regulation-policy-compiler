import copy
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


def _report_x(value):
    return decision_matrix_attestation(
        START, END, [{"id": "c1", "facts": {"x": value}}], _changing_rules()
    )


def _report_static(result):
    return decision_matrix_attestation(
        START, END, [{"id": "c2", "facts": {}}], [_rule(result=result)]
    )


def _before_bundle():
    return decision_matrix_attestation_bundle(
        [
            {"id": "m", "report": _report_x(True)},
            {"id": "b", "report": _report_static("z")},
            {"id": "a", "report": _report_x(True)},
        ]
    )


def _after_bundle():
    return decision_matrix_attestation_bundle(
        [
            {"id": "n", "report": _report_static("z")},
            {"id": "a", "report": _report_x(False)},
            {"id": "m", "report": _report_x(True)},
        ]
    )


def _diff():
    return matrix_bundle_diff(_before_bundle(), _after_bundle())


def _ids(bundle):
    return [member["id"] for member in bundle["reports"]]


def _expected(diff, before=None, after=None):
    before = before or _before_bundle()
    after = after or _after_bundle()
    return {
        "before_root": diff["before_root"],
        "after_root": diff["after_root"],
        "before_ids": _ids(before),
        "after_ids": _ids(after),
        "digest": diff["digest"],
    }


# ----------------------------------------------------------------- genuine


def test_verifies_genuine_diff():
    diff = _diff()
    assert verify_matrix_bundle_diff(diff, _expected(diff)) is True


def test_expected_id_arrays_accept_arbitrary_order():
    diff = _diff()
    expected = _expected(diff)
    expected["before_ids"] = list(reversed(expected["before_ids"]))
    expected["after_ids"] = list(reversed(expected["after_ids"]))
    assert verify_matrix_bundle_diff(diff, expected) is True


def test_verifies_identical_bundle_diff():
    before = _before_bundle()
    diff = matrix_bundle_diff(before, copy.deepcopy(before))
    expected = {
        "before_root": diff["before_root"],
        "after_root": diff["after_root"],
        "before_ids": list(reversed(_ids(before))),
        "after_ids": _ids(before),
        "digest": diff["digest"],
    }
    assert verify_matrix_bundle_diff(diff, expected) is True


def test_does_not_mutate_inputs():
    diff = _diff()
    expected = _expected(diff)
    diff_before = copy.deepcopy(diff)
    expected_before = copy.deepcopy(expected)
    verify_matrix_bundle_diff(diff, expected)
    assert diff == diff_before
    assert expected == expected_before


# ------------------------------------------------------------ false -> bool


def test_tampered_diff_digest_returns_false():
    diff = _diff()
    diff["digest"] = "f" * 64
    assert verify_matrix_bundle_diff(diff, _expected(diff)) is False


def test_forged_before_root_returns_false():
    diff = _diff()
    diff["before_root"] = "f" * 64
    assert verify_matrix_bundle_diff(diff, _expected(diff)) is False


def test_forged_after_root_returns_false():
    diff = _diff()
    diff["after_root"] = "f" * 64
    assert verify_matrix_bundle_diff(diff, _expected(diff)) is False


def test_false_sub_report_digest_returns_false():
    diff = _diff()
    diff["before"]["reports"][0]["report"]["digest"] = "f" * 64
    assert verify_matrix_bundle_diff(diff, _expected(diff)) is False


def test_broken_chain_link_returns_false():
    diff = _diff()
    diff["after"]["reports"][1]["previous"] = "f" * 64
    assert verify_matrix_bundle_diff(diff, _expected(diff)) is False


def test_forged_bundle_root_inside_diff_returns_false():
    diff = _diff()
    diff["after"]["root"] = "f" * 64
    assert verify_matrix_bundle_diff(diff, _expected(diff)) is False


def test_expected_root_mismatch_returns_false():
    diff = _diff()
    expected = _expected(diff)
    expected["before_root"] = "f" * 64
    assert verify_matrix_bundle_diff(diff, expected) is False


def test_expected_digest_mismatch_returns_false():
    diff = _diff()
    expected = _expected(diff)
    expected["digest"] = "f" * 64
    assert verify_matrix_bundle_diff(diff, expected) is False


@pytest.mark.parametrize(
    "field,bad_ids",
    [
        ("before_ids", ["a", "b"]),
        ("before_ids", ["a", "b", "m", "x"]),
        ("after_ids", ["a", "m"]),
        ("after_ids", ["a", "m", "n", "x"]),
    ],
)
def test_expected_id_set_mismatch_returns_false(field, bad_ids):
    diff = _diff()
    expected = _expected(diff)
    expected[field] = bad_ids
    assert verify_matrix_bundle_diff(diff, expected) is False


# ------------------------------------------------------------- invalid shape


def test_forged_change_kind_raises_value_error():
    diff = _diff()
    diff["changes"][0]["kind"] = "added"
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(diff, _expected(diff))


def test_missing_change_entry_raises_value_error():
    diff = _diff()
    diff["changes"].pop()
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(diff, _expected(diff))


def test_extra_change_entry_raises_value_error():
    diff = _diff()
    diff["changes"].append(copy.deepcopy(diff["changes"][0]))
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(diff, _expected(diff))


def test_unsorted_changes_raise_value_error():
    diff = _diff()
    diff["changes"].reverse()
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(diff, _expected(diff))


def test_duplicate_change_id_raises_value_error():
    diff = _diff()
    diff["changes"][1] = copy.deepcopy(diff["changes"][0])
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(diff, _expected(diff))


def test_change_side_not_matching_kind_raises_value_error():
    diff = _diff()
    # The first entry is 'changed'; nulling a side violates the kind.
    diff["changes"][0]["after"] = None
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(diff, _expected(diff))


def test_structurally_invalid_change_side_raises_value_error():
    diff = _diff()
    diff["changes"][0]["before"] = {"start": START}
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(diff, _expected(diff))


def test_semantic_forgery_in_change_side_raises_value_error():
    diff = _diff()
    diff["changes"][0]["before"]["matrix"]["points"][0]["cases"][0][
        "decision"
    ] = "forged"
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(diff, _expected(diff))


def test_unsorted_embedded_bundle_members_raise_value_error():
    diff = _diff()
    diff["before"]["reports"].reverse()
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(diff, _expected(diff))


@pytest.mark.parametrize(
    "report",
    [
        None,
        [],
        "x",
        {},
        {"before_root": "0" * 64},
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before": {},
            "after": {},
            "changes": [],
        },
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before": {},
            "after": {},
            "changes": [],
            "digest": "0" * 64,
            "extra": 1,
        },
        {
            "before_root": "X" * 64,
            "after_root": "0" * 64,
            "before": {},
            "after": {},
            "changes": [],
            "digest": "0" * 64,
        },
    ],
)
def test_bad_report_shape_raises_value_error(report):
    diff = _diff()
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(report, _expected(diff))


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
            "before_ids": ["a", "a"],
            "after_ids": ["a"],
            "digest": "0" * 64,
        },
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before_ids": ["a"],
            "after_ids": [1],
            "digest": "0" * 64,
        },
    ],
)
def test_bad_expected_shape_raises_value_error(expected):
    diff = _diff()
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(diff, expected)


def test_structure_validated_before_value_comparison():
    # A structurally illegal report raises even if its digest-looking
    # fields happen to line up.
    diff = _diff()
    diff["after"] = {"root": "0" * 64, "reports": []}
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(diff, _expected(diff))
    # An illegal expected raises regardless of a genuine report.
    good = _diff()
    expected = _expected(good)
    expected["after_ids"] = []
    with pytest.raises(ValueError):
        verify_matrix_bundle_diff(good, expected)


# ---------------------------------------------------------------- endpoint


def test_http_valid_diff_is_200_compact_json():
    response = client.post(
        "/decision-matrix/attest/bundle/diff/verify",
        json={"report": _diff(), "expected": _expected(_diff())},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_tampered_diff_is_200_false():
    diff = _diff()
    diff["digest"] = "f" * 64
    response = client.post(
        "/decision-matrix/attest/bundle/diff/verify",
        json={"report": diff, "expected": _expected(_diff())},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": False}


def test_http_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/decision-matrix/attest/bundle/diff/verify",
        json={"report": _diff(), "expected": _expected(_diff())},
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
    diff = _diff()
    diff["changes"].reverse()
    response = client.post(
        "/decision-matrix/attest/bundle/diff/verify",
        json={"report": diff, "expected": _expected(_diff())},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
