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
            {"id": "é", "report": _report_static("z")},
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
            {"id": "é", "report": _report_static("q")},
            {"id": "m", "report": _report_x(True)},
        ]
    )


def _diff():
    return matrix_bundle_diff(_before_bundle(), _after_bundle())


# ---------------------------------------------------------------- structure


def test_top_level_key_order():
    diff = _diff()
    assert list(diff) == [
        "before_root",
        "after_root",
        "before",
        "after",
        "changes",
        "digest",
    ]


def test_change_entry_key_order():
    diff = _diff()
    assert [list(change) for change in diff["changes"]] == [
        ["id", "kind", "before", "after"]
    ] * len(diff["changes"])


def test_roots_match_the_two_bundles():
    before = _before_bundle()
    after = _after_bundle()
    diff = matrix_bundle_diff(before, after)
    assert diff["before_root"] == before["root"]
    assert diff["after_root"] == after["root"]


def test_before_after_are_normalized_bundle_copies():
    before = _before_bundle()
    after = _after_bundle()
    diff = matrix_bundle_diff(before, after)
    assert diff["before"] == before
    assert diff["after"] == after
    assert list(diff["before"]) == ["root", "reports"]


def test_changes_match_added_removed_changed_members():
    diff = _diff()
    by_id = {change["id"]: change for change in diff["changes"]}
    # m is unchanged and must be omitted.
    assert list(by_id) == ["a", "b", "n", "é"]
    assert by_id["a"]["kind"] == "changed"
    assert by_id["b"]["kind"] == "removed"
    assert by_id["n"]["kind"] == "added"
    assert by_id["é"]["kind"] == "changed"


def test_changes_sorted_by_unicode_code_point():
    diff = _diff()
    ids = [change["id"] for change in diff["changes"]]
    assert ids == sorted(ids)
    assert ids == ["a", "b", "n", "é"]


def test_change_sides_are_reports_or_null_by_kind():
    diff = _diff()
    for change in diff["changes"]:
        if change["kind"] == "added":
            assert change["before"] is None
            assert change["after"] is not None
        elif change["kind"] == "removed":
            assert change["before"] is not None
            assert change["after"] is None
        else:
            assert change["before"] is not None
            assert change["after"] is not None


def test_identical_bundles_yield_empty_changes():
    before = _before_bundle()
    diff = matrix_bundle_diff(before, copy.deepcopy(before))
    assert diff["changes"] == []
    assert diff["before_root"] == diff["after_root"] == before["root"]


def test_digest_is_sha256_of_the_first_five_fields():
    diff = _diff()
    payload = {
        "before_root": diff["before_root"],
        "after_root": diff["after_root"],
        "before": diff["before"],
        "after": diff["after"],
        "changes": diff["changes"],
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert diff["digest"] == expected
    assert len(diff["digest"]) == 64


def test_byte_identical_regardless_of_input_key_order():
    before = _before_bundle()
    after = _after_bundle()
    first = matrix_bundle_diff(before, after)

    def reorder(value):
        if isinstance(value, dict):
            return {key: reorder(value[key]) for key in reversed(list(value))}
        if isinstance(value, list):
            return [reorder(item) for item in value]
        return value

    second = matrix_bundle_diff(reorder(before), reorder(after))
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == (
        json.dumps(second, ensure_ascii=False, separators=(",", ":"))
    )


def test_does_not_mutate_inputs():
    before = _before_bundle()
    after = _after_bundle()
    before_before = copy.deepcopy(before)
    after_before = copy.deepcopy(after)
    matrix_bundle_diff(before, after)
    assert before == before_before
    assert after == after_before


def test_no_shared_mutable_containers():
    before = _before_bundle()
    after = _after_bundle()
    diff = matrix_bundle_diff(before, after)
    diff["before"]["root"] = "f" * 64
    diff["after"]["reports"][0]["id"] = "zzz"
    diff["changes"][0]["before"]["digest"] = "e" * 64
    assert before["root"] != "f" * 64
    assert after["reports"][0]["id"] != "zzz"
    original_a = next(
        member for member in before["reports"] if member["id"] == "a"
    )
    assert original_a["report"]["digest"] != "e" * 64


def test_result_levels_do_not_share_containers():
    diff = _diff()
    # The same source credential (m) appears only inside the two bundles;
    # the changed a-side appears both embedded and in a change entry, yet the
    # copies must be independent.
    diff["changes"][0]["after"]["digest"] = "d" * 64
    after_a = next(
        member for member in diff["after"]["reports"] if member["id"] == "a"
    )
    assert after_a["report"]["digest"] != "d" * 64


# ----------------------------------------------------------------- errors


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        "x",
        {},
        {"root": "0" * 64},
        {"root": "0" * 64, "reports": []},
        {"root": "F" * 64, "reports": []},
    ],
)
def test_invalid_before_raises_value_error(bad):
    with pytest.raises(ValueError):
        matrix_bundle_diff(bad, _after_bundle())


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        {},
        {"root": "0" * 64, "reports": []},
    ],
)
def test_invalid_after_raises_value_error(bad):
    with pytest.raises(ValueError):
        matrix_bundle_diff(_before_bundle(), bad)


def test_false_sub_report_digest_raises_value_error():
    after = _after_bundle()
    after["reports"][0]["report"]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_bundle_diff(_before_bundle(), after)


def test_false_bundle_root_raises_value_error():
    after = _after_bundle()
    after["root"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_bundle_diff(_before_bundle(), after)


def test_broken_chain_link_raises_value_error():
    after = _after_bundle()
    after["reports"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_bundle_diff(_before_bundle(), after)


def test_digest_mismatch_does_not_mask_other_end_structure_error():
    # A false sub digest on the before end must not skip structural
    # validation of the after end: an independently malformed after still
    # surfaces as ValueError (it would do so with a valid before too).
    before = _before_bundle()
    before["reports"][0]["report"]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_bundle_diff(before, {"root": "0" * 64, "reports": []})


# ---------------------------------------------------------------- endpoint


def test_http_valid_diff_is_200_compact_json():
    response = client.post(
        "/decision-matrix/attest/bundle/diff",
        json={"before": _before_bundle(), "after": _after_bundle()},
    )
    assert response.status_code == 200
    assert not response.content.endswith(b"\n")
    assert response.json() == _diff()


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b'"x"',
        b"null",
        b"{}",
        b'{"before": {}}',
        b'{"before": {}, "after": {}, "extra": 1}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        "/decision-matrix/attest/bundle/diff",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_value_error_in_function_is_422():
    response = client.post(
        "/decision-matrix/attest/bundle/diff",
        json={
            "before": {"root": "0" * 64, "reports": []},
            "after": _after_bundle(),
        },
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
