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


# ---------------------------------------------------------------- structure


def test_top_level_and_change_key_order():
    report = _diff()
    assert list(report) == [
        "before_root",
        "after_root",
        "before",
        "after",
        "changes",
        "digest",
    ]
    assert [list(change) for change in report["changes"]] == [
        ["id", "kind", "before", "after"]
    ]


def test_roots_match_the_two_bundles():
    before = _bundle_before()
    after = _bundle_after()
    report = matrix_bundle_diff(before, after)
    assert report["before_root"] == before["root"]
    assert report["after_root"] == after["root"]


def test_before_and_after_are_normalized_bundle_copies():
    before = _bundle_before()
    after = _bundle_after()
    report = matrix_bundle_diff(before, after)
    assert report["before"] == before
    assert report["after"] == after
    assert report["before"] is not report["after"]
    assert report["before"] is not before
    assert report["after"] is not after


def test_added_change_shape():
    report = _diff()
    (change,) = report["changes"]
    assert change["id"] == "c"
    assert change["kind"] == "added"
    assert change["before"] is None
    assert change["after"] == _bundle_after()["reports"][-1]["report"]


def test_removed_change_shape():
    after = decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()}]
    )
    report = matrix_bundle_diff(_bundle_before(), after)
    (change,) = report["changes"]
    assert change["id"] == "b"
    assert change["kind"] == "removed"
    assert change["before"] == _bundle_before()["reports"][-1]["report"]
    assert change["after"] is None


def test_changed_change_shape():
    after = decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": _report_a()},
            {"id": "b", "report": _report_b_variant()},
        ]
    )
    report = matrix_bundle_diff(_bundle_before(), after)
    (change,) = report["changes"]
    assert change["id"] == "b"
    assert change["kind"] == "changed"
    assert change["before"] == _bundle_before()["reports"][-1]["report"]
    assert change["after"] == after["reports"][-1]["report"]


def test_added_and_removed_sorted_by_unicode_code_point():
    # before has b, after has c (a in both): removed b sorts before added c.
    before = decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()}, {"id": "b", "report": _report_b()}]
    )
    after = decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()}, {"id": "c", "report": _report_c()}]
    )
    report = matrix_bundle_diff(before, after)
    assert [(c["id"], c["kind"]) for c in report["changes"]] == [
        ("b", "removed"),
        ("c", "added"),
    ]


def test_unicode_ids_sort_by_code_point():
    before = decision_matrix_attestation_bundle(
        [{"id": "é", "report": _report_a()}]
    )
    after = decision_matrix_attestation_bundle(
        [
            {"id": "é", "report": _report_a()},
            {"id": "a", "report": _report_b()},
        ]
    )
    report = matrix_bundle_diff(before, after)
    assert [c["id"] for c in report["changes"]] == ["a"]


def test_identical_bundles_yield_empty_changes():
    bundle = _bundle_before()
    report = matrix_bundle_diff(bundle, bundle)
    assert report["changes"] == []
    assert report["before_root"] == report["after_root"] == bundle["root"]


def test_unchanged_member_is_omitted():
    report = _diff()
    assert "a" not in {change["id"] for change in report["changes"]}
    assert "b" not in {change["id"] for change in report["changes"]}


def test_digest_covers_first_five_items():
    report = _diff()
    payload = {
        "before_root": report["before_root"],
        "after_root": report["after_root"],
        "before": report["before"],
        "after": report["after"],
        "changes": report["changes"],
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert report["digest"] == expected
    assert len(report["digest"]) == 64


def test_equal_valued_inputs_are_byte_identical_regardless_of_dict_order():
    before = _bundle_before()
    after = _bundle_after()

    def reverse_key_order(value):
        if isinstance(value, dict):
            return {k: reverse_key_order(v) for k, v in reversed(list(value.items()))}
        if isinstance(value, list):
            return [reverse_key_order(item) for item in value]
        return value

    first = matrix_bundle_diff(before, after)
    second = matrix_bundle_diff(reverse_key_order(before), reverse_key_order(after))
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_layers_do_not_share_mutable_containers():
    before = _bundle_before()
    after = _bundle_after()
    report = matrix_bundle_diff(before, after)
    change = report["changes"][0]
    # The added credential is independent of the embedded after bundle copy.
    assert change["after"] is not None
    assert change["after"] is not report["after"]["reports"][-1]["report"]
    change["after"]["digest"] = "mutated"
    assert report["after"]["reports"][-1]["report"]["digest"] != "mutated"


def test_does_not_mutate_inputs():
    before = _bundle_before()
    after = _bundle_after()
    before_snapshot = copy.deepcopy(before)
    after_snapshot = copy.deepcopy(after)
    matrix_bundle_diff(before, after)
    assert before == before_snapshot
    assert after == after_snapshot


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "before,after",
    [
        (None, _bundle_after()),
        ("x", _bundle_after()),
        ([], _bundle_after()),
        ({}, _bundle_after()),
        ({"root": "0" * 64}, _bundle_after()),
        (_bundle_before(), None),
        (_bundle_before(), {}),
        (_bundle_before(), {"root": "0" * 64, "reports": []}),
    ],
)
def test_invalid_bundle_shape_raises(before, after):
    with pytest.raises(ValueError):
        matrix_bundle_diff(before, after)


def test_structurally_invalid_member_report_raises():
    before = copy.deepcopy(_bundle_before())
    before["reports"][0]["report"] = {"start": START}
    with pytest.raises(ValueError):
        matrix_bundle_diff(before, _bundle_after())


def test_false_bundle_root_raises():
    before = copy.deepcopy(_bundle_before())
    before["root"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_bundle_diff(before, _bundle_after())


def test_false_member_digest_raises():
    after = copy.deepcopy(_bundle_after())
    after["reports"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_bundle_diff(_bundle_before(), after)


def test_broken_member_chain_link_raises():
    before = copy.deepcopy(_bundle_before())
    before["reports"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_bundle_diff(before, _bundle_after())


def test_false_sub_report_digest_raises():
    after = copy.deepcopy(_bundle_after())
    after["reports"][0]["report"]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_bundle_diff(_bundle_before(), after)


def test_semantic_forgery_in_member_raises():
    before = copy.deepcopy(_bundle_before())
    before["reports"][0]["report"]["matrix"]["points"][0]["cases"][0][
        "decision"
    ] = "forged"
    with pytest.raises(ValueError):
        matrix_bundle_diff(before, _bundle_after())


def test_second_side_still_checked_when_first_summary_is_false():
    # before carries a format-valid but false root; that must not short-circuit
    # the full structural validation of the malformed after bundle.
    before = copy.deepcopy(_bundle_before())
    before["root"] = "f" * 64
    after = {"reports": [{"id": "a"}]}
    with pytest.raises(ValueError):
        matrix_bundle_diff(before, after)


def test_first_side_still_checked_when_second_summary_is_false():
    before = {"reports": "not-a-list"}
    after = copy.deepcopy(_bundle_after())
    after["root"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_bundle_diff(before, after)


# ---------------------------------------------------------------- endpoint


def test_http_diff_returns_200_compact_json():
    before = _bundle_before()
    after = _bundle_after()
    response = client.post(
        "/decision-matrix/attest/bundle/diff",
        json={"before": before, "after": after},
    )
    assert response.status_code == 200
    assert response.json() == matrix_bundle_diff(before, after)
    expected_body = json.dumps(
        matrix_bundle_diff(before, after), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert response.content == expected_body
    assert not response.content.endswith(b"\n")
    assert "允许" in response.content.decode("utf-8")


def test_http_diff_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("diff endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/decision-matrix/attest/bundle/diff",
        json={"before": _bundle_before(), "after": _bundle_after()},
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
        b'{"before": {}}',
        b'{"before": {}, "after": {}, "extra": 1}',
        b'{"earlier": {}, "later": {}}',
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
        json={"before": {"root": "0" * 64}, "after": _bundle_after()},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
