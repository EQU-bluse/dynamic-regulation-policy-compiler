import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    matrix_bundle_diff,
    matrix_bundle_evolution,
    verify_matrix_bundle_evolution,
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


def _report_a():
    return decision_matrix_attestation(
        START, END, [{"id": "c1", "facts": {"x": True}}],
        [_rule(id="a", **{"from": START}, when={"x": True}, result="允许")],
    )


def _report_b():
    return decision_matrix_attestation(
        START, END, [{"id": "c2", "facts": {}}], [_rule(id="b", result="z")]
    )


def _report_b_variant():
    return decision_matrix_attestation(
        START, END, [{"id": "c2", "facts": {}}], [_rule(id="b", result="zz")]
    )


def _bundle_zero():
    return decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()}]
    )


def _bundle_one():
    return decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": _report_a()},
            {"id": "b", "report": _report_b()},
        ]
    )


def _bundle_two():
    return decision_matrix_attestation_bundle(
        [{"id": "b", "report": _report_b_variant()}]
    )


def _stages():
    return [
        {"at": START, "bundle": _bundle_zero()},
        {"at": MID, "bundle": _bundle_one()},
        {"at": END, "bundle": _bundle_two()},
    ]


def _report():
    return matrix_bundle_evolution(_stages())


def _expected(report=None):
    report = report or _report()
    return {
        "root": report["root"],
        "stages": [
            {"at": stage["at"], "root": stage["bundle"]["root"]}
            for stage in report["stages"]
        ],
    }


# ---------------------------------------------------------------- genuine


def test_verifies_genuine_report():
    report = _report()
    assert verify_matrix_bundle_evolution(report, _expected(report)) is True


def test_verifies_single_stage_report():
    report = matrix_bundle_evolution([{"at": START, "bundle": _bundle_zero()}])
    assert verify_matrix_bundle_evolution(report, _expected(report)) is True


def test_verifies_report_with_adjacent_identical_bundles():
    stages = [
        {"at": START, "bundle": _bundle_zero()},
        {"at": MID, "bundle": _bundle_zero()},
    ]
    report = matrix_bundle_evolution(stages)
    assert verify_matrix_bundle_evolution(report, _expected(report)) is True
    # The adjacent diff is genuine and carries an empty changes list.
    assert report["stages"][1]["diff"]["changes"] == []


def test_expected_stage_order_is_caller_independent_for_contents():
    report = _report()
    expected = _expected(report)
    # Expected stage pairs are positional; values may be reordered dicts.
    for stage in expected["stages"]:
        assert set(stage) == {"at", "root"}
    assert verify_matrix_bundle_evolution(report, expected) is True


# ---------------------------------------------------------- False, not raise


def _assert_false(report):
    assert verify_matrix_bundle_evolution(report, _expected(_report())) is False


def test_false_report_root_returns_false():
    report = _report()
    report["root"] = "f" * 64
    _assert_false(report)


def test_false_stage_digest_returns_false():
    report = _report()
    report["stages"][1]["digest"] = "f" * 64
    _assert_false(report)


def test_broken_previous_link_returns_false():
    report = _report()
    report["stages"][2]["previous"] = "f" * 64
    _assert_false(report)


def test_false_diff_digest_returns_false():
    report = _report()
    report["stages"][2]["diff"]["digest"] = "f" * 64
    _assert_false(report)


def test_false_bundle_root_returns_false():
    report = _report()
    report["stages"][1]["bundle"]["root"] = "f" * 64
    _assert_false(report)


def test_false_member_digest_returns_false():
    report = _report()
    report["stages"][1]["bundle"]["reports"][0]["digest"] = "f" * 64
    _assert_false(report)


def test_false_diff_change_side_digest_returns_false():
    report = _report()
    report["stages"][1]["diff"]["changes"][0]["after"]["digest"] = "f" * 64
    _assert_false(report)


def test_false_diff_root_returns_false():
    report = _report()
    report["stages"][1]["diff"]["before_root"] = "f" * 64
    report["stages"][1]["diff"]["before"]["root"] = "f" * 64
    _assert_false(report)


def test_expected_root_mismatch_returns_false():
    expected = _expected()
    expected["root"] = "f" * 64
    assert verify_matrix_bundle_evolution(_report(), expected) is False


def test_expected_stage_root_mismatch_returns_false():
    expected = _expected()
    expected["stages"][0]["root"] = _bundle_one()["root"]
    assert verify_matrix_bundle_evolution(_report(), expected) is False


def test_expected_stage_at_mismatch_returns_false():
    report = _report()
    expected = _expected(report)
    expected["stages"][1]["at"] = "2021-03-01T00:00:00Z"
    assert verify_matrix_bundle_evolution(report, expected) is False


def test_expected_stage_count_mismatch_returns_false():
    report = _report()
    expected = _expected(report)
    expected["stages"] = expected["stages"][:2]
    assert verify_matrix_bundle_evolution(report, expected) is False


# ------------------------------------------------------------- ValueError


@pytest.mark.parametrize(
    "report",
    [
        None,
        "x",
        123,
        [],
        {},
        {"root": "0" * 64},
        {"stages": []},
        {"root": "0" * 64, "stages": []},
        {"root": "0" * 64, "stages": [{}]},
        {"root": "0" * 64, "stages": [{"at": START, "bundle": _bundle_zero()}]},
    ],
)
def test_bad_report_shape_raises(report):
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, _expected())


def test_bad_root_format_raises():
    report = _report()
    report["root"] = "Z" * 64
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, _expected())


def test_non_increasing_stage_at_raises():
    report = _report()
    report["stages"][1]["at"] = report["stages"][2]["at"]
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, _expected())


def test_invalid_stage_at_raises():
    report = _report()
    report["stages"][0]["at"] = "bad"
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, _expected())


def test_extra_stage_key_raises():
    report = _report()
    report["stages"][0]["extra"] = 1
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, _expected())


def test_bad_bundle_structure_raises():
    report = _report()
    report["stages"][0]["bundle"] = {"root": "0" * 64}
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, _expected())


def test_semantic_forgery_in_bundle_raises():
    report = _report()
    report["stages"][1]["bundle"]["reports"][0]["report"]["matrix"]["points"][0][
        "cases"
    ][0]["decision"] = "forged"
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, _expected())


def test_first_stage_diff_must_be_null():
    report = _report()
    report["stages"][0]["diff"] = matrix_bundle_diff(_bundle_zero(), _bundle_one())
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, _expected())


def test_first_stage_diff_null_format_is_strict():
    report = _report()
    report["stages"][0]["diff"] = {}
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, _expected())


def test_later_diff_must_describe_the_adjacent_pair():
    report = _report()
    report["stages"][2]["diff"] = matrix_bundle_diff(_bundle_zero(), _bundle_two())
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, _expected())


def test_later_diff_with_bad_shape_raises():
    report = _report()
    report["stages"][1]["diff"] = {"digest": "0" * 64}
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, _expected())


def test_later_diff_with_forged_change_raises():
    report = _report()
    report["stages"][1]["diff"]["changes"][0]["kind"] = "removed"
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, _expected())


def test_later_diff_with_extra_change_raises():
    report = _report()
    # An unchanged member ("a") must not be listed.
    stage_diff = report["stages"][1]["diff"]
    stage_diff["changes"].insert(
        0,
        {
            "id": "a",
            "kind": "changed",
            "before": _report_a(),
            "after": _report_a(),
        },
    )
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, _expected())


@pytest.mark.parametrize(
    "expected",
    [
        None,
        "x",
        [],
        {},
        {"root": "0" * 64},
        {"stages": []},
        {"root": "0" * 64, "stages": []},
        {"root": "0" * 64, "stages": [{}]},
        {"root": "0" * 64, "stages": [{"at": START}]},
        {"root": "0" * 64, "stages": [{"root": "0" * 64}]},
        {"root": "0" * 64, "stages": [{"at": "bad", "root": "0" * 64}]},
        {"root": "0" * 64, "stages": [{"at": START, "root": "Z" * 64}]},
    ],
)
def test_bad_expected_shape_raises(expected):
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(_report(), expected)


def test_expected_with_non_increasing_at_raises():
    report = _report()
    expected = _expected(report)
    expected["stages"][1]["at"] = expected["stages"][0]["at"]
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, expected)


def test_structural_validation_runs_before_any_false_comparison():
    # A format-valid but false root must not mask a structurally invalid
    # expected: structural checks on both inputs finish first and raise.
    report = _report()
    report["root"] = "f" * 64
    with pytest.raises(ValueError):
        verify_matrix_bundle_evolution(report, {"root": "0" * 64, "stages": []})


def test_does_not_mutate_inputs():
    report = _report()
    expected = _expected(report)
    report_snapshot = copy.deepcopy(report)
    expected_snapshot = copy.deepcopy(expected)
    verify_matrix_bundle_evolution(report, expected)
    assert report == report_snapshot
    assert expected == expected_snapshot


# ---------------------------------------------------------------- endpoint


def test_http_verify_accepts_genuine_report():
    report = _report()
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_verify_returns_false_for_tampered_report():
    report = _report()
    report["root"] = "f" * 64
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/verify",
        json={"report": report, "expected": _expected()},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":false}'


def test_http_verify_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("evolution verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/verify",
        json={"report": _report(), "expected": _expected()},
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
        b'{"report": {}, "expected": {}}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/verify",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_value_error_in_function_is_422():
    report = _report()
    report["stages"][0]["extra"] = 1
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/verify",
        json={"report": report, "expected": _expected()},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
