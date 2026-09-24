import copy

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


def _evolution():
    return matrix_bundle_evolution(
        [
            {
                "at": AT1,
                "bundle": decision_matrix_attestation_bundle(
                    [{"id": "a", "report": _report_a()}]
                ),
            },
            {
                "at": AT2,
                "bundle": decision_matrix_attestation_bundle(
                    [
                        {"id": "a", "report": _report_a()},
                        {"id": "b", "report": _report_b()},
                    ]
                ),
            },
            {
                "at": AT3,
                "bundle": decision_matrix_attestation_bundle(
                    [
                        {"id": "a", "report": _report_a()},
                        {"id": "b", "report": _report_b()},
                        {"id": "c", "report": _report_c()},
                    ]
                ),
            },
        ]
    )


def _proof_alpha():
    return evolution_checkpoint(_evolution(), AT1, AT2)


def _proof_alpha_variant():
    return evolution_checkpoint(_evolution(), AT1, AT1)


def _proof_beta():
    return evolution_checkpoint(_evolution(), AT2, AT3)


def _proof_gamma():
    return evolution_checkpoint(_evolution(), AT3, AT3)


def _proof_delta():
    return evolution_checkpoint(_evolution(), AT2, AT2)


def _bundle_before():
    return evolution_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _proof_alpha()},
            {"id": "beta", "proof": _proof_beta()},
            {"id": "delta", "proof": _proof_delta()},
        ]
    )


def _bundle_after():
    return evolution_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _proof_alpha_variant()},
            {"id": "delta", "proof": _proof_delta()},
            {"id": "伽马", "proof": _proof_gamma()},
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
    assert verify_evolution_checkpoint_bundle_diff(report, _expected(report)) is True


def test_verifies_empty_change_diff():
    bundle = _bundle_before()
    report = evolution_checkpoint_bundle_diff(bundle, bundle)
    assert verify_evolution_checkpoint_bundle_diff(report, _expected(report)) is True


def test_expected_id_arrays_accept_arbitrary_order():
    report = _diff()
    expected = _expected(
        report, before_ids=["delta", "beta", "alpha"], after_ids=["伽马", "delta", "alpha"]
    )
    assert verify_evolution_checkpoint_bundle_diff(report, expected) is True


def test_does_not_mutate_inputs():
    report = _diff()
    expected = _expected(report)
    report_snapshot = copy.deepcopy(report)
    expected_snapshot = copy.deepcopy(expected)
    verify_evolution_checkpoint_bundle_diff(report, expected)
    assert report == report_snapshot
    assert expected == expected_snapshot


# ------------------------------------------------------------- false -> bool


def test_tampered_diff_digest_returns_false():
    report = _diff()
    report["digest"] = "f" * 64
    assert verify_evolution_checkpoint_bundle_diff(report, _expected(report)) is False


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
        report, _expected(report, before_ids=["alpha"])
    ) is False
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report, before_ids=["alpha", "beta", "delta", "x"])
    ) is False


def test_expected_after_id_set_mismatch_returns_false():
    report = _diff()
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report, after_ids=["alpha", "delta"])
    ) is False
    assert verify_evolution_checkpoint_bundle_diff(
        report, _expected(report, after_ids=["alpha", "delta", "伽马", "x"])
    ) is False


def test_false_member_digest_in_embedded_bundle_returns_false():
    report = _diff()
    report["before"]["proofs"][0]["digest"] = "e" * 64
    assert verify_evolution_checkpoint_bundle_diff(report, _expected(report)) is False


def test_false_bundle_member_link_returns_false():
    report = _diff()
    report["after"]["proofs"][1]["previous"] = "f" * 64
    assert verify_evolution_checkpoint_bundle_diff(report, _expected(report)) is False


def test_false_bundle_root_returns_false():
    report = _diff()
    # Keep the top-level before_root consistent so the unsupported root is
    # the only thing at stake.
    report["before"]["root"] = "f" * 64
    report["before_root"] = "f" * 64
    expected = _expected(report)
    expected["before_root"] = "f" * 64
    assert verify_evolution_checkpoint_bundle_diff(report, expected) is False


def test_false_stage_digest_in_change_side_only_raises():
    report = _diff()
    changed = next(c for c in report["changes"] if c["kind"] == "changed")
    changed["after"]["stages"][0]["digest"] = "f" * 64
    # The after bundle still carries the true proof, so the change side no
    # longer equals its bundle member: a structural/classification violation.
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_false_stage_digest_everywhere_returns_false():
    report = _diff()
    member = report["after"]["proofs"][0]
    assert member["id"] == "alpha"
    member["proof"]["stages"][0]["digest"] = "f" * 64
    for change in report["changes"]:
        if change["id"] == "alpha":
            change["after"]["stages"][0]["digest"] = "f" * 64
    # Structural validation still passes; proof recomputation yields False.
    assert verify_evolution_checkpoint_bundle_diff(report, _expected(report)) is False


def test_false_change_proof_recomputation_returns_false():
    report = _diff()
    added = next(c for c in report["changes"] if c["kind"] == "added")
    member = next(m for m in report["after"]["proofs"] if m["id"] == "伽马")
    added["after"]["commitment"] = "f" * 64
    member["proof"]["commitment"] = "f" * 64
    assert verify_evolution_checkpoint_bundle_diff(report, _expected(report)) is False


# ------------------------------------------------------------- change set


def test_missing_change_returns_false():
    report = _diff()
    report["changes"] = []
    assert verify_evolution_checkpoint_bundle_diff(report, _expected(report)) is False


def test_extra_change_for_unchanged_member_returns_false():
    report = _diff()
    unchanged = next(
        member for member in report["after"]["proofs"] if member["id"] == "delta"
    )
    extra = {
        "id": "delta",
        "kind": "changed",
        "before": copy.deepcopy(unchanged["proof"]),
        "after": copy.deepcopy(unchanged["proof"]),
    }
    # Insert in code point order (alpha, beta, delta, 伽马) so the structural
    # checks pass; only the rebuilt change set disagrees.
    ids = [change["id"] for change in report["changes"]]
    report["changes"].insert(ids.index("伽马"), extra)
    assert verify_evolution_checkpoint_bundle_diff(report, _expected(report)) is False


def test_change_for_unknown_id_raises():
    report = _diff()
    extra = copy.deepcopy(report["changes"][0])
    extra["id"] = "zzz"
    report["changes"].append(extra)
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_wrong_kind_raises():
    # beta is removed between the bundles, not changed/added.
    report = _diff()
    removed = next(c for c in report["changes"] if c["id"] == "beta")
    removed["kind"] = "changed"
    removed["after"] = copy.deepcopy(removed["before"])
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_added_change_with_non_null_before_raises():
    report = _diff()
    added = next(c for c in report["changes"] if c["kind"] == "added")
    added["before"] = _proof_beta()
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_changed_side_not_equal_to_member_raises():
    report = _diff()
    changed = next(c for c in report["changes"] if c["kind"] == "changed")
    changed["after"] = copy.deepcopy(changed["before"])
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_unsorted_change_ids_raise():
    report = _diff()
    report["changes"].reverse()
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_duplicate_change_id_raises():
    report = _diff()
    report["changes"].append(copy.deepcopy(report["changes"][0]))
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


def test_invalid_proof_inside_change_raises():
    report = _diff()
    report["changes"][0]["before"] = {"start": START}
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, _expected(report))


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
    del report["changes"][0]["kind"]
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
            "before_ids": ["alpha"],
            "after_ids": ["alpha"],
        },
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before_ids": ["alpha"],
            "after_ids": ["alpha"],
            "digest": "0" * 64,
            "extra": 1,
        },
        {
            "before_root": "x",
            "after_root": "0" * 64,
            "before_ids": ["alpha"],
            "after_ids": ["alpha"],
            "digest": "0" * 64,
        },
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before_ids": [],
            "after_ids": ["alpha"],
            "digest": "0" * 64,
        },
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before_ids": ["alpha"],
            "after_ids": ["alpha", "alpha"],
            "digest": "0" * 64,
        },
        {
            "before_root": "0" * 64,
            "after_root": "0" * 64,
            "before_ids": ["alpha"],
            "after_ids": ["alpha", 1],
            "digest": "0" * 64,
        },
    ],
)
def test_bad_expected_shape_raises(expected):
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(_diff(), expected)


def test_structure_validated_before_value_comparison():
    # A bad expected raises against an otherwise genuine report.
    good = _diff()
    expected = _expected(good)
    expected["after_ids"] = []
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(good, expected)
    # Structural invalidity in the report raises even when expected is also
    # bad — both sides are validated first.
    report = _diff()
    report["changes"][0]["id"] = "zzz"
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle_diff(report, expected)


# ---------------------------------------------------------------- endpoint


def test_http_verify_true():
    report = _diff()
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_verify_false():
    report = _diff()
    report["digest"] = "f" * 64
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/verify",
        json={"report": report, "expected": _expected(_diff())},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":false}'


def test_http_verify_works_without_history(monkeypatch):
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
    assert response.content == b'{"valid":true}'


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b'"x"',
        b"null",
        b"{}",
        b'{"report": {}}',
        b'{"expected": {}}',
        b'{"report": {}, "expected": {}, "extra": 1}',
        b'{"report": {"root": "0"}, "expected": {"root": "0", "before_ids": []}}',
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
    report["changes"] = {}
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/verify",
        json={"report": report, "expected": _expected(_diff())},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
