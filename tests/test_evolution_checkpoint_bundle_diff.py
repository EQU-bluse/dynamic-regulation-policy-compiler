import copy
import hashlib
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
    # Same member id, different complete proof (a shorter window).
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
        ["id", "kind", "before", "after"],
        ["id", "kind", "before", "after"],
        ["id", "kind", "before", "after"],
    ]


def test_changes_classified_and_sorted_by_code_point():
    report = _diff()
    assert [(c["id"], c["kind"]) for c in report["changes"]] == [
        ("alpha", "changed"),
        ("beta", "removed"),
        ("伽马", "added"),
    ]


def test_roots_match_the_two_bundles():
    before = _bundle_before()
    after = _bundle_after()
    report = evolution_checkpoint_bundle_diff(before, after)
    assert report["before_root"] == before["root"]
    assert report["after_root"] == after["root"]


def test_before_and_after_are_normalized_independent_bundle_copies():
    before = _bundle_before()
    after = _bundle_after()
    report = evolution_checkpoint_bundle_diff(before, after)
    assert report["before"] == before
    assert report["after"] == after
    assert report["before"] is not before
    assert report["after"] is not after
    assert report["before"] is not report["after"]


def test_added_change_shape():
    (change,) = [c for c in _diff()["changes"] if c["kind"] == "added"]
    assert change["id"] == "伽马"
    assert change["before"] is None
    assert change["after"] == _proof_gamma()


def test_removed_change_shape():
    (change,) = [c for c in _diff()["changes"] if c["kind"] == "removed"]
    assert change["id"] == "beta"
    assert change["before"] == _proof_beta()
    assert change["after"] is None


def test_changed_change_shape():
    (change,) = [c for c in _diff()["changes"] if c["kind"] == "changed"]
    assert change["id"] == "alpha"
    assert change["before"] == _proof_alpha()
    assert change["after"] == _proof_alpha_variant()


def test_unchanged_member_is_omitted():
    assert all(c["id"] != "delta" for c in _diff()["changes"])


def test_identical_bundles_yield_empty_changes():
    bundle = _bundle_before()
    report = evolution_checkpoint_bundle_diff(bundle, bundle)
    assert report["changes"] == []
    assert report["before_root"] == report["after_root"] == bundle["root"]


def test_digest_is_sha256_of_compact_five_key_prefix():
    report = _diff()
    payload = {
        "before_root": report["before_root"],
        "after_root": report["after_root"],
        "before": report["before"],
        "after": report["after"],
        "changes": report["changes"],
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    assert report["digest"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert not json.dumps(report, ensure_ascii=False).endswith("\n")


def test_equal_inputs_are_byte_identical_regardless_of_dict_order():
    def reordered(value):
        if isinstance(value, dict):
            return {k: reordered(v) for k, v in reversed(list(value.items()))}
        if isinstance(value, list):
            return [reordered(item) for item in value]
        return value

    before = _bundle_before()
    after = _bundle_after()
    first = evolution_checkpoint_bundle_diff(before, after)
    second = evolution_checkpoint_bundle_diff(reordered(before), reordered(after))
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == (
        json.dumps(second, ensure_ascii=False, separators=(",", ":"))
    )


def test_inputs_and_result_do_not_share_containers():
    before = _bundle_before()
    after = _bundle_after()
    before_snapshot = copy.deepcopy(before)
    after_snapshot = copy.deepcopy(after)
    report = evolution_checkpoint_bundle_diff(before, after)
    assert before == before_snapshot
    assert after == after_snapshot
    report["changes"][0]["before"]["anchor"] = "f" * 64
    report["before"]["root"] = "e" * 64
    assert before == before_snapshot
    assert after == after_snapshot
    assert _diff()["changes"][0] is not _diff()["changes"][0]


def test_change_sides_are_independent_deep_copies():
    report = _diff()
    changed = next(c for c in report["changes"] if c["kind"] == "changed")
    assert changed["before"] is not changed["after"]
    assert changed["before"] is not report["before"]["proofs"][0]["proof"]
    assert changed["after"] is not report["after"]["proofs"][0]["proof"]


# ----------------------------------------------------------------- rejection


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        "x",
        {},
        {"root": "0" * 64},
        {"root": "0" * 64, "proofs": []},
        {"root": "0" * 64, "proofs": [{"id": "a"}], "extra": 1},
    ],
)
def test_structurally_invalid_side_raises(bad):
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle_diff(bad, _bundle_after())
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle_diff(_bundle_before(), bad)


def test_forged_member_digest_raises():
    bad = _bundle_before()
    bad["proofs"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle_diff(bad, _bundle_after())


def test_forged_bundle_root_raises():
    bad = _bundle_before()
    bad["root"] = "f" * 64
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle_diff(bad, _bundle_after())


def test_unordered_members_raise():
    bad = _bundle_before()
    bad["proofs"] = list(reversed(bad["proofs"]))
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle_diff(bad, _bundle_after())


def test_forged_proof_inside_member_raises():
    bad = _bundle_before()
    bad["proofs"][0]["proof"]["stages"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle_diff(bad, _bundle_after())


def test_no_partial_result_on_invalid_after():
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle_diff(_bundle_before(), {"root": "x"})


# ---------------------------------------------------------------- endpoint


def test_http_diff_is_200_compact_json():
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff",
        json={"before": _bundle_before(), "after": _bundle_after()},
    )
    assert response.status_code == 200
    assert response.json() == _diff()
    assert response.content == json.dumps(
        _diff(), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert not response.content.endswith(b"\n")


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b'"x"',
        b"null",
        b"{}",
        b'{"before": {}}',
        b'{"after": {}}',
        b'{"before": {}, "after": {}, "extra": 1}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_value_error_in_function_is_422():
    bad = _bundle_before()
    bad["root"] = "f" * 64
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff",
        json={"before": bad, "after": _bundle_after()},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
