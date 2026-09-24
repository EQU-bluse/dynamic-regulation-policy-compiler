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
    matrix_bundle_evolution,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
LATER = "2021-03-01T00:00:00Z"
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


def _evolution():
    return matrix_bundle_evolution(_stages())


# ---------------------------------------------------------------- structure


def test_top_level_and_stage_key_order():
    report = _evolution()
    assert list(report) == ["root", "stages"]
    assert [list(stage) for stage in report["stages"]] == [
        ["at", "bundle", "diff", "previous", "digest"]
    ] * 3


def test_stage_ats_follow_input_order():
    report = _evolution()
    assert [stage["at"] for stage in report["stages"]] == [START, MID, END]


def test_first_diff_is_null_later_diffs_are_full_diff_credentials():
    report = _evolution()
    assert report["stages"][0]["diff"] is None
    assert report["stages"][1]["diff"] == matrix_bundle_diff(
        _bundle_zero(), _bundle_one()
    )
    assert report["stages"][2]["diff"] == matrix_bundle_diff(
        _bundle_one(), _bundle_two()
    )


def test_bundles_are_deep_copies_of_normalized_bundles():
    report = _evolution()
    bundles = [_bundle_zero(), _bundle_one(), _bundle_two()]
    for stage, bundle in zip(report["stages"], bundles):
        assert stage["bundle"] == bundle
        assert stage["bundle"] is not bundle


def test_genesis_previous_and_digest_chain():
    report = _evolution()
    stages = report["stages"]
    assert stages[0]["previous"] == "0" * 64
    assert stages[1]["previous"] == stages[0]["digest"]
    assert stages[2]["previous"] == stages[1]["digest"]
    assert report["root"] == stages[-1]["digest"]
    for stage in stages:
        assert len(stage["digest"]) == 64
        assert all(char in "0123456789abcdef" for char in stage["digest"])


def test_single_stage_is_valid_with_null_diff():
    report = matrix_bundle_evolution([{"at": START, "bundle": _bundle_zero()}])
    (stage,) = report["stages"]
    assert stage["diff"] is None
    assert stage["previous"] == "0" * 64
    assert report["root"] == stage["digest"]


def test_stage_digest_covers_at_bundle_diff():
    report = _evolution()
    for index, stage in enumerate(report["stages"]):
        payload = {
            "at": stage["at"],
            "bundle": stage["bundle"],
            "diff": stage["diff"],
        }
        canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        expected = hashlib.sha256(
            stage["previous"].encode("ascii") + canonical.encode("utf-8")
        ).hexdigest()
        assert stage["digest"] == expected


def test_equal_valued_inputs_are_byte_identical_regardless_of_dict_order():
    def reverse_key_order(value):
        if isinstance(value, dict):
            return {k: reverse_key_order(v) for k, v in reversed(list(value.items()))}
        if isinstance(value, list):
            return [reverse_key_order(item) for item in value]
        return value

    first = _evolution()
    second = matrix_bundle_evolution(reverse_key_order(_stages()))
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_layers_do_not_share_mutable_containers():
    report = _evolution()
    report["stages"][1]["bundle"]["root"] = "mutated"
    # The adjacent diff embeds its own independent copies of the bundles.
    diff = report["stages"][1]["diff"]
    assert diff["before"]["root"] != "mutated"
    assert diff["after"]["root"] != "mutated"
    # Two stages never share a bundle container, even for equal values.
    single = matrix_bundle_evolution(
        [
            {"at": START, "bundle": _bundle_zero()},
            {"at": MID, "bundle": _bundle_zero()},
        ]
    )
    assert single["stages"][0]["bundle"] is not single["stages"][1]["bundle"]
    assert (
        single["stages"][1]["diff"]["before"]
        is not single["stages"][1]["diff"]["after"]
    )


def test_does_not_mutate_inputs():
    stages = _stages()
    snapshot = copy.deepcopy(stages)
    matrix_bundle_evolution(stages)
    assert stages == snapshot


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "stages",
    [
        None,
        "x",
        123,
        {},
        [],
        [None],
        ["x"],
        [{}],
        [{"at": START}],
        [{"bundle": _bundle_zero()}],
        [{"at": START, "bundle": _bundle_zero(), "extra": 1}],
        [{"at": "bad", "bundle": _bundle_zero()}],
        [
            {"at": MID, "bundle": _bundle_one()},
            {"at": START, "bundle": _bundle_zero()},
        ],
        [
            {"at": START, "bundle": _bundle_zero()},
            {"at": START, "bundle": _bundle_one()},
        ],
    ],
)
def test_invalid_stages_raise(stages):
    with pytest.raises(ValueError):
        matrix_bundle_evolution(stages)


def test_untruthful_bundle_raises():
    bundle = copy.deepcopy(_bundle_zero())
    bundle["root"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_bundle_evolution([{"at": START, "bundle": bundle}])


def test_structurally_invalid_bundle_raises():
    with pytest.raises(ValueError):
        matrix_bundle_evolution([{"at": START, "bundle": {"root": "0" * 64}}])


def test_false_member_digest_bundle_raises():
    bundle = copy.deepcopy(_bundle_one())
    bundle["reports"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_bundle_evolution(
            [
                {"at": START, "bundle": _bundle_zero()},
                {"at": MID, "bundle": bundle},
            ]
        )


def test_later_bundle_still_structurally_checked_when_first_is_untruthful():
    bad = copy.deepcopy(_bundle_zero())
    bad["root"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_bundle_evolution(
            [
                {"at": START, "bundle": bad},
                {"at": MID, "bundle": {"root": "0" * 64}},
            ]
        )


# ---------------------------------------------------------------- endpoint


def test_http_evolution_returns_200_compact_json():
    body = json.dumps(_evolution(), ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    response = client.post(
        "/decision-matrix/attest/bundle/evolution", json={"stages": _stages()}
    )
    assert response.status_code == 200
    assert response.content == body
    assert not response.content.endswith(b"\n")
    assert "允许" in response.content.decode("utf-8")


def test_http_evolution_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("evolution endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/decision-matrix/attest/bundle/evolution", json={"stages": _stages()}
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
        b'{"stages": []}',
        b'{"bundle": {}}',
        b'{"stages": [{"at": "x", "bundle": {}}], "extra": 1}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        "/decision-matrix/attest/bundle/evolution",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_value_error_in_function_is_422():
    response = client.post(
        "/decision-matrix/attest/bundle/evolution",
        json={"stages": [{"at": START, "bundle": {"root": "0" * 64}}]},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
