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
    return decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()}]
    )


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


def _stage_inputs():
    return [
        {"at": AT1, "bundle": _bundle_one()},
        {"at": AT2, "bundle": _bundle_two()},
        {"at": AT3, "bundle": _bundle_three()},
    ]


def _evolution():
    return matrix_bundle_evolution(_stage_inputs())


# ---------------------------------------------------------------- structure


def test_top_level_and_stage_key_order():
    report = _evolution()
    assert list(report) == ["root", "stages"]
    for stage in report["stages"]:
        assert list(stage) == ["at", "bundle", "diff", "previous", "digest"]


def test_stage_ats_follow_input_order():
    report = _evolution()
    assert [stage["at"] for stage in report["stages"]] == [AT1, AT2, AT3]


def test_bundles_are_copies_of_inputs():
    inputs = _stage_inputs()
    report = matrix_bundle_evolution(inputs)
    for stage, item in zip(report["stages"], inputs):
        assert stage["bundle"] == item["bundle"]
        assert stage["bundle"] is not item["bundle"]
        assert stage["bundle"]["reports"][0] is not item["bundle"]["reports"][0]


def test_first_stage_diff_is_null_and_genesis_previous():
    report = _evolution()
    first = report["stages"][0]
    assert first["diff"] is None
    assert first["previous"] == "0" * 64


def test_later_diffs_are_full_adjacent_diff_credentials():
    report = _evolution()
    bundles = [item["bundle"] for item in _stage_inputs()]
    assert report["stages"][1]["diff"] == matrix_bundle_diff(
        bundles[0], bundles[1]
    )
    assert report["stages"][2]["diff"] == matrix_bundle_diff(
        bundles[1], bundles[2]
    )


def test_previous_links_and_digests_chain():
    report = _evolution()
    stages = report["stages"]
    assert stages[1]["previous"] == stages[0]["digest"]
    assert stages[2]["previous"] == stages[1]["digest"]
    assert report["root"] == stages[-1]["digest"]
    for stage in stages:
        assert len(stage["previous"]) == 64
        assert len(stage["digest"]) == 64


def test_stage_digest_covers_at_bundle_diff_after_previous():
    report = _evolution()
    for index, stage in enumerate(report["stages"]):
        expected_previous = "0" * 64 if index == 0 else report["stages"][index - 1]["digest"]
        payload = {"at": stage["at"], "bundle": stage["bundle"], "diff": stage["diff"]}
        canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(
            expected_previous.encode("ascii") + canonical.encode("utf-8")
        ).hexdigest()
        assert stage["digest"] == digest


def test_single_stage_is_valid():
    report = matrix_bundle_evolution([{"at": AT1, "bundle": _bundle_one()}])
    assert len(report["stages"]) == 1
    assert report["stages"][0]["diff"] is None
    assert report["root"] == report["stages"][0]["digest"]


def test_equal_valued_inputs_are_byte_identical():
    first = _evolution()
    second = matrix_bundle_evolution(copy.deepcopy(_stage_inputs()))
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_layers_do_not_share_mutable_containers():
    inputs = _stage_inputs()
    report = matrix_bundle_evolution(inputs)
    stage = report["stages"][1]
    # The diff's after bundle is a distinct copy from the stage bundle.
    assert stage["diff"]["after"] is not stage["bundle"]
    stage["diff"]["digest"] = "mutated"
    stage["bundle"]["root"] = "mutated"
    assert inputs[1]["bundle"]["root"] != "mutated"


def test_does_not_mutate_inputs():
    inputs = _stage_inputs()
    snapshot = copy.deepcopy(inputs)
    matrix_bundle_evolution(inputs)
    assert inputs == snapshot


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "stages",
    [
        None,
        "x",
        {},
        [],
        [{"at": AT1}],
        [{"bundle": _bundle_one()}],
        [{"at": AT1, "bundle": _bundle_one(), "extra": 1}],
        [{"at": "not-a-time", "bundle": _bundle_one()}],
        [
            {"at": AT2, "bundle": _bundle_one()},
            {"at": AT1, "bundle": _bundle_two()},
        ],
        [
            {"at": AT1, "bundle": _bundle_one()},
            {"at": AT1, "bundle": _bundle_two()},
        ],
    ],
)
def test_invalid_stage_shape_raises(stages):
    with pytest.raises(ValueError):
        matrix_bundle_evolution(stages)


def test_invalid_bundle_raises():
    with pytest.raises(ValueError):
        matrix_bundle_evolution([{"at": AT1, "bundle": {"root": "0" * 64}}])


def test_false_bundle_root_raises():
    bad_bundle = copy.deepcopy(_bundle_one())
    bad_bundle["root"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_bundle_evolution(
            [
                {"at": AT1, "bundle": _bundle_two()},
                {"at": AT2, "bundle": bad_bundle},
            ]
        )


def test_broken_bundle_chain_raises():
    bad_bundle = copy.deepcopy(_bundle_two())
    bad_bundle["reports"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_bundle_evolution([{"at": AT1, "bundle": bad_bundle}])


def test_semantic_forgery_in_bundle_raises():
    bad_bundle = copy.deepcopy(_bundle_one())
    bad_bundle["reports"][0]["report"]["matrix"]["points"][0]["cases"][0][
        "decision"
    ] = "forged"
    with pytest.raises(ValueError):
        matrix_bundle_evolution([{"at": AT1, "bundle": bad_bundle}])


# ---------------------------------------------------------------- endpoint


def test_http_evolution_returns_200_compact_json():
    body = {"stages": _stage_inputs()}
    response = client.post(
        "/decision-matrix/attest/bundle/evolution", json=body
    )
    assert response.status_code == 200
    assert response.json() == _evolution()
    expected_body = json.dumps(
        _evolution(), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert response.content == expected_body
    assert not response.content.endswith(b"\n")
    assert "允许" in response.content.decode("utf-8")


def test_http_evolution_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("evolution endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/decision-matrix/attest/bundle/evolution", json={"stages": _stage_inputs()}
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
        b'{"stages": [{"at": "2021-05-01T00:00:00Z"}]}',
        b'{"stages": [], "extra": 1}',
        b'{"items": []}',
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
        json={"stages": [{"at": AT1, "bundle": {"root": "0" * 64}}]},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
