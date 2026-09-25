import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    checkpoint_chain,
    checkpoint_chain_checkpoint,
    checkpoint_chain_checkpoint_bundle,
    checkpoint_chain_checkpoint_bundle_diff,
    checkpoint_chain_checkpoint_bundle_evolution,
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    evolution_checkpoint,
    evolution_checkpoint_bundle,
    matrix_bundle_evolution,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"
AT1 = "2021-05-01T00:00:00Z"
AT2 = "2021-06-01T00:00:00Z"
AT3 = "2021-07-01T00:00:00Z"
RT1 = "2021-08-01T00:00:00Z"
RT2 = "2021-09-01T00:00:00Z"
RT3 = "2021-10-01T00:00:00Z"
DT1 = "2021-11-01T00:00:00Z"
DT2 = "2021-12-01T00:00:00Z"
DT3 = "2022-01-01T00:00:00Z"

EVOLUTION_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution"
)


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


def _matrix_bundle_one():
    return decision_matrix_attestation_bundle([{"id": "a", "report": _report_a()}])


def _matrix_bundle_two():
    return decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()}, {"id": "b", "report": _report_b()}]
    )


def _matrix_bundle_three():
    return decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": _report_a()},
            {"id": "b", "report": _report_b()},
            {"id": "c", "report": _report_c()},
        ]
    )


def _checkpoint_proofs():
    evolution = matrix_bundle_evolution(
        [
            {"at": AT1, "bundle": _matrix_bundle_one()},
            {"at": AT2, "bundle": _matrix_bundle_two()},
            {"at": AT3, "bundle": _matrix_bundle_three()},
        ]
    )
    return {
        "head": evolution_checkpoint(evolution, AT1, AT1),
        "mid": evolution_checkpoint(evolution, AT2, AT2),
        "tail": evolution_checkpoint(evolution, AT3, AT3),
        "span": evolution_checkpoint(evolution, AT1, AT2),
    }


def _chain():
    proofs = _checkpoint_proofs()
    bundle_one = evolution_checkpoint_bundle(
        [{"id": "a", "proof": proofs["head"]}, {"id": "z", "proof": proofs["span"]}]
    )
    bundle_two = evolution_checkpoint_bundle(
        [{"id": "a", "proof": proofs["mid"]}, {"id": "z", "proof": proofs["span"]}]
    )
    bundle_three = evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": proofs["tail"]},
            {"id": "b", "proof": proofs["mid"]},
            {"id": "z", "proof": proofs["span"]},
        ]
    )
    return checkpoint_chain(
        [
            {"at": RT1, "bundle": bundle_one},
            {"at": RT2, "bundle": bundle_two},
            {"at": RT3, "bundle": bundle_three},
        ]
    )


def _window_proof(start, end):
    return checkpoint_chain_checkpoint(_chain(), start, end)


def _bundle_one():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(RT1, RT1)},
            {"id": "beta", "proof": _window_proof(RT2, RT3)},
        ]
    )


def _bundle_two():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(RT1, RT1)},
            {"id": "beta", "proof": _window_proof(RT2, RT2)},
            {"id": "伽马", "proof": _window_proof(RT3, RT3)},
        ]
    )


def _bundle_three():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(RT1, RT2)},
            {"id": "伽马", "proof": _window_proof(RT3, RT3)},
        ]
    )


def _stage_inputs():
    return [
        {"at": DT1, "bundle": _bundle_one()},
        {"at": DT2, "bundle": _bundle_two()},
        {"at": DT3, "bundle": _bundle_three()},
    ]


def _evolution():
    return checkpoint_chain_checkpoint_bundle_evolution(_stage_inputs())


# ---------------------------------------------------------------- structure


def test_top_level_and_stage_key_order():
    report = _evolution()
    assert list(report) == ["root", "stages"]
    for stage in report["stages"]:
        assert list(stage) == ["at", "bundle", "diff", "previous", "digest"]


def test_stage_ats_follow_input_order():
    report = _evolution()
    assert [stage["at"] for stage in report["stages"]] == [DT1, DT2, DT3]


def test_bundles_are_copies_of_inputs():
    inputs = _stage_inputs()
    report = checkpoint_chain_checkpoint_bundle_evolution(inputs)
    for stage, item in zip(report["stages"], inputs):
        assert stage["bundle"] == item["bundle"]
        assert stage["bundle"] is not item["bundle"]
        assert stage["bundle"]["proofs"][0] is not item["bundle"]["proofs"][0]


def test_first_stage_diff_is_null_and_genesis_previous():
    report = _evolution()
    first = report["stages"][0]
    assert first["diff"] is None
    assert first["previous"] == "0" * 64


def test_later_diffs_are_full_adjacent_diff_credentials():
    report = _evolution()
    bundles = [item["bundle"] for item in _stage_inputs()]
    assert report["stages"][1]["diff"] == checkpoint_chain_checkpoint_bundle_diff(
        bundles[0], bundles[1]
    )
    assert report["stages"][2]["diff"] == checkpoint_chain_checkpoint_bundle_diff(
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
        expected_previous = (
            "0" * 64 if index == 0 else report["stages"][index - 1]["digest"]
        )
        payload = {
            "at": stage["at"],
            "bundle": stage["bundle"],
            "diff": stage["diff"],
        }
        canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(
            expected_previous.encode("ascii") + canonical.encode("utf-8")
        ).hexdigest()
        assert stage["digest"] == digest


def test_single_stage_is_valid():
    report = checkpoint_chain_checkpoint_bundle_evolution(
        [{"at": DT1, "bundle": _bundle_one()}]
    )
    assert len(report["stages"]) == 1
    assert report["stages"][0]["diff"] is None
    assert report["root"] == report["stages"][0]["digest"]


def test_equal_valued_inputs_are_byte_identical():
    first = _evolution()
    second = checkpoint_chain_checkpoint_bundle_evolution(
        copy.deepcopy(_stage_inputs())
    )
    assert json.dumps(
        first, ensure_ascii=False, separators=(",", ":")
    ) == json.dumps(second, ensure_ascii=False, separators=(",", ":"))


def test_layers_do_not_share_mutable_containers():
    inputs = _stage_inputs()
    report = checkpoint_chain_checkpoint_bundle_evolution(inputs)
    stage = report["stages"][1]
    assert stage["diff"]["after"] is not stage["bundle"]
    stage["diff"]["digest"] = "mutated"
    stage["bundle"]["root"] = "mutated"
    assert inputs[1]["bundle"]["root"] != "mutated"


def test_does_not_mutate_inputs():
    inputs = _stage_inputs()
    snapshot = copy.deepcopy(inputs)
    checkpoint_chain_checkpoint_bundle_evolution(inputs)
    assert inputs == snapshot


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "stages",
    [
        None,
        "x",
        {},
        [],
        [{"at": DT1}],
        [{"bundle": _bundle_one()}],
        [{"at": DT1, "bundle": _bundle_one(), "extra": 1}],
        [{"at": "not-a-time", "bundle": _bundle_one()}],
        [
            {"at": DT2, "bundle": _bundle_one()},
            {"at": DT1, "bundle": _bundle_two()},
        ],
        [
            {"at": DT1, "bundle": _bundle_one()},
            {"at": DT1, "bundle": _bundle_two()},
        ],
    ],
)
def test_invalid_stage_shape_raises(stages):
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint_bundle_evolution(stages)


def test_invalid_bundle_raises():
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint_bundle_evolution(
            [{"at": DT1, "bundle": {"root": "0" * 64}}]
        )


def test_false_bundle_root_raises():
    bad_bundle = copy.deepcopy(_bundle_one())
    bad_bundle["root"] = "f" * 64
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint_bundle_evolution(
            [
                {"at": DT1, "bundle": _bundle_two()},
                {"at": DT2, "bundle": bad_bundle},
            ]
        )


def test_broken_member_chain_raises():
    bad_bundle = copy.deepcopy(_bundle_two())
    bad_bundle["proofs"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint_bundle_evolution(
            [{"at": DT1, "bundle": bad_bundle}]
        )


def test_false_embedded_window_proof_raises():
    bad_bundle = copy.deepcopy(_bundle_one())
    bad_bundle["proofs"][0]["proof"]["commitment"] = "f" * 64
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint_bundle_evolution(
            [{"at": DT1, "bundle": bad_bundle}]
        )


# ---------------------------------------------------------------- endpoint


def test_http_evolution_returns_200_compact_json():
    body = {"stages": _stage_inputs()}
    response = client.post(EVOLUTION_PATH, json=body)
    assert response.status_code == 200
    assert response.json() == _evolution()
    expected_body = json.dumps(
        _evolution(), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert response.content == expected_body
    assert not response.content.endswith(b"\n")
    assert "伽马" in response.content.decode("utf-8")


def test_http_evolution_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("evolution endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        EVOLUTION_PATH, json={"stages": _stage_inputs()}
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
        b'{"stages": [{"at": "2021-11-01T00:00:00Z"}]}',
        b'{"stages": [], "extra": 1}',
        b'{"items": []}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        EVOLUTION_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_value_error_in_function_is_422():
    response = client.post(
        EVOLUTION_PATH,
        json={"stages": [{"at": DT1, "bundle": {"root": "0" * 64}}]},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
