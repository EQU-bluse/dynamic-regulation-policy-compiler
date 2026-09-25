import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    bundle_evolution_checkpoint,
    checkpoint_chain,
    checkpoint_chain_checkpoint,
    checkpoint_chain_checkpoint_bundle,
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
OTHER = "2022-01-15T00:00:00Z"
GENESIS = "0" * 64

GEN_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution/checkpoint"
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


def _evolution():
    return checkpoint_chain_checkpoint_bundle_evolution(
        [
            {"at": DT1, "bundle": _bundle_one()},
            {"at": DT2, "bundle": _bundle_two()},
            {"at": DT3, "bundle": _bundle_three()},
        ]
    )


def _proof(start, end):
    return bundle_evolution_checkpoint(_evolution(), start, end)


# ---------------------------------------------------------------- structure


def test_top_level_key_order_and_exact_keys():
    proof = _proof(DT2, DT3)
    assert list(proof) == ["start", "end", "anchor", "stages", "commitment"]
    for stage in proof["stages"]:
        assert list(stage) == ["at", "bundle", "diff", "previous", "digest"]


def test_full_window_from_head_uses_zero_anchor_and_all_stages():
    report = _evolution()
    proof = _proof(DT1, DT3)
    assert proof["start"] == DT1
    assert proof["end"] == DT3
    assert proof["anchor"] == GENESIS
    assert proof["stages"] == report["stages"]
    assert proof["commitment"] == report["stages"][-1]["digest"]
    assert proof["commitment"] == report["root"]


def test_middle_window_anchors_at_preceding_digest():
    report = _evolution()
    proof = _proof(DT2, DT3)
    assert proof["anchor"] == report["stages"][0]["digest"]
    assert [stage["at"] for stage in proof["stages"]] == [DT2, DT3]


def test_middle_first_stage_keeps_original_diff_and_previous():
    report = _evolution()
    proof = _proof(DT2, DT3)
    first = proof["stages"][0]
    original = report["stages"][1]
    assert first["at"] == DT2
    assert first["diff"] == original["diff"]
    assert first["previous"] == original["previous"]
    assert first["digest"] == original["digest"]
    assert first["bundle"] == original["bundle"]


def test_single_stage_middle_window_keeps_front_bundle_in_diff():
    report = _evolution()
    proof = _proof(DT2, DT2)
    assert len(proof["stages"]) == 1
    stage = proof["stages"][0]
    assert stage["at"] == DT2
    assert stage["diff"]["before_root"] == report["stages"][0]["bundle"]["root"]
    assert stage["diff"]["after_root"] == stage["bundle"]["root"]
    assert stage["previous"] == report["stages"][0]["digest"]
    assert proof["anchor"] == report["stages"][0]["digest"]
    assert proof["commitment"] == stage["digest"]


def test_single_stage_head_window():
    report = _evolution()
    proof = _proof(DT1, DT1)
    assert proof["anchor"] == GENESIS
    assert len(proof["stages"]) == 1
    assert proof["stages"][0]["diff"] is None
    assert proof["commitment"] == report["stages"][0]["digest"]
    assert proof["commitment"] != report["root"]


def test_tail_window_commitment_equals_root():
    report = _evolution()
    proof = _proof(DT2, DT3)
    assert proof["commitment"] == report["root"]


def test_stages_are_independent_deep_copies():
    report = _evolution()
    proof = _proof(DT2, DT3)
    for window_stage, original in zip(proof["stages"], report["stages"][1:]):
        assert window_stage is not original
        assert window_stage["bundle"] is not original["bundle"]
        assert window_stage["bundle"]["proofs"][0] is not (
            original["bundle"]["proofs"][0]
        )
        assert window_stage["diff"] is not original["diff"]


def test_does_not_mutate_report():
    report = _evolution()
    snapshot = copy.deepcopy(report)
    _proof(DT2, DT3)
    assert report == snapshot


def test_mutating_proof_does_not_touch_report():
    report = _evolution()
    proof = _proof(DT2, DT3)
    proof["stages"][0]["bundle"]["root"] = "mutated"
    proof["stages"][0]["diff"]["digest"] = "mutated"
    assert report["stages"][1]["bundle"]["root"] != "mutated"
    assert report["stages"][1]["diff"]["digest"] != "mutated"


def test_equal_valued_inputs_are_byte_identical():
    first = _proof(DT2, DT3)
    second = bundle_evolution_checkpoint(copy.deepcopy(_evolution()), DT2, DT3)
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_single_stage_report_window():
    report = checkpoint_chain_checkpoint_bundle_evolution(
        [{"at": DT1, "bundle": _bundle_one()}]
    )
    proof = bundle_evolution_checkpoint(report, DT1, DT1)
    assert proof["anchor"] == GENESIS
    assert proof["commitment"] == report["root"]
    assert len(proof["stages"]) == 1


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "start,end",
    [
        ("not-a-time", DT3),
        (DT2, "2021-13-01T00:00:00Z"),
        (123, DT3),
        (DT3, DT2),
        (OTHER, DT3),
        (DT2, OTHER),
        (OTHER, OTHER),
    ],
)
def test_invalid_times_or_missing_boundaries_raise(start, end):
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint(_evolution(), start, end)


def test_non_evolution_report_raises():
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint({"root": "0" * 64}, DT1, DT1)


def test_forged_report_root_raises():
    report = _evolution()
    report["root"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint(report, DT1, DT3)


def test_broken_stage_link_in_report_raises():
    report = _evolution()
    report["stages"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint(report, DT1, DT3)


def test_forged_stage_digest_in_report_raises():
    report = _evolution()
    report["stages"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint(report, DT1, DT3)


def test_forged_bundle_member_digest_in_report_raises():
    report = _evolution()
    report["stages"][0]["bundle"]["proofs"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint(report, DT1, DT3)


def test_forged_embedded_proof_in_report_raises():
    report = _evolution()
    member_proof = report["stages"][0]["bundle"]["proofs"][0]["proof"]
    member_proof["commitment"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint(report, DT2, DT3)


def test_incomplete_change_list_in_report_raises():
    report = _evolution()
    # Stage 2's diff must list its changed/added members; dropping the legal
    # change entries makes the full report fail recomputation.
    report["stages"][1]["diff"]["changes"] = []
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint(report, DT1, DT3)


def test_forged_diff_digest_in_report_raises():
    report = _evolution()
    report["stages"][1]["diff"]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint(report, DT1, DT3)


def test_invalid_report_does_not_mutate_inputs():
    report = _evolution()
    report["stages"][1]["previous"] = "f" * 64
    snapshot = copy.deepcopy(report)
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint(report, DT1, DT3)
    assert report == snapshot


# ---------------------------------------------------------------- endpoint


def test_http_checkpoint_returns_200_compact_json():
    body = {"report": _evolution(), "start": DT2, "end": DT3}
    response = client.post(GEN_PATH, json=body)
    assert response.status_code == 200
    expected_proof = _proof(DT2, DT3)
    assert response.json() == expected_proof
    expected_body = json.dumps(
        expected_proof, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert response.content == expected_body
    assert not response.content.endswith(b"\n")
    assert "允许" in response.content.decode("utf-8")
    assert "伽马" in response.content.decode("utf-8")


def test_http_checkpoint_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("checkpoint endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        GEN_PATH, json={"report": _evolution(), "start": DT1, "end": DT1}
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
        b'{"report": null, "start": "x", "end": "y"}',
        b'{"report": {}, "start": "x"}',
        b'{"report": {}, "start": "x", "end": "y", "extra": 1}',
        b'{"report": {}, "start": "x", "end": "y", "expected": {}}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        GEN_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_missing_boundary_is_422():
    response = client.post(
        GEN_PATH,
        json={"report": _evolution(), "start": OTHER, "end": DT3},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
