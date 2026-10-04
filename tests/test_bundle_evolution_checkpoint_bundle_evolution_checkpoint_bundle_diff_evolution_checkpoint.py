import copy
import functools
import json

import pytest
from fastapi.testclient import TestClient

import test_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff as fx
from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution as evolve,
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution_checkpoint as checkpoint,
)

client = TestClient(app)

FT1 = "2022-05-01T00:00:00Z"
FT2 = "2022-06-01T00:00:00Z"
FT3 = "2022-07-01T00:00:00Z"
OTHER = "2022-08-01T00:00:00Z"
GENESIS = "0" * 64

GEN_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/"
    "checkpoint/bundle/diff/evolution/checkpoint"
)

# The delivery-stage window proof bundle evolution report is five credential
# levels deep, so the distinct bundles are built once in the imported diff
# fixture module; tests mutate deep copies only.


def _bundle_one():
    return copy.deepcopy(fx._b1())


def _bundle_two():
    return copy.deepcopy(fx._b2())


def _bundle_three():
    return copy.deepcopy(fx._b3())


def _stage_inputs():
    return [
        {"at": FT1, "bundle": _bundle_one()},
        {"at": FT2, "bundle": _bundle_two()},
        {"at": FT3, "bundle": _bundle_three()},
    ]


@functools.lru_cache(maxsize=1)
def _evolution_raw():
    return evolve(_stage_inputs())


def _evolution():
    return copy.deepcopy(_evolution_raw())


def _proof(start, end):
    return checkpoint(_evolution(), start, end)


# ---------------------------------------------------------------- structure


def test_top_level_key_order_and_exact_keys():
    proof = _proof(FT2, FT3)
    assert list(proof) == ["start", "end", "anchor", "stages", "commitment"]
    for stage in proof["stages"]:
        assert list(stage) == ["at", "bundle", "diff", "previous", "digest"]


def test_full_window_from_head_uses_zero_anchor_and_all_stages():
    report = _evolution()
    proof = _proof(FT1, FT3)
    assert proof["start"] == FT1
    assert proof["end"] == FT3
    assert proof["anchor"] == GENESIS
    assert proof["stages"] == report["stages"]
    assert proof["commitment"] == report["stages"][-1]["digest"]
    assert proof["commitment"] == report["root"]


def test_middle_window_anchors_at_preceding_digest():
    report = _evolution()
    proof = _proof(FT2, FT3)
    assert proof["anchor"] == report["stages"][0]["digest"]
    assert [stage["at"] for stage in proof["stages"]] == [FT2, FT3]


def test_middle_first_stage_keeps_original_diff_and_previous():
    report = _evolution()
    proof = _proof(FT2, FT3)
    first = proof["stages"][0]
    original = report["stages"][1]
    assert first["at"] == FT2
    assert first["diff"] == original["diff"]
    assert first["previous"] == original["previous"]
    assert first["digest"] == original["digest"]
    assert first["bundle"] == original["bundle"]


def test_single_stage_middle_window_keeps_front_bundle_in_diff():
    report = _evolution()
    proof = _proof(FT2, FT2)
    assert len(proof["stages"]) == 1
    stage = proof["stages"][0]
    assert stage["at"] == FT2
    assert stage["diff"]["before_root"] == report["stages"][0]["bundle"]["root"]
    assert stage["diff"]["before"] == report["stages"][0]["bundle"]
    assert stage["diff"]["after_root"] == stage["bundle"]["root"]
    assert stage["previous"] == report["stages"][0]["digest"]
    assert proof["anchor"] == report["stages"][0]["digest"]
    assert proof["commitment"] == stage["digest"]


def test_single_stage_head_window():
    report = _evolution()
    proof = _proof(FT1, FT1)
    assert proof["anchor"] == GENESIS
    assert len(proof["stages"]) == 1
    assert proof["stages"][0]["diff"] is None
    assert proof["commitment"] == report["stages"][0]["digest"]
    assert proof["commitment"] != report["root"]


def test_tail_window_commitment_equals_root():
    report = _evolution()
    proof = _proof(FT2, FT3)
    assert proof["commitment"] == report["root"]


def test_window_does_not_skip_or_reorder_stages():
    report = _evolution()
    proof = _proof(FT1, FT2)
    assert [stage["at"] for stage in proof["stages"]] == [FT1, FT2]
    assert proof["stages"] == report["stages"][:2]


def test_stages_are_independent_deep_copies():
    report = _evolution()
    proof = _proof(FT2, FT3)
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
    _proof(FT2, FT3)
    assert report == snapshot


def test_mutating_proof_does_not_touch_report():
    report = _evolution()
    proof = _proof(FT2, FT3)
    proof["stages"][0]["bundle"]["root"] = "mutated"
    proof["stages"][0]["diff"]["digest"] = "mutated"
    assert report["stages"][1]["bundle"]["root"] != "mutated"
    assert report["stages"][1]["diff"]["digest"] != "mutated"


def test_equal_valued_inputs_are_byte_identical():
    first = _proof(FT2, FT3)
    second = checkpoint(copy.deepcopy(_evolution()), FT2, FT3)
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_single_stage_evolution_window():
    report = evolve([{"at": FT1, "bundle": _bundle_one()}])
    proof = checkpoint(report, FT1, FT1)
    assert proof["anchor"] == GENESIS
    assert proof["commitment"] == report["root"]
    assert len(proof["stages"]) == 1


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "start,end",
    [
        ("not-a-time", FT3),
        (FT2, "2022-13-01T00:00:00Z"),
        (123, FT3),
        (FT3, FT2),
        (OTHER, FT3),
        (FT2, OTHER),
        (OTHER, OTHER),
    ],
)
def test_invalid_times_or_missing_boundaries_raise(start, end):
    with pytest.raises(ValueError):
        checkpoint(_evolution(), start, end)


def test_non_evolution_report_raises():
    with pytest.raises(ValueError):
        checkpoint({"root": "0" * 64}, FT1, FT1)


def test_forged_report_root_raises():
    report = _evolution()
    report["root"] = "f" * 64
    with pytest.raises(ValueError):
        checkpoint(report, FT1, FT3)


def test_broken_stage_link_in_report_raises():
    report = _evolution()
    report["stages"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        checkpoint(report, FT1, FT3)


def test_forged_stage_digest_in_report_raises():
    report = _evolution()
    report["stages"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        checkpoint(report, FT1, FT3)


def test_forged_bundle_member_digest_in_report_raises():
    report = _evolution()
    report["stages"][0]["bundle"]["proofs"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        checkpoint(report, FT1, FT3)


def test_forged_embedded_window_proof_in_report_raises():
    report = _evolution()
    member_proof = report["stages"][0]["bundle"]["proofs"][0]["proof"]
    member_proof["commitment"] = "f" * 64
    with pytest.raises(ValueError):
        checkpoint(report, FT2, FT3)


def test_incomplete_change_list_in_report_raises():
    report = _evolution()
    report["stages"][1]["diff"]["changes"] = []
    with pytest.raises(ValueError):
        checkpoint(report, FT1, FT3)


def test_forged_diff_digest_in_report_raises():
    report = _evolution()
    report["stages"][1]["diff"]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        checkpoint(report, FT1, FT3)


def test_invalid_report_does_not_mutate_inputs():
    report = _evolution()
    report["stages"][1]["previous"] = "f" * 64
    snapshot = copy.deepcopy(report)
    with pytest.raises(ValueError):
        checkpoint(report, FT1, FT3)
    assert report == snapshot


# ---------------------------------------------------------------- endpoint


def test_http_checkpoint_returns_200_compact_json():
    body = {"report": _evolution(), "start": FT2, "end": FT3}
    response = client.post(GEN_PATH, json=body)
    assert response.status_code == 200
    expected_proof = _proof(FT2, FT3)
    assert response.json() == expected_proof
    expected_body = json.dumps(
        expected_proof, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert response.content == expected_body
    assert not response.content.endswith(b"\n")
    assert "允许" in response.content.decode("utf-8")


def test_http_checkpoint_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("checkpoint endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        GEN_PATH, json={"report": _evolution(), "start": FT1, "end": FT1}
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
        json={"report": _evolution(), "start": OTHER, "end": FT3},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
