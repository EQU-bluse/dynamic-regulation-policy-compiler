import copy
import functools
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

import test_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff as fx
from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff as diff,
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution as evolve,
)

client = TestClient(app)

FT1 = "2022-05-01T00:00:00Z"
FT2 = "2022-06-01T00:00:00Z"
FT3 = "2022-07-01T00:00:00Z"

EVOLUTION_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/"
    "checkpoint/bundle/diff/evolution"
)

# Delivery-stage window proof bundles are five credential levels deep, so the
# distinct bundles are built once in the imported diff fixture module; tests
# mutate deep copies only. Stage bundles: [a: X], [a: Y, b: X, 中: X],
# [a: X, b: Y] — adjacent diffs then cover added, removed, and changed.


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


# ---------------------------------------------------------------- structure


def test_top_level_and_stage_key_order():
    report = _evolution()
    assert list(report) == ["root", "stages"]
    assert [list(stage) for stage in report["stages"]] == [
        ["at", "bundle", "diff", "previous", "digest"],
        ["at", "bundle", "diff", "previous", "digest"],
        ["at", "bundle", "diff", "previous", "digest"],
    ]


def test_stage_ats_follow_input_order():
    report = _evolution()
    assert [stage["at"] for stage in report["stages"]] == [FT1, FT2, FT3]


def test_bundles_are_copies_of_inputs():
    inputs = _stage_inputs()
    report = evolve(inputs)
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
    assert report["stages"][1]["diff"] == diff(_bundle_one(), _bundle_two())
    assert report["stages"][2]["diff"] == diff(_bundle_two(), _bundle_three())
    assert report["stages"][1]["diff"]["before_root"] == _bundle_one()["root"]
    assert report["stages"][1]["diff"]["after_root"] == _bundle_two()["root"]
    kinds = {(c["id"], c["kind"]) for c in report["stages"][1]["diff"]["changes"]}
    assert ("a", "changed") in kinds
    assert ("b", "added") in kinds
    assert ("中", "added") in kinds
    kinds = {(c["id"], c["kind"]) for c in report["stages"][2]["diff"]["changes"]}
    assert ("a", "changed") in kinds
    assert ("b", "changed") in kinds
    assert ("中", "removed") in kinds


def test_previous_links_and_digests_chain():
    report = _evolution()
    stages = report["stages"]
    assert stages[1]["previous"] == stages[0]["digest"]
    assert stages[2]["previous"] == stages[1]["digest"]
    assert report["root"] == stages[-1]["digest"]
    for stage in stages:
        assert len(stage["previous"]) == 64
        assert len(stage["digest"]) == 64
        int(stage["digest"], 16)
        assert stage["digest"] == stage["digest"].lower()


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
    report = evolve([{"at": FT1, "bundle": _bundle_one()}])
    assert len(report["stages"]) == 1
    assert report["stages"][0]["diff"] is None
    assert report["root"] == report["stages"][0]["digest"]


def test_equal_valued_inputs_are_byte_identical_regardless_of_dict_order():
    def reverse_key_order(value):
        if isinstance(value, dict):
            return {k: reverse_key_order(v) for k, v in reversed(list(value.items()))}
        if isinstance(value, list):
            return [reverse_key_order(item) for item in value]
        return value

    first = evolve(_stage_inputs())
    second = evolve(
        [
            {"bundle": reverse_key_order(item["bundle"]), "at": item["at"]}
            for item in _stage_inputs()
        ]
    )
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_layers_do_not_share_mutable_containers():
    inputs = _stage_inputs()
    report = evolve(inputs)
    stage = report["stages"][1]
    assert stage["diff"]["after"] is not stage["bundle"]
    stage["diff"]["digest"] = "mutated"
    stage["bundle"]["root"] = "mutated"
    assert inputs[1]["bundle"]["root"] != "mutated"


def test_does_not_mutate_inputs():
    inputs = _stage_inputs()
    snapshot = copy.deepcopy(inputs)
    evolve(inputs)
    assert inputs == snapshot


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "stages",
    [
        None,
        "x",
        {},
        [],
        [{"at": FT1}],
        [{"bundle": _bundle_one()}],
        [{"at": FT1, "bundle": _bundle_one(), "extra": 1}],
        [{"at": "not-a-time", "bundle": _bundle_one()}],
        [
            {"at": FT2, "bundle": _bundle_one()},
            {"at": FT1, "bundle": _bundle_two()},
        ],
        [
            {"at": FT1, "bundle": _bundle_one()},
            {"at": FT1, "bundle": _bundle_two()},
        ],
    ],
)
def test_invalid_stage_shape_raises(stages):
    with pytest.raises(ValueError):
        evolve(stages)


def test_invalid_bundle_raises():
    with pytest.raises(ValueError):
        evolve([{"at": FT1, "bundle": {"root": "0" * 64}}])


def test_false_bundle_root_raises():
    bad_bundle = _bundle_one()
    bad_bundle["root"] = "f" * 64
    with pytest.raises(ValueError):
        evolve([{"at": FT1, "bundle": bad_bundle}])


def test_broken_member_chain_raises():
    bad_bundle = _bundle_two()
    bad_bundle["proofs"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        evolve([{"at": FT1, "bundle": bad_bundle}])


def test_false_embedded_window_proof_raises():
    bad_bundle = _bundle_one()
    bad_bundle["proofs"][0]["proof"]["commitment"] = "f" * 64
    with pytest.raises(ValueError):
        evolve([{"at": FT1, "bundle": bad_bundle}])


def test_invalid_input_does_not_mutate_stages():
    stages = _stage_inputs()
    stages[0]["bundle"]["root"] = "f" * 64
    snapshot = copy.deepcopy(stages)
    with pytest.raises(ValueError):
        evolve(stages)
    assert stages == snapshot


# ---------------------------------------------------------------- endpoint


def test_http_evolution_returns_200_compact_json():
    stages = [
        {"at": FT1, "bundle": _bundle_one()},
        {"at": FT2, "bundle": _bundle_two()},
    ]
    response = client.post(EVOLUTION_PATH, json={"stages": stages})
    assert response.status_code == 200
    generated = evolve(copy.deepcopy(stages))
    assert response.json() == generated
    expected_body = json.dumps(
        generated, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert response.content == expected_body
    assert not response.content.endswith(b"\n")
    assert "中".encode("utf-8") in response.content
    assert "允许".encode("utf-8") in response.content


def test_http_evolution_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("evolution endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        EVOLUTION_PATH,
        json={"stages": [{"at": FT1, "bundle": _bundle_one()}]},
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
        b'{"stages": [{"at": "2022-05-01T00:00:00Z"}]}',
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
        json={"stages": [{"at": FT1, "bundle": {"root": "0" * 64}}]},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
