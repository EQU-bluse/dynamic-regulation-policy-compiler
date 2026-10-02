import copy
import functools
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

import test_bundle_evolution_checkpoint_bundle_evolution_checkpoint as fx
from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle as bind,
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution as evolution,
)

client = TestClient(app)

T1 = "2023-01-01T00:00:00Z"
T2 = "2023-02-01T00:00:00Z"
T3 = "2023-03-01T00:00:00Z"
T4 = "2023-04-01T00:00:00Z"

EVOLUTION_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/"
    "checkpoint/bundle/diff/evolution"
)


# Delivery-stage window proofs are four credential levels deep; build each
# distinct proof once and bind bundles from cached copies.
@functools.lru_cache(maxsize=1)
def _x():
    return fx._proof(fx.ET1, fx.ET1)


@functools.lru_cache(maxsize=1)
def _y():
    return fx._proof(fx.ET2, fx.ET2)


@functools.lru_cache(maxsize=1)
def _z():
    return fx._proof(fx.ET3, fx.ET3)


@functools.lru_cache(maxsize=1)
def _bundle_one_raw():
    # [a: X]
    return bind([{"id": "a", "proof": _x()}])


@functools.lru_cache(maxsize=1)
def _bundle_two_raw():
    # a changed X->Y, b added with X, CJK 中 added with the same proof X.
    return bind(
        [
            {"id": "a", "proof": _y()},
            {"id": "b", "proof": _x()},
            {"id": "中", "proof": _x()},
        ]
    )


@functools.lru_cache(maxsize=1)
def _bundle_three_raw():
    # a changed Y->Z, b removed, 中 unchanged (must be omitted from the diff).
    return bind([{"id": "a", "proof": _z()}, {"id": "中", "proof": _x()}])


def _bundle_one():
    return copy.deepcopy(_bundle_one_raw())


def _bundle_two():
    return copy.deepcopy(_bundle_two_raw())


def _bundle_three():
    return copy.deepcopy(_bundle_three_raw())


@functools.lru_cache(maxsize=1)
def _evolution_raw():
    return evolution(
        [
            {"at": T1, "bundle": _bundle_one_raw()},
            {"at": T2, "bundle": _bundle_two_raw()},
            {"at": T3, "bundle": _bundle_three_raw()},
        ]
    )


def _report():
    return copy.deepcopy(_evolution_raw())


def _stage_inputs():
    return [
        {"at": T1, "bundle": _bundle_one()},
        {"at": T2, "bundle": _bundle_two()},
        {"at": T3, "bundle": _bundle_three()},
    ]


# ---------------------------------------------------------------- structure


def test_top_level_and_stage_key_order():
    report = _report()
    assert list(report) == ["root", "stages"]
    assert [list(stage) for stage in report["stages"]] == [
        ["at", "bundle", "diff", "previous", "digest"],
        ["at", "bundle", "diff", "previous", "digest"],
        ["at", "bundle", "diff", "previous", "digest"],
    ]


def test_stage_ats_follow_input_order():
    assert [stage["at"] for stage in _report()["stages"]] == [T1, T2, T3]


def test_bundles_are_independent_copies_of_inputs():
    inputs = _stage_inputs()
    report = evolution(inputs)
    for stage, item in zip(report["stages"], inputs):
        assert stage["bundle"] == item["bundle"]
        assert stage["bundle"] is not item["bundle"]
        assert stage["bundle"]["proofs"][0] is not item["bundle"]["proofs"][0]


def test_first_stage_diff_is_null_and_genesis_previous():
    first = _report()["stages"][0]
    assert first["diff"] is None
    assert first["previous"] == "0" * 64


def test_later_diffs_are_full_adjacent_diff_credentials():
    report = _report()
    assert report["stages"][1]["diff"]["before_root"] == _bundle_one()["root"]
    assert report["stages"][1]["diff"]["after_root"] == _bundle_two()["root"]
    assert report["stages"][2]["diff"]["before_root"] == _bundle_two()["root"]
    assert report["stages"][2]["diff"]["after_root"] == _bundle_three()["root"]
    first_changes = {
        (c["id"], c["kind"]) for c in report["stages"][1]["diff"]["changes"]
    }
    assert first_changes == {("a", "changed"), ("b", "added"), ("中", "added")}
    # b is removed and a replaced; 中 survives unchanged and is omitted.
    second_changes = {
        (c["id"], c["kind"]) for c in report["stages"][2]["diff"]["changes"]
    }
    assert second_changes == {("a", "changed"), ("b", "removed")}


def test_diff_change_sides_equal_bundle_members():
    report = _report()
    after_b = next(
        m for m in report["stages"][1]["bundle"]["proofs"] if m["id"] == "b"
    )
    added = next(
        c for c in report["stages"][1]["diff"]["changes"] if c["id"] == "b"
    )
    assert added["before"] is None
    assert added["after"] == after_b["proof"]
    before_a = report["stages"][2]["diff"]["before"]["proofs"][0]["proof"]
    changed = next(
        c for c in report["stages"][2]["diff"]["changes"] if c["id"] == "a"
    )
    assert changed["before"] == before_a
    assert changed["after"] == report["stages"][2]["bundle"]["proofs"][0]["proof"]


def test_previous_links_and_digests_chain():
    stages = _report()["stages"]
    assert stages[1]["previous"] == stages[0]["digest"]
    assert stages[2]["previous"] == stages[1]["digest"]
    assert _report()["root"] == stages[-1]["digest"]
    for stage in stages:
        assert len(stage["previous"]) == 64
        assert len(stage["digest"]) == 64
        int(stage["digest"], 16)
        assert stage["digest"] == stage["digest"].lower()


def test_stage_digest_covers_at_bundle_diff_after_previous():
    report = _report()
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
    report = evolution([{"at": T1, "bundle": _bundle_one()}])
    assert len(report["stages"]) == 1
    assert report["stages"][0]["diff"] is None
    assert report["root"] == report["stages"][0]["digest"]


def test_identical_adjacent_bundles_have_empty_diff_changes():
    report = evolution(
        [
            {"at": T1, "bundle": _bundle_one()},
            {"at": T2, "bundle": _bundle_one()},
        ]
    )
    assert report["stages"][1]["diff"]["changes"] == []


def test_equal_valued_inputs_are_byte_identical():
    first = _report()
    second = evolution(_stage_inputs())
    assert json.dumps(
        first, ensure_ascii=False, separators=(",", ":")
    ) == json.dumps(second, ensure_ascii=False, separators=(",", ":"))


def test_input_dict_key_order_does_not_change_output():
    def reverse_key_order(value):
        if isinstance(value, dict):
            return {
                k: reverse_key_order(v) for k, v in reversed(list(value.items()))
            }
        if isinstance(value, list):
            return [reverse_key_order(item) for item in value]
        return value

    first = evolution(_stage_inputs())
    second = evolution(reverse_key_order(_stage_inputs()))
    assert json.dumps(
        first, ensure_ascii=False, separators=(",", ":")
    ) == json.dumps(second, ensure_ascii=False, separators=(",", ":"))


def test_layers_do_not_share_mutable_containers():
    report = _report()
    stage = report["stages"][1]
    assert stage["diff"]["after"] is not stage["bundle"]
    stage["diff"]["digest"] = "mutated"
    stage["bundle"]["root"] = "mutated"
    assert _bundle_two_raw()["root"] != "mutated"


def test_does_not_mutate_inputs():
    inputs = _stage_inputs()
    snapshot = copy.deepcopy(inputs)
    evolution(inputs)
    assert inputs == snapshot


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "stages",
    [
        None,
        "x",
        {},
        [],
        [{"at": T1}],
        [{"bundle": _bundle_one()}],
        [{"at": T1, "bundle": _bundle_one(), "extra": 1}],
        [{"at": "not-a-time", "bundle": _bundle_one()}],
        [
            {"at": T2, "bundle": _bundle_one()},
            {"at": T1, "bundle": _bundle_two()},
        ],
        [
            {"at": T1, "bundle": _bundle_one()},
            {"at": T1, "bundle": _bundle_two()},
        ],
    ],
)
def test_invalid_stage_shape_raises(stages):
    with pytest.raises(ValueError):
        evolution(copy.deepcopy(stages))


def test_invalid_bundle_raises():
    with pytest.raises(ValueError):
        evolution([{"at": T1, "bundle": {"root": "0" * 64}}])


def test_false_bundle_root_raises():
    bad_bundle = _bundle_one()
    bad_bundle["root"] = "f" * 64
    with pytest.raises(ValueError):
        evolution([{"at": T1, "bundle": bad_bundle}])


def test_broken_member_chain_raises():
    bad_bundle = _bundle_two()
    bad_bundle["proofs"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        evolution([{"at": T1, "bundle": bad_bundle}])


def test_false_embedded_window_proof_raises():
    bad_bundle = _bundle_one()
    bad_bundle["proofs"][0]["proof"]["commitment"] = "f" * 64
    with pytest.raises(ValueError):
        evolution([{"at": T1, "bundle": bad_bundle}])


# ---------------------------------------------------------------- endpoint


def test_http_evolution_returns_200_compact_json():
    stages = [
        {"at": T1, "bundle": _bundle_one()},
        {"at": T2, "bundle": _bundle_two()},
    ]
    response = client.post(EVOLUTION_PATH, json={"stages": stages})
    assert response.status_code == 200
    generated = evolution(copy.deepcopy(stages))
    assert response.json() == generated
    expected_body = json.dumps(
        generated, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert response.content == expected_body
    assert not response.content.endswith(b"\n")
    assert "中" in response.content.decode("utf-8")


def test_http_evolution_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("evolution endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        EVOLUTION_PATH,
        json={"stages": [{"at": T1, "bundle": _bundle_one()}]},
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
        b'{"stages": [{"at": "2023-01-01T00:00:00Z"}]}',
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
        json={"stages": [{"at": T1, "bundle": {"root": "0" * 64}}]},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_other_public_entrypoints_unchanged():
    # The preceding diff endpoint keeps its before/after contract.
    diff_path = EVOLUTION_PATH.removesuffix("/evolution")
    response = client.post(
        diff_path,
        json={"before": _bundle_one(), "after": _bundle_two()},
    )
    assert response.status_code == 200
    assert list(response.json()) == [
        "before_root",
        "after_root",
        "before",
        "after",
        "changes",
        "digest",
    ]
