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
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff as diff,
)

client = TestClient(app)

DIFF_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/"
    "checkpoint/bundle/diff"
)

# Delivery-stage window proofs are four credential levels deep, so build each
# distinct proof/bundle/diff once per module; tests mutate deep copies only.
# Two distinct single-stage window proofs suffice for every change kind:
# X is the head window and Y a carried-diff window.


@functools.lru_cache(maxsize=1)
def _x():
    return fx._proof(fx.ET1, fx.ET1)


@functools.lru_cache(maxsize=1)
def _y():
    return fx._proof(fx.ET2, fx.ET2)


@functools.lru_cache(maxsize=1)
def _b1():
    # Main before: [a: X]
    return bind([{"id": "a", "proof": _x()}])


@functools.lru_cache(maxsize=1)
def _b2():
    # Main after: a changed X->Y, b added with X, CJK 中 added with the same
    # proof value X (equal proofs share one normalized node).
    return bind(
        [
            {"id": "a", "proof": _y()},
            {"id": "b", "proof": _x()},
            {"id": "中", "proof": _x()},
        ]
    )


@functools.lru_cache(maxsize=1)
def _b3():
    # Two shared members [a: X, b: Y].
    return bind(
        [
            {"id": "a", "proof": _x()},
            {"id": "b", "proof": _y()},
        ]
    )


@functools.lru_cache(maxsize=1)
def _b4():
    # [a: X, b: Y, c: X] against _b3: only c added.
    return bind(
        [
            {"id": "a", "proof": _x()},
            {"id": "b", "proof": _y()},
            {"id": "c", "proof": _x()},
        ]
    )


@functools.lru_cache(maxsize=1)
def _b5():
    # [a: X, c: Y] against _b3: b removed, c added.
    return bind(
        [
            {"id": "a", "proof": _x()},
            {"id": "c", "proof": _y()},
        ]
    )


@functools.lru_cache(maxsize=1)
def _b6():
    # [a: Y, 中: X] against _b1: a changed, 中 added (CJK sort check).
    return bind(
        [
            {"id": "a", "proof": _y()},
            {"id": "中", "proof": _x()},
        ]
    )


@functools.lru_cache(maxsize=1)
def _main_diff():
    return diff(_b1(), _b2())


def _before():
    return copy.deepcopy(_b1())


def _after():
    return copy.deepcopy(_b2())


def _report():
    return copy.deepcopy(_main_diff())


# ---------------------------------------------------------------- structure


def test_top_level_and_change_key_order():
    report = _main_diff()
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


def test_roots_match_the_two_bundles():
    report = _main_diff()
    assert report["before_root"] == _b1()["root"]
    assert report["after_root"] == _b2()["root"]


def test_before_and_after_are_normalized_bundle_copies():
    report = _main_diff()
    assert report["before"] == _b1()
    assert report["after"] == _b2()
    assert report["before"] is not report["after"]
    assert report["before"] is not _b1()
    assert report["after"] is not _b2()


def test_added_change_shape():
    added = next(c for c in _main_diff()["changes"] if c["id"] == "b")
    assert added["kind"] == "added"
    assert added["before"] is None
    after_b = next(m for m in _b2()["proofs"] if m["id"] == "b")
    assert added["after"] == after_b["proof"]


def test_removed_change_shape():
    report = diff(_b3(), _b1())
    (change,) = report["changes"]
    assert change["id"] == "b"
    assert change["kind"] == "removed"
    assert change["before"] == _b3()["proofs"][-1]["proof"]
    assert change["after"] is None


def test_changed_change_shape():
    changed = next(c for c in _main_diff()["changes"] if c["id"] == "a")
    assert changed["kind"] == "changed"
    assert changed["before"] == _b1()["proofs"][0]["proof"]
    assert changed["after"] == _b2()["proofs"][0]["proof"]


def test_changes_sorted_by_unicode_code_point():
    # a (changed, ASCII) sorts before 中 (added, CJK).
    report = diff(_b1(), _b6())
    assert [(c["id"], c["kind"]) for c in report["changes"]] == [
        ("a", "changed"),
        ("中", "added"),
    ]


def test_added_and_removed_sorted_by_unicode_code_point():
    report = diff(_b3(), _b5())
    assert [(c["id"], c["kind"]) for c in report["changes"]] == [
        ("b", "removed"),
        ("c", "added"),
    ]


def test_identical_bundles_yield_empty_changes():
    report = diff(_b3(), _b3())
    assert report["changes"] == []
    assert report["before_root"] == report["after_root"] == _b3()["root"]


def test_unchanged_member_is_omitted():
    report = diff(_b3(), _b4())
    (change,) = report["changes"]
    assert change["id"] == "c"
    assert change["kind"] == "added"


def test_digest_covers_first_five_items():
    report = _main_diff()
    payload = {
        "before_root": report["before_root"],
        "after_root": report["after_root"],
        "before": report["before"],
        "after": report["after"],
        "changes": report["changes"],
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert report["digest"] == expected
    assert len(report["digest"]) == 64


def test_equal_valued_inputs_are_byte_identical_regardless_of_dict_order():
    def reverse_key_order(value):
        if isinstance(value, dict):
            return {k: reverse_key_order(v) for k, v in reversed(list(value.items()))}
        if isinstance(value, list):
            return [reverse_key_order(item) for item in value]
        return value

    first = diff(_b1(), _b2())
    second = diff(reverse_key_order(_b1()), reverse_key_order(_b2()))
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_caller_member_order_does_not_change_result():
    items = [
        {"id": "a", "proof": _x()},
        {"id": "b", "proof": _y()},
    ]
    assert diff(bind(items), _b1()) == diff(
        bind(list(reversed(copy.deepcopy(items)))), _b1()
    )


def test_layers_do_not_share_mutable_containers():
    report = _report()
    added = next(c for c in report["changes"] if c["id"] == "b")
    after_b = next(m for m in report["after"]["proofs"] if m["id"] == "b")
    # The added proof is independent of the embedded after bundle copy.
    assert added["after"] is not None
    assert added["after"] is not after_b["proof"]
    added["after"]["commitment"] = "mutated"
    assert after_b["proof"]["commitment"] != "mutated"
    # The two sides of the diff do not share embedded containers either.
    changed = next(c for c in report["changes"] if c["id"] == "a")
    changed["before"]["stages"][0]["digest"] = "mutated"
    assert report["before"]["proofs"][0]["proof"]["stages"][0]["digest"] != (
        "mutated"
    )


def test_does_not_mutate_inputs():
    before = _before()
    after = _after()
    before_snapshot = copy.deepcopy(before)
    after_snapshot = copy.deepcopy(after)
    diff(before, after)
    assert before == before_snapshot
    assert after == after_snapshot


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "before",
    [
        None,
        "x",
        [],
        {},
        {"root": "0" * 64},
    ],
)
def test_invalid_before_shape_raises(before):
    with pytest.raises(ValueError):
        diff(before, _b2())


@pytest.mark.parametrize(
    "after",
    [
        None,
        "x",
        [],
        {},
        {"root": "0" * 64},
        {"root": "0" * 64, "proofs": []},
    ],
)
def test_invalid_after_shape_raises(after):
    with pytest.raises(ValueError):
        diff(_b1(), after)


def test_structurally_invalid_member_proof_raises():
    before = _before()
    before["proofs"][0]["proof"] = {"start": fx.ET1}
    with pytest.raises(ValueError):
        diff(before, _b2())


def test_false_bundle_root_raises():
    before = _before()
    before["root"] = "f" * 64
    with pytest.raises(ValueError):
        diff(before, _b2())


def test_false_member_digest_raises():
    after = _after()
    after["proofs"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        diff(_b1(), after)


def test_broken_member_chain_link_raises():
    before = _before()
    before["proofs"][0]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        diff(before, _b2())


def test_untruthful_window_proof_raises():
    after = _after()
    after["proofs"][0]["proof"]["stages"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        diff(_b1(), after)


def test_false_window_proof_commitment_raises():
    before = _before()
    before["proofs"][0]["proof"]["commitment"] = "f" * 64
    with pytest.raises(ValueError):
        diff(before, _b2())


def test_semantic_forgery_in_deep_window_proof_raises():
    before = _before()
    node = before["proofs"][0]["proof"]
    # delivery window -> bundle evolution window proof member
    node = node["stages"][0]["bundle"]["proofs"][0]["proof"]
    # bundle evolution window -> chain window proof member
    node = node["stages"][0]["bundle"]["proofs"][0]["proof"]
    # chain window proof -> evolution checkpoint proof member
    node = node["stages"][0]["bundle"]["proofs"][0]["proof"]
    # matrix evolution checkpoint -> matrix bundle report
    point = node["stages"][0]["bundle"]["reports"][0]["report"]["matrix"][
        "points"
    ][0]
    point["cases"][0]["decision"] = "forged"
    with pytest.raises(ValueError):
        diff(before, _b2())


def test_second_side_still_checked_when_first_summary_is_false():
    # before carries a format-valid but false root; that must not short-circuit
    # the full structural validation of the malformed after bundle.
    before = _before()
    before["root"] = "f" * 64
    with pytest.raises(ValueError):
        diff(before, {"proofs": [{"id": "a"}]})


def test_first_side_still_checked_when_second_summary_is_false():
    after = _after()
    after["root"] = "f" * 64
    with pytest.raises(ValueError):
        diff({"proofs": "not-a-list"}, after)


def test_invalid_input_does_not_mutate_bundles():
    before = _before()
    before["root"] = "f" * 64
    after = _after()
    before_snapshot = copy.deepcopy(before)
    after_snapshot = copy.deepcopy(after)
    with pytest.raises(ValueError):
        diff(before, after)
    assert before == before_snapshot
    assert after == after_snapshot


# ---------------------------------------------------------------- endpoint


def test_http_diff_returns_200_compact_json():
    before = _before()
    after = _after()
    response = client.post(DIFF_PATH, json={"before": before, "after": after})
    assert response.status_code == 200
    expected = diff(before, after)
    assert response.json() == expected
    expected_body = json.dumps(
        expected, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert response.content == expected_body
    assert not response.content.endswith(b"\n")
    assert "中".encode("utf-8") in response.content
    assert "允许".encode("utf-8") in response.content


def test_http_diff_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("diff endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        DIFF_PATH, json={"before": _before(), "after": _after()}
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
        b'{"before": {}}',
        b'{"before": {}, "after": {}, "extra": 1}',
        b'{"earlier": {}, "later": {}}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        DIFF_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_value_error_in_function_is_422():
    response = client.post(
        DIFF_PATH,
        json={"before": {"root": "0" * 64}, "after": _after()},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
