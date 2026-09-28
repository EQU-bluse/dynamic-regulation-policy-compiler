import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

import test_bundle_evolution_checkpoint_bundle_evolution_checkpoint as fx
from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    bundle_evolution_checkpoint_bundle_evolution_checkpoint as cut_window,
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle as bind,
)

client = TestClient(app)

BUNDLE_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/"
    "checkpoint/bundle"
)

GENESIS = "0" * 64


def _proof(start, end):
    return fx._proof(start, end)


def _items():
    return [
        {"id": "z", "proof": _proof(fx.ET2, fx.ET3)},
        {"id": "a", "proof": _proof(fx.ET1, fx.ET2)},
    ]


def _member_digest(previous, item_id, proof):
    payload = json.dumps(
        {"id": item_id, "proof": proof},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(
        previous.encode("ascii") + payload.encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------- structure


def test_top_level_and_member_key_order():
    bundle = bind(_items())
    assert list(bundle) == ["root", "proofs"]
    for member in bundle["proofs"]:
        assert list(member) == ["id", "proof", "previous", "digest"]


def test_members_sorted_by_id_code_point_regardless_of_caller_order():
    bundle = bind(_items())
    assert [m["id"] for m in bundle["proofs"]] == ["a", "z"]


def test_non_ascii_ids_follow_code_point_order():
    bundle = bind(
        [
            {"id": "中", "proof": _proof(fx.ET1, fx.ET3)},
            {"id": "a", "proof": _proof(fx.ET1, fx.ET2)},
        ]
    )
    assert [m["id"] for m in bundle["proofs"]] == ["a", "中"]


def test_chain_links_and_root():
    bundle = bind(_items())
    assert bundle["proofs"][0]["previous"] == GENESIS
    assert bundle["proofs"][1]["previous"] == bundle["proofs"][0]["digest"]
    assert bundle["root"] == bundle["proofs"][-1]["digest"]


def test_member_digests_recompute():
    bundle = bind(_items())
    previous = GENESIS
    for member in bundle["proofs"]:
        assert member["digest"] == _member_digest(
            previous, member["id"], member["proof"]
        )
        previous = member["digest"]


def test_proofs_are_normalized_deep_copies():
    proof = _proof(fx.ET1, fx.ET2)
    bundle = bind([{"id": "a", "proof": proof}])
    assert bundle["proofs"][0]["proof"] == proof
    assert bundle["proofs"][0]["proof"] is not proof


def test_does_not_mutate_items():
    items = _items()
    snapshot = copy.deepcopy(items)
    bind(items)
    assert items == snapshot


def test_mutating_result_does_not_touch_inputs():
    items = _items()
    bundle = bind(items)
    bundle["proofs"][0]["proof"]["commitment"] = "f" * 64
    bundle["proofs"][0]["id"] = "hacked"
    assert items[1]["proof"]["commitment"] == _proof(fx.ET1, fx.ET2)["commitment"]
    assert items[1]["id"] == "a"


def test_equal_valued_inputs_are_byte_identical():
    left = json.dumps(
        bind(_items()), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    right = json.dumps(
        bind(list(reversed(copy.deepcopy(_items())))),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert left == right


def test_single_item_bundle():
    bundle = bind([{"id": "only", "proof": _proof(fx.ET1, fx.ET3)}])
    assert len(bundle["proofs"]) == 1
    member = bundle["proofs"][0]
    assert member["previous"] == GENESIS
    assert bundle["root"] == member["digest"]


def test_carried_diff_window_proof_is_accepted():
    # A non-head single-stage window relies on its carried diff; it must
    # bind without the report outside the window.
    proof = cut_window(fx._evolution(), fx.ET2, fx.ET2)
    bundle = bind([{"id": "a", "proof": proof}])
    assert bundle["proofs"][0]["proof"] == proof


@pytest.mark.parametrize(
    "items",
    [
        None,
        [],
        "x",
        ["x"],
        [{"id": "a"}],
        [{"proof": _proof(fx.ET1, fx.ET2)}],
        [{"id": "a", "proof": _proof(fx.ET1, fx.ET2), "extra": 1}],
        [{"id": 1, "proof": _proof(fx.ET1, fx.ET2)}],
        [{"id": None, "proof": _proof(fx.ET1, fx.ET2)}],
        [{"id": "", "proof": _proof(fx.ET1, fx.ET2)}],
    ],
)
def test_invalid_items_raise(items):
    with pytest.raises(ValueError):
        bind(items)


def test_duplicate_ids_raise():
    with pytest.raises(ValueError):
        bind(
            [
                {"id": "a", "proof": _proof(fx.ET1, fx.ET2)},
                {"id": "a", "proof": _proof(fx.ET2, fx.ET3)},
            ]
        )


def test_structurally_invalid_proof_raises():
    with pytest.raises(ValueError):
        bind([{"id": "a", "proof": {"start": fx.ET1}}])


def test_proof_missing_key_raises():
    proof = dict(_proof(fx.ET1, fx.ET2))
    del proof["anchor"]
    with pytest.raises(ValueError):
        bind([{"id": "a", "proof": proof}])


def test_untruthful_proof_raises():
    proof = _proof(fx.ET1, fx.ET3)
    proof["stages"][1]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        bind([{"id": "a", "proof": proof}])


def test_forged_commitment_proof_raises():
    proof = _proof(fx.ET2, fx.ET3)
    proof["commitment"] = "f" * 64
    with pytest.raises(ValueError):
        bind([{"id": "a", "proof": proof}])


def test_broken_stage_link_proof_raises():
    proof = _proof(fx.ET1, fx.ET3)
    proof["stages"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        bind([{"id": "a", "proof": proof}])


def test_forged_embedded_bundle_member_digest_raises():
    proof = _proof(fx.ET1, fx.ET3)
    proof["stages"][0]["bundle"]["proofs"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        bind([{"id": "a", "proof": proof}])


def test_invalid_input_does_not_mutate_items():
    proof = _proof(fx.ET1, fx.ET2)
    proof["commitment"] = "f" * 64
    items = [{"id": "a", "proof": proof}]
    snapshot = copy.deepcopy(items)
    with pytest.raises(ValueError):
        bind(items)
    assert items == snapshot


# ---------------------------------------------------------------- endpoint


def test_http_bundle_returns_200_compact_json():
    response = client.post(BUNDLE_PATH, json={"items": _items()})
    assert response.status_code == 200
    expected = bind(_items())
    assert response.json() == expected
    expected_body = json.dumps(
        expected, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert response.content == expected_body
    assert not response.content.endswith(b"\n")
    assert "伽马".encode("utf-8") in response.content
    assert "允许".encode("utf-8") in response.content


def test_http_bundle_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("bundle endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(BUNDLE_PATH, json={"items": _items()})
    assert response.status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b'"x"',
        b"null",
        b"{}",
        b'{"items": null}',
        b'{"items": []}',
        b'{"items": [{"id": "a", "proof": {}}]}',
        b'{"items": [{"id": "a", "proof": {}}], "extra": 1}',
        b'{"items": [{"id": "a", "proof": {}}], "report": {}}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        BUNDLE_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_untruthful_proof_is_422():
    proof = _proof(fx.ET1, fx.ET2)
    proof["commitment"] = "f" * 64
    response = client.post(
        BUNDLE_PATH,
        json={"items": [{"id": "a", "proof": proof}]},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
