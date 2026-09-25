import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    bundle_evolution_checkpoint,
    bundle_evolution_checkpoint_bundle,
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
GENESIS = "0" * 64

BUNDLE_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution/checkpoint/bundle"
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


def _items():
    return [
        {"id": "beta", "proof": _proof(DT2, DT3)},
        {"id": "alpha", "proof": _proof(DT1, DT1)},
        {"id": "伽马", "proof": _proof(DT3, DT3)},
    ]


def _member_digest(previous, item_id, proof):
    payload = {"id": item_id, "proof": proof}
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(
        previous.encode("ascii") + canonical.encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------- structure


def test_top_level_and_member_key_order():
    bundle = bundle_evolution_checkpoint_bundle(_items())
    assert list(bundle) == ["root", "proofs"]
    for member in bundle["proofs"]:
        assert list(member) == ["id", "proof", "previous", "digest"]
        assert list(member["proof"]) == [
            "start",
            "end",
            "anchor",
            "stages",
            "commitment",
        ]


def test_members_sorted_by_id_code_point_regardless_of_caller_order():
    bundle = bundle_evolution_checkpoint_bundle(_items())
    assert [member["id"] for member in bundle["proofs"]] == [
        "alpha",
        "beta",
        "伽马",
    ]
    shuffled = bundle_evolution_checkpoint_bundle(list(reversed(_items())))
    assert shuffled == bundle


def test_chain_links_and_root():
    bundle = bundle_evolution_checkpoint_bundle(_items())
    members = bundle["proofs"]
    assert members[0]["previous"] == GENESIS
    for earlier, later in zip(members, members[1:]):
        assert later["previous"] == earlier["digest"]
    assert bundle["root"] == members[-1]["digest"]


def test_member_digests_recompute():
    bundle = bundle_evolution_checkpoint_bundle(_items())
    previous = GENESIS
    for member in bundle["proofs"]:
        recomputed = _member_digest(previous, member["id"], member["proof"])
        assert member["digest"] == recomputed
        previous = recomputed
    assert bundle["root"] == previous


def test_member_digest_covers_only_id_and_proof():
    bundle = bundle_evolution_checkpoint_bundle(_items())
    member = bundle["proofs"][0]
    payload = json.dumps(
        {"id": member["id"], "proof": member["proof"]},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    assert member["digest"] == hashlib.sha256(
        GENESIS.encode("ascii") + payload.encode("utf-8")
    ).hexdigest()


def test_proofs_are_normalized_deep_copies():
    items = _items()
    bundle = bundle_evolution_checkpoint_bundle(items)
    by_id = {member["id"]: member for member in bundle["proofs"]}
    assert by_id["alpha"]["proof"] == _proof(DT1, DT1)
    assert by_id["beta"]["proof"] == _proof(DT2, DT3)
    assert by_id["伽马"]["proof"] == _proof(DT3, DT3)
    for item in items:
        member = by_id[item["id"]]
        assert member["proof"] is not item["proof"]
        assert member["proof"]["stages"] is not item["proof"]["stages"]
        assert member["proof"]["stages"][0] is not item["proof"]["stages"][0]
        assert (
            member["proof"]["stages"][0]["bundle"]
            is not item["proof"]["stages"][0]["bundle"]
        )


def test_does_not_mutate_items():
    items = _items()
    snapshot = copy.deepcopy(items)
    bundle_evolution_checkpoint_bundle(items)
    assert items == snapshot


def test_mutating_result_does_not_touch_inputs():
    items = _items()
    bundle = bundle_evolution_checkpoint_bundle(items)
    bundle["proofs"][0]["proof"]["stages"][0]["digest"] = "mutated"
    assert items[1]["proof"]["stages"][0]["digest"] != "mutated"


def test_equal_valued_inputs_are_byte_identical():
    first = bundle_evolution_checkpoint_bundle(_items())
    second = bundle_evolution_checkpoint_bundle(copy.deepcopy(_items()))
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_single_item_bundle():
    bundle = bundle_evolution_checkpoint_bundle(
        [{"id": "only", "proof": _proof(DT2, DT2)}]
    )
    assert len(bundle["proofs"]) == 1
    assert bundle["proofs"][0]["previous"] == GENESIS
    assert bundle["root"] == bundle["proofs"][0]["digest"]


def test_window_proof_without_outside_report_is_accepted():
    # A middle single-stage window is self-contained thanks to its carried
    # front-side diff and must bundle without any access to the full report.
    bundle = bundle_evolution_checkpoint_bundle(
        [{"id": "solo", "proof": _proof(DT2, DT2)}]
    )
    assert bundle["proofs"][0]["id"] == "solo"


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "items",
    [
        None,
        "x",
        [],
        ["x"],
        [{"id": "a"}],
        [{"proof": {}}],
        [{"id": "a", "proof": {}, "extra": 1}],
        [{"id": "", "proof": {}}],
        [{"id": 1, "proof": {}}],
        [{"id": ["a"], "proof": {}}],
    ],
)
def test_invalid_items_raise(items):
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle(items)


def test_duplicate_ids_raise():
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle(
            [
                {"id": "a", "proof": _proof(DT1, DT1)},
                {"id": "a", "proof": _proof(DT2, DT2)},
            ]
        )


def test_structurally_invalid_proof_raises():
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle(
            [{"id": "a", "proof": {"start": DT1}}]
        )


def test_proof_missing_key_raises():
    proof = dict(_proof(DT1, DT1))
    del proof["anchor"]
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle([{"id": "a", "proof": proof}])


def test_untruthful_proof_raises():
    proof = _proof(DT1, DT3)
    proof["stages"][1]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle([{"id": "a", "proof": proof}])


def test_forged_commitment_proof_raises():
    proof = _proof(DT2, DT3)
    proof["commitment"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle([{"id": "a", "proof": proof}])


def test_broken_stage_link_proof_raises():
    proof = _proof(DT1, DT3)
    proof["stages"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle([{"id": "a", "proof": proof}])


def test_forged_embedded_bundle_proof_raises():
    proof = _proof(DT2, DT3)
    proof["stages"][0]["bundle"]["proofs"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle([{"id": "a", "proof": proof}])


def test_invalid_input_does_not_mutate_items():
    proof = _proof(DT1, DT1)
    proof["commitment"] = "f" * 64
    items = [{"id": "a", "proof": proof}]
    snapshot = copy.deepcopy(items)
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle(items)
    assert items == snapshot


# ---------------------------------------------------------------- endpoint


def test_http_bundle_returns_200_compact_json():
    response = client.post(BUNDLE_PATH, json={"items": _items()})
    assert response.status_code == 200
    expected = bundle_evolution_checkpoint_bundle(_items())
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
    proof = _proof(DT1, DT1)
    proof["commitment"] = "f" * 64
    response = client.post(
        BUNDLE_PATH,
        json={"items": [{"id": "a", "proof": proof}]},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
