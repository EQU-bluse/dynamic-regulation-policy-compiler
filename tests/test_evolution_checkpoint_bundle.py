import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    evolution_checkpoint,
    evolution_checkpoint_bundle,
    matrix_bundle_evolution,
    verify_evolution_checkpoint_bundle,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"
AT1 = "2021-05-01T00:00:00Z"
AT2 = "2021-06-01T00:00:00Z"
AT3 = "2021-07-01T00:00:00Z"
GENESIS = "0" * 64


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
    return decision_matrix_attestation_bundle([{"id": "a", "report": _report_a()}])


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


def _evolution():
    return matrix_bundle_evolution(
        [
            {"at": AT1, "bundle": _bundle_one()},
            {"at": AT2, "bundle": _bundle_two()},
            {"at": AT3, "bundle": _bundle_three()},
        ]
    )


def _proof_head():
    return evolution_checkpoint(_evolution(), AT1, AT2)


def _proof_tail():
    return evolution_checkpoint(_evolution(), AT2, AT3)


def _proof_single():
    return evolution_checkpoint(_evolution(), AT3, AT3)


def _items():
    return [
        {"id": "beta", "proof": _proof_tail()},
        {"id": "alpha", "proof": _proof_head()},
        {"id": "gamma", "proof": _proof_single()},
    ]


def _bundle():
    return evolution_checkpoint_bundle(_items())


def _expected(bundle):
    return {
        "root": bundle["root"],
        "proof_ids": [member["id"] for member in reversed(bundle["proofs"])],
    }


def _member_digest(previous, member):
    payload = json.dumps(
        {"id": member["id"], "proof": member["proof"]},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(
        previous.encode("ascii") + payload.encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------- structure


def test_top_level_and_member_key_order():
    bundle = _bundle()
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
    bundle = _bundle()
    assert [member["id"] for member in bundle["proofs"]] == [
        "alpha",
        "beta",
        "gamma",
    ]
    reordered = evolution_checkpoint_bundle(list(reversed(_items())))
    assert json.dumps(bundle, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        reordered, ensure_ascii=False, separators=(",", ":")
    )


def test_member_chain_and_root_recompute():
    bundle = _bundle()
    previous = GENESIS
    for member in bundle["proofs"]:
        assert member["previous"] == previous
        digest = _member_digest(previous, member)
        assert member["digest"] == digest
        previous = digest
    assert bundle["root"] == previous


def test_first_member_previous_is_64_zeroes():
    bundle = _bundle()
    assert bundle["proofs"][0]["previous"] == GENESIS
    assert len(bundle["proofs"][0]["previous"]) == 64


def test_single_item_bundle():
    bundle = evolution_checkpoint_bundle([{"id": "only", "proof": _proof_head()}])
    assert len(bundle["proofs"]) == 1
    assert bundle["root"] == bundle["proofs"][0]["digest"]


def test_proof_is_independent_deep_copy():
    items = _items()
    bundle = evolution_checkpoint_bundle(items)
    for member in bundle["proofs"]:
        source = next(item["proof"] for item in items if item["id"] == member["id"])
        assert member["proof"] == source
        assert member["proof"] is not source
        assert member["proof"]["stages"] is not source["stages"]
        assert member["proof"]["stages"][0] is not source["stages"][0]
        assert member["proof"]["stages"][0]["bundle"] is not (
            source["stages"][0]["bundle"]
        )


def test_does_not_mutate_items():
    items = _items()
    snapshot = copy.deepcopy(items)
    evolution_checkpoint_bundle(items)
    assert items == snapshot


def test_mutating_bundle_does_not_touch_inputs():
    items = _items()
    bundle = evolution_checkpoint_bundle(items)
    bundle["proofs"][0]["proof"]["stages"][0]["digest"] = "mutated"
    assert items[1]["proof"]["stages"][0]["digest"] != "mutated"


def test_equal_valued_inputs_are_byte_identical():
    first = evolution_checkpoint_bundle(_items())
    second = evolution_checkpoint_bundle(_items())
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "items",
    [
        None,
        "x",
        [],
        [{"id": "a"}],
        [{"id": "a", "proof": None}],
        [{"id": "a", "proof": "x", "extra": 1}],
        [{"id": "", "proof": "x"}],
        [{"id": 1, "proof": "x"}],
    ],
)
def test_invalid_items_raise(items):
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle(items)


def test_duplicate_ids_raise():
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle(
            [
                {"id": "a", "proof": _proof_head()},
                {"id": "a", "proof": _proof_tail()},
            ]
        )


def test_structurally_illegal_proof_raises():
    proof = _proof_head()
    proof["stages"][0]["digest"] = "not-hex"
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle([{"id": "a", "proof": proof}])


def test_untruthful_proof_raises():
    proof = _proof_head()
    proof["stages"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle([{"id": "a", "proof": proof}])


def test_forged_bundle_inside_proof_raises():
    proof = _proof_head()
    proof["stages"][0]["bundle"]["reports"][0]["report"]["matrix"]["points"][0][
        "cases"
    ][0]["decision"] = "forged"
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle([{"id": "a", "proof": proof}])


def test_invalid_items_do_not_mutate_inputs():
    items = _items()
    items[0]["proof"]["commitment"] = "f" * 64
    snapshot = copy.deepcopy(items)
    with pytest.raises(ValueError):
        evolution_checkpoint_bundle(items)
    assert items == snapshot


# ------------------------------------------------------------------- verify


def test_verify_generated_bundle_is_true():
    bundle = _bundle()
    assert verify_evolution_checkpoint_bundle(bundle, _expected(bundle)) is True


def test_verify_proof_ids_order_is_irrelevant():
    bundle = _bundle()
    expected = {
        "root": bundle["root"],
        "proof_ids": ["gamma", "alpha", "beta"],
    }
    assert verify_evolution_checkpoint_bundle(bundle, expected) is True


def test_verify_wrong_root_is_false():
    bundle = _bundle()
    expected = _expected(bundle)
    expected["root"] = "f" * 64
    assert verify_evolution_checkpoint_bundle(bundle, expected) is False


def test_verify_wrong_proof_ids_is_false():
    bundle = _bundle()
    expected = _expected(bundle)
    expected["proof_ids"] = ["alpha", "beta", "delta"]
    assert verify_evolution_checkpoint_bundle(bundle, expected) is False


def test_verify_tampered_member_digest_is_false():
    bundle = _bundle()
    bundle["proofs"][1]["digest"] = "f" * 64
    assert (
        verify_evolution_checkpoint_bundle(bundle, _expected(bundle)) is False
    )


def test_verify_tampered_member_previous_is_false():
    bundle = _bundle()
    bundle["proofs"][1]["previous"] = "f" * 64
    assert (
        verify_evolution_checkpoint_bundle(bundle, _expected(bundle)) is False
    )


def test_verify_tampered_proof_digest_is_false():
    bundle = _bundle()
    bundle["proofs"][0]["proof"]["stages"][0]["digest"] = "f" * 64
    assert (
        verify_evolution_checkpoint_bundle(bundle, _expected(bundle)) is False
    )


def test_verify_tampered_proof_anchor_is_false():
    bundle = _bundle()
    bundle["proofs"][1]["proof"]["anchor"] = "f" * 64
    assert (
        verify_evolution_checkpoint_bundle(bundle, _expected(bundle)) is False
    )


def test_verify_swapped_member_proofs_is_false():
    bundle = _bundle()
    first_proof = bundle["proofs"][0]["proof"]
    bundle["proofs"][0]["proof"] = bundle["proofs"][1]["proof"]
    bundle["proofs"][1]["proof"] = first_proof
    assert (
        verify_evolution_checkpoint_bundle(bundle, _expected(bundle)) is False
    )


def test_verify_does_not_mutate_inputs():
    bundle = _bundle()
    expected = _expected(bundle)
    bundle_snapshot = copy.deepcopy(bundle)
    expected_snapshot = copy.deepcopy(expected)
    verify_evolution_checkpoint_bundle(bundle, expected)
    assert bundle == bundle_snapshot
    assert expected == expected_snapshot


@pytest.mark.parametrize(
    "report",
    [
        None,
        [],
        {},
        {"root": "0" * 64},
        {"root": "0" * 64, "proofs": []},
        {"root": "0" * 64, "proofs": [], "extra": 1},
        {"root": "not-hex", "proofs": [{"id": "a"}]},
    ],
)
def test_verify_invalid_report_raises(report):
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(report, {"root": "0" * 64, "proof_ids": ["a"]})


def test_verify_member_wrong_keys_raise():
    bundle = _bundle()
    del bundle["proofs"][0]["previous"]
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(bundle, _expected(bundle))


def test_verify_member_bad_digest_format_raises():
    bundle = _bundle()
    bundle["proofs"][0]["digest"] = "F" * 64
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(bundle, _expected(bundle))


def test_verify_duplicate_member_ids_raise():
    bundle = _bundle()
    bundle["proofs"][1]["id"] = bundle["proofs"][0]["id"]
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(bundle, _expected(bundle))


def test_verify_misordered_members_raise():
    bundle = _bundle()
    bundle["proofs"] = list(reversed(bundle["proofs"]))
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(bundle, _expected(bundle))


def test_verify_structurally_illegal_proof_raises():
    bundle = _bundle()
    bundle["proofs"][0]["proof"]["anchor"] = "zz"
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(bundle, _expected(bundle))


@pytest.mark.parametrize(
    "expected",
    [
        None,
        [],
        {},
        {"root": "0" * 64},
        {"proof_ids": ["a"]},
        {"root": "0" * 64, "proof_ids": []},
        {"root": "0" * 64, "proof_ids": ["a"], "extra": 1},
        {"root": "0" * 64, "proof_ids": ["a", "a"]},
        {"root": "0" * 64, "proof_ids": ["a", ""]},
        {"root": "0" * 64, "proof_ids": ["a", 1]},
        {"root": "zz", "proof_ids": ["a"]},
    ],
)
def test_verify_invalid_expected_raises(expected):
    with pytest.raises(ValueError):
        verify_evolution_checkpoint_bundle(_bundle(), expected)


# ---------------------------------------------------------------- endpoint


def test_http_bundle_returns_200_compact_json():
    body = {"items": _items()}
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle", json=body
    )
    assert response.status_code == 200
    expected_bundle = evolution_checkpoint_bundle(_items())
    assert response.json() == expected_bundle
    expected_body = json.dumps(
        expected_bundle, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert response.content == expected_body
    assert not response.content.endswith(b"\n")
    assert "允许" in response.content.decode("utf-8")


def test_http_bundle_verify_returns_200_valid_true():
    bundle = evolution_checkpoint_bundle(_items())
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle)},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":true}'


def test_http_bundle_verify_returns_200_valid_false():
    bundle = evolution_checkpoint_bundle(_items())
    expected = _expected(bundle)
    expected["root"] = "f" * 64
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/verify",
        json={"report": bundle, "expected": expected},
    )
    assert response.status_code == 200
    assert response.content == b'{"valid":false}'


def test_http_bundle_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("bundle endpoints must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle",
        json={"items": [{"id": "a", "proof": _proof_head()}]},
    )
    assert response.status_code == 200
    bundle = response.json()
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b'"x"',
        b"null",
        b"{}",
        b'{"items": []}',
        b'{"items": [{}]}',
        b'{"items": [], "extra": 1}',
    ],
)
def test_http_bundle_bad_body_is_422(body):
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_bundle_invalid_proof_is_422():
    proof = _proof_head()
    proof["commitment"] = "f" * 64
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle",
        json={"items": [{"id": "a", "proof": proof}]},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b"null",
        b"{}",
        b'{"report": {}}',
        b'{"expected": {}}',
        b'{"report": {}, "expected": {}, "extra": 1}',
    ],
)
def test_http_bundle_verify_bad_body_is_422(body):
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/verify",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_bundle_verify_invalid_report_is_422():
    bundle = evolution_checkpoint_bundle(_items())
    bundle["proofs"][0]["digest"] = "zz"
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle)},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
