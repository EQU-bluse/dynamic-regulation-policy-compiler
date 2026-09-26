import copy
import functools
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    bundle_evolution_checkpoint,
    bundle_evolution_checkpoint_bundle,
    bundle_evolution_checkpoint_bundle_diff,
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

DIFF_PATH = (
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
    "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff"
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


@functools.lru_cache(maxsize=1)
def _chain_cached():
    return _chain()


def _chain_window_proof(start, end):
    return checkpoint_chain_checkpoint(_chain_cached(), start, end)


@functools.lru_cache(maxsize=1)
def _delivery_bundle_one_raw():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _chain_window_proof(RT1, RT1)},
            {"id": "beta", "proof": _chain_window_proof(RT2, RT3)},
        ]
    )


@functools.lru_cache(maxsize=1)
def _delivery_bundle_two_raw():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _chain_window_proof(RT1, RT1)},
            {"id": "beta", "proof": _chain_window_proof(RT2, RT2)},
            {"id": "伽马", "proof": _chain_window_proof(RT3, RT3)},
        ]
    )


@functools.lru_cache(maxsize=1)
def _delivery_bundle_three_raw():
    return checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _chain_window_proof(RT1, RT2)},
            {"id": "伽马", "proof": _chain_window_proof(RT3, RT3)},
        ]
    )


def _delivery_bundle_one():
    return copy.deepcopy(_delivery_bundle_one_raw())


def _delivery_bundle_two():
    return copy.deepcopy(_delivery_bundle_two_raw())


def _delivery_bundle_three():
    return copy.deepcopy(_delivery_bundle_three_raw())


@functools.lru_cache(maxsize=1)
def _delivery_evolution_raw():
    return checkpoint_chain_checkpoint_bundle_evolution(
        [
            {"at": DT1, "bundle": _delivery_bundle_one()},
            {"at": DT2, "bundle": _delivery_bundle_two()},
            {"at": DT3, "bundle": _delivery_bundle_three()},
        ]
    )


def _delivery_evolution():
    return copy.deepcopy(_delivery_evolution_raw())


@functools.lru_cache(maxsize=None)
def _window_proof_raw(start, end):
    return bundle_evolution_checkpoint(_delivery_evolution_raw(), start, end)


def _window_proof(start, end):
    return copy.deepcopy(_window_proof_raw(start, end))


@functools.lru_cache(maxsize=1)
def _bundle_before_raw():
    return bundle_evolution_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(DT1, DT2)},
            {"id": "beta", "proof": _window_proof(DT2, DT3)},
        ]
    )


@functools.lru_cache(maxsize=1)
def _bundle_after_raw():
    return bundle_evolution_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(DT1, DT2)},
            {"id": "beta", "proof": _window_proof(DT3, DT3)},
            {"id": "伽马", "proof": _window_proof(DT1, DT3)},
        ]
    )


def _bundle_before():
    return copy.deepcopy(_bundle_before_raw())


def _bundle_after():
    return copy.deepcopy(_bundle_after_raw())


@functools.lru_cache(maxsize=1)
def _diff_raw():
    return bundle_evolution_checkpoint_bundle_diff(
        _bundle_before_raw(), _bundle_after_raw()
    )


def _diff():
    return copy.deepcopy(_diff_raw())


# ---------------------------------------------------------------- structure


def test_top_level_and_change_key_order():
    report = _diff()
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
    ]


def test_roots_match_the_two_bundles():
    before = _bundle_before()
    after = _bundle_after()
    report = bundle_evolution_checkpoint_bundle_diff(before, after)
    assert report["before_root"] == before["root"]
    assert report["after_root"] == after["root"]


def test_before_and_after_are_normalized_bundle_copies():
    before = _bundle_before()
    after = _bundle_after()
    report = bundle_evolution_checkpoint_bundle_diff(before, after)
    assert report["before"] == before
    assert report["after"] == after
    assert report["before"] is not report["after"]
    assert report["before"] is not before
    assert report["after"] is not after


def test_added_change_shape():
    report = _diff()
    added = next(change for change in report["changes"] if change["id"] == "伽马")
    assert added["kind"] == "added"
    assert added["before"] is None
    assert added["after"] == _bundle_after()["proofs"][-1]["proof"]


def test_removed_change_shape():
    after = bundle_evolution_checkpoint_bundle(
        [{"id": "alpha", "proof": _window_proof(DT1, DT2)}]
    )
    report = bundle_evolution_checkpoint_bundle_diff(_bundle_before(), after)
    (change,) = report["changes"]
    assert change["id"] == "beta"
    assert change["kind"] == "removed"
    assert change["before"] == _bundle_before()["proofs"][-1]["proof"]
    assert change["after"] is None


def test_changed_change_shape():
    report = _diff()
    changed = next(change for change in report["changes"] if change["id"] == "beta")
    assert changed["kind"] == "changed"
    assert changed["before"] == _bundle_before()["proofs"][-1]["proof"]
    assert changed["after"] == _bundle_after()["proofs"][1]["proof"]


def test_changes_sorted_by_unicode_code_point():
    # beta (changed, ASCII) sorts before 伽马 (added, CJK).
    report = _diff()
    assert [(c["id"], c["kind"]) for c in report["changes"]] == [
        ("beta", "changed"),
        ("伽马", "added"),
    ]


def test_added_and_removed_sorted_by_unicode_code_point():
    before = bundle_evolution_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(DT1, DT2)},
            {"id": "beta", "proof": _window_proof(DT2, DT3)},
        ]
    )
    after = bundle_evolution_checkpoint_bundle(
        [
            {"id": "alpha", "proof": _window_proof(DT1, DT2)},
            {"id": "delta", "proof": _window_proof(DT3, DT3)},
        ]
    )
    report = bundle_evolution_checkpoint_bundle_diff(before, after)
    assert [(c["id"], c["kind"]) for c in report["changes"]] == [
        ("beta", "removed"),
        ("delta", "added"),
    ]


def test_identical_bundles_yield_empty_changes():
    bundle = _bundle_before()
    report = bundle_evolution_checkpoint_bundle_diff(bundle, bundle)
    assert report["changes"] == []
    assert report["before_root"] == report["after_root"] == bundle["root"]


def test_unchanged_member_is_omitted():
    report = _diff()
    assert "alpha" not in {change["id"] for change in report["changes"]}


def test_digest_covers_first_five_items():
    report = _diff()
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
    before = _bundle_before()
    after = _bundle_after()

    def reverse_key_order(value):
        if isinstance(value, dict):
            return {k: reverse_key_order(v) for k, v in reversed(list(value.items()))}
        if isinstance(value, list):
            return [reverse_key_order(item) for item in value]
        return value

    first = bundle_evolution_checkpoint_bundle_diff(before, after)
    second = bundle_evolution_checkpoint_bundle_diff(
        reverse_key_order(before), reverse_key_order(after)
    )
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_caller_member_order_does_not_change_result():
    items = [
        {"id": "beta", "proof": _window_proof(DT2, DT3)},
        {"id": "alpha", "proof": _window_proof(DT1, DT2)},
    ]
    before = bundle_evolution_checkpoint_bundle(items)
    after = bundle_evolution_checkpoint_bundle(list(reversed(items)))
    assert bundle_evolution_checkpoint_bundle_diff(
        before, _bundle_after()
    ) == bundle_evolution_checkpoint_bundle_diff(after, _bundle_after())


def test_layers_do_not_share_mutable_containers():
    report = _diff()
    added = next(change for change in report["changes"] if change["id"] == "伽马")
    # The added proof is independent of the embedded after bundle copy.
    assert added["after"] is not None
    assert added["after"] is not report["after"]["proofs"][-1]["proof"]
    added["after"]["commitment"] = "mutated"
    assert report["after"]["proofs"][-1]["proof"]["commitment"] != "mutated"
    # The two sides of the diff do not share embedded containers either.
    changed = next(change for change in report["changes"] if change["id"] == "beta")
    changed["before"]["stages"][0]["digest"] = "mutated"
    assert report["before"]["proofs"][-1]["proof"]["stages"][0]["digest"] != (
        "mutated"
    )


def test_does_not_mutate_inputs():
    before = _bundle_before()
    after = _bundle_after()
    before_snapshot = copy.deepcopy(before)
    after_snapshot = copy.deepcopy(after)
    bundle_evolution_checkpoint_bundle_diff(before, after)
    assert before == before_snapshot
    assert after == after_snapshot


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "before,after",
    [
        (None, _bundle_after()),
        ("x", _bundle_after()),
        ([], _bundle_after()),
        ({}, _bundle_after()),
        ({"root": "0" * 64}, _bundle_after()),
        (_bundle_before(), None),
        (_bundle_before(), {}),
        (_bundle_before(), {"root": "0" * 64, "proofs": []}),
    ],
)
def test_invalid_bundle_shape_raises(before, after):
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle_diff(before, after)


def test_structurally_invalid_member_proof_raises():
    before = copy.deepcopy(_bundle_before())
    before["proofs"][0]["proof"] = {"start": DT1}
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle_diff(before, _bundle_after())


def test_false_bundle_root_raises():
    before = copy.deepcopy(_bundle_before())
    before["root"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle_diff(before, _bundle_after())


def test_false_member_digest_raises():
    after = copy.deepcopy(_bundle_after())
    after["proofs"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle_diff(_bundle_before(), after)


def test_broken_member_chain_link_raises():
    before = copy.deepcopy(_bundle_before())
    before["proofs"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle_diff(before, _bundle_after())


def test_untruthful_window_proof_raises():
    after = copy.deepcopy(_bundle_after())
    after["proofs"][0]["proof"]["stages"][0]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle_diff(_bundle_before(), after)


def test_false_window_proof_commitment_raises():
    before = copy.deepcopy(_bundle_before())
    before["proofs"][0]["proof"]["commitment"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle_diff(before, _bundle_after())


def test_semantic_forgery_in_deep_window_proof_raises():
    before = copy.deepcopy(_bundle_before())
    node = before["proofs"][0]["proof"]
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
        bundle_evolution_checkpoint_bundle_diff(before, _bundle_after())


def test_second_side_still_checked_when_first_summary_is_false():
    # before carries a format-valid but false root; that must not short-circuit
    # the full structural validation of the malformed after bundle.
    before = copy.deepcopy(_bundle_before())
    before["root"] = "f" * 64
    after = {"proofs": [{"id": "a"}]}
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle_diff(before, after)


def test_first_side_still_checked_when_second_summary_is_false():
    before = {"proofs": "not-a-list"}
    after = copy.deepcopy(_bundle_after())
    after["root"] = "f" * 64
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle_diff(before, after)


def test_invalid_input_does_not_mutate_bundles():
    before = copy.deepcopy(_bundle_before())
    before["root"] = "f" * 64
    after = _bundle_after()
    before_snapshot = copy.deepcopy(before)
    after_snapshot = copy.deepcopy(after)
    with pytest.raises(ValueError):
        bundle_evolution_checkpoint_bundle_diff(before, after)
    assert before == before_snapshot
    assert after == after_snapshot


# ---------------------------------------------------------------- endpoint


def test_http_diff_returns_200_compact_json():
    before = _bundle_before()
    after = _bundle_after()
    response = client.post(DIFF_PATH, json={"before": before, "after": after})
    assert response.status_code == 200
    assert response.json() == bundle_evolution_checkpoint_bundle_diff(before, after)
    expected_body = json.dumps(
        bundle_evolution_checkpoint_bundle_diff(before, after),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert response.content == expected_body
    assert not response.content.endswith(b"\n")
    assert "伽马".encode("utf-8") in response.content
    assert "允许".encode("utf-8") in response.content


def test_http_diff_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("diff endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        DIFF_PATH, json={"before": _bundle_before(), "after": _bundle_after()}
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
        json={"before": {"root": "0" * 64}, "after": _bundle_after()},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
