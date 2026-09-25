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
E1 = "2021-11-01T00:00:00Z"
E2 = "2021-12-01T00:00:00Z"
E3 = "2022-01-01T00:00:00Z"
GENESIS = "0" * 64

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
        [{"id": "alpha", "proof": _window_proof(RT1, RT1)}]
    )


def _stages():
    return [
        {"at": E1, "bundle": _bundle_one()},
        {"at": E2, "bundle": _bundle_two()},
        {"at": E3, "bundle": _bundle_three()},
    ]


def _report():
    return checkpoint_chain_checkpoint_bundle_evolution(_stages())


def _stage_digest(previous, at, bundle, diff):
    payload = {"at": at, "bundle": bundle, "diff": diff}
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(
        previous.encode("ascii") + canonical.encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------- structure


def test_top_level_and_stage_key_order():
    report = _report()
    assert list(report) == ["root", "stages"]
    for stage in report["stages"]:
        assert list(stage) == ["at", "bundle", "diff", "previous", "digest"]
        assert list(stage["bundle"]) == ["root", "proofs"]


def test_first_stage_diff_is_null_and_later_diffs_are_full_credentials():
    report = _report()
    stages = report["stages"]
    assert stages[0]["diff"] is None
    assert stages[1]["diff"] == checkpoint_chain_checkpoint_bundle_diff(
        _bundle_one(), _bundle_two()
    )
    assert stages[2]["diff"] == checkpoint_chain_checkpoint_bundle_diff(
        _bundle_two(), _bundle_three()
    )
    for stage in stages[1:]:
        assert list(stage["diff"]) == [
            "before_root",
            "after_root",
            "before",
            "after",
            "changes",
            "digest",
        ]


def test_previous_chain_and_root():
    report = _report()
    stages = report["stages"]
    assert stages[0]["previous"] == GENESIS
    for earlier, later in zip(stages, stages[1:]):
        assert later["previous"] == earlier["digest"]
    assert report["root"] == stages[-1]["digest"]


def test_stage_digests_recompute():
    report = _report()
    previous = GENESIS
    for stage in report["stages"]:
        recomputed = _stage_digest(
            previous, stage["at"], stage["bundle"], stage["diff"]
        )
        assert stage["digest"] == recomputed
        previous = recomputed
    assert report["root"] == previous


def test_stage_digest_payload_covers_only_at_bundle_diff():
    report = _report()
    stage = report["stages"][1]
    payload = json.dumps(
        {"at": stage["at"], "bundle": stage["bundle"], "diff": stage["diff"]},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    assert stage["digest"] == hashlib.sha256(
        report["stages"][0]["digest"].encode("ascii") + payload.encode("utf-8")
    ).hexdigest()


def test_bundles_are_normalized_deep_copies():
    stages = _stages()
    report = checkpoint_chain_checkpoint_bundle_evolution(stages)
    for stage, source in zip(report["stages"], stages):
        assert stage["bundle"] == source["bundle"]
        assert stage["bundle"] is not source["bundle"]
        assert stage["bundle"]["proofs"] is not source["bundle"]["proofs"]
        assert stage["bundle"]["proofs"][0] is not source["bundle"]["proofs"][0]
        assert (
            stage["bundle"]["proofs"][0]["proof"]
            is not source["bundle"]["proofs"][0]["proof"]
        )


def test_does_not_mutate_stages():
    stages = _stages()
    snapshot = copy.deepcopy(stages)
    checkpoint_chain_checkpoint_bundle_evolution(stages)
    assert stages == snapshot


def test_mutating_result_does_not_touch_inputs():
    stages = _stages()
    report = checkpoint_chain_checkpoint_bundle_evolution(stages)
    report["stages"][0]["bundle"]["proofs"][0]["digest"] = "mutated"
    assert stages[0]["bundle"]["proofs"][0]["digest"] != "mutated"


def test_equal_valued_inputs_are_byte_identical():
    first = checkpoint_chain_checkpoint_bundle_evolution(_stages())
    second = checkpoint_chain_checkpoint_bundle_evolution(copy.deepcopy(_stages()))
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_single_stage_evolution():
    report = checkpoint_chain_checkpoint_bundle_evolution(
        [{"at": E2, "bundle": _bundle_one()}]
    )
    assert len(report["stages"]) == 1
    assert report["stages"][0]["diff"] is None
    assert report["stages"][0]["previous"] == GENESIS
    assert report["root"] == report["stages"][0]["digest"]


def test_identical_adjacent_bundles_yield_empty_changes():
    report = checkpoint_chain_checkpoint_bundle_evolution(
        [
            {"at": E1, "bundle": _bundle_one()},
            {"at": E2, "bundle": _bundle_one()},
        ]
    )
    assert report["stages"][1]["diff"]["changes"] == []
    assert report["stages"][1]["diff"]["before_root"] == (
        report["stages"][1]["diff"]["after_root"]
    )


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "stages",
    [
        None,
        "x",
        [],
        ["x"],
        [{"at": E1}],
        [{"bundle": {}}],
        [{"at": E1, "bundle": {}, "extra": 1}],
        [{"at": "not-a-time", "bundle": {}}],
        [{"at": 0, "bundle": {}}],
    ],
)
def test_invalid_stages_raise(stages):
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint_bundle_evolution(stages)


def test_duplicate_times_raise():
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint_bundle_evolution(
            [
                {"at": E1, "bundle": _bundle_one()},
                {"at": E1, "bundle": _bundle_two()},
            ]
        )


def test_disordered_times_raise():
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint_bundle_evolution(
            [
                {"at": E2, "bundle": _bundle_one()},
                {"at": E1, "bundle": _bundle_two()},
            ]
        )


def test_structurally_invalid_bundle_raises():
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint_bundle_evolution(
            [{"at": E1, "bundle": {"root": "f" * 64}}]
        )


def test_untruthful_bundle_root_raises():
    bundle = _bundle_one()
    bundle["root"] = "f" * 64
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint_bundle_evolution(
            [{"at": E1, "bundle": bundle}]
        )


def test_broken_member_chain_bundle_raises():
    bundle = _bundle_one()
    bundle["proofs"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint_bundle_evolution(
            [{"at": E1, "bundle": bundle}]
        )


def test_untruthful_embedded_window_proof_raises():
    bundle = _bundle_one()
    bundle["proofs"][0]["proof"]["commitment"] = "f" * 64
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint_bundle_evolution(
            [{"at": E1, "bundle": bundle}]
        )


def test_invalid_input_does_not_mutate_stages():
    bundle = _bundle_one()
    bundle["root"] = "f" * 64
    stages = [{"at": E1, "bundle": bundle}]
    snapshot = copy.deepcopy(stages)
    with pytest.raises(ValueError):
        checkpoint_chain_checkpoint_bundle_evolution(stages)
    assert stages == snapshot


# ---------------------------------------------------------------- endpoint


def test_http_evolution_returns_200_compact_json():
    response = client.post(EVOLUTION_PATH, json={"stages": _stages()})
    assert response.status_code == 200
    expected = _report()
    assert response.json() == expected
    expected_body = json.dumps(
        expected, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert response.content == expected_body
    assert not response.content.endswith(b"\n")
    assert "伽马".encode("utf-8") in response.content
    assert "允许".encode("utf-8") in response.content


def test_http_evolution_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("evolution endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(EVOLUTION_PATH, json={"stages": _stages()})
    assert response.status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b'"x"',
        b"null",
        b"{}",
        b'{"stages": null}',
        b'{"stages": []}',
        b'{"stages": [{"at": "2021-11-01T00:00:00Z"}]}',
        b'{"stages": [], "extra": 1}',
        b'{"stages": [], "report": {}}',
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


def test_http_untruthful_bundle_is_422():
    bundle = _bundle_one()
    bundle["root"] = "f" * 64
    response = client.post(
        EVOLUTION_PATH,
        json={"stages": [{"at": E1, "bundle": bundle}]},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
