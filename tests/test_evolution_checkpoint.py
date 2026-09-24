import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    evolution_checkpoint,
    matrix_bundle_evolution,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"
AT1 = "2021-05-01T00:00:00Z"
AT2 = "2021-06-01T00:00:00Z"
AT3 = "2021-07-01T00:00:00Z"
OTHER = "2021-06-15T00:00:00Z"


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


def _stage_inputs():
    return [
        {"at": AT1, "bundle": _bundle_one()},
        {"at": AT2, "bundle": _bundle_two()},
        {"at": AT3, "bundle": _bundle_three()},
    ]


def _evolution():
    return matrix_bundle_evolution(_stage_inputs())


# ---------------------------------------------------------------- structure


def test_top_level_key_order_and_exact_keys():
    proof = evolution_checkpoint(_evolution(), AT2, AT3)
    assert list(proof) == ["start", "end", "anchor", "stages", "commitment"]
    for stage in proof["stages"]:
        assert list(stage) == ["at", "bundle", "diff", "previous", "digest"]


def test_full_window_from_head_uses_zero_anchor_and_all_stages():
    report = _evolution()
    proof = evolution_checkpoint(report, AT1, AT3)
    assert proof["start"] == AT1
    assert proof["end"] == AT3
    assert proof["anchor"] == "0" * 64
    assert proof["stages"] == report["stages"]
    assert proof["commitment"] == report["stages"][-1]["digest"]
    assert proof["commitment"] == report["root"]


def test_middle_window_anchors_at_preceding_digest():
    report = _evolution()
    proof = evolution_checkpoint(report, AT2, AT3)
    assert proof["anchor"] == report["stages"][0]["digest"]
    assert [stage["at"] for stage in proof["stages"]] == [AT2, AT3]


def test_middle_first_stage_keeps_original_diff_and_previous():
    report = _evolution()
    proof = evolution_checkpoint(report, AT2, AT3)
    first = proof["stages"][0]
    original = report["stages"][1]
    assert first["at"] == AT2
    assert first["diff"] == original["diff"]
    assert first["previous"] == original["previous"]
    assert first["digest"] == original["digest"]
    assert first["bundle"] == original["bundle"]


def test_single_stage_middle_window_keeps_front_bundle_in_diff():
    report = _evolution()
    proof = evolution_checkpoint(report, AT2, AT2)
    assert len(proof["stages"]) == 1
    stage = proof["stages"][0]
    assert stage["at"] == AT2
    assert stage["diff"]["before_root"] == report["stages"][0]["bundle"]["root"]
    assert stage["diff"]["after_root"] == stage["bundle"]["root"]
    assert stage["previous"] == report["stages"][0]["digest"]
    assert proof["anchor"] == report["stages"][0]["digest"]
    assert proof["commitment"] == stage["digest"]


def test_single_stage_head_window():
    report = _evolution()
    proof = evolution_checkpoint(report, AT1, AT1)
    assert proof["anchor"] == "0" * 64
    assert len(proof["stages"]) == 1
    assert proof["stages"][0]["diff"] is None
    assert proof["commitment"] == report["stages"][0]["digest"]
    assert proof["commitment"] != report["root"]


def test_tail_window_commitment_equals_root():
    report = _evolution()
    proof = evolution_checkpoint(report, AT2, AT3)
    assert proof["commitment"] == report["root"]


def test_stages_are_independent_deep_copies():
    report = _evolution()
    proof = evolution_checkpoint(report, AT2, AT3)
    for window_stage, original in zip(proof["stages"], report["stages"][1:]):
        assert window_stage is not original
        assert window_stage["bundle"] is not original["bundle"]
        assert window_stage["bundle"]["reports"][0] is not (
            original["bundle"]["reports"][0]
        )
        assert window_stage["diff"] is not original["diff"]


def test_does_not_mutate_report():
    report = _evolution()
    snapshot = copy.deepcopy(report)
    evolution_checkpoint(report, AT2, AT3)
    assert report == snapshot


def test_mutating_proof_does_not_touch_report():
    report = _evolution()
    proof = evolution_checkpoint(report, AT2, AT3)
    proof["stages"][0]["bundle"]["root"] = "mutated"
    proof["stages"][0]["diff"]["digest"] = "mutated"
    assert report["stages"][1]["bundle"]["root"] != "mutated"
    assert report["stages"][1]["diff"]["digest"] != "mutated"


def test_equal_valued_inputs_are_byte_identical():
    first = evolution_checkpoint(_evolution(), AT2, AT3)
    second = evolution_checkpoint(copy.deepcopy(_evolution()), AT2, AT3)
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_single_stage_report_window():
    report = matrix_bundle_evolution([{"at": AT1, "bundle": _bundle_one()}])
    proof = evolution_checkpoint(report, AT1, AT1)
    assert proof["anchor"] == "0" * 64
    assert proof["commitment"] == report["root"]
    assert len(proof["stages"]) == 1


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "start,end",
    [
        ("not-a-time", AT3),
        (AT2, "2021-13-01T00:00:00Z"),
        (123, AT3),
        (AT3, AT2),
        (OTHER, AT3),
        (AT2, OTHER),
        (OTHER, OTHER),
    ],
)
def test_invalid_times_or_missing_boundaries_raise(start, end):
    with pytest.raises(ValueError):
        evolution_checkpoint(_evolution(), start, end)


def test_non_evolution_report_raises():
    with pytest.raises(ValueError):
        evolution_checkpoint({"root": "0" * 64}, AT1, AT1)


def test_forged_report_root_raises():
    report = _evolution()
    report["root"] = "f" * 64
    with pytest.raises(ValueError):
        evolution_checkpoint(report, AT1, AT3)


def test_broken_stage_link_in_report_raises():
    report = _evolution()
    report["stages"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        evolution_checkpoint(report, AT1, AT3)


def test_forged_bundle_inside_report_raises():
    report = _evolution()
    report["stages"][0]["bundle"]["reports"][0]["report"]["matrix"]["points"][0][
        "cases"
    ][0]["decision"] = "forged"
    with pytest.raises(ValueError):
        evolution_checkpoint(report, AT2, AT3)


def test_invalid_report_does_not_mutate_inputs():
    report = _evolution()
    report["stages"][1]["previous"] = "f" * 64
    snapshot = copy.deepcopy(report)
    with pytest.raises(ValueError):
        evolution_checkpoint(report, AT1, AT3)
    assert report == snapshot


# ---------------------------------------------------------------- endpoint


def test_http_checkpoint_returns_200_compact_json():
    body = {"report": _evolution(), "start": AT2, "end": AT3}
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint", json=body
    )
    assert response.status_code == 200
    expected_proof = evolution_checkpoint(_evolution(), AT2, AT3)
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
        "/decision-matrix/attest/bundle/evolution/checkpoint",
        json={"report": _evolution(), "start": AT1, "end": AT1},
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
        "/decision-matrix/attest/bundle/evolution/checkpoint",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_missing_boundary_is_422():
    response = client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint",
        json={"report": _evolution(), "start": OTHER, "end": AT3},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
