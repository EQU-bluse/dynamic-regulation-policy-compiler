import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    evolution_checkpoint,
    matrix_bundle_diff,
    matrix_bundle_evolution,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"
AT1 = "2021-05-01T00:00:00Z"
AT2 = "2021-06-01T00:00:00Z"
AT3 = "2021-07-01T00:00:00Z"


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
    return decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()}]
    )


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


def test_key_order():
    proof = evolution_checkpoint(_evolution(), AT1, AT3)
    assert list(proof) == ["start", "end", "anchor", "stages", "commitment"]
    for stage in proof["stages"]:
        assert list(stage) == ["at", "bundle", "diff", "previous", "digest"]


def test_full_window_matches_report_stages_and_root():
    report = _evolution()
    proof = evolution_checkpoint(report, AT1, AT3)
    assert proof["start"] == AT1
    assert proof["end"] == AT3
    assert proof["anchor"] == "0" * 64
    assert proof["stages"] == report["stages"]
    assert proof["commitment"] == report["stages"][-1]["digest"]
    assert proof["commitment"] == report["root"]


def test_middle_window_anchor_is_preceding_digest():
    report = _evolution()
    proof = evolution_checkpoint(report, AT2, AT3)
    assert proof["anchor"] == report["stages"][0]["digest"]
    assert [stage["at"] for stage in proof["stages"]] == [AT2, AT3]
    assert proof["commitment"] == report["stages"][2]["digest"]
    assert proof["commitment"] == report["root"]


def test_single_middle_stage_keeps_diff_and_preceding_bundle():
    report = _evolution()
    proof = evolution_checkpoint(report, AT2, AT2)
    assert len(proof["stages"]) == 1
    stage = proof["stages"][0]
    assert stage["at"] == AT2
    assert stage["diff"] == report["stages"][1]["diff"]
    assert stage["diff"] is not None
    # The diff embeds the preceding (out-of-window) bundle, so the window can
    # be recomputed standalone.
    assert stage["diff"]["before"] == report["stages"][0]["bundle"]
    assert stage["diff"]["after"] == report["stages"][1]["bundle"]
    assert proof["anchor"] == report["stages"][0]["digest"]
    assert proof["commitment"] == stage["digest"]


def test_single_first_stage_uses_genesis_anchor_and_null_diff():
    report = _evolution()
    proof = evolution_checkpoint(report, AT1, AT1)
    assert len(proof["stages"]) == 1
    assert proof["anchor"] == "0" * 64
    assert proof["stages"][0]["diff"] is None
    assert proof["commitment"] == report["stages"][0]["digest"]


def test_window_prefix_and_suffix():
    report = _evolution()
    prefix = evolution_checkpoint(report, AT1, AT2)
    assert prefix["anchor"] == "0" * 64
    assert [stage["at"] for stage in prefix["stages"]] == [AT1, AT2]
    assert prefix["stages"][0]["diff"] is None
    assert prefix["stages"][1]["diff"] is not None
    suffix = evolution_checkpoint(report, AT3, AT3)
    assert suffix["anchor"] == report["stages"][1]["digest"]
    assert suffix["commitment"] == report["stages"][2]["digest"]


def test_stages_are_independent_deep_copies():
    report = _evolution()
    proof = evolution_checkpoint(report, AT2, AT3)
    proof["stages"][0]["bundle"]["root"] = "mutated"
    proof["stages"][0]["diff"]["digest"] = "mutated"
    assert report["stages"][1]["bundle"]["root"] != "mutated"
    assert report["stages"][1]["diff"]["digest"] != "mutated"


def test_does_not_mutate_input():
    report = _evolution()
    snapshot = copy.deepcopy(report)
    evolution_checkpoint(report, AT2, AT3)
    assert report == snapshot


def test_equal_valued_inputs_are_byte_identical():
    first = evolution_checkpoint(_evolution(), AT2, AT3)
    second = evolution_checkpoint(copy.deepcopy(_evolution()), AT2, AT3)
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_adjacent_diffs_inside_window_are_original_diffs():
    report = _evolution()
    proof = evolution_checkpoint(report, AT1, AT3)
    bundles = [item["bundle"] for item in _stage_inputs()]
    assert proof["stages"][1]["diff"] == matrix_bundle_diff(bundles[0], bundles[1])
    assert proof["stages"][2]["diff"] == matrix_bundle_diff(bundles[1], bundles[2])


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "start,end",
    [
        ("not-a-time", AT3),
        (AT1, "not-a-time"),
        (123, AT3),
        (AT1, None),
        (None, AT3),
        ("2021-04-15T00:00:00Z", AT3),  # valid time, not a stage at
        (AT1, "2021-09-01T00:00:00Z"),
        (AT3, AT2),  # reversed
        (AT2, AT1),
    ],
)
def test_invalid_boundaries_raise(start, end):
    with pytest.raises(ValueError):
        evolution_checkpoint(_evolution(), start, end)


@pytest.mark.parametrize(
    "bad_report",
    [
        None,
        "x",
        [],
        {},
        {"root": "0" * 64},
        {"root": "0" * 64, "stages": []},
    ],
)
def test_malformed_report_raises(bad_report):
    with pytest.raises(ValueError):
        evolution_checkpoint(bad_report, AT1, AT1)


def test_false_report_root_raises():
    bad_report = copy.deepcopy(_evolution())
    bad_report["root"] = "f" * 64
    with pytest.raises(ValueError):
        evolution_checkpoint(bad_report, AT1, AT3)


def test_forged_stage_previous_raises():
    bad_report = copy.deepcopy(_evolution())
    bad_report["stages"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        evolution_checkpoint(bad_report, AT1, AT3)


def test_forged_stage_digest_raises():
    bad_report = copy.deepcopy(_evolution())
    bad_report["stages"][2]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        evolution_checkpoint(bad_report, AT1, AT3)


def test_forged_bundle_root_inside_report_raises():
    bad_report = copy.deepcopy(_evolution())
    bad_report["stages"][1]["bundle"]["root"] = "f" * 64
    with pytest.raises(ValueError):
        evolution_checkpoint(bad_report, AT1, AT3)


def test_forged_diff_inside_report_raises():
    bad_report = copy.deepcopy(_evolution())
    bad_report["stages"][1]["diff"]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        evolution_checkpoint(bad_report, AT1, AT3)


def test_forgery_outside_window_still_rejected():
    # The full report is verified before windowing; a forged link before the
    # window start cannot be hidden by choosing a later window.
    bad_report = copy.deepcopy(_evolution())
    bad_report["stages"][0]["digest"] = "f" * 64
    bad_report["stages"][1]["previous"] = "f" * 64
    with pytest.raises(ValueError):
        evolution_checkpoint(bad_report, AT3, AT3)


# ---------------------------------------------------------------- endpoint


def _post(body):
    return client.post(
        "/decision-matrix/attest/bundle/evolution/checkpoint", json=body
    )


def test_http_checkpoint_returns_200_compact_json():
    proof = evolution_checkpoint(_evolution(), AT2, AT3)
    response = _post({"report": _evolution(), "start": AT2, "end": AT3})
    assert response.status_code == 200
    assert response.json() == proof
    expected_body = json.dumps(
        proof, ensure_ascii=False, separators=(",", ":")
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
    response = _post({"report": _evolution(), "start": AT1, "end": AT1})
    assert response.status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b'"x"',
        b"null",
        b"{}",
        b'{"report": {}}',
        b'{"start": "2021-05-01T00:00:00Z", "end": "2021-07-01T00:00:00Z"}',
        b'{"report": {}, "start": "x", "end": "y", "extra": 1}',
        b'{"proof": {}, "start": "x", "end": "y"}',
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


def test_http_value_error_in_function_is_422():
    response = _post({"report": _evolution(), "start": AT3, "end": AT2})
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
