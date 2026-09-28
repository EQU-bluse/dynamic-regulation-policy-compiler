import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    compile_rules,
    decision_matrix_attestation,
    matrix_change_ledger,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
STOP = "2021-03-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"


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
        _rule(
            id="a",
            priority=5,
            **{"from": START},
            when={"x": True},
            result="允许",
        ),
        _rule(id="b", priority=1, **{"from": MID, "to": STOP}, result="deny"),
    ]


def _attest(cases, rules, start=START, end=END):
    return decision_matrix_attestation(start, end, cases, rules)


# ---------------------------------------------------------------- function


def test_top_level_shape_binds_source_to_report_digest():
    report = _attest(
        [{"id": "b", "facts": {}}, {"id": "a", "facts": {"x": True}}],
        _changing_rules(),
    )
    ledger = matrix_change_ledger(report)
    assert list(ledger) == ["start", "end", "source", "transitions", "digest"]
    assert ledger["start"] == START
    assert ledger["end"] == END
    assert ledger["source"] == report["digest"]
    matrix_ats = [point["at"] for point in report["matrix"]["points"]]
    assert [
        (transition["from"], transition["to"])
        for transition in ledger["transitions"]
    ] == list(zip(matrix_ats, matrix_ats[1:]))
    assert all(
        list(transition) == ["from", "to", "policy", "cases"]
        for transition in ledger["transitions"]
    )


def test_policy_is_delta_rebuilt_from_schedule_snapshots():
    report = _attest([{"id": "c", "facts": {}}], _changing_rules())
    ledger = matrix_change_ledger(report)
    schedule = {point["at"]: point for point in report["policy"]["points"]}
    for transition in ledger["transitions"]:
        before = {
            "at": transition["from"],
            "rules": schedule[transition["from"]]["rules"],
            "conflicts": schedule[transition["from"]]["conflicts"],
        }
        after = {
            "at": transition["to"],
            "rules": schedule[transition["to"]]["rules"],
            "conflicts": schedule[transition["to"]]["conflicts"],
        }
        expected = {
            "from": transition["from"],
            "to": transition["to"],
            "rules": _delta_rules(before, after),
            "conflicts": _delta_conflicts(before, after),
        }
        assert transition["policy"] == expected


def _delta_rules(before, after):
    from regulation_policy_compiler.policy import _delta_from_compiled

    return _delta_from_compiled(before, after)["rules"]


def _delta_conflicts(before, after):
    from regulation_policy_compiler.policy import _delta_from_compiled

    return _delta_from_compiled(before, after)["conflicts"]


def test_cases_only_list_changed_cases_with_full_endpoint_snapshots():
    report = _attest(
        [{"id": "b", "facts": {}}, {"id": "a", "facts": {"x": True}}],
        _changing_rules(),
    )
    ledger = matrix_change_ledger(report)
    points = report["matrix"]["points"]
    for transition, previous_point, current_point in zip(
        ledger["transitions"], points, points[1:]
    ):
        assert transition["cases"]
        assert [case["id"] for case in transition["cases"]] == current_point[
            "changes"
        ]
        previous_by_id = {entry["id"]: entry for entry in previous_point["cases"]}
        current_by_id = {entry["id"]: entry for entry in current_point["cases"]}
        for case in transition["cases"]:
            assert list(case) == ["id", "changes", "before", "after"]
            before_entry = previous_by_id[case["id"]]
            after_entry = current_by_id[case["id"]]
            assert case["before"] == {
                "at": transition["from"],
                "decision": before_entry["decision"],
                "trace": before_entry["trace"],
                "basis": before_entry["basis"],
                "conflicts": before_entry["conflicts"],
            }
            assert case["after"] == {
                "at": transition["to"],
                "decision": after_entry["decision"],
                "trace": after_entry["trace"],
                "basis": after_entry["basis"],
                "conflicts": after_entry["conflicts"],
            }
            assert case["changes"] == [
                field
                for field in ("decision", "trace", "basis", "conflicts")
                if before_entry[field] != after_entry[field]
            ]
            assert case["changes"]


def test_first_point_is_only_a_prior_state():
    report = _attest([{"id": "c", "facts": {}}], _changing_rules())
    ledger = matrix_change_ledger(report)
    assert ledger["transitions"][0]["from"] == START
    assert all(transition["to"] != START for transition in ledger["transitions"])


def test_changes_field_order_and_trace_only_change():
    rules = _changing_rules()
    report = _attest([{"id": "a", "facts": {"x": True}}], rules)
    ledger = matrix_change_ledger(report)
    first = ledger["transitions"][0]
    case = next(item for item in first["cases"] if item["id"] == "a")
    # The a rule keeps winning; only the trace (and conflicts) grow when b
    # starts, so the change list follows the fixed field order.
    assert case["changes"] == ["trace", "conflicts"]
    assert case["before"]["decision"] == case["after"]["decision"] == "允许"


def test_empty_cases_yield_empty_transitions_but_still_digest():
    report = _attest([], _changing_rules())
    ledger = matrix_change_ledger(report)
    assert ledger["transitions"] == []
    assert ledger["source"] == report["digest"]
    assert ledger["digest"] == hashlib.sha256(
        json.dumps(
            {
                "start": START,
                "end": END,
                "source": report["digest"],
                "transitions": [],
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def test_no_change_matrix_has_no_transitions():
    # A single rule effective across the whole window keeps one matrix point.
    report = _attest(
        [{"id": "c", "facts": {}}], [_rule(result="允许")]
    )
    assert len(report["matrix"]["points"]) == 1
    ledger = matrix_change_ledger(report)
    assert ledger["transitions"] == []


def test_digest_is_sha256_of_first_four_fields_compact_json():
    report = _attest([{"id": "c", "facts": {}}], _changing_rules())
    ledger = matrix_change_ledger(report)
    payload = {
        key: ledger[key] for key in ("start", "end", "source", "transitions")
    }
    expected = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    assert ledger["digest"] == expected
    assert ledger["digest"] == ledger["digest"].lower()
    assert len(ledger["digest"]) == 64


def test_equal_valued_inputs_byte_identical_regardless_of_key_order():
    rules = _changing_rules()
    cases = [{"facts": {}, "id": "b"}, {"facts": {"x": True}, "id": "a"}]
    first = matrix_change_ledger(_attest(cases, rules))
    reordered_report = _attest(
        copy.deepcopy(cases),
        [dict(reversed(list(rule.items()))) for rule in reversed(rules)],
    )
    # Reorder the credential dict keys themselves too.
    reordered_report = {
        key: reordered_report[key]
        for key in reversed(list(reordered_report))
    }
    second = matrix_change_ledger(reordered_report)
    assert json.dumps(
        first, ensure_ascii=False, separators=(",", ":")
    ) == json.dumps(second, ensure_ascii=False, separators=(",", ":"))


def test_result_is_independent_deep_copy_and_input_is_untouched():
    cases = [{"id": "a", "facts": {"x": True}}]
    report = _attest(cases, _changing_rules())
    report_before = copy.deepcopy(report)
    ledger = matrix_change_ledger(report)
    ledger["transitions"][0]["cases"][0]["before"]["decision"] = "mutated"
    ledger["transitions"][0]["policy"]["rules"].reverse()
    ledger["source"] = "0" * 64
    assert report == report_before
    assert matrix_change_ledger(copy.deepcopy(report_before))[
        "transitions"
    ] == matrix_change_ledger(copy.deepcopy(report))["transitions"]


def test_repeated_equal_calls_do_not_share_containers():
    report = _attest([{"id": "c", "facts": {}}], _changing_rules())
    first = matrix_change_ledger(report)
    second = matrix_change_ledger(report)
    assert first == second
    first["transitions"][0]["cases"][0]["after"]["trace"].append("z@9")
    assert second["transitions"][0]["cases"][0]["after"]["trace"] == (
        matrix_change_ledger(report)["transitions"][0]["cases"][0]["after"][
            "trace"
        ]
    )


def test_policy_delta_matches_recompiled_rule_diff():
    rules = _changing_rules()
    report = _attest([{"id": "c", "facts": {}}], rules)
    ledger = matrix_change_ledger(report)
    for transition in ledger["transitions"]:
        before = compile_rules(transition["from"], rules)
        after = compile_rules(transition["to"], rules)
        from regulation_policy_compiler.policy import policy_delta

        assert transition["policy"] == policy_delta(
            transition["from"], transition["to"], rules
        )
        assert before["at"] == transition["from"]
        assert after["at"] == transition["to"]


def test_invalid_report_structure_raises_value_error():
    good = _attest([{"id": "c", "facts": {}}], _changing_rules())
    bad_inputs = [
        None,
        [],
        "x",
        {},
        {**good, "extra": 1},
        {key: good[key] for key in good if key != "digest"},
    ]
    for bad in bad_inputs:
        with pytest.raises(ValueError):
            matrix_change_ledger(bad)


def test_false_report_digest_raises_value_error():
    report = _attest([{"id": "c", "facts": {}}], _changing_rules())
    report["digest"] = "0" * 64
    with pytest.raises(ValueError):
        matrix_change_ledger(report)


def test_false_schedule_chain_or_root_raises_value_error():
    report = _attest([{"id": "c", "facts": {}}], _changing_rules())
    root_bad = copy.deepcopy(report)
    root_bad["policy"]["root"] = "0" * 64
    with pytest.raises(ValueError):
        matrix_change_ledger(root_bad)
    chain_bad = copy.deepcopy(report)
    chain_bad["policy"]["points"][-1]["digest"] = "f" * 64
    with pytest.raises(ValueError):
        matrix_change_ledger(chain_bad)


def test_false_matrix_semantics_raises_value_error():
    report = _attest([{"id": "c", "facts": {}}], _changing_rules())
    tampered = copy.deepcopy(report)
    point = tampered["matrix"]["points"][0]
    point["cases"][0]["decision"] = "forged"
    with pytest.raises(ValueError):
        matrix_change_ledger(tampered)


def test_illegal_case_id_in_credential_raises_value_error():
    report = _attest([{"id": "c", "facts": {}}], _changing_rules())
    report["cases"][0]["id"] = ""
    with pytest.raises(ValueError):
        matrix_change_ledger(report)


# ---------------------------------------------------------------- endpoint


def test_http_ledger_returns_200_compact_json():
    report = _attest([{"id": "a", "facts": {"x": True}}], _changing_rules())
    response = client.post("/decision-matrix/ledger", json={"report": report})
    assert response.status_code == 200
    ledger = response.json()
    assert list(ledger) == ["start", "end", "source", "transitions", "digest"]
    expected = json.dumps(
        ledger, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert response.content == expected
    assert not response.content.endswith(b"\n")
    assert "允许" in response.content.decode("utf-8")


def test_http_ledger_empty_cases():
    report = _attest([], _changing_rules())
    response = client.post("/decision-matrix/ledger", json={"report": report})
    assert response.status_code == 200
    assert response.json()["transitions"] == []


def test_http_ledger_does_not_use_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("ledger endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    report = _attest([], _changing_rules())
    response = client.post("/decision-matrix/ledger", json={"report": report})
    assert response.status_code == 200


def test_http_bad_body_is_422():
    bodies = [
        b"{not json",
        b"[]",
        b"null",
        b'"x"',
        b"{}",
        b'{"report": {}}',
        b'{"report": null, "extra": 1}',
        b'{"credential": {}}',
    ]
    for body in bodies:
        response = client.post(
            "/decision-matrix/ledger",
            content=body,
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 422, body
        assert response.content == b'{"detail":"invalid request"}'


def test_http_value_error_in_function_is_422():
    report = _attest([{"id": "c", "facts": {}}], _changing_rules())
    report["digest"] = "0" * 64
    response = client.post(
        "/decision-matrix/ledger", json={"report": report}
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
