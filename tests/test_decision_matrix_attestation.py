import copy
import hashlib
import json

from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_matrix,
    decision_matrix_attestation,
    policy_schedule_attestation,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
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
        _rule(
            id="b",
            priority=1,
            **{"from": MID, "to": "2021-03-01T00:00:00Z"},
            result="deny",
        ),
    ]


def _attest(cases=None, rules=None, start=START, end=END):
    return decision_matrix_attestation(
        start, end, [] if cases is None else cases, rules or []
    )


# ---------------------------------------------------------------- function


def test_top_level_key_order_and_value_shapes():
    rules = _changing_rules()
    cases = [
        {"id": "c2", "facts": {"z": True, "a": False}},
        {"id": "c1", "facts": {"x": True}},
    ]
    report = decision_matrix_attestation(START, END, cases, rules)
    assert list(report) == ["start", "end", "cases", "matrix", "policy", "digest"]
    assert report["start"] == START
    assert report["end"] == END
    assert [case["id"] for case in report["cases"]] == ["c1", "c2"]
    assert list(report["cases"][0]) == ["id", "facts"]
    assert list(report["cases"][1]["facts"]) == ["a", "z"]
    assert report["matrix"] == decision_matrix(START, END, cases, rules)
    assert report["policy"] == policy_schedule_attestation(START, END, rules)
    assert list(report["matrix"]) == ["start", "end", "points"]
    assert list(report["matrix"]["points"][0]) == ["at", "changes", "cases"]


def test_matrix_keeps_first_point_change_points_and_change_ids():
    rules = _changing_rules()
    report = _attest(
        [{"id": "b", "facts": {}}, {"id": "a", "facts": {"x": True}}], rules
    )
    matrix = report["matrix"]
    # Decision-free boundaries (a's START from coincides with the first
    # candidate) leave exactly the points where some case changes: b starts
    # at MID and stops at its exclusive to boundary.
    assert [point["at"] for point in matrix["points"]] == [
        START,
        MID,
        "2021-03-01T00:00:00Z",
    ]
    first, second, third = matrix["points"]
    assert first["changes"] == []
    # At MID the empty-facts case flips fully; the x=True case also changes
    # trace/conflicts, so change ids follow ascending case order.
    assert second["changes"] == ["a", "b"]
    assert [entry["id"] for entry in second["cases"]] == ["a", "b"]
    assert list(second["cases"][0]) == [
        "id",
        "decision",
        "trace",
        "basis",
        "conflicts",
    ]
    # At b's exclusive to boundary it vanishes again, flipping both cases.
    assert third["changes"] == ["a", "b"]


def test_empty_cases_still_attest_with_only_the_start_point():
    report = _attest([], _changing_rules())
    assert report["cases"] == []
    assert [point["at"] for point in report["matrix"]["points"]] == [START]
    assert report["matrix"]["points"][0] == {"at": START, "changes": [], "cases": []}


def test_digest_is_sha256_of_first_five_fields_compact_json():
    report = _attest([{"id": "c", "facts": {"k": True}}], [_rule(result="允许")])
    payload = {
        key: report[key] for key in ("start", "end", "cases", "matrix", "policy")
    }
    expected = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert report["digest"] == expected
    assert len(report["digest"]) == 64
    assert report["digest"] == report["digest"].lower()


def test_equal_valued_inputs_are_byte_identical_regardless_of_key_order():
    rules = _changing_rules()
    cases = [
        {"facts": {"z": False, "a": True}, "id": "c2"},
        {"facts": {"x": True}, "id": "c1"},
    ]
    first = decision_matrix_attestation(START, END, cases, rules)
    reordered_rules = [dict(reversed(list(rule.items()))) for rule in reversed(rules)]
    second = decision_matrix_attestation(START, END, copy.deepcopy(cases), reordered_rules)
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_layers_are_independent_deep_copies():
    cases = [{"id": "c", "facts": {"x": True}}]
    rules = _changing_rules()
    cases_before = copy.deepcopy(cases)
    report = decision_matrix_attestation(START, END, cases, rules)
    report["cases"][0]["facts"]["x"] = False
    report["matrix"]["points"][0]["cases"][0]["decision"] = "mutated"
    report["policy"]["points"][0]["rules"].reverse()
    assert cases == cases_before
    # Rebuilding from untouched inputs is unaffected.
    assert decision_matrix_attestation(START, END, cases_before, rules) == _attest(
        cases_before, rules
    )


def test_does_not_mutate_inputs():
    cases = [{"id": "c2", "facts": {}}, {"id": "c1", "facts": {"x": True}}]
    rules = _changing_rules()
    cases_before = copy.deepcopy(cases)
    rules_before = copy.deepcopy(rules)
    decision_matrix_attestation(START, END, cases, rules)
    assert cases == cases_before
    assert rules == rules_before


def test_invalid_inputs_raise_value_error():
    import pytest

    valid_cases = [{"id": "c", "facts": {}}]
    valid_rules = [_rule()]
    with pytest.raises(ValueError):
        decision_matrix_attestation(END, START, valid_cases, valid_rules)
    with pytest.raises(ValueError):
        decision_matrix_attestation("not-a-time", END, valid_cases, valid_rules)
    with pytest.raises(ValueError):
        decision_matrix_attestation(START, "not-a-time", valid_cases, valid_rules)
    with pytest.raises(ValueError):
        decision_matrix_attestation(START, END, {"id": "c"}, valid_rules)
    with pytest.raises(ValueError):
        decision_matrix_attestation(START, END, [{"id": "", "facts": {}}], [])
    with pytest.raises(ValueError):
        decision_matrix_attestation(
            START,
            END,
            [{"id": "c", "facts": {}}, {"id": "c", "facts": {}}],
            [],
        )
    with pytest.raises(ValueError):
        decision_matrix_attestation(
            START, END, [{"id": "c", "facts": {"x": 1}}], valid_rules
        )
    with pytest.raises(ValueError):
        bad_rule = _rule()
        bad_rule["ver"] = 0
        decision_matrix_attestation(START, END, valid_cases, [bad_rule])


# ---------------------------------------------------------------- endpoint


def test_http_attest_returns_200_compact_json():
    body = {
        "start": START,
        "end": END,
        "cases": [{"id": "a", "facts": {"x": True}}],
        "rules": [_rule(when={"x": True}, result="允许")],
    }
    response = client.post("/decision-matrix/attest", json=body)
    assert response.status_code == 200
    report = response.json()
    assert list(report) == ["start", "end", "cases", "matrix", "policy", "digest"]
    expected = json.dumps(report, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    assert response.content == expected
    assert not response.content.endswith(b"\n")
    assert "允许" in response.content.decode("utf-8")


def test_http_attest_empty_cases():
    response = client.post(
        "/decision-matrix/attest",
        json={"start": START, "end": END, "cases": [], "rules": []},
    )
    assert response.status_code == 200
    assert response.json()["matrix"]["points"][0]["cases"] == []


def test_http_attest_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("attest endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/decision-matrix/attest",
        json={"start": START, "end": END, "cases": [], "rules": [_rule()]},
    )
    assert response.status_code == 200


def test_http_bad_body_is_422():
    cases = [
        b"{not json",
        b"[]",
        b"null",
        b'"x"',
        b"{}",
        b'{"start": "2021-01-01T00:00:00Z", "end": "2021-04-01T00:00:00Z", '
        b'"cases": []}',
        b'{"start": "2021-01-01T00:00:00Z", "end": "2021-04-01T00:00:00Z", '
        b'"cases": [], "rules": [], "extra": 1}',
    ]
    for body in cases:
        response = client.post(
            "/decision-matrix/attest",
            content=body,
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 422
        assert response.content == b'{"detail":"invalid request"}'


def test_http_value_error_in_function_is_422():
    response = client.post(
        "/decision-matrix/attest",
        json={
            "start": END,
            "end": START,
            "cases": [],
            "rules": [],
        },
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
