import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_matrix_attestation,
    verify_decision_matrix_attestation,
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


def _expected(report):
    return {"start": report["start"], "end": report["end"], "digest": report["digest"]}


def _rehash(report):
    payload = {
        key: report[key] for key in ("start", "end", "cases", "matrix", "policy")
    }
    report["digest"] = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return report


# ---------------------------------------------------------------- function


def test_verifies_genuine_reports():
    assert verify_decision_matrix_attestation(_attest(), _expected(_attest())) is True
    report = _attest(
        [{"id": "c", "facts": {"x": True}}], _changing_rules()
    )
    assert verify_decision_matrix_attestation(report, _expected(report)) is True


def test_verifies_empty_cases():
    report = _attest([], _changing_rules())
    assert verify_decision_matrix_attestation(report, _expected(report)) is True


def test_verifies_with_multiple_cases_and_sorted_fact_keys():
    cases = [
        {"id": "c2", "facts": {"z": False, "a": True}},
        {"id": "c1", "facts": {"x": True}},
    ]
    report = _attest(cases, _changing_rules())
    assert [case["id"] for case in report["cases"]] == ["c1", "c2"]
    assert verify_decision_matrix_attestation(report, _expected(report)) is True


def test_declared_digest_tampering_returns_false():
    report = _attest([{"id": "c", "facts": {}}], [_rule()])
    report["digest"] = "f" * 64
    assert verify_decision_matrix_attestation(report, _expected(report)) is False


def test_expected_digest_mismatch_returns_false():
    report = _attest()
    expected = _expected(report)
    expected["digest"] = "0" * 64
    assert verify_decision_matrix_attestation(report, expected) is False


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.update({"start": "2020-12-31T00:00:00Z"}),
        lambda e: e.update(end="2021-06-03T00:00:00Z"),
    ],
)
def test_expected_time_mismatch_returns_false(mutate):
    report = _attest()
    expected = _expected(report)
    mutate(expected)
    assert verify_decision_matrix_attestation(report, expected) is False


def test_irrelevant_fact_forgery_rehashed_fails_against_authentic_expected():
    # An added fact that changes no decision keeps the rebuilt matrix equal,
    # so this surfaces as a digest mismatch (False), not an exception.
    report = _attest([{"id": "c", "facts": {"x": True}}], [_rule(when={"x": True})])
    authentic = report["digest"]
    report["cases"][0]["facts"]["extra"] = False
    _rehash(report)
    expected = {"start": report["start"], "end": report["end"], "digest": authentic}
    assert verify_decision_matrix_attestation(report, expected) is False


def test_semantic_fact_forgery_raises_value_error():
    # Flipping a fact changes the decision; with the matrix left untouched
    # the rebuilt explanations no longer match.
    report = _attest([{"id": "c", "facts": {"x": True}}], _changing_rules())
    report["cases"][0]["facts"]["x"] = False
    _rehash(report)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(report, _expected(report))


def test_matrix_explanation_forgery_raises_value_error():
    report = _attest([{"id": "c", "facts": {}}], _changing_rules())
    bad = copy.deepcopy(report)
    bad["matrix"]["points"][0]["cases"][0]["decision"] = "forged"
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(bad, _expected(bad))


def test_matrix_trace_forgery_raises_value_error():
    report = _attest([{"id": "c", "facts": {"x": True}}], _changing_rules())
    bad = copy.deepcopy(report)
    bad["matrix"]["points"][0]["cases"][0]["trace"].append("z@9")
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(bad, _expected(bad))


def test_matrix_changes_forgery_raises_value_error():
    report = _attest(
        [{"id": "b", "facts": {}}, {"id": "a", "facts": {"x": True}}],
        _changing_rules(),
    )
    changed = next(point for point in report["matrix"]["points"] if point["changes"])
    assert changed["changes"] == ["a", "b"]
    bad = copy.deepcopy(report)
    bad["matrix"]["points"][1]["changes"] = []
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(bad, _expected(bad))


def test_missing_matrix_point_raises_value_error():
    report = _attest(
        [{"id": "b", "facts": {}}, {"id": "a", "facts": {"x": True}}],
        _changing_rules(),
    )
    assert len(report["matrix"]["points"]) > 1
    bad = copy.deepcopy(report)
    bad["matrix"]["points"].pop()
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(bad, _expected(bad))


def test_extra_matrix_point_raises_value_error():
    report = _attest([], _changing_rules())
    bad = copy.deepcopy(report)
    bad["matrix"]["points"].append(
        copy.deepcopy(bad["matrix"]["points"][0])
    )
    bad["matrix"]["points"][1]["at"] = MID
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(bad, _expected(bad))


def test_matrix_point_case_id_misalignment_raises_value_error():
    cases = [{"id": "c2", "facts": {}}, {"id": "c1", "facts": {"x": True}}]
    report = _attest(cases, _changing_rules())
    bad = copy.deepcopy(report)
    bad["matrix"]["points"][0]["cases"].reverse()
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(bad, _expected(bad))


def test_policy_snapshot_forgery_raises_value_error():
    report = _attest([{"id": "c", "facts": {}}], [_rule()])
    bad = copy.deepcopy(report)
    bad["policy"]["points"][0]["conflicts"].append(
        {"winner": ["law", "r1", 1], "loser": ["org", "z", 1]}
    )
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(bad, _expected(bad))


def test_broken_policy_chain_returns_false_even_with_rehashed_digest():
    report = _attest([{"id": "c", "facts": {}}], _changing_rules())
    assert len(report["policy"]["points"]) > 1
    report["policy"]["points"][0]["digest"] = "f" * 64
    report["policy"]["points"][1]["previous"] = "f" * 64
    report["policy"]["root"] = "f" * 64
    _rehash(report)
    assert (
        verify_decision_matrix_attestation(report, _expected(report)) is False
    )


def test_policy_root_mismatch_returns_false():
    report = _attest([{"id": "c", "facts": {}}], _changing_rules())
    report["policy"]["root"] = "f" * 64
    _rehash(report)
    assert (
        verify_decision_matrix_attestation(report, _expected(report)) is False
    )


def test_matrix_is_filtered_subset_of_schedule():
    # The schedule retains policy-only change points; the matrix drops points
    # where no case's decision fields change. Verification rebuilds from the
    # snapshots and must still accept the filtered matrix.
    rules = [
        _rule(id="base", result="allow"),
        _rule(
            id="gated",
            when={"x": True},
            result="allow",
            **{"from": MID, "to": "2021-03-01T00:00:00Z"},
        ),
    ]
    report = _attest([{"id": "c", "facts": {}}], rules)
    assert len(report["policy"]["points"]) == 3
    assert len(report["matrix"]["points"]) == 1
    assert verify_decision_matrix_attestation(report, _expected(report)) is True


def test_recomputed_digest_ignores_input_key_order():
    cases = [{"id": "c2", "facts": {}}, {"id": "c1", "facts": {"x": True}}]
    report = _attest(cases, _changing_rules())
    scrambled = {
        "digest": report["digest"],
        "policy": dict(reversed(list(report["policy"].items()))),
        "matrix": dict(reversed(list(report["matrix"].items()))),
        "cases": [
            {"facts": case["facts"], "id": case["id"]} for case in report["cases"]
        ],
        "end": report["end"],
        "start": report["start"],
    }
    assert verify_decision_matrix_attestation(scrambled, _expected(report)) is True


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.pop("digest"),
        lambda r: r.update(extra=1),
        lambda r: r.update({"start": "not-a-time"}),
        lambda r: r.update(end="not-a-time"),
        lambda r: r.update(end="2020-01-01T00:00:00Z"),
        lambda r: r.update(digest="F" * 64),
        lambda r: r.update(digest="0" * 63),
        lambda r: r.update(digest=123),
        lambda r: r.update(cases={}),
        lambda r: r.update(policy=[]),
        lambda r: r.update(matrix=[]),
        lambda r: r.update(cases=[{"id": "a", "facts": {}},
                                  {"id": "a", "facts": {}}]),
        lambda r: r.update(cases=[{"id": "b", "facts": {}},
                                  {"id": "a", "facts": {}}]),
        lambda r: r.update(cases=[{"id": "", "facts": {}}]),
        lambda r: r.update(cases=[{"id": "a", "facts": {"x": 1}}]),
        lambda r: r.update(cases=[{"facts": {}}]),
    ],
)
def test_bad_report_shapes_raise_value_error(mutate):
    report = _attest(
        [{"id": "a", "facts": {}}, {"id": "b", "facts": {"k": True}}], [_rule()]
    )
    mutate(report)
    authentic = _attest(
        [{"id": "a", "facts": {}}, {"id": "b", "facts": {"k": True}}], [_rule()]
    )
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(report, _expected(authentic))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.clear(),
        lambda m: m.update(extra=1),
        lambda m: m.pop("points"),
        lambda m: m.update(points={}),
        lambda m: m.update(points=[]),
        lambda m: m.update(start="2020-12-31T00:00:00Z"),
    ],
)
def test_bad_matrix_shapes_raise_value_error(mutate):
    report = _attest([{"id": "a", "facts": {}}], [_rule()])
    mutate(report["matrix"])
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(report, _expected(report))


def test_matrix_point_shape_errors_raise_value_error():
    report = _attest([{"id": "a", "facts": {}}], [_rule()])
    point = report["matrix"]["points"][0]
    bad = copy.deepcopy(report)
    bad["matrix"]["points"][0].update(extra=1)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(bad, _expected(bad))
    bad = copy.deepcopy(report)
    bad["matrix"]["points"][0]["at"] = "2020-12-31T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(bad, _expected(bad))
    bad = copy.deepcopy(report)
    bad["matrix"]["points"][0]["changes"] = ["a"]
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(bad, _expected(bad))
    bad = copy.deepcopy(report)
    bad["matrix"]["points"][0]["changes"] = [""]
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(bad, _expected(bad))
    bad = copy.deepcopy(report)
    bad["matrix"]["points"][0]["cases"] = []
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(bad, _expected(bad))
    bad = copy.deepcopy(report)
    bad["matrix"]["points"][0]["cases"][0].update(extra=1)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(bad, _expected(bad))


def test_matrix_window_mismatch_raises_value_error():
    report = _attest()
    report["matrix"]["end"] = "2021-06-02T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(report, _expected(report))


def test_policy_window_mismatch_raises_value_error():
    report = _attest()
    report["policy"]["end"] = "2021-06-02T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(report, _expected(report))


def test_non_dict_report_raises_value_error():
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(
            [], {"start": START, "end": END, "digest": "0" * 64}
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.clear(),
        lambda e: e.update(extra=1),
        lambda e: e.pop("digest"),
        lambda e: e.update({"start": "bad"}),
        lambda e: e.update(end="bad"),
        lambda e: e.__setitem__("end", "2020-01-01T00:00:00Z"),
        lambda e: e.update(digest="X" * 64),
        lambda e: e.update(digest=123),
        lambda e: e.update(root="x"),
    ],
)
def test_bad_expected_shapes_raise_value_error(mutate):
    report = _attest()
    expected = _expected(report)
    mutate(expected)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(report, expected)


def test_structure_validated_before_value_comparison():
    # Both inputs are structurally invalid; ValueError must win over the
    # start/digest comparisons (which would otherwise return False).
    report = _attest()
    expected = _expected(report)
    report["cases"] = {"x": 1}
    expected["start"] = "2020-12-31T00:00:00Z"
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(report, expected)


def test_semantic_validation_uses_rebuilt_not_declared_digest():
    # A semantically forged but fully rehashed report still raises ValueError
    # even when expected matches its declared digest.
    report = _attest([{"id": "c", "facts": {}}], _changing_rules())
    bad = copy.deepcopy(report)
    bad["matrix"]["points"][0]["cases"][0]["decision"] = "forged"
    _rehash(bad)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation(bad, _expected(bad))


def test_does_not_mutate_inputs():
    cases = [{"id": "c2", "facts": {}}, {"id": "c1", "facts": {"x": True}}]
    report = _attest(cases, _changing_rules())
    scrambled = {
        "digest": report["digest"],
        "policy": dict(reversed(list(report["policy"].items()))),
        "matrix": dict(reversed(list(report["matrix"].items()))),
        "cases": [
            {"facts": case["facts"], "id": case["id"]} for case in report["cases"]
        ],
        "end": report["end"],
        "start": report["start"],
    }
    expected = _expected(report)
    report_before = copy.deepcopy(scrambled)
    expected_before = copy.deepcopy(expected)
    assert verify_decision_matrix_attestation(scrambled, expected) is True
    assert scrambled == report_before
    assert expected == expected_before
    assert report == _attest(cases, _changing_rules())


# ---------------------------------------------------------------- endpoint


def test_http_valid_report_is_200_compact_json(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    report = _attest([{"id": "a", "facts": {"x": True}}], [_rule(when={"x": True})])
    response = client.post(
        "/decision-matrix/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_tampered_report_is_200_false(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    report = _attest()
    report["digest"] = "f" * 64
    response = client.post(
        "/decision-matrix/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": False}


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b"null",
        b'"x"',
        b"{}",
        b'{"report": {}}',
        b'{"report": {}, "expected": {}}',
        b'{"report": {}, "expected": {}, "extra": 1}',
    ],
)
def test_http_bad_body_is_422(monkeypatch, body):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    response = client.post(
        "/decision-matrix/attest/verify",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == json.dumps(
        {"detail": "invalid request"}, separators=(",", ":")
    ).encode("utf-8")


def test_http_value_error_in_function_is_422(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    report = _attest()
    report["cases"] = {"x": 1}
    response = client.post(
        "/decision-matrix/attest/verify",
        json={"report": report, "expected": _expected(_attest())},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_http_works_without_history_configured(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    report = _attest(rules=[_rule()])
    response = client.post(
        "/decision-matrix/attest/verify",
        json={"report": report, "expected": _expected(report)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
