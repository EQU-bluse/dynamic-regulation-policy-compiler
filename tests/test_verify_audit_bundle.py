import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.history import DecisionHistory, verify_audit_bundle


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


START = "2021-01-01T00:00:00Z"
END = "2021-12-31T00:00:00Z"
IDS = ["a", "b", "é"]


@pytest.fixture
def bundle(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("b", "2021-03-01T00:00:00Z", {}, [_rule(result="允许")])
    history.record("a", "2021-01-01T00:00:00Z", {}, [_rule(result="x")])
    history.record("a", "2021-02-01T00:00:00Z", {}, [])
    history.record("é", "2021-01-01T00:00:00Z", {}, [_rule(result="z")])
    return history.audit_bundle(["b", "a", "é"], START, END)


def _expected(bundle, record_ids=IDS, *, start=START, end=END, root=None):
    return {
        "start": start,
        "end": end,
        "root": bundle["root"] if root is None else root,
        "record_ids": list(record_ids),
    }


def test_verify_bundle_accepts_genuine_bundle_with_shuffled_expected_ids(bundle):
    assert verify_audit_bundle(copy.deepcopy(bundle), _expected(bundle, ["é", "a", "b"]))


def test_verify_bundle_single_id(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("a", "2021-03-01T00:00:00Z", {}, [_rule(result="x")])
    bundle = history.audit_bundle(["a"], START, END)
    assert verify_audit_bundle(bundle, _expected(bundle, ["a"]))


def test_verify_bundle_does_not_mutate_inputs(bundle):
    report = copy.deepcopy(bundle)
    expected = _expected(report)
    expected_snapshot = copy.deepcopy(expected)
    assert verify_audit_bundle(report, expected)
    assert report == bundle
    assert expected == expected_snapshot


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b["reports"][0]["entries"][0].__setitem__("decision", "hax"),
        lambda b: b["reports"][1]["entries"][0].__setitem__("digest", "0" * 64),
        lambda b: b["reports"][0]["entries"][1].__setitem__("previous", "0" * 64),
        lambda b: b["reports"][0].__setitem__("root", "1" * 64),
    ],
)
def test_verify_bundle_rejects_tampered_sub_chain(bundle, mutate):
    report = copy.deepcopy(bundle)
    mutate(report)
    assert not verify_audit_bundle(report, _expected(bundle))


def test_verify_bundle_recomputes_bundle_root(tmp_path, bundle):
    # A different top-level root can never match, even if expected copies it.
    report = copy.deepcopy(bundle)
    report["root"] = "f" * 64
    assert not verify_audit_bundle(report, _expected(bundle, root="f" * 64))


def test_verify_bundle_rejects_window_and_id_mismatches(bundle):
    assert not verify_audit_bundle(
        copy.deepcopy(bundle), _expected(bundle, start="2021-02-01T00:00:00Z")
    )
    assert not verify_audit_bundle(copy.deepcopy(bundle), _expected(bundle, end=START))
    assert not verify_audit_bundle(copy.deepcopy(bundle), _expected(bundle, ["a", "b"]))
    assert not verify_audit_bundle(
        copy.deepcopy(bundle), _expected(bundle, ["a", "b", "é", "c"])
    )
    assert not verify_audit_bundle(
        copy.deepcopy(bundle), _expected(bundle, root="0" * 64)
    )


def test_verify_bundle_rejects_unsorted_or_duplicate_reports(bundle):
    reversed_reports = copy.deepcopy(bundle)
    reversed_reports["reports"] = list(reversed(reversed_reports["reports"]))
    with pytest.raises(ValueError):
        verify_audit_bundle(reversed_reports, _expected(bundle))
    duplicated = copy.deepcopy(bundle)
    duplicated["reports"][1]["id"] = "a"
    with pytest.raises(ValueError):
        verify_audit_bundle(duplicated, _expected(bundle))


def test_verify_bundle_rejects_sub_report_window_mismatch(bundle):
    report = copy.deepcopy(bundle)
    report["reports"][0]["start"] = "2020-12-31T00:00:00Z"
    with pytest.raises(ValueError):
        verify_audit_bundle(report, _expected(bundle))


def test_verify_bundle_rejects_non_increasing_entries(bundle):
    report = copy.deepcopy(bundle)
    report["reports"][0]["entries"] = list(reversed(report["reports"][0]["entries"]))
    with pytest.raises(ValueError):
        verify_audit_bundle(report, _expected(bundle))


@pytest.mark.parametrize(
    "report",
    [
        None,
        [],
        {},
        {"start": START, "end": END, "root": "0" * 64},
        {"start": START, "end": END, "root": "0" * 64, "reports": []},
        {"start": "bad", "end": END, "root": "0" * 64, "reports": []},
        {"start": END, "end": START, "root": "0" * 64, "reports": []},
        {"start": START, "end": END, "root": "Z" * 64, "reports": []},
    ],
)
def test_verify_bundle_rejects_bad_report_shape(bundle, report):
    with pytest.raises(ValueError):
        verify_audit_bundle(
            copy.deepcopy(report) if isinstance(report, (dict, list)) else report,
            _expected(bundle),
        )


def test_verify_bundle_rejects_extra_report_key(bundle):
    report = copy.deepcopy(bundle)
    report["extra"] = 1
    with pytest.raises(ValueError):
        verify_audit_bundle(report, _expected(bundle))


@pytest.mark.parametrize(
    "expected",
    [
        None,
        [],
        {},
        {"start": START, "end": END, "root": "0" * 64},
        {"start": START, "end": END, "root": "0" * 64, "record_ids": []},
        {"start": START, "end": END, "root": "0" * 64, "record_ids": ["a", "a"]},
        {"start": START, "end": END, "root": "0" * 64, "record_ids": ["a", 1]},
        {"start": START, "end": END, "root": "0" * 64, "record_ids": "ab"},
        {"start": "bad", "end": END, "root": "0" * 64, "record_ids": ["a"]},
        {"start": END, "end": START, "root": "0" * 64, "record_ids": ["a"]},
        {"start": START, "end": END, "root": "g" * 64, "record_ids": ["a"]},
        {"start": START, "end": END, "root": "0" * 64, "record_ids": ["a"], "x": 1},
    ],
)
def test_verify_bundle_rejects_bad_expected(bundle, expected):
    with pytest.raises(ValueError):
        verify_audit_bundle(copy.deepcopy(bundle), expected)


def test_verify_bundle_http_success_and_byte_format(bundle):
    client = TestClient(app)
    response = client.post(
        "/audits/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw


def test_verify_bundle_http_false_body(bundle):
    client = TestClient(app)
    response = client.post(
        "/audits/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle, root="0" * 64)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": False}


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        json.dumps([1, 2]).encode(),
        json.dumps({"report": {}}).encode(),
        json.dumps({"report": {}, "expected": {}, "x": 1}).encode(),
    ],
)
def test_verify_bundle_http_malformed_body_is_422(body):
    client = TestClient(app)
    response = client.post(
        "/audits/bundle/verify",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_verify_bundle_http_value_error_is_422(bundle):
    client = TestClient(app)
    bad = copy.deepcopy(bundle)
    del bad["reports"][0]["entries"][0]["digest"]
    response = client.post(
        "/audits/bundle/verify",
        json={"report": bad, "expected": _expected(bundle)},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}
