import copy
import hashlib
import itertools
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.history import DecisionHistory, verify_audit_bundle

START = "2021-01-01T00:00:00Z"
END = "2021-12-31T00:00:00Z"
_BUNDLE_SEQ = itertools.count()


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


def _bundle(tmp_path):
    # Each bundle gets its own history file so a test can build several
    # independent bundles under one tmp_path without duplicate-record errors.
    directory = tmp_path / f"h{next(_BUNDLE_SEQ)}"
    directory.mkdir()
    history = DecisionHistory(str(directory / "history.json"))
    history.record("b", "2021-03-01T00:00:00Z", {}, [_rule(result="允许")])
    history.record("a", "2021-01-01T00:00:00Z", {}, [_rule(result="x")])
    history.record("a", "2021-02-01T00:00:00Z", {}, [])
    history.record("é", "2021-01-01T00:00:00Z", {}, [_rule(result="z")])
    return history.audit_bundle(["b", "a", "é"], START, END)


def _expected(bundle, ids=None):
    if ids is None:
        ids = [sub_report["id"] for sub_report in bundle["reports"]]
    return {
        "start": bundle["start"],
        "end": bundle["end"],
        "root": bundle["root"],
        "record_ids": ids,
    }


def test_verifies_genuine_bundle(tmp_path):
    bundle = _bundle(tmp_path)
    assert verify_audit_bundle(bundle, _expected(bundle)) is True


def test_expected_record_id_order_is_arbitrary(tmp_path):
    bundle = _bundle(tmp_path)
    expected = _expected(bundle, ids=["é", "a", "b"])
    assert verify_audit_bundle(bundle, expected) is True


def test_tampered_entry_content_returns_false(tmp_path):
    bundle = _bundle(tmp_path)
    bundle["reports"][0]["entries"][0]["decision"] = "tampered"
    assert verify_audit_bundle(bundle, _expected(bundle)) is False


def test_forged_chain_with_stale_report_root_returns_false(tmp_path):
    bundle = _bundle(tmp_path)
    entry = bundle["reports"][0]["entries"][0]
    entry["decision"] = "tampered"
    # Recompute the digest over the tampered content, but leave the report and
    # bundle roots untouched.
    payload = json.dumps(
        {key: entry[key] for key in ("at", "decision", "trace", "basis")},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    entry["digest"] = hashlib.sha256(
        entry["previous"].encode("ascii") + payload.encode("utf-8")
    ).hexdigest()
    assert verify_audit_bundle(bundle, _expected(bundle)) is False


def test_fully_recomputed_forgery_fails_against_authentic_expected(tmp_path):
    bundle = _bundle(tmp_path)
    authentic_root = bundle["root"]
    entry = bundle["reports"][0]["entries"][0]
    entry["decision"] = "tampered"
    payload = json.dumps(
        {key: entry[key] for key in ("at", "decision", "trace", "basis")},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    new_digest = hashlib.sha256(
        entry["previous"].encode("ascii") + payload.encode("utf-8")
    ).hexdigest()
    entry["digest"] = new_digest
    bundle["reports"][0]["root"] = new_digest
    root = "0" * 64
    for report in bundle["reports"]:
        link = json.dumps(
            {"id": report["id"], "root": report["root"]},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        root = hashlib.sha256(root.encode("ascii") + link).hexdigest()
    bundle["root"] = root
    # The internally consistent forgery does not match the authentic expected.
    expected = _expected(bundle)
    expected["root"] = authentic_root
    assert verify_audit_bundle(bundle, expected) is False


def test_wrong_previous_link_returns_false(tmp_path):
    bundle = _bundle(tmp_path)
    # The second entry of the two-entry "a" report must chain from the first.
    entries = bundle["reports"][0]["entries"]
    entries[1]["previous"] = "f" * 64
    assert verify_audit_bundle(bundle, _expected(bundle)) is False


def test_reordered_sub_reports_raise_value_error(tmp_path):
    bundle = _bundle(tmp_path)
    bundle["reports"].reverse()
    with pytest.raises(ValueError):
        verify_audit_bundle(bundle, _expected(bundle))


def test_duplicate_sub_report_id_raises_value_error(tmp_path):
    bundle = _bundle(tmp_path)
    bundle["reports"][1] = copy.deepcopy(bundle["reports"][0])
    with pytest.raises(ValueError):
        verify_audit_bundle(bundle, _expected(bundle))


def test_sub_report_window_must_equal_bundle_window(tmp_path):
    bundle = _bundle(tmp_path)
    bundle["reports"][0]["start"] = "2021-02-01T00:00:00Z"
    with pytest.raises(ValueError):
        verify_audit_bundle(bundle, _expected(bundle))
    bundle["reports"][0]["start"] = START
    bundle["reports"][0]["end"] = "2022-01-01T00:00:00Z"
    with pytest.raises(ValueError):
        verify_audit_bundle(bundle, _expected(bundle))


def test_expected_window_mismatch_returns_false(tmp_path):
    bundle = _bundle(tmp_path)
    expected = _expected(bundle)
    expected["start"] = "2021-02-01T00:00:00Z"
    assert verify_audit_bundle(bundle, expected) is False
    expected = _expected(bundle)
    expected["end"] = "2022-01-01T00:00:00Z"
    assert verify_audit_bundle(bundle, expected) is False


def test_expected_root_mismatch_returns_false(tmp_path):
    bundle = _bundle(tmp_path)
    expected = _expected(bundle)
    expected["root"] = "f" * 64
    assert verify_audit_bundle(bundle, expected) is False


def test_expected_record_id_set_mismatch_returns_false(tmp_path):
    bundle = _bundle(tmp_path)
    expected = _expected(bundle, ids=["a", "b"])
    assert verify_audit_bundle(bundle, expected) is False
    expected = _expected(bundle, ids=["a", "b", "é", "c"])
    assert verify_audit_bundle(bundle, expected) is False
    expected = _expected(bundle, ids=["a", "b", "c"])
    assert verify_audit_bundle(bundle, expected) is False


def test_deleted_sub_report_returns_false(tmp_path):
    bundle = _bundle(tmp_path)
    del bundle["reports"][1]
    # Deletion makes the declared root inconsistent with the remaining chain.
    assert verify_audit_bundle(bundle, _expected(bundle)) is False


def test_bad_report_shapes_raise_value_error(tmp_path):
    bundle = _bundle(tmp_path)

    def with_report(report):
        return verify_audit_bundle(report, _expected(bundle))

    with pytest.raises(ValueError):
        with_report([])
    with pytest.raises(ValueError):
        with_report({"start": bundle["start"], "end": bundle["end"], "root": bundle["root"]})
    good = bundle
    bad = copy.deepcopy(good)
    bad["extra"] = 1
    with pytest.raises(ValueError):
        with_report(bad)
    bad = copy.deepcopy(good)
    bad["root"] = "F" * 64
    with pytest.raises(ValueError):
        with_report(bad)
    bad = copy.deepcopy(good)
    bad["start"] = "not-a-time"
    with pytest.raises(ValueError):
        with_report(bad)
    bad = copy.deepcopy(good)
    bad["start"], bad["end"] = bad["end"], bad["start"]
    with pytest.raises(ValueError):
        with_report(bad)
    bad = copy.deepcopy(good)
    bad["reports"] = []
    with pytest.raises(ValueError):
        with_report(bad)
    bad = copy.deepcopy(good)
    bad["reports"] = "x"
    with pytest.raises(ValueError):
        with_report(bad)


def test_bad_sub_report_shapes_raise_value_error(tmp_path):
    bundle = _bundle(tmp_path)

    def check():
        return verify_audit_bundle(bundle, _expected(bundle))

    sub = bundle["reports"][0]
    sub["id"] = ""
    with pytest.raises(ValueError):
        check()

    bundle2 = _bundle(tmp_path)
    bundle2["reports"][0]["root"] = "g" * 64
    with pytest.raises(ValueError):
        verify_audit_bundle(bundle2, _expected(bundle2))

    bundle3 = _bundle(tmp_path)
    del bundle3["reports"][0]["entries"][0]["digest"]
    with pytest.raises(ValueError):
        verify_audit_bundle(bundle3, _expected(bundle3))

    bundle4 = _bundle(tmp_path)
    bundle4["reports"][0]["entries"] = []
    with pytest.raises(ValueError):
        verify_audit_bundle(bundle4, _expected(bundle4))

    bundle5 = _bundle(tmp_path)
    entries = bundle5["reports"][0]["entries"]
    if len(entries) > 1:
        entries[1]["at"] = entries[0]["at"]
        with pytest.raises(ValueError):
            verify_audit_bundle(bundle5, _expected(bundle5))

    bundle6 = _bundle(tmp_path)
    bundle6["reports"][0]["entries"][0]["at"] = "2020-12-31T23:59:59Z"
    with pytest.raises(ValueError):
        verify_audit_bundle(bundle6, _expected(bundle6))

    bundle7 = _bundle(tmp_path)
    bundle7["reports"][0]["entries"][0]["decision"] = 5
    with pytest.raises(ValueError):
        verify_audit_bundle(bundle7, _expected(bundle7))


def test_bad_expected_shapes_raise_value_error(tmp_path):
    bundle = _bundle(tmp_path)

    def with_expected(expected):
        return verify_audit_bundle(bundle, expected)

    with pytest.raises(ValueError):
        with_expected({})
    with pytest.raises(ValueError):
        with_expected([])
    expected = _expected(bundle)
    del expected["root"]
    with pytest.raises(ValueError):
        with_expected(expected)
    expected = _expected(bundle)
    expected["extra"] = 1
    with pytest.raises(ValueError):
        with_expected(expected)
    expected = _expected(bundle)
    expected["root"] = "x"
    with pytest.raises(ValueError):
        with_expected(expected)
    expected = _expected(bundle)
    expected["start"] = "bad"
    with pytest.raises(ValueError):
        with_expected(expected)
    expected = _expected(bundle)
    expected["record_ids"] = []
    with pytest.raises(ValueError):
        with_expected(expected)
    expected = _expected(bundle)
    expected["record_ids"] = "ab"
    with pytest.raises(ValueError):
        with_expected(expected)
    expected = _expected(bundle)
    expected["record_ids"] = ["a", "a"]
    with pytest.raises(ValueError):
        with_expected(expected)
    expected = _expected(bundle)
    expected["record_ids"] = ["a", ""]
    with pytest.raises(ValueError):
        with_expected(expected)
    expected = _expected(bundle)
    expected["record_ids"] = ["a", 1]
    with pytest.raises(ValueError):
        with_expected(expected)


def test_structure_is_validated_before_value_comparison(tmp_path):
    # A structurally invalid report raises even though its summary fields
    # happen to equal the expected ones.
    bundle = _bundle(tmp_path)
    bundle["reports"] = []
    with pytest.raises(ValueError):
        verify_audit_bundle(bundle, _expected(bundle))
    # An invalid expected raises regardless of a matching report.
    good = _bundle(tmp_path)
    expected = _expected(good)
    expected["record_ids"] = []
    with pytest.raises(ValueError):
        verify_audit_bundle(good, expected)


def test_does_not_mutate_inputs(tmp_path):
    bundle = _bundle(tmp_path)
    expected = _expected(bundle, ids=["é", "b", "a"])
    bundle_before = copy.deepcopy(bundle)
    expected_before = copy.deepcopy(expected)
    verify_audit_bundle(bundle, expected)
    assert bundle == bundle_before
    assert expected == expected_before


def test_http_valid_bundle_is_200_compact_json(tmp_path, monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    bundle = _bundle(tmp_path)
    response = TestClient(app).post(
        "/audits/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
    raw = response.content.decode("utf-8")
    assert raw == json.dumps({"valid": True}, separators=(",", ":"))
    assert not raw.endswith("\n")


def test_http_tampered_bundle_is_200_false(tmp_path, monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    bundle = _bundle(tmp_path)
    bundle["reports"][0]["entries"][0]["decision"] = "tampered"
    response = TestClient(app).post(
        "/audits/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": False}


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b'"x"',
        b"{}",
        b'{"report": {}}',
        b'{"report": {}, "expected": {}, "extra": 1}',
    ],
)
def test_http_bad_body_is_422(tmp_path, monkeypatch, body):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    response = TestClient(app).post(
        "/audits/bundle/verify",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}


def test_http_value_error_in_function_is_422(tmp_path, monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    bundle = _bundle(tmp_path)
    bundle["reports"] = []
    response = TestClient(app).post(
        "/audits/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle)},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}
