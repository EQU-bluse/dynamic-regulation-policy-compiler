import hashlib
import json

import pytest

from regulation_policy_compiler.history import DecisionHistory


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


def _history(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("b", "2021-03-01T00:00:00Z", {}, [_rule(result="允许")])
    history.record("a", "2021-01-01T00:00:00Z", {}, [_rule(result="x")])
    history.record("a", "2021-02-01T00:00:00Z", {}, [])
    history.record("é", "2021-01-01T00:00:00Z", {}, [_rule(result="z")])
    return history


def _expected_root(reports):
    root = "0" * 64
    for report in reports:
        payload = json.dumps(
            {"id": report["id"], "root": report["root"]},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        root = hashlib.sha256(root.encode("ascii") + payload).hexdigest()
    return root


def test_bundle_shape_sorted_reports_and_root(tmp_path):
    history = _history(tmp_path)
    bundle = history.audit_bundle(
        ["b", "a", "é"], "2021-01-01T00:00:00Z", "2021-12-31T00:00:00Z"
    )
    assert list(bundle) == ["start", "end", "root", "reports"]
    assert bundle["start"] == "2021-01-01T00:00:00Z"
    assert bundle["end"] == "2021-12-31T00:00:00Z"
    assert [report["id"] for report in bundle["reports"]] == ["a", "b", "é"]
    for report in bundle["reports"]:
        assert list(report) == ["id", "start", "end", "root", "entries"]
        for entry in report["entries"]:
            assert list(entry) == [
                "at",
                "decision",
                "trace",
                "basis",
                "previous",
                "digest",
            ]
        assert report["root"] == report["entries"][-1]["digest"]
    assert bundle["root"] == _expected_root(bundle["reports"])


def test_bundle_single_id(tmp_path):
    history = _history(tmp_path)
    bundle = history.audit_bundle(
        ["a"], "2021-01-01T00:00:00Z", "2021-12-31T00:00:00Z"
    )
    assert [report["id"] for report in bundle["reports"]] == ["a"]
    payload = json.dumps(
        {"id": "a", "root": bundle["reports"][0]["root"]},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert bundle["root"] == hashlib.sha256(
        ("0" * 64).encode("ascii") + payload
    ).hexdigest()


def test_bundle_reports_match_audit(tmp_path):
    history = _history(tmp_path)
    start, end = "2021-01-01T00:00:00Z", "2021-12-31T00:00:00Z"
    bundle = history.audit_bundle(["a", "b", "é"], start, end)
    for record_id in ("a", "b", "é"):
        report = next(r for r in bundle["reports"] if r["id"] == record_id)
        assert report == history.audit(record_id, start, end)


def test_bundle_is_order_independent_and_byte_stable(tmp_path):
    history = _history(tmp_path)
    start, end = "2021-01-01T00:00:00Z", "2021-12-31T00:00:00Z"
    first = history.audit_bundle(["é", "b", "a"], start, end)
    second = history.audit_bundle(["a", "é", "b"], start, end)
    text = json.dumps(first, ensure_ascii=False, separators=(",", ":"))
    assert text == json.dumps(second, ensure_ascii=False, separators=(",", ":"))
    assert "é" in text and "允许" in text and "\\u" not in text


def test_bundle_missing_id_raises_key_error_without_partial_result(tmp_path):
    history = _history(tmp_path)
    with pytest.raises(KeyError):
        history.audit_bundle(
            ["a", "missing"], "2021-01-01T00:00:00Z", "2021-12-31T00:00:00Z"
        )
    # An id with no record inside the window also fails the whole bundle.
    with pytest.raises(KeyError):
        history.audit_bundle(
            ["a", "b"], "2021-03-15T00:00:00Z", "2021-12-31T00:00:00Z"
        )


def test_bundle_validates_before_auditing(tmp_path):
    history = _history(tmp_path)
    # Duplicate ids raise ValueError even when the ids are also absent.
    with pytest.raises(ValueError):
        history.audit_bundle(
            ["nope", "nope"], "2021-01-01T00:00:00Z", "2021-12-31T00:00:00Z"
        )


@pytest.mark.parametrize(
    "record_ids",
    [
        [],
        None,
        "a",
        {},
        ("a",),
        True,
        1,
        [""],
        [None],
        [1],
        ["a", 1],
        ["a", ""],
        ["a", "a"],
        ["a", "b", "a"],
    ],
)
def test_bundle_rejects_bad_record_ids(tmp_path, record_ids):
    history = _history(tmp_path)
    with pytest.raises(ValueError):
        history.audit_bundle(
            record_ids, "2021-01-01T00:00:00Z", "2021-12-31T00:00:00Z"
        )


def test_bundle_rejects_bad_time_window(tmp_path):
    history = _history(tmp_path)
    with pytest.raises(ValueError):
        history.audit_bundle(["a"], "bad", "2021-12-31T00:00:00Z")
    with pytest.raises(ValueError):
        history.audit_bundle(["a"], "2021-01-01T00:00:00Z", "bad")
    with pytest.raises(ValueError):
        history.audit_bundle(
            ["a"], "2021-12-31T00:00:00Z", "2021-01-01T00:00:00Z"
        )


def test_bundle_does_not_mutate_inputs_or_result(tmp_path):
    history = _history(tmp_path)
    ids = ["b", "a", "é"]
    ids_snapshot = list(ids)
    bundle = history.audit_bundle(
        ids, "2021-01-01T00:00:00Z", "2021-12-31T00:00:00Z"
    )
    assert ids == ids_snapshot
    bundle["reports"][0]["entries"][0]["decision"] = "tampered"
    bundle["reports"][0]["entries"][0]["trace"].append("x@9")
    bundle["reports"][0]["entries"][0]["basis"]["result"] = "tampered"
    again = history.audit_bundle(
        ids, "2021-01-01T00:00:00Z", "2021-12-31T00:00:00Z"
    )
    assert again["reports"][0]["entries"][0]["decision"] in ("x", None)
    assert "x@9" not in again["reports"][0]["entries"][0]["trace"]
    assert again["reports"][0]["entries"][0]["basis"]["result"] != "tampered"


def test_bundle_is_read_only(tmp_path):
    path = tmp_path / "history.json"
    history = _history(tmp_path)
    before = path.read_bytes()
    history.audit_bundle(
        ["a", "b", "é"], "2021-01-01T00:00:00Z", "2021-12-31T00:00:00Z"
    )
    with pytest.raises(KeyError):
        history.audit_bundle(
            ["zzz"], "2021-01-01T00:00:00Z", "2021-12-31T00:00:00Z"
        )
    assert path.read_bytes() == before
