import copy
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


START = "2021-01-01T00:00:00Z"
END = "2021-12-31T00:00:00Z"


def _history(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("b", "2021-02-01T00:00:00Z", {}, [_rule(result="允许")])
    history.record("a", "2021-01-01T00:00:00Z", {}, [_rule(result="x")])
    history.record("é", "2021-03-01T00:00:00Z", {}, [])
    return history


def _expected_root(reports):
    previous = "0" * 64
    for report in reports:
        link = {"id": report["id"], "root": report["root"]}
        payload = json.dumps(link, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        previous = hashlib.sha256(previous.encode("ascii") + payload).hexdigest()
    return previous


def test_audit_bundle_shape_ordering_and_chain(tmp_path):
    history = _history(tmp_path)
    bundle = history.audit_bundle(["é", "a", "b"], START, END)
    assert list(bundle) == ["start", "end", "root", "reports"]
    assert bundle["start"] == START
    assert bundle["end"] == END
    # Sorted by Unicode code point regardless of input order.
    assert [report["id"] for report in bundle["reports"]] == ["a", "b", "é"]
    for report in bundle["reports"]:
        assert list(report) == ["id", "start", "end", "root", "entries"]
        for entry in report["entries"]:
            assert list(entry) == [
                "at", "decision", "trace", "basis", "previous", "digest"
            ]
    assert bundle["root"] == _expected_root(bundle["reports"])


def test_audit_bundle_reports_equal_plain_audit(tmp_path):
    history = _history(tmp_path)
    bundle = history.audit_bundle(["é", "a", "b"], START, END)
    for report in bundle["reports"]:
        assert report == history.audit(report["id"], START, END)


def test_audit_bundle_is_deterministic_across_input_permutations(tmp_path):
    history = _history(tmp_path)
    first = history.audit_bundle(["é", "a", "b"], START, END)
    second = history.audit_bundle(["b", "é", "a"], START, END)
    serialized_first = json.dumps(first, ensure_ascii=False, separators=(",", ":"))
    serialized_second = json.dumps(second, ensure_ascii=False, separators=(",", ":"))
    assert serialized_first == serialized_second


def test_audit_bundle_returns_deep_copies(tmp_path):
    history = _history(tmp_path)
    bundle = history.audit_bundle(["a"], START, END)
    bundle["reports"][0]["entries"][0]["decision"] = "tampered"
    bundle["reports"][0]["entries"][0]["basis"]["result"] = "tampered"
    again = history.audit_bundle(["a"], START, END)
    assert again["reports"][0]["entries"][0]["decision"] == "x"
    assert again["reports"][0]["entries"][0]["basis"]["result"] == "x"


def test_audit_bundle_is_read_only(tmp_path):
    path = tmp_path / "history.json"
    history = DecisionHistory(str(path))
    history.record("a", "2021-01-01T00:00:00Z", {}, [])
    before = path.read_bytes()
    history.audit_bundle(["a"], START, END)
    with pytest.raises(KeyError):
        history.audit_bundle(["a", "missing"], START, END)
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "record_ids",
    [
        [],
        (),
        None,
        "a",
        {"a": 1},
        [""],
        ["a", "a"],
        ["a", "", "b"],
        [None],
        [1],
        ["a", 1],
    ],
)
def test_audit_bundle_rejects_bad_record_ids(tmp_path, record_ids):
    history = _history(tmp_path)
    with pytest.raises(ValueError):
        history.audit_bundle(record_ids, START, END)


def test_audit_bundle_rejects_bad_time_window(tmp_path):
    history = _history(tmp_path)
    with pytest.raises(ValueError):
        history.audit_bundle(["a"], "bad", END)
    with pytest.raises(ValueError):
        history.audit_bundle(["a"], START, "bad")
    with pytest.raises(ValueError):
        history.audit_bundle(["a"], END, START)


def test_audit_bundle_validates_arguments_before_history_lookup(tmp_path):
    history = _history(tmp_path)
    # Bad ids and bad window together must surface ValueError, not KeyError.
    with pytest.raises(ValueError):
        history.audit_bundle(["a", "a"], END, START)


def test_audit_bundle_does_not_mutate_input_on_error(tmp_path):
    history = _history(tmp_path)
    record_ids = ["b", "a"]
    snapshot = copy.deepcopy(record_ids)
    with pytest.raises(KeyError):
        history.audit_bundle(["z", "a"], START, END)
    assert record_ids == snapshot
    with pytest.raises(ValueError):
        history.audit_bundle(record_ids + record_ids, START, END)
    assert record_ids == snapshot


def test_audit_bundle_missing_id_raises_key_error_without_partial_result(tmp_path):
    history = _history(tmp_path)
    with pytest.raises(KeyError) as exc_info:
        history.audit_bundle(["a", "missing"], START, END)
    assert exc_info.value.args[0] == "missing"
    # Missing id sorts first as well: still KeyError identifying it.
    with pytest.raises(KeyError) as exc_info:
        history.audit_bundle(["missing", "a"], START, END)
    assert exc_info.value.args[0] == "missing"
    # An id with no record inside the narrowed window.
    with pytest.raises(KeyError):
        history.audit_bundle(
            ["a"], "2022-01-01T00:00:00Z", "2022-12-31T00:00:00Z"
        )
