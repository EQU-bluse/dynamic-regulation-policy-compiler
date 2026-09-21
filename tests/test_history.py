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


def _read(path):
    return path.read_text(encoding="utf-8")


def test_missing_file_is_created_empty(tmp_path):
    path = tmp_path / "nested" / "history.json"
    history = DecisionHistory(str(path))

    assert path.read_text(encoding="utf-8") == '{"records":[]}\n'
    assert json.loads(path.read_text(encoding="utf-8")) == {"records": []}
    assert history.replay.__name__ == "replay"


@pytest.mark.parametrize("path", ["", 123, None])
def test_path_must_be_non_empty_str(path):
    with pytest.raises(ValueError):
        DecisionHistory(path)


def test_bad_json_raises_value_error(tmp_path):
    path = tmp_path / "history.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        DecisionHistory(str(path))


@pytest.mark.parametrize(
    "document",
    [
        "[]",
        "{}",
        '{"records": {}}',
        '{"records": [], "extra": 1}',
        '{"records": [{"id": "x", "at": "2021-06-01T00:00:00Z"}]}',
        '{"records": [{"id": "", "at": "2021-06-01T00:00:00Z",'
        ' "decision": null, "trace": [], "basis": null}]}',
        '{"records": [{"id": "x", "at": "2021-02-30T00:00:00Z",'
        ' "decision": null, "trace": [], "basis": null}]}',
        '{"records": [{"id": "x", "at": "2021-06-01T00:00:00Z",'
        ' "decision": 1, "trace": [], "basis": null}]}',
        '{"records": [{"id": "x", "at": "2021-06-01T00:00:00Z",'
        ' "decision": "", "trace": [], "basis": null}]}',
        '{"records": [{"id": "x", "at": "2021-06-01T00:00:00Z",'
        ' "decision": null, "trace": "nope", "basis": null}]}',
        '{"records": [{"id": "x", "at": "2021-06-01T00:00:00Z",'
        ' "decision": null, "trace": ["r1@1"], "basis": null}]}',
        '{"records": [{"id": "x", "at": "2021-06-01T00:00:00Z",'
        ' "decision": "allow", "trace": [], "basis": null}]}',
        '{"records": [{"id": "x", "at": "2021-06-01T00:00:00Z",'
        ' "decision": "other", "trace": ["r1@1"], '
        '"basis": {"id": "r1", "ver": 1, "source": "law", "priority": 0, '
        '"from": "2020-01-01T00:00:00Z", "to": null, "when": null, "result": "allow"}}]}',
        '{"records": [{"id": "x", "at": "2021-06-01T00:00:00Z",'
        ' "decision": null, "trace": [], "basis": {"nope": 1}}]}',
        '{"records": ['
        '{"id": "x", "at": "2021-06-01T00:00:00Z", "decision": null, "trace": [], "basis": null},'
        '{"id": "x", "at": "2021-06-01T00:00:00Z", "decision": null, "trace": [], "basis": null}'
        "]}",
    ],
)
def test_bad_structure_raises_value_error(tmp_path, document):
    path = tmp_path / "history.json"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(ValueError):
        DecisionHistory(str(path))


def test_io_error_is_oserror(tmp_path):
    path = tmp_path / "a-directory"
    path.mkdir()
    with pytest.raises(OSError):
        DecisionHistory(str(path))


def test_record_match_persists_compact_sorted_json(tmp_path):
    path = tmp_path / "history.json"
    history = DecisionHistory(str(path))
    rules = [
        _rule(id="b", result="b"),
        _rule(id="a", priority=5, result="a", when={"z": True, "a": False}),
    ]

    entry = history.record("案-1", "2021-06-01T00:00:00Z", {"z": True, "a": False}, rules)

    assert entry["id"] == "案-1"
    assert entry["decision"] == "a"
    assert entry["trace"] == ["a@1", "b@1"]
    assert tuple(entry["basis"]) == ("id", "ver", "source", "priority", "from", "to", "when", "result")
    assert entry["basis"]["id"] == "a"
    assert entry["basis"]["result"] == "a"
    assert list(entry["basis"]["when"]) == ["a", "z"]

    text = _read(path)
    assert text.endswith("\n") and not text.endswith("\n\n")
    assert "\\u" not in text  # ensure_ascii=False
    assert ", " not in text and '": ' not in text
    assert '"id":"案-1"' in text


def test_records_sorted_by_id_then_at_code_points(tmp_path):
    path = tmp_path / "history.json"
    history = DecisionHistory(str(path))

    history.record("b", "2021-06-01T00:00:00Z", {}, [_rule()])
    history.record("a", "2022-01-01T00:00:00Z", {}, [])
    history.record("a", "2020-01-01T00:00:00Z", {}, [])
    history.record("A", "2020-01-01T00:00:00Z", {}, [])

    data = json.loads(_read(path))
    keys = [(r["id"], r["at"]) for r in data["records"]]
    assert keys == [
        ("A", "2020-01-01T00:00:00Z"),
        ("a", "2020-01-01T00:00:00Z"),
        ("a", "2022-01-01T00:00:00Z"),
        ("b", "2021-06-01T00:00:00Z"),
    ]


def test_no_match_persists_nulls(tmp_path):
    history = DecisionHistory(str(tmp_path / "h.json"))
    entry = history.record("x", "2019-01-01T00:00:00Z", {}, [_rule()])
    assert entry == {"id": "x", "at": "2019-01-01T00:00:00Z",
                     "decision": None, "trace": [], "basis": None}


def test_duplicate_id_at_raises(tmp_path):
    history = DecisionHistory(str(tmp_path / "h.json"))
    history.record("x", "2021-06-01T00:00:00Z", {}, [])
    with pytest.raises(ValueError):
        history.record("x", "2021-06-01T00:00:00Z", {}, [_rule()])
    # Same id at a different at is allowed.
    assert history.record("x", "2021-06-02T00:00:00Z", {}, [])["id"] == "x"


@pytest.mark.parametrize("record_id", ["", 5, None])
def test_record_validates_id(record_id, tmp_path):
    history = DecisionHistory(str(tmp_path / "h.json"))
    with pytest.raises(ValueError):
        history.record(record_id, "2021-06-01T00:00:00Z", {}, [])


def test_record_validation_matches_evaluate(tmp_path):
    path = tmp_path / "h.json"
    history = DecisionHistory(str(path))
    before = _read(path)

    with pytest.raises(ValueError):
        history.record("x", "2021-02-30T00:00:00Z", {}, [])
    with pytest.raises(ValueError):
        history.record("x", "2021-06-01T00:00:00Z", {"k": 1}, [])
    with pytest.raises(ValueError):
        history.record("x", "2021-06-01T00:00:00Z", {}, [_rule(ver=0)])
    with pytest.raises(ValueError):
        history.record("x", "2021-06-01T00:00:00Z", {}, [_rule(), _rule()])

    assert _read(path) == before


def test_replay_returns_latest_at_or_before_without_recompute(tmp_path):
    path = tmp_path / "h.json"
    history = DecisionHistory(str(path))
    history.record("x", "2021-01-01T00:00:00Z", {}, [_rule(result="old")])
    history.record("x", "2021-06-01T00:00:00Z", {}, [_rule(result="new")])

    # Boundary is inclusive.
    assert history.replay("x", "2021-01-01T00:00:00Z")["decision"] == "old"
    assert history.replay("x", "2021-05-31T23:59:59Z")["decision"] == "old"
    assert history.replay("x", "2021-06-01T00:00:00Z")["decision"] == "new"
    assert history.replay("x", "2025-01-01T00:00:00Z")["decision"] == "new"


def test_replay_scoped_by_id(tmp_path):
    history = DecisionHistory(str(tmp_path / "h.json"))
    history.record("a", "2021-06-01T00:00:00Z", {}, [])
    history.record("b", "2021-06-01T00:00:00Z", {}, [_rule()])

    assert history.replay("b", "2021-06-01T00:00:00Z")["decision"] == "allow"
    with pytest.raises(KeyError):
        history.replay("c", "2021-06-01T00:00:00Z")
    with pytest.raises(KeyError):
        history.replay("a", "2020-01-01T00:00:00Z")


def test_replay_validates_arguments(tmp_path):
    history = DecisionHistory(str(tmp_path / "h.json"))
    with pytest.raises(ValueError):
        history.replay("", "2021-06-01T00:00:00Z")
    with pytest.raises(ValueError):
        history.replay("a", "not-a-time")


def test_replay_reads_from_disk_and_returns_copy(tmp_path):
    path = tmp_path / "h.json"
    history = DecisionHistory(str(path))
    history.record("x", "2021-06-01T00:00:00Z", {}, [_rule(result="new", ver=2)])

    reopened = DecisionHistory(str(path))
    entry = reopened.replay("x", "2021-06-01T00:00:00Z")
    assert entry["decision"] == "new"
    assert entry["trace"] == ["r1@2"]

    entry["decision"] = "mutated"
    entry["basis"]["result"] = "mutated"
    assert reopened.replay("x", "2021-06-01T00:00:00Z")["decision"] == "new"


def test_failed_atomic_write_keeps_old_file_and_state(tmp_path, monkeypatch):
    path = tmp_path / "h.json"
    history = DecisionHistory(str(path))
    history.record("x", "2021-06-01T00:00:00Z", {}, [_rule()])
    before = _read(path)

    import regulation_policy_compiler.history as module

    def boom(src, dst):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(module.os, "replace", boom)

    with pytest.raises(OSError):
        history.record("y", "2021-06-01T00:00:00Z", {}, [_rule()])

    assert _read(path) == before
    assert not list(tmp_path.glob(".history-*.tmp"))
    # In-memory state matches the file.
    assert history.replay("x", "2021-06-01T00:00:00Z")["decision"] == "allow"
    with pytest.raises(KeyError):
        history.replay("y", "2021-06-01T00:00:00Z")


def test_unicode_sorting_and_ascii_free_serialization(tmp_path):
    path = tmp_path / "h.json"
    history = DecisionHistory(str(path))
    history.record("é1", "2021-06-01T00:00:00Z", {}, [])
    history.record("e2", "2021-06-01T00:00:00Z", {}, [])

    text = _read(path)
    assert "é1" in text and "\\u" not in text
    data = json.loads(text)
    # 'e' (U+0065) < 'é' (U+00E9) in code-point order.
    assert [r["id"] for r in data["records"]] == ["e2", "é1"]
