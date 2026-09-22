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
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def test_init_rejects_bad_path(tmp_path):
    for bad in ("", None, 123, tmp_path):
        with pytest.raises(ValueError):
            DecisionHistory(bad)


def test_missing_file_is_created(tmp_path):
    path = tmp_path / "history.json"
    DecisionHistory(str(path))
    assert _read(path) == {"records": []}
    with open(path, encoding="utf-8") as handle:
        raw = handle.read()
    assert raw == '{"records":[]}\n'


def test_bad_json_raises_value_error(tmp_path):
    path = tmp_path / "history.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError):
        DecisionHistory(str(path))


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"records": [], "extra": 1},
        {"records": {}},
        {"records": [{"id": "a", "at": "2021-01-01T00:00:00Z", "decision": None, "trace": []}]},
        {"records": [{"id": "", "at": "2021-01-01T00:00:00Z", "decision": None, "trace": [], "basis": None}]},
        {"records": [{"id": "a", "at": "bad", "decision": None, "trace": [], "basis": None}]},
        {"records": [{"id": "a", "at": "2021-01-01T00:00:00Z", "decision": 1, "trace": [], "basis": None}]},
        {"records": [{"id": "a", "at": "2021-01-01T00:00:00Z", "decision": None, "trace": [1], "basis": None}]},
        {"records": [{"id": "a", "at": "2021-01-01T00:00:00Z", "decision": None, "trace": ["x"], "basis": None}]},
        {"records": [{"id": "a", "at": "2021-01-01T00:00:00Z", "decision": None, "trace": [], "basis": {"id": "r"}}]},
    ],
)
def test_bad_structure_raises_value_error(tmp_path, payload):
    path = tmp_path / "history.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError):
        DecisionHistory(str(path))


def test_record_no_match(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    entry = history.record("rec-1", "2021-06-01T00:00:00Z", {}, [])
    assert entry == {"id": "rec-1", "at": "2021-06-01T00:00:00Z", "decision": None, "trace": [], "basis": None}


def test_record_with_match_snap(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    rules = [
        _rule(id="b", priority=5, result="b", when={"z": False, "a": True}),
        _rule(id="a", priority=5, result="a"),
    ]
    entry = history.record("rec-1", "2021-06-01T00:00:00Z", {"z": False, "a": True}, rules)
    assert entry["decision"] == "a"
    assert entry["trace"] == ["a@1", "b@1"]
    assert entry["basis"] == _rule(id="a", priority=5, result="a")
    assert list(entry) == ["id", "at", "decision", "trace", "basis"]
    assert list(entry["basis"]) == ["id", "ver", "source", "priority", "from", "to", "when", "result"]


def test_record_basis_when_keys_sorted(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    rules = [_rule(when={"z": True, "m": False, "a": True})]
    entry = history.record("rec-1", "2021-06-01T00:00:00Z", {"z": True, "m": False, "a": True}, rules)
    assert list(entry["basis"]["when"]) == ["a", "m", "z"]


def test_record_persists_sorted_compact_utf8(tmp_path):
    path = tmp_path / "history.json"
    history = DecisionHistory(str(path))
    history.record("b", "2021-01-01T00:00:00Z", {}, [])
    history.record("a", "2021-06-01T00:00:00Z", {}, [])
    history.record("a", "2021-01-01T00:00:00Z", {}, [])
    history.record("é", "2021-01-01T00:00:00Z", {}, [])
    raw = path.read_bytes().decode("utf-8")
    assert raw.endswith("\n") and not raw.endswith("\n\n")
    assert ", " not in raw and '": ' not in raw
    assert "é" in raw  # ensure_ascii=False
    data = json.loads(raw)
    assert set(data) == {"records"}
    keys = [(entry["id"], entry["at"]) for entry in data["records"]]
    assert keys == sorted(keys)


def test_record_reload_roundtrip(tmp_path):
    path = str(tmp_path / "history.json")
    history = DecisionHistory(path)
    history.record("rec-1", "2021-06-01T00:00:00Z", {}, [_rule()])
    reloaded = DecisionHistory(path)
    assert reloaded.replay("rec-1", "2021-06-01T00:00:00Z")["decision"] == "allow"


def test_record_rejects_duplicate_and_bad_input(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("rec-1", "2021-06-01T00:00:00Z", {}, [])
    with pytest.raises(ValueError):
        history.record("rec-1", "2021-06-01T00:00:00Z", {}, [])
    with pytest.raises(ValueError):
        history.record("", "2021-06-02T00:00:00Z", {}, [])
    with pytest.raises(ValueError):
        history.record("rec-2", "not-a-time", {}, [])
    with pytest.raises(ValueError):
        history.record("rec-2", "2021-06-02T00:00:00Z", {"x": 1}, [])
    with pytest.raises(ValueError):
        history.record("rec-2", "2021-06-02T00:00:00Z", {}, [_rule(ver=0)])


def test_replay_returns_most_recent_at_or_before(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="first")])
    history.record("rec-1", "2021-06-01T00:00:00Z", {}, [_rule(result="second")])
    history.record("rec-2", "2021-03-01T00:00:00Z", {}, [_rule(result="other")])
    assert history.replay("rec-1", "2021-06-01T00:00:00Z")["decision"] == "second"
    assert history.replay("rec-1", "2021-05-31T23:59:59Z")["decision"] == "first"
    with pytest.raises(KeyError):
        history.replay("rec-1", "2020-12-31T23:59:59Z")
    with pytest.raises(KeyError):
        history.replay("missing", "2022-01-01T00:00:00Z")
    with pytest.raises(ValueError):
        history.replay("", "2021-01-01T00:00:00Z")
    with pytest.raises(ValueError):
        history.replay("rec-1", "bad")


def test_replay_returns_a_copy(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule()])
    entry = history.replay("rec-1", "2021-01-01T00:00:00Z")
    entry["decision"] = "tampered"
    entry["basis"]["result"] = "tampered"
    assert history.replay("rec-1", "2021-01-01T00:00:00Z")["decision"] == "allow"


def test_record_does_not_recompute_on_replay(tmp_path):
    path = str(tmp_path / "history.json")
    history = DecisionHistory(path)
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule()])
    # Corrupt nothing: replay must serve the stored snapshot even though the
    # original rules are no longer supplied.
    assert history.replay("rec-1", "2021-01-01T00:00:00Z")["basis"]["result"] == "allow"


def test_failed_write_keeps_old_file(tmp_path, monkeypatch):
    path = tmp_path / "history.json"
    history = DecisionHistory(str(path))
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [])
    before = path.read_bytes()

    import regulation_policy_compiler.history as history_module

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(history_module.os, "replace", boom)
    with pytest.raises(OSError):
        history.record("rec-2", "2021-01-01T00:00:00Z", {}, [])
    assert path.read_bytes() == before
    # The failed record was rolled back in memory as well.
    with pytest.raises(KeyError):
        history.replay("rec-2", "2021-01-01T00:00:00Z")


def _history_with_records(tmp_path, triples):
    history = DecisionHistory(str(tmp_path / "history.json"))
    for record_id, at, rules in triples:
        history.record(record_id, at, {}, rules)
    return history


def test_evolution_returns_entries_in_closed_interval_ascending(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("rec-1", "2021-03-01T00:00:00Z", {}, [])
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="first")])
    history.record("rec-1", "2021-06-01T00:00:00Z", {}, [_rule(result="second")])
    history.record("other", "2021-02-01T00:00:00Z", {}, [_rule(result="x")])
    report = history.evolution(
        "rec-1", "2021-01-01T00:00:00Z", "2021-06-01T00:00:00Z"
    )
    assert list(report) == ["id", "start", "end", "entries"]
    assert report["id"] == "rec-1"
    assert report["start"] == "2021-01-01T00:00:00Z"
    assert report["end"] == "2021-06-01T00:00:00Z"
    assert [entry["at"] for entry in report["entries"]] == [
        "2021-01-01T00:00:00Z",
        "2021-03-01T00:00:00Z",
        "2021-06-01T00:00:00Z",
    ]
    for entry in report["entries"]:
        assert list(entry) == ["at", "decision", "trace", "basis", "changes"]


def test_evolution_interval_bounds_are_inclusive(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="a")])
    history.record("rec-1", "2021-02-01T00:00:00Z", {}, [_rule(result="b")])
    history.record("rec-1", "2021-03-01T00:00:00Z", {}, [_rule(result="c")])
    report = history.evolution(
        "rec-1", "2021-02-01T00:00:00Z", "2021-02-01T00:00:00Z"
    )
    assert [entry["at"] for entry in report["entries"]] == ["2021-02-01T00:00:00Z"]
    assert report["entries"][0]["decision"] == "b"
    assert report["entries"][0]["changes"] == []


def test_evolution_changes_listed_in_fixed_order(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(id="r", result="allow")])
    history.record("rec-1", "2021-02-01T00:00:00Z", {}, [_rule(id="r", result="allow")])
    history.record("rec-1", "2021-03-01T00:00:00Z", {}, [])
    report = history.evolution(
        "rec-1", "2021-01-01T00:00:00Z", "2021-03-01T00:00:00Z"
    )
    first, second, third = report["entries"]
    assert first["changes"] == []
    # Identical decision/trace/basis values -> no changes.
    assert second["changes"] == []
    # decision, trace, basis all differ from the previous entry.
    assert third["changes"] == ["decision", "trace", "basis"]


def test_evolution_changes_compared_to_immediate_previous_entry(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="a")])
    history.record("rec-1", "2021-02-01T00:00:00Z", {}, [_rule(result="b")])
    history.record("rec-1", "2021-03-01T00:00:00Z", {}, [_rule(result="a")])
    report = history.evolution(
        "rec-1", "2021-01-01T00:00:00Z", "2021-03-01T00:00:00Z"
    )
    first, second, third = report["entries"]
    assert first["changes"] == []
    assert second["changes"] == ["decision", "basis"]
    # Compared against the second entry, not the first.
    assert third["changes"] == ["decision", "basis"]


def test_evolution_trace_only_change(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record(
        "rec-1",
        "2021-01-01T00:00:00Z",
        {"a": True},
        [_rule(id="win", priority=9, result="allow"), _rule(id="loser", result="deny", when={"a": True})],
    )
    history.record(
        "rec-1",
        "2021-02-01T00:00:00Z",
        {},
        [_rule(id="win", priority=9, result="allow"), _rule(id="loser", result="deny", when={"a": True})],
    )
    report = history.evolution(
        "rec-1", "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z"
    )
    assert report["entries"][0]["trace"] == ["win@1", "loser@1"]
    assert report["entries"][1]["trace"] == ["win@1"]
    assert report["entries"][1]["decision"] == "allow"
    assert report["entries"][1]["changes"] == ["trace"]


def test_evolution_empty_interval_raises_key_error(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("rec-1", "2021-06-01T00:00:00Z", {}, [])
    with pytest.raises(KeyError):
        history.evolution("rec-1", "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z")
    with pytest.raises(KeyError):
        history.evolution("missing", "2021-01-01T00:00:00Z", "2022-01-01T00:00:00Z")


def test_evolution_rejects_bad_arguments(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    with pytest.raises(ValueError):
        history.evolution("", "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z")
    with pytest.raises(ValueError):
        history.evolution(None, "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z")
    with pytest.raises(ValueError):
        history.evolution("rec-1", "bad", "2021-02-01T00:00:00Z")
    with pytest.raises(ValueError):
        history.evolution("rec-1", "2021-01-01T00:00:00Z", "bad")
    with pytest.raises(ValueError):
        history.evolution(
            "rec-1", "2021-02-01T00:00:00Z", "2021-01-01T00:00:00Z"
        )


def test_evolution_returns_deep_copies_and_does_not_mutate(tmp_path):
    history = DecisionHistory(str(tmp_path / "history.json"))
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [_rule(result="a")])
    history.record("rec-1", "2021-02-01T00:00:00Z", {}, [_rule(result="b")])
    report = history.evolution(
        "rec-1", "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z"
    )
    report["entries"][0]["decision"] = "tampered"
    report["entries"][0]["trace"].append("x@9")
    report["entries"][0]["basis"]["result"] = "tampered"
    again = history.evolution(
        "rec-1", "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z"
    )
    assert again["entries"][0]["decision"] == "a"
    assert again["entries"][0]["trace"] == ["r1@1"]
    assert again["entries"][0]["basis"]["result"] == "a"
    assert again["entries"][1]["changes"] == ["decision", "basis"]


def test_evolution_is_read_only(tmp_path):
    path = tmp_path / "history.json"
    history = DecisionHistory(str(path))
    history.record("rec-1", "2021-01-01T00:00:00Z", {}, [])
    before = path.read_bytes()
    history.evolution("rec-1", "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z")
    with pytest.raises(KeyError):
        history.evolution("rec-1", "2022-01-01T00:00:00Z", "2022-02-01T00:00:00Z")
    assert path.read_bytes() == before
