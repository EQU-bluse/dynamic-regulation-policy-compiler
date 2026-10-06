import copy

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    ReplayInputError,
    compile_rules,
    explain,
    replay_history,
)

client = TestClient(app)


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


def _record(record_id="rec-1", at="2021-06-01T00:00:00Z", facts=None):
    return {"id": record_id, "at": at, "facts": {} if facts is None else facts}


# ---------------------------------------------------------------------------
# version selection and cutoff semantics
# ---------------------------------------------------------------------------


def test_selects_version_effective_at_record_time_only():
    rules = [
        _rule(id="r", ver=1, **{"from": "2020-01-01T00:00:00Z"}, result="old"),
        _rule(id="r", ver=2, **{"from": "2021-01-01T00:00:00Z"}, result="new"),
    ]
    records = [
        _record("a", "2020-06-01T00:00:00Z"),
        _record("b", "2021-06-01T00:00:00Z"),
    ]
    result = replay_history(rules, records)
    assert [item["id"] for item in result["results"]] == ["a", "b"]
    assert result["results"][0]["decision"] == "old"
    assert result["results"][0]["versions"] == {"law": {"r": 1}, "org": {}}
    assert result["results"][1]["decision"] == "new"
    assert result["results"][1]["versions"] == {"law": {"r": 2}, "org": {}}


def test_window_is_from_inclusive_to_exclusive():
    rules = [
        _rule(
            id="r",
            ver=1,
            **{
                "from": "2021-01-01T00:00:00Z",
                "to": "2021-07-01T00:00:00Z",
            },
        )
    ]
    result = replay_history(
        rules,
        [
            _record("start", "2021-01-01T00:00:00Z"),
            _record("end", "2021-07-01T00:00:00Z"),
        ],
    )
    assert result["results"][0]["decision"] == "allow"
    assert result["results"][1]["error"]["code"] == "VERSION_NOT_FOUND"


def test_cutoff_hides_versions_effective_after_it():
    rules = [
        _rule(id="r", ver=1, **{"from": "2020-01-01T00:00:00Z"}, result="old"),
        _rule(id="r", ver=2, **{"from": "2021-01-01T00:00:00Z"}, result="new"),
    ]
    records = [_record("a", "2021-06-01T00:00:00Z")]
    without = replay_history(rules, records)
    assert without["cutoff"] is None
    assert without["results"][0]["decision"] == "new"
    with_cutoff = replay_history(rules, records, "2020-06-01T00:00:00Z")
    assert with_cutoff["cutoff"] == "2020-06-01T00:00:00Z"
    assert with_cutoff["results"][0]["decision"] == "old"
    assert with_cutoff["results"][0]["versions"] == {"law": {"r": 1}, "org": {}}


def test_cutoff_does_not_override_occurrence_time():
    # The record happened before any rule was effective; a late cutoff must
    # not make a version visible for that instant.
    rules = [_rule(id="r", ver=1, **{"from": "2021-01-01T00:00:00Z"})]
    result = replay_history(
        rules, [_record("a", "2020-06-01T00:00:00Z")], "2022-01-01T00:00:00Z"
    )
    assert result["results"][0]["error"]["code"] == "VERSION_NOT_FOUND"


def test_cutoff_boundary_includes_version_effective_exactly_at_cutoff():
    rules = [_rule(id="r", ver=1, **{"from": "2021-01-01T00:00:00Z"})]
    result = replay_history(
        rules, [_record("a", "2021-06-01T00:00:00Z")], "2021-01-01T00:00:00Z"
    )
    assert result["results"][0]["decision"] == "allow"


def test_version_not_found_when_every_version_is_after_cutoff():
    rules = [_rule(id="r", ver=1, **{"from": "2021-01-01T00:00:00Z"})]
    result = replay_history(
        rules, [_record("a", "2021-06-01T00:00:00Z")], "2020-01-01T00:00:00Z"
    )
    item = result["results"][0]
    assert item["error"]["code"] == "VERSION_NOT_FOUND"
    assert item["at"] == "2021-06-01T00:00:00Z"
    assert "decision" not in item


# ---------------------------------------------------------------------------
# timestamp normalization
# ---------------------------------------------------------------------------


def test_offsets_naming_the_same_instant_select_the_same_version():
    rules = [
        _rule(id="r", ver=1, **{"from": "2020-01-01T00:00:00Z"}, result="old"),
        _rule(id="r", ver=2, **{"from": "2021-06-01T00:00:00Z"}, result="new"),
    ]
    records = [
        _record("utc", "2021-06-01T00:00:00Z"),
        _record("east", "2021-06-01T08:00:00+08:00"),
        _record("west", "2021-05-31T16:00:00-08:00"),
    ]
    result = replay_history(rules, records)
    for item in result["results"]:
        assert item["at"] == "2021-06-01T00:00:00Z"
        assert item["decision"] == "new"
        assert item["versions"] == {"law": {"r": 2}, "org": {}}


def test_cutoff_is_normalized_to_utc():
    result = replay_history([], [], "2021-06-01T08:00:00+08:00")
    assert result == {"cutoff": "2021-06-01T00:00:00Z", "results": []}


# ---------------------------------------------------------------------------
# ordering, determinism, and positional failures
# ---------------------------------------------------------------------------


def test_results_follow_input_order_and_reorder_only_reorders():
    rules = [
        _rule(id="r", ver=1, **{"from": "2020-01-01T00:00:00Z"}, result="old"),
        _rule(id="r", ver=2, **{"from": "2021-01-01T00:00:00Z"}, result="new"),
    ]
    records = [
        _record("a", "2021-06-01T00:00:00Z"),
        _record("b", "2020-06-01T00:00:00Z"),
    ]
    forward = replay_history(rules, records)
    backward = replay_history(rules, list(reversed(records)))
    assert [item["id"] for item in forward["results"]] == ["a", "b"]
    assert [item["id"] for item in backward["results"]] == ["b", "a"]
    assert forward["results"][0] == backward["results"][1]
    assert forward["results"][1] == backward["results"][0]


def test_repeated_calls_are_identical():
    rules = [_rule(id="r", ver=1), _rule(id="o", source="org", priority=3)]
    records = [_record("a"), _record("b", "2020-06-01T00:00:00Z")]
    first = replay_history(rules, records, "2021-01-01T00:00:00Z")
    second = replay_history(rules, records, "2021-01-01T00:00:00Z")
    assert first == second


def test_empty_batch_returns_empty_results():
    assert replay_history([], []) == {"cutoff": None, "results": []}
    assert replay_history([_rule()], [])["results"] == []


def test_failing_record_does_not_block_others_and_keeps_position():
    rules = [_rule(id="r", ver=1)]
    records = [
        _record("ok-1"),
        _record("bad", "not-a-time"),
        _record("ok-2", "2020-06-01T00:00:00Z"),
    ]
    result = replay_history(rules, records)
    assert [item["id"] for item in result["results"]] == ["ok-1", "bad", "ok-2"]
    assert result["results"][0]["decision"] == "allow"
    assert result["results"][1]["error"]["code"] == "INVALID_TIMESTAMP"
    assert result["results"][2]["decision"] == "allow"


# ---------------------------------------------------------------------------
# per-record error codes
# ---------------------------------------------------------------------------


def test_invalid_timestamp_variants():
    rules = [_rule(id="r", ver=1)]
    for bad in ("not-a-time", "2021-13-01T00:00:00Z", "2021-06-01T00:00:00", 42):
        result = replay_history(rules, [_record("x", bad)])
        item = result["results"][0]
        assert item["error"]["code"] == "INVALID_TIMESTAMP", bad
        assert item["error"]["field"] == "at"
        assert item["at"] is None
        assert "decision" not in item


def test_missing_fact_lists_sorted_fields():
    rules = [
        _rule(id="r", ver=1, when={"b": True, "a": False}),
        _rule(id="o", ver=1, source="org", when={"c": True}),
    ]
    result = replay_history(rules, [_record("x", facts={"a": False})])
    item = result["results"][0]
    assert item["error"]["code"] == "MISSING_FACT"
    assert item["error"]["fields"] == ["b", "c"]
    assert item["versions"] == {"law": {"r": 1}, "org": {"o": 1}}
    assert "decision" not in item


def test_error_items_are_stable_and_carry_no_environment_data():
    rules = [_rule(id="r", ver=1, when={"x": True})]
    records = [_record("x", "bad"), _record("y", facts={})]
    first = replay_history(rules, records)
    second = replay_history(rules, records)
    assert first == second
    for item in first["results"]:
        assert set(item["error"]) <= {"code", "message", "field", "fields"}
        assert isinstance(item["error"]["message"], str)


# ---------------------------------------------------------------------------
# batch-level ReplayInputError
# ---------------------------------------------------------------------------


def test_batch_level_errors_raise_replay_input_error():
    good = [_record("a")]
    with pytest.raises(ReplayInputError):
        replay_history([_rule()], {"not": "a list"})
    with pytest.raises(ReplayInputError):
        replay_history([_rule()], [_record("dup"), _record("dup")])
    with pytest.raises(ReplayInputError):
        replay_history(None, good)
    with pytest.raises(ReplayInputError):
        replay_history({"at": "2021-01-01T00:00:00Z"}, good)
    with pytest.raises(ReplayInputError):
        replay_history([_rule()], good, "not-a-time")
    with pytest.raises(ReplayInputError):
        replay_history([_rule()], good, "2021-06-01T00:00:00")
    with pytest.raises(ReplayInputError):
        replay_history([_rule()], [{"id": "a", "at": "2021-06-01T00:00:00Z"}])
    with pytest.raises(ReplayInputError):
        replay_history([_rule()], [_record("a", facts={"x": 1})])
    with pytest.raises(ReplayInputError):
        replay_history([_rule(ver=0)], good)


def test_replay_input_error_is_a_value_error():
    assert issubclass(ReplayInputError, ValueError)


# ---------------------------------------------------------------------------
# explanation trace
# ---------------------------------------------------------------------------


def test_explanation_covers_candidates_reasons_ranking_and_hit():
    rules = [
        _rule(id="win", ver=1, priority=5, result="allow"),
        _rule(id="lose", ver=1, priority=1, result="deny"),
        _rule(id="old", ver=1, **{"from": "2019-01-01T00:00:00Z",
                                  "to": "2020-01-01T00:00:00Z"}),
        _rule(id="sup", ver=1, **{"from": "2020-01-01T00:00:00Z"}),
        _rule(id="sup", ver=2, **{"from": "2020-06-01T00:00:00Z"},
              when={"x": True}),
        _rule(id="late", ver=1, **{"from": "2021-03-01T00:00:00Z"}),
    ]
    result = replay_history(
        rules, [_record("a", facts={"x": False})], "2021-01-01T00:00:00Z"
    )
    item = result["results"][0]
    assert item["decision"] == "allow"
    explanation = item["explanation"]
    assert explanation["trace"] == ["win@1", "lose@1"]
    assert explanation["basis"]["id"] == "win"
    by_id = {
        tuple(entry["rule"]): entry for entry in explanation["candidates"]
    }
    assert by_id[("law", "win", 1)]["status"] == "hit"
    assert by_id[("law", "win", 1)]["rank"] == 0
    assert by_id[("law", "lose", 1)]["status"] == "outranked"
    assert by_id[("law", "lose", 1)]["rank"] == 1
    assert by_id[("law", "old", 1)]["status"] == "not_effective"
    assert by_id[("law", "sup", 1)]["status"] == "superseded"
    assert by_id[("law", "sup", 2)]["status"] == "not_matched"
    assert by_id[("law", "late", 1)]["status"] == "after_cutoff"
    for entry in explanation["candidates"]:
        assert isinstance(entry["reason"], str) and entry["reason"]


def test_decision_matches_single_shot_explain():
    rules = [
        _rule(id="a", priority=2, result="allow", when={"x": True}),
        _rule(id="b", priority=1, result="deny"),
    ]
    facts = {"x": True}
    at = "2021-06-01T00:00:00Z"
    item = replay_history(rules, [_record("r", at, facts)])["results"][0]
    expected = explain(at, facts, rules)
    assert item["decision"] == expected["decision"]
    assert item["explanation"]["trace"] == expected["trace"]
    assert item["explanation"]["basis"] == expected["basis"]
    assert item["explanation"]["conflicts"] == expected["conflicts"]


def test_no_match_yields_null_decision_not_an_error():
    rules = [_rule(id="r", ver=1, when={"x": True}, result="allow")]
    item = replay_history(rules, [_record("r", facts={"x": False})])["results"][0]
    assert item["decision"] is None
    assert item["explanation"]["basis"] is None
    assert item["explanation"]["trace"] == []


# ---------------------------------------------------------------------------
# compiled artifact input and non-mutation
# ---------------------------------------------------------------------------


def test_compiled_artifact_is_accepted_and_not_modified():
    rules = [
        _rule(id="r", ver=1, **{"from": "2020-01-01T00:00:00Z"}, result="old"),
        _rule(id="r", ver=2, **{"from": "2021-01-01T00:00:00Z"}, result="new"),
    ]
    artifact = compile_rules("2021-06-01T00:00:00Z", rules)
    frozen = copy.deepcopy(artifact)
    result = replay_history(artifact, [_record("a", "2021-06-01T00:00:00Z")])
    assert result["results"][0]["decision"] == "new"
    assert artifact == frozen


def test_inputs_are_never_mutated():
    rules = [_rule(id="r", ver=1, when={"x": True})]
    records = [_record("a", facts={"x": True}), _record("b", "bad")]
    frozen_rules = copy.deepcopy(rules)
    frozen_records = copy.deepcopy(records)
    replay_history(rules, records, "2021-01-01T00:00:00Z")
    assert rules == frozen_rules
    assert records == frozen_records


def test_results_do_not_share_mutable_containers_with_inputs():
    when = {"x": True}
    rules = [_rule(id="r", ver=1, when=when)]
    result = replay_history(rules, [_record("a", facts={"x": True})])
    result["results"][0]["explanation"]["basis"]["when"]["x"] = False
    assert when == {"x": True}


# ---------------------------------------------------------------------------
# HTTP endpoint
# ---------------------------------------------------------------------------


def _payload(**overrides):
    payload = {"policy": [_rule()], "records": [_record("a")]}
    payload.update(overrides)
    return payload


def test_http_replay_success_without_cutoff():
    response = client.post("/history/replay", json=_payload())
    assert response.status_code == 200
    data = response.json()
    assert data["cutoff"] is None
    assert data["results"][0]["decision"] == "allow"


def test_http_replay_success_with_cutoff():
    response = client.post(
        "/history/replay", json=_payload(cutoff="2021-01-01T00:00:00Z")
    )
    assert response.status_code == 200
    assert response.json()["cutoff"] == "2021-01-01T00:00:00Z"


def test_http_replay_per_record_errors_are_200():
    response = client.post(
        "/history/replay", json=_payload(records=[_record("a", "bad")])
    )
    assert response.status_code == 200
    assert response.json()["results"][0]["error"]["code"] == "INVALID_TIMESTAMP"


def test_http_replay_batch_errors_are_422():
    bodies = [
        _payload(records={"not": "a list"}),
        _payload(records=[_record("d"), _record("d")]),
        _payload(policy=None),
        _payload(cutoff="not-a-time"),
    ]
    for body in bodies:
        response = client.post("/history/replay", json=body)
        assert response.status_code == 422, body
        assert response.json() == {"detail": "invalid request"}


def test_http_replay_rejects_bad_envelopes():
    for raw in (
        b"not json",
        b"[]",
        b"{}",
        b'{"policy":[],"records":[],"extra":1}',
    ):
        response = client.post(
            "/history/replay",
            content=raw,
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 422, raw
        assert response.json() == {"detail": "invalid request"}


def test_http_replay_response_is_compact_utf8_without_trailing_newline():
    response = client.post(
        "/history/replay",
        json=_payload(policy=[_rule(result="允许")]),
    )
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw
    assert "允许" in raw and "\\u" not in raw


def test_http_replay_does_not_touch_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def record(self, *args, **kwargs):
            raise AssertionError("POST /history/replay must not write history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post("/history/replay", json=_payload())
    assert response.status_code == 200
