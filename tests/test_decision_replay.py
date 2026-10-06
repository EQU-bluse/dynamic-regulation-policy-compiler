import copy
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    ReplayInputError,
    compile_rules,
    replay_decisions,
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


def _record(record_id="a", at="2021-06-01T00:00:00Z", facts=None, **extra):
    record = {"id": record_id, "at": at, "facts": facts if facts is not None else {}}
    record.update(extra)
    return record


RULES = [
    _rule(id="law-a", ver=1, priority=5, result="v1-result"),
    _rule(
        id="law-a",
        ver=2,
        priority=5,
        **{"from": "2021-01-01T00:00:00Z"},
        result="v2-result",
    ),
    _rule(id="org-b", ver=1, source="org", priority=9, result="org-result"),
]


def test_basic_replay_selects_versions_by_record_time():
    records = [
        _record("old", "2020-06-01T00:00:00Z"),
        _record("new", "2021-06-01T00:00:00Z"),
    ]
    result = replay_decisions(records, rules=RULES)
    assert list(result) == ["cutoff", "results"]
    assert result["cutoff"] is None
    assert [entry["id"] for entry in result["results"]] == ["old", "new"]
    old, new = result["results"]
    assert old["status"] == "ok"
    assert old["at"] == "2020-06-01T00:00:00Z"
    assert old["law"] == ["law-a@1"]
    assert old["org"] == ["org-b@1"]
    assert old["decision"] == "v1-result"
    assert new["law"] == ["law-a@2"]
    assert new["decision"] == "v2-result"
    for entry in (old, new):
        assert list(entry) == [
            "id",
            "at",
            "status",
            "law",
            "org",
            "decision",
            "explanation",
        ]
        assert list(entry["explanation"]) == ["candidates", "conflicts", "hit"]


def test_from_is_inclusive_and_to_is_exclusive():
    rules = [
        _rule(
            id="r",
            ver=1,
            **{
                "from": "2021-01-01T00:00:00Z",
                "to": "2021-06-01T00:00:00Z",
            },
        )
    ]
    inside = replay_decisions([_record(at="2021-01-01T00:00:00Z")], rules=rules)
    assert inside["results"][0]["status"] == "ok"
    boundary = replay_decisions([_record(at="2021-06-01T00:00:00Z")], rules=rules)
    assert boundary["results"][0]["error"]["code"] == "VERSION_NOT_FOUND"


def test_cutoff_hides_later_versions_but_keeps_record_time_selection():
    # ver 2 takes effect after the cutoff: it must not participate, so the
    # record falls back to ver 1 even though ver 2 is effective at the
    # record's occurrence time.
    cutoff = "2020-12-31T23:59:59Z"
    result = replay_decisions(
        [_record(at="2021-06-01T00:00:00Z")], rules=RULES, cutoff=cutoff
    )
    entry = result["results"][0]
    assert result["cutoff"] == cutoff
    assert entry["status"] == "ok"
    assert entry["law"] == ["law-a@1"]
    assert entry["decision"] == "v1-result"


def test_cutoff_at_version_start_makes_it_visible():
    result = replay_decisions(
        [_record(at="2021-06-01T00:00:00Z")],
        rules=RULES,
        cutoff="2021-01-01T00:00:00Z",
    )
    assert result["results"][0]["law"] == ["law-a@2"]


def test_cutoff_can_produce_version_not_found():
    result = replay_decisions(
        [_record(at="2021-06-01T00:00:00Z")],
        rules=RULES,
        cutoff="2019-01-01T00:00:00Z",
    )
    entry = result["results"][0]
    assert entry["status"] == "error"
    assert entry["error"]["code"] == "VERSION_NOT_FOUND"
    assert entry["error"]["details"] == {
        "at": "2021-06-01T00:00:00Z",
        "cutoff": "2019-01-01T00:00:00Z",
    }


def test_timezone_offsets_naming_the_same_instant_select_the_same_versions():
    records = [
        _record("zulu", "2021-06-01T00:00:00Z"),
        _record("cst", "2021-06-01T08:00:00+08:00"),
        _record("pst", "2021-05-31T17:00:00-07:00"),
    ]
    result = replay_decisions(records, rules=RULES)
    outcomes = [
        (entry["at"], entry["law"], entry["decision"]) for entry in result["results"]
    ]
    assert outcomes == [("2021-06-01T00:00:00Z", ["law-a@2"], "v2-result")] * 3


def test_fractional_seconds_are_truncated():
    result = replay_decisions([_record(at="2021-06-01T00:00:00.999Z")], rules=RULES)
    assert result["results"][0]["at"] == "2021-06-01T00:00:00Z"


def test_empty_batch_returns_empty_results():
    assert replay_decisions([], rules=RULES) == {"cutoff": None, "results": []}
    assert replay_decisions([], rules=RULES, cutoff="2021-01-01T00:00:00Z") == {
        "cutoff": "2021-01-01T00:00:00Z",
        "results": [],
    }


def test_repeated_calls_and_record_permutation():
    records = [
        _record("a", "2020-06-01T00:00:00Z"),
        _record("b", "2021-06-01T00:00:00Z"),
        _record("c", "2019-06-01T00:00:00Z"),
    ]
    first = replay_decisions(records, rules=RULES, cutoff="2022-01-01T00:00:00Z")
    second = replay_decisions(
        copy.deepcopy(records), rules=copy.deepcopy(RULES), cutoff="2022-01-01T00:00:00Z"
    )
    assert json.dumps(first, ensure_ascii=False, sort_keys=True) == json.dumps(
        second, ensure_ascii=False, sort_keys=True
    )
    shuffled = replay_decisions(
        [records[2], records[0], records[1]], rules=RULES, cutoff="2022-01-01T00:00:00Z"
    )
    by_id = {entry["id"]: entry for entry in first["results"]}
    for entry in shuffled["results"]:
        assert entry == by_id[entry["id"]]
    assert [entry["id"] for entry in shuffled["results"]] == ["c", "a", "b"]


def test_explanation_reports_candidates_reasons_comparisons_and_hit():
    rules = [
        _rule(id="top", priority=9, when={"x": True}, result="top-result"),
        _rule(id="mid", priority=5, result="mid-result"),
        _rule(id="low", priority=1, when={"y": False}, result="low-result"),
    ]
    facts = {"x": True, "y": True}
    result = replay_decisions([_record(facts=facts)], rules=rules)
    entry = result["results"][0]
    assert entry["decision"] == "top-result"
    explanation = entry["explanation"]
    assert explanation["hit"]["id"] == "top"
    reasons = [candidate["reason"] for candidate in explanation["candidates"]]
    assert reasons == ["hit", "outranked", "unmatched"]
    low = explanation["candidates"][2]
    assert low["matched"] is False
    assert low["unmet"] == {"y": False}
    assert explanation["conflicts"] == [
        {"winner": ["law", "top", 1], "loser": ["law", "mid", 1]},
        {"winner": ["law", "top", 1], "loser": ["law", "low", 1]},
    ]


def test_no_match_is_a_successful_null_decision():
    rules = [_rule(id="cond", when={"x": True})]
    result = replay_decisions([_record(facts={"x": False})], rules=rules)
    entry = result["results"][0]
    assert entry["status"] == "ok"
    assert entry["decision"] is None
    assert entry["explanation"]["hit"] is None
    assert entry["explanation"]["conflicts"] == []
    assert entry["explanation"]["candidates"][0]["reason"] == "unmatched"


def test_invalid_timestamp_fails_only_its_own_position():
    records = [
        _record("good-1", "2021-06-01T00:00:00Z"),
        _record("bad", "not-a-time"),
        _record("naive", "2021-06-01T00:00:00"),
        _record("good-2", "2020-06-01T00:00:00Z"),
    ]
    result = replay_decisions(records, rules=RULES)
    statuses = [entry["status"] for entry in result["results"]]
    assert statuses == ["ok", "error", "error", "ok"]
    for index in (1, 2):
        entry = result["results"][index]
        assert list(entry) == ["id", "at", "status", "error"]
        assert entry["at"] is None
        assert entry["error"]["code"] == "INVALID_TIMESTAMP"
        assert entry["error"]["details"]["field"] == "at"
        assert "decision" not in entry
    assert result["results"][0]["decision"] == "v2-result"
    assert result["results"][3]["decision"] == "v1-result"


def test_missing_fact_lists_required_fields_sorted():
    rules = [
        _rule(id="needs", when={"b": True, "a": False}, priority=5),
        _rule(id="also", when={"c": True}, priority=1),
    ]
    result = replay_decisions([_record(facts={"a": False})], rules=rules)
    entry = result["results"][0]
    assert entry["status"] == "error"
    assert entry["error"]["code"] == "MISSING_FACT"
    assert entry["error"]["details"] == {"fields": ["b", "c"]}
    assert "b" in entry["error"]["message"] and "c" in entry["error"]["message"]


def test_compiled_artifact_is_accepted_as_policy_input():
    compiled = compile_rules("2021-06-01T00:00:00Z", RULES)
    snapshot = copy.deepcopy(compiled)
    result = replay_decisions([_record(at="2021-06-01T00:00:00Z")], compiled=compiled)
    entry = result["results"][0]
    assert entry["status"] == "ok"
    assert entry["law"] == ["law-a@2"]
    assert entry["org"] == ["org-b@1"]
    assert entry["decision"] == "v2-result"
    assert compiled == snapshot


def test_compiled_artifact_respects_record_time_and_cutoff():
    compiled = compile_rules("2021-06-01T00:00:00Z", RULES)
    # A record before the artifact's versions took effect finds nothing.
    early = replay_decisions([_record(at="2019-06-01T00:00:00Z")], compiled=compiled)
    assert early["results"][0]["error"]["code"] == "VERSION_NOT_FOUND"
    # A cutoff before ver 2's start hides it even in the compiled pool; the
    # older org rule stays visible and decides alone.
    hidden = replay_decisions(
        [_record(at="2021-06-01T00:00:00Z")],
        compiled=compiled,
        cutoff="2020-06-01T00:00:00Z",
    )
    entry = hidden["results"][0]
    assert entry["status"] == "ok"
    assert entry["law"] == []
    assert entry["org"] == ["org-b@1"]
    assert entry["decision"] == "org-result"


def test_unresolved_conflict_from_twin_versions_in_compiled_artifact():
    compiled = {
        "at": "2021-01-01T00:00:00Z",
        "rules": [
            _rule(id="twin", ver=1, result="allow"),
            _rule(id="twin", ver=1, result="deny"),
        ],
        "conflicts": [],
    }
    result = replay_decisions([_record(at="2021-06-01T00:00:00Z")], compiled=compiled)
    entry = result["results"][0]
    assert entry["status"] == "error"
    assert entry["error"]["code"] == "UNRESOLVED_CONFLICT"
    assert entry["error"]["details"] == {
        "candidates": [["law", "twin", 1], ["law", "twin", 1]]
    }
    assert "decision" not in entry


def test_twin_versions_with_equal_results_are_not_a_conflict():
    compiled = {
        "at": "2021-01-01T00:00:00Z",
        "rules": [
            _rule(id="twin", ver=1, result="allow"),
            _rule(id="twin", ver=1, result="allow"),
        ],
        "conflicts": [],
    }
    result = replay_decisions([_record(at="2021-06-01T00:00:00Z")], compiled=compiled)
    assert result["results"][0]["decision"] == "allow"


def test_batch_level_errors_raise_replay_input_error():
    with pytest.raises(ReplayInputError):
        replay_decisions("not-an-array", rules=RULES)
    with pytest.raises(ReplayInputError):
        replay_decisions([_record("dup"), _record("dup")], rules=RULES)
    with pytest.raises(ReplayInputError):
        replay_decisions([_record("a")])
    with pytest.raises(ReplayInputError):
        replay_decisions([_record("a")], rules=RULES, compiled=compile_rules("2021-06-01T00:00:00Z", RULES))
    with pytest.raises(ReplayInputError):
        replay_decisions([_record("a")], rules=RULES, cutoff="not-a-time")
    with pytest.raises(ReplayInputError):
        replay_decisions([_record("a")], rules=RULES, cutoff="2021-06-01T00:00:00")
    with pytest.raises(ReplayInputError):
        replay_decisions([{"id": "a", "facts": {}}], rules=RULES)
    with pytest.raises(ReplayInputError):
        replay_decisions([_record("a", facts={"x": 1})], rules=RULES)
    with pytest.raises(ReplayInputError):
        replay_decisions([_record("")], rules=RULES)
    # ReplayInputError stays compatible with the ValueError boundary.
    with pytest.raises(ValueError):
        replay_decisions("not-an-array", rules=RULES)


def test_invalid_rules_keep_value_error_semantics():
    with pytest.raises(ValueError):
        replay_decisions([_record("a")], rules=[_rule(ver=0)])
    with pytest.raises(ValueError):
        replay_decisions([_record("a")], compiled={"at": "bad", "rules": [], "conflicts": []})


def test_inputs_are_not_mutated():
    rules = copy.deepcopy(RULES)
    rules_snapshot = copy.deepcopy(rules)
    records = [
        _record("bad", "nope"),
        _record("ok", "2021-06-01T08:00:00+08:00", facts={"z": True}),
    ]
    records_snapshot = copy.deepcopy(records)
    replay_decisions(records, rules=rules, cutoff="2022-01-01T00:00:00Z")
    assert rules == rules_snapshot
    assert records == records_snapshot


def test_results_do_not_share_containers_with_inputs():
    when = {"x": True}
    rules = [_rule(id="cond", when=when)]
    records = [_record("a", facts={"x": True})]
    result = replay_decisions(records, rules=rules)
    result["results"][0]["explanation"]["hit"]["when"]["x"] = False
    result["results"][0]["explanation"]["candidates"][0]["rule"]["when"].clear()
    assert when == {"x": True}
    assert rules[0]["when"] == {"x": True}


def test_error_entries_carry_no_time_or_environment_markers():
    result = replay_decisions(
        [_record("bad", "nope"), _record("missing", "2019-01-01T00:00:00Z")],
        rules=RULES,
    )
    text = json.dumps(result)
    for marker in ("now", "uuid", "pid", "hostname"):
        assert marker not in text


def _payload(**overrides):
    payload = {"records": [_record("a")], "rules": RULES}
    payload.update(overrides)
    return payload


def test_http_endpoint_success_and_key_order():
    response = client.post("/decision-replay", json=_payload())
    assert response.status_code == 200
    data = response.json()
    assert list(data) == ["cutoff", "results"]
    assert data["results"][0]["decision"] == "v2-result"
    raw = response.content.decode("utf-8")
    assert not raw.endswith("\n")
    assert ", " not in raw and '": ' not in raw


def test_http_endpoint_with_compiled_and_cutoff():
    compiled = compile_rules("2021-06-01T00:00:00Z", RULES)
    response = client.post(
        "/decision-replay",
        json={
            "records": [_record("a", "2021-06-01T08:00:00+08:00")],
            "compiled": compiled,
            "cutoff": "2021-06-01T00:00:00Z",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["cutoff"] == "2021-06-01T00:00:00Z"
    assert data["results"][0]["at"] == "2021-06-01T00:00:00Z"
    assert data["results"][0]["decision"] == "v2-result"


def test_http_endpoint_rejects_invalid_requests():
    bad_bodies = [
        b"not json",
        b"[]",
        b"{}",
        json.dumps({"records": [], "extra": 1}).encode(),
        json.dumps({"rules": RULES}).encode(),
        json.dumps(_payload(records="nope")).encode(),
        json.dumps(_payload(records=[_record("d"), _record("d")])).encode(),
        json.dumps({"records": [_record("a")]}).encode(),
        json.dumps(_payload(cutoff="2021-06-01")).encode(),
        json.dumps(_payload(rules=[_rule(ver=0)])).encode(),
    ]
    for raw in bad_bodies:
        response = client.post(
            "/decision-replay", content=raw, headers={"content-type": "application/json"}
        )
        assert response.status_code == 422, raw
        assert response.json() == {"detail": "invalid request"}


def test_http_endpoint_does_not_touch_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def record(self, *args, **kwargs):
            raise AssertionError("POST /decision-replay must not write history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post("/decision-replay", json=_payload())
    assert response.status_code == 200
