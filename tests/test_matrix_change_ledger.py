import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_matrix_attestation,
    matrix_change_ledger,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
STOP = "2021-03-01T00:00:00Z"
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
        _rule(id="b", priority=1, **{"from": MID, "to": STOP}, result="deny"),
    ]


def _report(cases, rules=None, start=START, end=END):
    return decision_matrix_attestation(start, end, cases, rules or _changing_rules())


# ---------------------------------------------------------------- function


def test_top_level_key_order_and_binding():
    report = _report([{"id": "a", "facts": {"x": True}}, {"id": "b", "facts": {}}])
    ledger = matrix_change_ledger(report)
    assert list(ledger) == ["start", "end", "source", "transitions", "digest"]
    assert ledger["start"] == START
    assert ledger["end"] == END
    assert ledger["source"] == report["digest"]
    assert isinstance(ledger["digest"], str) and len(ledger["digest"]) == 64


def test_transitions_follow_retention_points_skipping_first():
    report = _report([{"id": "a", "facts": {"x": True}}, {"id": "b", "facts": {}}])
    ats = [point["at"] for point in report["matrix"]["points"]]
    ledger = matrix_change_ledger(report)
    assert [(t["from"], t["to"]) for t in ledger["transitions"]] == list(
        zip(ats, ats[1:])
    )
    assert all(
        list(transition) == ["from", "to", "policy", "cases"]
        for transition in ledger["transitions"]
    )


def test_policy_matches_policy_delta_rebuilt_from_schedule_snapshots():
    report = _report([{"id": "b", "facts": {}}])
    ledger = matrix_change_ledger(report)
    snapshots = {point["at"]: point for point in report["policy"]["points"]}
    for transition in ledger["transitions"]:
        before = snapshots[transition["from"]]
        after = snapshots[transition["to"]]
        assert transition["policy"]["from"] == transition["from"]
        assert transition["policy"]["to"] == transition["to"]
        # The schedule credential already stores exactly this adjacent delta;
        # rebuilding from endpoint snapshots must reproduce it byte-for-byte.
        assert transition["policy"] == after["delta"]
        assert list(transition["policy"]) == ["from", "to", "rules", "conflicts"]
        assert before is not after


def test_cases_only_list_changes_in_canonical_case_order_with_full_snapshots():
    cases = [
        {"id": "c2", "facts": {}},
        {"id": "c1", "facts": {"x": True}},
    ]
    report = _report(cases)
    points = report["matrix"]["points"]
    ledger = matrix_change_ledger(report)
    for transition, previous_point, current_point in zip(
        ledger["transitions"], points, points[1:]
    ):
        expected_ids = current_point["changes"]
        assert [case["id"] for case in transition["cases"]] == expected_ids
        previous_by_id = {entry["id"]: entry for entry in previous_point["cases"]}
        current_by_id = {entry["id"]: entry for entry in current_point["cases"]}
        for item in transition["cases"]:
            assert list(item) == ["id", "changes", "before", "after"]
            before_entry = previous_by_id[item["id"]]
            after_entry = current_by_id[item["id"]]
            assert item["changes"] == [
                field
                for field in ("decision", "trace", "basis", "conflicts")
                if before_entry[field] != after_entry[field]
            ]
            assert item["before"] == {
                "at": previous_point["at"],
                "decision": before_entry["decision"],
                "trace": before_entry["trace"],
                "basis": before_entry["basis"],
                "conflicts": before_entry["conflicts"],
            }
            assert item["after"] == {
                "at": current_point["at"],
                "decision": after_entry["decision"],
                "trace": after_entry["trace"],
                "basis": after_entry["basis"],
                "conflicts": after_entry["conflicts"],
            }
            assert list(item["before"]) == [
                "at",
                "decision",
                "trace",
                "basis",
                "conflicts",
            ]
        # Unchanged cases are not listed; listed ids equal the changed set.
        changed = {
            entry["id"]
            for entry in current_point["cases"]
            if any(
                previous_by_id[entry["id"]][field] != entry[field]
                for field in ("decision", "trace", "basis", "conflicts")
            )
        }
        assert {item["id"] for item in transition["cases"]} == changed


def test_empty_cases_yield_empty_transitions_but_still_digest():
    report = _report([])
    ledger = matrix_change_ledger(report)
    assert ledger["transitions"] == []
    assert ledger["source"] == report["digest"]
    payload = {
        key: ledger[key] for key in ("start", "end", "source", "transitions")
    }
    expected = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert ledger["digest"] == expected


def test_digest_covers_first_four_fields_in_key_order():
    report = _report([{"id": "c", "facts": {}}])
    ledger = matrix_change_ledger(report)
    payload = {
        "start": ledger["start"],
        "end": ledger["end"],
        "source": ledger["source"],
        "transitions": ledger["transitions"],
    }
    expected = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert ledger["digest"] == expected
    assert ledger["digest"] == ledger["digest"].lower()


def test_equal_reports_regardless_of_dict_order_are_byte_identical():
    cases = [{"id": "c", "facts": {}}]
    first = _report(cases)
    shuffled = {key: first[key] for key in reversed(list(first))}
    first_ledger = json.dumps(
        matrix_change_ledger(first), ensure_ascii=False, separators=(",", ":")
    )
    shuffled_ledger = json.dumps(
        matrix_change_ledger(shuffled),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    assert first_ledger == shuffled_ledger
    assert matrix_change_ledger(first) == matrix_change_ledger(copy.deepcopy(first))


def test_layers_are_independent_deep_copies_and_input_is_not_mutated():
    report = _report([{"id": "b", "facts": {}}, {"id": "a", "facts": {"x": True}}])
    snapshot = copy.deepcopy(report)
    ledger = matrix_change_ledger(report)
    ledger["source"] = "x"
    ledger["transitions"][0]["from"] = "mutated"
    ledger["transitions"][0]["policy"]["rules"].reverse()
    ledger["transitions"][0]["cases"][0]["before"]["decision"] = "mutated"
    assert report == snapshot
    # Repeated equal calls are unaffected by the mutated prior result.
    again = matrix_change_ledger(copy.deepcopy(snapshot))
    fresh = matrix_change_ledger(copy.deepcopy(snapshot))
    assert again == fresh
    again["transitions"][0]["to"] = "mutated"
    assert fresh["transitions"][0]["to"] != "mutated"


def test_invalid_reports_raise_value_error():
    valid = _report([{"id": "c", "facts": {}}])
    bad_reports = [
        None,
        [],
        "x",
        42,
        {},
        {"a": 1},
        {key: valid[key] for key in ("start", "end", "cases", "matrix", "policy")},
    ]
    tampered_digest = copy.deepcopy(valid)
    tampered_digest["digest"] = "0" * 64
    bad_reports.append(tampered_digest)
    tampered_root = copy.deepcopy(valid)
    tampered_root["policy"]["root"] = "0" * 64
    bad_reports.append(tampered_root)
    tampered_chain = copy.deepcopy(valid)
    tampered_chain["policy"]["points"][-1]["digest"] = "f" * 64
    bad_reports.append(tampered_chain)
    tampered_matrix = copy.deepcopy(valid)
    tampered_matrix["matrix"]["points"][0]["changes"] = ["c"]
    bad_reports.append(tampered_matrix)
    tampered_case = copy.deepcopy(valid)
    tampered_case["matrix"]["points"][0]["cases"][0]["decision"] = "forged"
    bad_reports.append(tampered_case)
    for bad in bad_reports:
        with pytest.raises(ValueError):
            matrix_change_ledger(bad)


def test_does_not_mutate_invalid_input():
    valid = _report([{"id": "c", "facts": {}}])
    bad = copy.deepcopy(valid)
    bad["digest"] = "0" * 64
    snapshot = copy.deepcopy(bad)
    with pytest.raises(ValueError):
        matrix_change_ledger(bad)
    assert bad == snapshot


# ---------------------------------------------------------------- endpoint


def test_http_ledger_returns_200_compact_unescaped_json_without_newline():
    report = _report([{"id": "a", "facts": {"x": True}}, {"id": "b", "facts": {}}])
    response = client.post("/decision-matrix/ledger", json={"report": report})
    assert response.status_code == 200
    ledger = response.json()
    assert list(ledger) == ["start", "end", "source", "transitions", "digest"]
    expected = json.dumps(
        ledger, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert response.content == expected
    assert not response.content.endswith(b"\n")


def test_http_ledger_non_ascii_is_not_escaped():
    rules = [_rule(result="允许")]
    report = decision_matrix_attestation(
        START,
        MID,
        [
            {"id": "c", "facts": {}},
        ],
        rules
        + [
            _rule(
                id="z",
                ver=1,
                priority=9,
                **{"from": MID},
                when=None,
                result="拒绝",
            )
        ],
    )
    response = client.post("/decision-matrix/ledger", json={"report": report})
    assert response.status_code == 200
    text = response.content.decode("utf-8")
    assert "允许" in text or "拒绝" in text
    assert "\\u" not in text


def test_http_ledger_empty_cases():
    report = decision_matrix_attestation(START, END, [], _changing_rules())
    response = client.post("/decision-matrix/ledger", json={"report": report})
    assert response.status_code == 200
    assert response.json()["transitions"] == []


def test_http_bad_body_is_422():
    bodies = [
        b"{not json",
        b"[]",
        b"null",
        b'"x"',
        b"42",
        b"{}",
        b'{"report": null}',
        b'{"report": 1}',
        b'{"report": []}',
        b'{"report": {}, "extra": 1}',
    ]
    valid = _report([{"id": "c", "facts": {}}])
    bodies.append(
        json.dumps({"report": valid}).replace(valid["digest"], "0" * 64).encode()
    )
    for body in bodies:
        response = client.post(
            "/decision-matrix/ledger",
            content=body,
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 422, body
        assert response.content == b'{"detail":"invalid request"}'


def test_http_ledger_does_not_touch_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("ledger endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    report = _report([{"id": "c", "facts": {}}])
    response = client.post("/decision-matrix/ledger", json={"report": report})
    assert response.status_code == 200
