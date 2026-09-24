import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"
GENESIS = "0" * 64


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
        _rule(id="a", priority=5, **{"from": START}, when={"x": True}, result="允许"),
        _rule(
            id="b",
            priority=1,
            **{"from": MID, "to": "2021-03-01T00:00:00Z"},
            result="deny",
        ),
    ]


def _report_a():
    return decision_matrix_attestation(
        START, END, [{"id": "c1", "facts": {"x": True}}], _changing_rules()
    )


def _report_b():
    return decision_matrix_attestation(
        START, END, [{"id": "c2", "facts": {}}], [_rule(result="z")]
    )


def _items():
    return [
        {"id": "b", "report": _report_b()},
        {"id": "é", "report": _report_a()},
        {"id": "a", "report": _report_a()},
    ]


def _bundle():
    return decision_matrix_attestation_bundle(_items())


# ---------------------------------------------------------------- structure


def test_top_level_and_member_key_order():
    bundle = _bundle()
    assert list(bundle) == ["root", "reports"]
    assert [list(member) for member in bundle["reports"]] == [
        ["id", "report", "previous", "digest"]
    ] * 3


def test_members_sorted_by_id_regardless_of_caller_order():
    bundle = _bundle()
    assert [member["id"] for member in bundle["reports"]] == ["a", "b", "é"]


def test_first_previous_is_genesis_and_later_chained():
    bundle = _bundle()
    members = bundle["reports"]
    assert members[0]["previous"] == GENESIS
    for index in range(1, len(members)):
        assert members[index]["previous"] == members[index - 1]["digest"]
    assert bundle["root"] == members[-1]["digest"]


def test_digests_are_sha256_of_previous_plus_id_report_payload():
    bundle = _bundle()
    previous = GENESIS
    for member in bundle["reports"]:
        payload = json.dumps(
            {"id": member["id"], "report": member["report"]},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        expected = hashlib.sha256(
            previous.encode("ascii") + payload.encode("utf-8")
        ).hexdigest()
        assert member["digest"] == expected
        assert len(member["digest"]) == 64
        previous = member["digest"]


def test_single_member_bundle_root_is_its_digest():
    bundle = decision_matrix_attestation_bundle([{"id": "x", "report": _report_a()}])
    assert bundle["root"] == bundle["reports"][0]["digest"]
    assert bundle["reports"][0]["previous"] == GENESIS


def test_equal_valued_inputs_are_byte_identical():
    first = _bundle()
    second = decision_matrix_attestation_bundle(
        [{"id": "a", "report": _report_a()},
         {"id": "é", "report": _report_a()},
         {"id": "b", "report": _report_b()}]
    )
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_layers_are_independent_deep_copies():
    items = _items()
    bundle = decision_matrix_attestation_bundle(items)
    bundle["reports"][0]["report"]["digest"] = "mutated"
    bundle["reports"][0]["id"] = "mutated"
    # Input untouched.
    assert items[2]["id"] == "a"
    assert items[2]["report"]["digest"] != "mutated"
    # Rebuilding is unaffected by mutating a prior result.
    assert decision_matrix_attestation_bundle(copy.deepcopy(_items())) == _bundle()


def test_does_not_mutate_inputs():
    items = _items()
    before = copy.deepcopy(items)
    decision_matrix_attestation_bundle(items)
    assert items == before


# --------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "items",
    [
        None,
        [],
        {},
        "x",
        [{"id": "a"}],
        [{"report": _report_a()}],
        [{"id": "a", "report": _report_a(), "extra": 1}],
        [{"id": "", "report": _report_a()}],
        [{"id": 1, "report": _report_a()}],
        [{"id": "a", "report": _report_a()}, {"id": "a", "report": _report_b()}],
    ],
)
def test_invalid_items_raise_value_error(items):
    with pytest.raises(ValueError):
        decision_matrix_attestation_bundle(items)


def test_structurally_invalid_member_report_raises():
    items = [{"id": "a", "report": {"start": START}}]
    with pytest.raises(ValueError):
        decision_matrix_attestation_bundle(items)


def test_member_report_with_false_digest_raises():
    report = _report_a()
    report["digest"] = "f" * 64
    with pytest.raises(ValueError):
        decision_matrix_attestation_bundle([{"id": "a", "report": report}])


def test_member_report_semantic_forgery_raises():
    report = _report_a()
    report["matrix"]["points"][0]["cases"][0]["decision"] = "forged"
    with pytest.raises(ValueError):
        decision_matrix_attestation_bundle([{"id": "a", "report": report}])


# ---------------------------------------------------------------- endpoint


def test_http_bundle_returns_200_compact_json():
    response = client.post("/decision-matrix/attest/bundle", json={"items": _items()})
    assert response.status_code == 200
    assert response.json() == _bundle()
    expected = json.dumps(
        _bundle(), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert response.content == expected
    assert not response.content.endswith(b"\n")
    assert "允许" in response.content.decode("utf-8")


def test_http_bundle_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("bundle endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/decision-matrix/attest/bundle",
        json={"items": [{"id": "a", "report": _report_a()}]},
    )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b'"x"',
        b"null",
        b"{}",
        b'{"items": []}',
        b'{"items": [], "extra": 1}',
        b'{"members": []}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        "/decision-matrix/attest/bundle",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_value_error_in_function_is_422():
    response = client.post(
        "/decision-matrix/attest/bundle",
        json={"items": [{"id": "a", "report": {"start": START}}]},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
