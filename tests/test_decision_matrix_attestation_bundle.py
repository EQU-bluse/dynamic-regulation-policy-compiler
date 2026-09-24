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
        _rule(
            id="a",
            priority=5,
            **{"from": START},
            when={"x": True},
            result="允许",
        ),
        _rule(
            id="b",
            priority=1,
            **{"from": MID, "to": "2021-03-01T00:00:00Z"},
            result="deny",
        ),
    ]


def _report(case_id="c", facts=None, rules=None, start=START, end=END):
    return decision_matrix_attestation(
        start,
        end,
        [] if case_id is None else [{"id": case_id, "facts": {} if facts is None else facts}],
        [] if rules is None else rules,
    )


def _items():
    return [
        {"id": "b", "report": _report("z", rules=[_rule(result="ok")])},
        {"id": "é", "report": _report(None, rules=[_rule()])},
        {"id": "a", "report": _report("c", {"x": True}, _changing_rules())},
    ]


# ---------------------------------------------------------------- function


def test_top_level_and_member_key_order():
    bundle = decision_matrix_attestation_bundle(_items())
    assert list(bundle) == ["root", "reports"]
    assert [member["id"] for member in bundle["reports"]] == ["a", "b", "é"]
    for member in bundle["reports"]:
        assert list(member) == ["id", "report", "previous", "digest"]
        assert list(member["report"]) == [
            "start",
            "end",
            "cases",
            "matrix",
            "policy",
            "digest",
        ]


def test_members_chain_from_genesis_and_root_closes_chain():
    bundle = decision_matrix_attestation_bundle(_items())
    members = bundle["reports"]
    assert members[0]["previous"] == GENESIS
    for index, member in enumerate(members[1:], 1):
        assert member["previous"] == members[index - 1]["digest"]
    assert bundle["root"] == members[-1]["digest"]


def test_member_digest_is_sha256_of_previous_plus_id_report_payload():
    bundle = decision_matrix_attestation_bundle(_items())
    previous = GENESIS
    for member in bundle["reports"]:
        payload = json.dumps(
            {"id": member["id"], "report": member["report"]},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        assert "\n" not in payload
        expected = hashlib.sha256(
            previous.encode("ascii") + payload.encode("utf-8")
        ).hexdigest()
        assert member["digest"] == expected
        assert len(member["digest"]) == 64
        assert member["digest"] == member["digest"].lower()
        previous = member["digest"]


def test_caller_order_does_not_change_result():
    items = _items()
    first = decision_matrix_attestation_bundle(items)
    second = decision_matrix_attestation_bundle(list(reversed(copy.deepcopy(items))))
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_unicode_code_point_ordering():
    # Capital letters sort before lowercase, which sort before accented code
    # points; ordering is by code point, not locale collation.
    items = [
        {"id": "乙", "report": _report("c1")},
        {"id": "A", "report": _report("c2")},
        {"id": "a", "report": _report("c3")},
    ]
    bundle = decision_matrix_attestation_bundle(items)
    assert [member["id"] for member in bundle["reports"]] == ["A", "a", "乙"]


def test_single_member_bundle():
    report = _report("c", {"x": True}, _changing_rules())
    bundle = decision_matrix_attestation_bundle([{"id": "only", "report": report}])
    (member,) = bundle["reports"]
    assert member["id"] == "only"
    assert member["previous"] == GENESIS
    assert member["digest"] == bundle["root"]
    assert member["report"] == report


def test_layers_are_independent_deep_copies():
    items = _items()
    bundle = decision_matrix_attestation_bundle(items)
    bundle["reports"][0]["report"]["cases"][0]["facts"]["x"] = False
    bundle["reports"][0]["digest"] = "mutated"
    # The source reports and rebuilt bundle are unaffected.
    fresh = decision_matrix_attestation_bundle(copy.deepcopy(_items()))
    assert fresh["reports"][0]["report"]["cases"][0]["facts"].get("x") is True
    assert fresh["reports"][0]["digest"] != "mutated"


def test_does_not_mutate_inputs():
    items = _items()
    before = copy.deepcopy(items)
    decision_matrix_attestation_bundle(items)
    assert items == before


def test_scrambled_report_key_order_normalizes_to_identical_bundle():
    report = _report("c", {"x": True}, _changing_rules())
    scrambled_report = dict(reversed(list(report.items())))
    scrambled_policy = dict(reversed(list(report["policy"].items())))
    scrambled_report["policy"] = scrambled_policy
    canonical = decision_matrix_attestation_bundle(
        [{"id": "a", "report": report}]
    )
    scrambled = decision_matrix_attestation_bundle(
        [{"id": "a", "report": scrambled_report}]
    )
    assert json.dumps(canonical, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        scrambled, ensure_ascii=False, separators=(",", ":")
    )


@pytest.mark.parametrize(
    "items",
    [
        [],
        "x",
        {},
        None,
        [{"id": "a"}],
        [{"report": _report("c")}],
        [{"id": "a", "report": _report("c"), "extra": 1}],
        [{"id": "", "report": _report("c")}],
        [{"id": 1, "report": _report("c")}],
        [{"id": "a", "report": _report("c")}, "not-a-dict"],
        [
            {"id": "a", "report": _report("c")},
            {"id": "a", "report": _report("d")},
        ],
        [{"id": "a", "report": "not-a-report"}],
        [{"id": "a", "report": {}}],
        [{"id": "a", "report": []}],
    ],
)
def test_invalid_items_raise_value_error(items):
    with pytest.raises(ValueError):
        decision_matrix_attestation_bundle(items)


def test_untrue_sub_credential_digest_raises_value_error():
    report = _report("c", {"x": True}, _changing_rules())
    report["digest"] = "f" * 64
    with pytest.raises(ValueError):
        decision_matrix_attestation_bundle([{"id": "a", "report": report}])


def test_broken_sub_credential_schedule_chain_raises_value_error():
    report = _report("c", rules=_changing_rules())
    assert len(report["policy"]["points"]) > 1
    report["policy"]["points"][0]["digest"] = "f" * 64
    report["policy"]["root"] = "f" * 64
    with pytest.raises(ValueError):
        decision_matrix_attestation_bundle([{"id": "a", "report": report}])


def test_semantically_forged_sub_report_raises_value_error():
    report = _report("c", {}, _changing_rules())
    report["matrix"]["points"][0]["cases"][0]["decision"] = "forged"
    with pytest.raises(ValueError):
        decision_matrix_attestation_bundle([{"id": "a", "report": report}])


# ---------------------------------------------------------------- endpoint


def test_http_bundle_is_200_compact_json():
    body = {"items": _items()}
    response = client.post("/decision-matrix/attest/bundle", json=body)
    assert response.status_code == 200
    report = response.json()
    assert list(report) == ["root", "reports"]
    canonical = json.dumps(report, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    assert response.content == canonical
    assert not response.content.endswith(b"\n")
    assert "允许" in response.content.decode("utf-8")


def test_http_endpoint_ignores_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("bundle endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    response = client.post(
        "/decision-matrix/attest/bundle",
        json={"items": [{"id": "a", "report": _report("c")}]},
    )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b"null",
        b'"x"',
        b"{}",
        b'{"items": []}',
        b'{"items": [{"id": "a", "report": {}}]}',
        b'{"items": []',
        b'{"items": [{"id": "a"}], "extra": 1}',
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
    report = _report("c")
    report["digest"] = "f" * 64
    response = client.post(
        "/decision-matrix/attest/bundle",
        json={"items": [{"id": "a", "report": report}]},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
