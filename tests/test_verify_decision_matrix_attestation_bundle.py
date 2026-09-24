import copy
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    verify_decision_matrix_attestation_bundle,
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


def _bundle():
    return decision_matrix_attestation_bundle(
        [
            {"id": "b", "report": _report_b()},
            {"id": "a", "report": _report_a()},
            {"id": "é", "report": _report_a()},
        ]
    )


def _expected(bundle, ids=None):
    if ids is None:
        ids = [member["id"] for member in bundle["reports"]]
    return {"root": bundle["root"], "report_ids": ids}


def _member_digest(previous, item_id, report):
    payload = json.dumps(
        {"id": item_id, "report": report},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(
        previous.encode("ascii") + payload.encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------- genuine


def test_verifies_genuine_bundle():
    bundle = _bundle()
    assert verify_decision_matrix_attestation_bundle(bundle, _expected(bundle)) is True


def test_expected_report_id_order_is_arbitrary():
    bundle = _bundle()
    assert verify_decision_matrix_attestation_bundle(
        bundle, _expected(bundle, ids=["é", "a", "b"])
    ) is True


def test_does_not_mutate_inputs():
    bundle = _bundle()
    expected = _expected(bundle, ids=["é", "b", "a"])
    bundle_before = copy.deepcopy(bundle)
    expected_before = copy.deepcopy(expected)
    verify_decision_matrix_attestation_bundle(bundle, expected)
    assert bundle == bundle_before
    assert expected == expected_before


# ------------------------------------------------------------- false -> bool


def test_tampered_member_digest_returns_false():
    bundle = _bundle()
    bundle["reports"][1]["digest"] = "f" * 64
    assert verify_decision_matrix_attestation_bundle(bundle, _expected(bundle)) is False


def test_wrong_previous_link_returns_false():
    bundle = _bundle()
    bundle["reports"][1]["previous"] = "f" * 64
    assert verify_decision_matrix_attestation_bundle(bundle, _expected(bundle)) is False


def test_bundle_root_mismatch_returns_false():
    bundle = _bundle()
    bundle["root"] = "f" * 64
    assert verify_decision_matrix_attestation_bundle(bundle, _expected(bundle)) is False


def test_false_sub_report_digest_returns_false():
    bundle = _bundle()
    bundle["reports"][0]["report"]["digest"] = "f" * 64
    assert verify_decision_matrix_attestation_bundle(bundle, _expected(bundle)) is False


def test_broken_embedded_policy_chain_returns_false():
    bundle = _bundle()
    point = bundle["reports"][0]["report"]["policy"]["points"][-1]
    point["digest"] = "f" * 64
    # The structure still validates; only the recomputed chain disagrees.
    assert verify_decision_matrix_attestation_bundle(bundle, _expected(bundle)) is False


def test_semantic_forgery_in_sub_report_raises_value_error():
    bundle = _bundle()
    # Changing an embedded decision breaks agreement with the rebuilt matrix;
    # that is a single-report semantic violation, so it raises rather than
    # returning False.
    bundle["reports"][0]["report"]["matrix"]["points"][0]["cases"][0][
        "decision"
    ] = "forged"
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, _expected(bundle))


def test_deleted_member_returns_false():
    bundle = _bundle()
    del bundle["reports"][1]
    # Reordering survivors still leaves the declared root unsupported.
    assert verify_decision_matrix_attestation_bundle(bundle, _expected(bundle)) is False


def test_recomputed_root_after_tampering_does_not_match_expected():
    bundle = _bundle()
    members = bundle["reports"]
    members[0]["report"]["digest"] = "e" * 64  # format-valid but false digest
    # Rebuild member chain over the (false-digest) reports to make root internally consistent.
    previous = GENESIS
    for member in members:
        member["previous"] = previous
        member["digest"] = _member_digest(previous, member["id"], member["report"])
        previous = member["digest"]
    bundle["root"] = previous
    expected = _expected(bundle)
    expected["root"] = _bundle()["root"]
    assert verify_decision_matrix_attestation_bundle(bundle, expected) is False


def test_expected_root_mismatch_returns_false():
    bundle = _bundle()
    expected = _expected(bundle)
    expected["root"] = "f" * 64
    assert verify_decision_matrix_attestation_bundle(bundle, expected) is False


def test_expected_report_id_set_mismatch_returns_false():
    bundle = _bundle()
    assert verify_decision_matrix_attestation_bundle(
        bundle, _expected(bundle, ids=["a", "b"])
    ) is False
    assert verify_decision_matrix_attestation_bundle(
        bundle, _expected(bundle, ids=["a", "b", "é", "c"])
    ) is False
    assert verify_decision_matrix_attestation_bundle(
        bundle, _expected(bundle, ids=["a", "b", "c"])
    ) is False


# ------------------------------------------------------------- invalid shape


def test_reordered_members_raise_value_error():
    bundle = _bundle()
    bundle["reports"].reverse()
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, _expected(bundle))


def test_duplicate_member_id_raises_value_error():
    bundle = _bundle()
    bundle["reports"][1] = copy.deepcopy(bundle["reports"][0])
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, _expected(bundle))


@pytest.mark.parametrize(
    "report",
    [
        None,
        [],
        "x",
        {},
        {"root": "0" * 64},
        {"reports": []},
        {"root": "0" * 64, "reports": [], "extra": 1},
        {"root": "F" * 64, "reports": []},
    ],
)
def test_bad_report_shape_raises_value_error(report):
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(report, {"root": "0" * 64,
                                                           "report_ids": ["a"]})


def test_empty_reports_raises_value_error():
    bundle = _bundle()
    bundle["reports"] = []
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, _expected(bundle))


def test_bad_member_shape_raises_value_error():
    bundle = _bundle()
    member = bundle["reports"][0]
    original = copy.deepcopy(member)
    del member["digest"]
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, _expected(bundle))
    bundle["reports"][0] = copy.deepcopy(original)
    member = bundle["reports"][0]
    member["id"] = ""
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, _expected(bundle))
    bundle["reports"][0] = copy.deepcopy(original)
    member = bundle["reports"][0]
    member["previous"] = "g" * 64
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, _expected(bundle))


def test_structurally_invalid_sub_report_raises_value_error():
    bundle = _bundle()
    bundle["reports"][0]["report"] = {"start": START}
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, _expected(bundle))


@pytest.mark.parametrize(
    "expected",
    [
        None,
        [],
        {},
        {"root": "0" * 64},
        {"report_ids": ["a"]},
        {"root": "0" * 64, "report_ids": ["a"], "extra": 1},
        {"root": "x", "report_ids": ["a"]},
        {"root": "0" * 64, "report_ids": []},
        {"root": "0" * 64, "report_ids": "a"},
        {"root": "0" * 64, "report_ids": ["a", "a"]},
        {"root": "0" * 64, "report_ids": ["a", ""]},
        {"root": "0" * 64, "report_ids": ["a", 1]},
    ],
)
def test_bad_expected_shape_raises_value_error(expected):
    bundle = _bundle()
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, expected)


def test_structure_validated_before_value_comparison():
    # Invalid report raises even if summary fields happen to line up.
    bundle = _bundle()
    bundle["reports"] = []
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, _expected(bundle))
    # Invalid expected raises regardless of a matching report.
    good = _bundle()
    expected = _expected(good)
    expected["report_ids"] = []
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(good, expected)


# ---------------------------------------------------------------- endpoint


def test_http_valid_bundle_is_200_compact_json():
    bundle = _bundle()
    response = client.post(
        "/decision-matrix/attest/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_tampered_bundle_is_200_false():
    bundle = _bundle()
    bundle["reports"][0]["digest"] = "f" * 64
    response = client.post(
        "/decision-matrix/attest/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": False}


def test_http_works_without_history(monkeypatch):
    import regulation_policy_compiler.app as app_module

    class ExplodingHistory:
        def __getattr__(self, name):
            raise AssertionError("verify endpoint must not use history")

    monkeypatch.setattr(app_module, "H", ExplodingHistory())
    bundle = _bundle()
    response = client.post(
        "/decision-matrix/attest/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b'"x"',
        b"null",
        b"{}",
        b'{"report": {}}',
        b'{"report": {}, "expected": {}, "extra": 1}',
    ],
)
def test_http_bad_body_is_422(body):
    response = client.post(
        "/decision-matrix/attest/bundle/verify",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_value_error_in_function_is_422():
    bundle = _bundle()
    bundle["reports"] = []
    response = client.post(
        "/decision-matrix/attest/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle)},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'
