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


def _bundle(items=None):
    return decision_matrix_attestation_bundle(_items() if items is None else items)


def _expected(bundle, ids=None):
    return {
        "root": bundle["root"],
        "report_ids": ids
        if ids is not None
        else [member["id"] for member in bundle["reports"]],
    }


def _rehash_member(previous, member):
    payload = json.dumps(
        {"id": member["id"], "report": member["report"]},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    member["previous"] = previous
    member["digest"] = hashlib.sha256(
        previous.encode("ascii") + payload.encode("utf-8")
    ).hexdigest()
    return member["digest"]


def _rehash_bundle(bundle):
    previous = GENESIS
    for member in bundle["reports"]:
        previous = _rehash_member(previous, member)
    bundle["root"] = previous
    return bundle


# ---------------------------------------------------------------- function


def test_verifies_genuine_bundle():
    bundle = _bundle()
    assert verify_decision_matrix_attestation_bundle(
        bundle, _expected(bundle)
    ) is True


def test_single_member_bundle_verifies():
    bundle = _bundle([{"id": "a", "report": _report("c")}])
    assert verify_decision_matrix_attestation_bundle(
        bundle, _expected(bundle)
    ) is True


def test_expected_report_id_order_is_arbitrary():
    bundle = _bundle()
    assert verify_decision_matrix_attestation_bundle(
        bundle, _expected(bundle, ids=["é", "a", "b"])
    ) is True


def test_declared_root_mismatch_returns_false():
    bundle = _bundle()
    expected = _expected(bundle)
    expected["root"] = "f" * 64
    assert verify_decision_matrix_attestation_bundle(bundle, expected) is False


@pytest.mark.parametrize("ids", [["a", "b"], ["a", "b", "é", "x"], ["x", "y", "z"]])
def test_report_id_set_mismatch_returns_false(ids):
    bundle = _bundle()
    assert verify_decision_matrix_attestation_bundle(
        bundle, _expected(bundle, ids=ids)
    ) is False


def test_tampered_member_digest_returns_false():
    bundle = _bundle()
    bundle["reports"][1]["digest"] = "f" * 64
    assert verify_decision_matrix_attestation_bundle(
        bundle, _expected(bundle)
    ) is False


def test_tampered_member_previous_returns_false():
    bundle = _bundle()
    bundle["reports"][1]["previous"] = "f" * 64
    assert verify_decision_matrix_attestation_bundle(
        bundle, _expected(bundle)
    ) is False


def test_tampered_sub_credential_digest_returns_false():
    bundle = _bundle()
    bundle["reports"][0]["report"]["digest"] = "f" * 64
    # Leave the bundle links and root untouched: the untrue sub digest alone
    # must be detected.
    assert verify_decision_matrix_attestation_bundle(
        bundle, _expected(bundle)
    ) is False


def test_broken_sub_credential_schedule_chain_returns_false():
    bundle = _bundle()
    # Member "a" attests the changing rules, so its schedule has multiple
    # points and a real hash chain to break.
    target = bundle["reports"][0]["report"]
    assert len(target["policy"]["points"]) > 1
    target["policy"]["points"][0]["digest"] = "f" * 64
    target["policy"]["root"] = "f" * 64
    assert verify_decision_matrix_attestation_bundle(
        bundle, _expected(bundle)
    ) is False


def test_tampered_bundle_root_returns_false():
    bundle = _bundle()
    bundle["root"] = "f" * 64
    assert verify_decision_matrix_attestation_bundle(
        bundle, _expected(bundle)
    ) is False


def test_deleted_member_returns_false():
    bundle = _bundle()
    del bundle["reports"][1]
    # The declared root no longer matches the chain over the remainder.
    assert verify_decision_matrix_attestation_bundle(
        bundle, _expected(bundle, ids=["a", "é"])
    ) is False


def test_fully_rehashed_forgery_fails_against_authentic_expected():
    bundle = _bundle()
    authentic_root = bundle["root"]
    # Tamper with a sub-report's matrix, rehash the single credential, every
    # bundle link, and the bundle root. The semantic matrix forgery is
    # rejected structurally (ValueError) during member normalization...
    bad = copy.deepcopy(bundle)
    bad["reports"][0]["report"]["matrix"]["points"][0]["cases"][0][
        "decision"
    ] = "forged"
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bad, _expected(bad))
    # ...whereas a semantically inert content change that keeps the matrix
    # equal still cannot pass against the authentic root after rehashing.
    bad = copy.deepcopy(bundle)
    bad["reports"][0]["report"]["cases"][0]["facts"]["extra"] = False
    payload = {
        key: bad["reports"][0]["report"][key]
        for key in ("start", "end", "cases", "matrix", "policy")
    }
    bad["reports"][0]["report"]["digest"] = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    _rehash_bundle(bad)
    expected = _expected(bad)
    expected["root"] = authentic_root
    assert verify_decision_matrix_attestation_bundle(bad, expected) is False


def test_misordered_members_raise_value_error():
    bundle = _bundle()
    bundle["reports"].reverse()
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, _expected(bundle))


def test_duplicate_member_ids_raise_value_error():
    bundle = _bundle()
    bundle["reports"][1] = copy.deepcopy(bundle["reports"][0])
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, _expected(bundle))


def test_semantic_sub_report_forgery_raises_value_error():
    bundle = _bundle()
    bad = copy.deepcopy(bundle)
    bad["reports"][0]["report"]["matrix"]["points"][0]["cases"][0][
        "decision"
    ] = "forged"
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bad, _expected(bad))


def test_sub_report_with_extra_key_raises_value_error():
    bundle = _bundle()
    bundle["reports"][0]["report"]["extra"] = 1
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, _expected(bundle))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.pop("root"),
        lambda b: b.update(extra=1),
        lambda b: b.__setitem__("root", "F" * 64),
        lambda b: b.__setitem__("root", "0" * 63),
        lambda b: b.__setitem__("root", 123),
        lambda b: b.__setitem__("reports", []),
        lambda b: b.__setitem__("reports", {}),
        lambda b: b.__setitem__("reports", "x"),
    ],
)
def test_bad_report_shapes_raise_value_error(mutate):
    bundle = _bundle()
    mutate(bundle)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, _expected(_bundle()))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.pop("digest"),
        lambda m: m.update(extra=1),
        lambda m: m.__setitem__("id", ""),
        lambda m: m.__setitem__("id", 1),
        lambda m: m.__setitem__("previous", "G" * 64),
        lambda m: m.__setitem__("digest", "g" * 64),
        lambda m: m.__setitem__("report", {}),
        lambda m: m.__setitem__("report", []),
    ],
)
def test_bad_member_shapes_raise_value_error(mutate):
    bundle = _bundle()
    mutate(bundle["reports"][0])
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, _expected(bundle))


def test_non_dict_report_raises_value_error():
    expected = {"root": "f" * 64, "report_ids": ["a"]}
    for bad in ([], "x", None):
        with pytest.raises(ValueError):
            verify_decision_matrix_attestation_bundle(bad, expected)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.clear(),
        lambda e: e.update(extra=1),
        lambda e: e.pop("root"),
        lambda e: e.pop("report_ids"),
        lambda e: e.__setitem__("root", "X" * 64),
        lambda e: e.__setitem__("root", 123),
        lambda e: e.__setitem__("report_ids", []),
        lambda e: e.__setitem__("report_ids", {}),
        lambda e: e.__setitem__("report_ids", ["a", "a"]),
        lambda e: e.__setitem__("report_ids", [""]),
        lambda e: e.__setitem__("report_ids", [1]),
    ],
)
def test_bad_expected_shapes_raise_value_error(mutate):
    bundle = _bundle()
    expected = _expected(bundle)
    mutate(expected)
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bundle, expected)


def test_structure_validated_before_value_comparison():
    # Structural invalidity must raise ValueError even though root and ids
    # happen to match, and an invalid expected must raise even for a good
    # report (no short-circuiting to False).
    bundle = _bundle()
    bad_report = copy.deepcopy(bundle)
    bad_report["reports"] = []
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(bad_report, _expected(bundle))
    good = _bundle()
    bad_expected = _expected(good)
    bad_expected["report_ids"] = []
    with pytest.raises(ValueError):
        verify_decision_matrix_attestation_bundle(good, bad_expected)


def test_recomputation_ignores_input_key_order():
    bundle = _bundle()
    member = bundle["reports"][0]
    scrambled_member = {
        "digest": member["digest"],
        "previous": member["previous"],
        "report": dict(reversed(list(member["report"].items()))),
        "id": member["id"],
    }
    scrambled = copy.deepcopy(bundle)
    scrambled["reports"][0] = scrambled_member
    assert verify_decision_matrix_attestation_bundle(
        scrambled, _expected(bundle)
    ) is True


def test_does_not_mutate_inputs():
    bundle = _bundle()
    expected = _expected(bundle, ids=["é", "b", "a"])
    report_before = copy.deepcopy(bundle)
    expected_before = copy.deepcopy(expected)
    assert verify_decision_matrix_attestation_bundle(bundle, expected) is True
    assert bundle == report_before
    assert expected == expected_before


# ---------------------------------------------------------------- endpoint


def test_http_valid_bundle_is_200_compact_json(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    bundle = _bundle()
    response = client.post(
        "/decision-matrix/attest/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": True}
    assert response.content == b'{"valid":true}'
    assert not response.content.endswith(b"\n")


def test_http_tampered_bundle_is_200_false(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    bundle = _bundle()
    bundle["root"] = "f" * 64
    response = client.post(
        "/decision-matrix/attest/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle)},
    )
    assert response.status_code == 200
    assert response.json() == {"valid": False}


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[]",
        b"null",
        b'"x"',
        b"{}",
        b'{"report": {}}',
        b'{"report": {}, "expected": {}}',
        b'{"report": {}, "expected": {}, "extra": 1}',
    ],
)
def test_http_bad_body_is_422(monkeypatch, body):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    response = client.post(
        "/decision-matrix/attest/bundle/verify",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_value_error_in_function_is_422(monkeypatch):
    monkeypatch.setattr("regulation_policy_compiler.app.H", None)
    bundle = _bundle()
    bundle["reports"].reverse()
    response = client.post(
        "/decision-matrix/attest/bundle/verify",
        json={"report": bundle, "expected": _expected(bundle)},
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_http_works_without_history_configured(monkeypatch):
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
