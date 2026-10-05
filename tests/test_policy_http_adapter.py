"""Regression tests for the shared stateless-policy HTTP adapter.

Every endpoint in ROUTES delegates request-body parsing, exact key-set
enforcement, ValueError mapping, and compact UTF-8 JSON encoding to
``_policy_response``.  These tests pin that shared boundary per endpoint
without touching real history files or the network: the policy operations
are replaced with recording stubs via monkeypatch.
"""

import asyncio
import json

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

import regulation_policy_compiler.app as app_module
from regulation_policy_compiler.app import app

client = TestClient(app)
raising_client = TestClient(app, raise_server_exceptions=True)

# (path, endpoint attribute, policy operation, request fields, wrap valid)
ROUTES = [
    ('/rules/compile', 'compile_rules_endpoint', 'compile_rules', ('at', 'rules'), False),
    ('/rules/coverage', 'policy_coverage_endpoint', 'policy_coverage', ('at', 'fact_keys', 'rules'), False),
    ('/rules/coverage/timeline', 'policy_coverage_timeline_endpoint', 'policy_coverage_timeline', ('start', 'end', 'fact_keys', 'rules'), False),
    ('/rules/attest', 'policy_attestation_endpoint', 'policy_attestation', ('at', 'rules'), False),
    ('/rules/schedule', 'policy_schedule_endpoint', 'policy_schedule', ('start', 'end', 'rules'), False),
    ('/rules/schedule/attest', 'policy_schedule_attestation_endpoint', 'policy_schedule_attestation', ('start', 'end', 'rules'), False),
    ('/explanations', 'explain_decision', 'explain', ('at', 'facts', 'rules'), False),
    ('/decision-counterfactual', 'decision_counterfactual_endpoint', 'decision_counterfactual', ('at', 'facts', 'target', 'rules'), False),
    ('/explanations/attest', 'decision_attestation_endpoint', 'decision_attestation', ('at', 'facts', 'rules'), False),
    ('/explanations/attest/verify', 'verify_decision_attestation_endpoint', 'verify_decision_attestation', ('report', 'expected'), True),
    ('/decision-changes', 'decision_changes', 'compare_decisions', ('from', 'to', 'facts', 'rules'), False),
    ('/decision-timeline', 'decision_timeline_endpoint', 'decision_timeline', ('start', 'end', 'facts', 'rules'), False),
    ('/decision-timeline/attest', 'decision_timeline_attestation_endpoint', 'decision_timeline_attestation', ('start', 'end', 'facts', 'rules'), False),
    ('/decision-timeline/attest/verify', 'verify_decision_timeline_attestation_endpoint', 'verify_decision_timeline_attestation', ('report', 'expected'), True),
    ('/decision-journey', 'decision_journey_endpoint', 'decision_journey', ('start', 'end', 'initial_facts', 'events', 'rules'), False),
    ('/decision-impact', 'decision_impact_endpoint', 'decision_impact', ('from', 'to', 'cases', 'rules'), False),
    ('/decision-impact/attest', 'decision_impact_attestation_endpoint', 'decision_impact_attestation', ('from', 'to', 'cases', 'rules'), False),
    ('/decision-impact/attest/verify', 'verify_decision_impact_attestation_endpoint', 'verify_decision_impact_attestation', ('report', 'expected'), True),
    ('/decision-matrix/attest', 'decision_matrix_attestation_endpoint', 'decision_matrix_attestation', ('start', 'end', 'cases', 'rules'), False),
    ('/decision-matrix/attest/verify', 'verify_decision_matrix_attestation_endpoint', 'verify_decision_matrix_attestation', ('report', 'expected'), True),
    ('/decision-matrix/ledger', 'matrix_change_ledger_endpoint', 'matrix_change_ledger', ('report',), False),
    ('/decision-matrix/attest/bundle', 'decision_matrix_attestation_bundle_endpoint', 'decision_matrix_attestation_bundle', ('items',), False),
    ('/decision-matrix/attest/bundle/verify', 'verify_decision_matrix_attestation_bundle_endpoint', 'verify_decision_matrix_attestation_bundle', ('report', 'expected'), True),
    ('/decision-matrix/attest/bundle/diff', 'matrix_bundle_diff_endpoint', 'matrix_bundle_diff', ('before', 'after'), False),
    ('/decision-matrix/attest/bundle/diff/verify', 'verify_matrix_bundle_diff_endpoint', 'verify_matrix_bundle_diff', ('report', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution', 'matrix_bundle_evolution_endpoint', 'matrix_bundle_evolution', ('stages',), False),
    ('/decision-matrix/attest/bundle/evolution/verify', 'verify_matrix_bundle_evolution_endpoint', 'verify_matrix_bundle_evolution', ('report', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint', 'evolution_checkpoint_endpoint', 'evolution_checkpoint', ('report', 'start', 'end'), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/verify', 'verify_evolution_checkpoint_endpoint', 'verify_evolution_checkpoint', ('proof', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle', 'evolution_checkpoint_bundle_endpoint', 'evolution_checkpoint_bundle', ('items',), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/verify', 'verify_evolution_checkpoint_bundle_endpoint', 'verify_evolution_checkpoint_bundle', ('report', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff', 'evolution_checkpoint_bundle_diff_endpoint', 'evolution_checkpoint_bundle_diff', ('before', 'after'), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/verify', 'verify_evolution_checkpoint_bundle_diff_endpoint', 'verify_evolution_checkpoint_bundle_diff', ('report', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain', 'checkpoint_chain_endpoint', 'checkpoint_chain', ('stages',), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/verify', 'verify_checkpoint_chain_endpoint', 'verify_checkpoint_chain', ('report', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint', 'checkpoint_chain_checkpoint_endpoint', 'checkpoint_chain_checkpoint', ('report', 'start', 'end'), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/verify', 'verify_checkpoint_chain_checkpoint_endpoint', 'verify_checkpoint_chain_checkpoint', ('proof', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle', 'checkpoint_chain_checkpoint_bundle_endpoint', 'checkpoint_chain_checkpoint_bundle', ('items',), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/verify', 'verify_checkpoint_chain_checkpoint_bundle_endpoint', 'verify_checkpoint_chain_checkpoint_bundle', ('report', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/diff', 'checkpoint_chain_checkpoint_bundle_diff_endpoint', 'checkpoint_chain_checkpoint_bundle_diff', ('before', 'after'), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/diff/verify', 'verify_checkpoint_chain_checkpoint_bundle_diff_endpoint', 'verify_checkpoint_chain_checkpoint_bundle_diff', ('report', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution', 'checkpoint_chain_checkpoint_bundle_evolution_endpoint', 'checkpoint_chain_checkpoint_bundle_evolution', ('stages',), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/verify', 'verify_checkpoint_chain_checkpoint_bundle_evolution_endpoint', 'verify_checkpoint_chain_checkpoint_bundle_evolution', ('report', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint', 'bundle_evolution_checkpoint_endpoint', 'bundle_evolution_checkpoint', ('report', 'start', 'end'), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/verify', 'verify_bundle_evolution_checkpoint_endpoint', 'verify_bundle_evolution_checkpoint', ('proof', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/bundle', 'bundle_evolution_checkpoint_bundle_endpoint', 'bundle_evolution_checkpoint_bundle', ('items',), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/verify', 'verify_bundle_evolution_checkpoint_bundle_endpoint', 'verify_bundle_evolution_checkpoint_bundle', ('report', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/diff', 'bundle_evolution_checkpoint_bundle_diff_endpoint', 'bundle_evolution_checkpoint_bundle_diff', ('before', 'after'), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/verify', 'verify_bundle_evolution_checkpoint_bundle_diff_endpoint', 'verify_bundle_evolution_checkpoint_bundle_diff', ('report', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution', 'bundle_evolution_checkpoint_bundle_evolution_endpoint', 'bundle_evolution_checkpoint_bundle_evolution', ('stages',), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/verify', 'verify_bundle_evolution_checkpoint_bundle_evolution_endpoint', 'verify_bundle_evolution_checkpoint_bundle_evolution', ('report', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/checkpoint', 'bundle_evolution_checkpoint_bundle_evolution_checkpoint_endpoint', 'bundle_evolution_checkpoint_bundle_evolution_checkpoint', ('report', 'start', 'end'), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/checkpoint/verify', 'verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_endpoint', 'verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint', ('proof', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/checkpoint/bundle', 'bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_endpoint', 'bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle', ('items',), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/checkpoint/bundle/verify', 'verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_endpoint', 'verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle', ('report', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/checkpoint/bundle/diff', 'bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_endpoint', 'bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff', ('before', 'after'), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/checkpoint/bundle/diff/verify', 'verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_endpoint', 'verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff', ('report', 'expected'), True),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/checkpoint/bundle/diff/evolution', 'bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution_endpoint', 'bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution', ('stages',), False),
    ('/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution/checkpoint/bundle/diff/evolution/verify', 'verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution_endpoint', 'verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution', ('report', 'expected'), True)
]

KEY_SETS = sorted(
    {frozenset(fields) for _, _, _, fields, _ in ROUTES}, key=lambda s: sorted(s)
)

OPENAPI = app.openapi()


def _body(fields):
    return {field: f"{field}-value" for field in fields}


@pytest.mark.parametrize(
    "path,endpoint,operation,fields,wrap", ROUTES, ids=[r[1] for r in ROUTES]
)
def test_route_registration_preserved(path, endpoint, operation, fields, wrap):
    function = getattr(app_module, endpoint)
    assert function.__name__ == endpoint
    matches = [r for r in app.routes if getattr(r, "path", None) == path]
    assert len(matches) == 1
    route = matches[0]
    assert "POST" in route.methods
    assert route.endpoint is function
    assert route.name == endpoint
    assert OPENAPI["paths"][path]["post"]["operationId"] == route.unique_id


@pytest.mark.parametrize(
    "path,endpoint,operation,fields,wrap", ROUTES, ids=[r[1] for r in ROUTES]
)
def test_success_passes_fields_in_order_and_encodes_compact_utf8(
    monkeypatch, path, endpoint, operation, fields, wrap
):
    marker = {"摘要": "允许", "items": [1, "é", {"k": None}]}
    calls = []

    def stub(*args):
        calls.append(args)
        return True if wrap else marker

    monkeypatch.setattr(app_module, operation, stub)
    body = _body(fields)
    response = client.post(path, json=body)
    assert response.status_code == 200
    assert calls == [tuple(body[field] for field in fields)]
    expected = {"valid": True} if wrap else marker
    assert response.content == json.dumps(
        expected, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert not response.content.endswith(b"\n")
    assert response.headers["content-type"].startswith("application/json")


@pytest.mark.parametrize(
    "path,endpoint,operation,fields,wrap", ROUTES, ids=[r[1] for r in ROUTES]
)
@pytest.mark.parametrize(
    "raw",
    [b"{not json", b'{"at": ', b"\xff\xfe", b'{"at": "\xff"}'],
    ids=["truncated", "unterminated", "bad-utf8", "bad-utf8-inside"],
)
def test_invalid_json_is_422(path, endpoint, operation, fields, wrap, raw):
    response = client.post(
        path, content=raw, headers={"content-type": "application/json"}
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


@pytest.mark.parametrize(
    "path,endpoint,operation,fields,wrap", ROUTES, ids=[r[1] for r in ROUTES]
)
@pytest.mark.parametrize(
    "raw", [b"[]", b"[1, 2]", b'"x"', b"null", b"1"], ids=lambda b: b.decode()
)
def test_non_object_body_is_422(path, endpoint, operation, fields, wrap, raw):
    response = client.post(
        path, content=raw, headers={"content-type": "application/json"}
    )
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


@pytest.mark.parametrize(
    "path,endpoint,operation,fields,wrap", ROUTES, ids=[r[1] for r in ROUTES]
)
def test_wrong_key_set_is_422(path, endpoint, operation, fields, wrap):
    bodies = []
    missing = _body(fields)
    missing.pop(fields[0])
    bodies.append(missing)
    bodies.append(_body(fields) | {"unexpected": 1})
    own = frozenset(fields)
    for other in KEY_SETS:
        if other != own:
            bodies.append({field: 0 for field in sorted(other)})
    for body in bodies:
        response = client.post(path, json=body)
        assert response.status_code == 422, (path, body)
        assert response.content == b'{"detail":"invalid request"}'


@pytest.mark.parametrize(
    "path,endpoint,operation,fields,wrap", ROUTES, ids=[r[1] for r in ROUTES]
)
def test_value_error_from_operation_is_422(
    monkeypatch, path, endpoint, operation, fields, wrap
):
    def stub(*args):
        raise ValueError("boom")

    monkeypatch.setattr(app_module, operation, stub)
    response = client.post(path, json=_body(fields))
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


@pytest.mark.parametrize(
    "path,endpoint,operation,fields,wrap", ROUTES, ids=[r[1] for r in ROUTES]
)
def test_other_exceptions_are_not_swallowed(
    monkeypatch, path, endpoint, operation, fields, wrap
):
    def stub(*args):
        raise RuntimeError("boom")

    monkeypatch.setattr(app_module, operation, stub)
    with pytest.raises(RuntimeError):
        raising_client.post(path, json=_body(fields))


def test_endpoint_remains_directly_callable(monkeypatch):
    monkeypatch.setattr(
        app_module, "compile_rules", lambda at, rules: {"回显": [at, rules]}
    )
    payload = json.dumps(
        {"at": "2021-01-01T00:00:00Z", "rules": []}
    ).encode("utf-8")

    async def call():
        sent = False

        async def receive():
            nonlocal sent
            if sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": payload, "more_body": False}

        scope = {"type": "http", "method": "POST", "headers": []}
        return await app_module.compile_rules_endpoint(Request(scope, receive))

    response = asyncio.run(call())
    assert response.status_code == 200
    assert (
        response.body
        == b'{"\xe5\x9b\x9e\xe6\x98\xbe":["2021-01-01T00:00:00Z",[]]}'
    )
