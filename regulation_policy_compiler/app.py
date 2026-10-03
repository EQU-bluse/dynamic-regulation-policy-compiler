"""HTTP interface for the regulation policy compiler service."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from .history import DecisionHistory, verify_audit, verify_audit_bundle
from .policy import (
    _check_fact_map,
    _check_non_empty_str,
    _check_time,
    _validate_rules,
    bundle_evolution_checkpoint,
    bundle_evolution_checkpoint_bundle,
    bundle_evolution_checkpoint_bundle_diff,
    bundle_evolution_checkpoint_bundle_evolution,
    bundle_evolution_checkpoint_bundle_evolution_checkpoint,
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle,
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff,
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution,
    checkpoint_chain,
    checkpoint_chain_checkpoint,
    checkpoint_chain_checkpoint_bundle,
    checkpoint_chain_checkpoint_bundle_diff,
    checkpoint_chain_checkpoint_bundle_evolution,
    compare_decisions,
    compile_rules,
    decision_attestation,
    decision_counterfactual,
    decision_impact,
    decision_impact_attestation,
    decision_journey,
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    decision_timeline,
    decision_timeline_attestation,
    evolution_checkpoint,
    evolution_checkpoint_bundle,
    evolution_checkpoint_bundle_diff,
    explain,
    matrix_bundle_diff,
    matrix_bundle_evolution,
    matrix_change_ledger,
    policy_attestation,
    policy_coverage,
    policy_schedule,
    policy_schedule_attestation,
    verify_bundle_evolution_checkpoint,
    verify_bundle_evolution_checkpoint_bundle,
    verify_bundle_evolution_checkpoint_bundle_diff,
    verify_bundle_evolution_checkpoint_bundle_evolution,
    verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint,
    verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle,
    verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff,
    verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution,
    verify_checkpoint_chain,
    verify_checkpoint_chain_checkpoint,
    verify_checkpoint_chain_checkpoint_bundle,
    verify_checkpoint_chain_checkpoint_bundle_diff,
    verify_checkpoint_chain_checkpoint_bundle_evolution,
    verify_decision_attestation,
    verify_decision_impact_attestation,
    verify_decision_matrix_attestation,
    verify_decision_matrix_attestation_bundle,
    verify_decision_timeline_attestation,
    verify_evolution_checkpoint,
    verify_evolution_checkpoint_bundle,
    verify_evolution_checkpoint_bundle_diff,
    verify_matrix_bundle_diff,
    verify_matrix_bundle_evolution,
)

app = FastAPI(title="Dynamic Regulation Policy Compiler")

_HISTORY_PATH = os.environ.get("REGULATION_HISTORY_PATH")
H: DecisionHistory | None = (
    DecisionHistory(_HISTORY_PATH) if _HISTORY_PATH is not None else None
)

_POST_KEYS = {"at", "facts", "rules"}
_COUNTERFACTUAL_KEYS = {"at", "facts", "target", "rules"}
_COMPILE_KEYS = {"at", "rules"}
_COVERAGE_KEYS = {"at", "fact_keys", "rules"}
_SCHEDULE_KEYS = {"start", "end", "rules"}
_COMPARE_KEYS = {"from", "to", "facts", "rules"}
_TIMELINE_KEYS = {"start", "end", "facts", "rules"}
_JOURNEY_KEYS = {"start", "end", "initial_facts", "events", "rules"}
_IMPACT_KEYS = {"from", "to", "cases", "rules"}
_MATRIX_KEYS = {"start", "end", "cases", "rules"}
_MATRIX_BUNDLE_ITEMS_KEYS = {"items"}
_MATRIX_BUNDLE_DIFF_KEYS = {"before", "after"}
_MATRIX_BUNDLE_EVOLUTION_KEYS = {"stages"}
_EVOLUTION_CHECKPOINT_KEYS = {"report", "start", "end"}
_LEDGER_KEYS = {"report"}
_VERIFY_KEYS = {"report", "expected"}
_EVOLUTION_CHECKPOINT_VERIFY_KEYS = {"proof", "expected"}
_CHECKPOINT_BUNDLE_ITEMS_KEYS = {"items"}
_CHECKPOINT_BUNDLE_DIFF_KEYS = {"before", "after"}
_CHECKPOINT_CHAIN_KEYS = {"stages"}
_CHECKPOINT_CHAIN_CHECKPOINT_KEYS = {"report", "start", "end"}
_BUNDLE_KEYS = {"record_ids", "start", "end"}
_REPLAY_DIFF_KEYS = {"record_ids", "from", "to"}


def _error(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": message})


def _invalid_request() -> JSONResponse:
    return _error(422, "invalid request")


def _history_unavailable() -> JSONResponse:
    return _error(503, "history unavailable")


def _record_response(record: dict[str, Any]) -> Response:
    text = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    return Response(content=text, media_type="application/json")


async def _policy_request(
    request: Request,
    keys: frozenset[str] | set[str],
    fields: tuple[str, ...],
    operation: Callable[..., Any],
    *,
    verify: bool = False,
) -> Response:
    """Shared HTTP boundary for stateless policy endpoints.

    Reads and parses the request body, enforces the exact key set, calls the
    pure policy operation with the listed fields in order, maps ValueError to
    422, and encodes the result as compact UTF-8 JSON. Verify operations wrap
    their boolean outcome as {"valid": ...}; any other exception propagates.
    """
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != keys:
        return _invalid_request()
    try:
        result = operation(*(body[field] for field in fields))
    except ValueError:
        return _invalid_request()
    if verify:
        result = {"valid": result}
    return _record_response(result)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/rules/compile",
)
async def compile_rules_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _COMPILE_KEYS, ("at", "rules",), compile_rules
    )


@app.post(
    "/rules/coverage",
)
async def policy_coverage_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _COVERAGE_KEYS, ("at", "fact_keys", "rules",), policy_coverage
    )


@app.post(
    "/rules/attest",
)
async def policy_attestation_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _COMPILE_KEYS, ("at", "rules",), policy_attestation
    )


@app.post(
    "/rules/schedule",
)
async def policy_schedule_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _SCHEDULE_KEYS, ("start", "end", "rules",), policy_schedule
    )


@app.post(
    "/rules/schedule/attest",
)
async def policy_schedule_attestation_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _SCHEDULE_KEYS, ("start", "end", "rules",), policy_schedule_attestation
    )


@app.post(
    "/explanations",
)
async def explain_decision(request: Request) -> Response:
    return await _policy_request(
        request, _POST_KEYS, ("at", "facts", "rules",), explain
    )


@app.post(
    "/decision-counterfactual",
)
async def decision_counterfactual_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _COUNTERFACTUAL_KEYS, ("at", "facts", "target", "rules",), decision_counterfactual
    )


@app.post(
    "/explanations/attest",
)
async def decision_attestation_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _POST_KEYS, ("at", "facts", "rules",), decision_attestation
    )


@app.post(
    "/explanations/attest/verify",
)
async def verify_decision_attestation_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_decision_attestation, verify=True
    )


@app.post(
    "/decision-changes",
)
async def decision_changes(request: Request) -> Response:
    return await _policy_request(
        request, _COMPARE_KEYS, ("from", "to", "facts", "rules",), compare_decisions
    )


@app.post(
    "/decision-timeline",
)
async def decision_timeline_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _TIMELINE_KEYS, ("start", "end", "facts", "rules",), decision_timeline
    )


@app.post(
    "/decision-timeline/attest",
)
async def decision_timeline_attestation_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _TIMELINE_KEYS, ("start", "end", "facts", "rules",), decision_timeline_attestation
    )


@app.post(
    "/decision-timeline/attest/verify",
)
async def verify_decision_timeline_attestation_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_decision_timeline_attestation, verify=True
    )


@app.post(
    "/decision-journey",
)
async def decision_journey_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _JOURNEY_KEYS, ("start", "end", "initial_facts", "events", "rules",), decision_journey
    )


@app.post(
    "/decision-impact",
)
async def decision_impact_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _IMPACT_KEYS, ("from", "to", "cases", "rules",), decision_impact
    )


@app.post(
    "/decision-impact/attest",
)
async def decision_impact_attestation_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _IMPACT_KEYS, ("from", "to", "cases", "rules",), decision_impact_attestation
    )


@app.post(
    "/decision-impact/attest/verify",
)
async def verify_decision_impact_attestation_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_decision_impact_attestation, verify=True
    )


@app.post(
    "/decision-matrix/attest",
)
async def decision_matrix_attestation_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _MATRIX_KEYS, ("start", "end", "cases", "rules",), decision_matrix_attestation
    )


@app.post(
    "/decision-matrix/attest/verify",
)
async def verify_decision_matrix_attestation_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_decision_matrix_attestation, verify=True
    )


@app.post(
    "/decision-matrix/ledger",
)
async def matrix_change_ledger_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _LEDGER_KEYS, ("report",), matrix_change_ledger
    )


@app.post(
    "/decision-matrix/attest/bundle",
)
async def decision_matrix_attestation_bundle_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _MATRIX_BUNDLE_ITEMS_KEYS, ("items",), decision_matrix_attestation_bundle
    )


@app.post(
    "/decision-matrix/attest/bundle/verify",
)
async def verify_decision_matrix_attestation_bundle_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_decision_matrix_attestation_bundle, verify=True
    )


@app.post(
    "/decision-matrix/attest/bundle/diff",
)
async def matrix_bundle_diff_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _MATRIX_BUNDLE_DIFF_KEYS, ("before", "after",), matrix_bundle_diff
    )


@app.post(
    "/decision-matrix/attest/bundle/diff/verify",
)
async def verify_matrix_bundle_diff_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_matrix_bundle_diff, verify=True
    )


@app.post(
    "/decision-matrix/attest/bundle/evolution",
)
async def matrix_bundle_evolution_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _MATRIX_BUNDLE_EVOLUTION_KEYS, ("stages",), matrix_bundle_evolution
    )


@app.post(
    "/decision-matrix/attest/bundle/evolution/verify",
)
async def verify_matrix_bundle_evolution_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_matrix_bundle_evolution, verify=True
    )


@app.post(
    "/decision-matrix/attest/bundle/evolution/checkpoint",
)
async def evolution_checkpoint_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _EVOLUTION_CHECKPOINT_KEYS, ("report", "start", "end",), evolution_checkpoint
    )


@app.post(
    "/decision-matrix/attest/bundle/evolution/checkpoint/verify",
)
async def verify_evolution_checkpoint_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _EVOLUTION_CHECKPOINT_VERIFY_KEYS, ("proof", "expected",), verify_evolution_checkpoint, verify=True
    )


@app.post(
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle",
)
async def evolution_checkpoint_bundle_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _CHECKPOINT_BUNDLE_ITEMS_KEYS, ("items",), evolution_checkpoint_bundle
    )


@app.post(
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/verify",
)
async def verify_evolution_checkpoint_bundle_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_evolution_checkpoint_bundle, verify=True
    )


@app.post(
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff",
)
async def evolution_checkpoint_bundle_diff_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _CHECKPOINT_BUNDLE_DIFF_KEYS, ("before", "after",), evolution_checkpoint_bundle_diff
    )


@app.post(
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/verify",
)
async def verify_evolution_checkpoint_bundle_diff_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_evolution_checkpoint_bundle_diff, verify=True
    )


@app.post(
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain",
)
async def checkpoint_chain_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _CHECKPOINT_CHAIN_KEYS, ("stages",), checkpoint_chain
    )


@app.post(
    "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/chain/verify",
)
async def verify_checkpoint_chain_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_checkpoint_chain, verify=True
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint"
    ),
)
async def checkpoint_chain_checkpoint_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _CHECKPOINT_CHAIN_CHECKPOINT_KEYS, ("report", "start", "end",), checkpoint_chain_checkpoint
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/verify"
    ),
)
async def verify_checkpoint_chain_checkpoint_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _EVOLUTION_CHECKPOINT_VERIFY_KEYS, ("proof", "expected",), verify_checkpoint_chain_checkpoint, verify=True
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle"
    ),
)
async def checkpoint_chain_checkpoint_bundle_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _CHECKPOINT_BUNDLE_ITEMS_KEYS, ("items",), checkpoint_chain_checkpoint_bundle
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/verify"
    ),
)
async def verify_checkpoint_chain_checkpoint_bundle_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_checkpoint_chain_checkpoint_bundle, verify=True
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/diff"
    ),
)
async def checkpoint_chain_checkpoint_bundle_diff_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _CHECKPOINT_BUNDLE_DIFF_KEYS, ("before", "after",), checkpoint_chain_checkpoint_bundle_diff
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/diff/verify"
    ),
)
async def verify_checkpoint_chain_checkpoint_bundle_diff_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_checkpoint_chain_checkpoint_bundle_diff, verify=True
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution"
    ),
)
async def checkpoint_chain_checkpoint_bundle_evolution_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _MATRIX_BUNDLE_EVOLUTION_KEYS, ("stages",), checkpoint_chain_checkpoint_bundle_evolution
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/verify"
    ),
)
async def verify_checkpoint_chain_checkpoint_bundle_evolution_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_checkpoint_chain_checkpoint_bundle_evolution, verify=True
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint"
    ),
)
async def bundle_evolution_checkpoint_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _CHECKPOINT_CHAIN_CHECKPOINT_KEYS, ("report", "start", "end",), bundle_evolution_checkpoint
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/verify"
    ),
)
async def verify_bundle_evolution_checkpoint_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _EVOLUTION_CHECKPOINT_VERIFY_KEYS, ("proof", "expected",), verify_bundle_evolution_checkpoint, verify=True
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/bundle"
    ),
)
async def bundle_evolution_checkpoint_bundle_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _CHECKPOINT_BUNDLE_ITEMS_KEYS, ("items",), bundle_evolution_checkpoint_bundle
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/"
        "verify"
    ),
)
async def verify_bundle_evolution_checkpoint_bundle_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_bundle_evolution_checkpoint_bundle, verify=True
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/"
        "diff"
    ),
)
async def bundle_evolution_checkpoint_bundle_diff_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _CHECKPOINT_BUNDLE_DIFF_KEYS, ("before", "after",), bundle_evolution_checkpoint_bundle_diff
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/"
        "diff/verify"
    ),
)
async def verify_bundle_evolution_checkpoint_bundle_diff_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_bundle_evolution_checkpoint_bundle_diff, verify=True
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/"
        "diff/evolution"
    ),
)
async def bundle_evolution_checkpoint_bundle_evolution_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _MATRIX_BUNDLE_EVOLUTION_KEYS, ("stages",), bundle_evolution_checkpoint_bundle_evolution
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/"
        "diff/evolution/verify"
    ),
)
async def verify_bundle_evolution_checkpoint_bundle_evolution_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_bundle_evolution_checkpoint_bundle_evolution, verify=True
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/"
        "diff/evolution/checkpoint"
    ),
)
async def bundle_evolution_checkpoint_bundle_evolution_checkpoint_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _CHECKPOINT_CHAIN_CHECKPOINT_KEYS, ("report", "start", "end",), bundle_evolution_checkpoint_bundle_evolution_checkpoint
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/"
        "diff/evolution/checkpoint/verify"
    ),
)
async def verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _EVOLUTION_CHECKPOINT_VERIFY_KEYS, ("proof", "expected",), verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint, verify=True
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/"
        "diff/evolution/checkpoint/bundle"
    ),
)
async def bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _CHECKPOINT_BUNDLE_ITEMS_KEYS, ("items",), bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/"
        "diff/evolution/checkpoint/bundle/verify"
    ),
)
async def verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle, verify=True
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/"
        "diff/evolution/checkpoint/bundle/diff"
    ),
)
async def bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _CHECKPOINT_BUNDLE_DIFF_KEYS, ("before", "after",), bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/"
        "diff/evolution/checkpoint/bundle/diff/verify"
    ),
)
async def verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff, verify=True
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/"
        "diff/evolution/checkpoint/bundle/diff/evolution"
    ),
)
async def bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _MATRIX_BUNDLE_EVOLUTION_KEYS, ("stages",), bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution
    )


@app.post(
    (
        "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/"
        "diff/chain/checkpoint/bundle/evolution/checkpoint/bundle/"
        "diff/evolution/checkpoint/bundle/diff/evolution/verify"
    ),
)
async def verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution_endpoint(request: Request) -> Response:
    return await _policy_request(
        request, _VERIFY_KEYS, ("report", "expected",), verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution, verify=True
    )


@app.post("/decisions/{record_id}")
async def create_decision(record_id: str, request: Request) -> Response:
    try:
        _check_non_empty_str(record_id, "record_id")
    except ValueError:
        return _invalid_request()
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _POST_KEYS:
        return _invalid_request()
    try:
        _check_time(body["at"], "at")
        _check_fact_map(body["facts"], "facts")
        _validate_rules(body["rules"])
    except ValueError:
        return _invalid_request()
    if H is None:
        return _history_unavailable()
    try:
        record = H.record(record_id, body["at"], body["facts"], body["rules"])
    except ValueError as exc:
        if str(exc).startswith("duplicate record"):
            return _error(409, "record already exists")
        return _invalid_request()
    except OSError:
        return _history_unavailable()
    return _record_response(record)


@app.get("/decisions/{record_id}")
def get_decision(record_id: str, at: str | None = None) -> Response:
    try:
        _check_non_empty_str(record_id, "record_id")
        _check_time(at, "at")
    except ValueError:
        return _invalid_request()
    if H is None:
        return _history_unavailable()
    try:
        record = H.replay(record_id, at)
    except KeyError:
        return _error(404, "record not found")
    except ValueError:
        return _invalid_request()
    except OSError:
        return _history_unavailable()
    return _record_response(record)


@app.get("/decisions/{record_id}/evolution")
def get_evolution(record_id: str, request: Request) -> Response:
    pairs = request.query_params.multi_items()
    if sorted(key for key, _ in pairs) != ["end", "start"] or len(pairs) != 2:
        return _invalid_request()
    values = dict(pairs)
    start = values["start"]
    end = values["end"]
    try:
        _check_non_empty_str(record_id, "record_id")
        _check_time(start, "start")
        _check_time(end, "end")
        if start > end:
            raise ValueError("start must not be after end")
    except ValueError:
        return _invalid_request()
    if H is None:
        return _history_unavailable()
    try:
        report = H.evolution(record_id, start, end)
    except KeyError:
        return _error(404, "record not found")
    except ValueError:
        return _invalid_request()
    except OSError:
        return _history_unavailable()
    return _record_response(report)


@app.post("/audits/verify")
async def verify_audit_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _VERIFY_KEYS:
        return _invalid_request()
    try:
        valid = verify_audit(body["report"], body["expected"])
    except ValueError:
        return _invalid_request()
    return _record_response({"valid": valid})


@app.get("/decisions/{record_id}/audit")
def get_audit(record_id: str, request: Request) -> Response:
    pairs = request.query_params.multi_items()
    if sorted(key for key, _ in pairs) != ["end", "start"] or len(pairs) != 2:
        return _invalid_request()
    values = dict(pairs)
    start = values["start"]
    end = values["end"]
    try:
        _check_non_empty_str(record_id, "record_id")
        _check_time(start, "start")
        _check_time(end, "end")
        if start > end:
            raise ValueError("start must not be after end")
    except ValueError:
        return _invalid_request()
    if H is None:
        return _history_unavailable()
    try:
        report = H.audit(record_id, start, end)
    except KeyError:
        return _error(404, "record not found")
    except ValueError:
        return _invalid_request()
    except OSError:
        return _history_unavailable()
    return _record_response(report)


@app.post("/audits/bundle")
async def audit_bundle_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _BUNDLE_KEYS:
        return _invalid_request()
    try:
        record_ids = body["record_ids"]
        if not isinstance(record_ids, list) or not record_ids:
            raise ValueError("record_ids must be a non-empty list of record id strings")
        seen: set[str] = set()
        for index, record_id in enumerate(record_ids):
            _check_non_empty_str(record_id, f"record_ids[{index}]")
            if record_id in seen:
                raise ValueError("record_ids must not contain duplicates")
            seen.add(record_id)
        _check_time(body["start"], "start")
        _check_time(body["end"], "end")
        if body["start"] > body["end"]:
            raise ValueError("start must not be after end")
    except ValueError:
        return _invalid_request()
    if H is None:
        return _history_unavailable()
    try:
        bundle = H.audit_bundle(record_ids, body["start"], body["end"])
    except KeyError:
        return _error(404, "record not found")
    except OSError:
        return _history_unavailable()
    return _record_response(bundle)


@app.post("/history/replay-diff")
async def replay_diff_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _REPLAY_DIFF_KEYS:
        return _invalid_request()
    try:
        record_ids = body["record_ids"]
        if not isinstance(record_ids, list) or not record_ids:
            raise ValueError("record_ids must be a non-empty list of record id strings")
        seen: set[str] = set()
        for index, record_id in enumerate(record_ids):
            _check_non_empty_str(record_id, f"record_ids[{index}]")
            if record_id in seen:
                raise ValueError("record_ids must not contain duplicates")
            seen.add(record_id)
        _check_time(body["from"], "from")
        _check_time(body["to"], "to")
        if body["from"] > body["to"]:
            raise ValueError("from must not be after to")
    except ValueError:
        return _invalid_request()
    if H is None:
        return _history_unavailable()
    try:
        report = H.replay_diff(record_ids, body["from"], body["to"])
    except KeyError:
        return _error(404, "record not found")
    except OSError:
        return _history_unavailable()
    return _record_response(report)


@app.post("/audits/bundle/verify")
async def verify_audit_bundle_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _VERIFY_KEYS:
        return _invalid_request()
    try:
        valid = verify_audit_bundle(body["report"], body["expected"])
    except ValueError:
        return _invalid_request()
    return _record_response({"valid": valid})
