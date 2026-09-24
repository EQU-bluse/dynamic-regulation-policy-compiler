"""HTTP interface for the regulation policy compiler service."""

from __future__ import annotations

import json
import os
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from .history import DecisionHistory, verify_audit, verify_audit_bundle
from .policy import (
    _check_fact_map,
    _check_non_empty_str,
    _check_time,
    _validate_rules,
    compare_decisions,
    compile_rules,
    decision_attestation,
    decision_impact,
    decision_impact_attestation,
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    decision_timeline,
    decision_timeline_attestation,
    explain,
    matrix_bundle_diff,
    policy_attestation,
    policy_schedule,
    policy_schedule_attestation,
    verify_decision_attestation,
    verify_decision_impact_attestation,
    verify_decision_matrix_attestation,
    verify_decision_matrix_attestation_bundle,
    verify_decision_timeline_attestation,
    verify_matrix_bundle_diff,
)

app = FastAPI(title="Dynamic Regulation Policy Compiler")

_HISTORY_PATH = os.environ.get("REGULATION_HISTORY_PATH")
H: DecisionHistory | None = (
    DecisionHistory(_HISTORY_PATH) if _HISTORY_PATH is not None else None
)

_POST_KEYS = {"at", "facts", "rules"}
_COMPILE_KEYS = {"at", "rules"}
_SCHEDULE_KEYS = {"start", "end", "rules"}
_COMPARE_KEYS = {"from", "to", "facts", "rules"}
_TIMELINE_KEYS = {"start", "end", "facts", "rules"}
_IMPACT_KEYS = {"from", "to", "cases", "rules"}
_MATRIX_KEYS = {"start", "end", "cases", "rules"}
_MATRIX_BUNDLE_ITEMS_KEYS = {"items"}
_MATRIX_BUNDLE_DIFF_KEYS = {"before", "after"}
_VERIFY_KEYS = {"report", "expected"}
_BUNDLE_KEYS = {"record_ids", "start", "end"}


def _error(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": message})


def _invalid_request() -> JSONResponse:
    return _error(422, "invalid request")


def _history_unavailable() -> JSONResponse:
    return _error(503, "history unavailable")


def _record_response(record: dict[str, Any]) -> Response:
    text = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    return Response(content=text, media_type="application/json")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/rules/compile")
async def compile_rules_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _COMPILE_KEYS:
        return _invalid_request()
    try:
        compiled = compile_rules(body["at"], body["rules"])
    except ValueError:
        return _invalid_request()
    return _record_response(compiled)


@app.post("/rules/attest")
async def policy_attestation_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _COMPILE_KEYS:
        return _invalid_request()
    try:
        attestation = policy_attestation(body["at"], body["rules"])
    except ValueError:
        return _invalid_request()
    return _record_response(attestation)


@app.post("/rules/schedule")
async def policy_schedule_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _SCHEDULE_KEYS:
        return _invalid_request()
    try:
        report = policy_schedule(body["start"], body["end"], body["rules"])
    except ValueError:
        return _invalid_request()
    return _record_response(report)


@app.post("/rules/schedule/attest")
async def policy_schedule_attestation_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _SCHEDULE_KEYS:
        return _invalid_request()
    try:
        report = policy_schedule_attestation(
            body["start"], body["end"], body["rules"]
        )
    except ValueError:
        return _invalid_request()
    return _record_response(report)


@app.post("/explanations")
async def explain_decision(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _POST_KEYS:
        return _invalid_request()
    try:
        report = explain(body["at"], body["facts"], body["rules"])
    except ValueError:
        return _invalid_request()
    return _record_response(report)


@app.post("/explanations/attest")
async def decision_attestation_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _POST_KEYS:
        return _invalid_request()
    try:
        attestation = decision_attestation(body["at"], body["facts"], body["rules"])
    except ValueError:
        return _invalid_request()
    return _record_response(attestation)


@app.post("/explanations/attest/verify")
async def verify_decision_attestation_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _VERIFY_KEYS:
        return _invalid_request()
    try:
        valid = verify_decision_attestation(body["report"], body["expected"])
    except ValueError:
        return _invalid_request()
    return _record_response({"valid": valid})


@app.post("/decision-changes")
async def decision_changes(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _COMPARE_KEYS:
        return _invalid_request()
    try:
        report = compare_decisions(
            body["from"], body["to"], body["facts"], body["rules"]
        )
    except ValueError:
        return _invalid_request()
    return _record_response(report)


@app.post("/decision-timeline")
async def decision_timeline_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _TIMELINE_KEYS:
        return _invalid_request()
    try:
        report = decision_timeline(
            body["start"], body["end"], body["facts"], body["rules"]
        )
    except ValueError:
        return _invalid_request()
    return _record_response(report)


@app.post("/decision-timeline/attest")
async def decision_timeline_attestation_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _TIMELINE_KEYS:
        return _invalid_request()
    try:
        report = decision_timeline_attestation(
            body["start"], body["end"], body["facts"], body["rules"]
        )
    except ValueError:
        return _invalid_request()
    return _record_response(report)


@app.post("/decision-timeline/attest/verify")
async def verify_decision_timeline_attestation_endpoint(
    request: Request,
) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _VERIFY_KEYS:
        return _invalid_request()
    try:
        valid = verify_decision_timeline_attestation(
            body["report"], body["expected"]
        )
    except ValueError:
        return _invalid_request()
    return _record_response({"valid": valid})


@app.post("/decision-impact")
async def decision_impact_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _IMPACT_KEYS:
        return _invalid_request()
    try:
        report = decision_impact(
            body["from"], body["to"], body["cases"], body["rules"]
        )
    except ValueError:
        return _invalid_request()
    return _record_response(report)


@app.post("/decision-impact/attest")
async def decision_impact_attestation_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _IMPACT_KEYS:
        return _invalid_request()
    try:
        report = decision_impact_attestation(
            body["from"], body["to"], body["cases"], body["rules"]
        )
    except ValueError:
        return _invalid_request()
    return _record_response(report)


@app.post("/decision-impact/attest/verify")
async def verify_decision_impact_attestation_endpoint(
    request: Request,
) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _VERIFY_KEYS:
        return _invalid_request()
    try:
        valid = verify_decision_impact_attestation(
            body["report"], body["expected"]
        )
    except ValueError:
        return _invalid_request()
    return _record_response({"valid": valid})


@app.post("/decision-matrix/attest")
async def decision_matrix_attestation_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _MATRIX_KEYS:
        return _invalid_request()
    try:
        report = decision_matrix_attestation(
            body["start"], body["end"], body["cases"], body["rules"]
        )
    except ValueError:
        return _invalid_request()
    return _record_response(report)


@app.post("/decision-matrix/attest/verify")
async def verify_decision_matrix_attestation_endpoint(
    request: Request,
) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _VERIFY_KEYS:
        return _invalid_request()
    try:
        valid = verify_decision_matrix_attestation(
            body["report"], body["expected"]
        )
    except ValueError:
        return _invalid_request()
    return _record_response({"valid": valid})


@app.post("/decision-matrix/attest/bundle")
async def decision_matrix_attestation_bundle_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _MATRIX_BUNDLE_ITEMS_KEYS:
        return _invalid_request()
    try:
        bundle = decision_matrix_attestation_bundle(body["items"])
    except ValueError:
        return _invalid_request()
    return _record_response(bundle)


@app.post("/decision-matrix/attest/bundle/verify")
async def verify_decision_matrix_attestation_bundle_endpoint(
    request: Request,
) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _VERIFY_KEYS:
        return _invalid_request()
    try:
        valid = verify_decision_matrix_attestation_bundle(
            body["report"], body["expected"]
        )
    except ValueError:
        return _invalid_request()
    return _record_response({"valid": valid})


@app.post("/decision-matrix/attest/bundle/diff")
async def matrix_bundle_diff_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _MATRIX_BUNDLE_DIFF_KEYS:
        return _invalid_request()
    try:
        diff = matrix_bundle_diff(body["before"], body["after"])
    except ValueError:
        return _invalid_request()
    return _record_response(diff)


@app.post("/decision-matrix/attest/bundle/diff/verify")
async def verify_matrix_bundle_diff_endpoint(request: Request) -> Response:
    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _invalid_request()
    if not isinstance(body, dict) or set(body) != _VERIFY_KEYS:
        return _invalid_request()
    try:
        valid = verify_matrix_bundle_diff(body["report"], body["expected"])
    except ValueError:
        return _invalid_request()
    return _record_response({"valid": valid})


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
