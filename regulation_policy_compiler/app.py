"""HTTP interface for the regulation policy compiler service."""

from __future__ import annotations

import json
import os
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from .history import DecisionHistory
from .policy import (
    _check_fact_map,
    _check_non_empty_str,
    _check_time,
    _validate_rules,
    compare_decisions,
    compile_rules,
    explain,
)

app = FastAPI(title="Dynamic Regulation Policy Compiler")

_HISTORY_PATH = os.environ.get("REGULATION_HISTORY_PATH")
H: DecisionHistory | None = (
    DecisionHistory(_HISTORY_PATH) if _HISTORY_PATH is not None else None
)

_POST_KEYS = {"at", "facts", "rules"}
_COMPILE_KEYS = {"at", "rules"}
_COMPARE_KEYS = {"from", "to", "facts", "rules"}


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
