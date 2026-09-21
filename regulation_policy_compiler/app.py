"""HTTP interface for decision recording and replay."""

from __future__ import annotations

import json
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response

from .history import DecisionHistory
from .policy import _check_non_empty_str, _check_time

app = FastAPI(title="Dynamic Regulation Policy Compiler")

_HISTORY_PATH = os.environ.get("REGULATION_HISTORY_PATH")
H: DecisionHistory | None = (
    DecisionHistory(_HISTORY_PATH) if _HISTORY_PATH is not None else None
)

_BODY_KEYS = {"at", "facts", "rules"}


def _invalid() -> HTTPException:
    return HTTPException(status_code=422, detail="invalid request")


def _unavailable() -> HTTPException:
    return HTTPException(status_code=503, detail="history unavailable")


def _record_response(record: dict[str, Any]) -> Response:
    return Response(
        content=json.dumps(record, ensure_ascii=False, separators=(",", ":")),
        media_type="application/json",
    )


def _require_history() -> DecisionHistory:
    if H is None:
        raise _unavailable()
    return H


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/decisions/{record_id}")
async def record_decision(record_id: str, request: Request) -> Response:
    try:
        _check_non_empty_str(record_id, "record_id")
    except ValueError:
        raise _invalid() from None
    try:
        body = await request.json()
    except ValueError:
        raise _invalid() from None
    if not isinstance(body, dict) or set(body) != _BODY_KEYS:
        raise _invalid()
    history = _require_history()
    try:
        record = history.record(record_id, body["at"], body["facts"], body["rules"])
    except ValueError as exc:
        if str(exc).startswith("duplicate record"):
            raise HTTPException(status_code=409, detail="record already exists") from None
        raise _invalid() from None
    except OSError:
        raise _unavailable() from None
    return _record_response(record)


@app.get("/decisions/{record_id}")
def replay_decision(record_id: str, at: str | None = None) -> Response:
    try:
        _check_non_empty_str(record_id, "record_id")
        _check_time(at, "at")
    except ValueError:
        raise _invalid() from None
    history = _require_history()
    try:
        record = history.replay(record_id, at)
    except KeyError:
        raise HTTPException(status_code=404, detail="record not found") from None
    except OSError:
        raise _unavailable() from None
    return _record_response(record)
