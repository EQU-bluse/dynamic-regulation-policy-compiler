"""Persistent decision history with point-in-time replay."""

from __future__ import annotations

import copy
import json
import os
import tempfile
from typing import Any

from .policy import (
    _check_fact_map,
    _check_non_empty_str,
    _check_time,
    _select_matched,
    _snapshot_basis,
    _validate_rules,
)

_RECORD_KEYS = frozenset({"id", "at", "decision", "trace", "basis"})
_BASIS_KEYS = ("id", "ver", "source", "priority", "from", "to", "when", "result")


def _check_trace(value: Any, field: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list of 'id@ver' strings")
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field} must be a list of 'id@ver' strings")
        head, sep, _tail = item.rpartition("@")
        if not sep or not head or not _tail:
            raise ValueError(f"{field} entries must look like 'id@ver': {item!r}")
    return value


def _check_basis_shape(basis: Any, field: str) -> dict[str, Any]:
    """Validate the structural shape of a persisted basis rule and return it
    in canonical key order (``when`` keys sorted ascending)."""
    if not isinstance(basis, dict) or set(basis) != set(_BASIS_KEYS):
        raise ValueError(
            f"{field} must be a dict with exactly the keys "
            "id, ver, source, priority, from, to, when, result"
        )
    _check_non_empty_str(basis["id"], f"{field}.id")
    if isinstance(basis["ver"], bool) or not isinstance(basis["ver"], int) or basis["ver"] < 1:
        raise ValueError(f"{field}.ver must be a positive integer")
    if basis["source"] not in ("law", "org"):
        raise ValueError(f"{field}.source must be 'law' or 'org'")
    if isinstance(basis["priority"], bool) or not isinstance(basis["priority"], int):
        raise ValueError(f"{field}.priority must be an integer")
    _check_non_empty_str(basis["result"], f"{field}.result")
    frm = _check_time(basis["from"], f"{field}.from")
    to = basis["to"]
    if to is not None:
        _check_time(to, f"{field}.to")
        if not frm < to:
            raise ValueError(f"{field} requires from < to")
    when = basis["when"]
    if when is not None:
        _check_fact_map(when, f"{field}.when")
        when = {key: when[key] for key in sorted(when)}
    return {
        "id": basis["id"],
        "ver": basis["ver"],
        "source": basis["source"],
        "priority": basis["priority"],
        "from": frm,
        "to": to,
        "when": when,
        "result": basis["result"],
    }


class DecisionHistory:
    """Append decision records to a compact UTF-8 JSON file and replay them.

    The file always holds ``{"records": [...]}`` sorted by ``(id, at)``
    Unicode code point order, serialized without ASCII escaping or extra
    whitespace and terminated by a single trailing newline. A missing file is
    created on the first :meth:`record` call.
    """

    def __init__(self, path: str):
        _check_non_empty_str(path, "path")
        self.path = path
        self._records: list[dict[str, Any]] = self._load()
        if not os.path.exists(path):
            self._write()

    def _load(self) -> list[dict[str, Any]]:
        try:
            with open(self.path, encoding="utf-8") as handle:
                text = handle.read()
        except FileNotFoundError:
            return []

        try:
            data = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"history file is not valid JSON: {self.path!r}") from exc

        if not isinstance(data, dict) or set(data) != {"records"}:
            raise ValueError("history document must be an object with exactly the key 'records'")
        raw_records = data["records"]
        if not isinstance(raw_records, list):
            raise ValueError("history 'records' must be a list")

        records: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for index, record in enumerate(raw_records):
            field = f"records[{index}]"
            if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
                raise ValueError(
                    f"{field} must be a dict with exactly the keys "
                    "id, at, decision, trace, basis"
                )
            record_id = _check_non_empty_str(record["id"], f"{field}.id")
            at = _check_time(record["at"], f"{field}.at")
            decision = record["decision"]
            if decision is not None:
                _check_non_empty_str(decision, f"{field}.decision")
            trace = _check_trace(record["trace"], f"{field}.trace")
            basis = record["basis"]
            if basis is not None:
                basis = _check_basis_shape(basis, f"{field}.basis")
            if decision is None:
                if trace or basis is not None:
                    raise ValueError(
                        f"{field}: a null decision requires an empty trace and a null basis"
                    )
            else:
                if not trace or basis is None:
                    raise ValueError(
                        f"{field}: a non-null decision requires a trace and a basis"
                    )
                if basis["result"] != decision or trace[0] != f"{basis['id']}@{basis['ver']}":
                    raise ValueError(f"{field}: basis must be the winning rule named by trace")
            key = (record_id, at)
            if key in seen:
                raise ValueError(f"duplicate record (id, at): {key!r}")
            seen.add(key)
            records.append(
                {"id": record_id, "at": at, "decision": decision, "trace": list(trace),
                 "basis": basis}
            )
        records.sort(key=lambda item: (item["id"], item["at"]))
        return records

    def _write(self) -> None:
        """Atomically replace the history file; a failed write leaves the
        previous file in place and raises :class:`OSError`."""
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        payload = json.dumps(
            {"records": self._records}, ensure_ascii=False, separators=(",", ":")
        )
        fd, tmp_name = tempfile.mkstemp(
            prefix=".history-", suffix=".tmp", dir=directory, text=True
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                handle.write(payload)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
        except OSError:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def record(
        self,
        record_id: str,
        at: str,
        facts: dict[str, bool],
        rules: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Evaluate ``rules`` against ``facts`` at ``at`` and persist the
        outcome under ``record_id``.

        Validation, latest-version selection, match ranking and
        :class:`ValueError` conditions behave exactly like
        :func:`regulation_policy_compiler.policy.evaluate`. ``record_id`` must
        be a non-empty string and ``(record_id, at)`` must be unique. Returns
        the stored record: with no matching rule it is
        ``decision=None, trace=[], basis=None``, otherwise ``basis`` is an
        ordered snapshot of the winning rule.
        """
        _check_non_empty_str(record_id, "record_id")
        _check_time(at, "at")
        _check_fact_map(facts, "facts")
        rules = _validate_rules(rules)

        key = (record_id, at)
        if any((item["id"], item["at"]) == key for item in self._records):
            raise ValueError(f"duplicate record (id, at): {key!r}")

        matched = _select_matched(at, facts, rules)
        if matched:
            winner = matched[0]
            entry: dict[str, Any] = {
                "id": record_id,
                "at": at,
                "decision": winner["result"],
                "trace": [f"{rule['id']}@{rule['ver']}" for rule in matched],
                "basis": _snapshot_basis(winner),
            }
        else:
            entry = {"id": record_id, "at": at, "decision": None, "trace": [], "basis": None}

        self._records.append(entry)
        self._records.sort(key=lambda item: (item["id"], item["at"]))
        try:
            self._write()
        except OSError:
            # The old file is untouched; keep in-memory state consistent with it.
            self._records.remove(entry)
            self._records.sort(key=lambda item: (item["id"], item["at"]))
            raise
        return copy.deepcopy(entry)

    def replay(self, record_id: str, at: str) -> dict[str, Any]:
        """Return a copy of the stored record for ``record_id`` whose ``at`` is
        the most recent one not later than ``at``.

        The decision is read from storage and never recomputed. Raises
        :class:`KeyError` when no such record exists.
        """
        _check_non_empty_str(record_id, "record_id")
        _check_time(at, "at")
        choice: dict[str, Any] | None = None
        for item in self._records:
            if item["id"] == record_id and item["at"] <= at:
                if choice is None or item["at"] > choice["at"]:
                    choice = item
        if choice is None:
            raise KeyError(f"no record for {record_id!r} at or before {at!r}")
        return copy.deepcopy(choice)
