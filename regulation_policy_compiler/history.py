"""Persistent, replayable history of policy decisions."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
from typing import Any

from .policy import _check_non_empty_str, _check_time, _matched_rules, _validate_rules

_RECORD_KEYS = ("id", "at", "decision", "trace", "basis")
_BASIS_KEYS = ("id", "ver", "source", "priority", "from", "to", "when", "result")
_EVOLUTION_FIELDS = ("decision", "trace", "basis")
_AUDIT_PAYLOAD_KEYS = ("at", "decision", "trace", "basis")
_AUDIT_GENESIS = "0" * 64


def _check_trace_entry(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string of the form id@ver")
    rule_id, sep, ver = value.rpartition("@")
    if not sep or not rule_id or not ver.isdigit() or int(ver) < 1:
        raise ValueError(f"{field} must be a string of the form id@ver")
    return value


def _validate_entry(entry: Any, index: int) -> dict[str, Any]:
    field = f"records[{index}]"
    if not isinstance(entry, dict) or set(entry) != set(_RECORD_KEYS):
        raise ValueError(
            f"{field} must be a dict with exactly the keys id, at, decision, trace, basis"
        )
    _check_non_empty_str(entry["id"], f"{field}.id")
    _check_time(entry["at"], f"{field}.at")
    decision = entry["decision"]
    if decision is not None and not isinstance(decision, str):
        raise ValueError(f"{field}.decision must be a string or null")
    trace = entry["trace"]
    if not isinstance(trace, list):
        raise ValueError(f"{field}.trace must be a list of id@ver strings")
    for position, item in enumerate(trace):
        _check_trace_entry(item, f"{field}.trace[{position}]")
    basis = entry["basis"]
    if basis is not None:
        try:
            _validate_rules([basis])
        except ValueError as exc:
            raise ValueError(f"{field}.basis is not a valid rule: {exc}") from exc
        # Normalize the snapshot to the canonical key order in memory so every
        # history method returns the same basis shape; the file is not rewritten.
        entry["basis"] = _snapshot_basis(basis)
    return entry


def _snapshot_basis(rule: dict[str, Any]) -> dict[str, Any]:
    when = rule["when"]
    if when is not None:
        when = {key: when[key] for key in sorted(when)}
    return {
        "id": rule["id"],
        "ver": rule["ver"],
        "source": rule["source"],
        "priority": rule["priority"],
        "from": rule["from"],
        "to": rule["to"],
        "when": when,
        "result": rule["result"],
    }


def _dump(records: list[dict[str, Any]]) -> bytes:
    ordered = sorted(records, key=lambda entry: (entry["id"], entry["at"]))
    text = json.dumps({"records": ordered}, ensure_ascii=False, separators=(",", ":"))
    return (text + "\n").encode("utf-8")


def _audit_digest(previous: str, entry: dict[str, Any]) -> str:
    payload = {key: entry[key] for key in _AUDIT_PAYLOAD_KEYS}
    content = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(previous.encode("ascii") + content.encode("utf-8")).hexdigest()


class DecisionHistory:
    """A JSON-file-backed store of decision records.

    The file is UTF-8 compact JSON (a single trailing newline) holding only a
    ``records`` array sorted by ``(id, at)`` in Unicode code point order.
    """

    def __init__(self, path: str) -> None:
        if not isinstance(path, str) or not path:
            raise ValueError("path must be a non-empty string")
        self._path = path
        self._records: list[dict[str, Any]] = []
        if os.path.exists(path):
            self._records = self._load()
        else:
            self._persist()

    def _load(self) -> list[dict[str, Any]]:
        with open(self._path, encoding="utf-8") as handle:
            try:
                raw = json.load(handle)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{self._path!r} does not contain valid JSON") from exc
        if not isinstance(raw, dict) or set(raw) != {"records"}:
            raise ValueError(f"{self._path!r} must contain only a records array")
        records = raw["records"]
        if not isinstance(records, list):
            raise ValueError(f"{self._path!r}: records must be an array")
        return [_validate_entry(entry, index) for index, entry in enumerate(records)]

    def _persist(self) -> None:
        data = _dump(self._records)
        directory = os.path.dirname(os.path.abspath(self._path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".decision-history-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._path)
        except OSError:
            try:
                os.unlink(tmp)
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
        """Evaluate ``rules`` and persist the outcome under ``(record_id, at)``."""
        _check_non_empty_str(record_id, "record_id")
        matched = _matched_rules(at, facts, rules)
        if any(entry["id"] == record_id and entry["at"] == at for entry in self._records):
            raise ValueError(f"duplicate record for (record_id, at): ({record_id!r}, {at!r})")
        if matched:
            decision: str | None = matched[0]["result"]
            trace = [f"{rule['id']}@{rule['ver']}" for rule in matched]
            basis: dict[str, Any] | None = _snapshot_basis(matched[0])
        else:
            decision = None
            trace = []
            basis = None
        entry = {"id": record_id, "at": at, "decision": decision, "trace": trace, "basis": basis}
        self._records.append(entry)
        try:
            self._persist()
        except OSError:
            self._records.remove(entry)
            raise
        return copy.deepcopy(entry)

    def replay(self, record_id: str, at: str) -> dict[str, Any]:
        """Return a copy of the most recent record for ``record_id`` at or before ``at``."""
        _check_non_empty_str(record_id, "record_id")
        _check_time(at, "at")
        best: dict[str, Any] | None = None
        for entry in self._records:
            if entry["id"] == record_id and entry["at"] <= at:
                if best is None or entry["at"] > best["at"]:
                    best = entry
        if best is None:
            raise KeyError(record_id)
        return copy.deepcopy(best)

    def evolution(self, record_id: str, start: str, end: str) -> dict[str, Any]:
        """Return stored snapshots for ``record_id`` within the closed ``[start, end]``.

        Only already-persisted records are read; nothing is recomputed, written,
        or otherwise mutated. ``record_id`` must be a non-empty string and
        ``start``/``end`` valid UTC seconds with ``start <= end``; otherwise
        ``ValueError`` is raised. Matching records are returned in ascending
        ``at`` order; when none match, ``KeyError`` is raised. The result is a
        deep copy with keys ``id, start, end, entries``; each entry has keys
        ``at, decision, trace, basis, changes``, where ``changes`` lists, in
        the order ``decision, trace, basis``, the fields differing from the
        previous entry (the first entry's ``changes`` is ``[]``).
        """
        _check_non_empty_str(record_id, "record_id")
        _check_time(start, "start")
        _check_time(end, "end")
        if start > end:
            raise ValueError(f"start must not be after end: {start!r} > {end!r}")
        matched = [
            entry
            for entry in self._records
            if entry["id"] == record_id and start <= entry["at"] <= end
        ]
        if not matched:
            raise KeyError(record_id)
        matched.sort(key=lambda entry: entry["at"])
        entries: list[dict[str, Any]] = []
        previous: dict[str, Any] | None = None
        for entry in matched:
            if previous is None:
                changes: list[str] = []
            else:
                changes = [
                    field
                    for field in _EVOLUTION_FIELDS
                    if entry[field] != previous[field]
                ]
            entries.append(
                {
                    "at": entry["at"],
                    "decision": copy.deepcopy(entry["decision"]),
                    "trace": copy.deepcopy(entry["trace"]),
                    "basis": copy.deepcopy(entry["basis"]),
                    "changes": changes,
                }
            )
            previous = entry
        return {"id": record_id, "start": start, "end": end, "entries": entries}

    def audit(self, record_id: str, start: str, end: str) -> dict[str, Any]:
        """Return a hash-chained audit trail for ``record_id`` over ``[start, end]``.

        Only already-persisted records are read; nothing is recomputed, written,
        or otherwise mutated. ``record_id`` must be a non-empty string and
        ``start``/``end`` valid UTC seconds with ``start <= end``; otherwise
        ``ValueError`` is raised. Matching records are returned in ascending
        ``at`` order; when none match, ``KeyError`` is raised. The result is a
        deep copy with keys ``id, start, end, root, entries``; each entry has
        keys ``at, decision, trace, basis, previous, digest``, the first four
        following the record contract.

        Let ``C`` be the UTF-8 compact JSON bytes (non-ASCII unescaped, no
        trailing newline) of the current entry restricted to
        ``at, decision, trace, basis`` in that key order. The first entry's
        ``previous`` is 64 ASCII ``0`` characters; every later entry's
        ``previous`` is the preceding entry's ``digest``. ``digest`` is the
        lowercase hexadecimal SHA-256 of ``previous``'s ASCII bytes immediately
        followed by ``C``; ``root`` is the last entry's ``digest``.
        """
        _check_non_empty_str(record_id, "record_id")
        _check_time(start, "start")
        _check_time(end, "end")
        if start > end:
            raise ValueError(f"start must not be after end: {start!r} > {end!r}")
        matched = [
            entry
            for entry in self._records
            if entry["id"] == record_id and start <= entry["at"] <= end
        ]
        if not matched:
            raise KeyError(record_id)
        matched.sort(key=lambda entry: entry["at"])
        entries: list[dict[str, Any]] = []
        previous = _AUDIT_GENESIS
        for entry in matched:
            digest = _audit_digest(previous, entry)
            entries.append(
                {
                    "at": entry["at"],
                    "decision": copy.deepcopy(entry["decision"]),
                    "trace": copy.deepcopy(entry["trace"]),
                    "basis": copy.deepcopy(entry["basis"]),
                    "previous": previous,
                    "digest": digest,
                }
            )
            previous = digest
        return {
            "id": record_id,
            "start": start,
            "end": end,
            "root": previous,
            "entries": entries,
        }
