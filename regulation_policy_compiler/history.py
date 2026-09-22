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
_AUDIT_ENTRY_KEYS = ("at", "decision", "trace", "basis", "previous", "digest")
_AUDIT_REPORT_KEYS = ("id", "start", "end", "root", "entries")
_AUDIT_EXPECTED_KEYS = ("id", "start", "end", "root")
_AUDIT_GENESIS = "0" * 64
_HEX_DIGITS = frozenset("0123456789abcdef")


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


def _check_hex64(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in _HEX_DIGITS for char in value)
    ):
        raise ValueError(f"{field} must be 64 lowercase hexadecimal characters")
    return value


def _check_time_window(start: Any, end: Any, field: str) -> None:
    _check_time(start, f"{field}.start")
    _check_time(end, f"{field}.end")
    if start > end:
        raise ValueError(f"{field}.start must not be after {field}.end")


def _validate_audit_entry(entry: Any, index: int) -> dict[str, Any]:
    """Validate one audit entry and return a normalized deep copy of it."""
    field = f"entries[{index}]"
    if not isinstance(entry, dict) or set(entry) != set(_AUDIT_ENTRY_KEYS):
        raise ValueError(
            f"{field} must be a dict with exactly the keys "
            "at, decision, trace, basis, previous, digest"
        )
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
        basis = _snapshot_basis(basis)
    _check_hex64(entry["previous"], f"{field}.previous")
    _check_hex64(entry["digest"], f"{field}.digest")
    return {
        "at": entry["at"],
        "decision": copy.deepcopy(decision),
        "trace": copy.deepcopy(trace),
        "basis": basis,
        "previous": entry["previous"],
        "digest": entry["digest"],
    }


def verify_audit(report: Any, expected: Any) -> bool:
    """Verify an audit report against an expected summary by recomputation.

    ``report`` must be a dict with exactly the keys ``id, start, end, root,
    entries``; ``id`` a non-empty string, ``start``/``end`` valid UTC seconds
    with ``start <= end``, and ``entries`` a non-empty list whose ``at``
    values are strictly increasing and lie in the closed interval
    ``[start, end]``. Each entry must have exactly the keys ``at, decision,
    trace, basis, previous, digest``; the first four follow the audit entry
    contract, and ``previous``/``digest`` must be 64 lowercase hexadecimal
    characters. ``expected`` must have exactly the keys ``id, start, end,
    root`` and is validated the same way. Any violation raises ``ValueError``.

    Returns ``False`` when the shared fields differ between ``report`` and
    ``expected``. Otherwise each entry's ``basis`` (and its ``when`` keys) is
    normalized to the canonical key order and the chain is recomputed exactly
    as :meth:`DecisionHistory.audit` defines it: the first ``previous`` is 64
    ASCII ``0`` characters, every later ``previous`` is the preceding entry's
    ``digest``, and ``digest`` is the lowercase hexadecimal SHA-256 of
    ``previous``'s ASCII bytes immediately followed by ``C``. Any chain,
    digest, or root mismatch returns ``False``; otherwise ``True``.

    The function touches neither history nor files and does not mutate its
    inputs.
    """
    if not isinstance(report, dict) or set(report) != set(_AUDIT_REPORT_KEYS):
        raise ValueError(
            "report must be a dict with exactly the keys id, start, end, root, entries"
        )
    _check_non_empty_str(report["id"], "report.id")
    _check_time_window(report["start"], report["end"], "report")
    _check_hex64(report["root"], "report.root")
    entries = report["entries"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("report.entries must be a non-empty list")
    normalized: list[dict[str, Any]] = []
    previous_at: str | None = None
    for index, entry in enumerate(entries):
        normalized.append(_validate_audit_entry(entry, index))
        at = entry["at"]
        if previous_at is not None and at <= previous_at:
            raise ValueError("report.entries must be strictly increasing in at")
        if not report["start"] <= at <= report["end"]:
            raise ValueError(f"entries[{index}].at lies outside [start, end]")
        previous_at = at
    if not isinstance(expected, dict) or set(expected) != set(_AUDIT_EXPECTED_KEYS):
        raise ValueError(
            "expected must be a dict with exactly the keys id, start, end, root"
        )
    _check_non_empty_str(expected["id"], "expected.id")
    _check_time_window(expected["start"], expected["end"], "expected")
    _check_hex64(expected["root"], "expected.root")
    for key in _AUDIT_EXPECTED_KEYS:
        if report[key] != expected[key]:
            return False
    previous = _AUDIT_GENESIS
    for entry in normalized:
        if entry["previous"] != previous:
            return False
        if entry["digest"] != _audit_digest(previous, entry):
            return False
        previous = entry["digest"]
    return report["root"] == previous


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

    def audit_bundle(self, record_ids: Any, start: str, end: str) -> dict[str, Any]:
        """Return one hash-chained bundle of audit reports over ``[start, end]``.

        Only already-persisted records are read; nothing is recomputed,
        written, or otherwise mutated. ``record_ids`` must be a non-empty list
        of unique non-empty strings and ``start``/``end`` valid UTC seconds
        with ``start <= end``; otherwise ``ValueError`` is raised and the
        inputs are left untouched. Each id is audited once in ascending
        Unicode code point order; if any id has no record in the closed
        interval, ``KeyError`` is raised and no partial result is returned.

        The result is a deep copy with keys ``start, end, root, reports``;
        ``reports`` holds each id's complete audit result in that same order,
        preserving the per-report contract. Let ``h0`` be 64 ASCII ``0``
        characters and ``Pi`` the UTF-8 compact JSON bytes (non-ASCII
        unescaped, no trailing newline) of the i-th report restricted to
        ``id, root`` in that key order. ``hi`` is the lowercase hexadecimal
        SHA-256 of ``h{i-1}``'s ASCII bytes immediately followed by ``Pi``;
        the bundle ``root`` is ``hn``.
        """
        if not isinstance(record_ids, list) or not record_ids:
            raise ValueError("record_ids must be a non-empty list of record id strings")
        seen: set[str] = set()
        for index, record_id in enumerate(record_ids):
            _check_non_empty_str(record_id, f"record_ids[{index}]")
            if record_id in seen:
                raise ValueError(
                    f"record_ids must not contain duplicates: {record_id!r}"
                )
            seen.add(record_id)
        _check_time(start, "start")
        _check_time(end, "end")
        if start > end:
            raise ValueError(f"start must not be after end: {start!r} > {end!r}")
        reports = [
            self.audit(record_id, start, end)
            for record_id in sorted(record_ids)
        ]
        root = _AUDIT_GENESIS
        for report in reports:
            payload = json.dumps(
                {"id": report["id"], "root": report["root"]},
                ensure_ascii=False,
                separators=(",", ":"),
            )
            root = hashlib.sha256(
                root.encode("ascii") + payload.encode("utf-8")
            ).hexdigest()
        return copy.deepcopy(
            {"start": start, "end": end, "root": root, "reports": reports}
        )
