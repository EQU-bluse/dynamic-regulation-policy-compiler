"""Deterministic evaluation of versioned regulation and organization rules."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime
from functools import cmp_to_key
from typing import Any

_TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_RULE_KEYS = frozenset({"id", "ver", "source", "priority", "from", "to", "when", "result"})
_SOURCES = ("law", "org")


def _check_time(value: Any, field: str) -> str:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be a UTC timestamp of the form YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid calendar time: {value!r}") from exc
    return value


def _check_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer (bool is not accepted)")
    return value


def _check_non_empty_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _check_fact_map(value: Any, field: str) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a dict[str, bool]")
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise ValueError(f"{field} keys must be non-empty strings")
        if not isinstance(item, bool):
            raise ValueError(f"{field} values must be bool")
    return value


def _validate_rules(rules: Any) -> list[dict[str, Any]]:
    if not isinstance(rules, list):
        raise ValueError("rules must be a list of rule dicts")
    seen: set[tuple[str, str, int]] = set()
    for index, rule in enumerate(rules):
        field = f"rules[{index}]"
        if not isinstance(rule, dict) or set(rule) != _RULE_KEYS:
            raise ValueError(
                f"{field} must be a dict with exactly the keys "
                "id, ver, source, priority, from, to, when, result"
            )
        _check_non_empty_str(rule["id"], f"{field}.id")
        _check_non_empty_str(rule["result"], f"{field}.result")
        ver = _check_int(rule["ver"], f"{field}.ver")
        if ver < 1:
            raise ValueError(f"{field}.ver must be a positive integer")
        source = rule["source"]
        if source not in _SOURCES:
            raise ValueError(f"{field}.source must be 'law' or 'org'")
        _check_int(rule["priority"], f"{field}.priority")
        frm = _check_time(rule["from"], f"{field}.from")
        to = rule["to"]
        if to is not None:
            _check_time(to, f"{field}.to")
            if not frm < to:
                raise ValueError(f"{field} requires from < to")
        when = rule["when"]
        if when is not None:
            _check_fact_map(when, f"{field}.when")
        key = (source, rule["id"], ver)
        if key in seen:
            raise ValueError(f"duplicate (source, id, ver): {key!r}")
        seen.add(key)
    return rules


def _compare(a: dict[str, Any], b: dict[str, Any]) -> int:
    if a["source"] != b["source"]:
        return -1 if a["source"] == "law" else 1
    if a["priority"] != b["priority"]:
        return -1 if a["priority"] > b["priority"] else 1
    if a["from"] != b["from"]:
        return -1 if a["from"] > b["from"] else 1
    if a["id"] != b["id"]:
        return -1 if a["id"] < b["id"] else 1
    if a["ver"] != b["ver"]:
        return -1 if a["ver"] > b["ver"] else 1
    return 0


def _effective_rules(at: str, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate, select effective-at-``at`` rules, keep the highest ver per
    ``(source, id)``, and rank them exactly as :func:`evaluate` does."""
    _check_time(at, "at")
    rules = _validate_rules(rules)

    effective = [
        rule
        for rule in rules
        if rule["from"] <= at and (rule["to"] is None or at < rule["to"])
    ]

    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for rule in effective:
        key = (rule["source"], rule["id"])
        if key not in latest or rule["ver"] > latest[key]["ver"]:
            latest[key] = rule

    ranked = list(latest.values())
    ranked.sort(key=cmp_to_key(_compare))
    return ranked


def _matches(rule: dict[str, Any], facts: dict[str, bool]) -> bool:
    """Return whether ``rule``'s ``when`` condition holds under ``facts``."""
    when = rule["when"]
    return when is None or all(
        key in facts and facts[key] == value for key, value in when.items()
    )


def _matched_rules(
    at: str, facts: dict[str, bool], rules: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return the matching rules in ranking order after validation.

    Validation, latest-version selection, and ordering are exactly those of
    :func:`evaluate`.
    """
    _check_fact_map(facts, "facts")
    ranked = _effective_rules(at, rules)
    return [rule for rule in ranked if _matches(rule, facts)]


def evaluate(
    at: str, facts: dict[str, bool], rules: list[dict[str, Any]]
) -> tuple[str | None, list[str]]:
    """Evaluate versioned rules against facts at a UTC second timestamp.

    Returns ``(decision, trace)`` where ``trace`` lists every matching rule as
    ``id@ver`` in ranking order and ``decision`` is the top rule's ``result``
    (``None`` with an empty trace when nothing matches).
    """
    matched = _matched_rules(at, facts, rules)
    if not matched:
        return None, []
    trace = [f"{rule['id']}@{rule['ver']}" for rule in matched]
    return matched[0]["result"], trace


def _conditions_compatible(a: dict[str, bool] | None, b: dict[str, bool] | None) -> bool:
    """Return whether two ``when`` conditions can hold simultaneously.

    ``None`` means unconstrained. Conditions are incompatible only when they
    assign opposite booleans to a shared key.
    """
    if a is None or b is None:
        return True
    for key, value in a.items():
        if key in b and b[key] is not value:
            return False
    return True


def _snapshot_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """Return a deep-copied rule snapshot with stable key order.

    Keys are ordered ``id, ver, source, priority, from, to, when, result``
    and ``when`` keys are sorted in Unicode code point order.
    """
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


def _find_conflicts(ranked: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """List conflicts between ranked rules as ``winner``/``loser`` triples.

    For ranked indices ``i < j``, a pair conflicts when the results differ
    and the ``when`` conditions can hold simultaneously; the earlier rule is
    the winner.
    """
    conflicts: list[dict[str, Any]] = []
    for i in range(len(ranked)):
        winner = ranked[i]
        for j in range(i + 1, len(ranked)):
            loser = ranked[j]
            if winner["result"] != loser["result"] and _conditions_compatible(
                winner["when"], loser["when"]
            ):
                conflicts.append(
                    {
                        "winner": [winner["source"], winner["id"], winner["ver"]],
                        "loser": [loser["source"], loser["id"], loser["ver"]],
                    }
                )
    return conflicts


def compile_rules(at: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Compile the rules effective at ``at`` into rules and conflicts.

    Reuses the full validation of :func:`evaluate` for ``at`` and ``rules``
    (raising ``ValueError`` on anything invalid), keeps rules in their
    ``[from, to)`` window, retains only the highest ``ver`` per
    ``(source, id)``, and orders the survivors with :func:`evaluate`'s ranking.

    ``conflicts`` lists, for ranked indices ``i < j``, pairs whose results
    differ and whose ``when`` conditions can hold simultaneously; the earlier
    rule is the winner. The returned structure is a deep copy with stable key
    order.
    """
    ranked = _effective_rules(at, rules)
    compiled_rules = [_snapshot_rule(rule) for rule in ranked]
    conflicts = _find_conflicts(ranked)
    return {"at": at, "rules": compiled_rules, "conflicts": conflicts}


def policy_attestation(at: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Attest a :func:`compile_rules` result with a SHA-256 digest.

    ``at`` and ``rules`` are validated exactly as in :func:`compile_rules`;
    any type, time, rule-field, ``[from, to)`` interval, or duplicate
    ``(source, id, ver)`` error raises ``ValueError`` without mutating the
    inputs.

    Let ``policy`` be the :func:`compile_rules` result and let ``C`` be the
    UTF-8 bytes of ``json.dumps(policy, ensure_ascii=False,
    separators=(',', ':'))`` (with no trailing newline). Returns a deep copy
    with keys ``at``, ``policy``, ``digest``; ``policy`` keeps every
    :func:`compile_rules` key order, ordering, ``when`` Unicode code point
    sort, and ``conflicts`` order, and ``digest`` is the lowercase 64-char
    hex SHA-256 of ``C``. Equal-valued inputs yield byte-identical results.
    """
    policy = compile_rules(at, rules)
    canonical = json.dumps(policy, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {"at": at, "policy": copy.deepcopy(policy), "digest": digest}


_SOURCE_ORDER = {"law": 0, "org": 1}


def _conflict_identity(conflict: dict[str, Any]) -> tuple[str, str, int, str, str, int]:
    """Return the six-element identity of a conflict: winner then loser."""
    return tuple(conflict["winner"]) + tuple(conflict["loser"])


def policy_delta(
    from_at: str, to_at: str, rules: list[dict[str, Any]]
) -> dict[str, Any]:
    """Diff the :func:`compile_rules` results at two UTC timestamps.

    Both timestamps must be valid UTC seconds of the form
    ``YYYY-MM-DDTHH:MM:SSZ`` with ``from_at <= to_at``; ``rules`` is
    validated exactly as in :func:`compile_rules`. Any type, time,
    rule-structure, or ordering violation raises ``ValueError`` without
    mutating the inputs.

    The rules effective at each timestamp are compiled separately and
    identified by ``(source, id)``. Returns a deep copy with keys ``from``,
    ``to``, ``rules``, ``conflicts``. ``rules`` lists, ordered by ``source``
    (``law`` before ``org``) then ``id`` in Unicode code point order, one
    entry per rule that was ``added`` (only at ``to_at``), ``removed`` (only
    at ``from_at``), or ``updated`` (present at both but with a different
    compiled value); identical rules are omitted. Each entry has keys
    ``source``, ``id``, ``kind``, ``before``, ``after``; ``before``/``after``
    are the corresponding compiled rule snapshots (with :func:`compile_rules`
    key order and ``when`` sorting) or ``None``.

    ``conflicts`` has keys ``added``, ``removed``. A conflict's identity is
    the six-element value of its ``winner`` array followed by its ``loser``
    array. ``added`` lists, in the ``to_at`` compile order, the conflicts
    present only at ``to_at``; ``removed`` lists, in the ``from_at`` compile
    order, those present only at ``from_at``. Each conflict keeps the keys
    ``winner``, ``loser`` with deep-copied values. When nothing differs,
    ``rules`` is empty and both conflict arrays are empty.
    """
    _check_time(from_at, "from_at")
    _check_time(to_at, "to_at")
    if from_at > to_at:
        raise ValueError(f"from_at must not be after to_at: {from_at!r} > {to_at!r}")
    before_compiled = compile_rules(from_at, rules)
    after_compiled = compile_rules(to_at, rules)

    before_rules = {
        (rule["source"], rule["id"]): rule for rule in before_compiled["rules"]
    }
    after_rules = {
        (rule["source"], rule["id"]): rule for rule in after_compiled["rules"]
    }
    entries: list[dict[str, Any]] = []
    for key in sorted(
        set(before_rules) | set(after_rules),
        key=lambda item: (_SOURCE_ORDER[item[0]], item[1]),
    ):
        before = before_rules.get(key)
        after = after_rules.get(key)
        if before is not None and after is not None and before == after:
            continue
        if before is None:
            kind = "added"
        elif after is None:
            kind = "removed"
        else:
            kind = "updated"
        entries.append(
            {
                "source": key[0],
                "id": key[1],
                "kind": kind,
                "before": before,
                "after": after,
            }
        )

    before_conflicts = before_compiled["conflicts"]
    after_conflicts = after_compiled["conflicts"]
    before_identities = {_conflict_identity(c) for c in before_conflicts}
    after_identities = {_conflict_identity(c) for c in after_conflicts}
    added_conflicts = [
        {"winner": list(c["winner"]), "loser": list(c["loser"])}
        for c in after_conflicts
        if _conflict_identity(c) not in before_identities
    ]
    removed_conflicts = [
        {"winner": list(c["winner"]), "loser": list(c["loser"])}
        for c in before_conflicts
        if _conflict_identity(c) not in after_identities
    ]
    return {
        "from": from_at,
        "to": to_at,
        "rules": entries,
        "conflicts": {"added": added_conflicts, "removed": removed_conflicts},
    }


def policy_schedule(
    start: str, end: str, rules: list[dict[str, Any]]
) -> dict[str, Any]:
    """Compile the policy at the rule boundaries inside a time range.

    ``start`` and ``end`` must be valid UTC seconds of the form
    ``YYYY-MM-DDTHH:MM:SSZ`` with ``start <= end``; ``rules`` is validated
    exactly as in :func:`compile_rules`. Any type, time, rule-structure, or
    ordering violation raises ``ValueError`` without mutating the inputs.

    The candidate timestamps are ``start`` plus every rule ``from`` and
    non-``None`` ``to`` falling in ``(start, end]``, deduplicated and sorted
    ascending; :func:`compile_rules` is called at each candidate. The first
    point is always kept; for each later candidate the function computes
    :func:`policy_delta` from the previously kept point to the candidate and
    keeps the point unless that delta reports no changes at all (``rules``
    empty and both ``conflicts`` arrays empty).

    Returns a deep copy with keys ``start``, ``end``, ``points``. Each point
    has keys ``at``, ``rules``, ``conflicts``, ``delta``; ``rules`` and
    ``conflicts`` are exactly the same-named :func:`compile_rules` values at
    ``at`` and keep that contract at every level. The first point's ``delta``
    is ``None``; a later point's ``delta`` is the full :func:`policy_delta`
    result described above.
    """
    _check_time(start, "start")
    _check_time(end, "end")
    if start > end:
        raise ValueError(f"start must not be after end: {start!r} > {end!r}")
    _validate_rules(rules)
    first = compile_rules(start, rules)
    candidates = {start}
    for rule in rules:
        for boundary in (rule["from"], rule["to"]):
            if boundary is not None and start < boundary <= end:
                candidates.add(boundary)
    points = [
        {
            "at": first["at"],
            "rules": first["rules"],
            "conflicts": first["conflicts"],
            "delta": None,
        }
    ]
    previous_at = start
    for at in sorted(candidates - {start}):
        compiled = compile_rules(at, rules)
        delta = policy_delta(previous_at, at, rules)
        if (
            not delta["rules"]
            and not delta["conflicts"]["added"]
            and not delta["conflicts"]["removed"]
        ):
            continue
        points.append(
            {
                "at": compiled["at"],
                "rules": compiled["rules"],
                "conflicts": compiled["conflicts"],
                "delta": delta,
            }
        )
        previous_at = at
    return {"start": start, "end": end, "points": points}


def policy_schedule_attestation(
    start: str, end: str, rules: list[dict[str, Any]]
) -> dict[str, Any]:
    """Attest a :func:`policy_schedule` result with a SHA-256 hash chain.

    ``start``, ``end``, and ``rules`` are validated exactly as in
    :func:`policy_schedule`; any invalid value raises ``ValueError`` without
    mutating the inputs.

    Let ``S`` be the :func:`policy_schedule` result. Returns a deep copy with
    top-level keys ``start``, ``end``, ``root``, ``points``; ``start`` and
    ``end`` come from ``S`` and ``points`` keeps ``S``'s point order. Each
    point has keys ``at``, ``rules``, ``conflicts``, ``delta``, ``previous``,
    ``digest``; the first four equal the corresponding ``S`` point at every
    level and keep its key order. The first point's ``previous`` is 64 ASCII
    ``0`` characters; every later point's ``previous`` is the previous
    point's ``digest``.

    Let ``C`` be the UTF-8 bytes (with no newline) of
    ``json.dumps`` applied to the current point restricted to the keys
    ``at``, ``rules``, ``conflicts``, ``delta`` in that order, with
    ``ensure_ascii=False`` and ``separators=(',', ':')``. ``digest`` is the
    lowercase 64-char hex SHA-256 of the ASCII bytes of ``previous`` followed
    immediately by ``C``; ``root`` is the last point's ``digest``.
    Equal-valued inputs yield byte-identical results.
    """
    schedule = policy_schedule(start, end, rules)
    points: list[dict[str, Any]] = []
    previous = "0" * 64
    digest = previous
    for point in schedule["points"]:
        content = {
            "at": point["at"],
            "rules": copy.deepcopy(point["rules"]),
            "conflicts": copy.deepcopy(point["conflicts"]),
            "delta": copy.deepcopy(point["delta"]),
        }
        canonical = json.dumps(content, ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(
            previous.encode("ascii") + canonical.encode("utf-8")
        ).hexdigest()
        attested = dict(content)
        attested["previous"] = previous
        attested["digest"] = digest
        points.append(attested)
        previous = digest
    return {
        "start": schedule["start"],
        "end": schedule["end"],
        "root": digest,
        "points": points,
    }


_SCHEDULE_ATTEST_REPORT_KEYS = ("start", "end", "root", "points")
_SCHEDULE_ATTEST_EXPECTED_KEYS = ("start", "end", "root")
_SCHEDULE_POINT_KEYS = (
    "at",
    "rules",
    "conflicts",
    "delta",
    "previous",
    "digest",
)
_SCHEDULE_POINT_CONTENT_KEYS = ("at", "rules", "conflicts", "delta")
_SCHEDULE_GENESIS = "0" * 64
_SCHEDULE_HEX_DIGITS = frozenset("0123456789abcdef")
_CONFLICT_KEYS = frozenset({"winner", "loser"})
_DELTA_KEYS = frozenset({"from", "to", "rules", "conflicts"})
_DELTA_ENTRY_KEYS = frozenset({"source", "id", "kind", "before", "after"})
_DELTA_DELTA_KEYS = frozenset({"added", "removed"})
_DELTA_KINDS = frozenset({"added", "removed", "updated"})


def _check_schedule_hex64(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in _SCHEDULE_HEX_DIGITS for char in value)
    ):
        raise ValueError(f"{field} must be 64 lowercase hexadecimal characters")
    return value


def _normalize_conflict_party(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list) or len(value) != 3:
        raise ValueError(f"{field} must be a [source, id, ver] triple")
    source, rule_id, ver = value
    if source not in _SOURCES:
        raise ValueError(f"{field} source must be 'law' or 'org'")
    _check_non_empty_str(rule_id, f"{field} id")
    _check_int(ver, f"{field} ver")
    if ver < 1:
        raise ValueError(f"{field} ver must be a positive integer")
    return [source, rule_id, ver]


def _normalize_conflicts(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list of conflict dicts")
    conflicts: list[dict[str, Any]] = []
    for index, conflict in enumerate(value):
        item_field = f"{field}[{index}]"
        if not isinstance(conflict, dict) or set(conflict) != _CONFLICT_KEYS:
            raise ValueError(
                f"{item_field} must be a dict with exactly the keys winner, loser"
            )
        conflicts.append(
            {
                "winner": _normalize_conflict_party(
                    conflict["winner"], f"{item_field}.winner"
                ),
                "loser": _normalize_conflict_party(
                    conflict["loser"], f"{item_field}.loser"
                ),
            }
        )
    return conflicts


def _normalize_optional_rule(value: Any, field: str) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        _validate_rules([value])
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid rule snapshot or null") from exc
    return _snapshot_rule(value)


def _normalize_delta(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _DELTA_KEYS:
        raise ValueError(
            f"{field} must be a dict with exactly the keys from, to, rules, conflicts"
        )
    frm = _check_time(value["from"], f"{field}.from")
    to = _check_time(value["to"], f"{field}.to")
    if frm > to:
        raise ValueError(f"{field}.from must not be after {field}.to")
    raw_entries = value["rules"]
    if not isinstance(raw_entries, list):
        raise ValueError(f"{field}.rules must be a list of delta entry dicts")
    entries: list[dict[str, Any]] = []
    for index, entry in enumerate(raw_entries):
        entry_field = f"{field}.rules[{index}]"
        if not isinstance(entry, dict) or set(entry) != _DELTA_ENTRY_KEYS:
            raise ValueError(
                f"{entry_field} must be a dict with exactly the keys "
                "source, id, kind, before, after"
            )
        source = entry["source"]
        if source not in _SOURCES:
            raise ValueError(f"{entry_field}.source must be 'law' or 'org'")
        rule_id = _check_non_empty_str(entry["id"], f"{entry_field}.id")
        kind = entry["kind"]
        if kind not in _DELTA_KINDS:
            raise ValueError(
                f"{entry_field}.kind must be 'added', 'removed', or 'updated'"
            )
        before = _normalize_optional_rule(entry["before"], f"{entry_field}.before")
        after = _normalize_optional_rule(entry["after"], f"{entry_field}.after")
        if kind == "added" and (before is not None or after is None):
            raise ValueError(
                f"{entry_field} is 'added' but before/after do not match the contract"
            )
        if kind == "removed" and (before is None or after is not None):
            raise ValueError(
                f"{entry_field} is 'removed' but before/after do not match the contract"
            )
        if kind == "updated" and (before is None or after is None):
            raise ValueError(
                f"{entry_field} is 'updated' but before/after do not match the contract"
            )
        entries.append(
            {
                "source": source,
                "id": rule_id,
                "kind": kind,
                "before": before,
                "after": after,
            }
        )
    raw_conflicts = value["conflicts"]
    if not isinstance(raw_conflicts, dict) or set(raw_conflicts) != _DELTA_DELTA_KEYS:
        raise ValueError(
            f"{field}.conflicts must be a dict with exactly the keys added, removed"
        )
    return {
        "from": frm,
        "to": to,
        "rules": entries,
        "conflicts": {
            "added": _normalize_conflicts(
                raw_conflicts["added"], f"{field}.conflicts.added"
            ),
            "removed": _normalize_conflicts(
                raw_conflicts["removed"], f"{field}.conflicts.removed"
            ),
        },
    }


def _normalize_schedule_point(
    point: Any,
    index: int,
    start: str,
    end: str,
    previous_at: str | None,
) -> tuple[dict[str, Any], str]:
    """Validate one attestation point and return its normalized copy and ``at``."""
    field = f"points[{index}]"
    if not isinstance(point, dict) or set(point) != set(_SCHEDULE_POINT_KEYS):
        raise ValueError(
            f"{field} must be a dict with exactly the keys "
            "at, rules, conflicts, delta, previous, digest"
        )
    at = _check_time(point["at"], f"{field}.at")
    if not start <= at <= end:
        raise ValueError(f"{field}.at lies outside [start, end]")
    if index == 0:
        if at != start:
            raise ValueError("points[0].at must equal start")
    elif at <= previous_at:  # type: ignore[operator]
        raise ValueError("points must be strictly increasing in at")
    try:
        _validate_rules(point["rules"])
    except ValueError as exc:
        raise ValueError(f"{field}.rules are not valid rule snapshots: {exc}") from exc
    rules = [_snapshot_rule(rule) for rule in point["rules"]]
    conflicts = _normalize_conflicts(point["conflicts"], f"{field}.conflicts")
    raw_delta = point["delta"]
    if index == 0:
        if raw_delta is not None:
            raise ValueError("points[0].delta must be null")
        delta: dict[str, Any] | None = None
    else:
        if raw_delta is None:
            raise ValueError(f"{field}.delta must be a policy_delta result")
        delta = _normalize_delta(raw_delta, f"{field}.delta")
    previous = _check_schedule_hex64(point["previous"], f"{field}.previous")
    digest = _check_schedule_hex64(point["digest"], f"{field}.digest")
    normalized = {
        "at": at,
        "rules": rules,
        "conflicts": conflicts,
        "delta": delta,
        "previous": previous,
        "digest": digest,
    }
    return normalized, at


def verify_policy_schedule_attestation(report: Any, expected: Any) -> bool:
    """Verify a :func:`policy_schedule_attestation` report by recomputation.

    ``report`` must be a dict with exactly the keys ``start, end, root,
    points``; ``start``/``end`` valid UTC seconds with ``start <= end``,
    ``root`` 64 lowercase hexadecimal characters, and ``points`` a non-empty
    list conforming level by level to the :func:`policy_schedule_attestation`
    contract (exact key sets, types, and value domains, including the
    :func:`compile_rules` rule/conflict shapes and the :func:`policy_delta`
    delta shape). The points' ``at`` values must be strictly increasing, lie
    in the closed interval ``[start, end]``, and the first point must have
    ``at == start`` and ``delta == null``; later points must carry a full
    delta. Each point's ``previous``/``digest`` must be 64 lowercase
    hexadecimal characters. ``expected`` must have exactly the keys
    ``start, end, root`` and is validated the same way. Any violation raises
    ``ValueError`` without mutating the inputs.

    Every dict is rebuilt in the contract key order (rule ``when`` keys in
    Unicode code point order) and the hash chain is recomputed exactly as
    :func:`policy_schedule_attestation` defines it: the first ``previous`` is
    64 ASCII ``0`` characters, every later ``previous`` is the preceding
    point's ``digest``, and each ``digest`` is the lowercase hexadecimal
    SHA-256 of ``previous``'s ASCII bytes immediately followed by the point's
    compact-JSON ``C`` over ``at, rules, conflicts, delta`` in that order.

    Returns ``False`` when ``report`` and ``expected`` differ in ``start``,
    ``end``, or ``root``, or when any chain link, digest, or the final root
    does not match; otherwise ``True``. The function is pure: it touches no
    files and does not mutate its inputs.
    """
    if not isinstance(report, dict) or set(report) != set(
        _SCHEDULE_ATTEST_REPORT_KEYS
    ):
        raise ValueError(
            "report must be a dict with exactly the keys start, end, root, points"
        )
    start = _check_time(report["start"], "report.start")
    end = _check_time(report["end"], "report.end")
    if start > end:
        raise ValueError("report.start must not be after report.end")
    _check_schedule_hex64(report["root"], "report.root")
    points = report["points"]
    if not isinstance(points, list) or not points:
        raise ValueError("report.points must be a non-empty list")
    normalized_points: list[dict[str, Any]] = []
    previous_at: str | None = None
    for index, point in enumerate(points):
        normalized, at = _normalize_schedule_point(
            point, index, start, end, previous_at
        )
        normalized_points.append(normalized)
        previous_at = at
    if not isinstance(expected, dict) or set(expected) != set(
        _SCHEDULE_ATTEST_EXPECTED_KEYS
    ):
        raise ValueError(
            "expected must be a dict with exactly the keys start, end, root"
        )
    expected_start = _check_time(expected["start"], "expected.start")
    expected_end = _check_time(expected["end"], "expected.end")
    if expected_start > expected_end:
        raise ValueError("expected.start must not be after expected.end")
    _check_schedule_hex64(expected["root"], "expected.root")
    if (
        start != expected_start
        or end != expected_end
        or report["root"] != expected["root"]
    ):
        return False
    previous = _SCHEDULE_GENESIS
    for point in normalized_points:
        if point["previous"] != previous:
            return False
        content = {key: point[key] for key in _SCHEDULE_POINT_CONTENT_KEYS}
        canonical = json.dumps(content, ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(
            previous.encode("ascii") + canonical.encode("utf-8")
        ).hexdigest()
        if point["digest"] != digest:
            return False
        previous = digest
    return report["root"] == previous


def explain(
    at: str, facts: dict[str, bool], rules: list[dict[str, Any]]
) -> dict[str, Any]:
    """Explain the decision :func:`evaluate` reaches for the same inputs.

    Applies exactly :func:`evaluate`'s validation (raising ``ValueError`` on
    anything invalid), effective-window selection, latest-version retention,
    ranking, and matching, without mutating the inputs. The result is a deep
    copy with keys ``at``, ``decision``, ``trace``, ``basis``, ``conflicts``;
    ``decision`` and ``trace`` are exactly :func:`evaluate`'s outputs.

    When nothing matches, ``basis`` is ``None`` and ``conflicts`` is empty.
    Otherwise ``basis`` is a snapshot of the top-ranked matching rule and
    ``conflicts`` keeps, in original order, the :func:`compile_rules`
    conflicts whose winner or loser equals
    ``[basis.source, basis.id, basis.ver]``.
    """
    _check_fact_map(facts, "facts")
    ranked = _effective_rules(at, rules)
    matched = [rule for rule in ranked if _matches(rule, facts)]
    if not matched:
        return {"at": at, "decision": None, "trace": [], "basis": None, "conflicts": []}
    basis = _snapshot_rule(matched[0])
    basis_key = [basis["source"], basis["id"], basis["ver"]]
    conflicts = [
        conflict
        for conflict in _find_conflicts(ranked)
        if conflict["winner"] == basis_key or conflict["loser"] == basis_key
    ]
    trace = [f"{rule['id']}@{rule['ver']}" for rule in matched]
    return {
        "at": at,
        "decision": matched[0]["result"],
        "trace": trace,
        "basis": basis,
        "conflicts": conflicts,
    }


_COMPARE_FIELDS = ("decision", "trace", "basis", "conflicts")


def compare_decisions(
    from_at: str,
    to_at: str,
    facts: dict[str, bool],
    rules: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compare the decisions :func:`explain` reaches at two UTC timestamps.

    Both timestamps must be valid UTC seconds of the form
    ``YYYY-MM-DDTHH:MM:SSZ`` with ``from_at <= to_at``; ``facts`` and
    ``rules`` are validated exactly as in :func:`explain`. Any type, time,
    rule-structure, or ordering violation raises ``ValueError`` without
    mutating the inputs.

    Returns a deep copy with keys ``from``, ``to``, ``changes``, ``before``,
    ``after``. ``before``/``after`` are the full :func:`explain` results for
    ``from_at``/``to_at`` and are independent of each other. ``changes``
    lists, in the order ``decision``, ``trace``, ``basis``, ``conflicts``,
    the fields whose values differ between the two snapshots (empty when the
    snapshots are identical).
    """
    _check_time(from_at, "from_at")
    _check_time(to_at, "to_at")
    if from_at > to_at:
        raise ValueError(f"from_at must not be after to_at: {from_at!r} > {to_at!r}")
    before = explain(from_at, facts, rules)
    after = explain(to_at, facts, rules)
    changes = [field for field in _COMPARE_FIELDS if before[field] != after[field]]
    return {
        "from": from_at,
        "to": to_at,
        "changes": changes,
        "before": before,
        "after": after,
    }


def decision_timeline(
    start: str,
    end: str,
    facts: dict[str, bool],
    rules: list[dict[str, Any]],
) -> dict[str, Any]:
    """Explain how the decision evolves across the rule boundaries in a range.

    ``start`` and ``end`` must be valid UTC seconds of the form
    ``YYYY-MM-DDTHH:MM:SSZ`` with ``start <= end``; ``facts`` and ``rules``
    are validated exactly as in :func:`explain`. Any type, time,
    rule-structure, or ordering violation raises ``ValueError`` without
    mutating the inputs.

    The candidate timestamps are ``start`` plus every rule ``from`` and
    non-``None`` ``to`` falling in ``(start, end]``, deduplicated and sorted
    ascending; :func:`explain` is called at each candidate. The first point
    is always kept; a later point is kept only when it differs from the
    previously kept point.

    Returns a deep copy with keys ``start``, ``end``, ``points``. Each point
    has keys ``at``, ``decision``, ``trace``, ``basis``, ``conflicts``,
    ``changes``; the first five are exactly the :func:`explain` values at
    ``at``. The first point's ``changes`` is ``[]``; a later point's
    ``changes`` lists, in the order ``decision``, ``trace``, ``basis``,
    ``conflicts``, the fields that differ from the previously kept point.
    """
    _check_time(start, "start")
    _check_time(end, "end")
    if start > end:
        raise ValueError(f"start must not be after end: {start!r} > {end!r}")
    first = explain(start, facts, rules)
    candidates = {start}
    for rule in rules:
        for boundary in (rule["from"], rule["to"]):
            if boundary is not None and start < boundary <= end:
                candidates.add(boundary)
    points = [
        {
            "at": first["at"],
            "decision": first["decision"],
            "trace": first["trace"],
            "basis": first["basis"],
            "conflicts": first["conflicts"],
            "changes": [],
        }
    ]
    previous = first
    for at in sorted(candidates - {start}):
        report = explain(at, facts, rules)
        changes = [
            field for field in _COMPARE_FIELDS if previous[field] != report[field]
        ]
        if not changes:
            continue
        points.append(
            {
                "at": report["at"],
                "decision": report["decision"],
                "trace": report["trace"],
                "basis": report["basis"],
                "conflicts": report["conflicts"],
                "changes": changes,
            }
        )
        previous = report
    return {"start": start, "end": end, "points": points}


_CASE_KEYS = frozenset({"id", "facts"})


def _validate_cases(cases: Any) -> list[dict[str, Any]]:
    if not isinstance(cases, list):
        raise ValueError("cases must be a list of case dicts")
    seen_ids: set[str] = set()
    for index, case in enumerate(cases):
        field = f"cases[{index}]"
        if not isinstance(case, dict) or set(case) != _CASE_KEYS:
            raise ValueError(f"{field} must be a dict with exactly the keys id, facts")
        case_id = _check_non_empty_str(case["id"], f"{field}.id")
        if case_id in seen_ids:
            raise ValueError(f"duplicate case id: {case_id!r}")
        seen_ids.add(case_id)
        _check_fact_map(case["facts"], f"{field}.facts")
    return cases


def decision_impact(
    from_at: str,
    to_at: str,
    cases: list[dict[str, Any]],
    rules: list[dict[str, Any]],
) -> dict[str, Any]:
    """Measure how a policy change affects a set of fact cases.

    ``from_at`` and ``to_at`` must be valid UTC seconds of the form
    ``YYYY-MM-DDTHH:MM:SSZ`` with ``from_at <= to_at``; ``rules`` is
    validated exactly as in :func:`compile_rules`. ``cases`` must be a list
    whose items are dicts with exactly the keys ``id`` and ``facts``; ``id``
    is a non-empty string unique across the list and ``facts`` is validated
    exactly as in :func:`explain`. Any type, time, case-structure, or
    rule-structure violation raises ``ValueError`` without mutating the
    inputs. An empty ``cases`` list is valid.

    Returns a deep copy with keys ``from``, ``to``, ``policy``, ``cases``.
    ``policy`` is the full :func:`policy_delta` result for the two
    timestamps. ``cases`` lists one entry per case ordered by ``id`` in
    Unicode code point order; each entry has keys ``id``, ``changes``,
    ``before``, ``after`` where ``before``/``after`` are the full
    :func:`explain` results at ``from_at``/``to_at`` and ``changes`` lists,
    in the order ``decision``, ``trace``, ``basis``, ``conflicts``, the
    fields whose values differ between the two snapshots (empty when the
    snapshots are identical).
    """
    _check_time(from_at, "from_at")
    _check_time(to_at, "to_at")
    if from_at > to_at:
        raise ValueError(f"from_at must not be after to_at: {from_at!r} > {to_at!r}")
    _validate_cases(cases)

    policy = policy_delta(from_at, to_at, rules)
    entries: list[dict[str, Any]] = []
    for case in sorted(cases, key=lambda item: item["id"]):
        before = explain(from_at, case["facts"], rules)
        after = explain(to_at, case["facts"], rules)
        changes = [field for field in _COMPARE_FIELDS if before[field] != after[field]]
        entries.append(
            {
                "id": case["id"],
                "changes": changes,
                "before": before,
                "after": after,
            }
        )
    return {"from": from_at, "to": to_at, "policy": policy, "cases": entries}


def decision_matrix(
    start: str,
    end: str,
    cases: list[dict[str, Any]],
    rules: list[dict[str, Any]],
) -> dict[str, Any]:
    """Explain a set of fact cases across the rule boundaries in a range.

    ``start`` and ``end`` must be valid UTC seconds of the form
    ``YYYY-MM-DDTHH:MM:SSZ`` with ``start <= end``; ``rules`` is validated
    exactly as in :func:`compile_rules`. ``cases`` must be a list whose items
    are dicts with exactly the keys ``id`` and ``facts``; ``id`` is a
    non-empty string unique across the list and ``facts`` is validated
    exactly as in :func:`explain`. Any type, time, case-structure, or
    rule-structure violation raises ``ValueError`` without mutating the
    inputs. An empty ``cases`` list is valid.

    The candidate timestamps are ``start`` plus every rule ``from`` and
    non-``None`` ``to`` falling in ``(start, end]``, deduplicated and sorted
    ascending. At each candidate, :func:`explain` is called for every case in
    ``id`` Unicode code point order. The first point is always kept; a later
    point is kept only when some case's ``decision``, ``trace``, ``basis``,
    or ``conflicts`` differs from the previously kept point.

    Returns a deep copy with keys ``start``, ``end``, ``points``. Each point
    has keys ``at``, ``changes``, ``cases``. The first point's ``changes`` is
    ``[]``; a later point's ``changes`` lists the ids of the cases that
    changed relative to the previously kept point, in the case order above.
    ``cases`` lists one entry per case in that same order, with keys ``id``,
    ``decision``, ``trace``, ``basis``, ``conflicts``; the last four are
    exactly the same-named :func:`explain` values at ``at`` and keep that
    contract at every level. With an empty ``cases`` list only the ``start``
    point is returned, with empty ``changes`` and ``cases``.
    """
    _check_time(start, "start")
    _check_time(end, "end")
    if start > end:
        raise ValueError(f"start must not be after end: {start!r} > {end!r}")
    _validate_cases(cases)
    _validate_rules(rules)

    ordered_cases = sorted(cases, key=lambda item: item["id"])

    def explain_cases(at: str) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for case in ordered_cases:
            report = explain(at, case["facts"], rules)
            entries.append(
                {
                    "id": case["id"],
                    "decision": report["decision"],
                    "trace": report["trace"],
                    "basis": report["basis"],
                    "conflicts": report["conflicts"],
                }
            )
        return entries

    candidates = {start}
    for rule in rules:
        for boundary in (rule["from"], rule["to"]):
            if boundary is not None and start < boundary <= end:
                candidates.add(boundary)

    first_cases = explain_cases(start)
    points = [{"at": start, "changes": [], "cases": first_cases}]
    previous_cases = first_cases
    for at in sorted(candidates - {start}):
        current_cases = explain_cases(at)
        changes = [
            entry["id"]
            for entry, previous in zip(current_cases, previous_cases)
            if any(
                previous[field] != entry[field] for field in _COMPARE_FIELDS
            )
        ]
        if not changes:
            continue
        points.append({"at": at, "changes": changes, "cases": current_cases})
        previous_cases = current_cases
    return {"start": start, "end": end, "points": points}
