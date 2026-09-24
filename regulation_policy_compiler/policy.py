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


def _check_schedule_point_semantics(
    point: dict[str, Any],
    index: int,
    previous: dict[str, Any] | None,
) -> None:
    """Check one normalized point against the schedule semantics.

    The point's ``rules`` must be effective at its ``at``, unique per
    ``(source, id)``, and ranked exactly as :func:`compile_rules` ranks them;
    ``conflicts`` must equal the conflicts derived from those rules. A later
    point's ``delta`` must span from the previous point's ``at`` to this
    point's ``at`` and exactly match the :func:`policy_delta` of the two
    adjacent snapshots, and must not be empty.
    """
    field = f"points[{index}]"
    at = point["at"]
    rules = point["rules"]
    seen: set[tuple[str, str]] = set()
    for rule_index, rule in enumerate(rules):
        if not (rule["from"] <= at and (rule["to"] is None or at < rule["to"])):
            raise ValueError(
                f"{field}.rules[{rule_index}] is not effective at {field}.at"
            )
        key = (rule["source"], rule["id"])
        if key in seen:
            raise ValueError(f"{field}.rules has duplicate (source, id): {key!r}")
        seen.add(key)
    for rule_index in range(len(rules) - 1):
        if _compare(rules[rule_index], rules[rule_index + 1]) > 0:
            raise ValueError(
                f"{field}.rules are not in compile_rules ranking order"
            )
    if point["conflicts"] != _find_conflicts(rules):
        raise ValueError(
            f"{field}.conflicts do not equal the conflicts derived from "
            f"{field}.rules"
        )
    if index == 0:
        return
    assert previous is not None
    delta = point["delta"]
    if delta["from"] != previous["at"] or delta["to"] != at:
        raise ValueError(
            f"{field}.delta from/to must equal the previous point's at and "
            f"{field}.at"
        )
    before_rules = {
        (rule["source"], rule["id"]): rule for rule in previous["rules"]
    }
    after_rules = {(rule["source"], rule["id"]): rule for rule in rules}
    expected_entries: list[dict[str, Any]] = []
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
        expected_entries.append(
            {
                "source": key[0],
                "id": key[1],
                "kind": kind,
                "before": before,
                "after": after,
            }
        )
    if delta["rules"] != expected_entries:
        raise ValueError(
            f"{field}.delta.rules do not equal the diff of the adjacent "
            "snapshots"
        )
    before_identities = {_conflict_identity(c) for c in previous["conflicts"]}
    after_identities = {_conflict_identity(c) for c in point["conflicts"]}
    expected_added = [
        c for c in point["conflicts"] if _conflict_identity(c) not in before_identities
    ]
    expected_removed = [
        c for c in previous["conflicts"] if _conflict_identity(c) not in after_identities
    ]
    if (
        delta["conflicts"]["added"] != expected_added
        or delta["conflicts"]["removed"] != expected_removed
    ):
        raise ValueError(
            f"{field}.delta.conflicts do not equal the conflict identity "
            "diff of the adjacent snapshots"
        )
    if (
        not delta["rules"]
        and not delta["conflicts"]["added"]
        and not delta["conflicts"]["removed"]
    ):
        raise ValueError(f"{field}.delta must not be empty")


def _normalize_verified_schedule_report(
    report: Any, field: str
) -> dict[str, Any]:
    """Structurally and semantically validate a schedule attestation report.

    Returns a fresh normalized copy with keys ``start``, ``end``, ``root``,
    ``points``. Every key-set, type, value-domain, time, snapshot, delta, and
    hash-chain-field-format rule of
    :func:`verify_policy_schedule_attestation` is enforced; the chain itself
    is recomputed separately by :func:`_recompute_schedule_root`. Any
    violation raises ``ValueError``.
    """
    if not isinstance(report, dict) or set(report) != set(
        _SCHEDULE_ATTEST_REPORT_KEYS
    ):
        raise ValueError(
            f"{field} must be a dict with exactly the keys "
            "start, end, root, points"
        )
    start = _check_time(report["start"], f"{field}.start")
    end = _check_time(report["end"], f"{field}.end")
    if start > end:
        raise ValueError(f"{field}.start must not be after {field}.end")
    root = _check_schedule_hex64(report["root"], f"{field}.root")
    points = report["points"]
    if not isinstance(points, list) or not points:
        raise ValueError(f"{field}.points must be a non-empty list")
    normalized_points: list[dict[str, Any]] = []
    previous_at: str | None = None
    for index, point in enumerate(points):
        normalized, at = _normalize_schedule_point(
            point, index, start, end, previous_at
        )
        _check_schedule_point_semantics(
            normalized, index, normalized_points[-1] if normalized_points else None
        )
        normalized_points.append(normalized)
        previous_at = at
    return {"start": start, "end": end, "root": root, "points": normalized_points}


def _recompute_schedule_root(points: list[dict[str, Any]]) -> tuple[bool, str]:
    """Recompute a schedule hash chain.

    Returns ``(ok, root)`` where ``ok`` is ``False`` at the first broken
    ``previous``/``digest`` link and ``root`` is the running digest.
    """
    previous = _SCHEDULE_GENESIS
    for point in points:
        if point["previous"] != previous:
            return False, previous
        content = {key: point[key] for key in _SCHEDULE_POINT_CONTENT_KEYS}
        canonical = json.dumps(content, ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(
            previous.encode("ascii") + canonical.encode("utf-8")
        ).hexdigest()
        if point["digest"] != digest:
            return False, digest
        previous = digest
    return True, previous


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

    Each point is also checked against the schedule semantics: its ``rules``
    must be effective at its ``at`` (``from <= at < to`` or ``to`` null),
    unique per ``(source, id)``, and ranked exactly as :func:`compile_rules`
    ranks them (``law`` before ``org``, then ``priority`` descending,
    ``from`` descending, ``id`` in Unicode code point order, ``ver``
    descending); its ``conflicts`` must equal the conflicts derived from
    those rules (ranked indices ``i < j``, differing results, compatible
    ``when`` conditions, earlier rule wins) with none missing, forged,
    duplicated, or misordered. A later point's ``delta`` must span from the
    previous point's ``at`` to its own ``at`` and exactly match the
    :func:`policy_delta` of the two adjacent snapshots — ``rules`` ordered by
    ``source`` (``law`` before ``org``) then ``id`` in Unicode code point
    order, ``conflicts.added`` in the current point's conflict order and
    ``conflicts.removed`` in the previous point's — and must not be empty.
    Any semantic violation raises ``ValueError``.

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
    normalized = _normalize_verified_schedule_report(report, "report")
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
        normalized["start"] != expected_start
        or normalized["end"] != expected_end
        or normalized["root"] != expected["root"]
    ):
        return False
    ok, root = _recompute_schedule_root(normalized["points"])
    return ok and normalized["root"] == root


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


def _sorted_fact_map(facts: dict[str, bool]) -> dict[str, bool]:
    """Return a deep-copied fact map with keys in Unicode code point order."""
    return {key: facts[key] for key in sorted(facts)}


def decision_attestation(
    at: str, facts: dict[str, bool], rules: list[dict[str, Any]]
) -> dict[str, Any]:
    """Attest a single-point decision with the facts, explanation, and policy.

    ``at``, ``facts``, and ``rules`` are validated exactly as in
    :func:`explain`; any invalid time, fact type, rule structure, interval,
    or duplicate rule version raises ``ValueError`` without mutating the
    inputs. Only the passed values are used; no history or file is accessed.

    Returns a deep copy with top-level keys ``at``, ``facts``,
    ``explanation``, ``policy``, ``digest``. ``facts`` is a deep copy of the
    input facts with keys sorted in Unicode code point order (an empty dict
    is valid); ``explanation`` is the full deep-copied :func:`explain`
    result at ``at`` keeping its canonical key order at every level;
    ``policy`` is the full deep-copied :func:`compile_rules` result at
    ``at``, conflicts included.

    Let ``C`` be the UTF-8 bytes of compact JSON (``ensure_ascii=False``,
    ``separators=(',', ':')``) over a payload containing exactly ``at``,
    ``facts``, ``explanation``, ``policy`` in that key order. ``digest`` is
    the lowercase 64-char hex SHA-256 of ``C``. Equal-valued inputs yield
    byte-identical attestations regardless of input dict key order; empty
    facts, empty rules, and no-match decisions all attest normally.
    """
    explanation = explain(at, facts, rules)
    policy = compile_rules(at, rules)
    payload = {
        "at": at,
        "facts": _sorted_fact_map(facts),
        "explanation": explanation,
        "policy": policy,
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    attestation = copy.deepcopy(payload)
    attestation["digest"] = digest
    return attestation


_DECISION_ATTEST_REPORT_KEYS = frozenset(
    {"at", "facts", "explanation", "policy", "digest"}
)
_DECISION_ATTEST_EXPECTED_KEYS = frozenset({"at", "digest"})
_COMPILED_POLICY_KEYS = frozenset({"at", "rules", "conflicts"})
_EXPLANATION_KEYS = frozenset({"at", "decision", "trace", "basis", "conflicts"})
_DECISION_ATTEST_CONTENT_KEYS = ("at", "facts", "explanation", "policy")


def _check_hex64(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in _SCHEDULE_HEX_DIGITS for char in value)
    ):
        raise ValueError(f"{field} must be 64 lowercase hexadecimal characters")
    return value


def _check_trace_ref(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string of the form id@ver")
    rule_id, sep, ver = value.rpartition("@")
    if not sep or not rule_id or not ver.isdigit() or int(ver) < 1:
        raise ValueError(f"{field} must be a string of the form id@ver")
    return value


def _normalize_verified_policy(
    value: Any, at: str, field: str
) -> dict[str, Any]:
    """Validate a ``compile_rules`` snapshot structurally and semantically.

    Returns a fresh normalized copy with the contract key order. The rules
    must be valid snapshots, all effective at ``at``, unique per
    ``(source, id)``, and ranked exactly as :func:`compile_rules` ranks them;
    ``conflicts`` must equal the conflicts rebuilt from those rules. Any
    violation raises ``ValueError``.
    """
    if not isinstance(value, dict) or set(value) != _COMPILED_POLICY_KEYS:
        raise ValueError(
            f"{field} must be a dict with exactly the keys at, rules, conflicts"
        )
    policy_at = _check_time(value["at"], f"{field}.at")
    if policy_at != at:
        raise ValueError(f"{field}.at must equal report.at")
    raw_rules = value["rules"]
    try:
        _validate_rules(raw_rules)
    except ValueError as exc:
        raise ValueError(f"{field}.rules are not valid rule snapshots: {exc}") from exc
    rules = [_snapshot_rule(rule) for rule in raw_rules]
    seen: set[tuple[str, str]] = set()
    for index, rule in enumerate(rules):
        if not (rule["from"] <= at and (rule["to"] is None or at < rule["to"])):
            raise ValueError(f"{field}.rules[{index}] is not effective at report.at")
        key = (rule["source"], rule["id"])
        if key in seen:
            raise ValueError(f"{field}.rules has a duplicate (source, id): {key!r}")
        seen.add(key)
    for index in range(len(rules) - 1):
        if _compare(rules[index], rules[index + 1]) > 0:
            raise ValueError(f"{field}.rules are not in compile_rules ranking order")
    conflicts = _normalize_conflicts(value["conflicts"], f"{field}.conflicts")
    if conflicts != _find_conflicts(rules):
        raise ValueError(
            f"{field}.conflicts do not equal the conflicts derived from "
            f"{field}.rules"
        )
    return {"at": at, "rules": rules, "conflicts": conflicts}


def _normalize_verified_explanation(
    value: Any, at: str, field: str
) -> dict[str, Any]:
    """Validate an ``explain`` snapshot structurally and return a fresh copy."""
    if not isinstance(value, dict) or set(value) != _EXPLANATION_KEYS:
        raise ValueError(
            f"{field} must be a dict with exactly the keys "
            "at, decision, trace, basis, conflicts"
        )
    explanation_at = _check_time(value["at"], f"{field}.at")
    if explanation_at != at:
        raise ValueError(f"{field}.at must equal report.at")
    decision = value["decision"]
    if decision is not None and not isinstance(decision, str):
        raise ValueError(f"{field}.decision must be a string or null")
    raw_trace = value["trace"]
    if not isinstance(raw_trace, list):
        raise ValueError(f"{field}.trace must be a list of id@ver strings")
    trace = [
        _check_trace_ref(item, f"{field}.trace[{index}]")
        for index, item in enumerate(raw_trace)
    ]
    raw_basis = value["basis"]
    if raw_basis is None:
        basis = None
    else:
        try:
            _validate_rules([raw_basis])
        except ValueError as exc:
            raise ValueError(
                f"{field}.basis is not a valid rule snapshot: {exc}"
            ) from exc
        basis = _snapshot_rule(raw_basis)
    conflicts = _normalize_conflicts(value["conflicts"], f"{field}.conflicts")
    return {
        "at": at,
        "decision": decision,
        "trace": trace,
        "basis": basis,
        "conflicts": conflicts,
    }


def verify_decision_attestation(report: Any, expected: Any) -> bool:
    """Verify a :func:`decision_attestation` report by recomputation.

    Pure function: it only inspects its arguments, touches neither history
    nor files, and never mutates an input object at any level.

    ``report`` must be a dict with exactly the keys ``at``, ``facts``,
    ``explanation``, ``policy``, ``digest`` and conform level by level to the
    :func:`decision_attestation` contract. ``at`` must be a valid UTC second;
    ``facts`` must map non-empty string keys to bool values (an empty dict is
    valid); ``digest`` must be 64 lowercase hexadecimal characters. ``policy``
    must have exactly the keys ``at``, ``rules``, ``conflicts`` with its
    ``at`` equal to the report ``at``; its rules must be effective at that
    time (``from <= at < to`` or ``to`` null), unique per ``(source, id)``,
    and ranked exactly as :func:`compile_rules` ranks them, and its
    ``conflicts`` must equal the conflicts fully rebuilt from those rules
    (ranked indices ``i < j``, differing results, compatible ``when``
    conditions, earlier rule wins) — missing, forged, duplicated, or
    misordered entries are all illegal. ``explanation`` must have exactly the
    keys ``at``, ``decision``, ``trace``, ``basis``, ``conflicts`` with its
    ``at`` equal to the report ``at``; it is re-evaluated against the policy
    rules with the report facts, so with no match ``decision``/``basis`` are
    null and ``trace``/``conflicts`` empty, while with a match ``decision`` is
    the top-ranked matching rule's result, ``trace`` lists every matching
    rule, ``basis`` is that rule's snapshot, and ``conflicts`` keeps the
    policy conflicts involving that basis in their original order.
    ``expected`` must have exactly the keys ``at`` and ``digest``, validated
    the same way.

    Any key-set, type, time, fact, rule, conflict, or explanation-semantic
    violation raises ``ValueError``. Both inputs complete structural and
    semantic validation before any comparison, so a bad report is never
    masked by short-circuiting. Afterwards the canonical key order is rebuilt
    (``facts`` and ``when`` keys in Unicode code point order) and the digest
    is recomputed as the lowercase hexadecimal SHA-256 of the compact UTF-8
    JSON bytes over ``at``, ``facts``, ``explanation``, ``policy`` in that
    order. Returns ``False`` when the declared digest differs from the
    recomputed value or the report's ``at``/``digest`` differ from
    ``expected``; otherwise ``True``.
    """
    if not isinstance(report, dict) or set(report) != _DECISION_ATTEST_REPORT_KEYS:
        raise ValueError(
            "report must be a dict with exactly the keys "
            "at, facts, explanation, policy, digest"
        )
    at = _check_time(report["at"], "report.at")
    _check_fact_map(report["facts"], "report.facts")
    facts = _sorted_fact_map(report["facts"])
    policy = _normalize_verified_policy(report["policy"], at, "report.policy")
    explanation = _normalize_verified_explanation(
        report["explanation"], at, "report.explanation"
    )
    recomputed_explanation = explain(at, facts, policy["rules"])
    if explanation != recomputed_explanation:
        raise ValueError(
            "report.explanation does not follow from report.facts and "
            "report.policy under the explain contract"
        )
    _check_hex64(report["digest"], "report.digest")
    if not isinstance(expected, dict) or set(expected) != (
        _DECISION_ATTEST_EXPECTED_KEYS
    ):
        raise ValueError("expected must be a dict with exactly the keys at, digest")
    expected_at = _check_time(expected["at"], "expected.at")
    expected_digest = _check_hex64(expected["digest"], "expected.digest")

    if at != expected_at or report["digest"] != expected_digest:
        return False
    content = {
        "at": at,
        "facts": facts,
        "explanation": recomputed_explanation,
        "policy": policy,
    }
    canonical = json.dumps(content, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return report["digest"] == digest


_TIMELINE_ATTEST_REPORT_KEYS = frozenset(
    {"start", "end", "facts", "timeline", "policy", "digest"}
)
_TIMELINE_ATTEST_EXPECTED_KEYS = frozenset({"start", "end", "digest"})
_TIMELINE_KEYS = frozenset({"start", "end", "points"})
_TIMELINE_POINT_KEYS = frozenset(
    {"at", "decision", "trace", "basis", "conflicts", "changes"}
)


def _normalize_verified_timeline(
    value: Any, start: str, end: str, field: str
) -> list[dict[str, Any]]:
    """Validate an embedded decision timeline structurally.

    Returns the normalized timeline points. Each point must have exactly the
    :func:`decision_timeline` keys; its explanation half must conform to the
    :func:`explain` contract, ``at`` values must be strictly increasing inside
    ``[start, end]`` with the first point at ``start``, and ``changes`` must be
    distinct members of the decision comparison field order. Semantic
    agreement with a timeline rebuilt from the attested policy is checked
    separately. Any violation raises ``ValueError``.
    """
    if not isinstance(value, dict) or set(value) != _TIMELINE_KEYS:
        raise ValueError(
            f"{field} must be a dict with exactly the keys start, end, points"
        )
    timeline_start = _check_time(value["start"], f"{field}.start")
    timeline_end = _check_time(value["end"], f"{field}.end")
    if timeline_start != start or timeline_end != end:
        raise ValueError(f"{field}.start/end must equal report.start/end")
    raw_points = value["points"]
    if not isinstance(raw_points, list) or not raw_points:
        raise ValueError(f"{field}.points must be a non-empty list")
    points: list[dict[str, Any]] = []
    previous_at: str | None = None
    for index, point in enumerate(raw_points):
        point_field = f"{field}.points[{index}]"
        if not isinstance(point, dict) or set(point) != _TIMELINE_POINT_KEYS:
            raise ValueError(
                f"{point_field} must be a dict with exactly the keys "
                "at, decision, trace, basis, conflicts, changes"
            )
        at = _check_time(point["at"], f"{point_field}.at")
        if not start <= at <= end:
            raise ValueError(f"{point_field}.at lies outside [start, end]")
        if index == 0:
            if at != start:
                raise ValueError(f"{field}.points[0].at must equal start")
        elif at <= previous_at:  # type: ignore[operator]
            raise ValueError(f"{field} points must be strictly increasing in at")
        explanation = _normalize_verified_explanation(
            {
                "at": point["at"],
                "decision": point["decision"],
                "trace": point["trace"],
                "basis": point["basis"],
                "conflicts": point["conflicts"],
            },
            at,
            point_field,
        )
        raw_changes = point["changes"]
        if not isinstance(raw_changes, list):
            raise ValueError(f"{point_field}.changes must be a list")
        changes: list[str] = []
        for change_index, change in enumerate(raw_changes):
            if not isinstance(change, str) or change not in _COMPARE_FIELDS:
                raise ValueError(
                    f"{point_field}.changes[{change_index}] must be one of "
                    "decision, trace, basis, conflicts"
                )
            if change in changes:
                raise ValueError(f"{point_field}.changes must not repeat fields")
            changes.append(change)
        points.append(
            {
                "at": at,
                "decision": explanation["decision"],
                "trace": explanation["trace"],
                "basis": explanation["basis"],
                "conflicts": explanation["conflicts"],
                "changes": changes,
            }
        )
        previous_at = at
    return points


def _rebuild_timeline_from_schedule(
    start: str,
    end: str,
    facts: dict[str, bool],
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    """Rebuild the full decision timeline implied by an attested schedule.

    The candidate timestamps are ``start`` plus every rule ``from``/non-empty
    ``to`` boundary visible in the schedule's attested snapshots that falls in
    ``(start, end]``; :func:`explain` is re-evaluated at each candidate with
    the given facts, the first point is always kept, and later points are kept
    exactly when a decision, trace, basis, or conflicts field changes — the
    :func:`decision_timeline` rule.
    """
    rules: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for point in policy["points"]:
        for rule in point["rules"]:
            key = (rule["source"], rule["id"], rule["ver"])
            if key not in seen:
                seen.add(key)
                rules.append(rule)
    candidates = {start}
    for rule in rules:
        for boundary in (rule["from"], rule["to"]):
            if boundary is not None and start < boundary <= end:
                candidates.add(boundary)
    first = explain(start, facts, rules)
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
    return points


def verify_decision_timeline_attestation(report: Any, expected: Any) -> bool:
    """Verify a :func:`decision_timeline_attestation` report by recomputation.

    Pure function: it only inspects its arguments, touches neither history
    nor files, and never mutates an input object at any level.

    ``report`` must be a dict with exactly the keys ``start``, ``end``,
    ``facts``, ``timeline``, ``policy``, ``digest`` and conform level by level
    to the :func:`decision_timeline_attestation` contract. ``start``/``end``
    must be valid UTC seconds with ``start <= end``, ``facts`` must map
    non-empty string keys to bool values (an empty dict is valid), and
    ``digest`` must be 64 lowercase hexadecimal characters. ``policy`` must be
    a full :func:`policy_schedule_attestation` report over the same
    ``start``/``end`` and pass the existing schedule attestation checks,
    including snapshots, deltas, and the hash chain. ``timeline`` must have
    exactly the keys ``start``, ``end``, ``points`` with strictly increasing
    point times inside ``[start, end]`` (first point at ``start``); each point
    must have exactly the keys ``at``, ``decision``, ``trace``, ``basis``,
    ``conflicts``, ``changes`` and its explanation half must conform to the
    :func:`explain` contract. All key-set, type, value-domain, and time checks
    complete before any semantic or digest comparison.

    The points are then re-evaluated with the report facts against the rules
    attested in the policy snapshots, following the :func:`decision_timeline`
    candidate and filtering rules; the reported points must match the rebuilt
    timeline item by item — times, explanation contents, and ``changes`` — in
    order. ``expected`` must have exactly the keys ``start``, ``end``,
    ``digest`` and is validated the same way. Any structural or semantic
    violation raises ``ValueError``.

    Afterwards the digest is recomputed as the lowercase hexadecimal SHA-256
    of the compact UTF-8 JSON bytes over ``start``, ``end``, ``facts``,
    ``timeline``, ``policy`` in that key order (facts and rule ``when`` keys
    in Unicode code point order). Returns ``False`` when the embedded policy
    chain or root, the declared digest, the recomputed digest, or the expected
    values do not match; otherwise ``True``.
    """
    if not isinstance(report, dict) or set(report) != _TIMELINE_ATTEST_REPORT_KEYS:
        raise ValueError(
            "report must be a dict with exactly the keys "
            "start, end, facts, timeline, policy, digest"
        )
    start = _check_time(report["start"], "report.start")
    end = _check_time(report["end"], "report.end")
    if start > end:
        raise ValueError("report.start must not be after report.end")
    _check_fact_map(report["facts"], "report.facts")
    facts = _sorted_fact_map(report["facts"])
    _check_hex64(report["digest"], "report.digest")
    policy = _normalize_verified_schedule_report(report["policy"], "report.policy")
    if policy["start"] != start or policy["end"] != end:
        raise ValueError("report.policy.start/end must equal report.start/end")
    timeline_points = _normalize_verified_timeline(
        report["timeline"], start, end, "report.timeline"
    )
    if not isinstance(expected, dict) or set(expected) != (
        _TIMELINE_ATTEST_EXPECTED_KEYS
    ):
        raise ValueError(
            "expected must be a dict with exactly the keys start, end, digest"
        )
    expected_start = _check_time(expected["start"], "expected.start")
    expected_end = _check_time(expected["end"], "expected.end")
    if expected_start > expected_end:
        raise ValueError("expected.start must not be after expected.end")
    expected_digest = _check_hex64(expected["digest"], "expected.digest")

    rebuilt_points = _rebuild_timeline_from_schedule(start, end, facts, policy)
    if timeline_points != rebuilt_points:
        raise ValueError(
            "report.timeline does not match the timeline rebuilt from "
            "report.facts and report.policy under the decision_timeline "
            "contract"
        )

    if (
        start != expected_start
        or end != expected_end
        or report["digest"] != expected_digest
    ):
        return False
    chain_ok, chain_root = _recompute_schedule_root(policy["points"])
    if not chain_ok or policy["root"] != chain_root:
        return False
    content = {
        "start": start,
        "end": end,
        "facts": facts,
        "timeline": {"start": start, "end": end, "points": rebuilt_points},
        "policy": policy,
    }
    canonical = json.dumps(content, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return report["digest"] == digest


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


def decision_timeline_attestation(
    start: str,
    end: str,
    facts: dict[str, bool],
    rules: list[dict[str, Any]],
) -> dict[str, Any]:
    """Attest a :func:`decision_timeline` result together with its policy.

    ``start``, ``end``, ``facts``, and ``rules`` are validated exactly as in
    :func:`decision_timeline`; any invalid time, fact, or rule raises
    ``ValueError`` without mutating the inputs or touching history or files.
    Empty facts and empty rules are both valid.

    Returns a deep copy with top-level keys ``start``, ``end``, ``facts``,
    ``timeline``, ``policy``, ``digest``. ``facts`` is a deep copy of the
    input facts with keys sorted in Unicode code point order; ``timeline`` is
    the full deep-copied :func:`decision_timeline` result for the same range;
    ``policy`` is the full deep-copied
    :func:`policy_schedule_attestation` result for the same range.

    Let ``C`` be the UTF-8 bytes of compact JSON (``ensure_ascii=False``,
    ``separators=(',', ':')``) over a payload containing exactly ``start``,
    ``end``, ``facts``, ``timeline``, ``policy`` in that key order. ``digest``
    is the lowercase 64-char hex SHA-256 of ``C``. Equal-valued inputs yield
    byte-identical attestations.
    """
    timeline = decision_timeline(start, end, facts, rules)
    policy = policy_schedule_attestation(start, end, rules)
    payload = {
        "start": start,
        "end": end,
        "facts": _sorted_fact_map(facts),
        "timeline": timeline,
        "policy": policy,
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    attestation = copy.deepcopy(payload)
    attestation["digest"] = digest
    return attestation


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


_IMPACT_ATTEST_REPORT_KEYS = frozenset(
    {"from", "to", "cases", "policy", "impact", "digest"}
)
_IMPACT_ATTEST_EXPECTED_KEYS = frozenset({"from", "to", "digest"})
_IMPACT_ATTEST_CONTENT_KEYS = ("from", "to", "cases", "policy", "impact")
_IMPACT_POLICY_KEYS = frozenset({"before", "after", "delta"})
_IMPACT_CASE_KEYS = frozenset({"id", "facts"})
_IMPACT_RESULT_KEYS = frozenset({"from", "to", "policy", "cases"})
_IMPACT_RESULT_CASE_KEYS = frozenset({"id", "changes", "before", "after"})


def decision_impact_attestation(
    from_at: str,
    to_at: str,
    cases: list[dict[str, Any]],
    rules: list[dict[str, Any]],
) -> dict[str, Any]:
    """Attest a :func:`decision_impact` result with bound policy evidence.

    ``from_at``, ``to_at``, ``cases``, and ``rules`` are validated exactly as
    in :func:`decision_impact`; any invalid time, case, fact, or rule raises
    ``ValueError`` without mutating the inputs or touching history or files.
    An empty ``cases`` list is valid.

    Returns a deep copy with top-level keys ``from``, ``to``, ``cases``,
    ``policy``, ``impact``, ``digest``. ``cases`` lists the input cases in
    ``id`` Unicode code point order with each case's fact keys sorted in
    Unicode code point order (items keep the keys ``id``, ``facts``).
    ``policy`` has keys ``before``, ``after``, ``delta``: ``before`` and
    ``after`` are the full :func:`compile_rules` snapshots at the two
    timestamps and ``delta`` is the full :func:`policy_delta` result between
    them. ``impact`` is the complete :func:`decision_impact` result for the
    same inputs, keeping its case order, explanations, and ``changes``
    semantics.

    Let ``C`` be the UTF-8 bytes of compact JSON (``ensure_ascii=False``,
    ``separators=(',', ':')``) over a payload containing exactly ``from``,
    ``to``, ``cases``, ``policy``, ``impact`` in that key order. ``digest``
    is the lowercase 64-char hex SHA-256 of ``C``. Equal-valued inputs yield
    byte-identical attestations.
    """
    _check_time(from_at, "from_at")
    _check_time(to_at, "to_at")
    if from_at > to_at:
        raise ValueError(f"from_at must not be after to_at: {from_at!r} > {to_at!r}")
    _validate_cases(cases)

    before = compile_rules(from_at, rules)
    after = compile_rules(to_at, rules)
    delta = policy_delta(from_at, to_at, rules)
    impact = decision_impact(from_at, to_at, cases, rules)
    attested_cases = [
        {"id": case["id"], "facts": _sorted_fact_map(case["facts"])}
        for case in sorted(cases, key=lambda item: item["id"])
    ]
    payload = {
        "from": from_at,
        "to": to_at,
        "cases": attested_cases,
        "policy": {"before": before, "after": after, "delta": delta},
        "impact": impact,
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    attestation = copy.deepcopy(payload)
    attestation["digest"] = digest
    return attestation


def _delta_from_compiled(
    before: dict[str, Any], after: dict[str, Any]
) -> dict[str, Any]:
    """Rebuild a :func:`policy_delta` result from two compiled snapshots.

    Unlike :func:`policy_delta` this needs no original rules: the diff is
    derived solely from the two ``compile_rules`` snapshots.
    """
    from_at = before["at"]
    to_at = after["at"]
    before_rules = {(rule["source"], rule["id"]): rule for rule in before["rules"]}
    after_rules = {(rule["source"], rule["id"]): rule for rule in after["rules"]}
    entries: list[dict[str, Any]] = []
    for key in sorted(
        set(before_rules) | set(after_rules),
        key=lambda item: (_SOURCE_ORDER[item[0]], item[1]),
    ):
        before_rule = before_rules.get(key)
        after_rule = after_rules.get(key)
        if before_rule is not None and after_rule is not None and (
            before_rule == after_rule
        ):
            continue
        if before_rule is None:
            kind = "added"
        elif after_rule is None:
            kind = "removed"
        else:
            kind = "updated"
        entries.append(
            {
                "source": key[0],
                "id": key[1],
                "kind": kind,
                "before": before_rule,
                "after": after_rule,
            }
        )
    before_identities = {_conflict_identity(c) for c in before["conflicts"]}
    after_identities = {_conflict_identity(c) for c in after["conflicts"]}
    added = [
        {"winner": list(c["winner"]), "loser": list(c["loser"])}
        for c in after["conflicts"]
        if _conflict_identity(c) not in before_identities
    ]
    removed = [
        {"winner": list(c["winner"]), "loser": list(c["loser"])}
        for c in before["conflicts"]
        if _conflict_identity(c) not in after_identities
    ]
    return {
        "from": from_at,
        "to": to_at,
        "rules": entries,
        "conflicts": {"added": added, "removed": removed},
    }


def _normalize_verified_impact_cases(
    value: Any, field: str
) -> list[dict[str, Any]]:
    """Structurally validate the attested input case list.

    Each item must have exactly the keys ``id``, ``facts``; ids must be
    non-empty, unique, and strictly ascending in Unicode code point order,
    and facts must map non-empty string keys to bool values. Returns fresh
    normalized copies with sorted fact keys. Any violation raises
    ``ValueError``.
    """
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list of case dicts")
    cases: list[dict[str, Any]] = []
    seen: set[str] = set()
    previous_id: str | None = None
    for index, case in enumerate(value):
        item_field = f"{field}[{index}]"
        if not isinstance(case, dict) or set(case) != _IMPACT_CASE_KEYS:
            raise ValueError(
                f"{item_field} must be a dict with exactly the keys id, facts"
            )
        case_id = _check_non_empty_str(case["id"], f"{item_field}.id")
        if case_id in seen:
            raise ValueError(f"{field} has a duplicate case id: {case_id!r}")
        if previous_id is not None and case_id <= previous_id:
            raise ValueError(f"{field} case ids must be strictly ascending")
        _check_fact_map(case["facts"], f"{item_field}.facts")
        cases.append({"id": case_id, "facts": _sorted_fact_map(case["facts"])})
        seen.add(case_id)
        previous_id = case_id
    return cases


def _normalize_verified_impact_result_cases(
    value: Any,
    input_cases: list[dict[str, Any]],
    from_at: str,
    to_at: str,
    field: str,
) -> list[dict[str, Any]]:
    """Structurally validate the ``cases`` half of an attested impact result.

    Each item must have exactly the keys ``id``, ``changes``, ``before``,
    ``after``; the ids must be non-empty, unique, strictly ascending, and
    match the attested input-case ids one for one and in order. ``before``/
    ``after`` must conform to the :func:`explain` contract at the two
    timestamps and ``changes`` must list distinct comparison fields. Returns
    fresh normalized copies. Any violation raises ``ValueError``.
    """
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list of case result dicts")
    if len(value) != len(input_cases):
        raise ValueError(
            f"{field} must contain one result per attested input case"
        )
    cases: list[dict[str, Any]] = []
    seen: set[str] = set()
    previous_id: str | None = None
    for index, case in enumerate(value):
        item_field = f"{field}[{index}]"
        if not isinstance(case, dict) or set(case) != _IMPACT_RESULT_CASE_KEYS:
            raise ValueError(
                f"{item_field} must be a dict with exactly the keys "
                "id, changes, before, after"
            )
        case_id = _check_non_empty_str(case["id"], f"{item_field}.id")
        if case_id != input_cases[index]["id"]:
            raise ValueError(
                f"{item_field}.id must match the attested input case id at "
                f"the same position"
            )
        if case_id in seen:
            raise ValueError(f"{field} has a duplicate case id: {case_id!r}")
        if previous_id is not None and case_id <= previous_id:
            raise ValueError(f"{field} case ids must be strictly ascending")
        before = _normalize_verified_explanation(
            case["before"], from_at, f"{item_field}.before"
        )
        after = _normalize_verified_explanation(
            case["after"], to_at, f"{item_field}.after"
        )
        raw_changes = case["changes"]
        if not isinstance(raw_changes, list):
            raise ValueError(f"{item_field}.changes must be a list")
        changes: list[str] = []
        for change_index, change in enumerate(raw_changes):
            if not isinstance(change, str) or change not in _COMPARE_FIELDS:
                raise ValueError(
                    f"{item_field}.changes[{change_index}] must be one of "
                    "decision, trace, basis, conflicts"
                )
            if change in changes:
                raise ValueError(f"{item_field}.changes must not repeat fields")
            changes.append(change)
        cases.append(
            {
                "id": case_id,
                "changes": changes,
                "before": before,
                "after": after,
            }
        )
        seen.add(case_id)
        previous_id = case_id
    return cases


def verify_decision_impact_attestation(report: Any, expected: Any) -> bool:
    """Verify a :func:`decision_impact_attestation` report by recomputation.

    Pure function: it only inspects its arguments, needs no original rules
    (the before/after policy snapshots are sufficient), touches neither
    history nor files, and never mutates an input object at any level.

    ``report`` must be a dict with exactly the keys ``from``, ``to``,
    ``cases``, ``policy``, ``impact``, ``digest`` and conform level by level
    to the :func:`decision_impact_attestation` contract. ``from``/``to`` must
    be valid UTC seconds with ``from <= to`` and ``digest`` 64 lowercase
    hexadecimal characters. ``cases`` must list ``id``/``facts`` items whose
    ids are non-empty, unique, and strictly ascending in Unicode code point
    order and whose fact maps are valid. ``policy`` must have exactly the
    keys ``before``, ``after``, ``delta``: the two snapshots must pass the
    existing :func:`compile_rules` structural and semantic checks at the two
    timestamps and the ``delta`` must be a valid :func:`policy_delta`
    structure spanning that window. ``impact`` must have exactly the keys
    ``from``, ``to``, ``policy``, ``cases``, carry a structurally valid delta
    over the same window, and one structurally valid result per input case in
    the same order. ``expected`` must have exactly the keys ``from``, ``to``,
    ``digest`` and is validated the same way.

    Both inputs complete every level of structural validation before any
    semantic rebuild or comparison. Semantically, the delta is rebuilt from
    the two snapshots, then each case's two explanations, its ``changes``,
    and the complete impact result are rebuilt solely from the snapshots and
    attested facts; any mismatch raises ``ValueError``.

    Afterwards the digest is recomputed as the lowercase hexadecimal SHA-256
    of the compact UTF-8 JSON bytes over ``from``, ``to``, ``cases``,
    ``policy``, ``impact`` in that key order. Returns ``False`` when the
    declared digest, a timestamp, or an ``expected`` value does not match;
    otherwise ``True``.
    """
    if not isinstance(report, dict) or set(report) != _IMPACT_ATTEST_REPORT_KEYS:
        raise ValueError(
            "report must be a dict with exactly the keys "
            "from, to, cases, policy, impact, digest"
        )
    from_at = _check_time(report["from"], "report.from")
    to_at = _check_time(report["to"], "report.to")
    if from_at > to_at:
        raise ValueError("report.from must not be after report.to")
    digest = _check_hex64(report["digest"], "report.digest")
    input_cases = _normalize_verified_impact_cases(report["cases"], "report.cases")

    policy = report["policy"]
    if not isinstance(policy, dict) or set(policy) != _IMPACT_POLICY_KEYS:
        raise ValueError(
            "report.policy must be a dict with exactly the keys "
            "before, after, delta"
        )
    before_policy = _normalize_verified_policy(
        policy["before"], from_at, "report.policy.before"
    )
    after_policy = _normalize_verified_policy(
        policy["after"], to_at, "report.policy.after"
    )
    delta = _normalize_delta(policy["delta"], "report.policy.delta")
    if delta["from"] != from_at or delta["to"] != to_at:
        raise ValueError(
            "report.policy.delta from/to must equal report.from/report.to"
        )

    impact = report["impact"]
    if not isinstance(impact, dict) or set(impact) != _IMPACT_RESULT_KEYS:
        raise ValueError(
            "report.impact must be a dict with exactly the keys "
            "from, to, policy, cases"
        )
    impact_from = _check_time(impact["from"], "report.impact.from")
    impact_to = _check_time(impact["to"], "report.impact.to")
    if impact_from != from_at or impact_to != to_at:
        raise ValueError(
            "report.impact.from/to must equal report.from/report.to"
        )
    impact_delta = _normalize_delta(impact["policy"], "report.impact.policy")
    if impact_delta["from"] != from_at or impact_delta["to"] != to_at:
        raise ValueError(
            "report.impact.policy from/to must equal report.from/report.to"
        )
    impact_cases = _normalize_verified_impact_result_cases(
        impact["cases"], input_cases, from_at, to_at, "report.impact.cases"
    )

    if not isinstance(expected, dict) or set(expected) != (
        _IMPACT_ATTEST_EXPECTED_KEYS
    ):
        raise ValueError(
            "expected must be a dict with exactly the keys from, to, digest"
        )
    expected_from = _check_time(expected["from"], "expected.from")
    expected_to = _check_time(expected["to"], "expected.to")
    if expected_from > expected_to:
        raise ValueError("expected.from must not be after expected.to")
    expected_digest = _check_hex64(expected["digest"], "expected.digest")

    rebuilt_delta = _delta_from_compiled(before_policy, after_policy)
    if delta != rebuilt_delta:
        raise ValueError(
            "report.policy.delta does not equal the delta rebuilt from "
            "report.policy.before and report.policy.after"
        )
    rebuilt_cases: list[dict[str, Any]] = []
    for case in input_cases:
        before_explanation = explain(
            from_at, case["facts"], before_policy["rules"]
        )
        after_explanation = explain(to_at, case["facts"], after_policy["rules"])
        changes = [
            field
            for field in _COMPARE_FIELDS
            if before_explanation[field] != after_explanation[field]
        ]
        rebuilt_cases.append(
            {
                "id": case["id"],
                "changes": changes,
                "before": before_explanation,
                "after": after_explanation,
            }
        )
    rebuilt_impact = {
        "from": from_at,
        "to": to_at,
        "policy": rebuilt_delta,
        "cases": rebuilt_cases,
    }
    declared_impact = {
        "from": from_at,
        "to": to_at,
        "policy": impact_delta,
        "cases": impact_cases,
    }
    if declared_impact != rebuilt_impact:
        raise ValueError(
            "report.impact does not match the impact rebuilt from "
            "report.cases and report.policy under the decision_impact "
            "contract"
        )

    if (
        from_at != expected_from
        or to_at != expected_to
        or digest != expected_digest
    ):
        return False
    content = {
        "from": from_at,
        "to": to_at,
        "cases": input_cases,
        "policy": {
            "before": before_policy,
            "after": after_policy,
            "delta": rebuilt_delta,
        },
        "impact": rebuilt_impact,
    }
    canonical = json.dumps(content, ensure_ascii=False, separators=(",", ":"))
    recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return digest == recomputed


_MATRIX_ATTEST_REPORT_KEYS = frozenset(
    {"start", "end", "cases", "matrix", "policy", "digest"}
)
_MATRIX_ATTEST_EXPECTED_KEYS = frozenset({"start", "end", "digest"})
_MATRIX_RESULT_KEYS = frozenset({"start", "end", "points"})
_MATRIX_POINT_KEYS = frozenset({"at", "changes", "cases"})
_MATRIX_RESULT_CASE_KEYS = frozenset(
    {"id", "decision", "trace", "basis", "conflicts"}
)
_MATRIX_ATTEST_CONTENT_KEYS = ("start", "end", "cases", "matrix", "policy")


def decision_matrix_attestation(
    start: str,
    end: str,
    cases: list[dict[str, Any]],
    rules: list[dict[str, Any]],
) -> dict[str, Any]:
    """Attest a :func:`decision_matrix` result together with its schedule.

    ``start``, ``end``, ``cases``, and ``rules`` are validated exactly as in
    :func:`decision_matrix`; any invalid time, case, fact, or rule raises
    ``ValueError`` without mutating the inputs or touching history or files.
    An empty ``cases`` list is valid.

    Returns a deep copy with top-level keys ``start``, ``end``, ``cases``,
    ``matrix``, ``policy``, ``digest``; no two levels share a mutable
    container. ``cases`` lists the input cases in ``id`` Unicode code point
    order with each case's fact keys sorted in Unicode code point order
    (items keep the keys ``id``, ``facts``); ``matrix`` is the complete
    :func:`decision_matrix` result for the same inputs, keeping its first
    point, change points, case order, explanations, and ``changes``
    semantics; ``policy`` is the complete
    :func:`policy_schedule_attestation` result over the same time window,
    including its snapshots, deltas, conflicts, and hash chain.

    Let ``C`` be the UTF-8 bytes of compact JSON (``ensure_ascii=False``,
    ``separators=(',', ':')``) over a payload containing exactly ``start``,
    ``end``, ``cases``, ``matrix``, ``policy`` in that key order. ``digest``
    is the lowercase 64-char hex SHA-256 of ``C``. Equal-valued inputs yield
    byte-identical attestations regardless of input dict key order.
    """
    _check_time(start, "start")
    _check_time(end, "end")
    if start > end:
        raise ValueError(f"start must not be after end: {start!r} > {end!r}")
    _validate_cases(cases)
    matrix = decision_matrix(start, end, cases, rules)
    policy = policy_schedule_attestation(start, end, rules)
    attested_cases = [
        {"id": case["id"], "facts": _sorted_fact_map(case["facts"])}
        for case in sorted(cases, key=lambda item: item["id"])
    ]
    payload = {
        "start": start,
        "end": end,
        "cases": attested_cases,
        "matrix": matrix,
        "policy": policy,
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    attestation = copy.deepcopy(payload)
    attestation["digest"] = digest
    return attestation


def _normalize_verified_matrix_cases(value: Any, field: str) -> list[dict[str, Any]]:
    """Structurally validate the attested matrix input case list.

    Each item must have exactly the keys ``id``, ``facts``; ids must be
    non-empty, unique, and strictly ascending in Unicode code point order,
    and facts must map non-empty string keys to bool values. Returns fresh
    normalized copies with sorted fact keys. Any violation raises
    ``ValueError``.
    """
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list of case dicts")
    cases: list[dict[str, Any]] = []
    seen: set[str] = set()
    previous_id: str | None = None
    for index, case in enumerate(value):
        item_field = f"{field}[{index}]"
        if not isinstance(case, dict) or set(case) != _CASE_KEYS:
            raise ValueError(
                f"{item_field} must be a dict with exactly the keys id, facts"
            )
        case_id = _check_non_empty_str(case["id"], f"{item_field}.id")
        if case_id in seen:
            raise ValueError(f"{field} has a duplicate case id: {case_id!r}")
        if previous_id is not None and case_id <= previous_id:
            raise ValueError(f"{field} case ids must be strictly ascending")
        _check_fact_map(case["facts"], f"{item_field}.facts")
        cases.append({"id": case_id, "facts": _sorted_fact_map(case["facts"])})
        seen.add(case_id)
        previous_id = case_id
    return cases


def _normalize_verified_matrix(
    value: Any,
    start: str,
    end: str,
    input_cases: list[dict[str, Any]],
    field: str,
) -> list[dict[str, Any]]:
    """Validate an embedded decision matrix structurally.

    Returns the normalized matrix points. The matrix must have exactly the
    :func:`decision_matrix` keys with its window equal to the report window;
    ``points`` must be a non-empty list with strictly increasing ``at``
    values inside ``[start, end]`` and the first point at ``start``. Each
    point must have exactly the keys ``at``, ``changes``, ``cases``;
    ``changes`` must be a list of distinct non-empty strings and ``cases``
    must contain one entry per attested input case, in the same strictly
    ascending id order, with each entry conforming to the :func:`explain`
    contract at the point's ``at``. Semantic agreement with a matrix rebuilt
    from the attested schedule is checked separately. Any violation raises
    ``ValueError``.
    """
    if not isinstance(value, dict) or set(value) != _MATRIX_RESULT_KEYS:
        raise ValueError(
            f"{field} must be a dict with exactly the keys start, end, points"
        )
    matrix_start = _check_time(value["start"], f"{field}.start")
    matrix_end = _check_time(value["end"], f"{field}.end")
    if matrix_start != start or matrix_end != end:
        raise ValueError(f"{field}.start/end must equal report.start/end")
    raw_points = value["points"]
    if not isinstance(raw_points, list) or not raw_points:
        raise ValueError(f"{field}.points must be a non-empty list")
    points: list[dict[str, Any]] = []
    previous_at: str | None = None
    for index, point in enumerate(raw_points):
        point_field = f"{field}.points[{index}]"
        if not isinstance(point, dict) or set(point) != _MATRIX_POINT_KEYS:
            raise ValueError(
                f"{point_field} must be a dict with exactly the keys "
                "at, changes, cases"
            )
        at = _check_time(point["at"], f"{point_field}.at")
        if not start <= at <= end:
            raise ValueError(f"{point_field}.at lies outside [start, end]")
        if index == 0:
            if at != start:
                raise ValueError(f"{field}.points[0].at must equal start")
        elif at <= previous_at:  # type: ignore[operator]
            raise ValueError(f"{field} points must be strictly increasing in at")
        raw_changes = point["changes"]
        if not isinstance(raw_changes, list):
            raise ValueError(f"{point_field}.changes must be a list")
        changes: list[str] = []
        for change_index, change in enumerate(raw_changes):
            change_field = f"{point_field}.changes[{change_index}]"
            if not isinstance(change, str) or not change:
                raise ValueError(f"{change_field} must be a non-empty case id")
            if change in changes:
                raise ValueError(f"{point_field}.changes must not repeat case ids")
            changes.append(change)
        raw_cases = point["cases"]
        if not isinstance(raw_cases, list):
            raise ValueError(f"{point_field}.cases must be a list of case dicts")
        if len(raw_cases) != len(input_cases):
            raise ValueError(
                f"{point_field}.cases must contain one entry per attested "
                "input case"
            )
        entries: list[dict[str, Any]] = []
        for case_index, entry in enumerate(raw_cases):
            entry_field = f"{point_field}.cases[{case_index}]"
            if not isinstance(entry, dict) or set(entry) != _MATRIX_RESULT_CASE_KEYS:
                raise ValueError(
                    f"{entry_field} must be a dict with exactly the keys "
                    "id, decision, trace, basis, conflicts"
                )
            case_id = _check_non_empty_str(entry["id"], f"{entry_field}.id")
            if case_id != input_cases[case_index]["id"]:
                raise ValueError(
                    f"{entry_field}.id must match the attested input case id "
                    "at the same position"
                )
            explanation = _normalize_verified_explanation(
                {
                    "at": at,
                    "decision": entry["decision"],
                    "trace": entry["trace"],
                    "basis": entry["basis"],
                    "conflicts": entry["conflicts"],
                },
                at,
                entry_field,
            )
            entries.append(
                {
                    "id": case_id,
                    "decision": explanation["decision"],
                    "trace": explanation["trace"],
                    "basis": explanation["basis"],
                    "conflicts": explanation["conflicts"],
                }
            )
        points.append({"at": at, "changes": changes, "cases": entries})
        previous_at = at
    return points


def _rebuild_matrix_from_schedule(
    start: str,
    end: str,
    cases: list[dict[str, Any]],
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Rebuild the full decision matrix implied by an attested schedule.

    The candidate timestamps are ``start`` plus every rule ``from``/non-empty
    ``to`` boundary visible in the schedule's attested snapshots that falls in
    ``(start, end]``; :func:`explain` is re-evaluated at each candidate for
    every case in attested ``id`` order, the first point is always kept, and
    later points are kept exactly when at least one case's ``decision``,
    ``trace``, ``basis``, or ``conflicts`` changes — the
    :func:`decision_matrix` rule. The original rules are not needed; the
    union of the attested snapshots supplies every rule.
    """
    rules: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for point in policy["points"]:
        for rule in point["rules"]:
            key = (rule["source"], rule["id"], rule["ver"])
            if key not in seen:
                seen.add(key)
                rules.append(rule)
    candidates = {start}
    for rule in rules:
        for boundary in (rule["from"], rule["to"]):
            if boundary is not None and start < boundary <= end:
                candidates.add(boundary)

    def explain_cases(at: str) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for case in cases:
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

    first_cases = explain_cases(start)
    points = [{"at": start, "changes": [], "cases": first_cases}]
    previous_cases = first_cases
    for at in sorted(candidates - {start}):
        current_cases = explain_cases(at)
        changed = [
            entry["id"]
            for entry, previous in zip(current_cases, previous_cases)
            if any(previous[field] != entry[field] for field in _COMPARE_FIELDS)
        ]
        if not changed:
            continue
        points.append({"at": at, "changes": changed, "cases": current_cases})
        previous_cases = current_cases
    return {"start": start, "end": end, "points": points}


def _check_verified_matrix_attestation(
    report: Any, field: str = "report"
) -> tuple[dict[str, Any], str, str, bool, str]:
    """Run every structural and semantic matrix-attestation check.

    Enforces the full :func:`decision_matrix_attestation` contract exactly as
    :func:`verify_decision_matrix_attestation` does — key sets, types, value
    domains, time window, the embedded schedule's structural and semantic
    checks, and the matrix rebuilt from the attested schedule — and returns
    ``(content, declared_digest, recomputed_digest, chain_ok, chain_root)``
    where ``content`` is a fresh canonical-order dict over ``start``, ``end``,
    ``cases``, ``matrix``, ``policy`` matching :func:`decision_matrix_attestation`
    output. Any structural or semantic violation raises ``ValueError`` and the
    input is never mutated. A false declared digest or a broken embedded chain
    is reported via the returned values, not raised, mirroring the single
    report's ``False`` semantics.
    """
    if not isinstance(report, dict) or set(report) != _MATRIX_ATTEST_REPORT_KEYS:
        raise ValueError(
            f"{field} must be a dict with exactly the keys "
            "start, end, cases, matrix, policy, digest"
        )
    start = _check_time(report["start"], f"{field}.start")
    end = _check_time(report["end"], f"{field}.end")
    if start > end:
        raise ValueError(f"{field}.start must not be after {field}.end")
    digest = _check_hex64(report["digest"], f"{field}.digest")
    cases = _normalize_verified_matrix_cases(report["cases"], f"{field}.cases")
    policy = _normalize_verified_schedule_report(report["policy"], f"{field}.policy")
    if policy["start"] != start or policy["end"] != end:
        raise ValueError(f"{field}.policy.start/end must equal {field}.start/end")
    matrix_points = _normalize_verified_matrix(
        report["matrix"], start, end, cases, f"{field}.matrix"
    )
    rebuilt_matrix = _rebuild_matrix_from_schedule(start, end, cases, policy)
    declared_matrix = {"start": start, "end": end, "points": matrix_points}
    if declared_matrix != rebuilt_matrix:
        raise ValueError(
            f"{field}.matrix does not match the matrix rebuilt from "
            f"{field}.cases and {field}.policy under the decision_matrix "
            "contract"
        )
    chain_ok, chain_root = _recompute_schedule_root(policy["points"])
    content = {
        "start": start,
        "end": end,
        "cases": cases,
        "matrix": rebuilt_matrix,
        "policy": policy,
    }
    canonical = json.dumps(content, ensure_ascii=False, separators=(",", ":"))
    recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return content, digest, recomputed, chain_ok, chain_root


def _canonical_matrix_attestation(report: Any, field: str) -> dict[str, Any]:
    """Return a canonical member report, raising unless it fully verifies.

    Used when bundling: the member must fully conform to the published single
    :func:`decision_matrix_attestation` contract, so a false declared digest
    or a broken embedded policy chain raises ``ValueError`` alongside every
    structural and semantic violation. The returned dict is a fresh
    canonical-order copy (with the declared digest) that byte-for-byte matches
    :func:`decision_matrix_attestation` output.
    """
    content, digest, recomputed, chain_ok, chain_root = (
        _check_verified_matrix_attestation(report, field)
    )
    if not chain_ok or content["policy"]["root"] != chain_root:
        raise ValueError(f"{field}.policy hash chain or root does not verify")
    if digest != recomputed:
        raise ValueError(f"{field}.digest does not match its recomputed value")
    canonical_report = copy.deepcopy(content)
    canonical_report["digest"] = digest
    return canonical_report


def verify_decision_matrix_attestation(report: Any, expected: Any) -> bool:
    """Verify a :func:`decision_matrix_attestation` report by recomputation.

    Pure function: it only inspects its arguments, needs no original rules
    (the attested schedule snapshots are sufficient), touches neither
    history nor files, and never mutates an input object at any level.

    ``report`` must be a dict with exactly the keys ``start``, ``end``,
    ``cases``, ``matrix``, ``policy``, ``digest`` and conform level by level
    to the :func:`decision_matrix_attestation` contract. ``start``/``end``
    must be valid UTC seconds with ``start <= end`` and ``digest`` must be 64
    lowercase hexadecimal characters. ``cases`` must list ``id``/``facts``
    items whose ids are non-empty, unique, and strictly ascending in Unicode
    code point order and whose fact values are bool (an empty list is
    valid). ``policy`` must be a full :func:`policy_schedule_attestation`
    report over the same window and pass the existing schedule checks,
    including snapshots, deltas, conflicts, and the hash chain. ``matrix``
    must have exactly the keys ``start``, ``end``, ``points`` with the same
    window; its points must be strictly increasing inside ``[start, end]``
    (first point at ``start``), each with exactly the keys ``at``,
    ``changes``, ``cases``; ``changes`` must be distinct non-empty strings
    and ``cases`` must hold one structurally valid :func:`explain`-shaped
    entry per attested input case in the same id order. ``expected`` must
    have exactly the keys ``start``, ``end``, ``digest`` and is validated the
    same way. All key-set, type, value-domain, and time checks complete
    before any semantic rebuild or comparison.

    The matrix is then rebuilt by re-evaluating the attested facts against
    the rules visible in the policy snapshots, following the
    :func:`decision_matrix` candidate and filtering rules; the reported
    points must match the rebuilt matrix item by item — times, per-case
    explanations, retained points, and the ``changes`` case-id lists — in
    order. Any structural or semantic forgery raises ``ValueError``.

    Afterwards the embedded schedule hash chain and the report digest are
    recomputed as the lowercase hexadecimal SHA-256 of the compact UTF-8
    JSON bytes over ``start``, ``end``, ``cases``, ``matrix``, ``policy`` in
    that key order. Returns ``False`` when the declared digest, a timestamp,
    the window, an ``expected`` value, a chain link, or the root does not
    match; otherwise ``True``.
    """
    if not isinstance(expected, dict) or set(expected) != (
        _MATRIX_ATTEST_EXPECTED_KEYS
    ):
        raise ValueError(
            "expected must be a dict with exactly the keys start, end, digest"
        )
    expected_start = _check_time(expected["start"], "expected.start")
    expected_end = _check_time(expected["end"], "expected.end")
    if expected_start > expected_end:
        raise ValueError("expected.start must not be after expected.end")
    expected_digest = _check_hex64(expected["digest"], "expected.digest")

    content, digest, recomputed, chain_ok, chain_root = (
        _check_verified_matrix_attestation(report, "report")
    )
    if (
        content["start"] != expected_start
        or content["end"] != expected_end
        or digest != expected_digest
    ):
        return False
    if not chain_ok or content["policy"]["root"] != chain_root:
        return False
    return digest == recomputed


_MATRIX_BUNDLE_ITEM_KEYS = frozenset({"id", "report"})
_MATRIX_BUNDLE_REPORT_KEYS = ("root", "reports")
_MATRIX_BUNDLE_MEMBER_KEYS = ("id", "report", "previous", "digest")
_MATRIX_BUNDLE_EXPECTED_KEYS = ("root", "report_ids")
_MATRIX_BUNDLE_GENESIS = "0" * 64


def _validate_matrix_bundle_items(items: Any) -> list[tuple[str, Any]]:
    """Validate the ``items`` argument of :func:`decision_matrix_attestation_bundle`.

    ``items`` must be a non-empty list whose members are dicts with exactly
    the keys ``id``, ``report``; ``id`` must be a non-empty string unique
    across the list. Member reports are not checked here; they are validated
    separately with the single-report contract. Any violation raises
    ``ValueError``.
    """
    if not isinstance(items, list) or not items:
        raise ValueError("items must be a non-empty list of {id, report} dicts")
    members: list[tuple[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        field = f"items[{index}]"
        if not isinstance(item, dict) or set(item) != _MATRIX_BUNDLE_ITEM_KEYS:
            raise ValueError(
                f"{field} must be a dict with exactly the keys id, report"
            )
        item_id = _check_non_empty_str(item["id"], f"{field}.id")
        if item_id in seen:
            raise ValueError(f"items contains a duplicate id: {item_id!r}")
        seen.add(item_id)
        members.append((item_id, item["report"]))
    return members


def _matrix_bundle_member_digest(previous: str, item_id: str, report: Any) -> str:
    """Compute one bundle member digest.

    The payload contains exactly ``id``, ``report`` in that key order and is
    encoded as compact UTF-8 JSON with no newline; the digest is the lowercase
    hexadecimal SHA-256 of ``previous``'s ASCII bytes immediately followed by
    those payload bytes.
    """
    payload = {"id": item_id, "report": report}
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(
        previous.encode("ascii") + canonical.encode("utf-8")
    ).hexdigest()


def decision_matrix_attestation_bundle(items: Any) -> dict[str, Any]:
    """Bind multiple decision matrix attestations into one verifiable bundle.

    Pure function: it only processes its argument, accesses neither history
    nor files, and never mutates an input object at any level.

    ``items`` must be a non-empty list whose members are dicts with exactly
    the keys ``id`` and ``report``; ``id`` must be a non-empty string unique
    across the list (duplicates or wrong types raise ``ValueError``), and
    every ``report`` must fully conform to the published single
    :func:`decision_matrix_attestation` contract. Members are checked with
    the existing verification semantics before anything is produced: any
    structural or semantic violation, including a false sub-report digest,
    raises ``ValueError``.

    Members are ordered by ``id`` in ascending Unicode code point order, so
    the caller's order never affects the result. Returns a deep copy with
    keys ``root``, ``reports`` in that order; each member has keys ``id``,
    ``report``, ``previous``, ``digest``. The first member's ``previous`` is
    64 ASCII ``0`` characters; every later member's ``previous`` is the
    preceding member's ``digest``. The per-member digest payload contains
    exactly ``id``, ``report`` in that key order, encoded as compact UTF-8
    JSON (``ensure_ascii=False``, ``separators=(',', ':')``) with no
    newline, and ``digest`` is the lowercase hexadecimal SHA-256 of
    ``previous``'s ASCII bytes immediately followed by that payload.
    ``root`` is the last member's ``digest``. Equal-valued inputs yield
    byte-identical results.
    """
    members = _validate_matrix_bundle_items(items)
    normalized: list[tuple[str, dict[str, Any]]] = []
    for index, (item_id, raw_report) in enumerate(members):
        report = _canonical_matrix_attestation(raw_report, f"items[{index}].report")
        normalized.append((item_id, report))
    normalized.sort(key=lambda member: member[0])
    reports: list[dict[str, Any]] = []
    previous = _MATRIX_BUNDLE_GENESIS
    digest = previous
    for item_id, report in normalized:
        digest = _matrix_bundle_member_digest(previous, item_id, report)
        reports.append(
            {
                "id": item_id,
                "report": copy.deepcopy(report),
                "previous": previous,
                "digest": digest,
            }
        )
        previous = digest
    return {"root": digest, "reports": reports}


def _validate_matrix_bundle_report_ids(value: Any, field: str) -> list[str]:
    """Validate a non-empty list of unique non-empty strings."""
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a non-empty list of non-empty strings")
    ids: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        item_id = _check_non_empty_str(item, f"{field}[{index}]")
        if item_id in seen:
            raise ValueError(f"{field} must not contain duplicates: {item_id!r}")
        seen.add(item_id)
        ids.append(item_id)
    return ids


def _normalize_verified_matrix_bundle(
    report: Any, field: str = "report"
) -> tuple[str, list[dict[str, Any]]]:
    """Run every structural and single-report check on a matrix bundle.

    Enforces the full :func:`decision_matrix_attestation_bundle` report
    contract exactly as :func:`verify_decision_matrix_attestation_bundle`
    does: exact key sets, root/member digest formats, unique strictly
    ascending member ids, and every member sub-report's single-report
    structural and semantic checks. A false sub-report digest or a broken
    embedded policy chain is structural data, so it is carried back via the
    returned member entries (``sub_recomputed``, ``sub_chain_ok``,
    ``sub_chain_root``) rather than raised, mirroring the ``False``
    semantics. Returns ``(root, members)`` where each member carries a fresh
    canonical-order deep copy of its sub-report. Any structural or semantic
    violation raises ``ValueError`` and the input is never mutated.
    """
    if not isinstance(report, dict) or set(report) != set(_MATRIX_BUNDLE_REPORT_KEYS):
        raise ValueError(
            f"{field} must be a dict with exactly the keys root, reports"
        )
    bundle_root = _check_hex64(report["root"], f"{field}.root")
    raw_reports = report["reports"]
    if not isinstance(raw_reports, list) or not raw_reports:
        raise ValueError(f"{field}.reports must be a non-empty list")
    members: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    previous_id: str | None = None
    for index, member in enumerate(raw_reports):
        member_field = f"{field}.reports[{index}]"
        if not isinstance(member, dict) or set(member) != set(
            _MATRIX_BUNDLE_MEMBER_KEYS
        ):
            raise ValueError(
                f"{member_field} must be a dict with exactly the keys "
                "id, report, previous, digest"
            )
        item_id = _check_non_empty_str(member["id"], f"{member_field}.id")
        if item_id in seen_ids:
            raise ValueError(
                f"{field}.reports contains a duplicate id: {item_id!r}"
            )
        if previous_id is not None and item_id <= previous_id:
            raise ValueError(
                f"{field}.reports must be ordered by id in ascending "
                "Unicode code point order"
            )
        # Structural and single-report semantic violations raise; a false
        # sub-report digest or broken embedded chain is reported back as data
        # so it can yield False only after every input validates.
        content, sub_digest, sub_recomputed, sub_chain_ok, sub_chain_root = (
            _check_verified_matrix_attestation(
                member["report"], f"{member_field}.report"
            )
        )
        previous = _check_hex64(member["previous"], f"{member_field}.previous")
        digest = _check_hex64(member["digest"], f"{member_field}.digest")
        canonical_sub_report = copy.deepcopy(content)
        canonical_sub_report["digest"] = sub_digest
        members.append(
            {
                "id": item_id,
                "report": canonical_sub_report,
                "previous": previous,
                "digest": digest,
                "sub_recomputed": sub_recomputed,
                "sub_chain_ok": sub_chain_ok,
                "sub_chain_root": sub_chain_root,
                "sub_declared_root": content["policy"]["root"],
            }
        )
        seen_ids.add(item_id)
        previous_id = item_id
    return bundle_root, members


def verify_decision_matrix_attestation_bundle(report: Any, expected: Any) -> bool:
    """Verify a :func:`decision_matrix_attestation_bundle` by recomputation.

    Pure function: it only inspects its arguments, touches neither history
    nor files, and never mutates an input object at any level.

    ``report`` must be a dict with exactly the keys ``root``, ``reports`` and
    ``expected`` a dict with exactly the keys ``root``, ``report_ids``.
    ``root`` must be 64 lowercase hexadecimal characters and ``report_ids``
    a non-empty list of unique non-empty strings (caller order is arbitrary;
    comparison is by code point). ``reports`` must be a non-empty list whose
    members are dicts with exactly the keys ``id``, ``report``,
    ``previous``, ``digest``, ordered by ``id`` in ascending Unicode code
    point order with bundle-wide unique non-empty ids; each ``previous`` and
    ``digest`` must be 64 lowercase hexadecimal characters, and every
    ``report`` must fully pass the existing single
    :func:`verify_decision_matrix_attestation` structural and semantic
    checks (its own declared digest included). Both inputs complete every
    key-set, type, digest-format, member-order, and single-report semantic
    check before any comparison; any violation raises ``ValueError``.

    Once the structures are legal, every sub-report digest, each chain link,
    the bundle root, and the expected values are recomputed rather than
    trusted. Returns ``False`` when a sub-report digest is false, a
    ``previous``/``digest`` link does not chain, the final ``root`` does not
    equal the last member digest, the declared ``root`` differs from the
    recomputed value, or the ``root`` or ``report_ids`` set differ from
    ``expected`` (ids compared after code point sorting); otherwise
    ``True``.
    """
    bundle_root, members = _normalize_verified_matrix_bundle(report, "report")
    seen_ids = {member["id"] for member in members}

    if not isinstance(expected, dict) or set(expected) != set(
        _MATRIX_BUNDLE_EXPECTED_KEYS
    ):
        raise ValueError(
            "expected must be a dict with exactly the keys root, report_ids"
        )
    expected_root = _check_hex64(expected["root"], "expected.root")
    expected_ids = _validate_matrix_bundle_report_ids(
        expected["report_ids"], "expected.report_ids"
    )

    # Both inputs have now passed every key-set, type, digest-format,
    # member-order, and single-report semantic check. Only now recompute and
    # compare; any mismatch yields False rather than raising.
    previous = _MATRIX_BUNDLE_GENESIS
    for member in members:
        if (
            not member["sub_chain_ok"]
            or member["sub_declared_root"] != member["sub_chain_root"]
            or member["report"]["digest"] != member["sub_recomputed"]
        ):
            return False
        if member["previous"] != previous:
            return False
        recomputed = _matrix_bundle_member_digest(
            previous, member["id"], member["report"]
        )
        if member["digest"] != recomputed:
            return False
        previous = recomputed
    if bundle_root != previous:
        return False
    if bundle_root != expected_root:
        return False
    if seen_ids != set(expected_ids):
        return False
    return True


_MATRIX_BUNDLE_DIFF_KEYS = frozenset({"before", "after"})
_MATRIX_BUNDLE_DIFF_REPORT_KEYS = (
    "before_root",
    "after_root",
    "before",
    "after",
    "changes",
    "digest",
)
_MATRIX_BUNDLE_DIFF_CHANGE_KEYS = frozenset({"id", "kind", "before", "after"})
_MATRIX_BUNDLE_DIFF_EXPECTED_KEYS = (
    "before_root",
    "after_root",
    "before_ids",
    "after_ids",
    "digest",
)
_MATRIX_BUNDLE_DIFF_KINDS = frozenset({"added", "removed", "changed"})


def _matrix_bundle_is_truthful(
    bundle_root: str, members: list[dict[str, Any]]
) -> bool:
    """Recompute a structurally normalized bundle's full hash chain.

    Every sub-report digest and embedded policy chain must verify, each
    ``previous``/``digest`` link must chain from the 64-zero genesis, and the
    declared bundle ``root`` must equal the final member digest.
    """
    previous = _MATRIX_BUNDLE_GENESIS
    for member in members:
        if (
            not member["sub_chain_ok"]
            or member["sub_declared_root"] != member["sub_chain_root"]
            or member["report"]["digest"] != member["sub_recomputed"]
        ):
            return False
        if member["previous"] != previous:
            return False
        recomputed = _matrix_bundle_member_digest(
            previous, member["id"], member["report"]
        )
        if member["digest"] != recomputed:
            return False
        previous = recomputed
    return bundle_root == previous


def _canonical_bundle_from_members(
    bundle_root: str, members: list[dict[str, Any]]
) -> dict[str, Any]:
    """Rebuild a fresh ``root, reports`` bundle from normalized members."""
    return {
        "root": bundle_root,
        "reports": [
            {
                "id": member["id"],
                "report": copy.deepcopy(member["report"]),
                "previous": member["previous"],
                "digest": member["digest"],
            }
            for member in members
        ],
    }


def _matrix_member_content(member: dict[str, Any]) -> dict[str, Any]:
    """Return a normalized bundle member's sub-report without its digest."""
    return {key: member["report"][key] for key in _MATRIX_ATTEST_CONTENT_KEYS}


def _matrix_credential_semantics(content: dict[str, Any]) -> dict[str, Any]:
    """Project a normalized matrix credential to its summary-free content.

    The credential's own digest and the embedded schedule's ``root``,
    ``previous``, and per-point ``digest`` fields are summaries, not
    semantics: two credentials with the same facts, matrix, rules,
    conflicts, and deltas but different hash fields describe the same
    member. Change-side credentials are compared with bundle members on
    this projection, so a false summary yields ``False`` at recomputation
    rather than a structural mismatch, while genuinely different content
    still raises ``ValueError``.
    """
    policy = content["policy"]
    return {
        "start": content["start"],
        "end": content["end"],
        "cases": copy.deepcopy(content["cases"]),
        "matrix": copy.deepcopy(content["matrix"]),
        "policy": {
            "start": policy["start"],
            "end": policy["end"],
            "points": [
                {key: point[key] for key in _SCHEDULE_POINT_CONTENT_KEYS}
                for point in policy["points"]
            ],
        },
    }


def _matrix_member_semantics(member: dict[str, Any]) -> dict[str, Any]:
    """Summary-free semantic projection of a normalized bundle member."""
    return _matrix_credential_semantics(_matrix_member_content(member))


def _bundle_member_semantics(bundle: dict[str, Any]) -> list[tuple[str, Any]]:
    """Summary-free semantic projection of a canonical bundle.

    Projects a ``root, reports`` bundle to the ordered list of member ids and
    their summary-free credentials, so a bundle embedded inside a diff can be
    checked against the neighboring stage bundle on semantics: a false member
    or root summary then yields ``False`` at recomputation instead of a
    structural ``ValueError``.
    """
    return [
        (member["id"], _matrix_member_semantics(member))
        for member in bundle["reports"]
    ]


def matrix_bundle_diff(before: Any, after: Any) -> dict[str, Any]:
    """Attest the difference between two decision matrix attestation bundles.

    Pure function: it only processes its arguments, accesses neither history
    nor files, and never mutates an input object at any level.

    Both ``before`` and ``after`` must be complete
    :func:`decision_matrix_attestation_bundle` reports. Before anything is
    produced, both sides pass the full
    :func:`verify_decision_matrix_attestation_bundle` structural and semantic
    checks: key sets, digest formats, unique strictly ascending member ids,
    and every embedded single matrix credential; the second side is still
    fully checked when the first side merely carries a false digest. Any
    structural or semantic violation, and any false sub-report digest, chain
    link, or bundle root on either side, raises ``ValueError``.

    Returns a deep copy with keys ``before_root``, ``after_root``,
    ``before``, ``after``, ``changes``, ``digest`` in that order;
    ``before_root``/``after_root`` are the two bundles' roots and
    ``before``/``after`` are independent deep copies of the normalized
    bundles. Members are matched by ``id``; ``changes`` keeps only the
    ``added`` (only in ``after``), ``removed`` (only in ``before``), and
    ``changed`` (present in both but with a different matrix credential)
    members, ordered by ``id`` in ascending Unicode code point order. Each
    change has keys ``id``, ``kind``, ``before``, ``after``; the two sides
    are deep copies of the single matrix credential or ``null``. Identical
    bundles yield an empty ``changes`` list.

    Let ``C`` be the UTF-8 bytes of compact JSON (``ensure_ascii=False``,
    ``separators=(',', ':')``) with no newline over a payload containing
    exactly the first five keys in order. ``digest`` is the lowercase
    64-char hex SHA-256 of ``C``. Equal-valued inputs yield byte-identical
    results regardless of input dict key order, and no two levels share a
    mutable container.
    """
    before_root, before_members = _normalize_verified_matrix_bundle(
        before, "before"
    )
    after_root, after_members = _normalize_verified_matrix_bundle(
        after, "after"
    )
    if not _matrix_bundle_is_truthful(before_root, before_members):
        raise ValueError("before bundle root or hash chain does not verify")
    if not _matrix_bundle_is_truthful(after_root, after_members):
        raise ValueError("after bundle root or hash chain does not verify")

    before_bundle = _canonical_bundle_from_members(before_root, before_members)
    after_bundle = _canonical_bundle_from_members(after_root, after_members)
    before_by_id = {member["id"]: member for member in before_members}
    after_by_id = {member["id"]: member for member in after_members}

    changes: list[dict[str, Any]] = []
    for member_id in sorted(set(before_by_id) | set(after_by_id)):
        before_member = before_by_id.get(member_id)
        after_member = after_by_id.get(member_id)
        if (
            before_member is not None
            and after_member is not None
            and before_member["report"] == after_member["report"]
        ):
            continue
        if before_member is None:
            kind = "added"
        elif after_member is None:
            kind = "removed"
        else:
            kind = "changed"
        changes.append(
            {
                "id": member_id,
                "kind": kind,
                "before": (
                    copy.deepcopy(before_member["report"])
                    if before_member is not None
                    else None
                ),
                "after": (
                    copy.deepcopy(after_member["report"])
                    if after_member is not None
                    else None
                ),
            }
        )

    payload = {
        "before_root": before_root,
        "after_root": after_root,
        "before": before_bundle,
        "after": after_bundle,
        "changes": changes,
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    result = copy.deepcopy(payload)
    result["digest"] = digest
    return result


def _normalize_diff_change_credential(
    value: Any, field: str
) -> tuple[dict[str, Any], str, str, bool, str] | None:
    """Validate one non-null change-side matrix credential.

    Returns the same tuple :func:`_check_verified_matrix_attestation`
    returns (canonical content, declared digest, recomputed digest, embedded
    chain ok, embedded chain root), or ``None`` for an explicit null.
    Structural and single-report semantic violations raise ``ValueError``; a
    false digest is carried back as data.
    """
    if value is None:
        return None
    return _check_verified_matrix_attestation(value, field)


def _normalize_verified_matrix_bundle_diff_changes(
    value: Any,
    before_members: list[dict[str, Any]],
    after_members: list[dict[str, Any]],
    field: str,
) -> list[dict[str, Any]]:
    """Structurally validate a diff ``changes`` list against both bundles.

    Each change must have exactly the keys ``id``, ``kind``, ``before``,
    ``after``; ids non-empty, bundle-wide unique, and strictly ascending in
    Unicode code point order; ``kind`` one of ``added``, ``removed``,
    ``changed``; each non-null side a fully valid single matrix credential.
    Every change must agree with the two bundles — right kind for its id's
    presence, correct null sides, and credential content equal to the
    corresponding bundle member's credential — and the list must be
    complete: every added or removed member and every present-in-both member
    whose credential content differs must appear, unchanged members must
    not. Returns fresh normalized entries carrying canonical declared
    credentials and their digest-truth data. Any violation raises
    ``ValueError``.
    """
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list of change dicts")
    before_by_id = {member["id"]: member for member in before_members}
    after_by_id = {member["id"]: member for member in after_members}

    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    previous_id: str | None = None
    for index, change in enumerate(value):
        item_field = f"{field}[{index}]"
        if not isinstance(change, dict) or set(change) != _MATRIX_BUNDLE_DIFF_CHANGE_KEYS:
            raise ValueError(
                f"{item_field} must be a dict with exactly the keys "
                "id, kind, before, after"
            )
        member_id = _check_non_empty_str(change["id"], f"{item_field}.id")
        if member_id in seen:
            raise ValueError(f"{field} contains a duplicate change id: {member_id!r}")
        if previous_id is not None and member_id <= previous_id:
            raise ValueError(
                f"{field} must be ordered by id in ascending Unicode code "
                "point order"
            )
        kind = change["kind"]
        if kind not in _MATRIX_BUNDLE_DIFF_KINDS:
            raise ValueError(
                f"{item_field}.kind must be 'added', 'removed', or 'changed'"
            )
        before_data = _normalize_diff_change_credential(
            change["before"], f"{item_field}.before"
        )
        after_data = _normalize_diff_change_credential(
            change["after"], f"{item_field}.after"
        )
        before_member = before_by_id.get(member_id)
        after_member = after_by_id.get(member_id)
        if kind == "added":
            if before_data is not None or after_data is None:
                raise ValueError(
                    f"{item_field} is 'added' but before/after do not match "
                    "the contract"
                )
            if before_member is not None or after_member is None:
                raise ValueError(
                    f"{item_field} id {member_id!r} is not added between the "
                    "two bundles"
                )
            if _matrix_credential_semantics(after_data[0]) != _matrix_member_semantics(
                after_member
            ):
                raise ValueError(
                    f"{item_field}.after does not equal the after bundle's "
                    f"credential for id {member_id!r}"
                )
        elif kind == "removed":
            if before_data is None or after_data is not None:
                raise ValueError(
                    f"{item_field} is 'removed' but before/after do not "
                    "match the contract"
                )
            if before_member is None or after_member is not None:
                raise ValueError(
                    f"{item_field} id {member_id!r} is not removed between "
                    "the two bundles"
                )
            if _matrix_credential_semantics(
                before_data[0]
            ) != _matrix_member_semantics(before_member):
                raise ValueError(
                    f"{item_field}.before does not equal the before bundle's "
                    f"credential for id {member_id!r}"
                )
        else:
            if before_data is None or after_data is None:
                raise ValueError(
                    f"{item_field} is 'changed' but before/after do not "
                    "match the contract"
                )
            if before_member is None or after_member is None:
                raise ValueError(
                    f"{item_field} id {member_id!r} must exist in both "
                    "bundles to be 'changed'"
                )
            if _matrix_credential_semantics(
                before_data[0]
            ) != _matrix_member_semantics(before_member):
                raise ValueError(
                    f"{item_field}.before does not equal the before bundle's "
                    f"credential for id {member_id!r}"
                )
            if _matrix_credential_semantics(after_data[0]) != _matrix_member_semantics(
                after_member
            ):
                raise ValueError(
                    f"{item_field}.after does not equal the after bundle's "
                    f"credential for id {member_id!r}"
                )

        def canonical_credential(data: Any) -> dict[str, Any] | None:
            if data is None:
                return None
            credential = copy.deepcopy(data[0])
            credential["digest"] = data[1]
            return credential

        entries.append(
            {
                "id": member_id,
                "kind": kind,
                "before": canonical_credential(before_data),
                "after": canonical_credential(after_data),
                "before_truth": None if before_data is None else before_data[1:],
                "after_truth": None if after_data is None else after_data[1:],
            }
        )
        seen.add(member_id)
        previous_id = member_id

    expected_ids: set[str] = set(before_by_id) ^ set(after_by_id)
    for member_id in sorted(set(before_by_id) & set(after_by_id)):
        # Membership in the diff is a semantic question; false summaries are
        # recomputed afterwards and must not fabricate "changed" members.
        if _matrix_member_semantics(
            before_by_id[member_id]
        ) != _matrix_member_semantics(after_by_id[member_id]):
            expected_ids.add(member_id)
    if seen != expected_ids:
        raise ValueError(
            "changes must list exactly the added, removed, and changed "
            "members, with unchanged members omitted"
        )
    return entries


def _normalize_verified_matrix_diff_report(
    value: Any, field: str
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Run every structural and semantic check on a diff credential.

    Validates a :func:`matrix_bundle_diff`-shaped report exactly as
    :func:`verify_matrix_bundle_diff` does: the six exact keys, hex64
    summaries, root fields matching their embedded bundles, both bundles'
    full structural and embedded-credential checks, and the complete
    change-list consistency rules. Returns ``(content, before_members,
    after_members, change_entries)`` where ``content`` is a fresh
    canonical-order dict with the six diff keys (its ``before``/``after``
    bundles and change credentials are independent deep copies) and the
    remaining items carry the per-credential digest-truth data. False
    summaries are not detected here — callers recompute them afterwards,
    yielding ``False`` rather than ``ValueError``.
    """
    if not isinstance(value, dict) or set(value) != set(
        _MATRIX_BUNDLE_DIFF_REPORT_KEYS
    ):
        raise ValueError(
            f"{field} must be a dict with exactly the keys "
            "before_root, after_root, before, after, changes, digest"
        )
    before_root = _check_hex64(value["before_root"], f"{field}.before_root")
    after_root = _check_hex64(value["after_root"], f"{field}.after_root")
    digest = _check_hex64(value["digest"], f"{field}.digest")
    before_bundle_root, before_members = _normalize_verified_matrix_bundle(
        value["before"], f"{field}.before"
    )
    after_bundle_root, after_members = _normalize_verified_matrix_bundle(
        value["after"], f"{field}.after"
    )
    if before_bundle_root != before_root:
        raise ValueError(f"{field}.before_root must equal {field}.before.root")
    if after_bundle_root != after_root:
        raise ValueError(f"{field}.after_root must equal {field}.after.root")
    change_entries = _normalize_verified_matrix_bundle_diff_changes(
        value["changes"], before_members, after_members, f"{field}.changes"
    )
    declared_changes = [
        {
            "id": change["id"],
            "kind": change["kind"],
            "before": change["before"],
            "after": change["after"],
        }
        for change in change_entries
    ]
    content = {
        "before_root": before_root,
        "after_root": after_root,
        "before": _canonical_bundle_from_members(before_root, before_members),
        "after": _canonical_bundle_from_members(after_root, after_members),
        "changes": declared_changes,
        "digest": digest,
    }
    return content, before_members, after_members, change_entries


def verify_matrix_bundle_diff(report: Any, expected: Any) -> bool:
    """Verify a :func:`matrix_bundle_diff` report by recomputation.

    Pure function: it only inspects its arguments, touches neither history
    nor files, and never mutates an input object at any level.

    ``report`` must be a dict with exactly the keys ``before_root``,
    ``after_root``, ``before``, ``after``, ``changes``, ``digest`` and
    conform level by level to the :func:`matrix_bundle_diff` contract. The
    two roots and ``digest`` must be 64 lowercase hexadecimal characters,
    and each root must equal the root declared by its embedded bundle.
    ``before``/``after`` must be complete matrix bundles that pass every
    structural, member-order, digest-format, and embedded single-credential
    semantic check. ``changes`` items must have exactly the keys ``id``,
    ``kind``, ``before``, ``after`` with non-empty unique strictly ascending
    ids, legal kinds, null sides matching each kind, and non-null sides that
    are valid single matrix credentials and exactly reproduce the
    corresponding bundle members; the list must be complete and omit
    unchanged members. ``expected`` must have exactly the keys
    ``before_root``, ``after_root``, ``before_ids``, ``after_ids``,
    ``digest``; both id arrays must be non-empty lists of unique non-empty
    strings (caller order is arbitrary; comparison is by code point). Any
    structural, value-domain, uniqueness, ordering, or change-consistency
    violation raises ``ValueError``, and both inputs finish structural
    validation before any comparison.

    Only afterwards are values recomputed rather than trusted: every
    embedded sub-report digest and policy chain, both bundle hash chains and
    roots, and the diff digest over the five declared prefix items in their
    canonical compact-JSON form. Returns ``False`` when a sub-report digest,
    chain link, bundle root, the diff digest, or an ``expected`` value (the
    two roots, the digest, or either id set after code point sorting) does
    not match; otherwise ``True``.
    """
    content, before_members, after_members, changes = (
        _normalize_verified_matrix_diff_report(report, "report")
    )
    before_root = content["before_root"]
    after_root = content["after_root"]
    digest = content["digest"]

    if not isinstance(expected, dict) or set(expected) != set(
        _MATRIX_BUNDLE_DIFF_EXPECTED_KEYS
    ):
        raise ValueError(
            "expected must be a dict with exactly the keys "
            "before_root, after_root, before_ids, after_ids, digest"
        )
    expected_before_root = _check_hex64(
        expected["before_root"], "expected.before_root"
    )
    expected_after_root = _check_hex64(
        expected["after_root"], "expected.after_root"
    )
    expected_digest = _check_hex64(expected["digest"], "expected.digest")
    expected_before_ids = _validate_matrix_bundle_report_ids(
        expected["before_ids"], "expected.before_ids"
    )
    expected_after_ids = _validate_matrix_bundle_report_ids(
        expected["after_ids"], "expected.after_ids"
    )

    # Both inputs have now passed every key-set, type, digest-format,
    # ordering, and embedded-credential semantic check. Only now recompute
    # and compare; any mismatch yields False rather than raising.
    if not _matrix_bundle_is_truthful(before_root, before_members):
        return False
    if not _matrix_bundle_is_truthful(after_root, after_members):
        return False
    for change in changes:
        for credential, truth in (
            (change["before"], change["before_truth"]),
            (change["after"], change["after_truth"]),
        ):
            if truth is None:
                continue
            declared_digest, recomputed, chain_ok, chain_root = truth
            # The non-null change side is a standalone credential: its
            # declared digest must match, its embedded policy chain must
            # verify, and the declared policy root must end that chain.
            if (
                not chain_ok
                or declared_digest != recomputed
                or credential["policy"]["root"] != chain_root
            ):
                return False
    payload = {key: content[key] for key in _MATRIX_BUNDLE_DIFF_REPORT_KEYS[:5]}
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    recomputed_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if digest != recomputed_digest:
        return False
    if (
        before_root != expected_before_root
        or after_root != expected_after_root
        or digest != expected_digest
    ):
        return False
    if {member["id"] for member in before_members} != set(expected_before_ids):
        return False
    if {member["id"] for member in after_members} != set(expected_after_ids):
        return False
    return True


_MATRIX_BUNDLE_EVOLUTION_STAGE_ITEM_KEYS = frozenset({"at", "bundle"})
_MATRIX_BUNDLE_EVOLUTION_REPORT_KEYS = ("root", "stages")
_MATRIX_BUNDLE_EVOLUTION_STAGE_KEYS = ("at", "bundle", "diff", "previous", "digest")
_MATRIX_BUNDLE_EVOLUTION_EXPECTED_KEYS = ("root", "stages")
_MATRIX_BUNDLE_EVOLUTION_EXPECTED_STAGE_KEYS = frozenset({"at", "root"})
_MATRIX_BUNDLE_EVOLUTION_GENESIS = "0" * 64


def _matrix_bundle_evolution_stage_digest(
    previous: str, at: str, bundle: dict[str, Any], diff: dict[str, Any] | None
) -> str:
    """Compute one evolution stage digest.

    The payload contains exactly ``at``, ``bundle``, ``diff`` in that key
    order, encoded as compact UTF-8 JSON with no newline; the digest is the
    lowercase hexadecimal SHA-256 of ``previous``'s ASCII bytes immediately
    followed by those payload bytes.
    """
    payload = {"at": at, "bundle": bundle, "diff": diff}
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(
        previous.encode("ascii") + canonical.encode("utf-8")
    ).hexdigest()


def matrix_bundle_evolution(stages: Any) -> dict[str, Any]:
    """Chain decision matrix attestation bundles across release stages.

    Pure function: it only processes its argument, accesses neither history
    nor files, and never mutates an input object at any level.

    ``stages`` must be a non-empty list whose items are dicts with exactly
    the keys ``at`` and ``bundle``; array order is the release order. Each
    ``at`` must be a valid UTC second strictly increasing (a non-list, an
    empty list, duplicates, disorder, or extra fields raise ``ValueError``),
    and every ``bundle`` must pass every existing
    :func:`decision_matrix_attestation_bundle` structural, matrix-semantic,
    sub-summary, and chain-root check or raise ``ValueError``.

    Returns a deep copy with keys ``root``, ``stages`` in that order; each
    stage has keys ``at``, ``bundle``, ``diff``, ``previous``, ``digest``.
    The first stage's ``diff`` is ``null``; every later ``diff`` is the full
    :func:`matrix_bundle_diff` credential from the preceding bundle to the
    current one under the existing diff semantics. The first stage's
    ``previous`` is 64 ASCII ``0`` characters; every later stage's
    ``previous`` is the preceding stage's ``digest``. The per-stage payload
    contains exactly ``at``, ``bundle``, ``diff`` in that key order, encoded
    as compact UTF-8 JSON (``ensure_ascii=False``, ``separators=(',', ':')``)
    with no newline; ``digest`` is the lowercase hexadecimal SHA-256 of
    ``previous``'s ASCII bytes immediately followed by that payload, and
    ``root`` is the last stage's ``digest``. Equal-valued inputs yield
    byte-identical results and no level shares an input object.
    """
    if not isinstance(stages, list) or not stages:
        raise ValueError("stages must be a non-empty list of {at, bundle} dicts")
    normalized: list[tuple[str, dict[str, Any]]] = []
    previous_at: str | None = None
    for index, stage in enumerate(stages):
        field = f"stages[{index}]"
        if not isinstance(stage, dict) or set(stage) != (
            _MATRIX_BUNDLE_EVOLUTION_STAGE_ITEM_KEYS
        ):
            raise ValueError(
                f"{field} must be a dict with exactly the keys at, bundle"
            )
        at = _check_time(stage["at"], f"{field}.at")
        if previous_at is not None and at <= previous_at:
            raise ValueError(
                f"{field}.at must be strictly greater than the preceding at"
            )
        # Every bundle must fully verify (structure, semantics, sub-reports,
        # member chain, and root) before anything is produced.
        bundle_root, bundle_members = _normalize_verified_matrix_bundle(
            stage["bundle"], f"{field}.bundle"
        )
        if not _matrix_bundle_is_truthful(bundle_root, bundle_members):
            raise ValueError(f"{field}.bundle root or hash chain does not verify")
        normalized.append(
            (at, _canonical_bundle_from_members(bundle_root, bundle_members))
        )
        previous_at = at

    result_stages: list[dict[str, Any]] = []
    previous = _MATRIX_BUNDLE_EVOLUTION_GENESIS
    digest = previous
    prior_bundle: dict[str, Any] | None = None
    for at, bundle in normalized:
        diff = (
            None
            if prior_bundle is None
            else matrix_bundle_diff(prior_bundle, bundle)
        )
        digest = _matrix_bundle_evolution_stage_digest(previous, at, bundle, diff)
        result_stages.append(
            {
                "at": at,
                "bundle": copy.deepcopy(bundle),
                "diff": None if diff is None else copy.deepcopy(diff),
                "previous": previous,
                "digest": digest,
            }
        )
        prior_bundle = bundle
        previous = digest
    return {"root": digest, "stages": result_stages}


def _normalize_verified_matrix_bundle_evolution(
    report: Any, field: str = "report"
) -> tuple[str, list[dict[str, Any]]]:
    """Run every structural and semantic check on an evolution report.

    Enforces the full :func:`matrix_bundle_evolution` report contract:
    exact top-level and per-stage key sets, hex64 ``root``/``previous``/
    ``digest`` fields, a non-empty strictly increasing ``at`` chain, fully
    valid bundles, a ``null`` diff on the first stage and a complete
    structurally valid adjacent diff credential on every later stage whose
    embedded bundles reproduce the neighboring stage bundles. Returns
    ``(root, stages)`` with fresh normalized entries (canonical bundle and
    diff copies). A false declared bundle summary or broken bundle chain is
    carried back as ``bundle_truthful`` data so it yields ``False`` only
    after every input validates. Any structural or semantic violation
    raises ``ValueError`` and the input is never mutated.
    """
    if not isinstance(report, dict) or set(report) != set(
        _MATRIX_BUNDLE_EVOLUTION_REPORT_KEYS
    ):
        raise ValueError(
            f"{field} must be a dict with exactly the keys root, stages"
        )
    root = _check_hex64(report["root"], f"{field}.root")
    raw_stages = report["stages"]
    if not isinstance(raw_stages, list) or not raw_stages:
        raise ValueError(f"{field}.stages must be a non-empty list")

    normalized_stages: list[dict[str, Any]] = []
    previous_at: str | None = None
    for index, stage in enumerate(raw_stages):
        stage_field = f"{field}.stages[{index}]"
        if not isinstance(stage, dict) or set(stage) != set(
            _MATRIX_BUNDLE_EVOLUTION_STAGE_KEYS
        ):
            raise ValueError(
                f"{stage_field} must be a dict with exactly the keys "
                "at, bundle, diff, previous, digest"
            )
        at = _check_time(stage["at"], f"{stage_field}.at")
        if previous_at is not None and at <= previous_at:
            raise ValueError(
                f"{stage_field}.at must be strictly greater than the "
                "preceding stage at"
            )
        previous = _check_hex64(stage["previous"], f"{stage_field}.previous")
        digest = _check_hex64(stage["digest"], f"{stage_field}.digest")
        bundle_root, bundle_members = _normalize_verified_matrix_bundle(
            stage["bundle"], f"{stage_field}.bundle"
        )
        bundle = _canonical_bundle_from_members(bundle_root, bundle_members)
        bundle_truthful = _matrix_bundle_is_truthful(bundle_root, bundle_members)

        diff: dict[str, Any] | None
        if index == 0:
            if stage["diff"] is not None:
                raise ValueError(
                    f"{stage_field}.diff must be null on the first stage"
                )
            diff = None
        else:
            diff_content, _, _, _ = _normalize_verified_matrix_diff_report(
                stage["diff"], f"{stage_field}.diff"
            )
            if diff_content["before_root"] != normalized_stages[-1]["bundle_root"]:
                raise ValueError(
                    f"{stage_field}.diff.before_root must equal the preceding "
                    "stage bundle root"
                )
            if diff_content["after_root"] != bundle_root:
                raise ValueError(
                    f"{stage_field}.diff.after_root must equal this stage "
                    "bundle root"
                )
            if _bundle_member_semantics(
                diff_content["before"]
            ) != _bundle_member_semantics(normalized_stages[-1]["bundle"]):
                raise ValueError(
                    f"{stage_field}.diff.before must reproduce the preceding "
                    "stage bundle"
                )
            if _bundle_member_semantics(
                diff_content["after"]
            ) != _bundle_member_semantics(bundle):
                raise ValueError(
                    f"{stage_field}.diff.after must reproduce this stage bundle"
                )
            diff = diff_content

        normalized_stages.append(
            {
                "at": at,
                "bundle": bundle,
                "bundle_root": bundle_root,
                "bundle_truthful": bundle_truthful,
                "diff": diff,
                "previous": previous,
                "digest": digest,
            }
        )
        previous_at = at
    return root, normalized_stages


def verify_matrix_bundle_evolution(report: Any, expected: Any) -> bool:
    """Verify a :func:`matrix_bundle_evolution` report by recomputation.

    Pure function: it only inspects its arguments, touches neither history
    nor files, and never mutates an input object at any level.

    ``report`` must be a dict with exactly the keys ``root``, ``stages`` and
    conform level by level to the :func:`matrix_bundle_evolution` contract;
    ``expected`` must have exactly the keys ``root``, ``stages`` with a
    non-empty stage list whose items contain only strictly increasing ``at``
    values and the corresponding bundle ``root`` values. Every structure and
    semantic check — key sets, types, digest formats, strictly increasing
    timestamps, fully valid per-stage bundles and their embedded
    credentials, a ``null`` first diff, and each later stage's complete
    adjacent diff credential reproducing its neighbors — completes on both
    inputs before any comparison; any violation raises ``ValueError``.

    Only afterwards are values recomputed rather than trusted: every
    bundle's sub-summary and hash chain, each adjacent
    :func:`matrix_bundle_diff` credential (its digest included), every
    stage digest over the ``previous`` bytes plus the compact JSON of
    ``at``, ``bundle``, ``diff``, the stage ``previous``/``digest`` chain
    from the 64-zero genesis, the final ``root``, and the ``expected``
    timestamp/root pairs and overall root. Returns ``False`` when any
    chain link, stage digest, bundle, diff, root, or expected value does
    not match; otherwise ``True``.
    """
    report_root, stages = _normalize_verified_matrix_bundle_evolution(
        report, "report"
    )

    if not isinstance(expected, dict) or set(expected) != set(
        _MATRIX_BUNDLE_EVOLUTION_EXPECTED_KEYS
    ):
        raise ValueError(
            "expected must be a dict with exactly the keys root, stages"
        )
    expected_root = _check_hex64(expected["root"], "expected.root")
    raw_expected_stages = expected["stages"]
    if not isinstance(raw_expected_stages, list) or not raw_expected_stages:
        raise ValueError("expected.stages must be a non-empty list")
    expected_stages: list[tuple[str, str]] = []
    previous_at: str | None = None
    for index, stage in enumerate(raw_expected_stages):
        field = f"expected.stages[{index}]"
        if not isinstance(stage, dict) or set(stage) != (
            _MATRIX_BUNDLE_EVOLUTION_EXPECTED_STAGE_KEYS
        ):
            raise ValueError(
                f"{field} must be a dict with exactly the keys at, root"
            )
        at = _check_time(stage["at"], f"{field}.at")
        if previous_at is not None and at <= previous_at:
            raise ValueError(
                f"{field}.at must be strictly greater than the preceding at"
            )
        root_value = _check_hex64(stage["root"], f"{field}.root")
        expected_stages.append((at, root_value))
        previous_at = at

    # Both inputs have now passed every key-set, type, digest-format, time,
    # ordering, bundle, and adjacent-diff structural/semantic check. Only
    # now recompute and compare; any mismatch yields False rather than raising.
    if len(expected_stages) != len(stages):
        return False
    if any(not stage["bundle_truthful"] for stage in stages):
        return False
    previous = _MATRIX_BUNDLE_EVOLUTION_GENESIS
    for index, stage in enumerate(stages):
        if index > 0:
            recomputed_diff = matrix_bundle_diff(
                stages[index - 1]["bundle"], stage["bundle"]
            )
            if stage["diff"] != recomputed_diff:
                return False
        recomputed_digest = _matrix_bundle_evolution_stage_digest(
            previous, stage["at"], stage["bundle"], stage["diff"]
        )
        if stage["previous"] != previous:
            return False
        if stage["digest"] != recomputed_digest:
            return False
        expected_at, expected_stage_root = expected_stages[index]
        if stage["at"] != expected_at or stage["bundle_root"] != expected_stage_root:
            return False
        previous = recomputed_digest
    if report_root != previous or report_root != expected_root:
        return False
    return True


_EVOLUTION_CHECKPOINT_REPORT_KEYS = (
    "start",
    "end",
    "anchor",
    "stages",
    "commitment",
)
_EVOLUTION_CHECKPOINT_EXPECTED_KEYS = frozenset(
    {"start", "end", "anchor", "commitment"}
)


def evolution_checkpoint(report: Any, start: str, end: str) -> dict[str, Any]:
    """Cut a stage-window proof out of a full bundle evolution report.

    Pure function: it only processes its arguments, accesses neither history
    nor files, and never mutates an input object at any level.

    ``start`` and ``end`` must be valid UTC seconds with ``start <= end`` and
    both must be the ``at`` of stages that actually exist in ``report`` (an
    illegal time, a missing boundary, or a reversed window raises
    ``ValueError``). ``report`` must be a complete, fully verifiable
    :func:`matrix_bundle_evolution` report: any structural, time, ordering,
    bundle, adjacent-diff, chain-link, stage-digest, or root forgery raises
    ``ValueError`` before anything is produced.

    The proof covers the continuous run of stages from ``start`` through
    ``end`` inclusive, with no stage skipped, reordered, or rewritten.
    Returns a deep copy containing exactly the keys ``start``, ``end``,
    ``anchor``, ``stages``, ``commitment`` in that order. When the window
    begins at the report's first stage, ``anchor`` is 64 ASCII ``0``
    characters; otherwise it is the immediately preceding stage's ``digest``.
    ``stages`` are independent deep copies of the full window stages, each
    still following the published bundle, diff, and stage-chain contracts;
    the first stage of a non-head window keeps its original ``diff`` and the
    bundle on its front side, so even a single-stage window can be
    recomputed without the report outside the window. ``commitment`` is the
    last window stage's ``digest`` and also equals the original report
    ``root`` when the window reaches the report's end. Equal-valued inputs
    yield byte-identical results.
    """
    start = _check_time(start, "start")
    end = _check_time(end, "end")
    if start > end:
        raise ValueError(f"start must not be after end: {start!r} > {end!r}")
    report_root, stages = _normalize_verified_matrix_bundle_evolution(
        report, "report"
    )
    self_expected = {
        "root": report_root,
        "stages": [
            {"at": stage["at"], "root": stage["bundle_root"]} for stage in stages
        ],
    }
    if not verify_matrix_bundle_evolution(report, self_expected):
        raise ValueError(
            "report must be a fully verifiable matrix bundle evolution report"
        )
    ats = [stage["at"] for stage in stages]
    if start not in ats:
        raise ValueError("start must be the at of a stage that exists in report")
    if end not in ats:
        raise ValueError("end must be the at of a stage that exists in report")
    first_index = ats.index(start)
    last_index = ats.index(end)
    anchor = (
        _MATRIX_BUNDLE_EVOLUTION_GENESIS
        if first_index == 0
        else stages[first_index - 1]["digest"]
    )
    window = stages[first_index : last_index + 1]
    proof_stages = [
        {
            "at": stage["at"],
            "bundle": copy.deepcopy(stage["bundle"]),
            "diff": copy.deepcopy(stage["diff"]),
            "previous": stage["previous"],
            "digest": stage["digest"],
        }
        for stage in window
    ]
    return {
        "start": start,
        "end": end,
        "anchor": anchor,
        "stages": proof_stages,
        "commitment": window[-1]["digest"],
    }


def _normalize_verified_evolution_checkpoint(
    proof: Any, field: str = "proof"
) -> dict[str, Any]:
    """Run every structural and semantic check on a checkpoint proof.

    Enforces the :func:`evolution_checkpoint` proof contract: exact key sets,
    valid ``start``/``end`` timestamps with ``start <= end``, hex64
    ``anchor``/``commitment``, a non-empty strictly increasing stage chain,
    fully valid per-stage bundles, and adjacent diff credentials that
    reproduce their neighboring bundles. The first stage follows the genesis
    rule (``previous`` of 64 zeroes and ``null`` diff) or carries the full
    front-side diff whose ``after`` bundle reproduces the first stage.
    Window disorder or an adjacent diff that does not correspond raises
    ``ValueError``. False declared summaries are carried back as data
    (``bundle_truthful`` and the validated carried-diff members) so they
    yield ``False`` only after every input validates. Boundary agreement of
    ``start``/``end`` with the first/last stage ``at`` is reported via
    ``boundaries_ok`` rather than raised. The input is never mutated.
    """
    if not isinstance(proof, dict) or set(proof) != set(
        _EVOLUTION_CHECKPOINT_REPORT_KEYS
    ):
        raise ValueError(
            f"{field} must be a dict with exactly the keys "
            "start, end, anchor, stages, commitment"
        )
    start = _check_time(proof["start"], f"{field}.start")
    end = _check_time(proof["end"], f"{field}.end")
    if start > end:
        raise ValueError(f"{field}.start must not be after {field}.end")
    anchor = _check_hex64(proof["anchor"], f"{field}.anchor")
    commitment = _check_hex64(proof["commitment"], f"{field}.commitment")
    raw_stages = proof["stages"]
    if not isinstance(raw_stages, list) or not raw_stages:
        raise ValueError(f"{field}.stages must be a non-empty list")

    normalized_stages: list[dict[str, Any]] = []
    previous_at: str | None = None
    for index, stage in enumerate(raw_stages):
        stage_field = f"{field}.stages[{index}]"
        if not isinstance(stage, dict) or set(stage) != set(
            _MATRIX_BUNDLE_EVOLUTION_STAGE_KEYS
        ):
            raise ValueError(
                f"{stage_field} must be a dict with exactly the keys "
                "at, bundle, diff, previous, digest"
            )
        at = _check_time(stage["at"], f"{stage_field}.at")
        if previous_at is not None and at <= previous_at:
            raise ValueError(
                f"{stage_field}.at must be strictly greater than the "
                "preceding stage at"
            )
        previous_digest = _check_hex64(
            stage["previous"], f"{stage_field}.previous"
        )
        digest = _check_hex64(stage["digest"], f"{stage_field}.digest")
        bundle_root, bundle_members = _normalize_verified_matrix_bundle(
            stage["bundle"], f"{stage_field}.bundle"
        )
        bundle = _canonical_bundle_from_members(bundle_root, bundle_members)
        bundle_truthful = _matrix_bundle_is_truthful(bundle_root, bundle_members)

        carried_diff: tuple[dict[str, Any], list[Any], list[Any]] | None = None
        if index == 0 and previous_digest == _MATRIX_BUNDLE_EVOLUTION_GENESIS:
            if stage["diff"] is not None:
                raise ValueError(
                    f"{stage_field}.diff must be null at the genesis stage"
                )
            diff: dict[str, Any] | None = None
        elif index == 0:
            diff_content, before_members, after_members, _changes = (
                _normalize_verified_matrix_diff_report(
                    stage["diff"], f"{stage_field}.diff"
                )
            )
            if diff_content["after_root"] != bundle_root:
                raise ValueError(
                    f"{stage_field}.diff.after_root must equal this stage "
                    "bundle root"
                )
            if _bundle_member_semantics(
                diff_content["after"]
            ) != _bundle_member_semantics(bundle):
                raise ValueError(
                    f"{stage_field}.diff.after must reproduce this stage bundle"
                )
            diff = diff_content
            carried_diff = (diff_content, before_members, after_members)
        else:
            preceding = normalized_stages[-1]
            diff_content, _before_members, _after_members, _changes = (
                _normalize_verified_matrix_diff_report(
                    stage["diff"], f"{stage_field}.diff"
                )
            )
            if diff_content["before_root"] != preceding["bundle_root"]:
                raise ValueError(
                    f"{stage_field}.diff.before_root must equal the preceding "
                    "stage bundle root"
                )
            if diff_content["after_root"] != bundle_root:
                raise ValueError(
                    f"{stage_field}.diff.after_root must equal this stage "
                    "bundle root"
                )
            if _bundle_member_semantics(
                diff_content["before"]
            ) != _bundle_member_semantics(preceding["bundle"]):
                raise ValueError(
                    f"{stage_field}.diff.before must reproduce the preceding "
                    "stage bundle"
                )
            if _bundle_member_semantics(
                diff_content["after"]
            ) != _bundle_member_semantics(bundle):
                raise ValueError(
                    f"{stage_field}.diff.after must reproduce this stage bundle"
                )
            diff = diff_content

        normalized_stages.append(
            {
                "at": at,
                "bundle": bundle,
                "bundle_root": bundle_root,
                "bundle_truthful": bundle_truthful,
                "diff": diff,
                "carried_diff": carried_diff,
                "previous": previous_digest,
                "digest": digest,
            }
        )
        previous_at = at

    boundaries_ok = (
        start == normalized_stages[0]["at"]
        and end == normalized_stages[-1]["at"]
    )
    return {
        "start": start,
        "end": end,
        "anchor": anchor,
        "commitment": commitment,
        "stages": normalized_stages,
        "boundaries_ok": boundaries_ok,
    }


def verify_evolution_checkpoint(proof: Any, expected: Any) -> bool:
    """Verify a :func:`evolution_checkpoint` proof without the outside report.

    Pure function: it only inspects its arguments, touches neither history
    nor files, and never mutates an input object at any level.

    ``proof`` must be a dict with exactly the keys ``start``, ``end``,
    ``anchor``, ``stages``, ``commitment``; ``start``/``end`` must be valid
    UTC seconds with ``start <= end`` and ``anchor``/``commitment`` 64
    lowercase hexadecimal characters. ``stages`` must be a non-empty list of
    full evolution stages whose ``at`` values are strictly increasing, whose
    bundles pass every bundle structural and embedded-credential semantic
    check, and whose diffs correspond to their neighbors: the genesis stage
    carries 64 zeroes as ``previous`` and a ``null`` diff; any other first
    stage keeps its front-side diff whose ``after`` bundle reproduces that
    stage, and every later diff must reproduce the preceding and current
    bundles. ``expected`` must have exactly the keys ``start``, ``end``,
    ``anchor``, ``commitment`` and is validated the same way. Exact key
    sets, times, digest formats, stage order, and every embedded credential
    semantic are checked on both inputs first; window disorder or an
    adjacent diff that does not correspond raises ``ValueError``.

    Only afterwards are values recomputed rather than trusted: every bundle
    chain (including the front-side bundle carried by a non-head first-stage
    diff), the first stage digest seeded from ``anchor`` (the carried diff
    recomputed from its before/after bundles), each later adjacent
    :func:`matrix_bundle_diff` credential, every ``previous``/``digest``
    stage link, and the terminal ``commitment``. Returns ``False`` for a
    broken link, a wrong anchor, a boundary mismatch, or any ``expected``
    disagreement after the structures are legal; otherwise ``True``.
    """
    normalized = _normalize_verified_evolution_checkpoint(proof, "proof")
    if not isinstance(expected, dict) or set(expected) != (
        _EVOLUTION_CHECKPOINT_EXPECTED_KEYS
    ):
        raise ValueError(
            "expected must be a dict with exactly the keys "
            "start, end, anchor, commitment"
        )
    expected_start = _check_time(expected["start"], "expected.start")
    expected_end = _check_time(expected["end"], "expected.end")
    if expected_start > expected_end:
        raise ValueError("expected.start must not be after expected.end")
    expected_anchor = _check_hex64(expected["anchor"], "expected.anchor")
    expected_commitment = _check_hex64(
        expected["commitment"], "expected.commitment"
    )

    stages = normalized["stages"]
    # Both inputs have now passed every structural and embedded-credential
    # semantic check. Only now recompute and compare; any mismatch yields
    # False rather than raising.
    for stage in stages:
        if not stage["bundle_truthful"]:
            return False
        if stage["carried_diff"] is not None:
            diff_content, before_members, after_members = stage["carried_diff"]
            if not _matrix_bundle_is_truthful(
                diff_content["before_root"], before_members
            ):
                return False
            if not _matrix_bundle_is_truthful(
                diff_content["after_root"], after_members
            ):
                return False

    running = normalized["anchor"]
    for index, stage in enumerate(stages):
        if stage["previous"] != running:
            return False
        if index == 0:
            if stage["diff"] is not None:
                recomputed_diff = matrix_bundle_diff(
                    stage["diff"]["before"], stage["diff"]["after"]
                )
                if stage["diff"] != recomputed_diff:
                    return False
        else:
            recomputed_diff = matrix_bundle_diff(
                stages[index - 1]["bundle"], stage["bundle"]
            )
            if stage["diff"] != recomputed_diff:
                return False
        recomputed_digest = _matrix_bundle_evolution_stage_digest(
            running, stage["at"], stage["bundle"], stage["diff"]
        )
        if stage["digest"] != recomputed_digest:
            return False
        running = recomputed_digest

    if normalized["commitment"] != running:
        return False
    if not normalized["boundaries_ok"]:
        return False
    if (
        normalized["start"] != expected_start
        or normalized["end"] != expected_end
        or normalized["anchor"] != expected_anchor
        or normalized["commitment"] != expected_commitment
    ):
        return False
    return True


_CHECKPOINT_BUNDLE_ITEM_KEYS = frozenset({"id", "proof"})
_CHECKPOINT_BUNDLE_REPORT_KEYS = ("root", "proofs")
_CHECKPOINT_BUNDLE_MEMBER_KEYS = ("id", "proof", "previous", "digest")
_CHECKPOINT_BUNDLE_EXPECTED_KEYS = ("root", "proof_ids")
_CHECKPOINT_BUNDLE_GENESIS = "0" * 64


def _canonical_checkpoint_from_normalized(
    normalized: dict[str, Any],
) -> dict[str, Any]:
    """Rebuild a fresh ``start, end, anchor, stages, commitment`` proof.

    Every level is an independent deep copy of the normalized data produced
    by :func:`_normalize_verified_evolution_checkpoint`, so the result
    follows the published checkpoint key order and shares no container with
    the caller's input.
    """
    return {
        "start": normalized["start"],
        "end": normalized["end"],
        "anchor": normalized["anchor"],
        "stages": [
            {
                "at": stage["at"],
                "bundle": copy.deepcopy(stage["bundle"]),
                "diff": copy.deepcopy(stage["diff"]),
                "previous": stage["previous"],
                "digest": stage["digest"],
            }
            for stage in normalized["stages"]
        ],
        "commitment": normalized["commitment"],
    }


def _checkpoint_bundle_member_digest(
    previous: str, item_id: str, proof: dict[str, Any]
) -> str:
    """Compute one checkpoint bundle member digest.

    The payload contains exactly ``id``, ``proof`` in that key order and is
    encoded as compact UTF-8 JSON with no newline; the digest is the
    lowercase hexadecimal SHA-256 of ``previous``'s ASCII bytes immediately
    followed by those payload bytes.
    """
    payload = {"id": item_id, "proof": proof}
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(
        previous.encode("ascii") + canonical.encode("utf-8")
    ).hexdigest()


def _checkpoint_is_truthful(proof: dict[str, Any]) -> bool:
    """Recompute a canonical checkpoint proof against its own declarations.

    The expected values are taken from the proof itself, so the result
    reflects only the proof's internal integrity: window boundaries, the
    anchor, every embedded bundle and adjacent diff, and the full stage
    chain through the terminal commitment.
    """
    return verify_evolution_checkpoint(
        proof,
        {
            "start": proof["start"],
            "end": proof["end"],
            "anchor": proof["anchor"],
            "commitment": proof["commitment"],
        },
    )


def evolution_checkpoint_bundle(items: Any) -> dict[str, Any]:
    """Bind multiple evolution checkpoint proofs into one verifiable bundle.

    Pure function: it only processes its argument, accesses neither history
    nor files, and never mutates an input object at any level.

    ``items`` must be a non-empty list whose members are dicts with exactly
    the keys ``id`` and ``proof``; ``id`` must be a non-empty string unique
    across the list (duplicates or wrong types raise ``ValueError``), and
    every ``proof`` must fully conform to the published single
    :func:`evolution_checkpoint` contract. Each proof is checked with the
    existing verification semantics before anything is produced: any
    structural or semantic violation, and any proof that does not recompute
    as true, raises ``ValueError``.

    Members are ordered by ``id`` in ascending Unicode code point order, so
    the caller's order never affects the result. Returns a deep copy with
    keys ``root``, ``proofs`` in that order; each member has keys ``id``,
    ``proof``, ``previous``, ``digest`` and every ``proof`` is a normalized
    deep copy. The first member's ``previous`` is 64 ASCII ``0`` characters;
    every later member's ``previous`` is the preceding member's ``digest``.
    The per-member digest payload contains exactly ``id``, ``proof`` in that
    key order, encoded as compact UTF-8 JSON (``ensure_ascii=False``,
    ``separators=(',', ':')``) with no newline, and ``digest`` is the
    lowercase hexadecimal SHA-256 of ``previous``'s ASCII bytes immediately
    followed by that payload. ``root`` is the last member's ``digest``.
    Equal-valued inputs yield byte-identical results.
    """
    if not isinstance(items, list) or not items:
        raise ValueError("items must be a non-empty list of {id, proof} dicts")
    normalized: list[tuple[str, dict[str, Any]]] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        field = f"items[{index}]"
        if not isinstance(item, dict) or set(item) != _CHECKPOINT_BUNDLE_ITEM_KEYS:
            raise ValueError(
                f"{field} must be a dict with exactly the keys id, proof"
            )
        item_id = _check_non_empty_str(item["id"], f"{field}.id")
        if item_id in seen:
            raise ValueError(f"items contains a duplicate id: {item_id!r}")
        seen.add(item_id)
        # Every proof must fully verify (structure, semantics, window
        # boundaries, anchor, bundles, diffs, and stage chain) before
        # anything is produced.
        proof = _canonical_checkpoint_from_normalized(
            _normalize_verified_evolution_checkpoint(
                item["proof"], f"{field}.proof"
            )
        )
        if not _checkpoint_is_truthful(proof):
            raise ValueError(f"{field}.proof does not recompute as true")
        normalized.append((item_id, proof))
    normalized.sort(key=lambda member: member[0])
    proofs: list[dict[str, Any]] = []
    previous = _CHECKPOINT_BUNDLE_GENESIS
    digest = previous
    for item_id, proof in normalized:
        digest = _checkpoint_bundle_member_digest(previous, item_id, proof)
        proofs.append(
            {
                "id": item_id,
                "proof": copy.deepcopy(proof),
                "previous": previous,
                "digest": digest,
            }
        )
        previous = digest
    return {"root": digest, "proofs": proofs}


def _normalize_verified_checkpoint_bundle(
    report: Any, field: str = "report"
) -> tuple[str, list[dict[str, Any]]]:
    """Run every structural and per-proof check on a checkpoint bundle.

    Enforces the full :func:`evolution_checkpoint_bundle` report contract:
    exact top-level and per-member key sets, hex64 ``root``/``previous``/
    ``digest`` fields, unique strictly ascending member ids, and every
    member proof's full checkpoint structural and embedded-credential
    semantic checks. A proof that merely recomputes as false is structural
    data, so it is carried back inside the returned canonical member entries
    and yields ``False`` only after every input validates. Returns
    ``(root, members)`` where each member carries a fresh normalized deep
    copy of its proof. Any structural or semantic violation raises
    ``ValueError`` and the input is never mutated.
    """
    if not isinstance(report, dict) or set(report) != set(
        _CHECKPOINT_BUNDLE_REPORT_KEYS
    ):
        raise ValueError(
            f"{field} must be a dict with exactly the keys root, proofs"
        )
    bundle_root = _check_hex64(report["root"], f"{field}.root")
    raw_proofs = report["proofs"]
    if not isinstance(raw_proofs, list) or not raw_proofs:
        raise ValueError(f"{field}.proofs must be a non-empty list")
    members: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    previous_id: str | None = None
    for index, member in enumerate(raw_proofs):
        member_field = f"{field}.proofs[{index}]"
        if not isinstance(member, dict) or set(member) != set(
            _CHECKPOINT_BUNDLE_MEMBER_KEYS
        ):
            raise ValueError(
                f"{member_field} must be a dict with exactly the keys "
                "id, proof, previous, digest"
            )
        item_id = _check_non_empty_str(member["id"], f"{member_field}.id")
        if item_id in seen_ids:
            raise ValueError(
                f"{field}.proofs contains a duplicate id: {item_id!r}"
            )
        if previous_id is not None and item_id <= previous_id:
            raise ValueError(
                f"{field}.proofs must be ordered by id in ascending "
                "Unicode code point order"
            )
        proof = _canonical_checkpoint_from_normalized(
            _normalize_verified_evolution_checkpoint(
                member["proof"], f"{member_field}.proof"
            )
        )
        previous = _check_hex64(member["previous"], f"{member_field}.previous")
        digest = _check_hex64(member["digest"], f"{member_field}.digest")
        members.append(
            {
                "id": item_id,
                "proof": proof,
                "previous": previous,
                "digest": digest,
            }
        )
        seen_ids.add(item_id)
        previous_id = item_id
    return bundle_root, members


def verify_evolution_checkpoint_bundle(report: Any, expected: Any) -> bool:
    """Verify an :func:`evolution_checkpoint_bundle` by recomputation.

    Pure function: it only inspects its arguments, touches neither history
    nor files, and never mutates an input object at any level.

    ``report`` must be a dict with exactly the keys ``root``, ``proofs`` and
    ``expected`` a dict with exactly the keys ``root``, ``proof_ids``.
    ``root`` must be 64 lowercase hexadecimal characters and ``proof_ids``
    a non-empty list of unique non-empty strings (caller order is arbitrary;
    comparison is by code point). ``proofs`` must be a non-empty list whose
    members are dicts with exactly the keys ``id``, ``proof``, ``previous``,
    ``digest``, ordered by ``id`` in ascending Unicode code point order with
    bundle-wide unique non-empty ids; each ``previous`` and ``digest`` must
    be 64 lowercase hexadecimal characters, and every ``proof`` must fully
    pass the existing single :func:`verify_evolution_checkpoint` structural
    and semantic checks. Both inputs complete every key-set, type,
    digest-format, member-order, and per-proof structural/semantic check
    before any comparison; any violation raises ``ValueError``.

    Once the structures are legal, nothing declared is trusted: every proof
    is recomputed from its own window — boundaries, anchor, embedded
    bundles, adjacent diffs, and the stage chain through its commitment —
    and the member chain is recomputed from the 64-zero genesis (each member
    digest over the ``previous`` bytes plus the compact JSON of ``id``,
    ``proof``). Returns ``False`` when any proof does not recompute as true,
    a ``previous``/``digest`` link does not chain, the final ``root`` does
    not equal the last member digest, or the ``root`` or ``proof_ids`` set
    differ from ``expected``; otherwise ``True``.
    """
    bundle_root, members = _normalize_verified_checkpoint_bundle(
        report, "report"
    )

    if not isinstance(expected, dict) or set(expected) != set(
        _CHECKPOINT_BUNDLE_EXPECTED_KEYS
    ):
        raise ValueError(
            "expected must be a dict with exactly the keys root, proof_ids"
        )
    expected_root = _check_hex64(expected["root"], "expected.root")
    expected_ids = _validate_matrix_bundle_report_ids(
        expected["proof_ids"], "expected.proof_ids"
    )

    # Both inputs have now passed every key-set, type, digest-format,
    # member-order, and per-proof structural/semantic check. Only now
    # recompute and compare; any mismatch yields False rather than raising.
    previous = _CHECKPOINT_BUNDLE_GENESIS
    for member in members:
        if not _checkpoint_is_truthful(member["proof"]):
            return False
        if member["previous"] != previous:
            return False
        recomputed = _checkpoint_bundle_member_digest(
            previous, member["id"], member["proof"]
        )
        if member["digest"] != recomputed:
            return False
        previous = recomputed
    if bundle_root != previous:
        return False
    if bundle_root != expected_root:
        return False
    if {member["id"] for member in members} != set(expected_ids):
        return False
    return True


_CHECKPOINT_BUNDLE_DIFF_REPORT_KEYS = (
    "before_root",
    "after_root",
    "before",
    "after",
    "changes",
    "digest",
)
_CHECKPOINT_BUNDLE_DIFF_CHANGE_KEYS = frozenset({"id", "kind", "before", "after"})
_CHECKPOINT_BUNDLE_DIFF_EXPECTED_KEYS = (
    "before_root",
    "after_root",
    "before_ids",
    "after_ids",
    "digest",
)
_CHECKPOINT_BUNDLE_DIFF_KINDS = frozenset({"added", "removed", "changed"})


def _checkpoint_bundle_is_truthful(
    bundle_root: str, members: list[dict[str, Any]]
) -> bool:
    """Recompute a structurally normalized checkpoint bundle's hash chain.

    Every member proof must recompute as true against its own declarations,
    each ``previous``/``digest`` link must chain from the 64-zero genesis,
    and the declared bundle ``root`` must equal the final member digest.
    """
    previous = _CHECKPOINT_BUNDLE_GENESIS
    for member in members:
        if not _checkpoint_is_truthful(member["proof"]):
            return False
        if member["previous"] != previous:
            return False
        recomputed = _checkpoint_bundle_member_digest(
            previous, member["id"], member["proof"]
        )
        if member["digest"] != recomputed:
            return False
        previous = recomputed
    return bundle_root == previous


def _canonical_checkpoint_bundle_from_members(
    bundle_root: str, members: list[dict[str, Any]]
) -> dict[str, Any]:
    """Rebuild a fresh ``root, proofs`` bundle from normalized members."""
    return {
        "root": bundle_root,
        "proofs": [
            {
                "id": member["id"],
                "proof": copy.deepcopy(member["proof"]),
                "previous": member["previous"],
                "digest": member["digest"],
            }
            for member in members
        ],
    }


def _checkpoint_diff_semantics(diff: dict[str, Any] | None) -> Any:
    """Summary-free semantic projection of a normalized stage diff.

    The diff's own digest, both bundle roots, and every bundle or credential
    digest inside it are summaries, not semantics: two diffs with the same
    bundles and the same change classification but different hash fields
    describe the same transition. Projection keeps the summary-free member
    semantics of both bundles and of every non-null change side.
    """
    if diff is None:
        return None

    def credential_semantics(credential: dict[str, Any] | None) -> Any:
        if credential is None:
            return None
        content = {key: credential[key] for key in _MATRIX_ATTEST_CONTENT_KEYS}
        return _matrix_credential_semantics(content)

    return {
        "before": _bundle_member_semantics(diff["before"]),
        "after": _bundle_member_semantics(diff["after"]),
        "changes": [
            {
                "id": change["id"],
                "kind": change["kind"],
                "before": credential_semantics(change["before"]),
                "after": credential_semantics(change["after"]),
            }
            for change in diff["changes"]
        ],
    }


def _checkpoint_proof_semantics(proof: dict[str, Any]) -> dict[str, Any]:
    """Summary-free semantic projection of a canonical checkpoint proof.

    The proof's ``anchor``/``commitment``, every stage ``previous``/
    ``digest``, and every embedded bundle or diff summary are derived
    summaries, not semantics: two proofs over the same window, bundles, and
    transitions but different hash fields describe the same member. Change
    sides are compared with bundle members on this projection, so a false
    summary yields ``False`` at recomputation rather than a structural
    mismatch, while genuinely different content still raises ``ValueError``.
    """
    return {
        "start": proof["start"],
        "end": proof["end"],
        "stages": [
            {
                "at": stage["at"],
                "bundle": _bundle_member_semantics(stage["bundle"]),
                "diff": _checkpoint_diff_semantics(stage["diff"]),
            }
            for stage in proof["stages"]
        ],
    }


def evolution_checkpoint_bundle_diff(before: Any, after: Any) -> dict[str, Any]:
    """Attest the difference between two evolution checkpoint bundles.

    Pure function: it only processes its arguments, accesses neither history
    nor files, and never mutates an input object at any level.

    Both ``before`` and ``after`` must be complete
    :func:`evolution_checkpoint_bundle` reports. Before anything is
    produced, both sides pass the full
    :func:`verify_evolution_checkpoint_bundle` structural and semantic
    checks: key sets, digest formats, unique strictly ascending member ids,
    and every embedded checkpoint proof; the second side is still fully
    checked when the first side merely carries a false digest. Any
    structural or semantic violation, and any false proof, member chain
    link, or bundle root on either side, raises ``ValueError``.

    Returns a deep copy with keys ``before_root``, ``after_root``,
    ``before``, ``after``, ``changes``, ``digest`` in that order;
    ``before_root``/``after_root`` are the two bundles' roots and
    ``before``/``after`` are independent deep copies of the normalized
    bundles. Members are matched by ``id``; ``changes`` keeps only the
    ``added`` (only in ``after``), ``removed`` (only in ``before``), and
    ``changed`` (present in both but with a different complete proof)
    members, ordered by ``id`` in ascending Unicode code point order. Each
    change has keys ``id``, ``kind``, ``before``, ``after``; the two sides
    are deep copies of the checkpoint proof or ``null``. Identical bundles
    yield an empty ``changes`` list.

    Let ``C`` be the UTF-8 bytes of compact JSON (``ensure_ascii=False``,
    ``separators=(',', ':')``) with no newline over a payload containing
    exactly the first five keys in order. ``digest`` is the lowercase
    64-char hex SHA-256 of ``C``. Equal-valued inputs yield byte-identical
    results regardless of input dict key order, and no two levels share a
    mutable container.
    """
    before_root, before_members = _normalize_verified_checkpoint_bundle(
        before, "before"
    )
    after_root, after_members = _normalize_verified_checkpoint_bundle(
        after, "after"
    )
    if not _checkpoint_bundle_is_truthful(before_root, before_members):
        raise ValueError("before bundle root or hash chain does not verify")
    if not _checkpoint_bundle_is_truthful(after_root, after_members):
        raise ValueError("after bundle root or hash chain does not verify")

    before_bundle = _canonical_checkpoint_bundle_from_members(
        before_root, before_members
    )
    after_bundle = _canonical_checkpoint_bundle_from_members(
        after_root, after_members
    )
    before_by_id = {member["id"]: member for member in before_members}
    after_by_id = {member["id"]: member for member in after_members}

    changes: list[dict[str, Any]] = []
    for member_id in sorted(set(before_by_id) | set(after_by_id)):
        before_member = before_by_id.get(member_id)
        after_member = after_by_id.get(member_id)
        if (
            before_member is not None
            and after_member is not None
            and before_member["proof"] == after_member["proof"]
        ):
            continue
        if before_member is None:
            kind = "added"
        elif after_member is None:
            kind = "removed"
        else:
            kind = "changed"
        changes.append(
            {
                "id": member_id,
                "kind": kind,
                "before": (
                    copy.deepcopy(before_member["proof"])
                    if before_member is not None
                    else None
                ),
                "after": (
                    copy.deepcopy(after_member["proof"])
                    if after_member is not None
                    else None
                ),
            }
        )

    payload = {
        "before_root": before_root,
        "after_root": after_root,
        "before": before_bundle,
        "after": after_bundle,
        "changes": changes,
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    result = copy.deepcopy(payload)
    result["digest"] = digest
    return result


def _normalize_diff_change_proof(value: Any, field: str) -> dict[str, Any] | None:
    """Validate one non-null change-side checkpoint proof.

    Returns a fresh canonical deep copy of the proof, or ``None`` for an
    explicit null. Structural and semantic violations raise ``ValueError``;
    a false declared summary is carried back inside the canonical proof so
    it yields ``False`` only after every input validates.
    """
    if value is None:
        return None
    return _canonical_checkpoint_from_normalized(
        _normalize_verified_evolution_checkpoint(value, field)
    )


def _normalize_verified_checkpoint_diff_changes(
    value: Any,
    before_members: list[dict[str, Any]],
    after_members: list[dict[str, Any]],
    field: str,
) -> list[dict[str, Any]]:
    """Structurally validate a checkpoint diff ``changes`` list.

    Each change must have exactly the keys ``id``, ``kind``, ``before``,
    ``after``; ids non-empty, bundle-wide unique, and strictly ascending in
    Unicode code point order; ``kind`` one of ``added``, ``removed``,
    ``changed``; each non-null side a fully valid checkpoint proof. Every
    change must agree with the two bundles — right kind for its id's
    presence, correct null sides, and proof semantics equal to the
    corresponding bundle member's proof — and the list must be complete:
    every added or removed member and every present-in-both member whose
    proof semantics differ must appear, unchanged members must not. Returns
    fresh normalized entries carrying canonical deep-copy proofs. Any
    violation raises ``ValueError``.
    """
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list of change dicts")
    before_by_id = {member["id"]: member for member in before_members}
    after_by_id = {member["id"]: member for member in after_members}

    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    previous_id: str | None = None
    for index, change in enumerate(value):
        item_field = f"{field}[{index}]"
        if not isinstance(change, dict) or set(change) != (
            _CHECKPOINT_BUNDLE_DIFF_CHANGE_KEYS
        ):
            raise ValueError(
                f"{item_field} must be a dict with exactly the keys "
                "id, kind, before, after"
            )
        member_id = _check_non_empty_str(change["id"], f"{item_field}.id")
        if member_id in seen:
            raise ValueError(f"{field} contains a duplicate change id: {member_id!r}")
        if previous_id is not None and member_id <= previous_id:
            raise ValueError(
                f"{field} must be ordered by id in ascending Unicode code "
                "point order"
            )
        kind = change["kind"]
        if kind not in _CHECKPOINT_BUNDLE_DIFF_KINDS:
            raise ValueError(
                f"{item_field}.kind must be 'added', 'removed', or 'changed'"
            )
        before_proof = _normalize_diff_change_proof(
            change["before"], f"{item_field}.before"
        )
        after_proof = _normalize_diff_change_proof(
            change["after"], f"{item_field}.after"
        )
        before_member = before_by_id.get(member_id)
        after_member = after_by_id.get(member_id)
        if kind == "added":
            if before_proof is not None or after_proof is None:
                raise ValueError(
                    f"{item_field} is 'added' but before/after do not match "
                    "the contract"
                )
            if before_member is not None or after_member is None:
                raise ValueError(
                    f"{item_field} id {member_id!r} is not added between the "
                    "two bundles"
                )
            if _checkpoint_proof_semantics(after_proof) != (
                _checkpoint_proof_semantics(after_member["proof"])
            ):
                raise ValueError(
                    f"{item_field}.after does not equal the after bundle's "
                    f"proof for id {member_id!r}"
                )
        elif kind == "removed":
            if before_proof is None or after_proof is not None:
                raise ValueError(
                    f"{item_field} is 'removed' but before/after do not "
                    "match the contract"
                )
            if before_member is None or after_member is not None:
                raise ValueError(
                    f"{item_field} id {member_id!r} is not removed between "
                    "the two bundles"
                )
            if _checkpoint_proof_semantics(before_proof) != (
                _checkpoint_proof_semantics(before_member["proof"])
            ):
                raise ValueError(
                    f"{item_field}.before does not equal the before bundle's "
                    f"proof for id {member_id!r}"
                )
        else:
            if before_proof is None or after_proof is None:
                raise ValueError(
                    f"{item_field} is 'changed' but before/after do not "
                    "match the contract"
                )
            if before_member is None or after_member is None:
                raise ValueError(
                    f"{item_field} id {member_id!r} must exist in both "
                    "bundles to be 'changed'"
                )
            if _checkpoint_proof_semantics(before_proof) != (
                _checkpoint_proof_semantics(before_member["proof"])
            ):
                raise ValueError(
                    f"{item_field}.before does not equal the before bundle's "
                    f"proof for id {member_id!r}"
                )
            if _checkpoint_proof_semantics(after_proof) != (
                _checkpoint_proof_semantics(after_member["proof"])
            ):
                raise ValueError(
                    f"{item_field}.after does not equal the after bundle's "
                    f"proof for id {member_id!r}"
                )
        entries.append(
            {
                "id": member_id,
                "kind": kind,
                "before": before_proof,
                "after": after_proof,
            }
        )
        seen.add(member_id)
        previous_id = member_id

    expected_ids: set[str] = set(before_by_id) ^ set(after_by_id)
    for member_id in sorted(set(before_by_id) & set(after_by_id)):
        # Membership in the diff is a semantic question; false summaries are
        # recomputed afterwards and must not fabricate "changed" members.
        if _checkpoint_proof_semantics(before_by_id[member_id]["proof"]) != (
            _checkpoint_proof_semantics(after_by_id[member_id]["proof"])
        ):
            expected_ids.add(member_id)
    if seen != expected_ids:
        raise ValueError(
            "changes must list exactly the added, removed, and changed "
            "members, with unchanged members omitted"
        )
    return entries


def _normalize_verified_checkpoint_diff_report(
    value: Any, field: str
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Run every structural and semantic check on a checkpoint diff report.

    Validates an :func:`evolution_checkpoint_bundle_diff`-shaped report
    exactly as :func:`verify_evolution_checkpoint_bundle_diff` does: the six
    exact keys, hex64 summaries, root fields matching their embedded
    bundles, both bundles' full structural and embedded-proof checks, and
    the complete change-list consistency rules. Returns ``(content,
    before_members, after_members, change_entries)`` where ``content`` is a
    fresh canonical-order dict with the six diff keys (its ``before``/
    ``after`` bundles and change proofs are independent deep copies).
    False summaries are not detected here — callers recompute them
    afterwards, yielding ``False`` rather than ``ValueError``.
    """
    if not isinstance(value, dict) or set(value) != set(
        _CHECKPOINT_BUNDLE_DIFF_REPORT_KEYS
    ):
        raise ValueError(
            f"{field} must be a dict with exactly the keys "
            "before_root, after_root, before, after, changes, digest"
        )
    before_root = _check_hex64(value["before_root"], f"{field}.before_root")
    after_root = _check_hex64(value["after_root"], f"{field}.after_root")
    digest = _check_hex64(value["digest"], f"{field}.digest")
    before_bundle_root, before_members = _normalize_verified_checkpoint_bundle(
        value["before"], f"{field}.before"
    )
    after_bundle_root, after_members = _normalize_verified_checkpoint_bundle(
        value["after"], f"{field}.after"
    )
    if before_bundle_root != before_root:
        raise ValueError(f"{field}.before_root must equal {field}.before.root")
    if after_bundle_root != after_root:
        raise ValueError(f"{field}.after_root must equal {field}.after.root")
    change_entries = _normalize_verified_checkpoint_diff_changes(
        value["changes"], before_members, after_members, f"{field}.changes"
    )
    content = {
        "before_root": before_root,
        "after_root": after_root,
        "before": _canonical_checkpoint_bundle_from_members(
            before_root, before_members
        ),
        "after": _canonical_checkpoint_bundle_from_members(
            after_root, after_members
        ),
        "changes": [
            {
                "id": change["id"],
                "kind": change["kind"],
                "before": change["before"],
                "after": change["after"],
            }
            for change in change_entries
        ],
        "digest": digest,
    }
    return content, before_members, after_members, change_entries


def verify_evolution_checkpoint_bundle_diff(report: Any, expected: Any) -> bool:
    """Verify an :func:`evolution_checkpoint_bundle_diff` report by recomputation.

    Pure function: it only inspects its arguments, touches neither history
    nor files, and never mutates an input object at any level.

    ``report`` must be a dict with exactly the keys ``before_root``,
    ``after_root``, ``before``, ``after``, ``changes``, ``digest`` and
    conform level by level to the :func:`evolution_checkpoint_bundle_diff`
    contract. The two roots and ``digest`` must be 64 lowercase hexadecimal
    characters, and each root must equal the root declared by its embedded
    bundle. ``before``/``after`` must be complete checkpoint bundles that
    pass every structural, member-order, digest-format, and embedded-proof
    semantic check. ``changes`` items must have exactly the keys ``id``,
    ``kind``, ``before``, ``after`` with non-empty unique strictly ascending
    ids, legal kinds, null sides matching each kind, and non-null sides that
    are valid checkpoint proofs exactly reproducing the corresponding bundle
    members; the list must be complete and omit unchanged members.
    ``expected`` must have exactly the keys ``before_root``, ``after_root``,
    ``before_ids``, ``after_ids``, ``digest``; both id arrays must be
    non-empty lists of unique non-empty strings (caller order is arbitrary;
    comparison is by code point). Any structural, value-domain, uniqueness,
    ordering, or change-consistency violation raises ``ValueError``, and
    both inputs finish structural validation before any comparison.

    Only afterwards are values recomputed rather than trusted: every
    embedded checkpoint proof (window boundaries, anchor, bundles, adjacent
    diffs, and stage chain through its commitment), both bundle member
    chains and roots, and the diff digest over the five declared prefix
    items in their canonical compact-JSON form. Returns ``False`` when a
    proof, chain link, bundle root, the diff digest, or an ``expected``
    value (the two roots, the digest, or either id set after code point
    sorting) does not match; otherwise ``True``.
    """
    content, before_members, after_members, changes = (
        _normalize_verified_checkpoint_diff_report(report, "report")
    )
    before_root = content["before_root"]
    after_root = content["after_root"]
    digest = content["digest"]

    if not isinstance(expected, dict) or set(expected) != set(
        _CHECKPOINT_BUNDLE_DIFF_EXPECTED_KEYS
    ):
        raise ValueError(
            "expected must be a dict with exactly the keys "
            "before_root, after_root, before_ids, after_ids, digest"
        )
    expected_before_root = _check_hex64(
        expected["before_root"], "expected.before_root"
    )
    expected_after_root = _check_hex64(
        expected["after_root"], "expected.after_root"
    )
    expected_digest = _check_hex64(expected["digest"], "expected.digest")
    expected_before_ids = _validate_matrix_bundle_report_ids(
        expected["before_ids"], "expected.before_ids"
    )
    expected_after_ids = _validate_matrix_bundle_report_ids(
        expected["after_ids"], "expected.after_ids"
    )

    # Both inputs have now passed every key-set, type, digest-format,
    # ordering, and embedded-proof semantic check. Only now recompute and
    # compare; any mismatch yields False rather than raising.
    if not _checkpoint_bundle_is_truthful(before_root, before_members):
        return False
    if not _checkpoint_bundle_is_truthful(after_root, after_members):
        return False
    for change in changes:
        for proof in (change["before"], change["after"]):
            if proof is None:
                continue
            # The non-null change side is a standalone proof: its window,
            # anchor, embedded bundles and diffs, and stage chain through
            # its commitment must all recompute as true.
            if not _checkpoint_is_truthful(proof):
                return False
    payload = {
        key: content[key] for key in _CHECKPOINT_BUNDLE_DIFF_REPORT_KEYS[:5]
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    recomputed_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if digest != recomputed_digest:
        return False
    if (
        before_root != expected_before_root
        or after_root != expected_after_root
        or digest != expected_digest
    ):
        return False
    if {member["id"] for member in before_members} != set(expected_before_ids):
        return False
    if {member["id"] for member in after_members} != set(expected_after_ids):
        return False
    return True
