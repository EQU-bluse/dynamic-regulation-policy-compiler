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


_SCHEDULE_ATTESTATION_GENESIS = "0" * 64


def policy_schedule_attestation(
    start: str, end: str, rules: list[dict[str, Any]]
) -> dict[str, Any]:
    """Attest a :func:`policy_schedule` result with a SHA-256 hash chain.

    ``start``, ``end``, and ``rules`` are validated exactly as in
    :func:`policy_schedule`; any type, time, rule-structure, or ordering
    violation raises ``ValueError`` without mutating the inputs.

    Let ``schedule`` be the :func:`policy_schedule` result. Returns a deep
    copy with keys ``start``, ``end``, ``root``, ``points``; ``start`` and
    ``end`` come from ``schedule`` and ``points`` keeps ``schedule``'s point
    order. Each point has keys ``at``, ``rules``, ``conflicts``, ``delta``,
    ``previous``, ``digest``; the first four are exactly the same-named
    :func:`policy_schedule` values and keep that contract at every level.

    Let ``C`` be the UTF-8 bytes of the current point restricted to
    ``at``, ``rules``, ``conflicts``, ``delta`` in that key order, serialized
    with ``json.dumps(..., ensure_ascii=False, separators=(',', ':'))`` (no
    trailing newline). The first point's ``previous`` is 64 ASCII ``0``
    characters; every later point's ``previous`` is the preceding point's
    ``digest``. ``digest`` is the lowercase 64-char hex SHA-256 of
    ``previous``'s ASCII bytes immediately followed by ``C``; ``root`` is the
    last point's ``digest``. Equal-valued inputs yield byte-identical
    results.
    """
    schedule = policy_schedule(start, end, rules)
    points: list[dict[str, Any]] = []
    previous = _SCHEDULE_ATTESTATION_GENESIS
    for point in schedule["points"]:
        payload = {
            "at": copy.deepcopy(point["at"]),
            "rules": copy.deepcopy(point["rules"]),
            "conflicts": copy.deepcopy(point["conflicts"]),
            "delta": copy.deepcopy(point["delta"]),
        }
        content = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(
            previous.encode("ascii") + content.encode("utf-8")
        ).hexdigest()
        payload["previous"] = previous
        payload["digest"] = digest
        points.append(payload)
        previous = digest
    return {
        "start": schedule["start"],
        "end": schedule["end"],
        "root": previous,
        "points": points,
    }


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
