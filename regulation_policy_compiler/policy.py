"""Deterministic evaluation of versioned regulation and organization rules."""

from __future__ import annotations

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


def compare_decisions(
    from_at: str,
    to_at: str,
    facts: dict[str, bool],
    rules: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compare the decisions :func:`explain` reaches at two UTC timestamps.

    Both timestamps must be valid UTC seconds with ``from_at <= to_at``;
    ``facts`` and ``rules`` are validated exactly as :func:`explain` does.
    Any type, time, rule-structure, or ordering error raises ``ValueError``
    without mutating the inputs.

    Returns a deep copy with keys ``from``, ``to``, ``changes``, ``before``,
    ``after``. ``before`` and ``after`` are the full :func:`explain` results
    for ``from_at`` and ``to_at`` and share no mutable state. ``changes``
    lists, in the order ``decision``, ``trace``, ``basis``, ``conflicts``,
    the fields whose structural values differ between the two snapshots
    (empty when they are identical).
    """
    _check_time(from_at, "from")
    _check_time(to_at, "to")
    if from_at > to_at:
        raise ValueError("from must not be after to")
    before = explain(from_at, facts, rules)
    after = explain(to_at, facts, rules)
    changes = [
        field
        for field in ("decision", "trace", "basis", "conflicts")
        if before[field] != after[field]
    ]
    return {
        "from": from_at,
        "to": to_at,
        "changes": changes,
        "before": before,
        "after": after,
    }
