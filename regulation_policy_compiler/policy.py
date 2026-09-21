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


def _select_matched(
    at: str, facts: dict[str, bool], rules: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Select rules effective at ``at``, keep the newest version per
    ``(source, id)``, filter on ``facts``, and return matches ranked as in
    :func:`evaluate`. Inputs must already be validated."""
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

    matched = [
        rule
        for rule in latest.values()
        if rule["when"] is None
        or all(key in facts and facts[key] == value for key, value in rule["when"].items())
    ]
    matched.sort(key=cmp_to_key(_compare))
    return matched


def _snapshot_basis(rule: dict[str, Any]) -> dict[str, Any]:
    """Return an ordered deep copy of a rule suitable for persisted output:
    keys in id, ver, source, priority, from, to, when, result order and the
    ``when`` mapping sorted by key."""
    when = rule["when"]
    return {
        "id": rule["id"],
        "ver": rule["ver"],
        "source": rule["source"],
        "priority": rule["priority"],
        "from": rule["from"],
        "to": rule["to"],
        "when": None if when is None else {key: when[key] for key in sorted(when)},
        "result": rule["result"],
    }


def evaluate(
    at: str, facts: dict[str, bool], rules: list[dict[str, Any]]
) -> tuple[str | None, list[str]]:
    """Evaluate versioned rules against facts at a UTC second timestamp.

    Returns ``(decision, trace)`` where ``trace`` lists every matching rule as
    ``id@ver`` in ranking order and ``decision`` is the top rule's ``result``
    (``None`` with an empty trace when nothing matches).
    """
    _check_time(at, "at")
    _check_fact_map(facts, "facts")
    rules = _validate_rules(rules)

    matched = _select_matched(at, facts, rules)

    if not matched:
        return None, []
    trace = [f"{rule['id']}@{rule['ver']}" for rule in matched]
    return matched[0]["result"], trace
