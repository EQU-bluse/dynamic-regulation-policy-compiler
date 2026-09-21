"""Policy evaluation over time-bounded regulation rules."""

from __future__ import annotations

import re
from datetime import datetime, timezone

__all__ = ["evaluate"]

_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_RULE_KEYS = {"id", "ver", "source", "priority", "from", "to", "when", "result"}
_SOURCE_ORDER = {"law": 0, "org": 1}


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP_RE.match(value):
        raise ValueError(f"invalid UTC timestamp: {value!r}")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ValueError(f"invalid UTC timestamp: {value!r}") from None
    return parsed.replace(tzinfo=timezone.utc)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_facts(facts: object) -> dict[str, bool]:
    if not isinstance(facts, dict):
        raise ValueError("facts must be a dict[str, bool]")
    for key, value in facts.items():
        if not isinstance(key, str) or not key:
            raise ValueError("facts keys must be non-empty strings")
        if not isinstance(value, bool):
            raise ValueError("facts values must be bool")
    return facts


def _validate_when(when: object) -> dict[str, bool] | None:
    if when is None:
        return None
    if not isinstance(when, dict):
        raise ValueError("when must be None or a dict[str, bool]")
    for key, value in when.items():
        if not isinstance(key, str) or not key:
            raise ValueError("when keys must be non-empty strings")
        if not isinstance(value, bool):
            raise ValueError("when values must be bool")
    return when


def _validate_rules(rules: object) -> list[dict]:
    if not isinstance(rules, list):
        raise ValueError("rules must be a list of rule dicts")
    validated = []
    seen: set[tuple[str, str, int]] = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule.keys()) != _RULE_KEYS:
            raise ValueError(f"rule must contain exactly {sorted(_RULE_KEYS)}")
        rule_id = rule["id"]
        if not isinstance(rule_id, str) or not rule_id:
            raise ValueError("rule id must be a non-empty string")
        result = rule["result"]
        if not isinstance(result, str) or not result:
            raise ValueError("rule result must be a non-empty string")
        ver = rule["ver"]
        if not _is_int(ver) or ver <= 0:
            raise ValueError("rule ver must be a positive integer")
        source = rule["source"]
        if source not in _SOURCE_ORDER:
            raise ValueError("rule source must be 'law' or 'org'")
        priority = rule["priority"]
        if not _is_int(priority):
            raise ValueError("rule priority must be an integer")
        start = _parse_timestamp(rule["from"])
        end = rule["to"]
        if end is not None:
            end = _parse_timestamp(end)
            if end <= start:
                raise ValueError("rule 'to' must be after 'from'")
        when = _validate_when(rule["when"])
        key = (source, rule_id, ver)
        if key in seen:
            raise ValueError(f"duplicate rule (source, id, ver): {key!r}")
        seen.add(key)
        validated.append(
            {
                "id": rule_id,
                "ver": ver,
                "source": source,
                "priority": priority,
                "from": start,
                "to": end,
                "when": when,
                "result": result,
            }
        )
    return validated


def evaluate(
    at: object, facts: object, rules: object
) -> tuple[str | None, list[str]]:
    """Evaluate rules at a UTC second timestamp against boolean facts.

    Returns (decision, trace) where trace lists every matching rule as
    "id@ver" in precedence order and decision is the first match's result,
    or (None, []) when nothing matches.
    """
    moment = _parse_timestamp(at)
    facts = _validate_facts(facts)
    validated = _validate_rules(rules)

    effective = [
        rule
        for rule in validated
        if rule["from"] <= moment and (rule["to"] is None or moment < rule["to"])
    ]

    latest: dict[tuple[str, str], dict] = {}
    for rule in effective:
        key = (rule["source"], rule["id"])
        if key not in latest or rule["ver"] > latest[key]["ver"]:
            latest[key] = rule

    matched = [
        rule
        for rule in latest.values()
        if rule["when"] is None
        or all(facts.get(key) == value for key, value in rule["when"].items())
    ]

    matched.sort(
        key=lambda rule: (
            _SOURCE_ORDER[rule["source"]],
            -rule["priority"],
            -rule["from"].timestamp(),
            rule["id"],
            -rule["ver"],
        )
    )

    if not matched:
        return None, []
    trace = [f"{rule['id']}@{rule['ver']}" for rule in matched]
    return matched[0]["result"], trace
