"""Regression tests for the unified stateless-policy HTTP adapter.

Every POST endpoint that delegates to a pure ``policy`` function shares one
adapter for body parsing, exact key-set enforcement, ValueError mapping, and
canonical response encoding. These tests pin that shared boundary per
endpoint: success, malformed JSON, non-object bodies, wrong key sets,
ValueError from the target operation, non-ValueError propagation, and
cross-endpoint key-contract isolation. No history file or network is used.
"""

import functools
import json

import pytest
from fastapi.testclient import TestClient

import regulation_policy_compiler.app as app_module
from regulation_policy_compiler.app import app
from regulation_policy_compiler.policy import (
    bundle_evolution_checkpoint,
    bundle_evolution_checkpoint_bundle,
    bundle_evolution_checkpoint_bundle_evolution,
    bundle_evolution_checkpoint_bundle_evolution_checkpoint,
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle,
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff,
    bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution,
    checkpoint_chain,
    checkpoint_chain_checkpoint,
    checkpoint_chain_checkpoint_bundle,
    checkpoint_chain_checkpoint_bundle_evolution,
    decision_attestation,
    decision_impact_attestation,
    decision_matrix_attestation,
    decision_matrix_attestation_bundle,
    decision_timeline_attestation,
    evolution_checkpoint,
    evolution_checkpoint_bundle,
    matrix_bundle_evolution,
)

client = TestClient(app)

START = "2021-01-01T00:00:00Z"
MID = "2021-02-01T00:00:00Z"
STOP = "2021-03-01T00:00:00Z"
END = "2021-04-01T00:00:00Z"
AT = "2021-06-01T00:00:00Z"
FROM = "2020-06-01T00:00:00Z"
TO = "2021-06-01T00:00:00Z"
AT1 = "2021-05-01T00:00:00Z"
AT2 = "2021-06-01T00:00:00Z"
AT3 = "2021-07-01T00:00:00Z"
RT1 = "2021-08-01T00:00:00Z"
RT2 = "2021-09-01T00:00:00Z"
RT3 = "2021-10-01T00:00:00Z"
DT1 = "2021-11-01T00:00:00Z"
DT2 = "2021-12-01T00:00:00Z"
DT3 = "2022-01-01T00:00:00Z"
ET1 = "2022-02-01T00:00:00Z"
ET2 = "2022-03-01T00:00:00Z"
ET3 = "2022-04-01T00:00:00Z"
FT1 = "2022-05-01T00:00:00Z"
FT2 = "2022-06-01T00:00:00Z"
FT3 = "2022-07-01T00:00:00Z"


def _rule(**overrides):
    rule = {
        "id": "r1",
        "ver": 1,
        "source": "law",
        "priority": 0,
        "from": "2020-01-01T00:00:00Z",
        "to": None,
        "when": None,
        "result": "allow",
    }
    rule.update(overrides)
    return rule


def _changing_rules():
    return [
        _rule(id="a", priority=5, **{"from": START}, when={"x": True}, result="允许"),
        _rule(id="b", priority=1, **{"from": MID, "to": STOP}, result="deny"),
    ]


@functools.lru_cache(maxsize=1)
def _artifacts():
    rules = _changing_rules()
    report_a = decision_matrix_attestation(
        START, END, [{"id": "c1", "facts": {"x": True}}], rules
    )
    report_b = decision_matrix_attestation(
        START, END, [{"id": "c2", "facts": {}}], [_rule(result="z")]
    )
    report_c = decision_matrix_attestation(
        START, END, [{"id": "c3", "facts": {"y": False}}], [_rule(result="q")]
    )
    mb1 = decision_matrix_attestation_bundle([{"id": "a", "report": report_a}])
    mb2 = decision_matrix_attestation_bundle(
        [{"id": "a", "report": report_a}, {"id": "b", "report": report_b}]
    )
    mb3 = decision_matrix_attestation_bundle(
        [
            {"id": "a", "report": report_a},
            {"id": "b", "report": report_b},
            {"id": "c", "report": report_c},
        ]
    )
    matrix_evolution = matrix_bundle_evolution(
        [
            {"at": AT1, "bundle": mb1},
            {"at": AT2, "bundle": mb2},
            {"at": AT3, "bundle": mb3},
        ]
    )
    evo_proofs = {
        "head": evolution_checkpoint(matrix_evolution, AT1, AT1),
        "mid": evolution_checkpoint(matrix_evolution, AT2, AT2),
        "tail": evolution_checkpoint(matrix_evolution, AT3, AT3),
        "span": evolution_checkpoint(matrix_evolution, AT1, AT2),
    }
    eb1 = evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": evo_proofs["head"]},
            {"id": "z", "proof": evo_proofs["span"]},
        ]
    )
    eb2 = evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": evo_proofs["mid"]},
            {"id": "z", "proof": evo_proofs["span"]},
        ]
    )
    eb3 = evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": evo_proofs["tail"]},
            {"id": "b", "proof": evo_proofs["mid"]},
            {"id": "z", "proof": evo_proofs["span"]},
        ]
    )
    chain = checkpoint_chain(
        [
            {"at": RT1, "bundle": eb1},
            {"at": RT2, "bundle": eb2},
            {"at": RT3, "bundle": eb3},
        ]
    )
    chain_proofs = {
        "w11": checkpoint_chain_checkpoint(chain, RT1, RT1),
        "w12": checkpoint_chain_checkpoint(chain, RT1, RT2),
        "w22": checkpoint_chain_checkpoint(chain, RT2, RT2),
        "w23": checkpoint_chain_checkpoint(chain, RT2, RT3),
        "w33": checkpoint_chain_checkpoint(chain, RT3, RT3),
    }
    db1 = checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": chain_proofs["w11"]},
            {"id": "beta", "proof": chain_proofs["w23"]},
        ]
    )
    db2 = checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": chain_proofs["w11"]},
            {"id": "beta", "proof": chain_proofs["w22"]},
            {"id": "伽马", "proof": chain_proofs["w33"]},
        ]
    )
    db3 = checkpoint_chain_checkpoint_bundle(
        [
            {"id": "alpha", "proof": chain_proofs["w12"]},
            {"id": "伽马", "proof": chain_proofs["w33"]},
        ]
    )
    delivery_evolution = checkpoint_chain_checkpoint_bundle_evolution(
        [
            {"at": DT1, "bundle": db1},
            {"at": DT2, "bundle": db2},
            {"at": DT3, "bundle": db3},
        ]
    )
    be_proofs = {
        "p12": bundle_evolution_checkpoint(delivery_evolution, DT1, DT2),
        "p13": bundle_evolution_checkpoint(delivery_evolution, DT1, DT3),
        "p23": bundle_evolution_checkpoint(delivery_evolution, DT2, DT3),
        "p33": bundle_evolution_checkpoint(delivery_evolution, DT3, DT3),
    }
    bb1 = bundle_evolution_checkpoint_bundle(
        [
            {"id": "alpha", "proof": be_proofs["p12"]},
            {"id": "beta", "proof": be_proofs["p23"]},
        ]
    )
    bb2 = bundle_evolution_checkpoint_bundle(
        [
            {"id": "alpha", "proof": be_proofs["p12"]},
            {"id": "beta", "proof": be_proofs["p33"]},
            {"id": "伽马", "proof": be_proofs["p13"]},
        ]
    )
    bb3 = bundle_evolution_checkpoint_bundle(
        [{"id": "alpha", "proof": be_proofs["p23"]}]
    )
    be_evolution = bundle_evolution_checkpoint_bundle_evolution(
        [
            {"at": ET1, "bundle": bb1},
            {"at": ET2, "bundle": bb2},
            {"at": ET3, "bundle": bb3},
        ]
    )
    bec_proofs = {
        "q11": bundle_evolution_checkpoint_bundle_evolution_checkpoint(
            be_evolution, ET1, ET1
        ),
        "q22": bundle_evolution_checkpoint_bundle_evolution_checkpoint(
            be_evolution, ET2, ET2
        ),
        "q33": bundle_evolution_checkpoint_bundle_evolution_checkpoint(
            be_evolution, ET3, ET3
        ),
    }
    cb1 = bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle(
        [{"id": "a", "proof": bec_proofs["q11"]}]
    )
    cb2 = bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": bec_proofs["q22"]},
            {"id": "b", "proof": bec_proofs["q11"]},
        ]
    )
    cb3 = bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle(
        [
            {"id": "a", "proof": bec_proofs["q11"]},
            {"id": "b", "proof": bec_proofs["q22"]},
        ]
    )
    bec_diff_evolution = (
        bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution(
            [
                {"at": FT1, "bundle": cb1},
                {"at": FT2, "bundle": cb2},
                {"at": FT3, "bundle": cb3},
            ]
        )
    )
    return {
        "rules": rules,
        "report_a": report_a,
        "decision_attestation": decision_attestation(AT, {"x": True}, rules),
        "timeline_attestation": decision_timeline_attestation(
            START, END, {"x": True}, rules
        ),
        "impact_attestation": decision_impact_attestation(
            FROM, TO, [{"id": "c1", "facts": {"x": True}}], rules
        ),
        "matrix_attestation": report_a,
        "mb1": mb1,
        "mb2": mb2,
        "mb3": mb3,
        "matrix_evolution": matrix_evolution,
        "evo_proofs": evo_proofs,
        "eb1": eb1,
        "eb2": eb2,
        "eb3": eb3,
        "chain": chain,
        "chain_proofs": chain_proofs,
        "db1": db1,
        "db2": db2,
        "db3": db3,
        "delivery_evolution": delivery_evolution,
        "be_proofs": be_proofs,
        "bb1": bb1,
        "bb2": bb2,
        "bb3": bb3,
        "be_evolution": be_evolution,
        "bec_proofs": bec_proofs,
        "cb1": cb1,
        "cb2": cb2,
        "cb3": cb3,
        "bec_diff_evolution": bec_diff_evolution,
    }


def _digest_expected(report, *keys):
    return {key: report[key] for key in keys}


def _window_expected(proof):
    return {
        "start": proof["start"],
        "end": proof["end"],
        "anchor": proof["anchor"],
        "commitment": proof["commitment"],
    }


def _bundle_expected(bundle, member_key, ids_key):
    return {
        "root": bundle["root"],
        ids_key: [member["id"] for member in bundle[member_key]],
    }


def _diff_expected(report, member_key):
    return {
        "before_root": report["before_root"],
        "after_root": report["after_root"],
        "before_ids": [member["id"] for member in report["before"][member_key]],
        "after_ids": [member["id"] for member in report["after"][member_key]],
        "digest": report["digest"],
    }


def _matrix_evolution_expected(report):
    return {
        "root": report["root"],
        "stages": [
            {"at": stage["at"], "root": stage["bundle"]["root"]}
            for stage in report["stages"]
        ],
    }


def _chain_evolution_expected(report):
    return {
        "root": report["root"],
        "stages": [
            {
                "at": stage["at"],
                "bundle_root": stage["bundle"]["root"],
                "diff_digest": (
                    None if stage["diff"] is None else stage["diff"]["digest"]
                ),
            }
            for stage in report["stages"]
        ],
    }


def _base_bodies(a):
    rules = a["rules"]
    return {
        "compile": {"at": AT, "rules": rules},
        "coverage": {"at": AT, "fact_keys": ["x"], "rules": rules},
        "schedule": {"start": START, "end": END, "rules": rules},
        "post": {"at": AT, "facts": {"x": True}, "rules": rules},
        "counterfactual": {
            "at": AT,
            "facts": {"x": True},
            "target": "allow",
            "rules": rules,
        },
        "compare": {"from": FROM, "to": TO, "facts": {"x": True}, "rules": rules},
        "timeline": {
            "start": START,
            "end": END,
            "facts": {"x": True},
            "rules": rules,
        },
        "journey": {
            "start": START,
            "end": END,
            "initial_facts": {"x": True},
            "events": [{"at": MID, "set": {"z": True}, "unset": []}],
            "rules": rules,
        },
        "impact": {
            "from": FROM,
            "to": TO,
            "cases": [{"id": "c1", "facts": {"x": True}}],
            "rules": rules,
        },
        "matrix": {
            "start": START,
            "end": END,
            "cases": [{"id": "c1", "facts": {"x": True}}],
            "rules": rules,
        },
    }


def _endpoint_table():
    a = _artifacts()
    b = _base_bodies(a)
    da = a["decision_attestation"]
    ta = a["timeline_attestation"]
    ia = a["impact_attestation"]
    ma = a["matrix_attestation"]
    # (endpoint_name, path, keys, fields, operation, verify, body)
    return [
        ("compile_rules_endpoint", "/rules/compile",
         {"at", "rules"}, ("at", "rules"), "compile_rules", False,
         b["compile"]),
        ("policy_coverage_endpoint", "/rules/coverage",
         {"at", "fact_keys", "rules"}, ("at", "fact_keys", "rules"),
         "policy_coverage", False, b["coverage"]),
        ("policy_attestation_endpoint", "/rules/attest",
         {"at", "rules"}, ("at", "rules"), "policy_attestation", False,
         b["compile"]),
        ("policy_schedule_endpoint", "/rules/schedule",
         {"start", "end", "rules"}, ("start", "end", "rules"),
         "policy_schedule", False, b["schedule"]),
        ("policy_schedule_attestation_endpoint", "/rules/schedule/attest",
         {"start", "end", "rules"}, ("start", "end", "rules"),
         "policy_schedule_attestation", False, b["schedule"]),
        ("explain_decision", "/explanations",
         {"at", "facts", "rules"}, ("at", "facts", "rules"), "explain", False,
         b["post"]),
        ("decision_counterfactual_endpoint", "/decision-counterfactual",
         {"at", "facts", "target", "rules"}, ("at", "facts", "target", "rules"),
         "decision_counterfactual", False, b["counterfactual"]),
        ("decision_attestation_endpoint", "/explanations/attest",
         {"at", "facts", "rules"}, ("at", "facts", "rules"),
         "decision_attestation", False, b["post"]),
        ("verify_decision_attestation_endpoint", "/explanations/attest/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_decision_attestation", True,
         {"report": da, "expected": _digest_expected(da, "at", "digest")}),
        ("decision_changes", "/decision-changes",
         {"from", "to", "facts", "rules"}, ("from", "to", "facts", "rules"),
         "compare_decisions", False, b["compare"]),
        ("decision_timeline_endpoint", "/decision-timeline",
         {"start", "end", "facts", "rules"},
         ("start", "end", "facts", "rules"), "decision_timeline", False,
         b["timeline"]),
        ("decision_timeline_attestation_endpoint", "/decision-timeline/attest",
         {"start", "end", "facts", "rules"},
         ("start", "end", "facts", "rules"),
         "decision_timeline_attestation", False, b["timeline"]),
        ("verify_decision_timeline_attestation_endpoint",
         "/decision-timeline/attest/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_decision_timeline_attestation", True,
         {"report": ta,
          "expected": _digest_expected(ta, "start", "end", "digest")}),
        ("decision_journey_endpoint", "/decision-journey",
         {"start", "end", "initial_facts", "events", "rules"},
         ("start", "end", "initial_facts", "events", "rules"),
         "decision_journey", False, b["journey"]),
        ("decision_impact_endpoint", "/decision-impact",
         {"from", "to", "cases", "rules"}, ("from", "to", "cases", "rules"),
         "decision_impact", False, b["impact"]),
        ("decision_impact_attestation_endpoint", "/decision-impact/attest",
         {"from", "to", "cases", "rules"}, ("from", "to", "cases", "rules"),
         "decision_impact_attestation", False, b["impact"]),
        ("verify_decision_impact_attestation_endpoint",
         "/decision-impact/attest/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_decision_impact_attestation", True,
         {"report": ia,
          "expected": _digest_expected(ia, "from", "to", "digest")}),
        ("decision_matrix_attestation_endpoint", "/decision-matrix/attest",
         {"start", "end", "cases", "rules"},
         ("start", "end", "cases", "rules"),
         "decision_matrix_attestation", False, b["matrix"]),
        ("verify_decision_matrix_attestation_endpoint",
         "/decision-matrix/attest/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_decision_matrix_attestation", True,
         {"report": ma,
          "expected": _digest_expected(ma, "start", "end", "digest")}),
        ("matrix_change_ledger_endpoint", "/decision-matrix/ledger",
         {"report",}, ("report",), "matrix_change_ledger", False,
         {"report": ma}),
        ("decision_matrix_attestation_bundle_endpoint",
         "/decision-matrix/attest/bundle",
         {"items",}, ("items",), "decision_matrix_attestation_bundle", False,
         {"items": [{"id": "a", "report": a["report_a"]}]}),
        ("verify_decision_matrix_attestation_bundle_endpoint",
         "/decision-matrix/attest/bundle/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_decision_matrix_attestation_bundle", True,
         {"report": a["mb2"],
          "expected": _bundle_expected(a["mb2"], "reports", "report_ids")}),
        ("matrix_bundle_diff_endpoint", "/decision-matrix/attest/bundle/diff",
         {"before", "after"}, ("before", "after"), "matrix_bundle_diff", False,
         {"before": a["mb1"], "after": a["mb2"]}),
    ]


def _table():
    # Built in a function so diff/evolution reports needed by verify bodies
    # can be computed from the cached artifacts.
    a = _artifacts()
    import regulation_policy_compiler.policy as policy

    entries = _endpoint_table()
    mb_diff = policy.matrix_bundle_diff(a["mb1"], a["mb2"])
    eb_diff = policy.evolution_checkpoint_bundle_diff(a["eb1"], a["eb2"])
    db_diff = policy.checkpoint_chain_checkpoint_bundle_diff(a["db1"], a["db2"])
    bb_diff = policy.bundle_evolution_checkpoint_bundle_diff(a["bb1"], a["bb2"])
    cb_diff = policy.bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff(
        a["cb1"], a["cb2"]
    )
    matrix_stages = [
        {"at": AT1, "bundle": a["mb1"]},
        {"at": AT2, "bundle": a["mb2"]},
        {"at": AT3, "bundle": a["mb3"]},
    ]
    chain_stages = [
        {"at": RT1, "bundle": a["eb1"]},
        {"at": RT2, "bundle": a["eb2"]},
        {"at": RT3, "bundle": a["eb3"]},
    ]
    delivery_stages = [
        {"at": DT1, "bundle": a["db1"]},
        {"at": DT2, "bundle": a["db2"]},
        {"at": DT3, "bundle": a["db3"]},
    ]
    be_stages = [
        {"at": ET1, "bundle": a["bb1"]},
        {"at": ET2, "bundle": a["bb2"]},
        {"at": ET3, "bundle": a["bb3"]},
    ]
    bec_stages = [
        {"at": FT1, "bundle": a["cb1"]},
        {"at": FT2, "bundle": a["cb2"]},
        {"at": FT3, "bundle": a["cb3"]},
    ]
    entries += [
        ("verify_matrix_bundle_diff_endpoint",
         "/decision-matrix/attest/bundle/diff/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_matrix_bundle_diff", True,
         {"report": mb_diff, "expected": _diff_expected(mb_diff, "reports")}),
        ("matrix_bundle_evolution_endpoint",
         "/decision-matrix/attest/bundle/evolution",
         {"stages",}, ("stages",), "matrix_bundle_evolution", False,
         {"stages": matrix_stages}),
        ("verify_matrix_bundle_evolution_endpoint",
         "/decision-matrix/attest/bundle/evolution/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_matrix_bundle_evolution", True,
         {"report": a["matrix_evolution"],
          "expected": _matrix_evolution_expected(a["matrix_evolution"])}),
        ("evolution_checkpoint_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint",
         {"report", "start", "end"}, ("report", "start", "end"),
         "evolution_checkpoint", False,
         {"report": a["matrix_evolution"], "start": AT1, "end": AT2}),
        ("verify_evolution_checkpoint_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/verify",
         {"proof", "expected"}, ("proof", "expected"),
         "verify_evolution_checkpoint", True,
         {"proof": a["evo_proofs"]["span"],
          "expected": _window_expected(a["evo_proofs"]["span"])}),
        ("evolution_checkpoint_bundle_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle",
         {"items",}, ("items",), "evolution_checkpoint_bundle", False,
         {"items": [
             {"id": "a", "proof": a["evo_proofs"]["head"]},
             {"id": "z", "proof": a["evo_proofs"]["span"]},
         ]}),
        ("verify_evolution_checkpoint_bundle_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_evolution_checkpoint_bundle", True,
         {"report": a["eb1"],
          "expected": _bundle_expected(a["eb1"], "proofs", "proof_ids")}),
        ("evolution_checkpoint_bundle_diff_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff",
         {"before", "after"}, ("before", "after"),
         "evolution_checkpoint_bundle_diff", False,
         {"before": a["eb1"], "after": a["eb2"]}),
        ("verify_evolution_checkpoint_bundle_diff_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_evolution_checkpoint_bundle_diff", True,
         {"report": eb_diff, "expected": _diff_expected(eb_diff, "proofs")}),
        ("checkpoint_chain_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain",
         {"stages",}, ("stages",), "checkpoint_chain", False,
         {"stages": chain_stages}),
        ("verify_checkpoint_chain_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_checkpoint_chain", True,
         {"report": a["chain"],
          "expected": _chain_evolution_expected(a["chain"])}),
        ("checkpoint_chain_checkpoint_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint",
         {"report", "start", "end"}, ("report", "start", "end"),
         "checkpoint_chain_checkpoint", False,
         {"report": a["chain"], "start": RT1, "end": RT2}),
        ("verify_checkpoint_chain_checkpoint_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/verify",
         {"proof", "expected"}, ("proof", "expected"),
         "verify_checkpoint_chain_checkpoint", True,
         {"proof": a["chain_proofs"]["w12"],
          "expected": _window_expected(a["chain_proofs"]["w12"])}),
        ("checkpoint_chain_checkpoint_bundle_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle",
         {"items",}, ("items",), "checkpoint_chain_checkpoint_bundle", False,
         {"items": [
             {"id": "alpha", "proof": a["chain_proofs"]["w11"]},
             {"id": "beta", "proof": a["chain_proofs"]["w23"]},
         ]}),
        ("verify_checkpoint_chain_checkpoint_bundle_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_checkpoint_chain_checkpoint_bundle", True,
         {"report": a["db1"],
          "expected": _bundle_expected(a["db1"], "proofs", "proof_ids")}),
        ("checkpoint_chain_checkpoint_bundle_diff_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/diff",
         {"before", "after"}, ("before", "after"),
         "checkpoint_chain_checkpoint_bundle_diff", False,
         {"before": a["db1"], "after": a["db2"]}),
        ("verify_checkpoint_chain_checkpoint_bundle_diff_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/diff/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_checkpoint_chain_checkpoint_bundle_diff", True,
         {"report": db_diff, "expected": _diff_expected(db_diff, "proofs")}),
        ("checkpoint_chain_checkpoint_bundle_evolution_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution",
         {"stages",}, ("stages",),
         "checkpoint_chain_checkpoint_bundle_evolution", False,
         {"stages": delivery_stages}),
        ("verify_checkpoint_chain_checkpoint_bundle_evolution_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_checkpoint_chain_checkpoint_bundle_evolution", True,
         {"report": a["delivery_evolution"],
          "expected": _chain_evolution_expected(a["delivery_evolution"])}),
        ("bundle_evolution_checkpoint_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint",
         {"report", "start", "end"}, ("report", "start", "end"),
         "bundle_evolution_checkpoint", False,
         {"report": a["delivery_evolution"], "start": DT1, "end": DT2}),
        ("verify_bundle_evolution_checkpoint_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/verify",
         {"proof", "expected"}, ("proof", "expected"),
         "verify_bundle_evolution_checkpoint", True,
         {"proof": a["be_proofs"]["p12"],
          "expected": _window_expected(a["be_proofs"]["p12"])}),
        ("bundle_evolution_checkpoint_bundle_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/bundle",
         {"items",}, ("items",), "bundle_evolution_checkpoint_bundle", False,
         {"items": [
             {"id": "alpha", "proof": a["be_proofs"]["p12"]},
             {"id": "beta", "proof": a["be_proofs"]["p23"]},
         ]}),
        ("verify_bundle_evolution_checkpoint_bundle_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/bundle/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_bundle_evolution_checkpoint_bundle", True,
         {"report": a["bb1"],
          "expected": _bundle_expected(a["bb1"], "proofs", "proof_ids")}),
        ("bundle_evolution_checkpoint_bundle_diff_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff",
         {"before", "after"}, ("before", "after"),
         "bundle_evolution_checkpoint_bundle_diff", False,
         {"before": a["bb1"], "after": a["bb2"]}),
        ("verify_bundle_evolution_checkpoint_bundle_diff_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_bundle_evolution_checkpoint_bundle_diff", True,
         {"report": bb_diff, "expected": _diff_expected(bb_diff, "proofs")}),
        ("bundle_evolution_checkpoint_bundle_evolution_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/evolution",
         {"stages",}, ("stages",),
         "bundle_evolution_checkpoint_bundle_evolution", False,
         {"stages": be_stages}),
        ("verify_bundle_evolution_checkpoint_bundle_evolution_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/"
         "evolution/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_bundle_evolution_checkpoint_bundle_evolution", True,
         {"report": a["be_evolution"],
          "expected": _chain_evolution_expected(a["be_evolution"])}),
        ("bundle_evolution_checkpoint_bundle_evolution_checkpoint_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/"
         "evolution/checkpoint",
         {"report", "start", "end"}, ("report", "start", "end"),
         "bundle_evolution_checkpoint_bundle_evolution_checkpoint", False,
         {"report": a["be_evolution"], "start": ET1, "end": ET2}),
        ("verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/"
         "evolution/checkpoint/verify",
         {"proof", "expected"}, ("proof", "expected"),
         "verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint",
         True,
         {"proof": a["bec_proofs"]["q22"],
          "expected": _window_expected(a["bec_proofs"]["q22"])}),
        ("bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/"
         "evolution/checkpoint/bundle",
         {"items",}, ("items",),
         "bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle",
         False,
         {"items": [{"id": "a", "proof": a["bec_proofs"]["q11"]}]}),
        ("verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/"
         "evolution/checkpoint/bundle/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle",
         True,
         {"report": a["cb2"],
          "expected": _bundle_expected(a["cb2"], "proofs", "proof_ids")}),
        ("bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/"
         "evolution/checkpoint/bundle/diff",
         {"before", "after"}, ("before", "after"),
         "bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff",
         False,
         {"before": a["cb1"], "after": a["cb2"]}),
        ("verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/"
         "evolution/checkpoint/bundle/diff/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff",
         True,
         {"report": cb_diff, "expected": _diff_expected(cb_diff, "proofs")}),
        ("bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/"
         "evolution/checkpoint/bundle/diff/evolution",
         {"stages",}, ("stages",),
         "bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution",
         False,
         {"stages": bec_stages}),
        ("verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution_endpoint",
         "/decision-matrix/attest/bundle/evolution/checkpoint/bundle/diff/"
         "chain/checkpoint/bundle/evolution/checkpoint/bundle/diff/"
         "evolution/checkpoint/bundle/diff/evolution/verify",
         {"report", "expected"}, ("report", "expected"),
         "verify_bundle_evolution_checkpoint_bundle_evolution_checkpoint_bundle_diff_evolution",
         True,
         {"report": a["bec_diff_evolution"],
          "expected": _chain_evolution_expected(a["bec_diff_evolution"])}),
    ]
    return entries


ENDPOINTS = _table()
_ENDPOINT_IDS = [entry[0] for entry in ENDPOINTS]


def _post(path, body):
    return client.post(
        path, content=json.dumps(body).encode("utf-8"),
        headers={"content-type": "application/json"},
    )


@pytest.mark.parametrize(
    "name,path,keys,fields,operation,verify,body",
    ENDPOINTS,
    ids=_ENDPOINT_IDS,
)
def test_success_matches_direct_call_byte_for_byte(
    name, path, keys, fields, operation, verify, body
):
    response = _post(path, body)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    if verify:
        assert response.content == b'{"valid":true}'
    else:
        result = getattr(app_module, operation)(
            *(body[field] for field in fields)
        )
        expected = json.dumps(
            result, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        assert response.content == expected
        assert not response.content.endswith(b"\n")


@pytest.mark.parametrize(
    "name,path,keys,fields,operation,verify,body",
    ENDPOINTS,
    ids=_ENDPOINT_IDS,
)
def test_malformed_json_is_422(name, path, keys, fields, operation, verify, body):
    for raw in (b"{not json", b"\xff\xfe{\x00"):
        response = client.post(
            path, content=raw, headers={"content-type": "application/json"}
        )
        assert response.status_code == 422
        assert response.content == b'{"detail":"invalid request"}'


@pytest.mark.parametrize(
    "name,path,keys,fields,operation,verify,body",
    ENDPOINTS,
    ids=_ENDPOINT_IDS,
)
def test_non_object_body_is_422(
    name, path, keys, fields, operation, verify, body
):
    for raw in (b"[1, 2]", b"null", b'"x"'):
        response = client.post(
            path, content=raw, headers={"content-type": "application/json"}
        )
        assert response.status_code == 422
        assert response.content == b'{"detail":"invalid request"}'


@pytest.mark.parametrize(
    "name,path,keys,fields,operation,verify,body",
    ENDPOINTS,
    ids=_ENDPOINT_IDS,
)
def test_wrong_key_set_is_422(name, path, keys, fields, operation, verify, body):
    missing = dict(body)
    missing.pop(next(iter(missing)))
    extra = dict(body)
    extra["extra"] = 1
    for bad in (missing, extra, {}):
        response = _post(path, bad)
        assert response.status_code == 422
        assert response.content == b'{"detail":"invalid request"}'


@pytest.mark.parametrize(
    "name,path,keys,fields,operation,verify,body",
    ENDPOINTS,
    ids=_ENDPOINT_IDS,
)
def test_value_error_from_operation_is_422(
    name, path, keys, fields, operation, verify, body, monkeypatch
):
    def raising(*args):
        raise ValueError("boom")

    monkeypatch.setattr(app_module, operation, raising)
    response = _post(path, body)
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


@pytest.mark.parametrize(
    "name,path,keys,fields,operation,verify,body",
    ENDPOINTS,
    ids=_ENDPOINT_IDS,
)
def test_other_exceptions_are_not_swallowed(
    name, path, keys, fields, operation, verify, body, monkeypatch
):
    def raising(*args):
        raise RuntimeError("boom")

    monkeypatch.setattr(app_module, operation, raising)
    with pytest.raises(RuntimeError):
        _post(path, body)


def _cross_contract_pairs():
    pairs = []
    for entry in ENDPOINTS:
        name, path, keys = entry[0], entry[1], entry[2]
        for donor in ENDPOINTS:
            if donor[2] != keys:
                pairs.append((name, path, donor[0], donor[6]))
                break
    return pairs


@pytest.mark.parametrize(
    "name,path,donor_name,donor_body",
    _cross_contract_pairs(),
    ids=[pair[0] for pair in _cross_contract_pairs()],
)
def test_key_contracts_are_not_mixed_between_endpoints(
    name, path, donor_name, donor_body
):
    # A body that is valid for another endpoint's contract must be rejected
    # here: the adapter enforces each endpoint's own exact key set.
    response = _post(path, donor_body)
    assert response.status_code == 422
    assert response.content == b'{"detail":"invalid request"}'


def test_endpoint_names_and_openapi_operation_ids_preserved():
    names = {entry[0] for entry in ENDPOINTS}
    route_names = {
        route.name for route in app.routes if hasattr(route, "methods")
    }
    assert names <= route_names
    spec = client.get("/openapi.json").json()
    operation_ids = {
        operation["operationId"]
        for path_item in spec["paths"].values()
        for operation in path_item.values()
    }
    # FastAPI derives operation ids from the endpoint function names, so each
    # preserved name must still prefix exactly one operation id.
    for name in names:
        matches = [op for op in operation_ids if op.startswith(name + "_")]
        assert len(matches) == 1, (name, matches)
