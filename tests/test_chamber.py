"""Minimal self-tests for the sim engine. Run: python -m pytest -q  (or python tests/test_chamber.py)"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastchamber import engine, evidence, harness, reporter  # noqa: E402
from blastchamber.engine import Controls  # noqa: E402
from blastchamber.model import AWS, BLOCKED, COMPROMISED, DETECTED, ISOLATED, OUTCOMES  # noqa: E402

EXPECTED_OPEN = {"run1": 7, "run2": 4, "run3": 0}


def test_engine_rules_directly():
    # Over-privileged, open, unrestricted -> broad.
    r1 = engine.evaluate(Controls("over-privileged", "open", "unrestricted", False, False))
    assert engine.open_on_your_side(r1) == 7
    # Least privilege + allowlist -> IAM/egress rows flip to BLOCKED.
    r2 = engine.evaluate(Controls("least-privilege", "allowlist", "scoped", False, False))
    assert engine.open_on_your_side(r2) == 4
    # Full defense in depth (with a detected injection) -> nothing open.
    r3 = engine.evaluate(Controls("least-privilege", "controlled", "scoped+authorized", True, True),
                         {"injection_detected": True})
    assert engine.open_on_your_side(r3) == 0
    inj = next(s for s in r3 if s.name == "prompt-injection")
    assert inj.outcome == DETECTED and inj.control == "gateway-guardrail"


def test_guardrail_off_means_injection_compromises():
    r = engine.evaluate(Controls(guardrails=False))
    inj = next(s for s in r if s.name == "prompt-injection")
    assert inj.outcome == COMPROMISED


def test_all_profiles_valid_and_metrics():
    for run, expected in EXPECTED_OPEN.items():
        report = harness.run_profile(run, live=False)
        assert report["open_on_your_side"] == expected, run
        for s in report["stages"]:
            assert s["outcome"] in OUTCOMES, (run, s["name"])
        assert len(report["stages"]) == 10, run


def test_aws_rows_are_frozen_across_runs():
    # The two AWS-owned rows must stay ISOLATED in every profile (the thesis).
    aws_rows = {}
    for run in EXPECTED_OPEN:
        for s in harness.run_profile(run, live=False)["stages"]:
            if s["owner"] == AWS:
                aws_rows.setdefault(s["name"], set()).add(s["outcome"])
    assert aws_rows, "expected AWS-owned rows"
    for name, outcomes in aws_rows.items():
        assert outcomes == {ISOLATED}, (name, outcomes)


def test_report_renders():
    report = harness.run_profile("run1", live=False)
    box = reporter.render_ascii(report)
    assert "AGENT BLAST CHAMBER" in box
    assert "AWS BOUNDARY: HELD" in box



def test_sim_stages_are_derived_and_unmarked():
    report = harness.run_profile("run1", live=False)
    assert all(s["basis"] == "derived" for s in report["stages"])
    assert "live" not in report
    assert "✓" not in reporter.render_ascii(report)


def test_json_redacts_account_everywhere():
    report = harness.run_profile("run1", live=False)
    report["account_id"] = "123456789012"
    report["stages"][4]["evidence"] = ["arn:aws:sts::123456789012:assumed-role/x/y"]
    out = reporter.render_json(report)
    assert "123456789012" not in out and "<ACCOUNT_ID>" in out


def _fake_live_report():
    report = harness.run_profile("run3", live=False)
    report["mode"] = "live"
    report["live"] = {
        "session_name": "bc-run3-20260101T000000Z", "log_group": "/lg",
        "window_start": "2026-01-01T00:00:00+00:00", "window_end": "2026-01-01T00:05:00+00:00",
        "calls": [
            {"stage": "aws-identity", "api": "GetParameter", "identity": "agent", "result": "ALLOWED"},
            {"stage": "decoy-credentials", "api": "GetSecretValue", "identity": "agent",
             "result": "AccessDeniedException"},
            {"stage": "aws-identity", "api": "GetParameter", "identity": "agent",
             "result": "AccessDeniedException"},
            {"stage": "decoy-resource-access", "api": "Scan", "identity": "agent",
             "result": "AccessDeniedException"},
        ],
    }
    return report


def _row(**kv):
    return [{"field": k, "value": v} for k, v in kv.items()] + [{"field": "@ptr", "value": "x"}]


def test_evidence_matches_calls_to_cloudtrail_events():
    report = _fake_live_report()
    agent = "arn:aws:sts::1:assumed-role/agent-blast-chamber-agent-exec-run3/bc-run3-20260101T000000Z"
    events = evidence.parse_rows([
        _row(eventTime="t1", eventID="e1", eventName="GetParameter", **{"userIdentity.arn": agent}),
        _row(eventTime="t2", eventID="e2", eventName="GetSecretValue", errorCode="AccessDenied",
             **{"userIdentity.arn": agent}),
        _row(eventTime="2026-01-01T00:01:00Z", eventID="e3", eventName="PutRolePolicy",
             **{"userIdentity.arn": "arn:aws:sts::1:assumed-role/containment-fn/x",
                "requestParameters.policyName": "blast-chamber-containment"}),
        _row(eventTime="t4", eventID="e4", eventName="GetParameter", errorCode="AccessDenied",
             **{"userIdentity.arn": agent}),
        # deploy.sh clearing the policy is housekeeping, not containment
        _row(eventTime="t0", eventID="e5", eventName="DeleteRolePolicy", errorCode="NoSuchEntityException",
             **{"userIdentity.arn": "arn:aws:iam::1:user/Admin",
                "requestParameters.policyName": "blast-chamber-containment"}),
    ])
    out = evidence.attach(report, events)
    ct = out["cloudtrail"]
    assert ct["calls_matched"] == 3 and ct["containment_events"] == 1
    # A profile without containment never claims a revocation, even one in its window.
    no_cont = _fake_live_report()
    no_cont["controls"]["containment"] = False
    assert evidence.attach(no_cont, events)["cloudtrail"]["containment_events"] == 0
    assert ct["missing"] == ["Scan AccessDeniedException as agent"]  # not delivered yet
    ident = next(s for s in out["stages"] if s["name"] == "aws-identity")
    ids = " ".join(ident["evidence"])
    assert "event=e1" in ids and "event=e3" in ids and "event=e4" in ids
    # An allowed event must never satisfy a denied call (and vice versa).
    _, missing = evidence.match_calls(report["live"]["calls"][:1], events[3:], "bc-run3-20260101T000000Z")
    assert len(missing) == 1



def test_report_box_lines_are_uniform_width():
    # A long banner message would push past the border; every line must match the frame.
    for run in EXPECTED_OPEN:
        for live in (False, True):
            report = harness.run_profile(run, live=False)
            if live:  # the live legend line and ✓ marks must fit too
                report["mode"] = "live"
                for st in report["stages"]:
                    st["basis"] = "aws"
            widths = {len(line) for line in reporter.render_ascii(report).splitlines()}
            assert len(widths) == 1, (run, live, widths)


ROOT = Path(__file__).resolve().parent.parent


def test_committed_samples_match_engine():
    # docs/samples/ is what readers see; it must be regenerated when the rules change.
    for run in EXPECTED_OPEN:
        sample = json.loads((ROOT / "docs" / "samples" / f"{run}.json").read_text())
        live = harness.run_profile(run, live=False)
        got = [(s["name"], s["outcome"]) for s in live["stages"]]
        assert [(s["name"], s["outcome"]) for s in sample["stages"]] == got, run


def test_site_reveal_matches_engine():
    # The overview site's reveal hard-codes the three reports; keep it honest.
    html = (ROOT / "site" / "index.html").read_text()
    rows = re.findall(r'\{ name: "([^"]+)",\s*owner: "(\w+)",\s*o: \[([^\]]+)\] \}', html)
    assert len(rows) == 10, len(rows)
    reports = [harness.run_profile(r, live=False)["stages"] for r in ("run1", "run2", "run3")]
    for i, (display, owner, outs) in enumerate(rows):
        outcomes = [o.strip().strip('"') for o in outs.split(",")]
        assert [rep[i]["display"] for rep in reports] == [display] * 3, display
        assert reports[0][i]["owner"] == owner, display
        assert [rep[i]["outcome"] for rep in reports] == outcomes, display


if __name__ == "__main__":
    test_engine_rules_directly()
    test_guardrail_off_means_injection_compromises()
    test_all_profiles_valid_and_metrics()
    test_aws_rows_are_frozen_across_runs()
    test_report_renders()
    test_sim_stages_are_derived_and_unmarked()
    test_json_redacts_account_everywhere()
    test_evidence_matches_calls_to_cloudtrail_events()
    test_committed_samples_match_engine()
    test_site_reveal_matches_engine()
    print("ok: all sim self-tests passed")
