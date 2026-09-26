#!/usr/bin/env python3
"""Attach the CloudTrail receipts to a live blast-radius report.

  python scripts/collect_evidence.py reports/run1.json --wait 900

Queries the lab's CloudTrail log group (Logs Insights) for the run's agent session, matches
every call the harness made to its CloudTrail event, rewrites reports/<run>.json and .txt
with the event ids, and saves the raw events to reports/<run>.cloudtrail.json. CloudTrail
delivery usually takes several minutes, so --wait keeps polling until everything is in.
Needs BLAST_CHAMBER_LAB_ACCOUNT (same guard as live mode).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastchamber import evidence, labconfig, labguard, reporter  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("report", type=Path, help="a live report JSON written by run_chamber.py --out")
    p.add_argument("--wait", type=int, default=0,
                   help="seconds to keep polling until every agent call is in CloudTrail")
    args = p.parse_args(argv)

    report = json.loads(args.report.read_text())
    if report.get("mode") != "live" or "live" not in report:
        print("error: not a live report (run with --live first)", file=sys.stderr)
        return 1

    session = labconfig.session()
    try:
        account = labguard.require_lab_account(session.client("sts"))
    except labguard.LabGuardError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    report["account_id"] = account  # so rendering redacts it everywhere

    report, events = evidence.collect(session.client("logs"), report, args.wait)
    ct = report["cloudtrail"]

    stem = args.report.with_suffix("")
    args.report.write_text(reporter.render_json(report) + "\n")
    stem.with_suffix(".txt").write_text(reporter.render_ascii(report) + "\n")
    raw = labguard.redact_account(json.dumps(events, indent=2), account)
    Path(f"{stem}.cloudtrail.json").write_text(raw + "\n")

    print(f"CloudTrail receipts for {report['run']} "
          f"(session {report['live']['session_name']}):\n")
    for st in report["stages"]:
        lines = [e for e in st["evidence"] if e.startswith("cloudtrail ")]
        for line in lines:
            print(f"  {st['display']:<24} {line[len('cloudtrail '):]}")
    print(f"\n  matched {ct['calls_matched']}/{ct['calls_recorded']} recorded calls; "
          f"containment events: {ct['containment_events']}")
    if ct["missing"]:
        print(f"  not found yet: {', '.join(ct['missing'])}")
    if ct["gateway_not_in_cloudtrail"]:
        print(f"  gateway calls (not recorded by CloudTrail; see the API response): "
              f"{', '.join(ct['gateway_not_in_cloudtrail'])}")
    print(f"\n  wrote {args.report}, {stem.with_suffix('.txt')}, {stem}.cloudtrail.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
