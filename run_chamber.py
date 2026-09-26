#!/usr/bin/env python3
"""Agent Blast Chamber CLI.

Run the assumed-compromised scenario for a security profile and emit the blast-radius
report. Defaults to SIM mode (no AWS, no dependencies beyond pyyaml) so it is safe to run
anywhere and reproducible for the demo.

  python run_chamber.py run1                 # sim, print report
  python run_chamber.py all --out reports    # sim, all three profiles, write files
  python run_chamber.py run1 --live --out reports   # act as the agent role against the lab
  python scripts/collect_evidence.py reports/run1.json --wait 900   # attach CloudTrail ids

Live mode is gated by labguard: BLAST_CHAMBER_ALLOW_LIVE=yes and BLAST_CHAMBER_LAB_ACCOUNT
must be set, and the credentials must resolve to that exact account.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from blastchamber import harness, reporter

PROFILES = ["run1", "run2", "run3"]


def _fixture_text() -> str:
    fx = Path(__file__).resolve().parent / "agent" / "fixtures" / "poisoned_issue.md"
    return fx.read_text() if fx.exists() else ""


def run_one(run: str, live: bool, out: Path | None) -> dict:
    report = harness.run_profile(run, live=live, injection_text=_fixture_text())
    ascii_box = reporter.render_ascii(report)
    print(ascii_box)
    print()
    if out:
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{run}.txt").write_text(ascii_box + "\n")
        (out / f"{run}.json").write_text(reporter.render_json(report) + "\n")
        print(f"  wrote {out / (run + '.txt')} and {out / (run + '.json')}\n")
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Agent Blast Chamber — blast-radius report runner")
    p.add_argument("profile", choices=PROFILES + ["all"], help="which security profile to run")
    p.add_argument("--live", action="store_true",
                   help="probe live decoy resources (gated by labguard); default is sim")
    p.add_argument("--out", type=Path, default=None,
                   help="directory to write <run>.txt and <run>.json into")
    args = p.parse_args(argv)

    runs = PROFILES if args.profile == "all" else [args.profile]
    try:
        for run in runs:
            run_one(run, args.live, args.out)
    except Exception as e:  # labguard errors, missing profile, etc.
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
