"""harness — loads a profile's control set, runs the engine, optionally verifies live.

The harness is a deterministic orchestrator, not a free-form autonomous agent driving
arbitrary shell from untrusted text. It:

  1. loads a profile (a `Controls` set) from scenarios/<run>.yaml,
  2. asks the engine to derive every stage outcome from those controls,
  3. in --live mode, verifies the identity/credential/resource stages by acting as the
     agent's own IAM role against the DECOY resources (labguard-gated), screens the
     injection with the real run3 guardrail, and records any divergence from the rules.

This keeps the demo reproducible and the repo free of weaponized code, while the three
profiles remain real logic (see engine.py), not hand-written outcome tables.
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

import yaml

from . import engine, guardrails
from .engine import Controls
from .model import VERIFIED_AWS

SCENARIO_DIR = Path(__file__).resolve().parent.parent / "scenarios"


def load_profile(run: str) -> dict:
    path = SCENARIO_DIR / f"{run}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"unknown profile {run!r} (no {path})")
    with path.open() as fh:
        spec = yaml.safe_load(fh)
    spec["_controls"] = Controls(**spec["controls"])
    return spec


def run_profile(run: str, live: bool = False, injection_text: str | None = None) -> dict:
    """Run one profile and return a report dict (see docs/specs/04-blast-radius-report.md)."""
    spec = load_profile(run)
    controls: Controls = spec["_controls"]

    probes = None
    account = None
    guardrail_ev: list[str] = []
    if live:
        from .tools import LiveProbes, LIVE_PROBE_MAP  # lazy: keeps sim dependency-free
        probes = LiveProbes(run, controls.__dict__)
        account = probes.account

    # The gateway guardrail's verdict on the actual injection text feeds the engine.
    # Live run3 asks the real Bedrock Guardrail; sim uses the transparent local heuristic.
    injection_detected = True
    if controls.guardrails and injection_text is not None:
        if probes:
            injection_detected, guardrail_ev = probes.gateway_guardrail(injection_text)
        else:
            injection_detected = guardrails.detect_injection(injection_text)
    ctx = {"injection_detected": injection_detected}

    results = engine.evaluate(controls, ctx)

    if probes:
        for sr in results:
            if sr.name == "prompt-injection" and guardrail_ev:
                sr.evidence, sr.basis = guardrail_ev, VERIFIED_AWS
                if not injection_detected:
                    sr.evidence.append("the gateway guardrail did NOT intervene on this input, "
                                       "so the injection is recorded as accepted")
            if sr.name in LIVE_PROBE_MAP:
                actual, evidence = getattr(probes, LIVE_PROBE_MAP[sr.name])()
                sr.evidence, sr.basis = evidence, VERIFIED_AWS
                if actual != sr.outcome:
                    # The real world disagreed with the derived expectation — record it.
                    sr.evidence.append(f"DIVERGENCE: derived {sr.outcome}, probe saw {actual}")
                    sr.outcome = actual

    open_side = engine.open_on_your_side(results)
    return {
        "project": "agent-blast-chamber",
        "run": spec["run"],
        "label": spec.get("label", ""),
        "mode": "live" if live else "sim",
        "controls": controls.__dict__,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "account_is_lab": bool(live),
        "account_id": account,
        "blast_radius": engine.blast_radius(open_side),
        "open_on_your_side": open_side,
        "stages": [r.as_dict() for r in results],
        **({"live": probes.live_block()} if probes else {}),
    }
