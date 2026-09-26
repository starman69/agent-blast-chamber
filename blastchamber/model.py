"""Shared data model: outcomes, owners, and the stage-result record."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

# Outcome vocabulary (see docs/specs/03-attack-stages.md and 04-blast-radius-report.md)
COMPROMISED = "COMPROMISED"  # agent achieved the action; a customer control was absent
DISCOVERED = "DISCOVERED"    # agent found a planted canary / its own identity (a signal)
BLOCKED = "BLOCKED"          # a CUSTOMER control stopped it (IAM deny, egress deny, tool auth)
DETECTED = "DETECTED"        # a gateway guardrail caught it, outside the agent's reasoning
ISOLATED = "ISOLATED"        # an AWS boundary held (microVM / host / cross-tenant)
DESTROYED = "DESTROYED"      # persistence removed by teardown (VM was disposable)

OUTCOMES = {COMPROMISED, DISCOVERED, BLOCKED, DETECTED, ISOLATED, DESTROYED}

# Which outcomes count as "open on your side" — the blast-radius metric.
OPEN_ON_YOUR_SIDE = {COMPROMISED, DISCOVERED}

# Owners under the shared-responsibility model.
YOU = "YOU"
AWS = "AWS"
BOTH = "BOTH"
OWNERS = {YOU, AWS, BOTH}

# Where an outcome came from. "derived" = the engine's rules; "aws" = confirmed by a real
# call against the lab (API response, then CloudTrail event ids via collect_evidence).
DERIVED = "derived"
VERIFIED_AWS = "aws"


@dataclass
class StageResult:
    id: int
    name: str          # kebab-case id, e.g. "cloud-attack"
    display: str        # human label, e.g. "Decoy resource access"
    owner: str          # YOU | AWS | BOTH
    outcome: str        # one of OUTCOMES
    control: Optional[str] = None   # the control that decided it, if any
    note: str = ""
    evidence: list[str] = field(default_factory=list)
    basis: str = DERIVED

    def validate(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError(f"stage {self.name}: bad outcome {self.outcome!r}")
        if self.owner not in OWNERS:
            raise ValueError(f"stage {self.name}: bad owner {self.owner!r}")

    def as_dict(self) -> dict:
        return asdict(self)
