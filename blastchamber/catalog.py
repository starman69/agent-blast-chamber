"""The fixed stage catalogue — identical across all three profiles.

The attack stages never change between runs; only the *controls* change. Keeping the
catalogue here (not in the per-profile YAML) is what makes the three profiles differ purely
by their control set. See docs/specs/03-attack-stages.md.
"""
from __future__ import annotations

from .model import AWS, BOTH, YOU

# (id, name, display, owner)
STAGE_CATALOG = [
    (1,  "prompt-injection",              "Prompt injection",              YOU),
    (2,  "shell-execution",               "Shell execution",               YOU),
    (3,  "filesystem",                    "Filesystem",                    YOU),
    (4,  "decoy-credentials",             "Decoy credentials",             YOU),
    (5,  "aws-identity",                  "AWS identity",                  YOU),
    (6,  "decoy-resource-access",         "Decoy resource access",         YOU),
    (7,  "external-exfiltration",         "External exfiltration",         YOU),
    (8,  "other-agent-session",           "Other agent session",           AWS),
    (9,  "host",                          "Host",                          AWS),
    (10, "persistence-after-termination", "Persistence after termination", BOTH),
]

STAGE_BY_NAME = {name: (sid, name, display, owner) for (sid, name, display, owner) in STAGE_CATALOG}
