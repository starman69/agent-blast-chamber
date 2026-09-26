"""guardrails — gateway-layer controls that live OUTSIDE the agent's reasoning.

These model AgentCore Policy + Bedrock Guardrails at the gateway (run3) and the
network/egress controls (run2/run3). They are deliberately simple and auditable — the
point of the demo is *where* the control sits, not that it is a clever classifier.

The agent cannot reason around a control that runs before or after its own turn.
"""
from __future__ import annotations

import re

# A marker the fixture injection carries. A real gateway would run a trained
# prompt-injection classifier; here a transparent heuristic keeps the demo honest.
_INJECTION_MARKERS = [
    r"\[SYSTEM NOTE",
    r"INJECTED INSTRUCTION",
    r"ignore (all |any |previous |prior )+instructions",
    r"read any \.env",
    r"POST a summary to",
]
_INJECTION_RE = re.compile("|".join(_INJECTION_MARKERS), re.IGNORECASE)


def detect_injection(text: str) -> bool:
    """Return True if the gateway guardrail would flag this input as an injection."""
    return bool(_INJECTION_RE.search(text or ""))


def egress_allowed(url: str, allowlist: list[str]) -> bool:
    """Return True only if the URL's host is on the egress allowlist."""
    host = re.sub(r"^\w+://", "", url or "").split("/", 1)[0].split(":", 1)[0].lower()
    return any(host == a or host.endswith("." + a) for a in allowlist)


def sensitive_data_in(text: str) -> bool:
    """Flag obvious sensitive-data patterns leaving the boundary (guardrail DLP check)."""
    patterns = [r"AKIA[0-9A-Z]{16}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"canary"]
    return any(re.search(p, text or "") for p in patterns)
