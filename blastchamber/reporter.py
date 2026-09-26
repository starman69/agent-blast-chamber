"""reporter — render a report dict as the ASCII blast-radius box and as JSON.

Account ids are redacted from the ASCII form by default so a report can be pasted into
a post or committed as a sample without leaking an account number.
"""
from __future__ import annotations

import json

from . import labguard
from .model import VERIFIED_AWS

_WIDTH = 58  # inner width of the box

_RADIUS_TAIL = {
    "BROAD": "BROAD — the role already had the data",
    "NARROW": "NARROW — owning the sandbox buys little",
    "CONTAINED": "CONTAINED — detected and shut down",
}


def _line(text: str = "") -> str:
    return "║ " + text.ljust(_WIDTH - 2) + " ║"


def render_ascii(report: dict, redact: bool = True) -> str:
    title = f"AGENT BLAST CHAMBER — {report['run'].upper()}  [{report['mode']}]"
    top = "╔" + "═" * _WIDTH + "╗"
    mid = "╠" + "═" * _WIDTH + "╣"
    bot = "╚" + "═" * _WIDTH + "╝"

    live = report["mode"] == "live"
    rows = [top, _line(title.center(_WIDTH - 2)), mid]
    for s in report["stages"]:
        label = s["display"]
        cell = f"{s['outcome']:<12}({s['owner']})"
        mark = " ✓" if s.get("basis") == VERIFIED_AWS else ""
        rows.append(_line(f"{label:<34}{cell}{mark}"))
    rows.append(mid)
    tail = _RADIUS_TAIL.get(report["blast_radius"], report["blast_radius"])
    rows.append(_line(f"BLAST RADIUS: {tail}"))
    rows.append(_line(f"OPEN ON YOUR SIDE: {report['open_on_your_side']}   "
                      f"AWS BOUNDARY: HELD"))
    if live:
        rows.append(_line("✓ = verified by a real call as the agent's IAM role"))
    rows.append(bot)

    text = "\n".join(rows)
    if redact:
        text = labguard.redact_account(text, report.get("account_id"))
    return text


def render_json(report: dict, redact: bool = True) -> str:
    """JSON form. Redaction covers every string (evidence carries ARNs), not just one field."""
    text = json.dumps(report, indent=2)
    if redact:
        text = labguard.redact_account(text, report.get("account_id"))
    return text
