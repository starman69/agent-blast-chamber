"""labguard — the safety core. Refuses to act outside the disposable lab.

Every live probe routes through here. The rules are intentionally strict: the lab
must never be able to read, write, or reach anything that is not an explicitly tagged
decoy resource in an account the operator has declared as a throwaway lab.

None of this runs in sim mode (sim makes no AWS calls at all).
"""
from __future__ import annotations

import os

PROJECT_TAG_KEY = "Project"
PROJECT_TAG_VALUE = "agent-blast-chamber"


class LabGuardError(RuntimeError):
    """Raised when something tries to act outside the sanctioned lab."""


def require_live_optin() -> None:
    """Live mode must be explicitly opted into via env, so it can never fire by accident."""
    if os.environ.get("BLAST_CHAMBER_ALLOW_LIVE") != "yes":
        raise LabGuardError(
            "Live mode is disabled. Set BLAST_CHAMBER_ALLOW_LIVE=yes only in a dedicated "
            "throwaway lab account. Sim mode (the default) needs no AWS access."
        )


def require_lab_account(sts_client) -> str:
    """Confirm the current AWS account matches the operator-declared lab account.

    The operator sets BLAST_CHAMBER_LAB_ACCOUNT to the 12-digit account id they intend
    to attack. If the live credentials resolve to any other account, we refuse — this is
    the guard that stops a stray `--live` run from probing a real account.
    """
    declared = os.environ.get("BLAST_CHAMBER_LAB_ACCOUNT", "").strip()
    if not declared:
        raise LabGuardError(
            "BLAST_CHAMBER_LAB_ACCOUNT is not set. Refusing to run live without an "
            "explicitly declared lab account id."
        )
    actual = sts_client.get_caller_identity()["Account"]
    if actual != declared:
        raise LabGuardError(
            f"Account mismatch: credentials are for {actual!r} but the declared lab "
            f"account is {declared!r}. Refusing to touch a non-lab account."
        )
    return actual


def assert_lab_resource(tags: dict[str, str], what: str) -> None:
    """Confirm a resource carries the project tag before we touch it."""
    if tags.get(PROJECT_TAG_KEY) != PROJECT_TAG_VALUE:
        raise LabGuardError(
            f"Refusing to touch {what!r}: missing tag {PROJECT_TAG_KEY}={PROJECT_TAG_VALUE}. "
            "Only tagged decoy resources are in scope."
        )


def redact_account(text: str, account_id: str | None) -> str:
    """Redact a specific account id from any string headed for a committed artifact."""
    if account_id and account_id in text:
        text = text.replace(account_id, "<ACCOUNT_ID>")
    return text
