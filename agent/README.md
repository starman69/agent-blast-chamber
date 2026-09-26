# agent/

The agent harness and the poisoned-context fixture for the assumed-compromised scenario.

- `fixtures/poisoned_issue.md` — the indirect prompt-injection vector: a fake GitHub issue
  carrying a **defanged, clearly-labelled** DEMO injection. It is not a working jailbreak and
  references only the lab's own decoy tools.

The orchestration lives in the `blastchamber/` package (`harness.py`), which walks a fixed
catalogue of stages deterministically rather than driving free-form shell from untrusted text —
this keeps the demo reproducible and the repo free of weaponized code. See
`docs/specs/03-attack-stages.md`.
