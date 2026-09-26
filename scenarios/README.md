# scenarios/

Each file is a **security profile** — nothing but a set of customer-owned **control knobs**:

```yaml
controls:
  iam: over-privileged | least-privilege
  egress: open | allowlist | controlled
  tools: unrestricted | scoped | scoped+authorized
  guardrails: true | false      # gateway injection/DLP, outside the agent
  containment: true | false     # canary trip -> revoke the role's active sessions
```

- `run1.yaml` — isolation only (over-privileged identity)
- `run2.yaml` — isolation + least privilege
- `run3.yaml` — defense in depth (guardrails + containment)

The ten attack stages are **identical** across profiles (see `../blastchamber/catalog.py`); every
stage outcome is **derived from the controls** by the rules in `../blastchamber/engine.py`. So the
profiles are real logic, not hand-written outcome tables — change a knob and the report changes.
Live mode then verifies the IAM/identity stages against the real decoy resources.
