# Spec 02 — Security Profiles (the three runs)

The **same** assumed-compromised agent runs against three profiles. Only the controls change.

## Run 1 — Isolation only

| Control | Setting |
|---------|---------|
| MicroVM isolation | ✅ AWS-provided (constant across all runs) |
| Execution identity (IAM) | ❌ **Over-privileged** — broad S3/Secrets/DDB access |
| Network egress | ❌ Open |
| Tool / shell permissions | ❌ Unrestricted |
| Gateway policy / guardrails | ❌ None |
| Canaries / telemetry | Present (for measurement) but no automated containment |

**Expected result:** the AWS boundary holds, but the compromised agent freely reads decoy
S3, pulls canary secrets, enumerates identity, and reaches external egress. **Large blast radius —
entirely within customer responsibility.**

## Run 2 — Isolation + least privilege

| Control | Setting |
|---------|---------|
| MicroVM isolation | ✅ |
| Execution identity (IAM) | ✅ **Tightly scoped** — deny-by-default, only what the app needs |
| Network egress | ✅ Restricted (allowlist only) |
| Tool / shell permissions | ✅ Scoped tool set |
| Gateway policy / guardrails | ❌ None |
| Canaries / telemetry | Present |

**Expected result:** agent still "owns" the VM but discovers that owning the VM buys little —
IAM denies decoy cloud access, egress is blocked. **Blast radius shrinks dramatically.**

## Run 3 — Defense in depth

| Control | Setting |
|---------|---------|
| MicroVM isolation | ✅ |
| Execution identity (IAM) | ✅ Tightly scoped |
| Network egress | ✅ Controlled |
| Tool / shell permissions | ✅ Scoped + tool authorization |
| Gateway policy / guardrails | ✅ **Bedrock Guardrails** at the gateway (outside agent code) |
| Canaries / telemetry | ✅ + **automated containment** (canary trip revokes the role's sessions) |

**Expected result:** many attack stages are **detected or prevented before** they reach a
resource. The guardrail control lives outside the agent's reasoning, so the agent cannot "reason
around" it. **Compromise is detected and contained.**

## What stays constant

- The agent, the poisoned context, and the attack stages are **identical** across runs.
- The microVM boundary is **identical** — that is AWS's constant contribution.
- Only **customer-owned controls** vary. This is the whole point: the difference in outcomes
  is attributable to customer responsibility, not to AWS isolation.

## How the profiles are implemented in code

A profile is **only a control set** (`scenarios/<run>.yaml`):

```yaml
controls: { iam, egress, tools, guardrails, containment }
```

The ten stages are fixed (`blastchamber/catalog.py`) and every outcome is **derived from the
controls** by the rules engine (`blastchamber/engine.py`). This is the lab's core: the three
runs differ purely by their knobs, so the reports are a consequence of the controls, not a
hand-authored table. The control → outcome rules, in brief:

| Control | Stage(s) it decides | run1 → run2 → run3 |
|---------|--------------------|--------------------|
| `guardrails` | prompt-injection | COMPROMISED → COMPROMISED → DETECTED |
| `tools=scoped+authorized` | shell, filesystem | COMPROMISED → COMPROMISED → BLOCKED |
| `iam=least-privilege` | decoy-credentials, decoy-resource-access | open → BLOCKED → BLOCKED |
| `egress` restricted | external-exfiltration | COMPROMISED → BLOCKED → BLOCKED |
| `containment` | aws-identity | DISCOVERED → DISCOVERED → BLOCKED |
| (AWS, constant) | other-agent-session, host | ISOLATED → ISOLATED → ISOLATED |

## Profile → CloudFormation mapping

| Control | AWS resource | Stack |
|---------|--------------|-------|
| `iam` | Agent execution role policy, selected by `SecurityProfile` | `agent-blast-chamber-lab` |
| `guardrails` | `AWS::Bedrock::Guardrail` (prompt-attack filter + denied topic), applied by the gateway | `agent-blast-chamber-run3-controls` |
| `containment` | EventBridge canary tripwire → Lambda → revoke-sessions policy on the role | `agent-blast-chamber-run3-controls` |
| `egress`, `tools` | Not in AWS yet (no in-VM agent or VPC path). Engine-derived, marked `derived` in reports | none |

Evidence for all of it (trail, logs, dashboard) is in `agent-blast-chamber-evidence`. See
[`infra/cloudformation/README.md`](../../infra/cloudformation/README.md) and
[`05-aws-evidence.md`](05-aws-evidence.md).
