# CloudFormation — Agent Blast Chamber

Deployable, tear-downable **decoy** lab. All resources are fake and tagged
`Project=agent-blast-chamber`. One template per concern:

| Template | Stack | Lifetime | Purpose |
|----------|-------|----------|---------|
| `evidence.yaml` | `agent-blast-chamber-evidence` | Deployed once, kept across profile switches | CloudTrail trail (management events + **data events on the decoy bucket/table only**) → S3 **and** CloudWatch Logs; metric filters split by the agent's role; the `agent-blast-chamber` CloudWatch dashboard; the containment Lambda's log group (so it outlives run3). |
| `decoy-lab.yaml` | `agent-blast-chamber-lab` | Updated in place per profile | Decoy S3 / DynamoDB / canary secret, the app's legitimate SSM parameter, and the agent execution role whose policy `SecurityProfile` selects. |
| `run3-controls.yaml` | `agent-blast-chamber-run3-controls` | run3 only | Bedrock Guardrail (prompt-attack filter + denied topic) and automated containment: EventBridge canary tripwire → Lambda → revoke the agent role's sessions. |

Seed data (obviously fake) lives in [`../seed/`](../seed/) and is loaded by `deploy.sh`.

## Profile → what changes

| | run1 | run2 | run3 |
|---|---|---|---|
| Agent role policy | app SSM param + `s3:*`, `dynamodb:*`, `GetSecretValue` on the decoys | app SSM param only | app SSM param only |
| Guardrail at the gateway | — | — | ✅ |
| Canary → containment | — | — | ✅ |

run2/run3 have **no deny statements**. Least privilege is deny-by-default, so CloudTrail records
their denials as *"no identity-based policy allows …"*. The only **explicit** deny in the lab is
the one run3 containment writes, so the two kinds of denial are easy to tell apart in the logs.

## Deploy / switch / teardown

```bash
./scripts/deploy.sh run1      # evidence + lab(run1)
./scripts/deploy.sh run2      # same evidence stack; lab updated to run2
./scripts/deploy.sh run3      # lab → run3, plus run3-controls
./scripts/teardown.sh         # everything, then a Project-tag sweep for orphans
```

`deploy.sh` strips any run3 containment policy before changing the lab stack (CloudFormation can't
delete a role that carries an out-of-band inline policy), and removes the run3-controls stack when
you switch back to run1/run2. Re-running `deploy.sh run3` resets containment, so run3 can be
repeated.

## Evidence and cost notes

- **Use `us-east-1`.** IAM API calls (the containment `PutRolePolicy`) are only recorded by trails
  in `us-east-1`. `deploy.sh` warns you in any other region.
- **Why data events:** S3 object reads and DynamoDB scans are *data* events. Without the scoped
  selectors, "the role already had S3" would be invisible in CloudTrail.
- **Why EventBridge rather than a CloudWatch alarm for containment:** `GetSecretValue` is a
  read-only management event. EventBridge delivers those only to rules in the
  `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` state, and it reacts in about a minute, which is
  much faster than CloudTrail → CloudWatch Logs.
- **Shared-account cost:** the trail's management-event selector records the whole region's
  management events, not just the lab's. If the account already has a trail, this one is billed as
  a second copy (about $2 per 100k events), and those events are also ingested into CloudWatch Logs.
  For a day of lab use in a dev account that is small, but set an AWS Budgets alarm first and
  tear down when you're done.
- The dashboard and its log group are deleted with the evidence stack, so **review or capture it
  before teardown**.

## What CloudFormation does NOT create

- **The microVM / AgentCore Runtime.** The harness plays the compromised agent by *assuming the
  agent execution role* and acting as that session, so every call is attributed to the agent in
  CloudTrail. Running the agent itself on AgentCore Runtime (for in-VM traces and real egress
  control) is a follow-on. Swap the AgentCore principal into the role's trust policy when it is
  added.
- **Egress controls.** The lab has no AWS-side network path yet, so the exfiltration stage is
  engine-derived and marked that way in reports.

## Safety notes

- Deploy only into a **dedicated non-prod account**. Confirm the account and region before every
  deploy.
- The over-privileged run1 role is scoped to the **decoy resources only**. It models
  "over-privileged" for the demo without giving anything a real blast radius into your account.
- The containment Lambda can write inline policies on exactly one role
  (`agent-blast-chamber-agent-exec-run3`).
- The canary secret's value is self-evidently fake. It is a **tripwire**, not a credential.
