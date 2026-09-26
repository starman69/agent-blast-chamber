# Spec 01 — Architecture

## Overview

The lab is a **disposable AWS microVM** running an autonomous coding agent, surrounded by
**decoy cloud resources**. The agent is deliberately exposed to an **indirect prompt injection**,
and we observe how far a compromise propagates under three security profiles.

## As built today

The lab does **not** yet run the agent inside an AgentCore microVM. The harness runs where you
launch it, and in live mode it **assumes the agent's execution role**. Every AWS call is then
made, and recorded by CloudTrail, as the agent's identity. That is enough to prove the
identity-side stages: credentials, identity and decoy data (plus the run3 guardrail and
containment). The in-sandbox stages (shell, filesystem, egress) are derived from the profile's
controls. The AWS boundary stages are asserted from the model, never attacked. See
[`05-aws-evidence.md`](05-aws-evidence.md) for exactly which rows are backed by AWS evidence.

## Target architecture

```mermaid
flowchart TB
    PC["Poisoned context<br/>fake GH issue · README · dep docs"]:::inject
    subgraph VM["AgentCore Runtime microVM — AWS-isolated (kernel, microVM, host)"]
        H["Agent harness<br/>+ shell + MCP"]:::you
        LP["localhost platform API<br/>(loopback, per AWS docs)"]:::you
    end
    TB{{"TRUST BOUNDARY"}}

    PC --> H
    H <-->|loopback calls| LP
    H -->|"execution identity<br/>(scoped per profile)"| TB
    TB --> S3[("Decoy S3<br/>fake data")]:::decoy
    TB --> SM["Canary secret<br/>tripwire"]:::canary
    TB --> DDB[("Decoy DynamoDB<br/>fake records")]:::decoy
    S3 --> TEL["CloudTrail + OTel telemetry"]:::telemetry
    SM --> TEL
    DDB --> TEL
    TEL --> RPT["Blast-radius report"]:::telemetry

    style VM fill:#FFF3E0,stroke:#FF9900,stroke-width:2px,color:#111
    classDef you fill:#2563EB,stroke:#1E3A8A,stroke-width:2px,color:#fff;
    classDef inject fill:#7C3AED,stroke:#4C1D95,stroke-width:2px,color:#fff;
    classDef decoy fill:#0D9488,stroke:#134E4A,stroke-width:2px,color:#fff;
    classDef canary fill:#DC2626,stroke:#7F1D1D,stroke-width:2px,color:#fff;
    classDef telemetry fill:#6B7280,stroke:#374151,stroke-width:2px,color:#fff;
```

## Components

| Component | Owner | Notes |
|-----------|-------|-------|
| MicroVM / kernel / host isolation | **AWS** | Not built by us; asserted, not attacked. |
| Language-runtime patching | **AWS** (direct code deploy) / **YOU** (own container image) | Depends on the deployment mode (below). |
| Agent harness (shell, tools, MCP) | **YOU** | Intentionally permissive in run1; scoped in run2/3. |
| Execution identity (IAM role/session) | **YOU** | The variable that changes across the three runs. |
| Poisoned context fixtures | **YOU** | Fake issue/README/dependency docs carrying injected instructions. |
| Decoy resources (S3/Secrets/DDB) | **YOU** | Fake data + canaries. Tagged for teardown. |
| Network egress controls | **YOU** | Open in run1; controlled in run2/3. |
| Policy / guardrails at gateway | **YOU** | Added in run3 (AgentCore Policy + Bedrock Guardrails, outside agent code). |
| Telemetry (CloudTrail/OTel) | shared | Evidence pipeline for classification. |

## The localhost platform API test case

AWS documents a platform server on `localhost` inside each AgentCore Runtime microVM (session
lifecycle, storage, shell). AWS recommends restricting arbitrary localhost HTTP calls and
auditing networking tools. The lab treats reaching this loopback endpoint as a **customer-owned**
control: whether the agent can discover/abuse it is determined by the harness + egress config,
not by AWS isolation.

## Deployment modes

- **Direct code deployment** → AWS patches the language runtime; you own everything above it.
- **Your own container image** → you own rebuilding/redeploying on a secure base image; AWS
  still patches the underlying compute kernel and provides microVM isolation.

## Infra realization

CloudFormation provisions the **customer-side** pieces in three stacks: the evidence pipeline
(CloudTrail, CloudWatch Logs, metric filters, dashboard), the decoy lab (decoys, canary, the
agent role scoped per profile), and the run3 controls (Bedrock Guardrail, EventBridge → Lambda
containment). The AgentCore Runtime itself is not provisioned yet. See
[`infra/cloudformation/README.md`](../../infra/cloudformation/README.md).
