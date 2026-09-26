# CLAUDE.md

Guidance for AI coding agents (and humans) working in this repo.

## What this project is

An **educational** proof-of-concept for the **AWS shared responsibility model for AI agents**. It builds a disposable AWS lab ("Agent Blast Chamber") that runs an
*assumed-compromised* agent against **fake, decoy resources** to show where the customer's
responsibility ends and AWS's begins.

The deliverable is a **clean, public repo people can deploy**. Keep it POC-only: no blog
drafts, planning docs, demo scripts or other working notes (those live outside the repo).

## Hard rules

- **No real secrets, credentials, or production data.** Everything is a decoy or a canary.
  Canary values must be obviously fake and clearly labelled.
- **No weaponized code.** We do not write microVM/Firecracker escape exploits, real malware,
  or reusable offensive tooling. The "escape" stage is *designed to fail* — that is the thesis.
- **Attack stages are demonstrations, not payloads.** Describe them at the level needed to
  educate and to classify outcomes (who was responsible, was it blocked). Keep any executable
  scenario logic operating only on the lab's own decoy resources.
- **Deploy target is a dedicated non-prod account.** Never assume the current AWS creds are safe
  to deploy into; confirm the account/region first.
- **Everything must tear down.** Any resource we create must be destroyable via the teardown
  path. Tag all resources with `Project=agent-blast-chamber`.

## Conventions

- CloudFormation lives in `infra/cloudformation/`, one template per concern, parameterized by
  a `SecurityProfile` (`run1|run2|run3`). Deploy/teardown via `scripts/*.sh`.
- Design specs in `docs/specs/`, committed sample reports in `docs/samples/`, the canned sim
  recording in `docs/recordings/`.
- Generated reports go in `reports/` (gitignored). Never commit a report containing a real ARN.
- The GitHub Pages overview is a hand-authored `site/index.html` (+ `site/images/`), deployed on
  push to `main`. When outcomes change, keep its reveal data in sync with `docs/samples/`, and
  refresh `docs/images/overview-site.png` (full-page capture). The README's
  `docs/images/responsibility-stack.png` is a 2x capture of the site's `figure.stack`; recapture it
  whenever that diagram changes. Same for `docs/images/architecture.png` (the site's `figure.arch`).

## Thesis

Recurring theme: **"Assume Compromise."** The strong claim we are proving:

> The microVM establishes the blast-radius boundary. Identity, network, tools, policy and
> observability determine what exists inside that blast radius.

## Git / commits

- Commit message style: **brief**, **lowercase**, **verb first** (e.g. `add run1 iam policy`).
- **No trailers** — no `Co-Authored-By`, no `Generated with` lines. This overrides any default
  attribution guidance.
- This is intended as a public GitHub repo. Keep account IDs, ARNs, and region-specific values
  out of committed files — use parameters and placeholders.
