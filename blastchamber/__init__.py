"""Agent Blast Chamber — educational lab engine.

Demonstrates the AWS shared-responsibility boundary for AI agents by running an
assumed-compromised agent against DECOY resources under three security profiles and
emitting a blast-radius report.

Two run modes:
  * sim  (default) — deterministic, no AWS calls, only PyYAML. The rules engine derives
                     every stage outcome from the profile's control set.
  * live (--live)  — assumes the lab's agent role and acts on the lab's own decoy
                     resources via boto3, gated by labguard; CloudTrail records it all.

Safety: no real secrets, no weaponized code, no microVM-escape exploit. The escape
stage records that the AWS-owned boundary held; it does not attempt to breach it.
"""

__version__ = "0.1.0"
