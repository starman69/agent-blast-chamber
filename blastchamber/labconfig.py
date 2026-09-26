"""labconfig — find the deployed lab from its CloudFormation outputs.

Stack names are fixed (see scripts/_common.sh), so live mode needs no hand-copied ARNs:
it reads the evidence, lab and run3-controls stack outputs and merges them.
"""
from __future__ import annotations

import os

DEFAULT_REGION = "us-east-1"  # same default as scripts/_common.sh
PROJECT = "agent-blast-chamber"
STACKS = (f"{PROJECT}-evidence", f"{PROJECT}-lab", f"{PROJECT}-run3-controls")


def session():
    """Operator boto3 session in the lab region (AWS_REGION, then the profile, then us-east-1)."""
    import boto3
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    s = boto3.Session(region_name=region) if region else boto3.Session()
    return s if s.region_name else boto3.Session(region_name=DEFAULT_REGION)


def stack_outputs(cfn, name: str) -> dict[str, str]:
    """Outputs of one stack as {key: value}; {} if the stack isn't deployed."""
    try:
        stacks = cfn.describe_stacks(StackName=name)["Stacks"]
    except cfn.exceptions.ClientError as e:
        if "does not exist" in str(e):
            return {}
        raise
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def load(session) -> dict[str, str]:
    """Merged outputs of every lab stack that is currently deployed."""
    cfn = session.client("cloudformation")
    cfg: dict[str, str] = {}
    for name in STACKS:
        cfg.update(stack_outputs(cfn, name))
    return cfg
