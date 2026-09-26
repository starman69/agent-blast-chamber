# Shared settings for deploy.sh / teardown.sh. Sourced, not executed.
PROJECT_TAG="agent-blast-chamber"
REGION="${AWS_REGION:-us-east-1}"
CFN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../infra/cloudformation" && pwd)"
SEED_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../infra/seed" && pwd)"

# Stack names are fixed so the harness can find them (blastchamber/labconfig.py).
EVIDENCE_STACK="${PROJECT_TAG}-evidence"
LAB_STACK="${PROJECT_TAG}-lab"
CONTROLS_STACK="${PROJECT_TAG}-run3-controls"
CONTAINMENT_POLICY="blast-chamber-containment"

stack_exists () {
  aws cloudformation describe-stacks --stack-name "$1" --region "$REGION" >/dev/null 2>&1
}

stack_output () {
  aws cloudformation describe-stacks --stack-name "$1" --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text 2>/dev/null || true
}

# The run3 containment Lambda adds an inline policy to the agent role out of band.
# CloudFormation can't delete a role that still has it, so strip it before any
# update or delete of the lab stack. Also resets run3 so it can be re-run.
clear_containment () {
  for r in run1 run2 run3; do
    if aws iam delete-role-policy --role-name "${PROJECT_TAG}-agent-exec-$r" \
         --policy-name "$CONTAINMENT_POLICY" >/dev/null 2>&1; then
      echo "Removed containment policy from ${PROJECT_TAG}-agent-exec-$r"
    fi
  done
}

empty_bucket () {
  local b="$1"
  [[ -z "$b" || "$b" == "None" ]] && return 0
  echo "Emptying bucket: $b"
  aws s3 rm "s3://$b" --recursive --region "$REGION" >/dev/null 2>&1 || true
}
