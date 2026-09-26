#!/usr/bin/env bash
# Tear down the whole Agent Blast Chamber lab: run3 controls, lab, then evidence.
# Screenshot the dashboard first - the evidence log group goes with the evidence stack.
# Usage: ./scripts/teardown.sh
set -euo pipefail
source "$(dirname "$0")/_common.sh"

echo "== Agent Blast Chamber :: teardown =="
echo "Region : $REGION"
aws sts get-caller-identity --output table

delete () {
  local stack="$1"
  stack_exists "$stack" || { echo "(no $stack)"; return 0; }
  echo "Deleting $stack ..."
  aws cloudformation delete-stack --stack-name "$stack" --region "$REGION"
  aws cloudformation wait stack-delete-complete --stack-name "$stack" --region "$REGION"
}

# 1. Controls first so containment can't fire mid-teardown.
delete "$CONTROLS_STACK"

# 2. Lab: strip out-of-band containment policy, empty the decoy bucket, delete.
clear_containment
empty_bucket "$(stack_output "$LAB_STACK" DecoyBucketName)"
delete "$LAB_STACK"

# 3. Evidence: stop the trail so nothing new lands in the bucket, empty it, delete.
#    Retry once in case a final CloudTrail delivery raced the empty.
if stack_exists "$EVIDENCE_STACK"; then
  TRAIL=$(stack_output "$EVIDENCE_STACK" TrailName)
  TRAIL_BUCKET=$(stack_output "$EVIDENCE_STACK" TrailBucketName)
  aws cloudtrail stop-logging --name "$TRAIL" --region "$REGION" 2>/dev/null || true
  empty_bucket "$TRAIL_BUCKET"
  if ! delete "$EVIDENCE_STACK"; then
    echo "Retrying evidence stack delete after re-emptying the trail bucket ..."
    empty_bucket "$TRAIL_BUCKET"
    delete "$EVIDENCE_STACK"
  fi
fi

# 4. Sweep: anything still tagged Project=agent-blast-chamber is an orphan.
#    (The tagging API can lag a few minutes behind deletes - rerun if it lists something.)
echo
echo "Tag sweep (Project=$PROJECT_TAG):"
LEFT=$(aws resourcegroupstaggingapi get-resources --region "$REGION" \
  --tag-filters "Key=Project,Values=$PROJECT_TAG" \
  --query "ResourceTagMappingList[].ResourceARN" --output text 2>/dev/null || true)
if [[ -z "$LEFT" ]]; then
  echo "  nothing left. Blast radius: destroyed."
else
  echo "$LEFT" | tr '\t' '\n' | sed 's/^/  ORPHAN? /'
fi
