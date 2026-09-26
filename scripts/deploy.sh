#!/usr/bin/env bash
# Deploy (or switch) the Agent Blast Chamber lab to a security profile.
#   evidence stack      - trail + CloudWatch Logs + metric filters + dashboard (kept across runs)
#   lab stack           - decoys + agent role, updated in place per profile
#   run3-controls stack - guardrail + containment, present only for run3
# Usage: ./scripts/deploy.sh <run1|run2|run3>
set -euo pipefail
source "$(dirname "$0")/_common.sh"

PROFILE="${1:-run1}"
case "$PROFILE" in
  run1|run2|run3) ;;
  *) echo "ERROR: profile must be run1|run2|run3 (got '$PROFILE')" >&2; exit 2 ;;
esac

# Safety: show the target identity and require confirmation before deploying.
echo "== Agent Blast Chamber :: deploy =="
echo "Profile : $PROFILE"
echo "Region  : $REGION"
echo "Stacks  : $EVIDENCE_STACK, $LAB_STACK$([[ $PROFILE == run3 ]] && echo ", $CONTROLS_STACK")"
if [[ "$REGION" != us-east-1 ]]; then
  echo "WARNING: IAM API events (the run3 containment PutRolePolicy) are only recorded by"
  echo "         trails in us-east-1. In $REGION the containment metric and its CloudTrail"
  echo "         receipt stay empty; the containment Lambda's own log still shows it."
fi
echo "Caller identity:"
aws sts get-caller-identity --output table
echo
read -r -p "Deploy DECOY lab into the account above? Type the profile name to confirm: " CONFIRM
if [[ "$CONFIRM" != "$PROFILE" ]]; then
  echo "Aborted." >&2; exit 1
fi

deploy () {  # deploy <stack> <template> [param=value ...]
  local stack="$1" template="$2"; shift 2
  echo; echo "-- $stack"
  # A failed first create leaves ROLLBACK_COMPLETE, which can't be updated - clear it.
  # (Most often: CloudTrail rejecting a just-created logs role before IAM propagates.)
  local status
  status=$(aws cloudformation describe-stacks --stack-name "$stack" --region "$REGION" \
    --query "Stacks[0].StackStatus" --output text 2>/dev/null || true)
  if [[ "$status" == ROLLBACK_COMPLETE ]]; then
    echo "   $stack is ROLLBACK_COMPLETE from a failed first create; deleting and retrying"
    aws cloudformation delete-stack --stack-name "$stack" --region "$REGION"
    aws cloudformation wait stack-delete-complete --stack-name "$stack" --region "$REGION"
  fi
  aws cloudformation deploy \
    --stack-name "$stack" \
    --template-file "$CFN_DIR/$template" \
    --region "$REGION" \
    --capabilities CAPABILITY_NAMED_IAM \
    --no-fail-on-empty-changeset \
    --parameter-overrides "ProjectTag=$PROJECT_TAG" "$@" \
    --tags "Project=$PROJECT_TAG"
}

# 1. Evidence first, so the trail is recording before the agent does anything.
FRESH_TRAIL=0
stack_exists "$EVIDENCE_STACK" || FRESH_TRAIL=1
deploy "$EVIDENCE_STACK" evidence.yaml

# 2. Lab at the requested profile. Clear any run3 containment first so the role can change.
clear_containment
deploy "$LAB_STACK" decoy-lab.yaml "SecurityProfile=$PROFILE"

# 3. Seed the obviously fake decoy data (idempotent).
BUCKET=$(stack_output "$LAB_STACK" DecoyBucketName)
TABLE=$(stack_output "$LAB_STACK" DecoyTableName)
KEY=$(stack_output "$LAB_STACK" DecoyObjectKey)
echo; echo "-- seeding decoy data into $BUCKET/$KEY and $TABLE"
aws s3 cp "$SEED_DIR/customers.csv" "s3://$BUCKET/$KEY" --region "$REGION" >/dev/null
sed "s/__TABLE__/$TABLE/" "$SEED_DIR/decoy-customers.json" > "${TMPDIR:-/tmp}/bc-seed.json"
aws dynamodb batch-write-item --request-items "file://${TMPDIR:-/tmp}/bc-seed.json" \
  --region "$REGION" >/dev/null
rm -f "${TMPDIR:-/tmp}/bc-seed.json"

# 4. run3 controls exist only for run3 - guardrail and containment are run3 knobs.
if [[ "$PROFILE" == run3 ]]; then
  deploy "$CONTROLS_STACK" run3-controls.yaml
elif stack_exists "$CONTROLS_STACK"; then
  echo; echo "-- removing $CONTROLS_STACK ($PROFILE has no guardrail/containment)"
  aws cloudformation delete-stack --stack-name "$CONTROLS_STACK" --region "$REGION"
  aws cloudformation wait stack-delete-complete --stack-name "$CONTROLS_STACK" --region "$REGION"
fi

echo
echo "== Lab outputs =="
aws cloudformation describe-stacks --stack-name "$LAB_STACK" --region "$REGION" \
  --query "Stacks[0].Outputs" --output table
# The dashboard and collect_evidence.py read CloudWatch Logs, not the S3 copy - surface a
# broken delivery now rather than after an empty dashboard.
CT_ERR=$(aws cloudtrail get-trail-status --name "$(stack_output "$EVIDENCE_STACK" TrailName)" \
  --region "$REGION" --query "LatestCloudWatchLogsDeliveryError" --output text 2>/dev/null || true)
if [[ -n "$CT_ERR" && "$CT_ERR" != None ]]; then
  echo; echo "WARNING: CloudTrail -> CloudWatch Logs delivery is failing: $CT_ERR"
  echo "         Events still reach the S3 trail bucket, but the dashboard and"
  echo "         collect_evidence.py will stay empty until this clears."
else
  echo; echo "CloudTrail -> CloudWatch Logs: no delivery errors (a new trail takes a few minutes to start)."
fi

if [[ $FRESH_TRAIL == 1 ]]; then
  echo; echo "NOTE: the trail was just created. Its S3/DynamoDB data-event selectors can take"
  echo "      several minutes to become active - wait ~10 minutes before the first live run,"
  echo "      or some decoy reads will be missing from CloudTrail and the dashboard."
fi

DASH=$(stack_output "$EVIDENCE_STACK" DashboardName)
echo
echo "Dashboard: https://${REGION}.console.aws.amazon.com/cloudwatch/home?region=${REGION}#dashboards/dashboard/${DASH}"
echo
echo "Next:"
echo "  export BLAST_CHAMBER_ALLOW_LIVE=yes BLAST_CHAMBER_LAB_ACCOUNT=<this account id>"
echo "  python run_chamber.py $PROFILE --live --out reports"
echo "  python scripts/collect_evidence.py reports/$PROFILE.json --wait 900"
echo "Tear down when finished:  ./scripts/teardown.sh"
