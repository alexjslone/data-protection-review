#!/usr/bin/env bash
# Cloud Data Protection Review: guided cleanup.
#
#   bash cleanup.sh                  finds what the assessment created in this AWS account (in every Region), shows it, and
#                                    asks before it removes anything. Recommended.
#   bash cleanup.sh --yes            no questions: removes the AWS role stacks it found, keeps every local file
#   bash cleanup.sh --delete-results also deletes the local results (customer data)
#   bash cleanup.sh --remove-everything   removes the AWS role stacks, the results and the assessment files (this script too)
#
# It looks for the stacks run.sh and the Deployment Guide create (DataProtectionReviewer, DataProtectionReviewerAccess) and the
# StackSet DataProtectionReviewer-members.  Roles that look like ours but that no stack manages are listed, never deleted.
# Local files are only deleted after you say so, and never while a role is still in AWS.  Only the bundle's own file names are
# touched, and only in the folder this script is in.

STACKS=(DataProtectionReviewer DataProtectionReviewerAccess)
STACKSET=DataProtectionReviewer-members
# The files the bundle unpacks (and the zip it came in).  Nothing else is ever deleted.
BUNDLE_FILES=(
  START_HERE.txt Assessment_Instructions.pdf Deployment_Guide.html run.sh cleanup.sh collector.py requirements.txt
  data_risk_assessment_role.yaml data_risk_assessment_org.yaml data_risk_assessment_permission_set.yaml SECURITY_REVIEW.md
  settings.txt Sample_Report_made_up_data.html Sample_Organization_Report_made_up_data.html DataProtectionReview_Bundle.zip
)

die() { printf '\nStopped: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
step() { printf '+ %s\n' "$*" >&2; "$@"; }     # show an AWS command that changes something, then run it

HERE=$(cd "$(dirname "$0")" && pwd) || die "cannot find the folder this script is in."
cd "$HERE" || die "cannot open the folder this script is in."

usage() { sed -n '2,/^[^#]/{/^[^#]/!p}' "$HERE/$(basename "$0")" | sed 's/^# \{0,1\}//'; }

YES=0; DELETE_RESULTS=0; REMOVE_ALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=1; shift ;;
    --delete-results) DELETE_RESULTS=1; shift ;;
    --remove-everything) REMOVE_ALL=1; DELETE_RESULTS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
done

command -v aws >/dev/null 2>&1 || die "the AWS CLI was not found. Run this in AWS CloudShell, which has it."

ask_yn() {   # ask_yn "Question" y|n: succeeds for yes; no input takes the default
  local hint="[y/N]" a; [ "$2" = y ] && hint="[Y/n]"
  while true; do
    read -r -p "$1 $hint: " a || a=""
    a=${a%$'\r'}
    case "${a:-$2}" in y|Y|yes|YES|Yes) return 0 ;; n|N|no|NO|No) return 1 ;; *) say "Please answer y or n." ;; esac
  done
}

ACCOUNT=$(aws sts get-caller-identity --query Account --output text) || die "could not read your AWS sign-in."
HOME_REGION=${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region 2>/dev/null)}}
HOME_REGION=${HOME_REGION:-us-east-1}

say ""
say "Cloud Data Protection Review: cleanup (account $ACCOUNT)"
say ""
say "Looking for what the assessment created, in every Region (checked together; usually about a minute) ..."
REGIONS=$(aws ec2 describe-regions --region "$HOME_REGION" --query 'Regions[].RegionName' --output text 2>/dev/null)
REGIONS=${REGIONS:-$HOME_REGION}

# A Region that cannot be reached (blocked by network or policy) is given up on after a few seconds, not a minute.
SCAN=$(mktemp -d) || die "could not make a temporary folder."
trap 'rm -rf "$SCAN"' EXIT
QUICK=(--cli-connect-timeout 5 --cli-read-timeout 20)
scan_region() {
  local r=$1 name_filter="StackName=='${STACKS[0]}' || StackName=='${STACKS[1]}'"
  if AWS_MAX_ATTEMPTS=2 aws cloudformation list-stacks --region "$r" "${QUICK[@]}" \
      --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE UPDATE_ROLLBACK_COMPLETE ROLLBACK_COMPLETE CREATE_FAILED \
        DELETE_FAILED UPDATE_ROLLBACK_FAILED ROLLBACK_FAILED IMPORT_COMPLETE \
      --query "StackSummaries[?$name_filter].[StackName,StackStatus]" --output text > "$SCAN/$r.stacks" 2>/dev/null; then
    if AWS_MAX_ATTEMPTS=2 aws cloudformation describe-stack-set --region "$r" "${QUICK[@]}" --stack-set-name "$STACKSET" \
        --query StackSet.Status --output text 2>/dev/null | grep -q ACTIVE; then
      : > "$SCAN/$r.set"
    fi
  else
    : > "$SCAN/$r.skipped"
  fi
}
for r in $REGIONS; do scan_region "$r" & done
wait
# A Region that timed out may only have been slow (a live run named six Regions the first time and one the second): ask those once more.
for r in $REGIONS; do
  if [ -f "$SCAN/$r.skipped" ]; then rm -f "$SCAN/$r.skipped"; scan_region "$r" & fi
done
wait

FOUND_STACKS=()    # "region|name|status"
FOUND_SETS=()      # "region|name"
SKIPPED=()
for r in $REGIONS; do
  if [ -f "$SCAN/$r.skipped" ]; then SKIPPED+=("$r"); continue; fi
  while read -r name status; do
    [ -n "$name" ] && [ "$name" != None ] && FOUND_STACKS+=("$r|$name|$status")
  done < "$SCAN/$r.stacks"
  [ -f "$SCAN/$r.set" ] && FOUND_SETS+=("$r|$STACKSET")
done
if [ ${#SKIPPED[@]} -gt 0 ]; then
  say "Could not reach these Regions, so they were not checked: ${SKIPPED[*]}"
  say "(Usually Regions this account does not use. run.sh only ever deploys to the Region CloudShell is in.)"
fi

# Roles that look like ours but that no stack found above accounts for (made by hand, or left by a stack that is gone).
ROLES=$(aws iam list-roles --query "Roles[?starts_with(RoleName,'DataProtectionReviewer')].RoleName" --output text 2>/dev/null | tr '\t' '\n' | sed '/^$/d')
OWNED=""
for s in ${FOUND_STACKS[@]+"${FOUND_STACKS[@]}"}; do
  IFS='|' read -r r n st <<< "$s"
  rn=$(aws cloudformation describe-stacks --region "$r" --stack-name "$n" --query "Stacks[0].Parameters[?ParameterKey=='RoleName'].ParameterValue|[0]" --output text 2>/dev/null)
  { [ -n "$rn" ] && [ "$rn" != None ]; } || rn=DataProtectionReviewer
  OWNED="$OWNED $rn "
done
ORPHANS=()
for role in $ROLES; do
  case "$OWNED" in *" $role "*) ;; *) ORPHANS+=("$role") ;; esac
done

# -- what was found, and what to remove --------------------------------------------------------------------------------------------
DELETE_AWS=0
FOUND=$(( ${#FOUND_STACKS[@]} + ${#FOUND_SETS[@]} ))
say ""
if [ "$FOUND" -gt 0 ]; then
  say "Found in AWS:"
  for s in ${FOUND_STACKS[@]+"${FOUND_STACKS[@]}"}; do IFS='|' read -r r n st <<< "$s"; say "  Stack     $n ($r), $st"; done
  for s in ${FOUND_SETS[@]+"${FOUND_SETS[@]}"}; do
    IFS='|' read -r r n <<< "$s"
    cnt=$(aws cloudformation list-stack-instances --region "$r" --stack-set-name "$n" --query 'length(Summaries)' --output text 2>/dev/null)
    say "  StackSet  $n ($r), with the role in ${cnt:-?} member account(s)"
  done
  if [ "$YES" = 1 ] || ask_yn "Remove these, with their read-only roles?" y; then DELETE_AWS=1
  else say "  They stay in AWS. Run this script again to remove them later."; fi
else
  say "Nothing found in AWS: no assessment stack or StackSet."
fi
if [ ${#ORPHANS[@]} -gt 0 ]; then
  say ""
  say "These roles look like assessment roles, but no stack here manages them:"
  for o in "${ORPHANS[@]}"; do say "  $o"; done
  say "They were probably made by hand. They are read-only and are not deleted here; remove them in the IAM console if they are not needed."
fi

# -- local results and files ---------------------------------------------------------------------------------------------------------------
RESULT_PATHS=()
[ -d "$HERE/output" ] && RESULT_PATHS+=("$HERE/output")
for z in "$HERE"/*-results-*.zip; do [ -f "$z" ] && RESULT_PATHS+=("$z"); done
if [ ${#RESULT_PATHS[@]} -gt 0 ]; then
  say ""
  say "Local results (customer data):"
  for p in "${RESULT_PATHS[@]}"; do say "  ${p#"$HERE/"}"; done
  if [ "$DELETE_RESULTS" = 0 ] && [ "$YES" = 0 ]; then
    say "Download anything you need first: CloudShell > Actions > Download file."
    ask_yn "Delete the results?" n && DELETE_RESULTS=1
  fi
  if [ "$DELETE_RESULTS" = 1 ] && [ "$YES" = 0 ]; then
    read -r -p "Type DELETE to confirm deleting the results (anything else keeps them): " a || a=""
    a=${a%$'\r'}
    [ "$a" = DELETE ] || { DELETE_RESULTS=0; say "  The results will be kept."; }
  fi
else
  DELETE_RESULTS=0
fi

PRESENT=()
for f in "${BUNDLE_FILES[@]}"; do [ -e "$HERE/$f" ] && PRESENT+=("$f"); done
AWS_REMAINS=0
[ "$FOUND" -gt 0 ] && [ "$DELETE_AWS" = 0 ] && AWS_REMAINS=1
if [ ${#PRESENT[@]} -gt 0 ]; then
  if [ "$AWS_REMAINS" = 1 ]; then
    [ "$REMOVE_ALL" = 1 ] && say "The assessment files are kept because the roles stay in AWS and this script is what removes them."
    REMOVE_ALL=0
  elif [ "$REMOVE_ALL" = 0 ] && [ "$YES" = 0 ]; then
    say ""
    say "Assessment files: ${#PRESENT[@]} files (scripts, collector, templates, guides) in $HERE"
    say "Keep them to run again; delete them to leave CloudShell as it was before the upload."
    ask_yn "Delete the assessment files, this script included?" n && REMOVE_ALL=1
  fi
fi

say ""
say "Summary"
if [ "$FOUND" -gt 0 ]; then
  [ "$DELETE_AWS" = 1 ] && say "  REMOVE  the AWS stack(s) and StackSet listed above, and their roles" || say "  KEEP    the AWS stack(s) and StackSet"
fi
if [ ${#RESULT_PATHS[@]} -gt 0 ]; then
  [ "$DELETE_RESULTS" = 1 ] && say "  DELETE  the local results" || say "  KEEP    the local results"
fi
if [ ${#PRESENT[@]} -gt 0 ]; then
  [ "$REMOVE_ALL" = 1 ] && say "  DELETE  ${#PRESENT[@]} assessment files" || say "  KEEP    the assessment files"
fi
if [ "$DELETE_AWS" = 0 ] && [ "$DELETE_RESULTS" = 0 ] && [ "$REMOVE_ALL" = 0 ]; then
  say ""; say "Nothing to remove. No changes made."; exit 0
fi
if [ "$YES" = 0 ]; then
  ask_yn "Proceed?" n || { say "Cleanup canceled. No changes made."; exit 0; }
fi

# -- remove from AWS: member roles first, then the stacks, then a StackSet no stack owned ------------------------------------------
wait_operation() {   # region stack-set operation-id
  local s
  while s=$(aws cloudformation describe-stack-set-operation --region "$1" --stack-set-name "$2" --operation-id "$3" --query StackSetOperation.Status --output text); \
        [ "$s" = RUNNING ] || [ "$s" = QUEUED ] || [ "$s" = STOPPING ]; do
    sleep 10
  done
  say "  Member roles removed: $s"
  [ "$s" = SUCCEEDED ]
}
AWS_OK=1
if [ "$DELETE_AWS" = 1 ]; then
  for s in ${FOUND_SETS[@]+"${FOUND_SETS[@]}"}; do
    IFS='|' read -r r n <<< "$s"
    OUS=$(aws cloudformation list-stack-instances --region "$r" --stack-set-name "$n" --query 'Summaries[].OrganizationalUnitId' --output text 2>/dev/null | tr '\t' '\n' | sed '/^$/d;/^None$/d' | sort -u | paste -sd, -)
    IREG=$(aws cloudformation list-stack-instances --region "$r" --stack-set-name "$n" --query 'Summaries[].Region' --output text 2>/dev/null | tr '\t' '\n' | sed '/^$/d' | sort -u | tr '\n' ' ')
    if [ -n "$OUS" ] && [ -n "$IREG" ]; then
      say ""
      say "Removing the role from the member accounts of $n (often 5 to 15 minutes) ..."
      OP=$(step aws cloudformation delete-stack-instances --region "$r" --stack-set-name "$n" \
        --deployment-targets OrganizationalUnitIds="$OUS" --regions $IREG --no-retain-stacks \
        --operation-preferences FailureTolerancePercentage=100,MaxConcurrentPercentage=100 \
        --query OperationId --output text) || { AWS_OK=0; continue; }
      wait_operation "$r" "$n" "$OP" || AWS_OK=0
    fi
  done
  for s in ${FOUND_STACKS[@]+"${FOUND_STACKS[@]}"}; do
    IFS='|' read -r r n st <<< "$s"
    say ""
    say "Deleting the stack $n ($r) ..."
    step aws cloudformation delete-stack --region "$r" --stack-name "$n"
    if aws cloudformation wait stack-delete-complete --region "$r" --stack-name "$n"; then
      say "  Deleted $n and its role."
    else
      AWS_OK=0
      aws cloudformation describe-stack-events --region "$r" --stack-name "$n" \
        --query "StackEvents[?contains(ResourceStatus,'FAILED')]|[0:5].[LogicalResourceId,ResourceStatusReason]" --output table >&2 2>/dev/null
    fi
  done
  for s in ${FOUND_SETS[@]+"${FOUND_SETS[@]}"}; do      # a StackSet no stack owned (the no-management-role option), deleted once it is empty
    IFS='|' read -r r n <<< "$s"
    if aws cloudformation describe-stack-set --region "$r" --stack-set-name "$n" >/dev/null 2>&1; then
      if step aws cloudformation delete-stack-set --region "$r" --stack-set-name "$n"; then say "  Deleted the StackSet $n."; else AWS_OK=0; fi
    fi
  done
  if [ "$AWS_OK" = 0 ]; then
    die "not everything was removed from AWS (see above). Fix the cause, or use the CloudFormation console, then run this script again. No local file was deleted."
  fi
fi

# -- local files ---------------------------------------------------------------------------------------------------------------------------
if [ "$AWS_REMAINS" = 0 ]; then rm -f -- "$HERE/.external_id"; fi
if [ "$DELETE_RESULTS" = 1 ]; then
  for p in "${RESULT_PATHS[@]}"; do rm -rf -- "$p"; done
  say "Deleted the local results."
fi
if [ "$DELETE_AWS" = 1 ] && [ ${#FOUND_SETS[@]} -gt 0 ]; then
  say ""
  say "StackSets trusted access for the organization was left on, because other StackSets may rely on it."
  say "To turn it off: aws cloudformation deactivate-organizations-access"
fi
if [ "$DELETE_RESULTS" = 0 ] && [ ${#RESULT_PATHS[@]} -gt 0 ]; then
  say "Local results kept (customer data: delete them when they are no longer needed)."
fi
if [ "$REMOVE_ALL" = 1 ]; then
  for f in "${PRESENT[@]}"; do rm -f -- "$HERE/$f"; done
  say "Deleted ${#PRESENT[@]} assessment files. Cleanup complete."
  exit 0
fi
say "Cleanup complete."
