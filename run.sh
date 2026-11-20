#!/usr/bin/env bash
# Cloud Data Protection Review: one command for a single account or a whole organization.
#
#   bash run.sh                            asks a few questions (customer, what to assess, Cost Explorer, Regions), shows the
#                                          plan and waits for a yes before it creates anything. Recommended.
#   bash run.sh account                    one account: create the read-only role, then run the assessment (no questions)
#   bash run.sh org                        an organization: create the role in the management account and, through a
#                                          StackSet, in every member account, then run the assessment
#   bash run.sh org --no-management-role   an organization where you cannot create a role in the management account:
#                                          the role goes into the member accounts only (see the guide)
#   bash cleanup.sh                        when you are done: finds and removes what this created (asks first)
#
# Options, all optional (each one answers a question up front):
#   --org-name "Customer"      name shown in the report's header (--customer also works; settings.txt can set a default)
#   --partner-name "Partner"   preparer shown in the report's footer (--partner also works; settings.txt can set a default)
#   --target ID                an organization: deploy to one OU (ou-...) instead of the whole organization (default)
#   --regions "R1 R2"          only scan these Regions (default: every enabled Region that holds resources)
#   --no-costs                 leave Cost Explorer out (--include-costs is the default; about 7 requests at $0.01 each)
#   --output-dir DIR           where the report and CSV files are written (default ./output)
#   --external-id ID           use this ExternalId instead of making one (or reusing the one saved by an earlier run)
#   --yes                      with no questions asked: take the answer shown for anything not given, and do not wait for a yes
#
# This script runs the same commands as Deployment_Guide.html, in the same order, and prints each AWS command before it runs.
# It uses only your own sign-in, and it creates only the CloudFormation stack (or StackSet) that holds the read-only role.
# The ExternalId is made for you, saved next to this script in .external_id (readable by you only) so a second run reuses it,
# and printed at the end. It is not a secret, but the collector needs it each time.

STACK=DataProtectionReviewer
STACKSET=DataProtectionReviewer-members

die() { printf '\nStopped: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
step() { printf '+ %s\n' "${*//"$EXT"/<ExternalId>}" >&2; "$@"; }     # show an AWS command (without the ExternalId), then run it

HERE=$(cd "$(dirname "$0")" && pwd) || die "cannot find the folder this script is in."
SELF="$HERE/$(basename "$0")"                  # an absolute path, because the script changes folder next
cd "$HERE" || die "cannot open the folder this script is in."

usage() { sed -n '2,/^[^#]/{/^[^#]/!p}' "$SELF" | sed 's/^# \{0,1\}//'; }

MODE=${1:-}
GUIDED=0
case "$MODE" in
  account|org) shift ;;
  -h|--help) usage; exit 0 ;;
  ""|-*) GUIDED=1 ;;
  *) usage >&2; exit 2 ;;
esac

ORG_NAME=""
PARTNER=""
OUT=./output
EXT=""
NO_MGMT=0
TARGET=""            # an organization: one OU to deploy to instead of the whole organization
COSTS=""             # "", true or false: false leaves Cost Explorer out of the role and of the report
REGIONS=""           # Regions to scan; empty means every enabled Region that holds resources
YES=0
ORG_GIVEN=0; PARTNER_GIVEN=0    # given on the command line, so the question is not asked (a settings.txt name is only the default)

# Defaults a partner can put in settings.txt (org_name=..., partner_name=...). The file is read as text, never run.
if [ -f settings.txt ]; then
  while IFS='=' read -r key value; do
    value=${value%$'\r'}                       # a file edited on Windows ends its lines with a carriage return
    case "$key" in
      org_name) ORG_NAME=$value ;;
      partner_name) PARTNER=$value ;;
    esac
  done < settings.txt
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --org-name|--customer)  [ $# -ge 2 ] || die "$1 needs a value."; ORG_NAME=$2; ORG_GIVEN=1; shift 2 ;;
    --partner-name|--partner) [ $# -ge 2 ] || die "$1 needs a value."; PARTNER=$2; PARTNER_GIVEN=1; shift 2 ;;
    --target)        [ $# -ge 2 ] || die "--target needs a value."; TARGET=$2; shift 2 ;;
    --regions)       [ $# -ge 2 ] || die "--regions needs a value."; REGIONS=${2//,/ }; shift 2 ;;
    --include-costs) COSTS=true; shift ;;
    --no-costs)      COSTS=false; shift ;;
    --yes)           YES=1; shift ;;
    --output-dir)    [ $# -ge 2 ] || die "--output-dir needs a value."; OUT=$2; shift 2 ;;
    --external-id)   [ $# -ge 2 ] || die "--external-id needs a value."; EXT=$2; shift 2 ;;
    --no-management-role) NO_MGMT=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
done

valid_region() { [[ "$1" =~ ^[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-[0-9]+$ ]]; }
valid_target() { [[ "$1" =~ ^(r-[0-9a-z]{4,32}|ou-[0-9a-z]{4,32}-[0-9a-z]{8,32})$ ]]; }
for r in $REGIONS; do valid_region "$r" || die "not a Region: $r"; done
[ -z "$TARGET" ] || valid_target "$TARGET" || die "--target must be an organization root (r-...) or an OU (ou-...)."
if [ "$GUIDED" = 0 ] && [ "$NO_MGMT" = 1 ] && [ "$MODE" != org ]; then die "--no-management-role applies to an organization: bash run.sh org --no-management-role"; fi

command -v aws >/dev/null 2>&1 || die "the AWS CLI was not found. Run this in AWS CloudShell, which has it."
command -v python3 >/dev/null 2>&1 || die "python3 was not found. Run this in AWS CloudShell, which has it."
[ -f collector.py ] && [ -f data_risk_assessment_role.yaml ] || die "collector.py and the templates are not next to this script. Unzip the bundle, then run it from that folder."

# -- guided: ask the few questions instead of needing options -----------------------------------------------------------------------
ask() {   # ask "Question" "default": the answer is left in REPLY; Enter (or no input) keeps the default
  local shown=""; [ -n "$2" ] && shown=" [$2]"
  read -r -p "$1$shown: " REPLY || REPLY=""
  REPLY=${REPLY%$'\r'}                  # an answer pasted or piped from Windows ends with a carriage return
  REPLY=${REPLY:-$2}
}
ask_yn() {   # ask_yn "Question" y|n: succeeds for yes; no input takes the default
  local hint="[y/N]" a; [ "$2" = y ] && hint="[Y/n]"
  while true; do
    read -r -p "$1 $hint: " a || a=""
    a=${a%$'\r'}
    case "${a:-$2}" in y|Y|yes|YES|Yes) return 0 ;; n|N|no|NO|No) return 1 ;; *) say "Please answer y or n." ;; esac
  done
}
if [ "$GUIDED" = 1 ]; then
  say ""
  say "Cloud Data Protection Review. Reads backup and storage settings only; the one thing it creates is a read-only role."
  if [ "$YES" = 0 ]; then
    say "A few questions. Press Enter to take the answer shown in [brackets]."
    say ""
    if [ "$ORG_GIVEN" = 0 ]; then ask "Customer name for the report" "$ORG_NAME"; ORG_NAME=$REPLY; fi
    if [ "$PARTNER_GIVEN" = 0 ]; then ask "Partner name for the report (Enter to leave it out)" "$PARTNER"; PARTNER=$REPLY; fi
    say ""
    say "What should be assessed?"
    say "  1) This AWS account only"
    say "  2) Every account in the AWS Organization (run in the management account)"
    say "  3) The organization's member accounts only, because no role may be created in the management account"
    say "     (that account is then not assessed)"
    while true; do
      ask "Choose 1, 2 or 3" "1"
      case "$REPLY" in 1) MODE=account; break ;; 2) MODE=org; break ;; 3) MODE=org; NO_MGMT=1; break ;; *) say "Please choose 1, 2 or 3." ;; esac
    done
    if [ "$MODE" = org ] && [ -z "$TARGET" ]; then
      say ""
      say "Deploy the role to the whole organization, or to one organizational unit (OU)? One OU is a good first run in a large organization."
      while true; do
        ask "Press Enter for the whole organization, or type an OU ID (ou-...)" ""
        REPLY=${REPLY//[[:space:]]/}
        if [ -z "$REPLY" ]; then break; fi
        if valid_target "$REPLY" && [ "${REPLY%%-*}" = ou ]; then TARGET=$REPLY; break; fi
        say "That is not an OU ID. It looks like ou-ab12-cd34ef56."
      done
    fi
    if [ -z "$COSTS" ]; then
      say ""
      if ask_yn "Include Cost Explorer spend data? (about 7 requests at \$0.01 each)" y; then COSTS=true; else COSTS=false; fi
    fi
    if [ -z "$REGIONS" ]; then
      say ""
      ask "Regions to scan: Enter for every enabled Region that holds resources, or list them (for example us-east-1 us-west-2)" ""
      REGIONS=${REPLY//,/ }
      for r in $REGIONS; do valid_region "$r" || die "not a Region: $r"; done
    fi
  else
    MODE=account
  fi
fi
if [ "$NO_MGMT" = 1 ] && [ "$MODE" != org ]; then die "--no-management-role applies to an organization: bash run.sh org --no-management-role"; fi
if [ "$MODE" = org ]; then [ -f data_risk_assessment_org.yaml ] || die "data_risk_assessment_org.yaml is not next to this script."; fi
read -r -a REGION_LIST <<< "$REGIONS"
COST_OVERRIDE=(); COST_PARAMETER=()
if [ "$COSTS" = false ]; then COST_OVERRIDE=(EnableCostExplorer=false); COST_PARAMETER=(ParameterKey=EnableCostExplorer,ParameterValue=false); fi

# -- the ExternalId: given, saved by an earlier run, or new ---------------------------------------------------------------------
STATE=.external_id
valid_external_id() { [[ "$1" =~ ^[A-Za-z0-9_+=,.@-]{8,128}$ ]]; }
if [ -z "$EXT" ] && [ -f "$STATE" ]; then
  EXT=$(head -n 1 "$STATE" | tr -d '\r\n ')
  valid_external_id "$EXT" || EXT=""
  [ -n "$EXT" ] && say "Using the ExternalId saved by an earlier run ($STATE)."
fi
if [ -z "$EXT" ]; then
  EXT=$(python3 -c "import secrets; print(secrets.token_hex(24))") || die "could not make an ExternalId."
fi
valid_external_id "$EXT" || die "the ExternalId must be 8 to 128 letters, digits or _+=,.@- characters."
if ( umask 077; printf '%s\n' "$EXT" > "$STATE" ) 2>/dev/null; then :; else say "Note: could not save the ExternalId to $STATE; it is printed at the end."; fi

# -- who the role will trust: the role or user you are signed in as ---------------------------------------------------------
ME=$(aws sts get-caller-identity --query Arn --output text) || die "could not read who you are signed in as. Check your AWS sign-in."
case "$ME" in
  *:assumed-role/*)
    ME=$(aws iam get-role --role-name "$(echo "$ME" | cut -d/ -f2)" --query Role.Arn --output text) \
      || die "could not look up your role (iam:GetRole). Find its ARN and run the guide's lines by hand with ME set to it."
    ;;
esac
say "Role will trust: $ME"

if [ "$GUIDED" = 1 ] && [ "$YES" = 0 ]; then
  say ""
  say "Plan"
  case "$MODE$NO_MGMT" in
    account0) say "  Assess:       this account only" ;;
    org0)     say "  Assess:       the organization, management account included" ;;
    org1)     say "  Assess:       the organization's member accounts (the management account is not assessed)" ;;
  esac
  [ "$MODE" = org ] && say "  Deploy to:    ${TARGET:-the whole organization}"
  say "  Report for:   ${ORG_NAME:-(no name given)}${PARTNER:+, prepared by $PARTNER}"
  if [ ${#REGION_LIST[@]} -gt 0 ]; then say "  Regions:      ${REGION_LIST[*]}"; else say "  Regions:      every enabled Region that holds resources"; fi
  [ "$COSTS" = false ] && say "  Cost Explorer: left out" || say "  Cost Explorer: included"
  case "$MODE$NO_MGMT" in
    account0) say "  Creates:      the CloudFormation stack $STACK (one read-only role). Nothing else is changed." ;;
    org0)     say "  Creates:      the stack $STACK (the role here) and the StackSet $STACKSET (the role in each member account)." ;;
    org1)     say "  Creates:      the StackSet $STACKSET (the role in each member account)." ;;
  esac
  [ "$MODE" = org ] && say "                It also turns on StackSets trusted access for the organization if that is off."
  say ""
  ask_yn "Create the read-only role and run the assessment?" n || { say "Canceled. Nothing was created."; exit 0; }
fi

# -- the role's name: reuse the existing stack's, clear a failed attempt, avoid a role that exists outside the stack -------------
ROLE=DataProtectionReviewer
ST=""; R=""
SS_EXISTS=0
if [ "$NO_MGMT" = 1 ] && aws cloudformation describe-stack-set --stack-set-name "$STACKSET" >/dev/null 2>&1; then
  # A second run reuses the member StackSet, so the role name is the one it was made with.
  SS_EXISTS=1
  R=$(aws cloudformation describe-stack-set --stack-set-name "$STACKSET" --query "StackSet.Parameters[?ParameterKey=='RoleName'].ParameterValue|[0]" --output text 2>/dev/null) || R=""
  if [ -n "$R" ] && [ "$R" != None ]; then ROLE=$R; fi
  ST=reuse
else
  read -r ST R <<< "$(aws cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].[StackStatus,Parameters[?ParameterKey=='RoleName'].ParameterValue|[0]]" --output text 2>/dev/null)" || true
fi
if [ "$ST" = ROLLBACK_COMPLETE ]; then
  say "Removing a failed earlier attempt"
  step aws cloudformation delete-stack --stack-name "$STACK" || die "could not remove the failed earlier stack."
  step aws cloudformation wait stack-delete-complete --stack-name "$STACK" || die "the failed earlier stack did not finish deleting."
  ST=""
fi
if [ "$SS_EXISTS" = 1 ]; then
  :
elif [ -n "$ST" ]; then
  if [ -n "$R" ] && [ "$R" != None ]; then ROLE=$R; fi
  say "Updating the existing stack"
elif aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
  ROLE="DataProtectionReviewer-$(python3 -c "import secrets; print(secrets.token_hex(3))")"
  say "A role named DataProtectionReviewer exists outside this stack, so this one is named $ROLE"
fi
say "Role name: $ROLE"

# -- create the role ----------------------------------------------------------------------------------------------------------
ACCOUNTS=()
if [ "$MODE" = account ]; then
  step aws cloudformation deploy --stack-name "$STACK" --template-file data_risk_assessment_role.yaml \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameter-overrides TrustedPrincipalArn="$ME" ExternalId="$EXT" RoleName="$ROLE" "${COST_OVERRIDE[@]}" \
    || die "the role could not be created. The message above says why; the guide's \"If something goes wrong\" lists the usual causes."
elif [ "$NO_MGMT" = 0 ]; then
  step aws cloudformation activate-organizations-access || die "could not turn on StackSets for the organization. Run this in the management account."
  ROOT_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text) || die "could not read the organization's root (organizations:ListRoots). Run this in the management account."
  [ -z "$TARGET" ] || ROOT_ID=$TARGET
  step aws cloudformation deploy --stack-name "$STACK" --template-file data_risk_assessment_org.yaml \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameter-overrides TrustedPrincipalArn="$ME" ExternalId="$EXT" RoleName="$ROLE" OrganizationRootId="$ROOT_ID" "${COST_OVERRIDE[@]}" \
    || die "the organization stack could not be created. The message above says why. If you cannot create a role in the management account, run: bash run.sh org --no-management-role"
else
  if [ "$SS_EXISTS" = 1 ]; then
    say "The member StackSet $STACKSET already exists, so it is reused. It must have been made with the ExternalId in $STATE."
  else
    step aws cloudformation activate-organizations-access || die "could not turn on StackSets for the organization. Run this in the management account."
    ROOT_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text) || die "could not read the organization's root (organizations:ListRoots)."
    [ -z "$TARGET" ] || ROOT_ID=$TARGET
    step aws cloudformation create-stack-set --stack-set-name "$STACKSET" --template-body file://data_risk_assessment_role.yaml \
      --capabilities CAPABILITY_NAMED_IAM --permission-model SERVICE_MANAGED \
      --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
      --parameters ParameterKey=TrustedPrincipalArn,ParameterValue="$ME" ParameterKey=ExternalId,ParameterValue="$EXT" \
                   ParameterKey=RoleName,ParameterValue="$ROLE" ParameterKey=IsManagementAccount,ParameterValue=false \
                   "${COST_PARAMETER[@]}" \
      || die "the member StackSet could not be created."
    OP=$(step aws cloudformation create-stack-instances --stack-set-name "$STACKSET" \
      --deployment-targets OrganizationalUnitIds="$ROOT_ID" --regions "${AWS_REGION:-us-east-1}" \
      --operation-preferences FailureTolerancePercentage=100,MaxConcurrentPercentage=100 \
      --query OperationId --output text) || die "the member roles could not be started."
    say "Creating the member roles (this can take several minutes) ..."
    while S=$(aws cloudformation describe-stack-set-operation --stack-set-name "$STACKSET" --operation-id "$OP" --query StackSetOperation.Status --output text); [ "$S" = RUNNING ] || [ "$S" = QUEUED ]; do
      sleep 10
    done
    say "Member roles: $S"
    [ "$S" = SUCCEEDED ] || say "Some member accounts did not get the role. The run reads the others and lists those as not assessed."
  fi
  # Name the members that have the role, so the others are left out and counted on the report's Inputs page.
  for account in $(aws cloudformation list-stack-instances --stack-set-name "$STACKSET" --query "Summaries[].Account" --output text 2>/dev/null); do
    [[ "$account" =~ ^[0-9]{12}$ ]] && ACCOUNTS+=("$account")
  done
fi

# -- run the collector --------------------------------------------------------------------------------------------------------
ARGS=(--external-id "$EXT" --role-name "$ROLE" --output-dir "$OUT")
[ -n "$ORG_NAME" ] && ARGS+=(--org-name "$ORG_NAME")
[ -n "$PARTNER" ] && ARGS+=(--partner-name "$PARTNER")
[ "$COSTS" = false ] && ARGS+=(--no-cost)
[ ${#REGION_LIST[@]} -gt 0 ] && ARGS+=(--regions "${REGION_LIST[@]}")
if [ "$NO_MGMT" = 1 ]; then
  ARGS+=(--org-with-current-credentials)
  [ ${#ACCOUNTS[@]} -gt 0 ] && ARGS+=(--accounts "${ACCOUNTS[@]}")
fi

# A new role can take a little while before it can be used, so the access check tries a few times.
say "Checking access ..."
TRIES=0
until step python3 collector.py --preflight "${ARGS[@]}"; do
  TRIES=$((TRIES + 1))
  [ "$TRIES" -lt 3 ] || die "the access check did not pass. The lines above say which permission is missing. If the message is access denied when assuming the role, the person running this also needs permission to call sts:AssumeRole on the role; the guide's \"If something goes wrong\" explains the causes."
  say "Waiting 15 seconds for the new role to become usable, then trying again ..."
  sleep 15
done

say "Running the assessment ..."
step python3 collector.py "${ARGS[@]}" || die "the assessment did not finish. The lines above say why."

say ""
say "Done. The report is $OUT/report.html. Download it with Actions > Download file and open it in a browser."
say "ExternalId (saved in $HERE/$STATE; a later run reuses it): $EXT"

# One file to download: the report and the CSV files, named for the customer.  zip if it is installed, else python3's own zip.
if [ -s "$OUT/report.html" ]; then
  SLUG=$(printf '%s' "${ORG_NAME:-assessment}" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+|-+$//g' | cut -c1-48)
  ZIP="$HERE/${SLUG:-assessment}-results-$(date -u +%Y%m%dT%H%M%SZ).zip"
  { command -v zip >/dev/null 2>&1 && (cd "$OUT" && zip -qr "$ZIP" .); } >/dev/null 2>&1 || (cd "$OUT" && python3 -m zipfile -c "$ZIP" .) >/dev/null 2>&1       # from inside the folder, so report.html is at the top of the zip as with zip
  if [ -s "$ZIP" ]; then
    say ""
    say "Results ZIP, one file to download: $ZIP"
    say "It holds account IDs, resource names and tags: handle it as customer data."
  fi
fi
say ""
say "When you are done, remove what this created: bash cleanup.sh"
