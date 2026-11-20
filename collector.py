#!/usr/bin/env python3
"""
Cloud Data Protection Collector
────────────────────────────────
Assumes a read-only IAM role in every AWS account in an Organization,
collects backup and protection metadata, and renders an HTML report
(plus companion CSVs) in the style of the Cloud Data Protection Review.

Usage
-----
  python collector.py \
    --external-id  YOUR_EXTERNAL_ID \
    --role-name    DataProtectionReviewer \
    --regions      us-east-1 us-west-2 \
    --output-dir   ./output \
    --org-name     "Acme Logistics"

  Optional:
    --profile        AWS CLI profile for the management account (default: default)
    --single-account Run against one account only (skip org discovery)
    --sso-profile    Read each account through IAM Identity Center (no sts:AssumeRole),
                     with the reviewer permission set (--sso-permission-set)
    --max-workers    Accounts scanned at once (default: 8)
    --region-workers Regions scanned at once within each account (default: 4)
    --item-workers   Buckets or tables read at once within each Region (default: 8)

Nothing is written to any AWS account.  The role has an explicit Deny on
all object-level reads and all write/modify/delete actions.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import html
import json
import math
import os
import re
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import boto3
import botocore.credentials
import botocore.exceptions
import botocore.session
import botocore.utils
from botocore import xform_name
from botocore.config import Config as BotocoreConfig

# Adaptive retry: exponential backoff with jitter on throttling (429 / ThrottlingException).
# Without this, a burst of API calls silently drops data rather than waiting and retrying.
_RETRY_CONFIG = BotocoreConfig(retries={"max_attempts": 6, "mode": "adaptive"})

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

SESSION_NAME = "DataProtectionReview"
DEFAULT_ROLE_NAME = "DataProtectionReviewer"
DEFAULT_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
BACKUP_JOB_LOOKBACK_DAYS = 30
COST_LOOKBACK_DAYS = 30
RESTORE_LOOKBACK_DAYS = 90       # how far back restore jobs are read; --restore-lookback-days changes it
JOB_HISTORY_DAYS = 30            # how far back backup and copy jobs are read for the outcomes section; --job-history-days
FAILING_JOB_THRESHOLD_DAYS = 7   # consecutive failures ≥ this → flagged
MAX_CLOUDTRAIL_EVENTS = 50

PRODUCTION_TAG_KEYS   = {"environment", "env", "Environment", "Env"}
PRODUCTION_TAG_VALUES = {"prod", "production", "prd", "live"}
DEV_TAG_VALUES        = {"dev", "development", "test", "testing", "staging",
                          "stage", "sandbox", "nonprod", "non-prod"}

ICEBERG_TABLE_FORMATS = {"ICEBERG", "iceberg"}

# ── Resource type allowlist ─────────────────────────────────────────────────
# Only data-bearing resource types are inventoried.  Without this filter the
# Config path returns security groups, network interfaces, etc., inflating
# the "unprotected" count with resources that hold no recoverable data.
# Each entry maps the canonical AWS type to its Config, Resource Explorer v2,
# and direct-API equivalents so adding a type is a one-line edit.
ALLOWLISTED_TYPES: Dict[str, Dict[str, str]] = {
    "AWS::RDS::DBInstance":  {"config": "AWS::RDS::DBInstance",  "re2": "rds:db",              "service": "rds"},
    "AWS::RDS::DBCluster":   {"config": "AWS::RDS::DBCluster",  "re2": "rds:cluster",         "service": "rds"},
    "AWS::DynamoDB::Table":  {"config": "AWS::DynamoDB::Table",  "re2": "dynamodb:table",      "service": "dynamodb"},
    "AWS::EC2::Volume":      {"config": "AWS::EC2::Volume",      "re2": "ec2:volume",          "service": "ec2"},
    "AWS::S3::Bucket":       {"config": "AWS::S3::Bucket",       "re2": "s3:bucket",           "service": "s3"},
}

# RDS-family display types.  Discovery always returns AWS::RDS::DBCluster (the real
# Config / Resource Explorer type), so these are NOT allowlist keys: they are produced
# afterwards by remapping on the Engine field.  Keeping them out of ALLOWLISTED_TYPES
# avoids duplicate "config"/"re2" values colliding in the reverse maps below.
RDS_DB_CLUSTER   = "AWS::RDS::DBCluster"
RDS_DB_INSTANCE  = "AWS::RDS::DBInstance"
RDS_AURORA       = "AWS::RDS::AuroraCluster"
RDS_NEPTUNE      = "AWS::RDS::NeptuneCluster"
RDS_DOCDB        = "AWS::RDS::DocDBCluster"
RDS_CLUSTER_TYPES = frozenset({RDS_DB_CLUSTER, RDS_AURORA, RDS_NEPTUNE, RDS_DOCDB})

# Iceberg tables are first-class rows.  Glue-on-S3 tables live under a prefix of a
# general-purpose bucket; S3 Tables live in table buckets, which ListBuckets does not show.
ICEBERG_GLUE_TYPE = "AWS::S3::IcebergTable"
S3_TABLES_TYPE    = "AWS::S3Tables::Table"

# Reverse map: Resource Explorer type → canonical type
_RE2_TYPE_MAP: Dict[str, str] = {v["re2"]: k for k, v in ALLOWLISTED_TYPES.items()}
# Set of Config type names for WHERE IN clauses
_CONFIG_TYPE_SET: frozenset = frozenset(v["config"] for v in ALLOWLISTED_TYPES.values())

# Cost per GiB-month by mechanism (AWS list pricing, us-east-1, checked PRICES_CHECKED)
PRICES_CHECKED = "November 2026"   # the one pricing reference date the report names
# Development copies kept longer than this are listed under Waste.  14 days is a default assumption (Alex's decision, 2026-11-16, from
# common retention practice for development and test data), not an AWS limit: AWS keeps its own short-term backups up to 35 days.
# --dev-retention-days, or tier 3's max_retention_days in the recovery targets file, sets another.
DEFAULT_DEV_RETENTION_DAYS = 14   # development copies kept longer than this are listed under Waste (a default assumption)
DEV_LONG_RETENTION_DAYS = DEFAULT_DEV_RETENTION_DAYS

MECHANISM_RATES = {
    "aws_backup_warm":   0.05,
    "aws_backup_cold":   0.01,
    "aws_backup_airgap": 0.0575,   # EBS, S3 and EFS; Aurora, DocumentDB, Neptune $0.0242; DynamoDB $0.115; none for RDS instances
    "ebs_snapshot":      0.05,
    # EBS Snapshots Archive: a full copy of the volume's data at $0.0125 per GB-month, kept at least 90 days, and $0.03 per GB to
    # restore to the standard tier, which can take up to 72 hours (Amazon EBS user guide, "Pricing and billing for archiving").
    # AWS Backup's cold storage for EBS is the same archive tier.
    "ebs_snapshot_archive": 0.0125,
    "ebs_snapshot_archive_restore": 0.03,    # per GB restored, once
    "rds_backup":        0.095,
    "dynamodb_pitr":     0.20,
    "dynamodb_ondemand": 0.10,     # DynamoDB backups in warm storage, in DynamoDB or AWS Backup
    "dynamodb_backup_cold": 0.03,  # DynamoDB backups in AWS Backup cold storage (needs advanced DynamoDB backup)
    "s3_standard":       0.023,
    "ebs_volume_gp3":    0.08,     # a volume's own storage, gp3; other volume types cost more or less
}
# A volume's own storage by type, per GB-month, and provisioned performance, us-east-1 list prices (Amazon EBS pricing page,
# checked November 2026).  gp3 includes 3,000 IOPS and 125 MB/s; io1 and io2 bill every provisioned IOPS (io2 tiers above 32,000
# IOPS are cheaper, so this is an upper bound there).  A type not listed falls back to gp3, and the basis says so.
EBS_VOLUME_RATES = {"gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015, "standard": 0.05}
EBS_IOPS_RATES = {"gp3": 0.005, "io1": 0.065, "io2": 0.065}       # per provisioned IOPS-month (gp3: above 3,000)
EBS_GP3_THROUGHPUT_RATE = 0.04                                   # per MB/s-month above 125
# Snapshots older than this in the standard tier make the Waste pillar's "long-retained" row: the longest default retention target
# (confidential production data, Alex's decision 2026-11-16), a default assumption the report names.
OLD_SNAPSHOT_DAYS = 365
# Malware Protection for AWS Backup is billed under GuardDuty: per GB scanned, us-east-1 list price (AWS GuardDuty pricing page).
MALWARE_SCAN_PER_GB = 0.05
MALWARE_SCAN_TYPES = ("AWS::EC2::Volume", "AWS::S3::Bucket")

# ── Data sensitivity inference ───────────────────────────────────────────────
# Scanned across ALL tag key/value pairs and the resource name — no new API
# calls. Tokens are split on whitespace, hyphens, underscores, dots, slashes.
_HIGH_RISK_TOKENS: frozenset = frozenset([
    "admin", "administrator", "security", "sre", "devops", "infra",
    "infrastructure", "secrets", "vault", "kms", "platform",
])
_CONFIDENTIAL_TOKENS: frozenset = frozenset([
    "finance", "financial", "accounting", "legal", "hr", "payroll",
    "compliance", "audit", "executive", "pii", "gdpr", "hipaa", "sox",
    "contracts", "procurement", "billing",
])
_DATA_CLASS_TOKENS: Dict[str, str] = {
    "finance": "financial",    "financial": "financial",   "accounting": "financial",
    "billing": "financial",    "payroll": "PII",           "hr": "PII",
    "pii": "PII",              "gdpr": "PII",              "hipaa": "PII",
    "legal": "legal",          "compliance": "legal",      "audit": "legal",
    "contracts": "legal",      "admin": "admin_access",    "security": "admin_access",
    "secrets": "admin_access", "vault": "admin_access",    "administrator": "admin_access",
}
_SENSITIVITY_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "HIGH_RISK_CONFIDENTIAL": 3}

# Tag keys whose values are worth scanning for sensitivity tokens.
# Operational keys ("team", "owner", "department") are intentionally excluded:
# "team=platform" or "owner=billing" would otherwise trigger HIGH_RISK/CONFIDENTIAL
# on resources that have nothing to do with sensitive data.
_SENSITIVITY_SCAN_TAG_KEYS: frozenset = frozenset({
    "name", "application", "app", "service", "project", "workload",
    "description", "data-type", "datatype", "data_type", "purpose",
    "function", "role", "component", "module",
})

# ── Default posture controls ─────────────────────────────────────────────────
# Named rules evaluated per resource.
# Each control: name, min_retention_days, max_retention_days (optional),
#               applies_to_sensitivity (list or "all"), severity.
DEFAULT_POSTURE_CONTROLS: List[Dict] = [
    {
        "name": "CriticalDataMinimumRetention",
        "applies_to_sensitivity": ["HIGH_RISK_CONFIDENTIAL", "CONFIDENTIAL"],
        "min_retention_days": 90,
        "severity": "HIGH",
    },
    {
        "name": "StandardDataMinimumRetention",
        "applies_to_sensitivity": ["INTERNAL"],
        "min_retention_days": 30,
        "severity": "MEDIUM",
    },
    {
        "name": "DevOverprotection",
        "applies_to_criticality": ["development"],
        "max_retention_days": DEV_LONG_RETENTION_DAYS,
        "severity": "LOW",
    },
    {
        "name": "CriticalDataCrossRegion",
        "applies_to_sensitivity": ["HIGH_RISK_CONFIDENTIAL", "CONFIDENTIAL"],
        "requires_cross_region": True,
        "severity": "MEDIUM",
    },
    {
        "name": "HighRiskVaultLock",
        "applies_to_sensitivity": ["HIGH_RISK_CONFIDENTIAL"],
        "requires_vault_lock_compliance": True,
        "severity": "HIGH",
    },
    {
        "name": "MinimumRecoveryPoints",
        "applies_to_sensitivity": ["HIGH_RISK_CONFIDENTIAL", "CONFIDENTIAL"],
        "min_recovery_points": 2,
        "severity": "MEDIUM",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Logging helpers
# ─────────────────────────────────────────────────────────────────────────────

# ── Counts in running text ──────────────────────────────────────────────────────────────────────────────────────────────
# Report and console text is written with "(s)" after a noun that follows a number.  _tidy_counts settles it from the
# number: "1 vault(s)" becomes "1 vault" and "3 vault(s)" becomes "3 vaults", and the verb that follows agrees ("1 account
# could not be read").  A phrase that starts "of" ("2 of those resource(s)") keeps the plural noun, as the English does.
_SINGULAR_VERB = {"have": "has", "are": "is", "were": "was", "do": "does", "hold": "holds", "use": "uses", "exist": "exists",
                  "appear": "appears", "select": "selects", "remain": "remains", "belong": "belongs", "carry": "carries"}
_COUNT_NOUN = re.compile(r"(?<![\w.,])(\d[\d,]*) ((?:[A-Za-z/]+ )*?[A-Za-z/]+)\(s\)(?: (" + "|".join(_SINGULAR_VERB) + r")\b)?")


def _tidy_counts(text: str) -> str:
    def fix(m: "re.Match") -> str:
        n = int(m.group(1).replace(",", ""))
        phrase, verb = m.group(2), m.group(3)
        plural = n != 1 or phrase.startswith("of ")
        out = f"{m.group(1)} {phrase}{'s' if plural else ''}"
        if verb:
            out += " " + (_SINGULAR_VERB[verb] if n == 1 else verb)
        return out
    return _COUNT_NOUN.sub(fix, text)


def _rate(usd: float) -> str:
    """A list price as AWS writes it: 0.05, 0.10, 0.095, 0.0125 (at least two decimals, no trailing zeros beyond them)."""
    text = f"{usd:.4f}".rstrip("0")
    return text + "0" * max(0, 2 - len(text.split(".")[1]))


def _n(count: int, noun: str, plural: Optional[str] = None) -> str:
    """'1 vault', '3 vaults'."""
    return f"{count:,} {noun if count == 1 else (plural or noun + 's')}"


def _has(count: int) -> str:
    return "has" if count == 1 else "have"


def _is(count: int) -> str:
    return "is" if count == 1 else "are"


def _was(count: int) -> str:
    return "was" if count == 1 else "were"


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(_tidy_counts(f"[{ts}] {msg}"), flush=True)

def warn(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] WARN  {msg}", flush=True, file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────
# AWS client helpers
# ─────────────────────────────────────────────────────────────────────────────

ASSUME_HINTS = {
    "AccessDenied":
        "AWS gives this same answer when the role does not exist in that account, and when it "
        "exists but does not trust you. If the role exists, check four things: the ExternalId "
        "matches what you passed to CloudFormation, TrustedPrincipalArn is the role or "
        "user ARN you are actually running as (compare 'aws sts get-caller-identity'), "
        "if you are running as an assumed role, TrustedPrincipalArn is the ROLE arn "
        "not the assumed-role session arn, and your own identity is allowed to call "
        "sts:AssumeRole on the role (a restricted permission set or a session policy can leave it out); "
        "where that is not allowed, use --sso-profile.",
    "AccessDeniedException": "See AccessDenied above.",
    "InvalidClientTokenId":
        "Your own credentials are invalid or expired. Refresh them and try again.",
    "ExpiredToken":
        "Your own credentials have expired. Refresh them and try again.",
    "RegionDisabledException":
        "STS is disabled in this Region for your account.",
}


def _refreshing_session(sts_client, assume_kwargs: Dict, first: Dict, region: str) -> boto3.Session:
    """A session whose credentials renew themselves shortly before they expire.

    A run over many accounts and Regions can outlast the one-hour life of an assumed role.  Without
    this, every call after the hour fails with ExpiredToken and reads as a coverage gap.  (A role
    reached by role chaining is capped at one hour by AWS, and a refresh asks STS again with the
    same caller, which is fine as long as the caller's own credentials are still valid.)"""
    def metadata(c: Dict) -> Dict:
        return {"access_key": c["AccessKeyId"], "secret_key": c["SecretAccessKey"],
                "token": c["SessionToken"], "expiry_time": c["Expiration"].isoformat()}

    def refresh() -> Dict:
        return metadata(sts_client.assume_role(**assume_kwargs)["Credentials"])

    bsession = botocore.session.get_session()
    bsession._credentials = botocore.credentials.RefreshableCredentials.create_from_metadata(
        metadata=metadata(first), refresh_using=refresh, method="sts-assume-role")
    return boto3.Session(botocore_session=bsession, region_name=region)


def assume_role(
    sts_client,
    account_id: str,
    role_name: str,
    external_id: str,
    region: str = "us-east-1",
    role_arn: Optional[str] = None,
    hint: bool = True,
) -> Optional[boto3.Session]:
    """
    Assume the collector role. Pass role_arn to override the account_id/role_name
    convention, which is what a single-account test normally wants.  hint=False leaves out the
    long explanation under the warning, for a caller that tries many accounts.
    """
    role_arn = role_arn or f"arn:aws:iam::{account_id}:role/{role_name}"
    kwargs = dict(
        RoleArn=role_arn,
        RoleSessionName=SESSION_NAME,
        DurationSeconds=3600,
    )
    if external_id:
        kwargs["ExternalId"] = external_id
    try:
        resp = sts_client.assume_role(**kwargs)
        creds = resp["Credentials"]
        if creds.get("Expiration") is None:
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
        return _refreshing_session(sts_client, kwargs, creds, region)
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        warn(f"Could not assume {role_arn}: {code}")
        record_gap("", "sts:AssumeRole", "AccessDenied" if code in _DENIED_CODES else f"Error:{code}",
                   account_id=account_id)
        explanation = ASSUME_HINTS.get(code)
        if not hint:
            pass
        elif explanation:
            warn(f"  -> {explanation}")
        elif code in ("NoSuchEntity", "ValidationError"):
            warn("  -> That role does not exist in this account. Deploy the "
                 "CloudFormation template there first, or check --role-name.")
        return None


# ── IAM Identity Center (no sts:AssumeRole) ─────────────────────────────────
# Some organizations do not let the person running the review call sts:AssumeRole across accounts.  IAM Identity Center
# already gives that person credentials in each account it is assigned to, through its access portal: the same way the
# AWS CLI does after `aws sso login`.  The collector asks the portal for the credentials of one permission set (the
# reviewer permission set the customer deploys from data_risk_assessment_permission_set.yaml) in every account where it is
# assigned, and reads each account with them.  The sign-in token and the credentials are kept in memory only, never
# written or printed.

SSO_TOKEN_CACHE_DIR = os.path.join("~", ".aws", "sso", "cache")


class SSOSignInError(Exception):
    """The profile gives no usable IAM Identity Center sign-in.  The message says what to do; it holds no secret."""


def sso_sign_in(session: boto3.Session) -> Tuple[Any, str]:
    """The access-portal client and the access token for the profile's IAM Identity Center sign-in."""
    bsession = session._session
    config = bsession.get_scoped_config()
    profile = session.profile_name or "default"
    login = f"Sign in first with: aws sso login --profile {profile}"
    sso_session_name = config.get("sso_session")
    token = None
    if sso_session_name:
        region = (bsession.full_config.get("sso_sessions", {}).get(sso_session_name) or {}).get("sso_region")
        try:
            auth = bsession.get_auth_token()
            token = auth.get_frozen_token().token if auth else None
        except Exception:                        # an expired or missing sign-in; the type says nothing more useful
            token = None
    else:
        region, start_url = config.get("sso_region"), config.get("sso_start_url")
        if not start_url:
            raise SSOSignInError(f"Profile {profile} is not an IAM Identity Center profile (it has no sso_session or "
                                 f"sso_start_url). Set one up with: aws configure sso --profile {profile}")
        try:
            cached = botocore.utils.SSOTokenLoader(
                botocore.utils.JSONFileCache(os.path.expanduser(SSO_TOKEN_CACHE_DIR)))(start_url)
            expires = botocore.utils.parse_timestamp(cached["expiresAt"])
            if expires > datetime.now(timezone.utc):
                token = cached["accessToken"]
        except Exception:
            token = None
    if not region:
        raise SSOSignInError(f"Profile {profile} has no sso_region. Set it up again with: aws configure sso --profile {profile}")
    if not token:
        raise SSOSignInError(f"There is no current IAM Identity Center sign-in for profile {profile}. {login}")
    portal = boto3.Session(region_name=region).client(
        "sso", config=BotocoreConfig(signature_version=botocore.UNSIGNED, retries={"max_attempts": 8, "mode": "adaptive"}))
    return portal, token


def _sso_role_session(portal, token: str, account_id: str, permission_set: str, region: str) -> boto3.Session:
    """A session with the permission set's credentials in one account, renewed from the portal before they expire."""
    def fetch() -> Dict:
        c = portal.get_role_credentials(roleName=permission_set, accountId=account_id, accessToken=token)["roleCredentials"]
        expiry = datetime.fromtimestamp(c["expiration"] / 1000.0, tz=timezone.utc)
        return {"access_key": c["accessKeyId"], "secret_key": c["secretAccessKey"],
                "token": c["sessionToken"], "expiry_time": expiry.isoformat()}

    bsession = botocore.session.get_session()
    bsession._credentials = botocore.credentials.RefreshableCredentials.create_from_metadata(
        metadata=fetch(), refresh_using=fetch, method="sso")
    return boto3.Session(botocore_session=bsession, region_name=region)


def sso_account_sessions(portal, token: str, permission_set: str,
                         region: str) -> Tuple[List[Dict], Dict[str, boto3.Session]]:
    """Every account the sign-in can open ({"Id", "Name"}), and a session in each one where `permission_set` is assigned.

    Raises SSOSignInError when the portal refuses the sign-in itself (expired or revoked)."""
    accounts: List[Dict] = []
    sessions: Dict[str, boto3.Session] = {}
    try:
        for page in portal.get_paginator("list_accounts").paginate(accessToken=token):
            for a in page.get("accountList", []):
                accounts.append({"Id": a["accountId"], "Name": a.get("accountName") or a["accountId"]})
    except botocore.exceptions.ClientError as e:
        if e.response.get("Error", {}).get("Code") == "UnauthorizedException":
            raise SSOSignInError("The IAM Identity Center sign-in has expired. Sign in again with aws sso login.")
        raise
    for acct in accounts:
        try:
            names = {r.get("roleName") for page in portal.get_paginator("list_account_roles").paginate(
                accessToken=token, accountId=acct["Id"]) for r in page.get("roleList", [])}
            if permission_set in names:
                sessions[acct["Id"]] = _sso_role_session(portal, token, acct["Id"], permission_set, region)
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            warn(f"Account {acct['Id']}: the access portal answered {code}")
            record_gap("", "sso:GetRoleCredentials", "AccessDenied" if code in _DENIED_CODES or code == "UnauthorizedException"
                       else f"Error:{code}", account_id=acct["Id"])
    return accounts, sessions


# ─────────────────────────────────────────────────────────────────────────────
# Coverage ledger
# ─────────────────────────────────────────────────────────────────────────────
# Every API call that fails for a reason that means "we do not know what is there"
# is recorded here, keyed by (account_id, region, api).  An unscanned region or a
# denied call must never read as "nothing found", so the report surfaces this.

# Codes that mean "the thing is not there", not "we could not look".
_BENIGN_CODES = frozenset({
    "NoSuchEntity", "ResourceNotFoundException", "NoSuchConfigurationRecorderException",
    "NoSuchBucket", "NotFoundException", "NoSuchTagSet",
    "ServerSideEncryptionConfigurationNotFoundError",
    # S3: the answer is "none configured", which is a finding, not a gap
    "NoSuchLifecycleConfiguration", "ReplicationConfigurationNotFoundError",
    "ObjectLockConfigurationNotFoundError", "NoSuchBucketPolicy",
})
_AWS_ERRORS = (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError)
_DENIED_CODES = frozenset({
    "AccessDenied", "AccessDeniedException", "UnauthorizedAccess",
    "UnauthorizedOperation", "AuthorizationError",
})

_LEDGER_LOCK = threading.Lock()
COVERAGE_LEDGER: Dict[Tuple[str, str, str], str] = {}
# Failures of a call made for one specific resource (a table, a bucket).  Kept apart so one
# denied bucket does not make every bucket in the Region "not assessed".
RESOURCE_GAPS: Dict[Tuple[str, str, str, str], str] = {}
_ledger_ctx = threading.local()


def reset_coverage_ledger() -> None:
    with _LEDGER_LOCK:
        COVERAGE_LEDGER.clear()
        RESOURCE_GAPS.clear()


def set_ledger_account(account_id: str) -> None:
    """Attribute subsequent ledger entries made on this thread to account_id."""
    _ledger_ctx.account_id = account_id


def record_gap(region: str, api: str, status: str, account_id: str = "", subject: str = "") -> None:
    """Record a call that could not be made.  subject (a resource ARN) scopes it to one resource."""
    account = account_id or getattr(_ledger_ctx, "account_id", "") or "unknown"
    with _LEDGER_LOCK:
        table = RESOURCE_GAPS if subject else COVERAGE_LEDGER
        key = (account, region, api, subject) if subject else (account, region, api)
        # A denial is the more useful fact; never downgrade it to a generic error.
        if table.get(key) != "AccessDenied":
            table[key] = status


def note_failure(exc: Exception, region: str, service: str, default_op: str,
                 subject: str = "", account_id: str = "") -> Optional[str]:
    """Record a failed call and return its status, or None when the failure is an answer
    (for example "no lifecycle configuration") and not a gap.  The operation name is taken
    from the exception when it has one, so the ledger names the call that actually failed."""
    status = _gap_status(exc)
    if status is None:
        return None
    op = default_op
    if isinstance(exc, botocore.exceptions.ClientError) and getattr(exc, "operation_name", None):
        op = xform_name(exc.operation_name)
    record_gap(region, f"{service}:{op}", status, account_id=account_id, subject=subject)
    return status


def coverage_gap_rows() -> List[Dict]:
    """Snapshot the ledger as sorted rows: account, region, api, subject, status."""
    with _LEDGER_LOCK:
        general = [(a, r, api, "", st) for (a, r, api), st in COVERAGE_LEDGER.items()]
        specific = [(a, r, api, sub, st) for (a, r, api, sub), st in RESOURCE_GAPS.items()]
    return [{"account_id": a, "region": r, "api": api, "subject": sub, "status": st}
            for a, r, api, sub, st in sorted(general + specific)]


def _gap_status(exc: Exception) -> Optional[str]:
    """Map an exception to a ledger status, or None when it is not a coverage gap."""
    if isinstance(exc, botocore.exceptions.ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        if code in _DENIED_CODES:
            return "AccessDenied"
        if code in _BENIGN_CODES:
            return None
        return f"Error:{code}"
    if isinstance(exc, botocore.exceptions.BotoCoreError):
        return f"Error:{type(exc).__name__}"
    return None


def _client_context(client) -> Tuple[str, str]:
    """(region, 'service') for a boto3 client, for ledger keys."""
    try:
        return client.meta.region_name or "", client.meta.service_model.service_name
    except AttributeError:
        return "", "unknown"


# Calls whose failure means we cannot conclude that a resource has no protection.
_BLOCKING_APIS = {
    "rds": {"rds:describe_db_instances", "rds:describe_db_clusters"},
    "dynamodb": {"dynamodb:list_tables", "dynamodb:describe_table", "dynamodb:describe_continuous_backups"},
    "ebs": {"ec2:describe_snapshots", "dlm:get_lifecycle_policies", "dlm:get_lifecycle_policy"},
    "s3": {"s3:list_buckets", "s3:get_bucket_versioning", "s3:get_bucket_lifecycle_configuration",
           "s3:get_bucket_replication"},
}
# AWS Backup could be protecting any resource, so its failures block every type in the Region.
_BACKUP_BLOCKING_APIS = {
    "backup:list_protected_resources", "backup:list_backup_plans", "backup:get_backup_plan",
    "backup:list_backup_selections", "backup:get_backup_selection", "backup:list_backup_jobs",
    "backup:list_backup_vaults", "backup:describe_backup_vault",
    "backup:list_recovery_points_by_backup_vault",
}


def _resource_category(res_type: str) -> Optional[str]:
    if res_type in RDS_CLUSTER_TYPES or res_type == RDS_DB_INSTANCE:
        return "rds"
    return {"AWS::DynamoDB::Table": "dynamodb", "AWS::EC2::Volume": "ebs",
            "AWS::S3::Bucket": "s3"}.get(res_type)


def ledger_snapshot() -> Dict[str, Any]:
    with _LEDGER_LOCK:
        return {"general": dict(COVERAGE_LEDGER), "specific": dict(RESOURCE_GAPS)}


# Worker labels (see parallel_map) whose unexpected failure means a Region's protection state is unknown.
# A Region whose native or AWS Backup read failed must not read as "nothing protects anything there".
_WORKER_BLOCKING = frozenset({"native", "backup", "config", "describe", "enrich"})
_WORKER_BLOCKING_S3 = frozenset({"s3-native", "s3-bucket"})


def assessment_blockers(resource: Dict, snapshot: Optional[Dict[str, Any]] = None) -> List[str]:
    """Failed calls that stop us saying anything about this resource's protection."""
    snap = snapshot or ledger_snapshot()
    account = resource.get("account_id", "") or resource.get("accountId", "")
    region = resource.get("awsRegion", "")
    arn = resource.get("arn", "")
    category = _resource_category(resource.get("resourceType", ""))
    found = set()
    for (acct, reg, api), status in snap["general"].items():
        if acct != account:
            continue
        if category and api in _BLOCKING_APIS[category] and (reg == region or category == "s3"):
            found.add(f"{api} ({status})")
        elif api in _BACKUP_BLOCKING_APIS and reg == region:
            found.add(f"{api} ({status})")
        elif api.startswith("worker:"):
            label = api.split(":", 1)[1]
            if (label in _WORKER_BLOCKING and reg == region) or (category == "s3" and label in _WORKER_BLOCKING_S3):
                found.add(f"{api} ({status})")
    for (acct, _reg, api, subject), status in snap["specific"].items():
        if acct == account and subject == arn:
            found.add(f"{api} ({status})")
    return sorted(found)


def paginate(client, method_name: str, result_key: str, **kwargs) -> List[Any]:
    """Generic paginator for any boto3 client method.

    Failures that mean "we could not look" (denied, timeout, endpoint unreachable) are
    recorded in the coverage ledger instead of silently producing an empty list.  Pass
    `_raise=True` where an empty list would be mistaken for an answer: the failure is then
    recorded and raised too, so the caller can tell "none" from "could not look".
    """
    results: List[Any] = []
    raise_after = kwargs.pop("_raise", False)
    method = getattr(client, method_name)
    kwargs.setdefault("PaginationConfig", {}).setdefault("MaxItems", 10_000)
    region, service = _client_context(client)
    api = f"{service}:{method_name}"
    try:
        paginator = client.get_paginator(method_name)
        for page in paginator.paginate(**{k: v for k, v in kwargs.items()
                                          if k != "PaginationConfig"}):
            results.extend(page.get(result_key, []))
    except (botocore.exceptions.OperationNotPageableError, AttributeError):
        try:
            resp = method(**{k: v for k, v in kwargs.items()
                             if k != "PaginationConfig"})
            results = resp.get(result_key, [])
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            status = _gap_status(e)
            if status:
                record_gap(region, api, status)
            if raise_after:
                raise
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        status = _gap_status(e)
        if status:
            record_gap(region, api, status)
        if status and status != "AccessDenied":
            warn(f"paginate {method_name}: {status.split(':', 1)[-1]}")
        if raise_after:
            raise
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Parallelism
# ─────────────────────────────────────────────────────────────────────────────
# Regions are independent, and so are the per-bucket and per-table calls inside one, so they run
# concurrently.  boto3's session.client() is not safe to call from several threads at once (it
# lazily loads shared service data), so creating a client is serialised; the API calls made through
# it run in parallel.
REGION_WORKERS = 4        # Regions scanned at once within one account
ITEM_WORKERS = 8          # buckets or tables handled at once within one Region
_CLIENT_LOCK = threading.Lock()


def set_parallelism(region_workers: int, item_workers: int) -> None:
    global REGION_WORKERS, ITEM_WORKERS
    REGION_WORKERS, ITEM_WORKERS = max(1, region_workers), max(1, item_workers)


def make_client(session, service: str, region: Optional[str] = None, config=_RETRY_CONFIG):
    with _CLIENT_LOCK:
        return session.client(service, region_name=region, config=config)


def client_for(session: boto3.Session, service: str, region: str):
    return make_client(session, service, region)


class S3Clients:
    """S3 clients by Region, created once each.

    A bucket answers fastest through its own Region's endpoint; asked through us-east-1, S3 sends a redirect
    and the call is made twice.  The bucket's Region comes from GetBucketLocation, which any endpoint answers."""

    def __init__(self, session):
        self.session = session
        self._clients: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def get(self, region: Optional[str] = "us-east-1"):
        region = region if region and region != "global" else "us-east-1"
        with self._lock:
            if region not in self._clients:
                self._clients[region] = make_client(self.session, "s3", region)
            return self._clients[region]

    def for_bucket(self, name: str):
        """(client in the bucket's own Region, that Region).  Falls back to us-east-1 when the Region cannot be read."""
        try:
            region = _bucket_region(self.get().get_bucket_location(Bucket=name).get("LocationConstraint"))
        except _AWS_ERRORS as e:
            note_failure(e, "us-east-1", "s3", "get_bucket_location", subject=f"arn:aws:s3:::{name}")
            return self.get(), "global"
        return self.get(region), region


def _guarded(fn, item, label: str):
    try:
        return fn(item)
    except Exception as e:      # noqa: BLE001 - one bad Region or bucket must not lose all the others
        record_gap(item if isinstance(item, str) else "", f"worker:{label}", f"Error:{type(e).__name__}")
        warn(f"{label} failed for one item ({type(e).__name__}); it is listed under Coverage gaps")
        return None


def parallel_map(fn, items, workers: int, label: str = "task") -> List[Any]:
    """fn(item) for every item, concurrently, with results in the order of items.

    An unexpected error in one item is recorded as a coverage gap and gives None for that item; it
    does not stop the rest.  With one worker, or one item, it runs inline."""
    items = list(items)
    if workers <= 1 or len(items) <= 1:
        return [_guarded(fn, item, label) for item in items]
    account = getattr(_ledger_ctx, "account_id", "")

    def run(item):
        set_ledger_account(account)          # worker threads do not inherit the caller's context
        return _guarded(fn, item, label)

    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as pool:
        return list(pool.map(run, items))


# ─────────────────────────────────────────────────────────────────────────────
# Organization discovery
# ─────────────────────────────────────────────────────────────────────────────

def organization_reachable(session: boto3.Session) -> bool:
    """False only when AWS says this identity cannot list an organization (denied, no organization, or no accounts at all,
    which a real organization never returns since it holds the management account).  Any other failure returns True, so the
    organization path runs and reports it, and an organization is never quietly read as one account."""
    try:
        return bool(session.client("organizations").list_accounts(MaxResults=1).get("Accounts"))
    except botocore.exceptions.ClientError as e:
        return e.response.get("Error", {}).get("Code") not in ("AccessDeniedException", "AWSOrganizationsNotInUseException")
    except botocore.exceptions.BotoCoreError:
        return True


def get_org_accounts(mgmt_session: boto3.Session) -> List[Dict]:
    """Return all ACTIVE accounts with their OU path."""
    org = mgmt_session.client("organizations")
    accounts = paginate(org, "list_accounts", "Accounts")
    active = [a for a in accounts if a.get("Status") == "ACTIVE"]
    # Attach OU name for each account
    roots = paginate(org, "list_roots", "Roots")
    root_id = roots[0]["Id"] if roots else None
    ou_map: Dict[str, str] = {}
    ou_paths: Dict[str, str] = {}
    ou_chains: Dict[str, List[str]] = {}
    if root_id:
        _build_ou_map(org, root_id, "Root", ou_map, ou_paths, "", ou_chains)
    for acct in active:
        # Find parent OU
        try:
            parents = org.list_parents(ChildId=acct["Id"])["Parents"]
            if parents:
                parent_id = parents[0]["Id"]
                acct["OUName"] = ou_map.get(parent_id, parent_id)
                acct["OUPath"] = ou_paths.get(parent_id, acct["OUName"])
                # Every id above the account, root first.  An SCP attached to any of them applies to the account.
                acct["OUChain"] = ou_chains.get(parent_id, [parent_id])
            else:
                acct["OUName"] = "Root"
                acct["OUPath"] = "Root"
                acct["OUChain"] = [root_id] if root_id else []
        except botocore.exceptions.ClientError:
            acct["OUName"] = "Unknown"
            acct["OUPath"] = "Unknown"
            acct["OUChain"] = []
    return active


def _build_ou_map(org, parent_id: str, parent_name: str, ou_map: Dict[str, str],
                  ou_paths: Optional[Dict[str, str]] = None, parent_path: str = "",
                  ou_chains: Optional[Dict[str, List[str]]] = None, parent_chain: Optional[List[str]] = None):
    """ou_map: OU id -> its own name.  ou_paths: OU id -> the full path from the root.
    ou_chains: OU id -> the ids from the root down to and including it."""
    path = f"{parent_path}/{parent_name}" if parent_path else parent_name
    chain = (parent_chain or []) + [parent_id]
    ou_map[parent_id] = parent_name
    if ou_paths is not None:
        ou_paths[parent_id] = path
    if ou_chains is not None:
        ou_chains[parent_id] = chain
    try:
        children = paginate(org, "list_organizational_units_for_parent",
                            "OrganizationalUnits", ParentId=parent_id)
        for child in children:
            _build_ou_map(org, child["Id"], child["Name"], ou_map, ou_paths, path, ou_chains, chain)
    except botocore.exceptions.ClientError:
        pass


def get_org_info(mgmt_session: boto3.Session) -> Dict:
    try:
        resp = mgmt_session.client("organizations").describe_organization()
        return resp.get("Organization", {})
    except _AWS_ERRORS as e:
        note_failure(e, "us-east-1", "organizations", "describe_organization")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Resource inventory
# ─────────────────────────────────────────────────────────────────────────────

# Discovery sources in order of preference when the same ARN is found more than once.
# Config carries the richest metadata, Resource Explorer next, plain describe calls last.
_SOURCE_RANK = {"config": 0, "resource-explorer": 1, "describe": 2}


def collect_resources(
    session: boto3.Session,
    account_id: str,
    regions: List[str],
) -> List[Dict]:
    """
    Discover data-bearing resources and return one record per ARN.

    Sources are layered, cheapest and richest first, and each later source only fills the
    regions the earlier ones did not cover:
      1. AWS Config: the org aggregator, then each region's own recorder.
      2. Resource Explorer.
      3. Per-service Describe calls.
    S3 is global, so it is listed once per account rather than once per region.
    """
    resources: List[Dict] = []
    covered: set = set()

    cfg_resources, cfg_covered = _try_config(session, account_id, regions)
    if cfg_resources or cfg_covered:
        log(f"  {account_id}: {len(cfg_resources)} resources via AWS Config "
            f"({len(cfg_covered)} Region(s) covered)")
    resources += cfg_resources
    covered |= cfg_covered

    uncovered = [r for r in regions if r not in covered]
    if uncovered:
        re_resources = _try_resource_explorer(session, account_id)
        if re_resources:
            log(f"  {account_id}: {len(re_resources)} resources via Resource Explorer")
        scanned = set(regions)
        # Resource Explorer returns S3 buckets with no Region in the ARN; those pass through
        # and are placed by the S3 pass below.
        for r in re_resources:
            region = r.get("awsRegion", "")
            if region in uncovered or (region == "" and r.get("resourceType") == "AWS::S3::Bucket"):
                resources.append(r)
        covered |= {r.get("awsRegion") for r in re_resources if r.get("awsRegion") in scanned}
        uncovered = [r for r in regions if r not in covered]

    if uncovered:
        log(f"  {account_id}: supplementing with describe calls for {', '.join(uncovered)}")
        resources += _describe_resources(session, account_id, uncovered)

    resources += _describe_s3(session, account_id)

    resources = _enrich_resources(resources, session, account_id, regions)
    return _dedupe_by_arn(resources)


def _config_region_state(config) -> Tuple[bool, bool]:
    """(recording, records_every_allowlisted_type) for a region's Config recorder."""
    recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if not recorders:
        return False, False
    status = config.describe_configuration_recorder_status().get(
        "ConfigurationRecordersStatus", [])
    recording = any(st.get("recording") for st in status)
    group = recorders[0].get("recordingGroup", {}) or {}
    wanted = set(_CONFIG_TYPE_SET)
    if group.get("allSupported"):
        complete = True
    elif (group.get("recordingStrategy") or {}).get("useOnly") == "EXCLUSION_BY_RESOURCE_TYPES":
        excluded = set((group.get("exclusionByResourceTypes") or {}).get("resourceTypes", []))
        complete = not (wanted & excluded)
    else:
        complete = wanted <= set(group.get("resourceTypes", []))
    return recording, recording and complete


# The only parts of a Config record the collector reads.  Asking for whole `configuration` and
# `supplementaryConfiguration` documents would pull in far more than needed: for S3 the latter holds the
# bucket policy and ACL, and an RDS instance's holds its endpoint, master username and more.  Config's
# query language selects nested fields, so only these come back.
CONFIG_FIELDS_USED = (
    "configuration.engine", "configuration.allocatedStorage", "configuration.dBClusterIdentifier",
    "configuration.size", "configuration.attachments",
)


def _config_query(types: set, with_created: bool = True) -> str:
    type_list = ", ".join(f"'{t}'" for t in sorted(types))
    created = ", resourceCreationTime" if with_created else ""
    return (
        "SELECT resourceId, resourceType, resourceName, awsRegion, accountId, arn, tags"
        + created + ", " + ", ".join(CONFIG_FIELDS_USED)
        + f" WHERE resourceType IN ({type_list})"
    )


def _config_select(call, types: set, suffix: str = "", **kwargs) -> List[Dict]:
    """Run the inventory query.  If Config rejects the creation-time field, run it again without,
    so a field that one Config endpoint does not accept costs the creation date and nothing else."""
    try:
        return _config_run(call, Expression=_config_query(types) + suffix, **kwargs)
    except botocore.exceptions.ClientError as e:
        if e.response.get("Error", {}).get("Code") != "InvalidExpressionException":
            raise
    return _config_run(call, Expression=_config_query(types, with_created=False) + suffix, **kwargs)


def _config_run(call, **kwargs) -> List[Dict]:
    """Run a Config select_* call to completion and parse the JSON rows."""
    results: List[Dict] = []
    token = None
    while True:
        if token:
            kwargs["NextToken"] = token
        resp = call(**kwargs)
        for item in resp.get("Results", []):
            try:
                results.append(json.loads(item))
            except json.JSONDecodeError:
                pass
        token = resp.get("NextToken")
        if not token:
            return results


def _try_config(
    session: boto3.Session, account_id: str, regions: List[str]
) -> Tuple[List[Dict], set]:
    """Resources recorded by AWS Config, and the Regions that Config fully covers.

    1. The org aggregator in us-east-1, when this account can use one.
    2. For each Region the aggregator did not return anything for, that Region's own
       recorder (this is the only path for a member account).  A Region counts as
       covered only when its recorder is recording every allowlisted type, so a recorder
       that omits RDS cannot hide RDS resources.
    """
    out: List[Dict] = []
    covered: set = set()
    wanted_regions = set(regions)

    try:
        config = make_client(session, "config", "us-east-1")
        aggregators = config.describe_configuration_aggregators().get(
            "ConfigurationAggregators", [])
        if aggregators:
            rows = _config_select(
                config.select_aggregate_resource_config, set(_CONFIG_TYPE_SET),
                suffix=f" AND accountId = '{account_id}'",
                ConfigurationAggregatorName=aggregators[0]["ConfigurationAggregatorName"],
                Limit=100)
            for r in rows:
                region = r.get("awsRegion", "")
                # S3 listing is account-wide; every other type is limited to scanned Regions.
                if region in wanted_regions or r.get("resourceType") == "AWS::S3::Bucket":
                    r["discovery_source"] = "config"
                    out.append(r)
                if region in wanted_regions:
                    covered.add(region)
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        status = _gap_status(e)
        if status:
            record_gap("us-east-1", "config:select_aggregate_resource_config", status)

    def read_region(region: str):
        try:
            config = make_client(session, "config", region)
            recording, complete = _config_region_state(config)
            if not complete:
                return None
            rows = _config_select(config.select_resource_config, set(_CONFIG_TYPE_SET), Limit=100)
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            status = _gap_status(e)
            if status:
                record_gap(region, "config:select_resource_config", status)
            return None
        for r in rows:
            r.setdefault("awsRegion", region)
            r["discovery_source"] = "config"
        return rows

    pending = [region for region in regions if region not in covered]
    for region, rows in zip(pending, parallel_map(read_region, pending, REGION_WORKERS, "config")):
        if rows is None:
            continue
        out.extend(rows)
        covered.add(region)
    return out, covered


def _resource_explorer_regions(session: boto3.Session) -> List[str]:
    """The Regions to search: the one holding the aggregator index if there is one (it sees every Region), otherwise each Region
    with a local index.  Falls back to us-east-1 when the indexes cannot be listed."""
    try:
        client = make_client(session, "resource-explorer-2", "us-east-1", config=None)
        indexes = paginate(client, "list_indexes", "Indexes", _raise=True)
    except _AWS_ERRORS:
        return ["us-east-1"]                      # the failure is already recorded
    aggregators = [i["Region"] for i in indexes if i.get("Type") == "AGGREGATOR" and i.get("Region")]
    if aggregators:
        return aggregators[:1]
    local = sorted({i["Region"] for i in indexes if i.get("Region")})
    return local or ["us-east-1"]


def _try_resource_explorer(session: boto3.Session, account_id: str) -> List[Dict]:
    """Query Resource Explorer per allowlisted type.

    Uses per-type queries so each stays well under the 1,000-result cap of the Search
    API.  Results are mapped to canonical AWS::Service::Type names through
    _RE2_TYPE_MAP.  Neptune and DocumentDB share the rds:db / rds:cluster types and are
    kept; they are told apart later by Engine.  The search runs in the Region that holds the aggregator index (or in each
    Region with its own index), not always us-east-1, because an index elsewhere would otherwise be missed.
    """
    all_items: List[Dict] = []
    for search_region in _resource_explorer_regions(session):
        try:
            re2 = make_client(session, "resource-explorer-2", search_region, config=None)
            for canonical_type, mapping in ALLOWLISTED_TYPES.items():
                query = f"resourcetype:{mapping['re2']} accountid:{account_id}"
                for item in paginate(re2, "search", "Resources", QueryString=query):
                    r = _re2_to_resource(item)
                    r["resourceType"] = canonical_type
                    all_items.append(r)
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            status = _gap_status(e)
            if status:
                record_gap(search_region, "resource-explorer-2:search", status)
    return all_items


def _re2_tags(props: list) -> dict:
    """Extract tags from Resource Explorer v2 Properties array.

    RE2 returns tags as a named property:
      [{"Name": "tags", "Data": {"key1": "val1", "key2": "val2"}, ...}, ...]
    Data is a plain dict, not a list of Key/Value objects.
    """
    for prop in props:
        if not isinstance(prop, dict):
            continue
        if prop.get("Name") == "tags":
            data = prop.get("Data", {})
            if isinstance(data, dict):
                return data
            # Fallback: some older RE2 responses use list format
            if isinstance(data, list):
                return {t["Key"]: t["Value"] for t in data
                        if isinstance(t, dict) and "Key" in t}
    return {}


def _re2_to_resource(item: Dict) -> Dict:
    arn = item.get("Arn", "")
    parts = arn.split(":")
    return {
        "resourceId": item.get("Id", arn),
        "resourceType": item.get("ResourceType", ""),
        "resourceName": _name_from_arn(arn),
        "awsRegion": parts[3] if len(parts) > 3 else "",
        "tags": _re2_tags(item.get("Properties") or []),
        "arn": arn,
        "discovery_source": "resource-explorer",
    }


def _describe_resources(
    session: boto3.Session, account_id: str, regions: List[str]
) -> List[Dict]:
    """Fallback: call Describe* for each supported service in each region."""
    def one_region(region: str) -> List[Dict]:
        return (_describe_rds(session, account_id, region)
                + _describe_dynamodb(session, account_id, region)
                + _describe_ebs(session, account_id, region))

    resources: List[Dict] = []
    for part in parallel_map(one_region, regions, REGION_WORKERS, "describe"):
        resources += part or []
    return resources


def _describe_rds(session, account_id, region) -> List[Dict]:
    rds = client_for(session, "rds", region)
    out = []
    for inst in paginate(rds, "describe_db_instances", "DBInstances"):
        out.append(_make_resource(
            account_id, region, "AWS::RDS::DBInstance",
            inst["DBInstanceIdentifier"],
            inst.get("TagList", []),
            arn=inst.get("DBInstanceArn", ""),
            meta={"Engine": inst.get("Engine", ""),
                  "SizeGiB": inst.get("AllocatedStorage", 0),
                  "ClusterId": inst.get("DBClusterIdentifier", ""),
                  "CreatedAt": _iso(inst.get("InstanceCreateTime"))},
        ))
    for cluster in paginate(rds, "describe_db_clusters", "DBClusters"):
        out.append(_make_resource(
            account_id, region, "AWS::RDS::DBCluster",
            cluster["DBClusterIdentifier"],
            cluster.get("TagList", []),
            arn=cluster.get("DBClusterArn", ""),
            meta={"Engine": cluster.get("Engine", ""), "SizeGiB": 0,
                  "CreatedAt": _iso(cluster.get("ClusterCreateTime"))},
        ))
    return out


def _describe_dynamodb(session, account_id, region) -> List[Dict]:
    ddb = client_for(session, "dynamodb", region)
    out = []
    for tname in paginate(ddb, "list_tables", "TableNames"):
        try:
            desc = ddb.describe_table(TableName=tname)["Table"]
            tags_resp = ddb.list_tags_of_resource(ResourceArn=desc.get("TableArn", ""))
            size_bytes = desc.get("TableSizeBytes", 0)
            out.append(_make_resource(
                account_id, region, "AWS::DynamoDB::Table", tname,
                tags_resp.get("Tags", []),
                arn=desc.get("TableArn", ""),
                meta={"SizeGiB": size_bytes / (1024 ** 3),
                      "TableFormat": desc.get("TableClassSummary", {}).get("TableClass", "STANDARD"),
                      "CreatedAt": _iso(desc.get("CreationDateTime"))},
            ))
        except _AWS_ERRORS as e:
            note_failure(e, region, "dynamodb", "describe_table",
                         subject=f"arn:aws:dynamodb:{region}:{account_id}:table/{tname}")
    return out


def _describe_ebs(session, account_id, region) -> List[Dict]:
    ec2 = client_for(session, "ec2", region)
    out = []
    for vol in paginate(ec2, "describe_volumes", "Volumes"):
        out.append(_make_resource(
            account_id, region, "AWS::EC2::Volume",
            vol["VolumeId"],
            vol.get("Tags", []),
            arn=f"arn:aws:ec2:{region}:{account_id}:volume/{vol['VolumeId']}",
            meta={"SizeGiB": vol.get("Size", 0),
                  "AttachedInstance": _attached_instance(vol),
                  "CreatedAt": _iso(vol.get("CreateTime")),
                  "VolumeType": str(vol.get("VolumeType") or ""),
                  "Iops": int(vol.get("Iops") or 0), "Throughput": int(vol.get("Throughput") or 0)},
        ))
    return out


def _bucket_region(location_constraint: Optional[str]) -> str:
    """GetBucketLocation returns None for us-east-1 and 'EU' for the legacy eu-west-1."""
    if not location_constraint:
        return "us-east-1"
    return "eu-west-1" if location_constraint == "EU" else location_constraint


def _describe_s3(session, account_id) -> List[Dict]:
    """List every bucket in the account once.

    ListBuckets is global, so this runs once per account, not once per scanned Region.
    Each bucket is placed in its own Region through GetBucketLocation.
    """
    clients = S3Clients(session)
    s3 = clients.get()
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        status = _gap_status(e)
        if status:
            record_gap("us-east-1", "s3:list_buckets", status)
        return []

    def describe_bucket(b: Dict) -> Dict:
        name = b["Name"]
        tags: Dict = {}
        bucket_s3, region = clients.for_bucket(name)
        try:
            tags = {t["Key"]: t["Value"]
                    for t in bucket_s3.get_bucket_tagging(Bucket=name).get("TagSet", [])}
        except _AWS_ERRORS as e:
            note_failure(e, "us-east-1", "s3", "get_bucket_tagging", subject=f"arn:aws:s3:::{name}")
        return _make_resource(
            account_id, region, "AWS::S3::Bucket", name,
            [{"Key": k, "Value": v} for k, v in tags.items()],
            arn=f"arn:aws:s3:::{name}",
            meta={"SizeGiB": 0, "CreatedAt": _iso(b.get("CreationDate"))},
        )

    return [r for r in parallel_map(describe_bucket, buckets, ITEM_WORKERS, "s3-bucket") if r]


def _make_resource(
    account_id: str,
    region: str,
    res_type: str,
    name: str,
    tag_list: List[Dict],
    arn: str = "",
    meta: Optional[Dict] = None,
) -> Dict:
    tags = {}
    for t in tag_list:
        if isinstance(t, dict):
            key = t.get("Key") or t.get("key", "")
            val = t.get("Value") or t.get("value", "")
            if key:
                tags[key] = val
    return {
        "resourceId": name,
        "resourceType": res_type,
        "resourceName": name,
        "awsRegion": region,
        "accountId": account_id,
        "arn": arn,
        "tags": tags,
        "meta": meta or {},
        "discovery_source": "describe",
    }


def _attached_instance(volume: Dict) -> str:
    """Instance ID an EBS volume is attached to, or "" when unattached."""
    for att in volume.get("Attachments") or []:
        inst = att.get("InstanceId") if isinstance(att, dict) else ""
        if inst:
            return inst
    return ""


def classify_rds_type(res_type: str, engine: str) -> str:
    """Remap a discovery-time RDS cluster type to its engine family.

    Config and Resource Explorer report Aurora, Neptune and DocumentDB clusters all
    as AWS::RDS::DBCluster.  Only the Engine tells them apart.  Instances and
    non-cluster types pass through unchanged.
    """
    if res_type not in RDS_CLUSTER_TYPES:
        return res_type
    eng = (engine or "").lower()
    if eng.startswith("aurora"):
        return RDS_AURORA
    if eng == "neptune":
        return RDS_NEPTUNE
    if eng == "docdb":
        return RDS_DOCDB
    return RDS_DB_CLUSTER


def _config_blob(value: Any) -> Dict:
    """Config returns configuration / supplementaryConfiguration as an object or a string."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip().startswith("{"):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _ci_get(blob: Dict, *names: str) -> Any:
    """Case-insensitive key lookup.  Config's casing differs between resource types."""
    lowered = {str(k).lower(): v for k, v in blob.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _to_number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _iso(value: Any) -> str:
    """A boto datetime or an ISO string as an ISO string; anything else as ''."""
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()
    if isinstance(value, str) and value:
        return _as_dt(value).isoformat() if _as_dt(value).year > 1 else ""
    return ""


def _meta_from_config(r: Dict) -> Dict:
    """Pull Engine / size / attachment out of the fields _config_query asks Config for.

    DynamoDB and S3 records carry none of them (Config has no table size), so their size comes from
    the describe overlay in _enrich_resources."""
    meta: Dict = {}
    created = _iso(r.get("resourceCreationTime"))
    if created:
        meta["CreatedAt"] = created
    cfg = _config_blob(r.get("configuration"))
    if not cfg:
        return meta
    rtype = r.get("resourceType", "")
    if rtype in RDS_CLUSTER_TYPES or rtype == RDS_DB_INSTANCE:
        engine = _ci_get(cfg, "engine")
        if engine:
            meta["Engine"] = str(engine)
        if rtype == RDS_DB_INSTANCE:
            meta["ClusterId"] = str(_ci_get(cfg, "dbClusterIdentifier") or "")
            size = _to_number(_ci_get(cfg, "allocatedStorage"))
            if size:
                meta["SizeGiB"] = size
    elif rtype == "AWS::EC2::Volume":
        size = _to_number(_ci_get(cfg, "size"))
        if size:
            meta["SizeGiB"] = size
        attachments = _ci_get(cfg, "attachments") or []
        inst = ""
        for att in attachments if isinstance(attachments, list) else []:
            if isinstance(att, dict):
                inst = _ci_get(att, "instanceId") or ""
                if inst:
                    break
        meta["AttachedInstance"] = inst
    return meta


def _fill_meta(r: Dict, extra: Dict) -> None:
    """Add keys from extra to r['meta'] without overwriting a populated value."""
    meta = r.setdefault("meta", {})
    for k, v in extra.items():
        if meta.get(k) in (None, "", 0) and v not in (None, ""):
            meta[k] = v
        elif k not in meta:
            meta[k] = v


def _usable_region(region: str) -> bool:
    return bool(region) and region != "global"


def _enrich_resources(
    resources: List[Dict],
    session: boto3.Session,
    account_id: str,
    regions: List[str],
) -> List[Dict]:
    """Normalise Config/RE2 records and fill the fields they lack.

    Config and Resource Explorer return identifiers and tags, not engine, size or
    attachment.  Those come from the Config configuration blob when present, and
    otherwise from one describe call per (service, region) that actually has such
    resources, overlaid by ARN.  Finally RDS clusters are remapped by Engine.
    """
    for r in resources:
        r.setdefault("accountId", account_id)
        r.setdefault("arn", "")
        r.setdefault("meta", {})
        if isinstance(r.get("tags"), list):
            r["tags"] = {t.get("key", t.get("Key", "")): t.get("value", t.get("Value", ""))
                         for t in r["tags"] if isinstance(t, dict)}
        _fill_meta(r, _meta_from_config(r))

    needs: Dict[str, set] = {"rds": set(), "ebs": set(), "ddb": set()}
    for r in resources:
        region, rtype, meta = r.get("awsRegion", ""), r.get("resourceType", ""), r["meta"]
        if not _usable_region(region):
            continue
        if (rtype in RDS_CLUSTER_TYPES or rtype == RDS_DB_INSTANCE) and (
                not meta.get("Engine") or "CreatedAt" not in meta):
            needs["rds"].add(region)
        elif rtype == "AWS::EC2::Volume" and ("AttachedInstance" not in meta or "CreatedAt" not in meta):
            needs["ebs"].add(region)
        elif rtype == "AWS::DynamoDB::Table" and ("SizeGiB" not in meta or "CreatedAt" not in meta):
            needs["ddb"].add(region)

    # One describe call per (service, Region) that has resources lacking the fields, all at once.
    jobs = [(fn, region) for kind, fn in (("rds", _describe_rds), ("ebs", _describe_ebs),
                                          ("ddb", _describe_dynamodb)) for region in sorted(needs[kind])]
    described: Dict[str, Dict] = {}
    for found in parallel_map(lambda job: job[0](session, account_id, job[1]), jobs, REGION_WORKERS, "enrich"):
        for d in found or []:
            if d.get("arn"):
                described[d["arn"]] = d
    if described:
        for r in resources:
            d = described.get(r.get("arn", ""))
            if d:
                _fill_meta(r, d.get("meta", {}))

    for r in resources:
        r["resourceType"] = classify_rds_type(r.get("resourceType", ""),
                                               r["meta"].get("Engine", ""))
    return resources


def _dedupe_by_arn(resources: List[Dict]) -> List[Dict]:
    """One record per ARN.

    The same resource is often found by more than one path (Config and a describe call,
    or Resource Explorer and a describe call).  Keep the record from the richest source
    and fill whatever it lacks (tags, Region, size, engine) from the others.  Records
    with no ARN cannot be matched and are kept as they are.
    """
    groups: Dict[str, List[Dict]] = {}
    order: List[Any] = []
    for r in resources:
        arn = r.get("arn", "")
        if not arn:
            order.append(r)
            continue
        if arn not in groups:
            groups[arn] = []
            order.append(arn)
        groups[arn].append(r)

    out: List[Dict] = []
    for item in order:
        if not isinstance(item, str):
            out.append(item)
            continue
        recs = sorted(groups[item], key=lambda r: _SOURCE_RANK.get(r.get("discovery_source"), 9))
        best = recs[0]
        for other in recs[1:]:
            if not _usable_region(best.get("awsRegion", "")) and _usable_region(other.get("awsRegion", "")):
                best["awsRegion"] = other["awsRegion"]
            if not best.get("tags") and other.get("tags"):
                best["tags"] = other["tags"]
            _fill_meta(best, other.get("meta", {}))
        out.append(best)
    return out


def _name_from_arn(arn: str) -> str:
    if not arn:
        return ""
    parts = arn.split(":")
    return parts[-1].split("/")[-1]


# ─────────────────────────────────────────────────────────────────────────────
# Application grouping
# ─────────────────────────────────────────────────────────────────────────────

def get_application_groups(
    session: boto3.Session,
    account_id: str,
    regions: List[str],
    all_resources: List[Dict],
) -> List[Dict]:
    groups: List[Dict] = []
    groups += _appregistry_groups(session, account_id, regions)
    groups += _cfn_stack_groups(session, account_id, regions)
    groups += _ecs_groups(session, account_id, regions)
    groups += _eks_groups(session, account_id, regions)
    groups += _tag_groups(all_resources, account_id)
    groups += _naming_prefix_groups(all_resources, account_id)
    return groups


def _appregistry_groups(
    session: boto3.Session, account_id: str, regions: List[str]
) -> List[Dict]:
    """AppRegistry applications are regional, so ask every scanned region."""
    def one_region(region: str) -> List[Dict]:
        groups: List[Dict] = []
        try:
            sar = client_for(session, "servicecatalog-appregistry", region)
            apps = paginate(sar, "list_applications", "Applications")
            for app in apps:
                try:
                    res = paginate(sar, "list_associated_resources", "Resources",
                                   Application=app["Id"])
                    groups.append({
                        "name": app.get("DisplayName") or app.get("Name", app["Id"]),
                        "grouping_method": "AppRegistry",
                        "grouping_confidence": "high",
                        "account_id": account_id,
                        "region": region,
                        "resource_ids": [r.get("Arn", r.get("Name", "")) for r in res],
                    })
                except botocore.exceptions.ClientError:
                    pass
        except botocore.exceptions.ClientError:
            pass
        return groups

    return [g for part in parallel_map(one_region, regions, REGION_WORKERS, "groups-appregistry")
            for g in (part or [])]


def _cfn_stack_groups(
    session: boto3.Session, account_id: str, regions: List[str]
) -> List[Dict]:
    def one_region(region: str) -> List[Dict]:
        groups: List[Dict] = []
        try:
            cf = client_for(session, "cloudformation", region)
            stacks = paginate(cf, "list_stacks", "StackSummaries",
                              StackStatusFilter=["CREATE_COMPLETE", "UPDATE_COMPLETE",
                                                 "ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"])
            for stack in stacks:
                if stack.get("RootId"):   # skip nested
                    continue
                name = stack["StackName"]
                try:
                    res = paginate(cf, "list_stack_resources", "StackResourceSummaries",
                                   StackName=name)
                    groups.append({
                        "name": name,
                        "grouping_method": "CloudFormation",
                        "grouping_confidence": "high",
                        "account_id": account_id,
                        "resource_ids": [r["PhysicalResourceId"] for r in res
                                         if r.get("PhysicalResourceId")],
                    })
                except botocore.exceptions.ClientError:
                    pass
        except botocore.exceptions.ClientError:
            pass
        return groups

    return [g for part in parallel_map(one_region, regions, REGION_WORKERS, "groups-cloudformation")
            for g in (part or [])]


def _ecs_groups(
    session: boto3.Session, account_id: str, regions: List[str]
) -> List[Dict]:
    """Group resources by ECS cluster. Listed in the appendix as an authoritative
    grouping source alongside AppRegistry and CloudFormation."""
    def one_region(region: str) -> List[Dict]:
        groups: List[Dict] = []
        try:
            ecs = client_for(session, "ecs", region)
            cluster_arns = paginate(ecs, "list_clusters", "clusterArns")
            for cluster_arn in cluster_arns:
                cluster_name = cluster_arn.split("/")[-1]
                try:
                    service_arns = paginate(ecs, "list_services", "serviceArns",
                                            cluster=cluster_arn)
                    if service_arns:
                        groups.append({
                            "name": cluster_name,
                            "grouping_method": "ECS Cluster",
                            "grouping_confidence": "high",
                            "account_id": account_id,
                            "resource_ids": service_arns,
                        })
                except botocore.exceptions.ClientError:
                    pass
        except botocore.exceptions.ClientError:
            pass
        return groups

    return [g for part in parallel_map(one_region, regions, REGION_WORKERS, "groups-ecs")
            for g in (part or [])]


def _eks_groups(
    session: boto3.Session, account_id: str, regions: List[str]
) -> List[Dict]:
    """Group resources by EKS cluster. Listed in the appendix as an authoritative
    grouping source."""
    def one_region(region: str) -> List[Dict]:
        groups: List[Dict] = []
        try:
            eks = client_for(session, "eks", region)
            cluster_names = paginate(eks, "list_clusters", "clusters")
            for cluster_name in cluster_names:
                groups.append({
                    "name": cluster_name,
                    "grouping_method": "EKS Cluster",
                    "grouping_confidence": "high",
                    "account_id": account_id,
                    "resource_ids": [
                        f"arn:aws:eks:{region}:{account_id}:cluster/{cluster_name}"
                    ],
                })
        except botocore.exceptions.ClientError:
            pass
        return groups

    return [g for part in parallel_map(one_region, regions, REGION_WORKERS, "groups-eks")
            for g in (part or [])]


def _tag_groups(resources: List[Dict], account_id: str) -> List[Dict]:
    tag_keys = ["Application", "application", "app", "App",
                "Service", "service", "Project", "project", "Team", "team"]
    buckets: Dict[str, List[str]] = {}
    for r in resources:
        if r.get("accountId") != account_id:
            continue
        tags = r.get("tags", {})
        for key in tag_keys:
            val = tags.get(key)
            if val:
                buckets.setdefault(val, []).append(
                    r.get("arn") or r.get("resourceId", "")
                )
                break
    return [
        {"name": name,
         "grouping_method": "Application tag",
         "grouping_confidence": "medium",
         "account_id": account_id,
         "resource_ids": ids}
        for name, ids in buckets.items()
        if len(ids) >= 2
    ]


def _naming_prefix_groups(resources: List[Dict], account_id: str) -> List[Dict]:
    """Cluster resources by common naming prefix (2+ word tokens)."""
    from collections import Counter
    prefixes: Dict[str, List[str]] = {}
    for r in resources:
        if r.get("accountId") != account_id:
            continue
        name = r.get("resourceName") or r.get("resourceId", "")
        tokens = re.split(r"[-_]", name)
        if len(tokens) >= 2:
            prefix = "-".join(tokens[:2])
            prefixes.setdefault(prefix, []).append(
                r.get("arn") or r.get("resourceId", "")
            )
    return [
        {"name": prefix,
         "grouping_method": "Naming prefix",
         "grouping_confidence": "low",
         "account_id": account_id,
         "resource_ids": ids}
        for prefix, ids in prefixes.items()
        if 2 <= len(ids) <= 200
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Native mechanism state
# ─────────────────────────────────────────────────────────────────────────────

# Aurora publishes its volume size under AWS/RDS; Neptune and DocumentDB each publish it under their own namespace.
_CLUSTER_METRIC_NAMESPACE = {"neptune": "AWS/Neptune", "docdb": "AWS/DocDB"}


def _set_snapshot_fields(entry: Dict, newest: datetime, count: int) -> None:
    """Record the newest snapshot or backup of a resource on its native-state entry."""
    newest = newest if newest.tzinfo else newest.replace(tzinfo=timezone.utc)
    entry["snapshot_count"] = count
    entry["latest_snapshot_at"] = newest.isoformat()
    entry["latest_snapshot_age_days"] = (datetime.now(timezone.utc) - newest).days


def _note_snapshots(state: Dict[str, Dict], ids: Dict[Tuple[str, str], str], kind: str,
                    snapshots: List[Dict], id_field: str, time_field: str) -> List[Dict]:
    """Attach the newest available snapshot to the database it came from.

    Returns the manual snapshots whose source database is gone from this Region.  A snapshot is kept on
    purpose when its database is deleted, so it can be the only copy of that data; it is reported as a
    fact, with its age, and nobody is told to delete it.  Automated snapshots are not listed: they go
    when their database does."""
    newest: Dict[str, Tuple[datetime, int]] = {}
    manual: Dict[str, int] = {}
    orphans: List[Dict] = []
    for snap in snapshots:
        key = ids.get((kind, snap.get(id_field, "")))
        when = snap.get(time_field)
        if snap.get("Status") not in (None, "available") or not isinstance(when, datetime):
            continue
        is_manual = str(snap.get("SnapshotType", "")).lower() == "manual"
        if not key:
            if is_manual:
                snap_id = snap.get("DBSnapshotIdentifier") or snap.get("DBClusterSnapshotIdentifier") or ""
                orphans.append({"id": snap_id, "source": snap.get(id_field, ""), "kind": f"rds_{kind}_snapshot",
                                "size_gib": snap.get("AllocatedStorage", 0) or 0, "created": _iso(when)})
            continue
        prev = newest.get(key, (when, 0))
        newest[key] = (max(prev[0], when), prev[1] + 1)
        if is_manual:
            manual[key] = manual.get(key, 0) + 1
    for key, (when, count) in newest.items():
        if key in state:
            _set_snapshot_fields(state[key], when, count)
            state[key]["manual_snapshot_count"] = manual.get(key, 0)
    return orphans


def _shared_snapshots(rds, kind: str, snapshots: List[Dict], region: str) -> Tuple[List[Dict], bool]:
    """Manual snapshots that other accounts can restore, or anyone can ("all" is public).

    One read-only call per manual snapshot.  Returns (shared snapshots, complete).  `complete` is False when any
    snapshot's attributes could not be read, so "none shared" is never claimed on a partial look.  A permission
    that is denied is one gap for the Region, not one per snapshot, and stops further calls."""
    call = "describe_db_snapshot_attributes" if kind == "db" else "describe_db_cluster_snapshot_attributes"
    id_arg, result_key, list_key = (
        ("DBSnapshotIdentifier", "DBSnapshotAttributesResult", "DBSnapshotAttributes") if kind == "db"
        else ("DBClusterSnapshotIdentifier", "DBClusterSnapshotAttributesResult", "DBClusterSnapshotAttributes"))
    manual = [x.get("DBSnapshotIdentifier") or x.get("DBClusterSnapshotIdentifier") or ""
              for x in snapshots if str(x.get("SnapshotType", "")).lower() == "manual"]

    def read(snap_id: str) -> Tuple[str, Optional[Dict]]:
        try:
            attrs = getattr(rds, call)(**{id_arg: snap_id}).get(result_key, {}).get(list_key, [])
        except _AWS_ERRORS as e:
            if _gap_status(e) == "AccessDenied":
                return "denied", None
            note_failure(e, region, "rds", call, subject=snap_id)
            return "failed", None
        values = [v for a in attrs if a.get("AttributeName") == "restore" for v in a.get("AttributeValues", [])]
        if not values:
            return "ok", None
        return "ok", {"id": snap_id, "kind": f"rds_{kind}_snapshot", "public": "all" in values,
                      "accounts": sorted(v for v in values if v != "all")}

    if not manual:
        return [], True
    first_status, first = read(manual[0])
    if first_status == "denied":
        record_gap(region, f"rds:{call}", "AccessDenied")
        return [], False
    results = [(first_status, first)] + [r or ("failed", None) for r in
                                         parallel_map(read, manual[1:], ITEM_WORKERS, "rds-attributes")]
    if any(status == "denied" for status, _ in results):
        record_gap(region, f"rds:{call}", "AccessDenied")
    return [item for _, item in results if item], all(status == "ok" for status, _ in results)


def _retained_backups(rds, region: str) -> List[Dict]:
    """Automated backups kept after their database was deleted.  They cost storage and may be the only copy."""
    items: List[Dict] = []
    for call, key, id_field, arn_field in (
            ("describe_db_instance_automated_backups", "DBInstanceAutomatedBackups", "DBInstanceIdentifier",
             "DBInstanceAutomatedBackupsArn"),
            ("describe_db_cluster_automated_backups", "DBClusterAutomatedBackups", "DBClusterIdentifier",
             "DBClusterAutomatedBackupsArn")):
        for b in paginate(rds, call, key, _raise=True):
            if str(b.get("Status", "")).lower() != "retained":
                continue
            window = b.get("RestoreWindow") or {}
            items.append({"id": b.get(arn_field) or b.get(id_field, ""), "source": b.get(id_field, ""),
                          "kind": "rds_retained_automated_backup", "size_gib": b.get("AllocatedStorage", 0) or 0,
                          "created": _iso(window.get("EarliestTime") or b.get("InstanceCreateTime"))})
    return items


_AMI_IN_TEXT = re.compile(r"\bami-[0-9a-f]+")


def _is_archived(snap: Dict) -> bool:
    """An EBS snapshot in the archive tier.  DescribeSnapshots returns StorageTier ("archive" or "standard"); a snapshot restored
    temporarily from the archive reads "standard" until RestoreExpiryTime."""
    return str(snap.get("StorageTier") or "").lower() == "archive"


def _ebs_snapshot_findings(snaps: List[Dict], volume_ids: Optional[set]) -> List[Dict]:
    """Snapshots of volumes that no longer exist in the Region.

    Left out on purpose: snapshots that back an AMI (the description names it), copies made from another
    Region (volume id vol-ffffffff), snapshots AWS Backup manages (listed with the recovery points), and
    anything not yet completed.  With no volume list, nothing is claimed."""
    if volume_ids is None:
        return []
    out: List[Dict] = []
    for snap in snaps:
        vid = snap.get("VolumeId", "")
        if not vid or vid == "vol-ffffffff" or vid in volume_ids or snap.get("State") not in (None, "completed"):
            continue
        if _AMI_IN_TEXT.search(snap.get("Description", "") or ""):
            continue
        if any(str(t.get("Key", "")).startswith("aws:backup") for t in snap.get("Tags", []) or []):
            continue
        out.append({"id": snap.get("SnapshotId", ""), "source": vid, "kind": "ebs_snapshot",
                    "size_gib": snap.get("VolumeSize", 0) or 0, "created": _iso(snap.get("StartTime")),
                    "archived": _is_archived(snap)})
    return out


def collect_native_mechanisms(
    session: boto3.Session, account_id: str, regions: List[str],
    deep: bool = False,
) -> Dict[str, Any]:
    """Returns a dict keyed by resource ARN/ID with native mechanism details."""
    state: Dict[str, Dict] = {}

    def native_region(region: str) -> Dict[str, Dict]:
        state: Dict[str, Dict] = {}          # this Region's part only
        rds_ids: Dict[Tuple[str, str], str] = {}     # (kind, identifier) -> the ARN used as the state key
        # Copies whose source is gone, and copies visible outside the account.  Not tied to one resource.
        findings: Dict[str, Any] = {"region": region, "account_id": account_id, "orphans": [], "shared": [],
                                    "public_snapshots": [], "public_images": [], "unencrypted_snapshots": 0,
                                    # Which exposure checks finished here.  "None found" is only said for one that did.
                                    "checks": {"public_snapshots": True, "public_images": True, "rds_attributes": True,
                                               "orphans": True}}
        # RDS automated backups
        try:
            rds = client_for(session, "rds", region)
            for inst in paginate(rds, "describe_db_instances", "DBInstances"):
                rid = inst.get("DBInstanceArn", inst["DBInstanceIdentifier"])
                state[rid] = {
                    "mechanism": "rds_automated_backup",
                    "retention_days": inst.get("BackupRetentionPeriod", 0),
                    "enabled": inst.get("BackupRetentionPeriod", 0) > 0,
                    "same_region": True,
                    "cross_region": False,
                    "retention_ceiling_days": 35,
                    "latest_restorable_at": _iso(inst.get("LatestRestorableTime")),
                    "deletion_protection": inst.get("DeletionProtection"),
                    "multi_az": bool(inst.get("MultiAZ")),
                }
                rds_ids[("db", inst["DBInstanceIdentifier"])] = rid
            for cluster in paginate(rds, "describe_db_clusters", "DBClusters"):
                rid = cluster.get("DBClusterArn", cluster["DBClusterIdentifier"])
                cluster_id = cluster.get("DBClusterIdentifier", "")

                # Aurora storage is S3-backed and not visible via the RDS API.
                # CloudWatch VolumeBytesUsed gives the actual bytes in use, published
                # at 5-minute granularity in the cluster's own region.
                size_gib = 0.0
                if cluster_id:
                    try:
                        cw_rds = client_for(session, "cloudwatch", region)
                        cw_end = datetime.now(timezone.utc)
                        cw_start = cw_end - timedelta(days=1)
                        vol_resp = cw_rds.get_metric_statistics(
                            Namespace=_CLUSTER_METRIC_NAMESPACE.get(str(cluster.get("Engine", "")).lower(), "AWS/RDS"),
                            MetricName="VolumeBytesUsed",
                            Dimensions=[{"Name": "DBClusterIdentifier", "Value": cluster_id}],
                            StartTime=cw_start,
                            EndTime=cw_end,
                            Period=86400,
                            Statistics=["Maximum"],
                        )
                        dps = vol_resp.get("Datapoints", [])
                        if dps:
                            size_gib = max(dp["Maximum"] for dp in dps) / (1024 ** 3)
                    except _AWS_ERRORS as e:
                        note_failure(e, region, "cloudwatch", "get_metric_statistics", subject=rid)

                state[rid] = {
                    "mechanism": "aurora_automated_backup",
                    "retention_days": cluster.get("BackupRetentionPeriod", 0),
                    "enabled": cluster.get("BackupRetentionPeriod", 0) > 0,
                    "same_region": True,
                    "cross_region": False,
                    "retention_ceiling_days": 35,
                    "size_gib": size_gib,
                    "latest_restorable_at": _iso(cluster.get("LatestRestorableTime")),
                    "deletion_protection": cluster.get("DeletionProtection"),
                    "multi_az": bool(cluster.get("MultiAZ")),
                    "cluster_members": len(cluster.get("DBClusterMembers") or []),
                }
                rds_ids[("cluster", cluster_id)] = rid
        except _AWS_ERRORS as e:
            note_failure(e, region, "rds", "describe_db_instances")

        # Snapshots, manual and automated.  A manual snapshot is a real recovery copy even when automated
        # backups are off, so a database with one is not "nothing at all".
        for kind, call, key, id_field in (("db", "describe_db_snapshots", "DBSnapshots", "DBInstanceIdentifier"),
                                          ("cluster", "describe_db_cluster_snapshots", "DBClusterSnapshots",
                                           "DBClusterIdentifier")):
            try:
                rds = client_for(session, "rds", region)
                found = paginate(rds, call, key, _raise=True)
                findings["unencrypted_snapshots"] += sum(1 for x in found if x.get("Encrypted") is False
                                                         and str(x.get("SnapshotType", "")).lower() == "manual")
                findings["orphans"] += _note_snapshots(state, rds_ids, kind, found, id_field, "SnapshotCreateTime")
                shared, complete = _shared_snapshots(rds, kind, found, region)
                findings["shared"] += shared
                findings["checks"]["rds_attributes"] = findings["checks"]["rds_attributes"] and complete
            except _AWS_ERRORS as e:
                findings["checks"]["orphans"] = False
                note_failure(e, region, "rds", call)
        try:
            findings["orphans"] += _retained_backups(client_for(session, "rds", region), region)
        except _AWS_ERRORS as e:
            findings["checks"]["orphans"] = False
            note_failure(e, region, "rds", "describe_db_instance_automated_backups")

        # DynamoDB PITR + optional CloudWatch change rate
        try:
            ddb = client_for(session, "dynamodb", region)
            for tname in paginate(ddb, "list_tables", "TableNames"):
                try:
                    desc = ddb.describe_table(TableName=tname)["Table"]
                    pitr = ddb.describe_continuous_backups(TableName=tname)
                    pitr_spec = (pitr.get("ContinuousBackupsDescription", {})
                                 .get("PointInTimeRecoveryDescription", {}))
                    enabled = pitr_spec.get("PointInTimeRecoveryStatus") == "ENABLED"

                    # Write-rate metric costs ~3 CloudWatch calls per table and no
                    # finding uses it today.  Only fetch with --deep.
                    avg_daily_wcu = 0.0
                    if deep:
                        try:
                            cw_ddb = client_for(session, "cloudwatch", region)
                            cw_end = datetime.now(timezone.utc)
                            cw_start = cw_end - timedelta(days=14)
                            wcu_resp = cw_ddb.get_metric_statistics(
                                Namespace="AWS/DynamoDB",
                                MetricName="ConsumedWriteCapacityUnits",
                                Dimensions=[{"Name": "TableName", "Value": tname}],
                                StartTime=cw_start,
                                EndTime=cw_end,
                                Period=86400,
                                Statistics=["Sum"],
                            )
                            points = wcu_resp.get("Datapoints", [])
                            if points:
                                avg_daily_wcu = sum(p["Sum"] for p in points) / len(points)
                        except _AWS_ERRORS as e:
                            note_failure(e, region, "cloudwatch", "get_metric_statistics",
                                         subject=f"arn:aws:dynamodb:{region}:{account_id}:table/{tname}")

                    state[desc.get("TableArn", tname)] = {
                        "mechanism": "dynamodb_pitr",
                        # Retention is configurable from 1 to 35 days (default 35).
                        "retention_days": (int(pitr_spec.get("RecoveryPeriodInDays", 35))
                                           if enabled else 0),
                        "enabled": enabled,
                        "same_region": True,
                        "cross_region": False,
                        "retention_ceiling_days": 35,
                        "table_format": desc.get("TableClassSummary", {}).get("TableClass", ""),
                        "avg_daily_wcu": avg_daily_wcu,
                        "latest_restorable_at": _iso(pitr_spec.get("LatestRestorableDateTime")) if enabled else "",
                        "deletion_protection": desc.get("DeletionProtectionEnabled"),
                    }
                except _AWS_ERRORS as e:
                    # Without the answer this table would read as having no point-in-time recovery.
                    note_failure(e, region, "dynamodb", "describe_continuous_backups",
                                 subject=f"arn:aws:dynamodb:{region}:{account_id}:table/{tname}")
        except _AWS_ERRORS as e:
            note_failure(e, region, "dynamodb", "list_tables")

        # On-demand backups.  One list per Region, then matched to tables by ARN.
        try:
            ddb = client_for(session, "dynamodb", region)
            newest: Dict[str, Tuple[datetime, int]] = {}
            kwargs: Dict[str, Any] = {}
            while True:
                resp = ddb.list_backups(**kwargs)
                for b in resp.get("BackupSummaries", []):
                    when = b.get("BackupCreationDateTime")
                    if b.get("BackupStatus") == "AVAILABLE" and b.get("TableArn") and isinstance(when, datetime):
                        prev = newest.get(b["TableArn"], (when, 0))
                        newest[b["TableArn"]] = (max(prev[0], when), prev[1] + 1)
                if not resp.get("LastEvaluatedBackupArn"):
                    break
                kwargs["ExclusiveStartBackupArn"] = resp["LastEvaluatedBackupArn"]
            for arn, (when, count) in newest.items():
                if arn in state:
                    _set_snapshot_fields(state[arn], when, count)
        except _AWS_ERRORS as e:
            note_failure(e, region, "dynamodb", "list_backups")

        # EBS DLM.  Entries keep the target tags and exclusions so a policy can be
        # attributed to the volumes it actually covers (see dlm_policy_for_volume).
        try:
            dlm = client_for(session, "dlm", region)
            policies = paginate(dlm, "get_lifecycle_policies", "Policies")
            for pol in policies:
                try:
                    full = dlm.get_lifecycle_policy(PolicyId=pol["PolicyId"])["Policy"]
                except _AWS_ERRORS as e:
                    note_failure(e, region, "dlm", "get_lifecycle_policy")
                    continue
                details = full.get("PolicyDetails", {})
                targets = [r.get("TargetRegion") for s_ in details.get("Schedules", [])
                           for r in s_.get("CrossRegionCopyRules", []) if r.get("TargetRegion")]
                targets += [t.get("TargetRegion") for t in details.get("CrossRegionCopyTargets", [])
                            if t.get("TargetRegion")]
                resource_types = details.get("ResourceTypes") or (
                    [details["ResourceType"]] if details.get("ResourceType") else [])
                state[f"dlm:{region}:{pol['PolicyId']}"] = {
                    "mechanism": "ebs_dlm",
                    "policy_id": pol["PolicyId"],
                    "region": region,
                    "retention_days": _dlm_retention_days(details),
                    "enabled": full.get("State") == "ENABLED",
                    "same_region": True,
                    "cross_region": bool(targets),
                    "cross_region_targets": sorted(set(targets)),
                    "retention_ceiling_days": 366,
                    "policy_type": details.get("PolicyType", "EBS_SNAPSHOT_MANAGEMENT"),
                    "policy_language": details.get("PolicyLanguage", "STANDARD"),
                    "resource_types": resource_types,
                    "target_tags": details.get("TargetTags", []),
                    "exclusions": details.get("Exclusions", {}),
                    "parameters": details.get("Parameters", {}),
                }
        except _AWS_ERRORS as e:
            note_failure(e, region, "dlm", "get_lifecycle_policies")

        # Policies that target instances snapshot the volumes of every instance carrying their tags.  The tags of those
        # instances come from the tagging API (ARN and tags only), and only the keys such a policy targets are kept.
        wanted_keys = {t.get("Key") for k_, v_ in state.items() if k_.startswith(f"dlm:{region}:") and "INSTANCE" in (v_.get("resource_types") or [])
                       for t in v_.get("target_tags", []) if t.get("Key")}
        if wanted_keys:
            by_instance: Dict[str, Dict[str, str]] = {}
            try:
                tagging = client_for(session, "resourcegroupstaggingapi", region)
                for item in paginate(tagging, "get_resources", "ResourceTagMappingList", ResourceTypeFilters=["ec2:instance"], _raise=True):
                    kept = {t["Key"]: t.get("Value", "") for t in item.get("Tags", []) if t.get("Key") in wanted_keys}
                    by_instance[item["ResourceARN"].rsplit("/", 1)[-1]] = kept
                state[f"instance-tags:{region}"] = by_instance
            except _AWS_ERRORS as e:
                note_failure(e, region, "tag", "get_resources")

        # EBS snapshot count and age per volume, from describe_snapshots with an owner filter.
        # DLM tells you whether a policy exists; snapshot counts tell you whether it ran.
        try:
            ec2 = client_for(session, "ec2", region)
            snaps = paginate(ec2, "describe_snapshots", "Snapshots",
                             OwnerIds=["self"], _raise=True)
            # The volumes that exist right now, so a snapshot of a deleted volume can be told from the rest.
            # If the list could not be read, no snapshot is called an orphan.
            try:
                volume_ids: Optional[set] = {v["VolumeId"] for v in paginate(ec2, "describe_volumes", "Volumes", _raise=True)}
            except _AWS_ERRORS:
                volume_ids = None
                findings["checks"]["orphans"] = False
            findings["orphans"] += _ebs_snapshot_findings(snaps, volume_ids)
            findings["unencrypted_snapshots"] += sum(1 for x in snaps if x.get("Encrypted") is False)
            try:
                findings["public_snapshots"] = [
                    x["SnapshotId"] for x in paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"],
                                                      RestorableByUserIds=["all"], _raise=True)]
            except _AWS_ERRORS:
                findings["checks"]["public_snapshots"] = False
            try:
                findings["public_images"] = [
                    i["ImageId"] for i in ec2.describe_images(Owners=["self"]).get("Images", []) if i.get("Public")]
            except _AWS_ERRORS as e:
                findings["checks"]["public_images"] = False
                note_failure(e, region, "ec2", "describe_images")
            volume_snaps: Dict[str, List] = {}
            for s in snaps:
                vid = s.get("VolumeId", "")
                if vid:
                    volume_snaps.setdefault(vid, []).append(s)
            for vid, snap_list in volume_snaps.items():
                vol_arn = f"arn:aws:ec2:{region}:{account_id}:volume/{vid}"
                snap_list.sort(key=lambda s: s.get("StartTime", ""), reverse=True)
                archived = [x for x in snap_list if _is_archived(x)]
                # Long-retained snapshots still in the standard tier.  Snapshots behind an AMI and those AWS Backup manages are left
                # out (their retention is set elsewhere).  VolumeSize is the volume's provisioned size: an upper bound on what an
                # incremental snapshot stores.
                cutoff = datetime.now(timezone.utc) - timedelta(days=OLD_SNAPSHOT_DAYS)
                old_std = [x for x in snap_list if not _is_archived(x) and isinstance(x.get("StartTime"), datetime)
                           and _as_dt(x["StartTime"]) < cutoff and not _AMI_IN_TEXT.search(x.get("Description", "") or "")
                           and not any(str(tg.get("Key", "")).startswith("aws:backup") for tg in x.get("Tags", []) or [])]
                state.setdefault(vol_arn, {}).update({
                    "old_standard_snapshot_count": len(old_std),
                    "old_standard_snapshot_gib": sum(x.get("VolumeSize", 0) or 0 for x in old_std),
                    "snapshot_count": len(snap_list),
                    # Archived snapshots are full copies of the volume, so their size is the volume size each.
                    "archived_snapshot_count": len(archived),
                    "archived_snapshot_gib": sum(x.get("VolumeSize", 0) or 0 for x in archived),
                    "latest_snapshot_age_days": (
                        (datetime.now(timezone.utc) - snap_list[0]["StartTime"]).days
                        if snap_list and isinstance(snap_list[0].get("StartTime"), datetime)
                        else None
                    ),
                    "latest_snapshot_at": _iso(snap_list[0].get("StartTime")) if snap_list else "",
                })
        except _AWS_ERRORS as e:
            findings["checks"]["orphans"] = False
            findings["checks"]["public_snapshots"] = False
            note_failure(e, region, "ec2", "describe_snapshots")

        state[f"findings:{region}"] = findings
        return state

    for part in parallel_map(native_region, regions, REGION_WORKERS, "native"):
        state.update(part or {})

    # S3 versioning (global)
    clients = S3Clients(session)
    try:
        buckets = clients.get().list_buckets().get("Buckets", [])
    except _AWS_ERRORS as e:
        note_failure(e, "us-east-1", "s3", "list_buckets")
        buckets = []
    def one_bucket(b: Dict) -> Optional[Tuple[str, Dict]]:
        name = b["Name"]
        bucket_arn = f"arn:aws:s3:::{name}"
        s3, _ = clients.for_bucket(name)
        try:
            v = s3.get_bucket_versioning(Bucket=name)
        except _AWS_ERRORS as e:
            # Without the versioning answer nothing can be said about this bucket.
            note_failure(e, "us-east-1", "s3", "get_bucket_versioning", subject=bucket_arn)
            return None
        enabled = v.get("Status") == "Enabled"
        lc_rules: List[Dict] = []
        lifecycle_known = True
        try:
            lc_rules = s3.get_bucket_lifecycle_configuration(Bucket=name).get("Rules", [])
        except _AWS_ERRORS as e:
            # "No lifecycle configuration" is an answer; a denied or failed call is not.
            if note_failure(e, "us-east-1", "s3", "get_bucket_lifecycle_configuration", subject=bucket_arn):
                lifecycle_known = False
        has_expiry = any(
            r.get("NoncurrentVersionExpiration") or r.get("NoncurrentVersionTransitions")
            for r in lc_rules
        )
        cross_region = False
        replication_accounts: List[str] = []
        try:
            rep = s3.get_bucket_replication(Bucket=name)
            rep_rules = rep.get("ReplicationConfiguration", {}).get("Rules") or []
            cross_region = bool(rep_rules)
            # Destination.Account is only present when the destination bucket is
            # owned by another account.
            replication_accounts = sorted({r.get("Destination", {}).get("Account")
                                           for r in rep_rules
                                           if r.get("Destination", {}).get("Account")})
        except _AWS_ERRORS as e:
            note_failure(e, "us-east-1", "s3", "get_bucket_replication", subject=bucket_arn)
        # Object Lock stops deletion and overwrite for a retention period.  "Not configured" is an answer.
        object_lock: Optional[bool] = False
        try:
            lock = s3.get_object_lock_configuration(Bucket=name).get("ObjectLockConfiguration", {})
            object_lock = lock.get("ObjectLockEnabled") == "Enabled"
        except _AWS_ERRORS as e:
            if note_failure(e, "us-east-1", "s3", "get_object_lock_configuration", subject=bucket_arn):
                object_lock = None
        # AWS Backup's continuous backups of a bucket are driven by Amazon EventBridge notifications.  AWS documents the setting as on
        # when the response has an EventBridgeConfiguration member and off when it does not.  Only that yes or no is kept: the rest
        # of the response (the SNS, SQS and Lambda targets) is read and discarded.  None means the call was denied or failed.
        eventbridge: Optional[bool] = None
        try:
            eventbridge = "EventBridgeConfiguration" in s3.get_bucket_notification_configuration(Bucket=name)
        except _AWS_ERRORS as e:
            note_failure(e, "us-east-1", "s3", "get_bucket_notification_configuration", subject=bucket_arn)
        return bucket_arn, {
            "mechanism": "s3_versioning",
            "eventbridge_notifications": eventbridge,
            "object_lock": object_lock,
            "mfa_delete": v.get("MFADelete") == "Enabled",
            "enabled": enabled,
            "versioning_status": "enabled" if enabled else ("suspended" if v.get("Status") == "Suspended" else "never_enabled"),
            # None means the lifecycle call failed: unknown, not "no expiry rule".
            "has_expiry_rule": has_expiry if lifecycle_known else None,
            "cross_region": cross_region,
            "replication_dest_accounts": replication_accounts,
            "same_region": True,
            "retention_days": None,
            "retention_ceiling_days": None,
            "lifecycle_rules": len(lc_rules),
        }


    for item in parallel_map(one_bucket, buckets, ITEM_WORKERS, "s3-native"):
        if item:
            state[item[0]] = item[1]

    return state


# ─────────────────────────────────────────────────────────────────────────────
# AWS Backup state
# ─────────────────────────────────────────────────────────────────────────────

def collect_backup_state(
    session: boto3.Session, account_id: str, regions: List[str]
) -> Dict[str, Any]:
    vaults: List[Dict] = []
    plans: List[Dict] = []
    protected: List[Dict] = []
    jobs: List[Dict] = []
    restore_plans: List[Dict] = []
    restore_jobs: List[Dict] = []
    # resource_arn → {vault_locked, vault_air_gapped}
    # Built only from security-relevant (locked/air-gapped) vaults so API calls
    # stay proportional to the number of hardened vaults, not total resources.
    resource_vault_map: Dict[str, Dict] = {}
    # Per Region: which services AWS Backup is opted in for, and whether it fully manages them.
    region_settings: Dict[str, Dict] = {}

    def backup_region(region: str) -> Dict[str, Any]:
        """Everything read for one Region: its vaults, plans, jobs, settings and monitoring."""
        vaults: List[Dict] = []
        plans: List[Dict] = []
        protected: List[Dict] = []
        jobs: List[Dict] = []
        copy_jobs: List[Dict] = []
        restore_plans: List[Dict] = []
        restore_jobs: List[Dict] = []
        resource_vault_map: Dict[str, Dict] = {}
        region_settings: Dict[str, Dict] = {}
        bkp = client_for(session, "backup", region)

        try:
            settings = bkp.describe_region_settings()
            region_settings[region] = {
                "opt_in": settings.get("ResourceTypeOptInPreference", {}),
                "management": settings.get("ResourceTypeManagementPreference", {}),
            }
        except _AWS_ERRORS as e:
            note_failure(e, region, "backup", "describe_region_settings")

        # Vaults
        region_vaults = paginate(bkp, "list_backup_vaults", "BackupVaultList")
        for v in region_vaults:
            vname = v["BackupVaultName"]
            try:
                detail = bkp.describe_backup_vault(BackupVaultName=vname)
                v.update(detail)
            except _AWS_ERRORS as e:
                # Lock state is unknown, which is not the same as unlocked.
                note_failure(e, region, "backup", "describe_backup_vault")
            v["region"] = region
            v["account_id"] = account_id
            v["is_air_gapped"] = v.get("VaultType") == "LOGICALLY_AIR_GAPPED_BACKUP_VAULT"
            v["is_locked"] = v.get("Locked", False)
            # Distinguish governance vs compliance vault lock mode.
            # DescribeBackupVault returns LockDate only for compliance-mode locks:
            #   - LockDate absent → governance mode (removable by any principal with perms)
            #   - LockDate in the future → compliance mode, still in grace/cooling-off period
            #   - LockDate in the past → compliance mode, fully immutable (immune to root)
            # ChangeableForDays is only an input param to PutBackupVaultLockConfiguration
            # and is NOT returned by DescribeBackupVault.
            lock_date = v.get("LockDate")
            if v["is_air_gapped"]:
                v["vault_lock_mode"] = "compliance"
            elif v["is_locked"] and lock_date is not None:
                if isinstance(lock_date, str):
                    lock_date = datetime.fromisoformat(lock_date.replace("Z", "+00:00"))
                if isinstance(lock_date, datetime) and lock_date <= datetime.now(timezone.utc):
                    v["vault_lock_mode"] = "compliance"
                else:
                    v["vault_lock_mode"] = "compliance_grace"
            elif v["is_locked"]:
                v["vault_lock_mode"] = "governance"
            else:
                v["vault_lock_mode"] = "none"
            vaults.append(v)

        # Legal holds first, so each recovery point can be marked as held while the vaults are read.
        held_points: set = set()
        legal_holds_known = True
        try:
            for hold in paginate(bkp, "list_legal_holds", "LegalHolds", _raise=True):
                if str(hold.get("Status", "")).upper() in ("CANCELED",):
                    continue
                for rp in paginate(bkp, "list_recovery_points_by_legal_hold", "RecoveryPoints",
                                   LegalHoldId=hold["LegalHoldId"], _raise=True):
                    if rp.get("RecoveryPointArn"):
                        held_points.add(rp["RecoveryPointArn"])
        except _AWS_ERRORS:
            legal_holds_known = False                 # already in the ledger, recorded by paginate
        recovery_points: Dict[str, Dict] = {}
        points_complete = True

        # Build per-resource vault membership map from locked/air-gapped vaults only.
        # Previous code set vault_locked/is_air_gapped on any protected resource if
        # the account had a locked or air-gapped vault — regardless of which vault
        # that resource's recovery points were actually stored in.
        for v in region_vaults:
            v_locked = v.get("is_locked", False)
            v_airgap = v.get("is_air_gapped", False)
            v_lock_mode = v.get("vault_lock_mode", "none")
            try:
                rps = paginate(bkp, "list_recovery_points_by_backup_vault",
                               "RecoveryPoints", BackupVaultName=v["BackupVaultName"])
                for rp in rps:
                    _count_recovery_point(v, rp)
                    rarn = rp.get("ResourceArn", "")
                    if not rarn:
                        continue
                    _note_recovery_point(recovery_points, rp, v, held_points)
                    # Only a recovery point that can still be restored places a copy in a locked or air-gapped vault.
                    if not (v_locked or v_airgap) or not recovery_point_usable(rp):
                        continue
                    existing = resource_vault_map.get(rarn, {})
                    # Escalate lock mode: compliance > compliance_grace > governance > none
                    prev_mode = existing.get("vault_lock_mode", "none")
                    best_mode = (v_lock_mode if _LOCK_MODE_RANK.get(v_lock_mode, 0)
                                 > _LOCK_MODE_RANK.get(prev_mode, 0) else prev_mode)
                    resource_vault_map[rarn] = {
                        "vault_locked": existing.get("vault_locked", False) or v_locked,
                        "vault_air_gapped": existing.get("vault_air_gapped", False) or v_airgap,
                        "vault_lock_mode": best_mode,
                        # Accumulate count across all security-relevant vaults.
                        "recovery_point_count": existing.get("recovery_point_count", 0) + 1,
                        # Where the copies sit, so an org-wide merge can see a copy held
                        # in another account or Region.
                        "vault_accounts": set(existing.get("vault_accounts", ())) | {account_id},
                        "vault_regions": set(existing.get("vault_regions", ())) | {region},
                    }
            except _AWS_ERRORS as e:
                points_complete = False
                note_failure(e, region, "backup", "list_recovery_points_by_backup_vault")

        # Who the vault's own policy lets in, and which keys encrypt what is in it.
        key_info: Dict[str, Dict] = {}
        for v in region_vaults:
            try:
                text = bkp.get_backup_vault_access_policy(BackupVaultName=v["BackupVaultName"]).get("Policy", "")
                parsed = parse_vault_policy(text)
                v["access_policy"] = ({"state": "read", "statements": parsed} if parsed is not None
                                      else {"state": "unreadable"})
            except _AWS_ERRORS as e:
                # No policy is an answer; a denied or failed call is not.
                v["access_policy"] = {"state": "unreadable" if note_failure(
                    e, region, "backup", "get_backup_vault_access_policy", subject=v.get("BackupVaultArn", "")) else "none"}
        for key in sorted({k for v in region_vaults for k in ([v.get("EncryptionKeyArn")] + list((v.get("rp_stats") or {}).get("by_key", {})))
                           if k}):
            parts = key.split(":")
            key_region = parts[3] if len(parts) > 4 else region
            try:
                meta = client_for(session, "kms", key_region).describe_key(KeyId=key)["KeyMetadata"]
                key_info[key] = {"manager": meta.get("KeyManager", ""), "state": meta.get("KeyState", ""),
                                 "account": parts[4] if len(parts) > 4 else ""}
            except _AWS_ERRORS as e:
                note_failure(e, key_region, "kms", "describe_key", subject=key)
                key_info[key] = {"manager": "", "state": "", "account": parts[4] if len(parts) > 4 else ""}

        # Plans
        region_plans = paginate(bkp, "list_backup_plans", "BackupPlansList")
        for p in region_plans:
            try:
                full = bkp.get_backup_plan(BackupPlanId=p["BackupPlanId"])
                p.update(full.get("BackupPlan", {}))
                sels = paginate(bkp, "list_backup_selections", "BackupSelectionsList",
                                BackupPlanId=p["BackupPlanId"])
                enriched_sels = []
                for sel_summary in sels:
                    try:
                        sel_detail = bkp.get_backup_selection(
                            BackupPlanId=p["BackupPlanId"],
                            SelectionId=sel_summary["SelectionId"],
                        )
                        sel_data = sel_detail.get("BackupSelection", {})
                        sel_data["SelectionId"] = sel_summary["SelectionId"]
                        enriched_sels.append(sel_data)
                    except _AWS_ERRORS as e:
                        # The summary has no Resources or Conditions.  Without this flag an
                        # empty selection would read as "selects everything".
                        note_failure(e, region, "backup", "get_backup_selection")
                        sel_summary["_detail_unavailable"] = True
                        enriched_sels.append(sel_summary)
                p["Selections"] = enriched_sels
            except _AWS_ERRORS as e:
                # A plan whose rules could not be read is not a plan that selects nothing.
                note_failure(e, region, "backup", "get_backup_plan")
                p["Selections"] = [{"_detail_unavailable": True}]
            p["region"] = region
            p["account_id"] = account_id
            p["has_scan_actions"] = any(rule.get("ScanActions") for rule in p.get("Rules", []))
            p["has_copy_actions"] = any(
                rule.get("CopyActions") for rule in p.get("Rules", [])
            )
            # Detect cross-account copy: extract account IDs from destination vault ARNs.
            # ARN format: arn:aws:backup:{region}:{account_id}:backup-vault:{name}
            cross_account_dest_accounts: set = set()
            copy_destinations: List[Dict] = []
            for rule in p.get("Rules", []):
                for ca in rule.get("CopyActions", []):
                    dest_arn = ca.get("DestinationBackupVaultArn", "")
                    parts = dest_arn.split(":")
                    if len(parts) >= 5:
                        cross_account_dest_accounts.add(parts[4])
                        copy_destinations.append({"region": parts[3], "account_id": parts[4],
                                                  "vault_arn": dest_arn})
            p["cross_account_dest_accounts"] = cross_account_dest_accounts
            # Region and account of every copy target, so a copy can be classified as
            # cross-Region, cross-account, or neither.
            p["copy_destinations"] = copy_destinations
            plans.append(p)

        # Protected resources
        region_protected = paginate(bkp, "list_protected_resources", "Results")
        for r in region_protected:
            r["region"] = region
            r["account_id"] = account_id
            protected.append(r)

        # Jobs (last 30 days)
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(BACKUP_JOB_LOOKBACK_DAYS, JOB_HISTORY_DAYS))
        region_jobs = paginate(bkp, "list_backup_jobs", "BackupJobs",
                               ByCreatedAfter=cutoff)
        for j in region_jobs:
            j["region"] = region
            j["account_id"] = account_id
            jobs.append(j)

        # Whether AWS Backup Audit Manager is in use here: its frameworks (and the controls each turns on) and report plans.
        frameworks: List[Dict] = []
        report_plans: List[Dict] = []
        governance_known = True
        try:
            for fw in paginate(bkp, "list_frameworks", "Frameworks", _raise=True):
                controls: List[str] = []
                try:
                    controls = [c.get("ControlName", "") for c in
                                bkp.describe_framework(FrameworkName=fw["FrameworkName"]).get("FrameworkControls", [])]
                except _AWS_ERRORS as e:
                    note_failure(e, region, "backup", "describe_framework", subject=fw.get("FrameworkName", ""))
                frameworks.append({"name": fw.get("FrameworkName", ""), "status": fw.get("DeploymentStatus", ""),
                                   "controls": [c for c in controls if c], "region": region, "account_id": account_id})
            report_plans = [{"name": rp_.get("ReportPlanName", ""), "region": region, "account_id": account_id}
                            for rp_ in paginate(bkp, "list_report_plans", "ReportPlans", _raise=True)]
        except _AWS_ERRORS:
            governance_known = False                # already recorded by paginate; the report says it was not assessed

        # Copy jobs: a copy to another Region or account that fails leaves that protection unproven.
        for j in paginate(bkp, "list_copy_jobs", "CopyJobs", ByCreatedAfter=cutoff):
            j["region"] = region
            j["account_id"] = account_id
            copy_jobs.append(j)

        # Restore testing plans, and what each one covers: which resource types and ARNs or tags it selects, and
        # which vaults it restores from.  If the detail cannot be read the plan is kept and marked, so a plan that
        # exists is never reported as covering nothing.
        try:
            rp = paginate(bkp, "list_restore_testing_plans", "RestoreTestingPlans")
            denied_calls: set = set()
            for plan in rp:
                plan["region"] = region
                plan["account_id"] = account_id
                _read_restore_testing_plan(bkp, plan, region, denied_calls)
            restore_plans.extend(rp)
        except _AWS_ERRORS as e:
            note_failure(e, region, "backup", "list_restore_testing_plans")

        # Actual restore jobs — tells us whether any restore has ever been exercised.
        # The appendix lists backup:ListRestoreJobs as a source for this finding,
        # but the previous code only checked for testing plan configs, not actual runs.
        try:
            cutoff_restore = datetime.now(timezone.utc) - timedelta(days=RESTORE_LOOKBACK_DAYS)
            region_restore_jobs = paginate(bkp, "list_restore_jobs", "RestoreJobs",
                                           ByCreatedAfter=cutoff_restore)
            for j in region_restore_jobs:
                j["region"] = region
                j["account_id"] = account_id
            restore_jobs.extend(region_restore_jobs)
        except _AWS_ERRORS as e:
            note_failure(e, region, "backup", "list_restore_jobs")

        # Monitoring for this Region.  A vault name is only unique within one account and Region, so the
        # keys carry both.  Either signal counts: an alarm on the vault, or a vault notification.
        vault_alarms: Dict[str, bool] = {}
        try:
            cw = client_for(session, "cloudwatch", region)
            for alarm in paginate(cw, "describe_alarms", "MetricAlarms"):
                ns = alarm.get("Namespace", "")
                dims = {d["Name"]: d["Value"] for d in alarm.get("Dimensions", [])}
                if "AWS/Backup" in ns and "BackupVaultName" in dims:
                    vault_alarms[monitor_key(account_id, region, dims["BackupVaultName"])] = True
        except _AWS_ERRORS as e:
            note_failure(e, region, "cloudwatch", "describe_alarms")

        # Vault SNS notifications: BACKUP_JOB_FAILED / EXPIRED / COPY_JOB_FAILED.  The call raises
        # ResourceNotFoundException when none are configured, which is an answer, not a gap.
        for v in vaults:
            vault_name = v.get("BackupVaultName", "")
            if not vault_name or vault_alarms.get(monitor_key(account_id, region, vault_name)):
                continue
            try:
                notif = bkp.get_backup_vault_notifications(BackupVaultName=vault_name)
                if [e for e in notif.get("BackupVaultEvents", []) if "FAILED" in e or "EXPIRED" in e]:
                    vault_alarms[monitor_key(account_id, region, vault_name)] = True
            except _AWS_ERRORS as e:
                note_failure(e, region, "backup", "get_backup_vault_notifications")

        # An aws.backup EventBridge rule only sees events from its own Region.
        eventbridge_here = False
        try:
            events_client = client_for(session, "events", region)
            for rule in paginate(events_client, "list_rules", "Rules"):
                pattern = rule.get("EventPattern", "")
                if isinstance(pattern, str) and "aws.backup" in pattern.lower():
                    eventbridge_here = True
                    break
        except _AWS_ERRORS as e:
            note_failure(e, region, "events", "list_rules")

        # RAM shares, for air-gapped vault sharing.
        shared: List[str] = []
        try:
            ram = client_for(session, "ram", region)
            for share in paginate(ram, "get_resource_shares", "resourceShares", resourceOwner="SELF"):
                arn = share.get("resourceShareArn", "")
                if "backup" in share.get("name", "").lower() and arn not in shared:
                    shared.append(arn)
        except _AWS_ERRORS as e:
            note_failure(e, region, "ram", "get_resource_shares")

        return {"vaults": vaults, "plans": plans, "protected": protected, "jobs": jobs,
                "restore_plans": restore_plans, "restore_jobs": restore_jobs,
                "resource_vault_map": resource_vault_map, "region_settings": region_settings,
                "copy_jobs": copy_jobs,
                "recovery_points": recovery_points, "recovery_points_complete": points_complete,
                "legal_holds_known": legal_holds_known, "key_info": key_info,
                "frameworks": frameworks, "report_plans": report_plans, "governance_known": governance_known,
                "vault_alarms": vault_alarms, "eventbridge": eventbridge_here, "ram": shared}

    # Regions are read concurrently and merged in the order given, so the output does not depend on timing.
    vault_alarms: Dict[str, bool] = {}
    eventbridge_regions: List[str] = []
    air_gapped_verified: List[str] = []
    vault_maps: List[Dict[str, Dict]] = []
    point_maps: List[Dict[str, Dict]] = []
    frameworks: List[Dict] = []
    copy_jobs_all: List[Dict] = []
    report_plans_all: List[Dict] = []
    governance_known = True
    key_infos: Dict[str, Dict] = {}
    legal_holds_known = True
    points_incomplete: List[str] = []
    for region, part in zip(regions, parallel_map(backup_region, regions, REGION_WORKERS, "backup")):
        if not part:
            legal_holds_known = False
            points_incomplete.append(region)
            continue
        point_maps.append(part["recovery_points"])
        if not part.get("recovery_points_complete", True):
            points_incomplete.append(region)
        key_infos.update(part["key_info"])
        legal_holds_known = legal_holds_known and part["legal_holds_known"]
        vaults += part["vaults"]
        plans += part["plans"]
        protected += part["protected"]
        jobs += part["jobs"]
        restore_plans += part["restore_plans"]
        restore_jobs += part["restore_jobs"]
        vault_maps.append(part["resource_vault_map"])
        frameworks += part["frameworks"]
        copy_jobs_all += part["copy_jobs"]
        report_plans_all += part["report_plans"]
        governance_known = governance_known and part["governance_known"]
        region_settings.update(part["region_settings"])
        vault_alarms.update(part["vault_alarms"])
        if part["eventbridge"]:
            eventbridge_regions.append(region)
        air_gapped_verified += [arn for arn in part["ram"] if arn not in air_gapped_verified]
    resource_vault_map = merge_vault_maps(vault_maps)
    has_eventbridge_backup_monitoring = bool(eventbridge_regions)

    return {
        "vaults": vaults,
        "plans": plans,
        "protected_resources": protected,
        "jobs": jobs,
        "restore_testing_plans": restore_plans,
        "restore_jobs": restore_jobs,
        "vault_alarms": vault_alarms,
        "has_eventbridge_backup_monitoring": has_eventbridge_backup_monitoring,
        "eventbridge_regions": eventbridge_regions,
        "air_gapped_verified": air_gapped_verified,
        "resource_vault_map": resource_vault_map,
        "region_settings": region_settings,
        "recovery_points": merge_recovery_points(point_maps),
        # Regions where listing a vault's recovery points failed: there, ListProtectedResources is the only evidence of a copy.
        "recovery_points_incomplete": points_incomplete,
        "legal_holds_known": legal_holds_known,
        "key_info": key_infos,
        "frameworks": frameworks,
        "copy_jobs": copy_jobs_all,
        "report_plans": report_plans_all,
        "governance_known": governance_known,
    }


# A recovery point AWS Backup still holds and can restore from.  EXPIRED (retention passed but not deleted), DELETING and a DELETED
# storage class are kept out of the evidence; they still count towards stored size, which is what they may cost.
# STOPPED (a continuous backup that stopped) is left out as an assumption, named in the report's inputs table: AWS documentation
# does not say whether its earlier points can still be restored (Alex's decision, 2026-11-17: keep it out and say so).
_RP_UNUSABLE_STATUS = frozenset({"EXPIRED", "DELETING", "DELETED", "STOPPED", "CREATING"})


def recovery_point_usable(rp: Dict) -> bool:
    return (str(rp.get("Status") or "").upper() not in _RP_UNUSABLE_STATUS
            and str(rp.get("StorageClass") or "").upper() != "DELETED")


def _note_recovery_point(index: Dict[str, Dict], rp: Dict, vault: Dict, held: set) -> None:
    """Add one recovery point to the per-resource summary.  Keeps counts, size and dates, nothing else.

    `count`, `bytes` and the cold figures cover every recovery point stored (what may be billed).  `usable`, `newest`, `oldest`
    and where the copies sit cover only recovery points that can still be restored (the evidence of a copy).  DynamoDB keeps the
    date and size of each usable point, so the Waste pillar can tell which are kept past the retention target."""
    rarn = rp["ResourceArn"]
    entry = index.setdefault(rarn, {"resource_type": rp.get("ResourceType", ""), "count": 0, "bytes": 0, "held": 0,
                                    "cold": 0, "cold_bytes": 0, "usable": 0,
                                    "newest": "", "oldest": "", "vault_accounts": [], "vault_regions": []})
    entry["count"] += 1
    entry["bytes"] += int(rp.get("BackupSizeInBytes") or 0)
    # StorageClass is WARM, COLD or DELETED.  A cold EBS recovery point sits in the EBS Snapshots Archive tier.
    if str(rp.get("StorageClass") or "").upper() == "COLD":
        entry["cold"] = entry.get("cold", 0) + 1
        entry["cold_bytes"] = entry.get("cold_bytes", 0) + int(rp.get("BackupSizeInBytes") or 0)
    if rp.get("RecoveryPointArn") in held:
        entry["held"] += 1
    if not recovery_point_usable(rp):
        return
    entry["usable"] = entry.get("usable", 0) + 1
    when = _iso(rp.get("CreationDate"))
    if entry["resource_type"] == "DynamoDB":
        entry.setdefault("points", []).append([when, int(rp.get("BackupSizeInBytes") or 0)])
    if when:
        entry["newest"] = max(entry["newest"], when) if entry["newest"] else when
        entry["oldest"] = min(entry["oldest"], when) if entry["oldest"] else when
    for key, value in (("vault_accounts", vault.get("account_id", "")), ("vault_regions", vault.get("region", ""))):
        if value and value not in entry[key]:
            entry[key].append(value)


def _read_restore_testing_plan(bkp, plan: Dict, region: str, denied: Optional[set] = None) -> None:
    """Add to a restore testing plan what it restores from and what it selects.  Sets plan["detail_readable"].

    `denied` is shared across the plans of one Region: once a call is denied it is recorded once for the Region and not
    repeated for every plan."""
    denied = denied if denied is not None else set()
    name = plan.get("RestoreTestingPlanName", "")
    plan["detail_readable"] = True
    plan["selections"] = []
    plan["include_vaults"], plan["exclude_vaults"] = [], []

    def fail(api: str, e: Exception) -> None:
        plan["detail_readable"] = False
        if _gap_status(e) == "AccessDenied":
            if api not in denied:
                denied.add(api)
                record_gap(region, f"backup:{api}", "AccessDenied")
        else:
            note_failure(e, region, "backup", api, subject=name)

    if "get_restore_testing_plan" in denied:
        plan["detail_readable"] = False
    else:
        try:
            full = bkp.get_restore_testing_plan(RestoreTestingPlanName=name).get("RestoreTestingPlan", {})
            chosen = full.get("RecoveryPointSelection") or {}
            plan["include_vaults"] = list(chosen.get("IncludeVaults") or [])
            plan["exclude_vaults"] = list(chosen.get("ExcludeVaults") or [])
            plan["selection_window_days"] = chosen.get("SelectionWindowDays")
            plan["recovery_point_types"] = list(chosen.get("RecoveryPointTypes") or [])
        except _AWS_ERRORS as e:
            fail("get_restore_testing_plan", e)
    if denied & {"list_restore_testing_selections", "get_restore_testing_selection"}:
        plan["detail_readable"] = False
        return
    try:
        summaries = bkp.list_restore_testing_selections(RestoreTestingPlanName=name).get("RestoreTestingSelections", [])
    except _AWS_ERRORS as e:
        fail("list_restore_testing_selections", e)
        return
    for summary in summaries:
        try:
            detail = bkp.get_restore_testing_selection(
                RestoreTestingPlanName=name,
                RestoreTestingSelectionName=summary["RestoreTestingSelectionName"]).get("RestoreTestingSelection", {})
        except _AWS_ERRORS as e:
            fail("get_restore_testing_selection", e)
            return
        conditions = detail.get("ProtectedResourceConditions") or {}
        plan["selections"].append({
            "type": detail.get("ProtectedResourceType", summary.get("ProtectedResourceType", "")),
            "arns": list(detail.get("ProtectedResourceArns") or []),
            "equals": [(c.get("Key", ""), c.get("Value", "")) for c in conditions.get("StringEquals") or []],
            "not_equals": [(c.get("Key", ""), c.get("Value", "")) for c in conditions.get("StringNotEquals") or []],
        })


def _count_recovery_point(vault: Dict, rp: Dict) -> None:
    """Counts only: how many recovery points a vault holds, how many are unencrypted, under which key, and how many
    carry a malware scan result.  Nothing about what a recovery point contains."""
    stats = vault.setdefault("rp_stats", {"total": 0, "unencrypted": 0, "by_key": {}, "scanned": 0,
                                          "scan_malware": 0, "scan_failed": 0})
    stats["total"] += 1
    if rp.get("IsEncrypted") is False:
        stats["unencrypted"] += 1
    key = rp.get("EncryptionKeyArn")
    if key:
        stats["by_key"][key] = stats["by_key"].get(key, 0) + 1
    scan = rp.get("AggregatedScanResult")
    if scan:
        stats["scanned"] += 1
        if scan.get("FailedScan"):
            stats["scan_failed"] += 1
        elif scan.get("Findings"):
            stats["scan_malware"] += 1


_POLICY_ACTIONS = ("backup:DeleteRecoveryPoint", "backup:UpdateRecoveryPointLifecycle", "backup:PutBackupVaultAccessPolicy")


def parse_vault_policy(text: str) -> Optional[List[Dict]]:
    """A vault access policy reduced to what the review asks of it, or None when it is not valid JSON.

    Per statement: Effect, the principals named, the actions, and whether a condition limits it to the organization."""
    try:
        doc = json.loads(text)
    except (TypeError, ValueError):
        return None
    statements = doc.get("Statement", []) if isinstance(doc, dict) else []
    out: List[Dict] = []
    for st in [statements] if isinstance(statements, dict) else statements:
        if not isinstance(st, dict):
            continue
        principal = st.get("Principal")
        if principal == "*":
            names = ["*"]
        elif isinstance(principal, dict):
            names = [n for v in principal.values() for n in _as_list(v)]
        else:
            names = []
        condition_keys = [str(k).lower() for kv in (st.get("Condition") or {}).values() if isinstance(kv, dict) for k in kv]
        out.append({"effect": st.get("Effect", ""), "principals": names,
                    "actions": _as_list(st.get("Action")), "not_action": "NotAction" in st,
                    "org_condition": any(k.startswith("aws:principalorg") for k in condition_keys),
                    "conditional": bool(st.get("Condition"))})
    return out


def _principal_account(name: str) -> str:
    """The account id in a principal ARN or a bare id, else ''."""
    match = re.search(r"(?<![0-9])([0-9]{12})(?![0-9])", name)
    return match.group(1) if match else ""


def vault_policy_findings(vault: Dict, known_accounts: set) -> Dict[str, Any]:
    """What a vault's access policy says, as facts.  `known_accounts` are the accounts this run assessed."""
    policy = vault.get("access_policy") or {"state": "unreadable"}
    if policy["state"] != "read":
        return {"state": policy["state"], "denied": [], "external": [], "any_principal": False}
    denied: set = set()
    external: set = set()
    any_principal = False
    for st in policy["statements"]:
        if st["effect"] == "Deny":
            for action in _POLICY_ACTIONS:
                if any(_action_matches(pat, action) for pat in st["actions"]):
                    denied.add(action)
        elif st["effect"] == "Allow":
            for name in st["principals"]:
                if name == "*" and not st["org_condition"]:
                    any_principal = True
                account = _principal_account(name)
                if account and account != vault.get("account_id") and account not in known_accounts and not st["org_condition"]:
                    external.add(account)
    return {"state": "read", "denied": sorted(denied), "external": sorted(external), "any_principal": any_principal}


def region_geography(region: str) -> str:
    """A coarse area for an AWS Region, by its prefix.  Used to see when a copy leaves the area its source is in.
    The areas are broad on purpose: they say where a copy is, not which law applies to it."""
    r = (region or "").lower()
    for prefix, area in (("us-gov-", "US government"), ("us-", "United States"), ("ca-", "Canada"), ("mx-", "Mexico"),
                         ("sa-", "South America"), ("eu-", "Europe"), ("ap-", "Asia Pacific"), ("me-", "Middle East"),
                         ("il-", "Israel"), ("af-", "Africa"), ("cn-", "China")):
        if r.startswith(prefix):
            return area
    return ""


_UNUSABLE_KEY_STATES = frozenset({"Disabled", "PendingDeletion", "PendingReplicaDeletion", "Unavailable"})


def classify_vault_key(vault: Dict, key_info: Dict[str, Dict]) -> str:
    """aws_owned, aws_managed, customer_same_account, customer_other_account, or unknown."""
    key = vault.get("EncryptionKeyArn") or ""
    if not key:
        return "aws_owned" if vault.get("EncryptionKeyType") == "AWS_OWNED_KMS_KEY" else "unknown"
    info = key_info.get(key) or {}
    if info.get("manager") == "AWS":
        return "aws_managed"
    if info.get("manager") == "CUSTOMER":
        return "customer_same_account" if info.get("account") == vault.get("account_id") else "customer_other_account"
    if vault.get("EncryptionKeyType") == "AWS_OWNED_KMS_KEY":
        return "aws_owned"
    return "unknown"


def compute_backup_security(vaults: List[Dict], key_info: Dict[str, Dict], plans: List[Dict], known_accounts: set,
                            scp_cover: Optional[Dict[str, Any]], accounts: List[Dict], resources: List[Dict],
                            unencrypted_snapshots: int = 0, frameworks: Optional[List[Dict]] = None,
                            report_plans: Optional[List[Dict]] = None, governance_known: bool = True,
                            plans_readable: bool = True, org_backup_policies: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Facts about how the copies are protected from the credentials that made them: keys, vault policies, guardrails,
    where copies are kept, malware scanning and where copies are located.  No grade."""
    kinds: Dict[str, int] = {}
    unusable: List[Dict] = []
    total_rp = unencrypted_rp = 0
    for v in vaults:
        kinds[classify_vault_key(v, key_info)] = kinds.get(classify_vault_key(v, key_info), 0) + 1
        stats = v.get("rp_stats") or {}
        total_rp += stats.get("total", 0)
        unencrypted_rp += stats.get("unencrypted", 0)
        for key, count in (stats.get("by_key") or {}).items():
            info = key_info.get(key) or {}
            if info.get("state") in _UNUSABLE_KEY_STATES:
                unusable.append({"vault": v.get("BackupVaultName", ""), "account_id": v.get("account_id", ""),
                                 "region": v.get("region", ""), "state": info["state"], "recovery_points": count})
    policies = [vault_policy_findings(v, known_accounts | {v.get("account_id", "")}) for v in vaults]
    with_policy = [x for x in policies if x["state"] == "read"]
    external = [{"vault": v.get("BackupVaultName", ""), "account_id": v.get("account_id", ""), "accounts": x["external"],
                 "any_principal": x["any_principal"]}
                for v, x in zip(vaults, policies) if x["external"] or x["any_principal"]]

    # Accounts that hold copies for others and hold no data of their own.
    resource_counts: Dict[str, int] = {}
    for r in resources:
        resource_counts[r.get("account_id", "")] = resource_counts.get(r.get("account_id", ""), 0) + 1
    destinations = {a for p in plans for a in (p.get("cross_account_dest_accounts") or ())}
    by_id = {a["Id"]: a for a in accounts}
    backup_accounts = []
    for dest in sorted(destinations):
        info = by_id.get(dest)
        backup_accounts.append({"account_id": dest, "name": (info or {}).get("Name", ""), "assessed": dest in known_accounts,
                                "ou": (info or {}).get("OUName", ""), "resources": resource_counts.get(dest, 0)})

    scan_rules = sum(1 for p in plans for rule in p.get("Rules", []) if rule.get("ScanActions"))
    scan = {"plans": len(plans), "plans_with_scan": sum(1 for p in plans if any(r.get("ScanActions") for r in p.get("Rules", []))),
            "rules_with_scan": scan_rules,
            "recovery_points": total_rp,
            "scanned": sum((v.get("rp_stats") or {}).get("scanned", 0) for v in vaults),
            "malware": sum((v.get("rp_stats") or {}).get("scan_malware", 0) for v in vaults),
            "failed": sum((v.get("rp_stats") or {}).get("scan_failed", 0) for v in vaults)}

    # Copies that leave the geographic area their source is in, for resources inferred to hold sensitive data.
    moves: Dict[Tuple[str, str], int] = {}
    sensitive_moved = 0
    for r in resources:
        if not r.get("copy_geographies"):
            continue
        if not (_SENSITIVITY_RANK.get(r.get("data_sensitivity", "INTERNAL"), 1) >= 2
                or "PII" in str(r.get("data_classes", "")).split(",")):
            continue
        sensitive_moved += 1
        src = region_geography(r.get("awsRegion", ""))
        for dest in str(r["copy_geographies"]).split("|"):
            moves[(src, dest)] = moves.get((src, dest), 0) + 1

    return {
        "vaults": len(vaults), "plans_readable": plans_readable, "org_backup_policies": org_backup_policies,
        "encryption": {"kinds": kinds, "unusable_keys": unusable, "recovery_points": total_rp,
                       "unencrypted_recovery_points": unencrypted_rp, "unencrypted_snapshots": unencrypted_snapshots,
                       "keys_unknown": sum(1 for k, i in key_info.items() if not i.get("state"))},
        "policies": {"readable": len(with_policy), "unreadable": sum(1 for x in policies if x["state"] == "unreadable"),
                     "none": sum(1 for x in policies if x["state"] == "none"),
                     "deny_delete": sum(1 for x in with_policy if "backup:DeleteRecoveryPoint" in x["denied"]),
                     "deny_all_three": sum(1 for x in with_policy if len(x["denied"]) == len(_POLICY_ACTIONS)),
                     "external": external},
        "scp": scp_cover, "backup_accounts": backup_accounts, "scan": scan,
        "governance": {"frameworks": [{"name": f["name"], "status": f["status"], "controls": f["controls"]} for f in frameworks or []],
                       "report_plans": len(report_plans or []), "known": governance_known},
        "residency": {"sensitive_resources_with_copy_elsewhere": sensitive_moved,
                      "moves": [{"from": a, "to": b, "resources": n} for (a, b), n in sorted(moves.items(), key=lambda kv: -kv[1])]},
    }


def merge_recovery_points(maps: List[Dict[str, Dict]]) -> Dict[str, Dict]:
    """Combine per-Region (or per-account) recovery-point summaries; the same resource can have copies in several."""
    merged: Dict[str, Dict] = {}
    for m in maps:
        for rarn, e in (m or {}).items():
            cur = merged.get(rarn)
            if cur is None:
                merged[rarn] = {**e, "vault_accounts": list(e["vault_accounts"]), "vault_regions": list(e["vault_regions"]),
                                "usable": e.get("usable", e["count"]), "points": list(e.get("points") or [])}
                continue
            cur["usable"] = cur.get("usable", cur["count"]) + e.get("usable", e["count"])
            cur["points"] = list(cur.get("points") or []) + list(e.get("points") or [])
            cur["count"] += e["count"]
            cur["bytes"] += e["bytes"]
            cur["held"] += e["held"]
            cur["cold"] = cur.get("cold", 0) + e.get("cold", 0)
            cur["cold_bytes"] = cur.get("cold_bytes", 0) + e.get("cold_bytes", 0)
            for key, pick in (("newest", max), ("oldest", min)):
                values = [x for x in (cur[key], e[key]) if x]
                cur[key] = pick(values) if values else ""
            for key in ("vault_accounts", "vault_regions"):
                cur[key] += [x for x in e[key] if x not in cur[key]]
    return merged


def attach_recovery_point_totals(resources: List[Dict], points: Dict[str, Dict]) -> None:
    """Put each resource's AWS Backup recovery point count and stored size on the resource, from the merged summary.  Sizes are
    what AWS Backup reports for each recovery point (BackupSizeInBytes); for DynamoDB every recovery point is a full copy."""
    for r in resources:
        e = (points or {}).get(r.get("arn", "")) or {}
        r["rp_count"] = int(e.get("count") or 0)
        r["rp_gib"] = round((e.get("bytes") or 0) / 1024 ** 3, 2)
        r["rp_cold_count"] = int(e.get("cold") or 0)
        # DynamoDB: the date and size of each usable recovery point, so Waste can count those kept past the retention target.
        r["rp_points"] = list(e.get("points") or []) if r.get("resourceType") == "AWS::DynamoDB::Table" else []


# ─────────────────────────────────────────────────────────────────────────────
# S3 size collection via CloudWatch
# ─────────────────────────────────────────────────────────────────────────────

def collect_s3_sizes(session: boto3.Session) -> Dict[str, float]:
    """Return {bucket_name: size_gib} using CloudWatch BucketSizeBytes metric.

    S3 does not expose bucket size via the S3 API.  CloudWatch publishes a daily
    BucketSizeBytes metric in the *bucket's own region* (not us-east-1), with a
    separate StorageType dimension per storage class.  This function:
      1. Gets each bucket's region via GetBucketLocation.
      2. Uses ListMetrics to discover which (bucket, StorageType) pairs exist,
         avoiding blind queries for 23+ storage classes.
      3. Batches GetMetricData at up to 500 queries per call.
      4. Sums across all storage classes per bucket.
    """
    try:
        clients = S3Clients(session)
        buckets = [b["Name"] for b in clients.get().list_buckets().get("Buckets", [])]
    except _AWS_ERRORS as e:
        note_failure(e, "us-east-1", "s3", "list_buckets")
        return {}
    if not buckets:
        return {}

    # Step 1: Resolve each bucket's region.
    def locate(name: str) -> str:
        try:
            return clients.get().get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
        except _AWS_ERRORS as e:
            note_failure(e, "us-east-1", "s3", "get_bucket_location", subject=f"arn:aws:s3:::{name}")
            return "us-east-1"

    bucket_regions: Dict[str, str] = {
        name: region or "us-east-1"
        for name, region in zip(buckets, parallel_map(locate, buckets, ITEM_WORKERS, "s3-location"))}

    # Step 2: Group buckets by region for efficient CloudWatch queries.
    from collections import defaultdict
    region_buckets: Dict[str, List[str]] = defaultdict(list)
    for name, region in bucket_regions.items():
        region_buckets[region].append(name)

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=3)
    sizes: Dict[str, float] = {}

    def region_sizes(region: str) -> Dict[str, float]:
        region_bucket_list = region_buckets[region]
        sizes: Dict[str, float] = {}
        cw = client_for(session, "cloudwatch", region)

        # Step 3: Discover which (bucket, StorageType) pairs publish metrics.
        metric_pairs: List[Tuple[str, str]] = []
        try:
            lm_paginator = cw.get_paginator("list_metrics")
            for page in lm_paginator.paginate(
                Namespace="AWS/S3", MetricName="BucketSizeBytes"
            ):
                for m in page.get("Metrics", []):
                    dims = {d["Name"]: d["Value"] for d in m.get("Dimensions", [])}
                    bname = dims.get("BucketName", "")
                    stype = dims.get("StorageType", "")
                    if bname in region_bucket_list and stype:
                        metric_pairs.append((bname, stype))
        except _AWS_ERRORS as e:
            note_failure(e, region, "cloudwatch", "list_metrics")
            for name in region_bucket_list:
                metric_pairs.append((name, "StandardStorage"))

        if not metric_pairs:
            return sizes

        # Step 4: Batch GetMetricData, up to 500 queries per call.
        chunk_size = 450
        for i in range(0, len(metric_pairs), chunk_size):
            chunk = metric_pairs[i : i + chunk_size]
            queries = [
                {
                    "Id": f"m{j}",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/S3",
                            "MetricName": "BucketSizeBytes",
                            "Dimensions": [
                                {"Name": "BucketName", "Value": bname},
                                {"Name": "StorageType", "Value": stype},
                            ],
                        },
                        "Period": 86400,
                        "Stat": "Average",
                    },
                    "ReturnData": True,
                }
                for j, (bname, stype) in enumerate(chunk)
            ]
            try:
                resp = cw.get_metric_data(
                    MetricDataQueries=queries, StartTime=start, EndTime=end
                )
                for result in resp.get("MetricDataResults", []):
                    idx = int(result["Id"][1:])
                    if idx < len(chunk) and result.get("Values"):
                        bname = chunk[idx][0]
                        gib = result["Values"][-1] / (1024 ** 3)
                        sizes[bname] = sizes.get(bname, 0.0) + gib
            except _AWS_ERRORS as e:
                note_failure(e, region, "cloudwatch", "get_metric_data")
        return sizes

    bucket_region_list = list(region_buckets)
    for part in parallel_map(region_sizes, bucket_region_list, REGION_WORKERS, "s3-sizes"):
        for bname, gib in (part or {}).items():
            sizes[bname] = sizes.get(bname, 0.0) + gib

    return sizes


# ─────────────────────────────────────────────────────────────────────────────
# Cost data
# ─────────────────────────────────────────────────────────────────────────────

# Cost Explorer's own SERVICE names.  They differ from boto3's and from the console's: it is
# "Amazon Relational Database Service", not "Amazon RDS", and EBS snapshots bill under "EC2 - Other",
# not "Amazon Elastic Compute Cloud - Compute".  A name that does not match returns nothing, so these
# were checked against a real account's billing data.  S3 is deliberately absent: Cost Explorer has no
# usage type for noncurrent versions, so S3 spend cannot be split into "protection" and "other".
CE_BACKUP_SERVICES = (
    "AWS Backup", "Amazon Relational Database Service", "Amazon Neptune",
    "Amazon DocumentDB (with MongoDB compatibility)", "Amazon DynamoDB", "EC2 - Other",
)
_CE_DATABASE_SERVICES = {"Amazon Relational Database Service", "Amazon Neptune",
                         "Amazon DocumentDB (with MongoDB compatibility)"}


def classify_cost(service: str, usage_type: str) -> Optional[str]:
    """Which protection mechanism a Cost Explorer (service, usage type) pair pays for, or None.

    Decided by service first.  A usage type such as USE2-WarmStorage-ByteHrs-S3 never contains the
    word "backup", and DynamoDB's TimedBackupStorage belongs to DynamoDB, not to AWS Backup, so a
    keyword search over every usage type misfiles both."""
    ut = usage_type.lower()
    if service == "AWS Backup":
        # AWS names logically air-gapped vault storage with a -LAGV suffix, for example USE1-WarmStorage-ByteHrs-EBS-LAGV
        if ut.endswith("-lagv") or "airgap" in ut or "air-gap" in ut or "logically" in ut:
            return "aws_backup_airgap"
        if "coldstorage" in ut:
            return "aws_backup_cold"
        if "-rt-" in f"-{ut}-" or "recoverypoint-fixedfee" in ut:
            return "aws_backup_restore_testing"
        if "warmstorage" in ut:
            return "aws_backup_warm"
        return "aws_backup_other"
    if service in _CE_DATABASE_SERVICES:
        return "rds_backup" if ("backupusage" in ut or "snapshot" in ut) else None
    if service == "Amazon DynamoDB":
        if "pitr" in ut:
            return "dynamodb_pitr"
        return "dynamodb_ondemand" if "backupstorage" in ut else None
    if service == "EC2 - Other":
        # EBS:SnapshotArchiveStorage, SnapshotArchiveRetrieval and SnapshotArchiveEarlyDelete are the archive tier.
        if "snapshotarchive" in ut:
            return "ebs_snapshot_archive"
        return "ebs_snapshot" if ("snapshot" in ut and "ebs" in ut) else None
    return None


def cost_windows(start, end, max_days: int = 360) -> List[Tuple[Any, Any]]:
    """Split [start, end) into windows Cost Explorer will accept (it limits monthly data to 12 months)."""
    windows, cursor = [], start
    while cursor < end:
        stop = min(cursor + timedelta(days=max_days), end)
        windows.append((cursor, stop))
        cursor = stop
    return windows


def _cost_pages(ce, **kwargs):
    """Every page of a get_cost_and_usage call.  Large organizations return a NextPageToken."""
    token = None
    while True:
        if token:
            kwargs["NextPageToken"] = token
        resp = ce.get_cost_and_usage(**kwargs)
        yield resp
        token = resp.get("NextPageToken")
        if not token:
            return


def _warn_about_unmapped_backup_services(ce, start, end) -> None:
    """Cost Explorer renames services occasionally.  One call lists the names in use, and a name that
    mentions backup but is not one we map is reported, so new spend is not silently dropped."""
    try:
        resp = ce.get_dimension_values(TimePeriod={"Start": str(start), "End": str(end)}, Dimension="SERVICE")
    except _AWS_ERRORS as e:
        note_failure(e, "us-east-1", "ce", "get_dimension_values")
        return
    for item in resp.get("DimensionValues", []):
        name = item.get("Value", "")
        if "backup" in name.lower() and name not in CE_BACKUP_SERVICES:
            warn(f"Cost Explorer lists a backup-related service this report does not map: {name!r}. "
                 "Its spend is not included.")


def collect_costs(
    mgmt_session: boto3.Session, account_ids: List[str]
) -> Dict[str, Any]:
    """Pull trailing-30-day backup-related costs from Cost Explorer (actual billed cost)."""
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=COST_LOOKBACK_DAYS)
    ce = mgmt_session.client("ce", region_name="us-east-1")
    _warn_about_unmapped_backup_services(ce, start, end)

    costs: Dict[str, Dict] = {}
    for svc in CE_BACKUP_SERVICES:
        try:
            for window_start, window_end in cost_windows(start, end):
                for resp in _cost_pages(
                    ce,
                    TimePeriod={"Start": str(window_start), "End": str(window_end)},
                    Granularity="MONTHLY",
                    Filter={"Dimensions": {"Key": "SERVICE", "Values": [svc]}},
                    GroupBy=[
                        {"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"},
                        {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
                    ],
                    Metrics=["UnblendedCost"],
                ):
                    for result in resp.get("ResultsByTime", []):
                        for group in result.get("Groups", []):
                            keys = group.get("Keys", [])
                            acct = keys[0] if len(keys) > 0 else "unknown"
                            usage = keys[1] if len(keys) > 1 else ""
                            amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                            if amount > 0:
                                # A 30-day window almost always spans two calendar months and MONTHLY
                                # granularity returns one row per month, so amounts are added.
                                bucket = costs.setdefault(acct, {}).setdefault(svc, {})
                                bucket[usage] = bucket.get(usage, 0.0) + amount
        except _AWS_ERRORS as e:
            note_failure(e, "us-east-1", "ce", "get_cost_and_usage")

    return costs


def allocate_costs(raw_costs: Dict[str, Any], resources: List[Dict]) -> Tuple[Dict[str, Dict], Dict[str, float]]:
    """Allocate Cost Explorer spend to protection mechanisms, and total it per account.

    Returns (mechanisms, account_monthly).  Spend is actual billed cost for the trailing 30 days;
    `annual` is that times 12, an estimate.  `gib` is the size of the resources the mechanism was
    found on, and is 0 where no resource field says so."""
    mechanisms: Dict[str, Dict] = {
        "dynamodb_pitr":    {"label": "DynamoDB point-in-time recovery",        "monthly": 0, "gib": 0, "rate": 0.20,  "annual": 0},
        "dynamodb_ondemand":{"label": "DynamoDB on-demand backups",             "monthly": 0, "gib": 0, "rate": 0.10,  "annual": 0},
        "rds_backup":       {"label": "Database backup beyond free tier (RDS, Aurora, Neptune, DocumentDB)", "monthly": 0, "gib": 0, "rate": 0.095, "annual": 0},
        "ebs_snapshot":     {"label": "EBS snapshots",                           "monthly": 0, "gib": 0, "rate": 0.05,  "annual": 0},
        "ebs_snapshot_archive": {"label": "EBS Snapshots Archive (storage, restores and early deletion)", "monthly": 0, "gib": 0,
                                 "rate": 0.0125, "annual": 0},
        "aws_backup_warm":  {"label": "AWS Backup, warm storage",                "monthly": 0, "gib": 0, "rate": 0.05,  "annual": 0},
        "aws_backup_cold":  {"label": "AWS Backup, cold storage",                "monthly": 0, "gib": 0, "rate": 0.01,  "annual": 0},
        "aws_backup_airgap":{"label": "AWS Backup, logically air-gapped vault",  "monthly": 0, "gib": 0, "rate": 0.0575, "annual": 0},
        "aws_backup_restore_testing": {"label": "AWS Backup, restore testing",   "monthly": 0, "gib": 0, "rate": None,  "annual": 0},
        "aws_backup_other": {"label": "AWS Backup, other (search, indexing)",    "monthly": 0, "gib": 0, "rate": None,  "annual": 0},
    }

    account_monthly: Dict[str, float] = {}
    for acct_id, svc_map in raw_costs.items():
        for svc, usage_map in svc_map.items():
            for usage_type, amount in usage_map.items():
                mechanism = classify_cost(svc, usage_type)
                if mechanism:
                    mechanisms[mechanism]["monthly"] += amount
                    account_monthly[acct_id] = account_monthly.get(acct_id, 0.0) + amount

    # Size of what each mechanism protects, from the resources it was found on.
    for r in resources:
        size = r.get("size_gib", 0) or 0
        if r.get("native_mechanism") == "dynamodb_pitr" and r.get("has_native_protection"):
            mechanisms["dynamodb_pitr"]["gib"] += size
        if (r.get("native_mechanism") in ("rds_automated_backup", "aurora_automated_backup")
                and r.get("has_native_protection")):
            mechanisms["rds_backup"]["gib"] += size
        if r.get("has_backup_recovery_point"):
            mechanisms["aws_backup_warm"]["gib"] += size

    for info in mechanisms.values():
        info["annual"] = info["monthly"] * 12
    return mechanisms, account_monthly


# ─────────────────────────────────────────────────────────────────────────────
# Governance / SCP checks
# ─────────────────────────────────────────────────────────────────────────────

# The actions that would let someone delete or weaken backups.  A service control policy that denies them is a
# guardrail whoever holds the credentials; one that merely mentions them may allow them.
PROTECTED_ACTIONS = (
    "backup:DeleteRecoveryPoint", "backup:DeleteBackupVault", "backup:DeleteBackupPlan",
    "backup:UpdateRecoveryPointLifecycle", "backup:DeleteBackupVaultLockConfiguration",
    "backup:PutBackupVaultAccessPolicy", "kms:ScheduleKeyDeletion", "kms:DisableKey",
    "ec2:DeleteSnapshot", "rds:DeleteDBSnapshot", "rds:DeleteDBClusterSnapshot", "dynamodb:DeleteBackup",
    "dynamodb:UpdateContinuousBackups", "s3:PutBucketVersioning", "s3:PutLifecycleConfiguration",
)


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else [str(v) for v in value]


def _action_matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def scp_denied_actions(content: Dict) -> Tuple[List[str], bool]:
    """(protected actions this policy denies, whether any such Deny carries a Condition).

    Only `Effect: Deny` counts.  A `Deny` with `NotAction` denies everything except the listed actions."""
    denied: set = set()
    conditional = False
    statements = content.get("Statement", [])
    for st in [statements] if isinstance(statements, dict) else statements:
        if not isinstance(st, dict) or st.get("Effect") != "Deny":
            continue
        if "Action" in st:
            hits = {a for a in PROTECTED_ACTIONS if any(_action_matches(pat, a) for pat in _as_list(st["Action"]))}
        elif "NotAction" in st:
            hits = {a for a in PROTECTED_ACTIONS if not any(_action_matches(pat, a) for pat in _as_list(st["NotAction"]))}
        else:
            continue
        if hits and st.get("Condition"):
            conditional = True
        denied |= hits
    return sorted(denied), conditional


def collect_scps(mgmt_session: boto3.Session) -> List[Dict]:
    """Service control policies that deny backup-protection actions, with where each one is attached.

    An SCP that allows or only mentions those actions is not listed.  One that is attached nowhere is listed
    with no targets, because it protects nothing yet."""
    org = mgmt_session.client("organizations")
    try:
        scps = paginate(org, "list_policies", "Policies", Filter="SERVICE_CONTROL_POLICY")
        found = []
        for scp in scps:
            try:
                detail = org.describe_policy(PolicyId=scp["Id"])
                content = json.loads(detail["Policy"]["Content"])
            except _AWS_ERRORS as e:
                note_failure(e, "us-east-1", "organizations", "describe_policy")
                continue
            except json.JSONDecodeError:
                record_gap("us-east-1", "organizations:describe_policy", "Error:JSONDecodeError",
                           subject=scp.get("Id", ""))
                continue
            denied, conditional = scp_denied_actions(content)
            if not denied:
                continue
            targets = paginate(org, "list_targets_for_policy", "Targets", PolicyId=scp["Id"])
            found.append({**scp, "denied_actions": denied, "conditional": conditional,
                          "targets": [{"id": t.get("TargetId", ""), "type": t.get("Type", ""), "name": t.get("Name", "")}
                                      for t in targets]})
        return found
    except _AWS_ERRORS as e:
        note_failure(e, "us-east-1", "organizations", "list_policies")
        return []


def collect_org_backup_policies(mgmt_session: boto3.Session) -> Dict[str, Any]:
    """Organizations backup policies: how many exist, what plans they define, how they pick resources, and where they are attached.

    Facts only.  "Enabled" is whether the organization has the backup policy type at all; a policy type that is not enabled is an
    answer ("none"), not a gap.  The policy's own text is read only to count its plans and see whether it selects by tag or by
    resource; the text is not kept."""
    org = mgmt_session.client("organizations")
    policies: List[Dict] = []
    token = None
    try:
        while True:
            resp = org.list_policies(Filter="BACKUP_POLICY", **({"NextToken": token} if token else {}))
            policies += resp.get("Policies", [])
            token = resp.get("NextToken")
            if not token:
                break
    except botocore.exceptions.ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("PolicyTypeNotEnabledException", "PolicyTypeNotAvailableForOrganizationException"):
            return {"known": True, "enabled": False, "policies": []}
        note_failure(e, "us-east-1", "organizations", "list_policies")
        return {"known": False, "enabled": None, "policies": []}
    except botocore.exceptions.BotoCoreError as e:
        note_failure(e, "us-east-1", "organizations", "list_policies")
        return {"known": False, "enabled": None, "policies": []}
    known = True
    out: List[Dict] = []
    for pol in policies:
        entry: Dict[str, Any] = {"name": clean_text(pol.get("Name", ""), 80), "plans": [], "selects_by": [], "targets": {}, "readable": True}
        try:
            content = json.loads(org.describe_policy(PolicyId=pol["Id"])["Policy"]["Content"])
            for plan_name, plan in (content.get("plans") or {}).items():
                entry["plans"].append(clean_text(plan_name, 60))
                for kind in ("tags", "resources"):
                    if (plan.get("selections") or {}).get(kind) and kind not in entry["selects_by"]:
                        entry["selects_by"].append(kind)
        except _AWS_ERRORS as e:
            entry["readable"] = False
            known = False
            note_failure(e, "us-east-1", "organizations", "describe_policy")
        except (ValueError, AttributeError, TypeError):
            entry["readable"] = False
        for target in paginate(org, "list_targets_for_policy", "Targets", PolicyId=pol["Id"]):
            kind = target.get("Type", "")
            entry["targets"][kind] = entry["targets"].get(kind, 0) + 1
        out.append(entry)
    return {"known": known, "enabled": True, "policies": out}


def scp_coverage(scps: List[Dict], accounts: List[Dict], management_account: str = "") -> Dict[str, Any]:
    """For each protected action, how many accounts have it denied by an attached SCP.

    An SCP applies to an account when it is attached to the account, to any OU above it, or to the root.  SCPs never
    apply to the management account, so it is left out of the denominator."""
    scoped = [a for a in accounts if a["Id"] != management_account]
    per_action = {act: 0 for act in PROTECTED_ACTIONS}
    uncovered: List[str] = []
    for acct in scoped:
        reach = set(acct.get("OUChain", [])) | {acct["Id"]}
        denied_here: set = set()
        for scp in scps:
            if any(t["id"] in reach for t in scp["targets"]):
                denied_here |= set(scp["denied_actions"])
        for act in denied_here:
            per_action[act] += 1
        if not denied_here:
            uncovered.append(acct["Id"])
    return {"accounts": len(scoped), "per_action": per_action, "accounts_with_none": uncovered,
            "unattached": [x["Name"] or x["Id"] for x in scps if not x["targets"]],
            "scps": [{"name": x.get("Name", ""), "denied": len(x["denied_actions"]), "targets": len(x["targets"]),
                      "conditional": x["conditional"]} for x in scps],
            "management_account_excluded": any(a["Id"] == management_account for a in accounts)}


# ─────────────────────────────────────────────────────────────────────────────
# Multi-party approval (MPA)
# ─────────────────────────────────────────────────────────────────────────────

def collect_mpa_state(session: boto3.Session) -> Dict:
    """Check whether AWS Multi-Party Approval is configured on any backup vault.

    MPA is hardening rung 07: it provides an independent authorization path
    so vault contents remain reachable even when the primary identity path is
    unavailable. Previously this rung was hardcoded as 'Not configured'.
    """
    try:
        mpa = session.client("mpa", region_name="us-east-1", config=_RETRY_CONFIG)
        teams = paginate(mpa, "list_approval_teams", "ApprovalTeams")
        return {"configured": bool(teams), "team_count": len(teams)}
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        # A boto3 too old to know the service, or a TLS/endpoint failure, must not abort
        # the run after every account has already been collected.
        record_gap("us-east-1", "mpa:list_approval_teams", _gap_status(e) or "Error")
        return {"configured": False, "team_count": 0, "assessed": False}


# ─────────────────────────────────────────────────────────────────────────────
# Iceberg / S3 Tables detection
# ─────────────────────────────────────────────────────────────────────────────

def collect_iceberg_tables(
    session: boto3.Session, account_id: str, regions: List[str]
) -> List[Dict]:
    """Find Iceberg tables from the two catalogs that expose them to a metadata-only role.

    Glue tables with table_type=ICEBERG sit on general-purpose S3 buckets; S3 Tables live
    in table buckets.  Neither exposes a table size, and S3 object listing is deliberately
    not used (the role cannot list or read objects), so size is reported as not measured.
    Iceberg tables registered in no catalog the role can read are invisible.
    """
    def one_region(region: str) -> List[Dict]:
        tables: List[Dict] = []
        # Glue catalog tables with Iceberg format
        try:
            glue = client_for(session, "glue", region)
            dbs = paginate(glue, "get_databases", "DatabaseList")
            for db in dbs:
                db_name = db["Name"]
                glue_tables = paginate(glue, "get_tables", "TableList",
                                       DatabaseName=db_name)
                for t in glue_tables:
                    fmt = (t.get("Parameters", {}).get("table_type", "") or
                           t.get("StorageDescriptor", {}).get("InputFormat", ""))
                    if any(f.upper() in fmt.upper() for f in ICEBERG_TABLE_FORMATS):
                        size_bytes = int(t.get("Parameters", {}).get("size_in_bytes", 0) or 0)
                        location = t.get("StorageDescriptor", {}).get("Location", "")
                        s3_bucket = ""
                        if location.startswith(("s3://", "s3a://")):
                            s3_bucket = location.split("://", 1)[1].split("/")[0]
                        tables.append({
                            "name": t["Name"],
                            "database": db_name,
                            "region": region,
                            "account_id": account_id,
                            "type": "glue_iceberg",
                            "arn": f"arn:aws:glue:{region}:{account_id}:table/{db_name}/{t['Name']}",
                            "location": location,
                            "size_gib": size_bytes / (1024 ** 3),
                            "size_measured": size_bytes > 0,
                            "s3_bucket": s3_bucket,
                        })
        except _AWS_ERRORS as e:
            note_failure(e, region, "glue", "get_databases")

        # S3 Tables (native table buckets)
        try:
            s3t = client_for(session, "s3tables", region)
            buckets = paginate(s3t, "list_table_buckets", "tableBuckets")
            for b in buckets:
                inner = paginate(s3t, "list_tables", "tables",
                                 tableBucketARN=b["arn"])
                for t in inner:
                    namespace = ".".join(t.get("namespace") or [])
                    tables.append({
                        "name": t.get("name", ""),
                        "database": b.get("name", ""),
                        "namespace": namespace,
                        "region": region,
                        "account_id": account_id,
                        "type": "s3_tables",
                        "arn": t.get("tableARN", ""),
                        "size_gib": 0,
                        "size_measured": False,
                    })
        except _AWS_ERRORS as e:
            note_failure(e, region, "s3tables", "list_table_buckets")

        return tables

    return [t for part in parallel_map(one_region, regions, REGION_WORKERS, "iceberg")
            for t in (part or [])]


def iceberg_resources(tables: List[Dict], account_id: str) -> List[Dict]:
    """Turn Iceberg catalog entries into inventory rows, one per table."""
    rows: List[Dict] = []
    for t in tables:
        if t.get("type") == "glue_iceberg":
            rtype = ICEBERG_GLUE_TYPE
            name = f"{t.get('database', '')}.{t.get('name', '')}"
        else:
            rtype = S3_TABLES_TYPE
            ns = t.get("namespace", "")
            name = f"{t.get('database', '')}/{ns + '.' if ns else ''}{t.get('name', '')}"
        rows.append(_make_resource(
            t.get("account_id") or account_id, t.get("region", ""), rtype, name, [],
            arn=t.get("arn", ""),
            meta={"SizeGiB": 0, "SizeMeasured": False,
                  "Bucket": t.get("s3_bucket", ""), "Location": t.get("location", "")},
        ))
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Analysis
# ─────────────────────────────────────────────────────────────────────────────

# Words that name an environment.  Used on account names and OU paths as well as resource names.
_ENV_PROD_WORDS = frozenset({"prod", "prd", "production", "live"})
_ENV_DEV_WORDS = frozenset({"dev", "development", "test", "testing", "staging", "stage", "sandbox",
                            "demo", "qa", "uat", "nonprod", "preprod"})
# "non-prod" and "pre-prod" must not be read as "prod": the hyphen splits them into a word that is.
_NONPROD_RE = re.compile(r"(?<![a-z0-9])(non|pre)[-_. ]?prod(uction)?(?![a-z0-9])")


def _environment_in(text: str) -> Optional[Tuple[str, str]]:
    """(criticality, word) when the text names exactly one kind of environment, else None.

    A name that carries both kinds ("prod-test") says nothing reliable, so it gives no signal."""
    lowered = (text or "").lower()
    if _NONPROD_RE.search(lowered):
        return "development", "nonprod"
    tokens = [t for t in re.split(r"[^a-z0-9]+", lowered) if t]
    prod = [t for t in tokens if t in _ENV_PROD_WORDS]
    dev = [t for t in tokens if t in _ENV_DEV_WORDS]
    if prod and dev:
        return None
    if prod:
        return "production", prod[0]
    if dev:
        return "development", dev[0]
    return None


def account_environment(account: Optional[Dict]) -> Optional[Tuple[str, str, str]]:
    """(criticality, confidence, basis) from an account's OU path or name, or None.

    An OU named for an environment is a deliberate grouping, so it is high confidence.  An account
    name is a looser hint, so it is medium."""
    if not account:
        return None
    hit = _environment_in(account.get("ou_path") or account.get("ou") or "")
    if hit:
        return hit[0], "high", "account-ou"
    hit = _environment_in(account.get("name") or "")
    if hit:
        return hit[0], "medium", "account-name"
    return None


# An account's unknown resources are read as production only when most of what is already classified is,
# and only when enough is classified for "most" to mean something.
ACCOUNT_MAJORITY_SHARE = 0.8
ACCOUNT_MAJORITY_MIN_CLASSIFIED = 5


def infer_environment(resource: Dict, account: Optional[Dict] = None) -> Tuple[str, str, str]:
    """(criticality, confidence, basis): which environment a resource is in, and why.

    Signals, strongest first: the resource's own environment tag; the account's OU or name; the
    resource's name.  The basis never includes a tag value, only which signal decided it, so it is
    safe to print.  Account-wide inference (most of the account is production) is applied afterwards
    by infer_account_majority, because it needs every resource in the account."""
    tags = resource.get("tags", {})
    name = resource.get("resourceName") or resource.get("resourceId", "")

    for key in sorted(PRODUCTION_TAG_KEYS):
        val = tags.get(key, "").lower()
        if val in PRODUCTION_TAG_VALUES:
            return "production", "high", f"tag:{key}"
        if val in DEV_TAG_VALUES:
            return "development", "high", f"tag:{key}"

    from_account = account_environment(account)
    if from_account:
        return from_account

    lowered = name.lower()
    if _NONPROD_RE.search(lowered):
        return "development", "medium", "name:nonprod"
    parts = re.split(r"[-_.]", lowered)
    for hint in ("prod", "prd", "live", "master", "main"):
        if hint in parts:
            return "production", "medium", f"name:{hint}"
    for hint in ("dev", "test", "staging", "stage", "sandbox", "demo", "qa", "uat"):
        if hint in parts:
            return "development", "medium", f"name:{hint}"

    return "unknown", "low", "none"


def infer_criticality(resource: Dict) -> Tuple[str, str]:
    """
    Returns (criticality, confidence): criticality is 'production'|'development'|'unknown',
    confidence is 'high'|'medium'|'low'.
    """
    criticality, confidence, _ = infer_environment(resource)
    return criticality, confidence


def infer_account_majority(resources: List[Dict]) -> int:
    """Read an account's still-unknown resources as production when most of the account already is.

    Only resources classified by their own tag or name count toward "most": a resource classified by
    the account's name would make the test circular.  Returns how many resources were changed."""
    own = [r for r in resources
           if r.get("criticality") in ("production", "development")
           and str(r.get("criticality_basis", "")).split(":")[0] in ("tag", "name")]
    if len(own) < ACCOUNT_MAJORITY_MIN_CLASSIFIED:
        return 0
    production = sum(1 for r in own if r["criticality"] == "production")
    if production / len(own) < ACCOUNT_MAJORITY_SHARE:
        return 0
    changed = 0
    for r in resources:
        if r.get("criticality") == "unknown":
            r["criticality"], r["criticality_confidence"] = "production", "medium"
            r["criticality_basis"] = f"account-majority:{production}/{len(own)}"
            changed += 1
    return changed


def infer_sensitivity(resource: Dict) -> Tuple[str, List[str], str]:
    """
    Returns (sensitivity_level, data_classes, sensitivity_basis).

    sensitivity_basis is "explicit" when a data-classification tag drove the
    result, "inferred" when name/tag-pattern matching did, or "default" when
    no signal was found.  High-severity posture controls should only be applied
    to explicit or strong-signal resources.

    Levels (highest wins): HIGH_RISK_CONFIDENTIAL > CONFIDENTIAL > INTERNAL > PUBLIC
    No new API calls — everything is already collected before this runs.
    """
    tags = resource.get("tags", {})
    name = (resource.get("resourceName") or resource.get("resourceId", "")).lower()
    level = "INTERNAL"
    basis = "default"
    data_classes: List[str] = []

    def _elevate(new_level: str, new_basis: str) -> None:
        nonlocal level, basis
        if _SENSITIVITY_RANK.get(new_level, 0) > _SENSITIVITY_RANK.get(level, 0):
            level = new_level
            basis = new_basis

    def _add_class(cls: str) -> None:
        if cls not in data_classes:
            data_classes.append(cls)

    # Explicit data-classification tag — highest confidence, no inference needed.
    for tag_key in ("data-classification", "DataClassification", "data_classification",
                    "sensitivity", "Sensitivity", "data-sensitivity"):
        val = tags.get(tag_key, "").lower()
        if val in ("restricted", "high-risk-confidential", "secret", "top-secret"):
            _elevate("HIGH_RISK_CONFIDENTIAL", "explicit")
        elif val in ("confidential", "sensitive", "internal-confidential"):
            _elevate("CONFIDENTIAL", "explicit")
        elif val == "public":
            _elevate("PUBLIC", "explicit")

    # Scan only tag VALUES for keys that describe the resource's data or purpose.
    # Scanning all keys causes false positives: "team=platform" → HIGH_RISK_CONFIDENTIAL
    # because "platform" matches _HIGH_RISK_TOKENS. Operational metadata keys are excluded.
    tag_values = " ".join(
        v for k, v in tags.items() if k.lower() in _SENSITIVITY_SCAN_TAG_KEYS
    ).lower()
    search = f"{tag_values} {name}"
    for token in re.split(r"[\s\-_/\.]+", search):
        if not token:
            continue
        if token in _HIGH_RISK_TOKENS:
            _elevate("HIGH_RISK_CONFIDENTIAL", "inferred")
            _add_class(_DATA_CLASS_TOKENS.get(token, "admin_access"))
        elif token in _CONFIDENTIAL_TOKENS:
            _elevate("CONFIDENTIAL", "inferred")
            _add_class(_DATA_CLASS_TOKENS.get(token, "sensitive"))

    if not data_classes:
        data_classes.append("general")
    return level, data_classes, basis


# ─────────────────────────────────────────────────────────────────────────────
# Classification: environment, sensitivity, overrides and documented exclusions
# ─────────────────────────────────────────────────────────────────────────────
# What the tool infers is a proposal.  An overrides file lets the customer correct it without tagging
# anything, and also record a decision not to protect a resource ("documented exclusion"), which is
# different from a resource nobody ever looked at.

EXCLUSION_TAG_PREFIX = "backup:exclude-"          # <prefix>reason, <prefix>owner, <prefix>review-date
_OVERRIDE_CRITICALITY = {"production", "development", "unknown"}
_TRUE_WORDS = {"true", "yes", "y", "1"}
_TEXT_LIMIT = 200


def clean_text(value: Any, limit: int = _TEXT_LIMIT) -> str:
    """Free text from a tag or file, for display: control characters out, length capped.

    The text is written by people and can be anything.  This keeps it short and printable; the report
    and CSV writers still escape it for their own formats."""
    text = "".join(ch if ch.isprintable() else " " for ch in str(value or ""))
    return " ".join(text.split())[:limit]


def _parse_date(value: Any, where: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return datetime.strptime(text[:10], "%Y-%m-%d").date().isoformat()
    except ValueError:
        raise ValueError(f"{where}: review_date '{clean_text(text, 30)}' is not a date in YYYY-MM-DD form")


def _clean_override(raw: Dict, where: str) -> Dict:
    out: Dict[str, Any] = {}
    crit = str(raw.get("criticality") or "").strip().lower()
    if crit:
        if crit not in _OVERRIDE_CRITICALITY:
            raise ValueError(f"{where}: criticality must be production, development or unknown, not '{clean_text(crit, 30)}'")
        out["criticality"] = crit
    sens = str(raw.get("data_sensitivity") or "").strip().upper()
    if sens:
        if sens not in _SENSITIVITY_RANK:
            raise ValueError(f"{where}: data_sensitivity must be one of {', '.join(_SENSITIVITY_RANK)}, not '{clean_text(sens, 30)}'")
        out["data_sensitivity"] = sens
    tier = str(raw.get("tier") or "").strip().lower().replace("tier-", "").replace("tier", "")
    if tier:
        if tier not in {"1", "2", "3"}:
            raise ValueError(f"{where}: tier must be 1, 2 or 3, not '{clean_text(tier, 30)}'")
        out["tier"] = int(tier)
    excluded = raw.get("excluded")
    if excluded not in (None, ""):
        out["excluded"] = excluded is True or str(excluded).strip().lower() in _TRUE_WORDS
    for key in ("reason", "owner"):
        if raw.get(key):
            out[key] = clean_text(raw[key])
    out["review_date"] = _parse_date(raw.get("review_date"), where)
    if out.get("excluded") and not out.get("reason"):
        raise ValueError(f"{where}: an exclusion needs a reason")
    return out


def load_account_names(path: str) -> Dict[str, str]:
    """Read a file of 12-digit account ID and a display name, one pair per line, into {id: name}.  A comma separates them; a header
    row (account_id,name) and blank lines are allowed.  The names are labels the reader chose, shown instead of the bare ID.
    A bad line stops the run with the file and line, before any AWS call."""
    file = Path(path)
    if not file.is_file():
        raise ValueError(f"account names file not found: {path}")
    names: Dict[str, str] = {}
    for n, line in enumerate(file.read_text(encoding="utf-8-sig").splitlines(), start=1):
        if not line.strip():
            continue
        account, _, name = line.partition(",")
        account, name = account.strip(), name.strip().strip('"').strip()
        if n == 1 and not re.fullmatch(r"[0-9]{12}", account) and account.lower() in ("account_id", "account", "id"):
            continue
        if not re.fullmatch(r"[0-9]{12}", account):
            raise ValueError(f"{file.name} line {n}: the first value must be a 12-digit account ID")
        if not name or len(name) > 64 or any(ord(c) < 32 for c in name):
            raise ValueError(f"{file.name} line {n}: the name must be 1 to 64 printable characters")
        names[account] = name
    return names


def load_overrides(path: str) -> Dict[str, Dict]:
    """Read an overrides file (CSV or JSON) into {arn: fields}.  A bad row stops the run with its line."""
    file = Path(path)
    if not file.is_file():
        raise ValueError(f"overrides file not found: {path}")
    text = file.read_text(encoding="utf-8-sig")
    rows: List[Tuple[str, Dict]] = []
    if file.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"{file.name}: not valid JSON ({e.msg} at line {e.lineno})")
        if isinstance(data, dict):
            data = [{"arn": k, **(v if isinstance(v, dict) else {})} for k, v in data.items()]
        if not isinstance(data, list):
            raise ValueError(f"{file.name}: expected a list of rows or an object keyed by ARN")
        rows = [(f"{file.name} item {i + 1}", row) for i, row in enumerate(data) if isinstance(row, dict)]
    else:
        reader = csv.DictReader(text.splitlines())
        if not reader.fieldnames or "arn" not in [f.strip().lower() for f in reader.fieldnames]:
            raise ValueError(f"{file.name}: the first row must be a header that includes an 'arn' column")
        for n, row in enumerate(reader, start=2):
            rows.append((f"{file.name} line {n}", {(k or "").strip().lower(): v for k, v in row.items()}))
    overrides: Dict[str, Dict] = {}
    for where, row in rows:
        arn = str(row.get("arn") or "").strip()
        if not arn:
            continue                     # a blank row, such as an unfilled line in the worksheet
        fields = _clean_override(row, where)
        if any(v not in ("", None) for v in fields.values()):      # a row with nothing filled in is skipped
            overrides[arn] = fields
    return overrides


def exclusion_for(resource: Dict, override: Optional[Dict], prefix: str, today) -> Dict:
    """A recorded decision not to protect this resource, from its tags or the overrides file.

    status is "" (none), "documented", or "expired" when the review date has passed.  An expired
    exclusion counts as a gap again.  An exclusion with no readable review date does not expire."""
    tags = resource.get("tags") or {}
    reason = owner = review = source = ""
    if override and override.get("excluded"):
        reason, owner, review, source = (override.get("reason", ""), override.get("owner", ""),
                                         override.get("review_date", ""), "overrides file")
    elif tags.get(f"{prefix}reason"):
        reason, owner = clean_text(tags.get(f"{prefix}reason")), clean_text(tags.get(f"{prefix}owner"), 80)
        review, source = clean_text(tags.get(f"{prefix}review-date"), 10), "tag"
    if not reason:
        return {"exclusion_status": "", "exclusion_reason": "", "exclusion_owner": "",
                "exclusion_review_date": "", "exclusion_source": ""}
    status = "documented"
    try:
        if review and datetime.strptime(review[:10], "%Y-%m-%d").date() < today:
            status = "expired"
    except ValueError:
        review = ""                     # shown as "no review date", not guessed at
    return {"exclusion_status": status, "exclusion_reason": reason, "exclusion_owner": owner,
            "exclusion_review_date": review, "exclusion_source": source}


# Signs that a database or table is in live use, from settings already read.  None is proof: a Multi-AZ database may
# be a test of the Multi-AZ setting.  They are used only where no tag, account or name said what the environment is,
# and only at low confidence.
def behaviour_signals(native: Optional[Dict]) -> List[str]:
    native = native or {}
    signals = []
    if native.get("multi_az"):
        signals.append("multi-az")
    if (native.get("cluster_members") or 0) >= 2:
        signals.append("several cluster members")
    if (native.get("avg_daily_wcu") or 0) > 0:          # only measured with --deep
        signals.append("recent writes")
    if native.get("deletion_protection") is True:       # someone chose to guard it against deletion
        signals.append("deletion protection on")
    return signals


def fold_cluster_members(resources: List[Dict]) -> Tuple[List[Dict], int]:
    """Leave out database instances that belong to a cluster that is itself in the inventory.

    An Aurora, Neptune or DocumentDB instance is backed up through its cluster, so counting both would count one database
    twice.  Returns (resources to assess, how many instances were folded into their cluster)."""
    arns = {r.get("arn", "") for r in resources}
    kept, folded = [], 0
    for r in resources:
        cluster = (r.get("meta") or {}).get("ClusterId") or ""
        if r.get("resourceType") == RDS_DB_INSTANCE and cluster:
            parts = (r.get("arn") or "").split(":")
            if len(parts) > 5 and f"arn:aws:rds:{parts[3]}:{parts[4]}:cluster:{cluster}" in arns:
                folded += 1
                continue
        kept.append(r)
    return kept, folded


def classify_resources(resources: List[Dict], account: Dict, overrides: Optional[Dict[str, Dict]] = None,
                       exclusion_prefix: str = EXCLUSION_TAG_PREFIX, today=None,
                       native_state: Optional[Dict[str, Dict]] = None) -> Dict[str, int]:
    """Set environment, sensitivity, tier override and exclusion fields on one account's resources.

    Returns what was used, so the report can say how far the classifier was corrected by hand."""
    today = today or datetime.now(timezone.utc).date()
    overrides = overrides or {}
    stats = {"overrides_used": 0, "overrides_in_production": 0, "account_majority": 0, "behaviour": 0, "mismatch": 0}
    native_state = native_state or {}
    for r in resources:
        crit, conf, basis = infer_environment(r, account)
        r["criticality"], r["criticality_confidence"], r["criticality_basis"] = crit, conf, basis
    stats["account_majority"] = infer_account_majority(resources)
    for r in resources:
        signals = behaviour_signals(native_state.get(r.get("arn", "")))
        r["behaviour_signals"] = "|".join(signals)
        r["tag_behaviour_mismatch"] = False
        if not signals:
            continue
        if r["criticality"] == "unknown":
            r["criticality"], r["criticality_confidence"] = "production", "low"
            r["criticality_basis"] = f"behaviour:{signals[0]}"
            stats["behaviour"] += 1
        elif r["criticality"] == "development" and str(r["criticality_basis"]).split(":")[0] in ("tag", "name", "account-ou", "account-name"):
            # Called development by a label, but in use like production.  Reported, not overruled.
            r["tag_behaviour_mismatch"] = True
            stats["mismatch"] += 1
    for r in resources:
        level, classes, sbasis = infer_sensitivity(r)
        r["data_sensitivity"], r["data_classes"], r["sensitivity_basis"] = level, ",".join(classes), sbasis
        r["tier_override"] = None
        override = overrides.get(r.get("arn", ""))
        if override:
            used = False
            if override.get("criticality"):
                r["criticality"], r["criticality_confidence"] = override["criticality"], "high"
                r["criticality_basis"] = "override"
                used = True
            if override.get("data_sensitivity"):
                r["data_sensitivity"], r["sensitivity_basis"] = override["data_sensitivity"], "explicit"
                used = True
            if override.get("tier"):
                r["tier_override"] = override["tier"]
                used = True
            if used:
                if override.get("criticality"):
                    r["tag_behaviour_mismatch"] = False         # the customer has said what it is
                stats["overrides_used"] += 1
                if r["criticality"] == "production":
                    stats["overrides_in_production"] += 1
        r.update(exclusion_for(r, override, exclusion_prefix, today))
    return stats


# ─────────────────────────────────────────────────────────────────────────────
# Backup plan selection matching
# ─────────────────────────────────────────────────────────────────────────────
# Semantics are taken from the AWS Backup documentation (BackupSelection and "Assign
# resources with AWS CLI"): Resources and NotResources are OR lists; Conditions are
# ANDed; ListOfTags (legacy, StringEquals only) is ORed and is an alternative to Resources;
# '*' is zero or more non-whitespace characters and may appear anywhere.

# Lock modes ordered by strength.  compliance_grace is a compliance lock still inside its
# cooling-off window, so it is stronger than governance but not yet immutable.
_LOCK_MODE_RANK = {"none": 0, "governance": 1, "compliance_grace": 2, "compliance": 3}


@lru_cache(maxsize=512)
def _glob_regex(pattern: str):
    return re.compile("".join(r"\S*" if ch == "*" else re.escape(ch) for ch in pattern))


def _glob_match(pattern: str, value: str) -> bool:
    return _glob_regex(pattern).fullmatch(value) is not None


def _condition_holds(operator: str, tag_key: str, expected: str, tags: Dict) -> Optional[bool]:
    """Evaluate one tag condition.  None means the operator is not one we understand."""
    present = tag_key in tags
    value = tags.get(tag_key, "")
    if operator == "StringEquals":
        return present and value == expected
    if operator == "StringLike":
        return present and _glob_match(expected, value)
    # Negated operators hold when the tag is absent, as in IAM condition evaluation.
    if operator == "StringNotEquals":
        return (not present) or value != expected
    if operator == "StringNotLike":
        return (not present) or not _glob_match(expected, value)
    return None


def selection_match(sel: Dict, arn: str, tags: Dict) -> Tuple[bool, str]:
    """Does one backup selection pick this resource?  Returns (matched, reason).

    reason is one of: all-resources, arn-exact, arn-wildcard, tag:<key>=<value>, conditions
    (optionally joined with '+'), or on a miss: none, excluded, unevaluable.  A selection
    whose detail could not be read, or that uses a condition we cannot evaluate, is
    "unevaluable" and never credited, so unknown never counts as covered.
    """
    if sel.get("_detail_unavailable"):
        return False, "unevaluable"
    for pattern in sel.get("NotResources") or []:
        if _glob_match(pattern, arn):
            return False, "excluded"
    resources = sel.get("Resources") or []
    list_of_tags = sel.get("ListOfTags") or []
    conditions = [(op, c) for op, items in (sel.get("Conditions") or {}).items()
                  for c in (items or [])]

    base = ""
    if resources or list_of_tags:
        for pattern in resources:
            if _glob_match(pattern, arn):
                base = ("all-resources" if pattern == "*"
                        else "arn-exact" if pattern == arn else "arn-wildcard")
                break
        if not base:
            for t in list_of_tags:
                key = t.get("ConditionKey", "")
                if key in tags and tags[key] == t.get("ConditionValue", ""):
                    base = f"tag:{key}={tags[key]}"
                    break
        if not base:
            return False, "none"
    elif not conditions:
        base = "all-resources"          # no filter at all: AWS selects everything opted in

    for op, cond in conditions:
        ckey = cond.get("ConditionKey", "")
        if not ckey.startswith("aws:ResourceTag/"):
            return False, "unevaluable"
        held = _condition_holds(op, ckey[len("aws:ResourceTag/"):],
                                cond.get("ConditionValue", ""), tags)
        if held is None:
            return False, "unevaluable"
        if not held:
            return False, "none"
    if conditions:
        return True, f"{base}+conditions" if base else "conditions"
    return True, base


def plan_match(plan: Dict, resource: Dict) -> Tuple[bool, str]:
    """Does any selection in this plan pick the resource?  A plan only reaches resources in
    its own Region, so a plan in one Region never credits a resource in another."""
    region = resource.get("awsRegion", "")
    plan_region = plan.get("region", "")
    if plan_region:
        if not _usable_region(region):
            return False, "unknown-region"
        if plan_region != region:
            return False, "other-region"
    arn = resource.get("arn", "")
    tags = resource.get("tags") or {}
    unevaluable = False
    for sel in plan.get("Selections", []):
        matched, reason = selection_match(sel, arn, tags)
        if matched:
            return True, reason
        unevaluable = unevaluable or reason == "unevaluable"
    return False, "unevaluable" if unevaluable else "none"


# AWS Backup's name for the service each resource type belongs to in the Region opt-in settings.
_BACKUP_SERVICE_KEY = {
    "AWS::EC2::Volume": "EBS", RDS_DB_INSTANCE: "RDS", RDS_DB_CLUSTER: "RDS", RDS_AURORA: "Aurora",
    RDS_NEPTUNE: "Neptune", RDS_DOCDB: "DocumentDB", "AWS::DynamoDB::Table": "DynamoDB",
    "AWS::S3::Bucket": "S3",
}


def _is_type_specific(pattern: str) -> bool:
    """True for a selection pattern that names a resource type (arn:aws:ec2:*:*:volume/*,
    arn:aws:rds:*:*:db:*).  AWS Backup includes those whether or not the service is opted in.
    "*", a service alone (arn:aws:ec2:*) and tag-only selections do depend on the opt-in.  An S3
    pattern has no type token, so it is treated as depending on the opt-in: the cautious reading,
    since the other would credit a plan AWS may skip."""
    parts = pattern.split(":")
    return len(parts) >= 6 and parts[5] not in ("", "*") and ("/" in parts[5] or len(parts) > 6)


def plan_needs_opt_in(plan: Dict, resource: Dict) -> bool:
    """True when every selection of this plan that picks the resource relies on the service opt-in."""
    arn, tags = resource.get("arn", ""), resource.get("tags") or {}
    depends = False
    for sel in plan.get("Selections", []):
        matched, _ = selection_match(sel, arn, tags)
        if not matched:
            continue
        if any(_is_type_specific(p) and _glob_match(p, arn) for p in sel.get("Resources") or []):
            return False
        depends = True
    return depends


def _plan_covers_resource(plan: Dict, resource_arn: str, resource_type: str,
                          tags: Optional[Dict] = None, region: str = "") -> bool:
    """Boolean form of plan_match, kept for callers that only need yes or no."""
    return plan_match(plan, {"arn": resource_arn, "tags": tags or {},
                             "awsRegion": region or plan.get("region", ""),
                             "resourceType": resource_type})[0]


def _as_dt(value: Any) -> datetime:
    """Parse a boto datetime or ISO string; an unparseable value sorts as oldest."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.min.replace(tzinfo=timezone.utc)


def _backup_index(backup_state: Dict[str, Any]) -> Dict[str, Any]:
    """Index backup state once so each resource costs a lookup, not a scan of every job."""
    cached = backup_state.get("_index")
    if cached is not None:
        return cached
    protected = {r["ResourceArn"] for r in backup_state.get("protected_resources", [])
                 if r.get("ResourceArn")}
    jobs_by_arn: Dict[str, List[Dict]] = {}
    for j in backup_state.get("jobs", []):
        if j.get("ResourceArn"):
            jobs_by_arn.setdefault(j["ResourceArn"], []).append(j)
    for jobs in jobs_by_arn.values():
        jobs.sort(key=lambda j: _as_dt(j.get("CreationDate")), reverse=True)
    last_backup: Dict[str, datetime] = {}
    for r in backup_state.get("protected_resources", []):
        when = r.get("LastBackupTime")
        if r.get("ResourceArn") and when:
            when = _as_dt(when)
            if when > last_backup.get(r["ResourceArn"], when):
                last_backup[r["ResourceArn"]] = when
            last_backup.setdefault(r["ResourceArn"], when)
    index = {"protected": protected, "jobs_by_arn": jobs_by_arn, "last_backup": last_backup}
    backup_state["_index"] = index
    return index


def merge_vault_maps(maps: List[Dict[str, Dict]]) -> Dict[str, Dict]:
    """Merge per-account resource -> vault maps into one organization-wide map.

    A cross-account copy lives in a vault in the backup account, keyed by the source
    resource's ARN.  Only the merged view lets the source account's resource see it.
    """
    merged: Dict[str, Dict] = {}
    for vmap in maps:
        for arn, entry in (vmap or {}).items():
            cur = merged.get(arn)
            if cur is None:
                merged[arn] = {**entry,
                               "vault_accounts": set(entry.get("vault_accounts", ())),
                               "vault_regions": set(entry.get("vault_regions", ()))}
                continue
            cur["vault_locked"] = cur.get("vault_locked", False) or entry.get("vault_locked", False)
            cur["vault_air_gapped"] = cur.get("vault_air_gapped", False) or entry.get("vault_air_gapped", False)
            if (_LOCK_MODE_RANK.get(entry.get("vault_lock_mode", "none"), 0)
                    > _LOCK_MODE_RANK.get(cur.get("vault_lock_mode", "none"), 0)):
                cur["vault_lock_mode"] = entry["vault_lock_mode"]
            cur["recovery_point_count"] = (cur.get("recovery_point_count", 0)
                                           + entry.get("recovery_point_count", 0))
            cur["vault_accounts"] |= set(entry.get("vault_accounts", ()))
            cur["vault_regions"] |= set(entry.get("vault_regions", ()))
    return merged


# Monitoring keys.  A vault name is only unique within one account and Region, and an
# EventBridge rule only sees events from its own Region, so both are scoped.
def monitor_key(account_id: str, region: str, vault_name: str) -> str:
    return f"{account_id}:{region}:{vault_name}"


def eventbridge_key(account_id: str, region: str) -> str:
    return f"__eventbridge__:{account_id}:{region}"


def is_vault_monitored(vault: Dict, vault_alarms: Dict[str, bool]) -> bool:
    account, region = vault.get("account_id", ""), vault.get("region", "")
    return bool(vault_alarms.get(monitor_key(account, region, vault.get("BackupVaultName", "")))
                or vault_alarms.get(eventbridge_key(account, region)))


# ─────────────────────────────────────────────────────────────────────────────
# DLM attribution for EBS volumes
# ─────────────────────────────────────────────────────────────────────────────

def dlm_policies_from(native_state: Dict[str, Dict]) -> List[Dict]:
    return [v for k, v in native_state.items() if k.startswith("dlm:")]


def dlm_policy_for_volume(policies: List[Dict], region: str, tags: Dict) -> Optional[Dict]:
    """The enabled DLM snapshot policy that targets this volume, longest retention first.

    Custom policies target volumes carrying their target tags.  The AWS docs do not say
    whether several target tags must all be present or any one, so all are required: the
    stricter reading never credits a volume that may not be covered.  Default policies
    target every volume in the Region except those carrying an exclusion tag; exclusions
    on boot volumes or volume types cannot be evaluated here, so those policies are not
    credited.
    """
    best: Optional[Dict] = None
    for pol in policies:
        if not pol.get("enabled") or pol.get("region") != region:
            continue
        if pol.get("policy_type", "EBS_SNAPSHOT_MANAGEMENT") != "EBS_SNAPSHOT_MANAGEMENT":
            continue
        if "VOLUME" not in (pol.get("resource_types") or []):
            continue
        if pol.get("policy_language") == "SIMPLIFIED":
            excl = pol.get("exclusions") or {}
            if excl.get("ExcludeBootVolumes") or excl.get("ExcludeVolumeTypes"):
                continue
            if any(tags.get(t.get("Key")) == t.get("Value", "") and t.get("Key") in tags
                   for t in excl.get("ExcludeTags") or []):
                continue
        else:
            target = pol.get("target_tags") or []
            if not target or not all(t.get("Key") in tags and tags[t["Key"]] == t.get("Value", "")
                                     for t in target):
                continue
        if best is None or (pol.get("retention_days") or 0) > (best.get("retention_days") or 0):
            best = pol
    return best


def dlm_policy_for_instance_volume(policies: List[Dict], region: str, instance_tags: Dict[str, str]) -> Optional[Dict]:
    """The enabled DLM policy that targets the INSTANCE this volume is attached to, longest retention first.

    An instance policy snapshots every volume of an instance that carries all its target tags.  A policy that leaves out the boot
    volume, or data volumes carrying certain tags, is not credited, because whether this volume is one of those cannot be told here."""
    best: Optional[Dict] = None
    for pol in policies:
        if not pol.get("enabled") or pol.get("region") != region or "INSTANCE" not in (pol.get("resource_types") or []):
            continue
        if pol.get("policy_type", "EBS_SNAPSHOT_MANAGEMENT") != "EBS_SNAPSHOT_MANAGEMENT":
            continue
        params = pol.get("parameters") or {}
        if params.get("ExcludeBootVolume") or params.get("ExcludeDataVolumeTags"):
            continue
        target = pol.get("target_tags") or []
        if not target or not all(t.get("Key") in instance_tags and instance_tags[t["Key"]] == t.get("Value", "") for t in target):
            continue
        if best is None or (pol.get("retention_days") or 0) > (best.get("retention_days") or 0):
            best = pol
    return best


def _dlm_retention_days(details: Dict) -> int:
    """Retention in days.  RetainRule.Count is a number of snapshots, not days, so it is
    converted through the schedule's interval; a cron schedule has no fixed interval and
    is reported as 0 rather than mislabelling a snapshot count as days."""
    if details.get("PolicyLanguage") == "SIMPLIFIED":
        return int(details.get("RetainInterval", 7))
    best = 0
    unit_days = {"DAYS": 1, "WEEKS": 7, "MONTHS": 30, "YEARS": 365}
    for sched in details.get("Schedules", []):
        rule = sched.get("RetainRule", {})
        days = 0
        if rule.get("IntervalUnit"):
            days = int(rule.get("Interval", 0)) * unit_days.get(rule["IntervalUnit"], 0)
        elif rule.get("Count"):
            create = sched.get("CreateRule", {})
            per = {"HOURS": 1 / 24, "DAYS": 1, "WEEKS": 7, "MONTHS": 30}.get(create.get("IntervalUnit"))
            if per and create.get("Interval"):
                days = round(int(rule["Count"]) * int(create["Interval"]) * per)
        best = max(best, days)
    return best


def _s3_versioning_state(res_type: str, native: Optional[Dict]) -> str:
    """For an S3 bucket: enabled, suspended, never_enabled, or unknown when the versioning call was not answered.  Empty for
    anything else.  AWS Backup for S3 needs versioning on, so this is a fact the report can state next to a plan's selection."""
    if res_type != "AWS::S3::Bucket":
        return ""
    if not native:
        return "unknown"
    status = native.get("versioning_status")
    if status:
        return status
    return "enabled" if native.get("enabled") else "not_enabled"


def _s3_eventbridge_state(res_type: str, native: Optional[Dict]) -> str:
    """For an S3 bucket: on, off, or unknown when the notification call was not answered.  Empty for anything else."""
    if res_type != "AWS::S3::Bucket":
        return ""
    value = (native or {}).get("eventbridge_notifications")
    return "unknown" if value is None else ("on" if value else "off")


def analyze_protection(
    resource: Dict,
    native_state: Dict[str, Dict],
    backup_state: Dict[str, Any],
    iceberg_arns: set,
    dlm_policies: Optional[List[Dict]] = None,
) -> Dict:
    """
    Determine the protection profile for one resource.
    Returns a dict with protection fields to merge into the resource record.

    Three things are kept apart because they are different facts:
      has_backup_recovery_point  the resource has a recovery point in AWS Backup that can still be restored (expired and deleted
                                 ones are not evidence).  Where a vault's recovery points could not be listed, being listed by
                                 list_protected_resources is used instead and marked as unverified.  A resource dropped from a
                                 plan months ago still reads True while its copies last.
      plan_selected              a plan's selection CURRENTLY picks the resource (policy, not evidence).
      has_any_protection         a recovery copy is identified: an AWS Backup recovery point, a native snapshot or backup, or a
                                 continuous mechanism that is on.  A policy alone is not a copy, and a failing job does not
                                 remove a copy that still exists.
    """
    arn = resource.get("arn", "")
    rid = resource.get("resourceId", "")
    lookup_keys = list(dict.fromkeys(k for k in [arn, rid] if k))
    tags = resource.get("tags") or {}
    res_type = resource.get("resourceType", "")
    resource_account = resource.get("account_id", "") or resource.get("accountId", "")
    region = resource.get("awsRegion", "")
    if not _usable_region(region) and arn.count(":") >= 5:
        region = arn.split(":")[3]

    # Native mechanism
    native = None
    for k in lookup_keys:
        native = native_state.get(k)
        if native:
            break

    # AWS Backup evidence (indexed once per account, not rebuilt per resource).  The recovery points listed from every vault
    # assessed decide it; list_protected_resources returns resources "regardless of the recovery point's status", so being
    # listed there is used only where listing a vault's recovery points failed.
    index = _backup_index(backup_state)
    points = backup_state.get("org_recovery_points")
    if points is None:
        points = backup_state.get("recovery_points")
    incomplete = set(backup_state.get("recovery_points_incomplete") or ())

    def backup_evidence(keys: List[str]) -> Tuple[bool, bool, Optional[Dict]]:
        """(has a usable recovery point, evidence unverified, the merged recovery-point entry)."""
        listed = any(k in index["protected"] for k in keys)
        if points is None:                      # state collected before recovery points were read: the listing is all there is
            return listed, False, None
        for k in keys:
            e = points.get(k)
            if e and e.get("usable", e.get("count", 0)) > 0:
                return True, False, e
        if listed and region in incomplete:
            return True, True, None
        return False, False, None

    has_backup_recovery_point, backup_unverified, rp_entry = backup_evidence(lookup_keys)
    listed_without_usable_point = bool(not has_backup_recovery_point and any(k in index["protected"] for k in lookup_keys))
    # An EC2 recovery point holds a snapshot of every volume attached to the instance, so a volume whose instance has
    # recovery points is covered even though AWS Backup lists the instance, not the volume.  Only the evidence is used
    # (the instance has a recovery point); which plan selects the instance is not evaluated here.
    backup_via_instance = ""
    if res_type == "AWS::EC2::Volume" and not has_backup_recovery_point:
        attached = (resource.get("meta") or {}).get("AttachedInstance") or ""
        if attached and _usable_region(region) and resource_account:
            instance_arn = f"arn:aws:ec2:{region}:{resource_account}:instance/{attached}"
            via, via_unverified, via_entry = backup_evidence([instance_arn])
            if via:
                has_backup_recovery_point, backup_via_instance = True, instance_arn
                backup_unverified, rp_entry = via_unverified, via_entry
                listed_without_usable_point = False
                lookup_keys = lookup_keys + [instance_arn]
    jobs: List[Dict] = []
    for k in lookup_keys:
        jobs.extend(index["jobs_by_arn"].get(k, []))
    if len(lookup_keys) > 1:
        jobs.sort(key=lambda j: _as_dt(j.get("CreationDate")), reverse=True)

    # Vault / lock / air-gap status — look up the specific vault(s) this resource's
    # recovery points are stored in, rather than checking if any vault in the account
    # is locked or air-gapped.  The map is organization-wide, so a copy held in another
    # account's vault is visible here.
    is_air_gapped = False
    vault_locked = False
    vault_info = None
    resource_vault_map = backup_state.get("resource_vault_map", {})
    for k in lookup_keys:
        vault_info = resource_vault_map.get(k)
        if vault_info:
            break
    if vault_info:
        vault_locked = vault_info.get("vault_locked", False)
        is_air_gapped = vault_info.get("vault_air_gapped", False)
    vault_lock_mode = vault_info.get("vault_lock_mode", "none") if vault_info else "none"
    # Recovery point count from security-relevant (locked/air-gapped) vaults.
    # For resources in standard vaults, use successful job count as a proxy.
    if rp_entry:
        recovery_point_count = int(rp_entry.get("usable", rp_entry.get("count", 0)) or 0)
    elif vault_info and vault_info.get("recovery_point_count") is not None:
        recovery_point_count = vault_info["recovery_point_count"]
    elif has_backup_recovery_point:
        recovery_point_count = sum(1 for j in jobs if j.get("State") == "COMPLETED")
    else:
        recovery_point_count = 0

    # Which plans currently select this resource, and why.
    matching_plans: List[Dict] = []
    reasons: List[str] = []
    unevaluable = False
    for plan in backup_state.get("plans", []):
        matched, reason = plan_match(plan, resource)
        if matched:
            matching_plans.append(plan)
            reasons.append(reason)
        elif reason == "unevaluable":
            unevaluable = True

    # AWS Backup only protects a service's resources in a Region where the service is opted in, unless
    # the selection names the resource type.  A plan that picks the resource but is skipped for that
    # reason protects nothing.
    region_cfg = (backup_state.get("region_settings") or {}).get(region) or {}
    service_key = _BACKUP_SERVICE_KEY.get(res_type)
    backup_opted_in: Optional[bool] = None
    if service_key and service_key in region_cfg.get("opt_in", {}):
        backup_opted_in = bool(region_cfg["opt_in"][service_key])
    opt_in_skipped = False
    if backup_opted_in is False and matching_plans:
        kept = [(p, r) for p, r in zip(matching_plans, reasons) if not plan_needs_opt_in(p, resource)]
        opt_in_skipped = not kept
        matching_plans, reasons = [p for p, _ in kept], [r for _, r in kept]

    plan_selected = bool(matching_plans)
    # How often the plans that select this resource promise a backup.  The shortest wins: a resource
    # selected by an hourly and a monthly plan is backed up hourly.
    intervals = [h for plan in matching_plans for rule in plan.get("Rules", [])
                 for h in [schedule_interval_hours(rule.get("ScheduleExpression"))] if h]
    backup_interval_hours = min(intervals) if intervals else None
    selection_match_reason = ("not-opted-in" if opt_in_skipped
                              else reasons[0] if reasons else ("unevaluable" if unevaluable else "none"))

    # Copies.  A copy in another Region does not survive losing the Region; a copy in
    # another account is the one that survives the loss of this account's credentials, so
    # the two are tracked apart.  Only credit a resource when a plan that selects it has
    # the copy action, and only once it has a recovery point to copy.
    cross_region_copy = False
    # A copy in another account counts only when one is seen there: a recovery point in a vault of another assessed account.  A
    # plan's copy action to another account is configuration; when no copy is seen (the destination account was not assessed, or
    # the copy never completed) it is kept apart as configured, not verified.
    cross_account_configured = False
    # DynamoDB backups can only be copied to another Region or account when advanced DynamoDB backup
    # is on (both the opt-in and the management preference).  A plan's copy action does nothing otherwise.
    copy_withheld_reason = ""
    ddb_copies_unavailable = (res_type == "AWS::DynamoDB::Table"
                              and region_cfg.get("management", {}).get("DynamoDB") is False)
    if has_backup_recovery_point:
        for plan in matching_plans:
            if ddb_copies_unavailable and plan.get("copy_destinations"):
                copy_withheld_reason = "dynamodb-advanced-features-off"
                continue
            dests = plan.get("copy_destinations")
            if dests is None:                       # state collected before destinations existed
                cross_region_copy = cross_region_copy or bool(plan.get("has_copy_actions"))
                continue
            for d in dests:
                if d.get("region") and _usable_region(region) and d["region"] != region:
                    cross_region_copy = True
                if d.get("account_id") and resource_account and d["account_id"] != resource_account:
                    cross_account_configured = True
    # Direct evidence: a usable recovery point for this resource sits in another account's vault (any vault, from the
    # organization-wide recovery-point summary), or in another account's or Region's locked or air-gapped vault.
    seen_accounts = set((rp_entry or {}).get("vault_accounts") or ()) | set((vault_info or {}).get("vault_accounts") or ())
    cross_account_copy = any(a and resource_account and a != resource_account for a in seen_accounts)
    if vault_info:
        if any(r_ and _usable_region(region) and r_ != region
               for r_ in vault_info.get("vault_regions", ())):
            cross_region_copy = True

    # S3 replication
    if arn.startswith("arn:aws:s3:::") and native:
        if native.get("cross_region"):
            cross_region_copy = True
        if any(a and resource_account and a != resource_account
               for a in native.get("replication_dest_accounts", ())):
            cross_account_copy = True

    # EBS: attribute a DLM policy to the volume by its tags.  The policies are collected
    # per Region and per policy; without this match a volume never sees them.
    dlm_hit: Optional[Dict] = None
    if res_type == "AWS::EC2::Volume":
        policies = dlm_policies if dlm_policies is not None else dlm_policies_from(native_state)
        dlm_hit = dlm_policy_for_volume(policies, region, tags)
        attached = (resource.get("meta") or {}).get("AttachedInstance") or ""
        if not dlm_hit and attached:
            dlm_hit = dlm_policy_for_instance_volume(
                policies, region, (native_state.get(f"instance-tags:{region}") or {}).get(attached) or {})
        if dlm_hit and any(t and t != region for t in dlm_hit.get("cross_region_targets", ())):
            cross_region_copy = True

    # Where the copies are, as geographic areas other than the source's.
    dest_regions = {d["region"] for plan in matching_plans for d in (plan.get("copy_destinations") or []) if d.get("region")}
    if dlm_hit:
        dest_regions |= {t for t in dlm_hit.get("cross_region_targets", ()) if t}
    home_area = region_geography(region) if _usable_region(region) else ""
    copy_geographies = (sorted({region_geography(d) for d in dest_regions if region_geography(d)} - {home_area})
                        if home_area else [])

    if cross_account_copy:
        copy_scope = "cross_account"
    elif cross_region_copy:
        copy_scope = "cross_region_same_account"
    else:
        copy_scope = "none"

    # Job failure analysis — measure from the first failure in the current streak.
    job_failing = False
    consecutive_failures = 0
    job_failure_reason = ""
    if has_backup_recovery_point or plan_selected or listed_without_usable_point:
        for j in jobs:
            if j.get("State") == "FAILED":
                consecutive_failures += 1
            else:
                break
        if consecutive_failures > 0:
            threshold = datetime.now(timezone.utc) - timedelta(days=FAILING_JOB_THRESHOLD_DAYS)
            streak_first = jobs[consecutive_failures - 1].get("CreationDate")
            if streak_first and _as_dt(streak_first) < threshold:
                job_failing = True
        if job_failing:
            latest_failed = next((j for j in jobs if j.get("State") == "FAILED"), None)
            if latest_failed:
                job_failure_reason = latest_failed.get("StatusMessage", "")[:200]

    # No protection path (Iceberg/S3 Tables)
    no_backup_path = arn in iceberg_arns

    # Retention, by mechanism.  The short-term window is what a continuous mechanism keeps (point-in-time recovery, automated
    # database backups).  Long-term retention is what the policies that produce copies keep them for: a backup rule, its copy
    # actions, or a lifecycle policy.  A backup rule with no expiry keeps copies until someone deletes them ("indefinite").
    # `retention_days` stays the longest of them, as before, for the figures that need one number.
    native_enabled = bool(native and native.get("enabled")) or bool(dlm_hit)
    short_window_days = 0
    if native and native.get("enabled") and native.get("mechanism") in _CONTINUOUS_MECHANISMS:
        short_window_days = int(native.get("retention_days") or 0)
    long_term_days = 0
    long_term_indefinite = False
    if native and native.get("enabled") and native.get("mechanism") not in _CONTINUOUS_MECHANISMS:
        long_term_days = int(native.get("retention_days") or 0)
    if dlm_hit:
        long_term_days = max(long_term_days, int(dlm_hit.get("retention_days") or 0))
    if has_backup_recovery_point:
        for plan in matching_plans:
            for rule in plan.get("Rules", []):
                lifecycles = [rule.get("Lifecycle") or {}] + [(c or {}).get("Lifecycle") or {} for c in rule.get("CopyActions") or []]
                for life in lifecycles:
                    delete_after = life.get("DeleteAfterDays")
                    if delete_after:
                        long_term_days = max(long_term_days, int(delete_after))
                # A rule with no lifecycle at all keeps its recovery points until they are deleted.
                if not (rule.get("Lifecycle") or {}).get("DeleteAfterDays"):
                    long_term_indefinite = True
    retention_days = max(short_window_days, long_term_days)
    oldest = (rp_entry or {}).get("oldest") or ""
    observed_oldest_days = max(0, (datetime.now(timezone.utc) - _as_dt(oldest)).days) if oldest else None

    # DynamoDB backups kept past 90 days in warm storage.  Only DynamoDB is read: AWS Backup has no cold tier for EC2, and an EBS
    # snapshot moved to cold becomes a full copy, which AWS notes often costs more than the incremental snapshot it replaces.
    # The cold tier for DynamoDB needs advanced DynamoDB backup.  A rule that sets no cold transition keeps every copy warm.
    warm_long_days = 0
    if has_backup_recovery_point and res_type == "AWS::DynamoDB::Table" and region_cfg.get("management", {}).get("DynamoDB") is True:
        for plan in matching_plans:
            for rule in plan.get("Rules", []):
                life = rule.get("Lifecycle") or {}
                keep = int(life.get("DeleteAfterDays") or 0)
                if keep > 90 and not life.get("MoveToColdStorageAfterDays"):
                    warm_long_days = max(warm_long_days, keep)

    # EBS volumes: mark as protected when recent snapshots exist, even without
    # a named DLM policy. The snapshot data is already indexed by volume ARN.
    has_recent_snapshots = False
    if native and native.get("snapshot_count", 0) > 0:
        age = native.get("latest_snapshot_age_days")
        if age is not None and age <= BACKUP_JOB_LOOKBACK_DAYS:
            has_recent_snapshots = True

    # The signals of a recovery copy: the newest usable AWS Backup recovery point, and the newest native snapshot or restorable
    # time.  A continuous mechanism that is on (point-in-time recovery, versioning, automated database backups) is a copy; its
    # freshness comes from its latest restorable time where the service reports one.
    if rp_entry and rp_entry.get("newest"):
        last_recovery_point: Optional[datetime] = _as_dt(rp_entry["newest"])
    else:
        backup_times = ([index["last_backup"][k] for k in lookup_keys if k in index.get("last_backup", {})]
                        if has_backup_recovery_point else [])
        last_recovery_point = max(backup_times) if backup_times else None
    native_times = [_as_dt(t) for t in ((native or {}).get("latest_snapshot_at"),
                                        (native or {}).get("latest_restorable_at")) if t]
    last_native = max(native_times) if native_times else None
    continuous_copy = bool(native and native.get("enabled") and native.get("mechanism") in _CONTINUOUS_MECHANISMS)
    native_copy = bool(continuous_copy or last_native or (native and ((native.get("snapshot_count") or 0) > 0
                                                                       or (native.get("manual_snapshot_count") or 0) > 0)))

    # A copy is identified by evidence only.  A policy that should produce one (a plan selection, a lifecycle policy matched by
    # tags) is not a copy, and a failing job does not take away a copy that still exists: it is shown beside the evidence.
    has_any_protection = bool(has_backup_recovery_point or native_copy or has_recent_snapshots)

    # Deletion safety.  Only database and DynamoDB resources have a deletion-protection setting, so only
    # those get an answer; everything else is "not applicable", not "unprotected".
    protection_flag = (native or {}).get("deletion_protection")
    deletion_protection: Optional[bool] = protection_flag if res_type in _DELETION_PROTECTED_TYPES else None
    if res_type == "AWS::S3::Bucket" and native:
        deletion_protection = bool(native.get("object_lock") or native.get("mfa_delete")) if native.get("object_lock") is not None else None
    # A copy that survives deleting the resource: a recovery point in AWS Backup, a manual snapshot, an
    # on-demand backup, an EBS snapshot, a replica, or DynamoDB point-in-time recovery (AWS keeps a final
    # backup of a deleted table for 35 days).  RDS automated backups are removed with the instance unless it is
    # deleted with them retained, so they do not count.
    survives_deletion = bool(
        has_backup_recovery_point
        or (native and native.get("manual_snapshot_count", 0) > 0)
        or (res_type in ("AWS::DynamoDB::Table", "AWS::EC2::Volume") and native and native.get("snapshot_count", 0) > 0)
        # DynamoDB keeps a final backup of a deleted table for 35 days when point-in-time recovery is on.
        or (res_type == "AWS::DynamoDB::Table" and native and native.get("mechanism") == "dynamodb_pitr" and native.get("enabled"))
        or (arn.startswith("arn:aws:s3:::") and native and native.get("cross_region")))
    deletion_exposed = bool(res_type in _DELETION_PROTECTED_TYPES and deletion_protection is False and not survives_deletion)

    return {
        "deletion_protection": deletion_protection,
        "s3_versioning": _s3_versioning_state(res_type, native),
        "s3_eventbridge": _s3_eventbridge_state(res_type, native),
        # A plan that selects this bucket backs it up continuously: AWS Backup then depends on its EventBridge notifications.
        "s3_continuous_backup": bool(res_type == "AWS::S3::Bucket" and any(
            rule.get("EnableContinuousBackup") for plan in matching_plans for rule in plan.get("Rules", []))),
        "object_lock": (native or {}).get("object_lock") if res_type == "AWS::S3::Bucket" else None,
        "mfa_delete": (native or {}).get("mfa_delete") if res_type == "AWS::S3::Bucket" else None,
        "survives_deletion": survives_deletion,
        "deletion_exposed": deletion_exposed,
        "policy_assigned": bool(plan_selected or native_enabled),
        "last_recovery_point_at": last_recovery_point.isoformat() if last_recovery_point else "",
        "last_native_snapshot_at": last_native.isoformat() if last_native else "",
        "archived_snapshot_count": int((native or {}).get("archived_snapshot_count") or 0) if res_type == "AWS::EC2::Volume" else 0,
        "old_standard_snapshot_count": int((native or {}).get("old_standard_snapshot_count") or 0) if res_type == "AWS::EC2::Volume" else 0,
        "old_standard_snapshot_gib": float((native or {}).get("old_standard_snapshot_gib") or 0) if res_type == "AWS::EC2::Volume" else 0.0,
        # Every snapshot of the volume is in the archive tier: a restore first waits for one to come back to the standard tier.
        "snapshots_all_archived": bool(res_type == "AWS::EC2::Volume" and native and native.get("snapshot_count")
                                       and (native.get("archived_snapshot_count") or 0) >= native["snapshot_count"]),
        "continuous_copy": continuous_copy,
        "backup_interval_hours": backup_interval_hours,
        "has_native_protection": native_enabled,
        "has_backup_recovery_point": has_backup_recovery_point,
        # Listed by AWS Backup, but no recovery point that can still be restored was found in any vault assessed.
        "listed_without_usable_point": listed_without_usable_point,
        "backup_evidence_unverified": backup_unverified,
        "plan_selected": plan_selected,
        "selection_match_reason": selection_match_reason,
        "matching_plan_names": "|".join(p.get("BackupPlanName", "") for p in matching_plans),
        # Recovery points exist but no plan selects the resource now: it is unmanaged and
        # will age out.  Only asserted when every selection could actually be evaluated.
        "recovery_without_selection": has_backup_recovery_point and not backup_via_instance and selection_match_reason == "none",
        "backup_via_instance": backup_via_instance,
        "matching_plan_ids": "|".join(f"{p.get('account_id', '')}:{p.get('region', '')}:{p.get('BackupPlanId', '')}" for p in matching_plans),
        "backup_opted_in": backup_opted_in,
        "opt_in_skipped": opt_in_skipped,
        "copy_withheld_reason": copy_withheld_reason,
        "has_any_protection": has_any_protection,
        "no_backup_path": no_backup_path,
        "is_air_gapped": is_air_gapped,
        "vault_locked": vault_locked,
        "vault_lock_mode": vault_lock_mode,
        "cross_region_copy": cross_region_copy,
        "cross_account_copy": cross_account_copy,
        "cross_account_configured": bool(cross_account_configured and not cross_account_copy),
        "copy_scope": copy_scope,
        "copy_regions": "|".join(sorted(dest_regions)),
        "copy_geographies": "|".join(copy_geographies),
        "recovery_point_count": recovery_point_count,
        "job_failing": job_failing,
        "consecutive_failures": consecutive_failures,
        "job_failure_reason": job_failure_reason,
        "retention_days": retention_days,
        "short_window_days": short_window_days,
        "long_term_days": long_term_days,
        "long_term_indefinite": long_term_indefinite,
        "observed_oldest_days": observed_oldest_days,
        "warm_long_retention_days": warm_long_days,
        "native_mechanism": (native.get("mechanism") if native and native.get("enabled")
                             else ("ebs_dlm" if dlm_hit else (native.get("mechanism") if native else None))),
        "native_ceiling_days": (native.get("retention_ceiling_days") if native
                                else (dlm_hit.get("retention_ceiling_days") if dlm_hit else None)),
        "dlm_policy_id": dlm_hit.get("policy_id", "") if dlm_hit else "",
        # Exposed so detect_over_protection can check S3 lifecycle without re-looking up
        # the native state dict (which is keyed by ARN, not stored on the resource).
        # An unanswered lifecycle call (None) is not evidence that expiry is missing.
        "s3_has_expiry_rule": True if (native or {}).get("has_expiry_rule", True) is None
        else ((native or {}).get("has_expiry_rule", True)),
    }


def classify_protection_state(resource: Dict) -> str:
    """Map analysis fields to a simple state label."""
    if resource.get("no_backup_path"):
        return "no_backup_path"
    if not resource.get("has_any_protection"):
        # Enrolled in a plan but its jobs have been failing: not protected, and not the
        # same problem as a resource nobody ever enrolled.
        if resource.get("job_failing"):
            return "failing"
        # Nothing was found, but a call that could have found it failed.  That is "not
        # assessed", never "unprotected".
        if resource.get("assessment_blockers"):
            return "not_assessed"
        return "unprotected"
    # A failing plan does not take away a copy that still exists; the failure is shown beside the state.
    if resource.get("is_air_gapped"):
        return "air_gapped"
    if resource.get("vault_locked"):
        return "vault_locked"
    if resource.get("has_backup_recovery_point"):
        return "backup_plan"
    return "native_only"


# ─────────────────────────────────────────────────────────────────────────────
# Recovery-copy state, tiers and resource age
# ─────────────────────────────────────────────────────────────────────────────
# `has_any_protection` answers "is a mechanism delivering a copy right now".  The state below is a second,
# finer lens built from three independent signals: whether a policy exists, whether a recovery point
# exists, and whether a native snapshot exists.  It does not replace the first; both are reported.

# Types that have a deletion-protection setting the collector can read.
_DELETION_PROTECTED_TYPES = frozenset({"AWS::RDS::DBInstance", "AWS::RDS::AuroraCluster", "AWS::RDS::NeptuneCluster",
                                       "AWS::RDS::DocDBCluster", "AWS::RDS::DBCluster", "AWS::DynamoDB::Table"})

_CONTINUOUS_MECHANISMS = frozenset({"dynamodb_pitr", "rds_automated_backup", "aurora_automated_backup",
                                    "s3_versioning"})

# Default recovery targets by tier, in hours.  They are assumptions, shown in the report, and a customer
# overrides a resource's tier with the overrides file.  RTO is carried for restore assurance (Phase 10).
# Tier 1 shares tier 2's 24-hour recovery point target (Alex's decision, 2026-11-17: a tighter default would push customers toward
# backups more frequent than they need); it differs in restore time and retention.
RECOVERY_TIERS: Dict[int, Dict[str, int]] = {
    1: {"rpo_hours": 24, "rto_hours": 4, "min_retention_days": 365},
    2: {"rpo_hours": 24, "rto_hours": 24, "min_retention_days": 90},
    3: {"rpo_hours": 168, "rto_hours": 72},
}
# Default retention targets (Alex's decisions, 2026-11-16): default assumptions the customer changes in the targets file, drawn from
# common retention practice for each class and labelled in the report as the tool's assumptions.  Production data inferred
# confidential: at least a year.  Other production: at least 90 days.  Development: at most DEV_LONG_RETENTION_DAYS, the figure the
# Waste pillar uses, unless the targets file sets tier 3's max_retention_days.


def retention_target(tier: Optional[int]) -> Optional[Tuple[str, int]]:
    """("min" or "max", days) for a tier, or None for no tier."""
    if not tier:
        return None
    row = RECOVERY_TIERS.get(tier) or {}
    if row.get("min_retention_days"):
        return ("min", int(row["min_retention_days"]))
    if tier == 3:
        return ("max", int(row.get("max_retention_days") or DEV_LONG_RETENTION_DAYS))
    return None


def retention_vs_target(r: Dict) -> str:
    """"short" or "long" when a resource's retention, as read, falls outside its tier's target; otherwise "".  The same rule as the
    Waste pillar's development row: any retention read counts, whether or not the latest copy is current."""
    target = retention_target(r.get("recovery_tier"))
    if not target:
        return ""
    kind, limit = target
    if "long_term_days" in r:
        # Mechanism-aware: long-term copies (a backup rule, its copy actions, a lifecycle policy) answer the target when there are
        # any; otherwise the short-term window (point-in-time recovery, automated backups) is all there is.  A rule with no expiry
        # keeps copies until deleted, which meets a minimum and exceeds a maximum.
        if r.get("long_term_indefinite"):
            return "" if kind == "min" else "long"
        long_term, short = int(r.get("long_term_days") or 0), int(r.get("short_window_days") or 0)
        days = long_term if (kind == "min" and long_term) else max(long_term, short)
    else:
        days = r.get("retention_days") or 0
    if days <= 0:
        return ""
    if kind == "min" and days < limit:
        return "short"
    if kind == "max" and days > limit:
        return "long"
    return ""
# A copy is "older than target" only past this multiple of the target, so a daily backup that runs a little
# late is not reported as behind.
STALE_TOLERANCE = 1.5
NEW_RESOURCE_DAYS = 30


def recovery_tier(resource: Dict) -> Optional[int]:
    """The recovery tier of a resource, or None when its criticality is not known.

    An override wins.  Production data with CONFIDENTIAL or higher sensitivity is tier 1, other
    production data tier 2, development tier 3.  A resource whose environment is unknown gets no tier,
    so nothing is called late against a target nobody chose."""
    if resource.get("tier_override"):
        return int(resource["tier_override"])
    crit = resource.get("criticality")
    if crit == "development":
        return 3
    if crit == "production":
        return 1 if _SENSITIVITY_RANK.get(resource.get("data_sensitivity", "INTERNAL"), 1) >= 2 else 2
    return None


def _cron_field_count(field: str, low: int, high: int) -> Optional[int]:
    """How many values a cron field names, or None for a form not understood."""
    if field in ("*", "?"):
        return high - low + 1
    total = 0
    for part in field.split(","):
        step = re.fullmatch(r"(\*|\d+(?:-\d+)?)/(\d+)", part)
        if step:
            base, n = step.group(1), int(step.group(2))
            lo, hi = (low, high) if base == "*" else (
                (int(base.split("-")[0]), int(base.split("-")[1])) if "-" in base else (int(base), high))
            total += len(range(lo, hi + 1, n)) if n else 0
        elif re.fullmatch(r"\d+-\d+", part):
            a, b = part.split("-")
            total += int(b) - int(a) + 1
        elif re.fullmatch(r"\d+|[A-Za-z]{3}", part):
            total += 1
        else:
            return None
    return total or None


def schedule_interval_hours(expression: Optional[str]) -> Optional[float]:
    """The average hours between runs of an AWS Backup cron expression, or None when not understood.

    cron(minutes hours day-of-month month day-of-week year).  Only the common shapes are read: every N
    hours, daily, on some days of the week, on some days of the month.  Anything else gives None, which
    reports as "not known" and never as a guess."""
    m = re.fullmatch(r"\s*cron\((.*)\)\s*", expression or "")
    if not m:
        return None
    fields = m.group(1).split()
    if len(fields) != 6:
        return None
    minutes, hours, dom, month, dow, _year = fields
    for number, name in enumerate(("SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"), start=1):
        dow = dow.upper().replace(name, str(number))
    if month not in ("*", "?"):
        return None                                  # a monthly-subset schedule is not estimated
    per_hour = _cron_field_count(minutes, 0, 59)
    per_day = _cron_field_count(hours, 0, 23)
    if per_hour is None or per_day is None:
        return None
    runs_per_day = per_hour * per_day
    dom_free, dow_free = dom in ("*", "?"), dow in ("*", "?")
    if dom_free and dow_free:
        return 24.0 / runs_per_day
    if dom_free:
        days = _cron_field_count(dow, 1, 7)
        return 168.0 / (days * runs_per_day) if days else None
    if dow_free:
        days = _cron_field_count(dom, 1, 31)
        return 730.0 / (days * runs_per_day) if days else None
    return None


# The recovery-evidence state every coverage figure counts from (Alex's decision, 2026-11-17).  One per resource.
EVIDENCE_STATES = ("current", "outdated", "none_identified", "not_assessed")
EVIDENCE_LABELS = {"current": "Copy identified", "outdated": "Copy identified, older than the target",
                   "none_identified": "No recovery copy identified", "not_assessed": "Not assessed"}


def recovery_copy_state(resource: Dict, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Classify a resource by the three signals, against its tier's recovery target.

    States: none, policy_only, orphan_policy, stale, current, excluded_documented, no_backup_path,
    not_assessed.  A copy older than STALE_TOLERANCE times the target is `stale`.  A resource whose
    environment (and so tier) is unknown is never `stale`: nothing is late against a target nobody set.

    `recovery_evidence` folds them into the four states the report counts from: current, outdated, none_identified and
    not_assessed.  A copy with no date (a continuous mechanism with no restorable time, such as S3 versioning, or an AWS
    Backup listing whose recovery points could not be read) is current with its freshness marked as not known, never silently
    current."""
    now = now or datetime.now(timezone.utc)
    tier = recovery_tier(resource)
    rpo = RECOVERY_TIERS[tier]["rpo_hours"] if tier else None
    times = [_as_dt(t) for t in (resource.get("last_recovery_point_at"), resource.get("last_native_snapshot_at")) if t]
    newest = max(times) if times else None
    continuous = bool(resource.get("continuous_copy"))
    age_hours = round((now - newest).total_seconds() / 3600, 1) if newest else None
    if "has_any_protection" in resource:
        has_copy = bool(resource["has_any_protection"])
    else:
        has_copy = bool(newest) or continuous or bool(resource.get("has_backup_recovery_point"))
    policy = bool(resource.get("policy_assigned"))
    late = bool(rpo and age_hours is not None and age_hours > rpo * STALE_TOLERANCE)

    if resource.get("protection_state") == "not_assessed":
        state = "not_assessed"
    elif resource.get("no_backup_path"):
        state = "no_backup_path"
    elif not policy and not has_copy:
        state = "excluded_documented" if resource.get("exclusion_status") == "documented" else "none"
    elif not has_copy:
        state = "policy_only"
    elif not policy:
        state = "orphan_policy"
    elif late:
        state = "stale"
    else:
        state = "current"

    if state == "not_assessed":
        evidence = "not_assessed"
    elif state in ("none", "policy_only", "excluded_documented", "no_backup_path"):
        evidence = "none_identified"
    else:
        evidence = "outdated" if late else "current"
    if not has_copy or evidence == "not_assessed":
        freshness = ""
    elif newest is None:
        freshness = "not_measurable" if continuous else "unknown"
    else:
        freshness = "measured"

    interval = resource.get("backup_interval_hours")
    return {
        "recovery_copy_state": state,
        "recovery_evidence": evidence,
        "copy_freshness": freshness,
        "recovery_tier": tier,
        "rpo_hours": rpo,
        "rto_hours": RECOVERY_TIERS[tier]["rto_hours"] if tier else None,
        "copy_age_hours": age_hours,
        "frequency_exceeds_rpo": bool(rpo and interval and interval > rpo),
    }


# Badges shown beside the recovery-evidence state.  They add a fact; none changes the state.
EVIDENCE_BADGES = {
    "built_in_only": "Built-in protection only",
    "latest_job_failed": "Latest backup job failed",
    "assigned_no_copy": "Assigned to protection, no copy yet",
    "exception_recorded": "Exception recorded",
    "iceberg_table_recovery_not_validated": "Iceberg table recovery not validated",
    "freshness_not_measurable": "Freshness not measurable",
    "freshness_unknown": "Freshness not known",
    "copy_to_other_account_not_verified": "Copy to another account configured, not verified",
}


def evidence_badges(r: Dict) -> List[str]:
    """The badges that apply to a resource, in a fixed order."""
    out = []
    if paper_only(r):
        out.append("built_in_only")
    if r.get("latest_backup_failed") or r.get("job_failing"):
        out.append("latest_job_failed")
    if r.get("recovery_copy_state") == "policy_only":
        out.append("assigned_no_copy")
    if r.get("exclusion_status") in ("documented", "expired"):
        out.append("exception_recorded")
    if r.get("hosts_iceberg") or r.get("no_backup_path"):
        out.append("iceberg_table_recovery_not_validated")
    if r.get("copy_freshness") == "not_measurable":
        out.append("freshness_not_measurable")
    elif r.get("copy_freshness") == "unknown":
        out.append("freshness_unknown")
    if r.get("cross_account_configured"):
        out.append("copy_to_other_account_not_verified")
    return out


def resource_age(resource: Dict, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Age from the creation time, when the source gave one; otherwise "not known", never zero."""
    now = now or datetime.now(timezone.utc)
    created = (resource.get("meta") or {}).get("CreatedAt", "")
    if not created:
        return {"created_at": "", "age_days": None, "is_new": None}
    days = max(0, (now - _as_dt(created)).days)
    return {"created_at": created, "age_days": days, "is_new": days <= NEW_RESOURCE_DAYS}


# ─────────────────────────────────────────────────────────────────────────────
# Copies with no source, backups visible outside the account, unattached volumes
# ─────────────────────────────────────────────────────────────────────────────
# A snapshot or recovery point whose source resource is gone is kept on purpose or by accident, and the data
# may exist nowhere else.  These are reported as facts with their age and size.  Nothing here says to delete.

# AWS Backup recovery point resource types that the inventory covers, so a missing source can be trusted.
# S3 is left out: a bucket ARN carries no account, so "not in the inventory" cannot be told from "another account".
_RP_TYPES_CHECKED = frozenset({"EBS", "RDS", "Aurora", "DynamoDB"})
_DISCOVERY_APIS = ("config:", "resource-explorer-2:", "ec2:describe_volumes", "rds:describe_db_instances",
                   "rds:describe_db_clusters", "dynamodb:list_tables", "dynamodb:describe_table", "region:skipped",
                   "worker:describe", "worker:config", "worker:enrich")
_ORPHAN_RATE = {"ebs_snapshot": "ebs_snapshot", "recovery_point": "aws_backup_warm"}   # anything else: rds_backup


def _orphan_monthly(row: Dict) -> float:
    """List-rate monthly cost of a copy whose source is gone.  An archived EBS snapshot is a full copy at the archive rate; the
    cold part of a group of recovery points is at the cold rate (the EBS archive rate for EBS); the rest at the warm rate."""
    size = row.get("size_gib") or 0
    if row["kind"] == "ebs_snapshot" and row.get("archived"):
        return size * MECHANISM_RATES["ebs_snapshot_archive"]
    if row["kind"] == "recovery_point":
        cold = min(row.get("cold_gib") or 0, size)
        cold_rate = MECHANISM_RATES["ebs_snapshot_archive" if row.get("ebs") else "aws_backup_cold"]
        return (size - cold) * MECHANISM_RATES["aws_backup_warm"] + cold * cold_rate
    return size * MECHANISM_RATES[_ORPHAN_RATE.get(row["kind"], "rds_backup")]


def _discovery_incomplete(gaps: List[Dict], account: str, region: str) -> bool:
    """True when something that lists resources failed for this account and Region, so a resource missing from
    the inventory may simply not have been listed."""
    return any(g["account_id"] == account and g["region"] in (region, "") and g["api"].startswith(_DISCOVERY_APIS)
               for g in gaps)


def _unchecked_scopes(native_findings: List[Dict], scanned: set, check: str) -> List[str]:
    """Account/Region scopes where a check did not finish, including scopes whose Region read never produced a result."""
    seen = {(f["account_id"], f["region"]): f for f in native_findings}
    out = [f"{a}:{r}" for (a, r) in sorted(scanned) if (a, r) not in seen]
    out += [f"{a}:{r}" for (a, r), f in sorted(seen.items()) if not (f.get("checks") or {}).get(check, True)]
    return out


def find_orphans(native_findings: List[Dict], recovery_points: Dict[str, Dict], inventory: set,
                 scanned: set, accounts: set, gaps: List[Dict], legal_holds_known: bool,
                 now: Optional[datetime] = None) -> Dict[str, Any]:
    """Copies whose source resource is not in what was assessed.

    EBS and RDS findings come with the Region they were found in and were judged against that Region's own
    list of volumes and databases.  Recovery points are judged against the whole inventory, and only when the
    source's account and Region were both scanned and listing them did not fail; otherwise they are counted as
    "could not be verified" and are not called orphans."""
    now = now or datetime.now(timezone.utc)
    rows: List[Dict] = []
    for f in native_findings:
        for item in f.get("orphans", []):
            rows.append({**item, "account_id": f["account_id"], "region": f["region"], "held": False, "copies": 1})
    unverifiable = 0
    for rarn, e in recovery_points.items():
        if e.get("resource_type") not in _RP_TYPES_CHECKED or rarn in inventory:
            continue
        parts = rarn.split(":")
        account, region = (parts[4], parts[3]) if len(parts) >= 6 else ("", "")
        if (account not in accounts or (account, region) not in scanned
                or _discovery_incomplete(gaps, account, region)):
            unverifiable += 1
            continue
        rows.append({"id": rarn, "source": rarn, "kind": "recovery_point", "size_gib": e["bytes"] / (1024 ** 3),
                     "cold_gib": (e.get("cold_bytes") or 0) / (1024 ** 3), "ebs": e.get("resource_type") == "EBS",
                     "created": e.get("oldest", ""), "newest": e.get("newest", ""), "account_id": account,
                     "region": region, "held": e.get("held", 0) > 0, "copies": e["count"],
                     "vault_accounts": e.get("vault_accounts", [])})
    for row in rows:
        row["monthly_usd"] = round(_orphan_monthly(row), 2)
        row["age_days"] = max(0, (now - _as_dt(row["created"])).days) if row.get("created") else None
    held = [r for r in rows if r["held"]]
    removable = [r for r in rows if not r["held"]]
    unchecked = _unchecked_scopes(native_findings, scanned, "orphans")
    unchecked += [f"{g['account_id']}:{g['region']}" for g in gaps
                  if g["api"] in ("backup:list_backup_vaults", "backup:list_recovery_points_by_backup_vault")]
    return {
        "unchecked_scopes": sorted(set(unchecked)),
        "rows": sorted(rows, key=lambda r: (-r["monthly_usd"], r["id"])),
        "by_kind": {k: sum(1 for r in rows if r["kind"] == k) for k in sorted({r["kind"] for r in rows})},
        "unverifiable": unverifiable,
        "estimated_monthly_usd": round(sum(r["monthly_usd"] for r in rows), 2),
        "held": len(held), "held_monthly_usd": round(sum(r["monthly_usd"] for r in held), 2),
        "legal_holds_known": legal_holds_known,
        "not_held_monthly_usd": round(sum(r["monthly_usd"] for r in removable), 2),
    }


def find_exposure(native_findings: List[Dict], scanned: Optional[set] = None) -> Dict[str, Any]:
    """Backups that anyone, or another account, can restore from.  EBS snapshots are checked for public access
    only: reading who else they are shared with takes one call per snapshot."""
    public_snaps, public_images, shared = [], [], []
    unchecked: Dict[str, List[str]] = {name: _unchecked_scopes(native_findings, scanned or set(), name)
                                       for name in ("public_snapshots", "public_images", "rds_attributes")}
    for f in native_findings:
        base = {"account_id": f["account_id"], "region": f["region"]}
        public_snaps += [{**base, "id": i, "kind": "ebs_snapshot"} for i in f.get("public_snapshots", [])]
        public_images += [{**base, "id": i, "kind": "ami"} for i in f.get("public_images", [])]
        shared += [{**base, **item} for item in f.get("shared", [])]
    return {"public_ebs_snapshots": public_snaps, "public_images": public_images,
            "rds_public": [x for x in shared if x["public"]], "rds_shared": [x for x in shared if not x["public"]],
            "unchecked": unchecked}


def unmanaged_volumes(resources: List[Dict]) -> List[Dict]:
    """EBS volumes attached to nothing.  An instance-level backup cannot reach them."""
    out = []
    for r in resources:
        meta = r.get("meta") or {}
        if r.get("resourceType") == "AWS::EC2::Volume" and "AttachedInstance" in meta and not meta["AttachedInstance"]:
            out.append(r)
    return out


def compute_copies_summary(resources: List[Dict], orphans: Dict[str, Any], exposure: Dict[str, Any]) -> Dict[str, Any]:
    unattached = unmanaged_volumes(resources)
    checked = [r for r in resources if r.get("resourceType") in _DELETION_PROTECTED_TYPES
               and r.get("protection_state") != "not_assessed" and r.get("deletion_protection") is not None]
    exposed = [r for r in checked if r.get("deletion_exposed")]
    return {
        "orphans": orphans, "exposure": exposure,
        "unattached_volumes": len(unattached),
        "unattached_without_copy": sum(1 for r in unattached if not r.get("has_any_protection")),
        "unattached_gib": round(sum(r.get("size_gib", 0) or 0 for r in unattached), 1),
        "deletion_checked": len(checked), "deletion_protected": sum(1 for r in checked if r["deletion_protection"]),
        "deletion_exposed": len(exposed),
        "deletion_exposed_with_copy": sum(1 for r in exposed if recovery_evidence_of(r) in ("current", "outdated")),
        "deletion_exposed_names": [r.get("resourceName") or r.get("resourceId", "") for r in exposed][:10],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Backup and copy job outcomes
# ─────────────────────────────────────────────────────────────────────────────
# A backup that is scheduled is a promise; a job that completed is evidence.  These figures count how the jobs AWS Backup
# recorded in the history window ended, tie each to its resource, and say whether anything would have raised an alert.

_JOB_FAILED = frozenset({"FAILED", "EXPIRED", "ABORTED"})      # EXPIRED: the job did not start in its window, so no backup was made
_JOB_FINISHED = frozenset({"COMPLETED", "FAILED", "EXPIRED", "ABORTED", "PARTIAL"})
_JOB_RUNNING = frozenset({"CREATED", "PENDING", "RUNNING", "ABORTING"})
_UUID = re.compile(r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b")


def _job_when(job: Dict) -> datetime:
    return _as_dt(job.get("CompletionDate") or job.get("CreationDate"))


def _job_reason(job: Dict) -> str:
    return _UUID.sub("<id>", clean_text(job.get("StatusMessage") or "", 160))


def apply_backup_job_evidence(resources: List[Dict], jobs: List[Dict], copy_jobs: List[Dict], vault_alarms: Dict[str, bool],
                              jobs_known: bool = True, history_days: int = JOB_HISTORY_DAYS,
                              copies_known: bool = True) -> Dict[str, Any]:
    """Set backup and copy job fields on each resource and return the estate-level figures."""
    by_resource: Dict[str, List[Dict]] = {}
    for j in jobs:
        if j.get("ResourceArn"):
            by_resource.setdefault(j["ResourceArn"], []).append(j)
    copies_by_resource: Dict[str, List[Dict]] = {}
    for j in copy_jobs:
        if j.get("ResourceArn"):
            copies_by_resource.setdefault(j["ResourceArn"], []).append(j)

    def alerted(job: Dict) -> bool:
        return is_vault_monitored({"account_id": job.get("account_id", ""), "region": job.get("region", ""),
                                   "BackupVaultName": job.get("BackupVaultName", "")}, vault_alarms)

    for r in resources:
        mine = sorted(by_resource.get(r.get("arn", ""), []), key=_job_when)
        finished = [j for j in mine if j.get("State") in _JOB_FINISHED]
        failed = [j for j in mine if j.get("State") in _JOB_FAILED]
        done = [j for j in mine if j.get("State") == "COMPLETED"]
        last_failed = failed[-1] if failed else None
        latest = finished[-1] if finished else None
        copies = copies_by_resource.get(r.get("arn", ""), [])
        copy_failed = sorted((j for j in copies if j.get("State") in _JOB_FAILED), key=_job_when)
        # A destination has a copy gap when the latest finished copy job to it did not complete.  A failure followed by a completed
        # copy to the same destination is history (it stays in the job counts), and a job still running decides nothing.
        latest_by_dest: Dict[str, Dict] = {}
        for j in sorted((j for j in copies if j.get("State") in _JOB_FINISHED), key=_job_when):
            latest_by_dest[str(j.get("DestinationBackupVaultArn") or "")] = j
        gap_dests = sum(1 for j in latest_by_dest.values() if j.get("State") in _JOB_FAILED)
        r.update({
            "backup_jobs_in_window": len(mine),
            "backup_failures_in_window": len(failed),
            "backup_success_rate": round(len(done) / (len(done) + len(failed)), 2) if (done or failed) else None,
            "last_successful_backup_job_at": _iso(done[-1].get("CompletionDate")) if done else "",
            "last_backup_failure_at": _iso(_job_when(last_failed)) if last_failed else "",
            "last_backup_failure_state": last_failed.get("State", "") if last_failed else "",
            "last_backup_failure_reason": _job_reason(last_failed) if last_failed else "",
            "latest_backup_failed": bool(latest and latest.get("State") in _JOB_FAILED),
            "backup_failures_without_alert": sum(1 for j in failed if not alerted(j)),
            "copy_jobs_in_window": len(copies),
            "copy_failures_in_window": len(copy_failed),
            "copy_gap_destinations": gap_dests,
            "last_copy_failure_reason": _job_reason(copy_failed[-1]) if copy_failed else "",
        })

    def states(rows: List[Dict]) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for j in rows:
            out[j.get("State", "")] = out.get(j.get("State", ""), 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def reasons(rows: List[Dict]) -> List[Dict]:
        tally: Dict[str, int] = {}
        for j in rows:
            if j.get("State") in _JOB_FAILED:
                text = _job_reason(j) or f"{j.get('State', '')} with no message"
                tally[text] = tally.get(text, 0) + 1
        return [{"text": t, "count": n} for t, n in sorted(tally.items(), key=lambda kv: -kv[1])[:5]]

    failing = [r for r in resources if r.get("backup_failures_in_window")]
    failed_jobs = [j for j in jobs if j.get("State") in _JOB_FAILED]
    vault_keys = {(j.get("account_id", ""), j.get("region", ""), j.get("BackupVaultName", "")) for j in jobs}
    unalerted_vaults = {k for k in vault_keys if not is_vault_monitored(
        {"account_id": k[0], "region": k[1], "BackupVaultName": k[2]}, vault_alarms)}
    copy_failed_jobs = [j for j in copy_jobs if j.get("State") in _JOB_FAILED]
    return {
        "history_days": history_days, "known": jobs_known,
        "jobs": len(jobs), "states": states(jobs), "failed": len(failed_jobs),
        "running": sum(1 for j in jobs if j.get("State") in _JOB_RUNNING),
        "reasons": reasons(jobs),
        "resources_with_failures": len(failing),
        "resources_latest_failed": sum(1 for r in resources if r.get("latest_backup_failed")),
        "resources_recovered": sum(1 for r in failing if not r.get("latest_backup_failed")),
        "failures_without_alert": sum(1 for j in failed_jobs if not is_vault_monitored(
            {"account_id": j.get("account_id", ""), "region": j.get("region", ""), "BackupVaultName": j.get("BackupVaultName", "")}, vault_alarms)),
        "vaults_with_jobs": len(vault_keys), "vaults_without_alert": len(unalerted_vaults),
        "by_type": {t: n for t, n in sorted(_count_by(failed_jobs, lambda j: j.get("ResourceType", "") or "not known").items(), key=lambda kv: -kv[1])},
        "worst": [{"name": clean_text(r.get("resourceName") or r.get("resourceId", ""), 60), "type": r.get("resourceType", ""),
                   "failed": r["backup_failures_in_window"], "jobs": r["backup_jobs_in_window"],
                   "last_failure": r["last_backup_failure_at"], "last_success": r["last_successful_backup_job_at"],
                   "latest_failed": r["latest_backup_failed"], "reason": r["last_backup_failure_reason"],
                   "unalerted": r["backup_failures_without_alert"]}
                  for r in sorted(failing, key=lambda r: (-r["latest_backup_failed"], -r["backup_failures_in_window"],
                                                           r.get("resourceName") or ""))[:10]],
        "copy": {"known": copies_known, "jobs": len(copy_jobs), "states": states(copy_jobs), "failed": len(copy_failed_jobs),
                 "reasons": reasons(copy_jobs), "resources": len({j.get("ResourceArn") for j in copy_failed_jobs if j.get("ResourceArn")}),
                 "running": sum(1 for j in copy_jobs if j.get("State") in _JOB_RUNNING),
                 # Resources whose latest copy to some destination did not complete: a current gap, not history.
                 "resources_with_gap": sum(1 for r in resources if r.get("copy_gap_destinations"))},
    }


def backup_jobs_section_html(summary: Dict[str, Any]) -> List[str]:
    """How backup and copy jobs ended, and whether a failure would have raised an alert.  Facts only."""
    if not summary or (not summary["jobs"] and summary["known"] and not summary["copy"]["jobs"] and summary["copy"]["known"]):
        return []
    e = _esc
    out: List[str] = []
    w = out.append
    days = summary["history_days"]
    w('<section><div class="sec-head"><span class="sec-num">Jobs</span><h2>Did the backups run, and would a failure have been noticed</h2></div>')
    if not summary["known"]:
        w('<p><em>Not assessed:</em> the list of backup jobs could not be read in some account or Region (see Coverage gaps), so '
          'the counts below are a lower bound and say nothing about where it could not be read.</p>')
    names = {"COMPLETED": "completed", "FAILED": "failed", "EXPIRED": "expired before starting", "ABORTED": "aborted",
             "PARTIAL": "partly completed", "RUNNING": "running", "PENDING": "pending", "CREATED": "created", "ABORTING": "aborting"}
    parts = ", ".join(f"{n:,} {names.get(k, k.lower())}" for k, n in summary["states"].items())
    w(f'<p>{summary["jobs"]:,} backup job(s) in the last {days} days: {e(parts) if parts else "none"}. An expired job is a backup that '
      f'was scheduled and never started in time, so no recovery point was made.</p>')
    done = summary["states"].get("COMPLETED", 0)
    if summary["jobs"]:
        w('<div class="bar-pair">' + _pair_bars(done, summary["failed"], "Backup jobs completed", "Did not complete") + '</div>')
    if summary["failed"]:
        w(f'<div class="callout warn"><h4>Backups that did not complete</h4><p>{summary["failed"]:,} job(s) failed, expired or were aborted, '
          f'across {summary["resources_with_failures"]:,} resource(s). {summary["resources_latest_failed"]:,} of those resource(s) have a most '
          f'recent finished job that did not complete; {summary["resources_recovered"]:,} '
          f'{"has" if summary["resources_recovered"] == 1 else "have"} completed a backup since.</p>'
          f'<p>{summary["failures_without_alert"]:,} of the {summary["failed"]:,} failures were in a vault with no failure alert: no '
          f'alarm, no vault notification for failed jobs, and no EventBridge rule for AWS Backup events in that Region. '
          f'{summary["vaults_without_alert"]:,} of the {summary["vaults_with_jobs"]:,} vaults that ran jobs '
          f'{"has" if summary["vaults_without_alert"] == 1 else "have"} no alert.</p></div>')
        detail: List[str] = []
        if summary["reasons"]:
            detail.append('<p>The most common reasons AWS gave, as written by AWS Backup (generated identifiers replaced):</p><ul>')
            for reason in summary["reasons"]:
                detail.append(f'<li><span class="mono">{e(reason["text"])}</span> · {reason["count"]:,}</li>')
            detail.append('</ul>')
        if summary["worst"]:
            detail.append('<table><thead><tr><th>Resource</th><th>Kind</th><th class="num">Did not complete</th><th class="num">Jobs</th>'
              '<th>Last failure</th><th>Last completed backup</th><th>Latest job</th><th>Alert</th></tr></thead><tbody>')
            for row in summary["worst"]:
                detail.append(f'<tr><td>{e(row["name"])}</td><td class="mono">{e(row["type"].replace("AWS::", ""))}</td>'
                  f'<td class="num">{row["failed"]:,}</td><td class="num">{row["jobs"]:,}</td>'
                  f'<td>{e(row["last_failure"][:10] or "")}</td><td>{e(row["last_success"][:10] or "none in the window")}</td>'
                  f'<td>{"did not complete" if row["latest_failed"] else "completed"}</td>'
                  f'<td>{"none" if row["unalerted"] else "yes"}</td></tr>')
            detail.append('</tbody></table><p>All resources, with the reason for the last failure, are in <span class="mono">assets.csv</span> '
              '(<span class="mono">backup_failures_in_window</span>, <span class="mono">last_backup_failure_reason</span>).</p>')
        if detail:
            w(_own_fold("Which resources failed, and why", "".join(detail)))
    elif summary["jobs"] and summary["known"]:
        w(f'<p>Every finished backup job in the last {days} days completed.</p>')
    cp = summary["copy"]
    if not cp["known"]:
        w('<h3>Copy jobs</h3><p><em>Not assessed:</em> the list of copy jobs could not be read in some account or Region (see Coverage gaps), '
          'so nothing is said about whether copies to another Region or account completed'
          + (f'; {cp["jobs"]:,} copy job(s) were read where it could' if cp["jobs"] else '') + '.</p>')
    elif cp["jobs"]:
        parts = ", ".join(f"{n:,} {names.get(k, k.lower())}" for k, n in cp["states"].items())
        w(f'<h3>Copy jobs</h3><p>{cp["jobs"]:,} copy job(s) in the last {days} days: {e(parts)}.')
        if cp["failed"]:
            gap = cp.get("resources_with_gap", 0)
            w(f' {cp["failed"]:,} did not complete, across {cp["resources"]:,} resource(s). '
              + (f'For {gap:,} of them the latest copy to a destination did not complete and no later one has, so that destination '
                 f'may hold no recent copy; for the rest a later copy completed.' if gap else
                 'A later copy to the same destination completed for each of them.'))
        w('</p>')
        if cp["reasons"]:
            w('<ul>')
            for reason in cp["reasons"]:
                w(f'<li><span class="mono">{e(reason["text"])}</span> · {reason["count"]:,}</li>')
            w('</ul>')
    w('</section>')
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Restore evidence
# ─────────────────────────────────────────────────────────────────────────────
# A backup that has never been restored is a belief, not a fact.  These figures count the restores that AWS Backup
# recorded in the lookback window, tie each to the resource it restored, and compare how long it took with the
# target for the resource's tier.  Where a resource has never been restored, an estimate is given only if this
# estate has restored something of the same kind, and it is labelled as an estimate.

# AWS Backup's own names for what a restore job or restore testing selection is about.
_RESTORE_TYPE = {"AWS::EC2::Volume": "EBS", "AWS::RDS::DBInstance": "RDS", "AWS::RDS::AuroraCluster": "Aurora",
                 "AWS::RDS::NeptuneCluster": "Neptune", "AWS::RDS::DocDBCluster": "DocumentDB",
                 "AWS::RDS::DBCluster": "RDS", "AWS::DynamoDB::Table": "DynamoDB", "AWS::S3::Bucket": "S3"}


def _restore_succeeded(job: Dict) -> bool:
    """A restore that completed and, for a restore test, passed its validation."""
    return job.get("Status") == "COMPLETED" and job.get("ValidationStatus") not in ("FAILED", "TIMED_OUT")


def _restore_failed(job: Dict) -> bool:
    return job.get("Status") in ("FAILED", "ABORTED") or (
        job.get("Status") == "COMPLETED" and job.get("ValidationStatus") in ("FAILED", "TIMED_OUT"))


def _restore_minutes(job: Dict) -> Optional[float]:
    start, end = job.get("CreationDate"), job.get("CompletionDate")
    if not start or not end:
        return None
    return max(0.0, (_as_dt(end) - _as_dt(start)).total_seconds() / 60)


def restore_selection_matches(selection: Dict, resource: Dict) -> bool:
    """Whether one restore testing selection picks this resource: its type, then its ARN pattern or its tags."""
    if selection.get("type") != _RESTORE_TYPE.get(resource.get("resourceType", "")):
        return False
    arns = selection.get("arns") or []
    if arns and not any(fnmatch.fnmatchcase(resource.get("arn", ""), pattern) for pattern in arns):
        return False
    tags = resource.get("tags") or {}

    def value_of(key: str) -> Optional[str]:
        return tags.get(key.split("/", 1)[1] if key.startswith("aws:ResourceTag/") else key)
    if any(value_of(k) != v for k, v in selection.get("equals") or []):
        return False
    if any(value_of(k) == v for k, v in selection.get("not_equals") or []):
        return False
    return True


def apply_restore_evidence(resources: List[Dict], jobs: List[Dict], plans: List[Dict], vaults: List[Dict],
                           lookback_days: int = RESTORE_LOOKBACK_DAYS) -> Dict[str, Any]:
    """Set restore fields on each resource and return the estate-level figures."""
    vault_info = {v.get("BackupVaultArn", ""): v for v in vaults if v.get("BackupVaultArn")}
    by_resource: Dict[str, List[Dict]] = {}
    for j in jobs:
        if j.get("SourceResourceArn"):
            by_resource.setdefault(j["SourceResourceArn"], []).append(j)

    def from_a_copy(job: Dict) -> bool:
        """The restore read a recovery point from another account's vault or an air-gapped vault."""
        vault_arn = job.get("BackupVaultArn", "")
        parts = vault_arn.split(":")
        other_account = len(parts) > 4 and parts[4] and parts[4] != job.get("account_id", parts[4])
        return bool(other_account or (vault_info.get(vault_arn) or {}).get("is_air_gapped"))

    # What this estate has actually restored, by kind: the basis for any estimate.
    observed: Dict[str, List[Tuple[float, float]]] = {}
    for j in jobs:
        minutes = _restore_minutes(j)
        if _restore_succeeded(j) and minutes is not None and j.get("ResourceType"):
            observed.setdefault(j["ResourceType"], []).append((minutes, (j.get("BackupSizeInBytes") or 0) / 1024 ** 3))

    for r in resources:
        mine = by_resource.get(r.get("arn", ""), [])
        done = sorted((j for j in mine if _restore_succeeded(j)), key=lambda j: _as_dt(j.get("CompletionDate") or j.get("CreationDate")))
        failed = [j for j in mine if _restore_failed(j)]
        last = done[-1] if done else None
        minutes = _restore_minutes(last) if last else None
        tier = r.get("recovery_tier")
        rto_minutes = RECOVERY_TIERS[tier]["rto_hours"] * 60 if tier else None
        decided = len(done) + len(failed)
        estimate = None
        if not done and (r.get("size_gib") or 0) > 0 and observed.get(_RESTORE_TYPE.get(r.get("resourceType", ""), "")):
            longest = max(observed[_RESTORE_TYPE[r["resourceType"]]], key=lambda x: x[0])
            estimate = round(longest[0] * max(1.0, (r["size_gib"] / longest[1]) if longest[1] > 0 else 1.0), 1)
        tested = [bool(pl.get("detail_readable")) and any(restore_selection_matches(sel, r) for sel in pl.get("selections", []))
                  for pl in plans]
        unreadable = any(not pl.get("detail_readable", True) for pl in plans)
        r.update({
            "restore_jobs_in_window": len(mine),
            "last_successful_restore_at": _iso(last.get("CompletionDate")) if last else "",
            "last_restore_duration_minutes": round(minutes, 1) if minutes is not None else None,
            "restore_success_rate": round(len(done) / decided, 2) if decided else None,
            "restore_within_rto": (minutes <= rto_minutes) if (minutes is not None and rto_minutes) else None,
            "restore_from_copy": any(from_a_copy(j) for j in done),
            "restore_estimate_minutes": estimate,
            "restore_test_selected": True if any(tested) else (None if unreadable else False),
        })

    def tier_row(tier: int) -> Dict[str, int]:
        rows = [r for r in resources if r.get("recovery_tier") == tier and r.get("protection_state") != "not_assessed"]
        return {"resources": len(rows),
                "restored": sum(1 for r in rows if r["last_successful_restore_at"]),
                "within_rto": sum(1 for r in rows if r["restore_within_rto"]),
                "over_rto": sum(1 for r in rows if r["restore_within_rto"] is False),
                "test_selected": sum(1 for r in rows if r["restore_test_selected"]),
                "test_unknown": sum(1 for r in rows if r["restore_test_selected"] is None),
                "estimated": sum(1 for r in rows if r["restore_estimate_minutes"] is not None)}
    air_gapped_plans = [pl.get("RestoreTestingPlanName", "") for pl in plans
                        if any(name in (v.get("BackupVaultName"), v.get("BackupVaultArn")) and v.get("is_air_gapped")
                               and v.get("account_id") == pl.get("account_id") for name in pl.get("include_vaults", []) for v in vaults)]
    done_jobs = [j for j in jobs if _restore_succeeded(j)]

    # How restores ended, and the reasons AWS gave.  Generated ids in a message are replaced so equal reasons group.
    outcomes: Dict[Tuple[str, str, str], int] = {}
    reasons: Dict[str, int] = {}
    for j in jobs:
        key = (j.get("Status", ""), j.get("ValidationStatus", ""), j.get("ResourceType", ""))
        outcomes[key] = outcomes.get(key, 0) + 1
        if _restore_failed(j):
            text = j.get("StatusMessage") or j.get("ValidationStatusMessage") or ""
            text = _UUID.sub("<id>", clean_text(text, 160))
            if text:
                reasons[text] = reasons.get(text, 0) + 1
    summary = {
        "lookback_days": lookback_days,
        "jobs": len(jobs), "succeeded": len(done_jobs), "failed": sum(1 for j in jobs if _restore_failed(j)),
        "in_progress": sum(1 for j in jobs if j.get("Status") in ("PENDING", "RUNNING")),
        "outcomes": [{"status": k[0], "validation": k[1], "type": k[2], "count": n}
                     for k, n in sorted(outcomes.items(), key=lambda kv: -kv[1])],
        "reasons": [{"text": t, "count": n} for t, n in sorted(reasons.items(), key=lambda kv: -kv[1])[:3]],
        "from_copy": sum(1 for j in done_jobs if from_a_copy(j)),
        "test_jobs": sum(1 for j in jobs if (j.get("CreatedBy") or {}).get("RestoreTestingPlanArn")),
        "plans": len(plans), "plans_unreadable": sum(1 for pl in plans if not pl.get("detail_readable", True)),
        "plans_from_air_gapped_vault": air_gapped_plans,
        "tiers": {t: tier_row(t) for t in RECOVERY_TIERS},
        "observed_kinds": {k: len(v) for k, v in sorted(observed.items())},
    }
    t1 = summary["tiers"][1]
    if t1["resources"] and t1["within_rto"] == t1["resources"]:
        level = 3
    elif jobs or plans:
        level = 2
    else:
        level = 1
    summary["level"] = level
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# Owners, questions and references
# ─────────────────────────────────────────────────────────────────────────────
# Three ways to turn the findings into something a person can act on, without telling anyone what to do:
#   owners      who a resource probably belongs to, inferred, so each person sees only their part
#   questions   what each finding asks the people who own the resources, phrased as a decision
#   references  where AWS itself describes the practice a finding relates to (links only, no pass or fail)

# Tag keys that name an owner, strongest first.  Application-style keys are used only when no owner key exists.
OWNER_TAG_KEYS = ("owner", "Owner", "team", "Team", "owner-team", "OwnerTeam")
APPLICATION_TAG_KEYS = ("application", "Application", "app", "App", "service", "Service", "project", "Project")
_OWNER_TEXT_LIMIT = 60


def tag_facts(resource: Dict) -> Dict[str, Any]:
    """Whether and how a resource is tagged.  Tag keys are listed, tag values never are: values can hold sensitive text."""
    tags = resource.get("tags") or {}
    keys = sorted(str(k) for k in tags)
    env = {k.lower() for k in PRODUCTION_TAG_KEYS}
    owner = {k.lower() for k in OWNER_TAG_KEYS}
    return {"tag_count": len(keys), "has_tags": bool(keys),
            "has_environment_tag": any(k.lower() in env for k in keys),
            "has_owner_tag": any(k.lower() in owner for k in keys),
            "tag_keys": clean_text("|".join(keys), 200)}


def owner_hint(resource: Dict, group_by_resource: Optional[Dict[str, str]] = None) -> Tuple[str, str]:
    """(owner, basis) for a resource: an owner tag, else an application tag, else a grouping the tool found
    (CloudFormation stack, AppRegistry application, cluster), else the account.  Inferred; the report says so."""
    tags = resource.get("tags") or {}
    for keys, label in ((OWNER_TAG_KEYS, "owner tag"), (APPLICATION_TAG_KEYS, "application tag")):
        for key in keys:
            if tags.get(key):
                return clean_text(tags[key], _OWNER_TEXT_LIMIT), f"{label} ({key})"
    group = (group_by_resource or {}).get(resource.get("arn", "")) or (group_by_resource or {}).get(resource.get("resourceId", ""))
    if group:
        return clean_text(group, _OWNER_TEXT_LIMIT), "application group"
    return clean_text(resource.get("account_name") or resource.get("account_id", ""), _OWNER_TEXT_LIMIT), "account"


def group_index(app_groups: List[Dict]) -> Dict[str, str]:
    """resource ARN or id -> the name of the first high-confidence group that lists it."""
    index: Dict[str, str] = {}
    for g in app_groups:
        if g.get("grouping_confidence") != "high":
            continue
        for rid in g.get("resource_ids", []):
            index.setdefault(rid, g.get("name", ""))
    return index


def compute_owner_view(resources: List[Dict]) -> List[Dict]:
    """One row per inferred owner, ranked by production resources with no copy.  Counts only; no judgement."""
    rows: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for r in resources:
        key = (r.get("owner_hint", ""), r.get("owner_basis", ""))
        row = rows.setdefault(key, {"owner": key[0], "basis": key[1], "resources": 0, "production": 0, "no_copy": 0,
                                    "policy_only_or_stale": 0, "not_assessed": 0, "deletion_exposed": 0, "unmanaged_volumes": 0})
        row["resources"] += 1
        state = r.get("recovery_copy_state")
        if state == "not_assessed":
            row["not_assessed"] += 1
        if r.get("criticality") == "production":
            row["production"] += 1
            if state == "none":
                row["no_copy"] += 1
            elif state in ("policy_only", "stale"):
                row["policy_only_or_stale"] += 1
        if r.get("deletion_exposed"):
            row["deletion_exposed"] += 1
        if r.get("unmanaged_data"):
            row["unmanaged_volumes"] += 1
    return sorted(rows.values(), key=lambda x: (-x["no_copy"], -x["policy_only_or_stale"], -x["deletion_exposed"],
                                                -x["resources"], x["owner"]))


# AWS's own descriptions of the practices these findings relate to.  Links only: nothing is fetched, and a link
# is not a statement that the customer meets or misses the practice.
_WA = "https://docs.aws.amazon.com/wellarchitected/latest/framework/"
REFERENCES: Dict[str, Tuple[str, str]] = {
    "no_copy": ("REL09-BP01 Identify and back up all data that needs to be backed up",
                _WA + "rel_backing_up_data_identified_backups_data.html"),
    "automation": ("REL09-BP03 Perform data backup automatically",
                   _WA + "rel_backing_up_data_automated_backups_data.html"),
    "secure": ("REL09-BP02 Secure and encrypt backups", _WA + "rel_backing_up_data_secured_backups_data.html"),
    "restore": ("REL09-BP04 Perform periodic recovery of the data to verify backup integrity and processes",
                _WA + "rel_backing_up_data_periodic_recovery_testing_data.html"),
    "recovery_strategy": ("REL13-BP02 Use defined recovery strategies to meet the recovery objectives",
                          _WA + "rel_planning_for_recovery_disaster_recovery.html"),
    "rds_deletion": ("Amazon RDS: deleting a DB instance",
                     "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html"),
    "ddb_deletion": ("Amazon DynamoDB: table basics, including deletion protection",
                     "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithTables.Basics.html"),
    "ebs_sharing": ("Amazon EBS: sharing a snapshot with other accounts",
                    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html"),
    "s3_backup_versioning": ("AWS Backup: Amazon S3 backups, backups and versioning",
                             "https://docs.aws.amazon.com/aws-backup/latest/devguide/s3-backups.html#s3-backup-versioning"),
    "s3_eventbridge": ("AWS Backup: Amazon EventBridge dependency for S3 continuous backups",
                       "https://docs.aws.amazon.com/aws-backup/latest/devguide/s3-backups.html#s3-eventbridge-dependency"),
    "object_lock": ("Amazon S3 Object Lock", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html"),
    "org_backup": ("AWS Organizations backup policies",
                   "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_backup.html"),
}


def compute_questions(census: Dict[str, Any], copies: Dict[str, Any], owners: List[Dict],
                      drift: Optional[Dict[str, Any]] = None, gap_count: int = 0,
                      security: Optional[Dict[str, Any]] = None,
                      restore: Optional[Dict[str, Any]] = None,
                      jobs: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Each finding that has something behind it, with the question it asks and where to see the resources.

    A question is not an instruction: it names a decision the owner may or may not have made.  A finding with a
    count of zero produces no question."""
    c, o, x = census, copies["orphans"], copies["exposure"]
    q: List[Dict[str, Any]] = []

    def add(count: int, finding: str, question: str, where: str, ref: Optional[str] = None, group: str = "recovery",
            view: str = "") -> None:
        if count:
            q.append({"count": count, "finding": finding, "question": question, "where": where, "reference": ref,
                      "group": group, "view": view})

    # Each item is the finding, what it means, then the decision it asks for.  The full explanation is in the section it links to.
    # Recovery: whether a copy exists and would be there when needed
    no_copy = c.get("no_copy_identified", c["strict_no_copy"])
    sps = c.get("same_plan_scope") or {}
    assigned = c.get("assigned_no_copy", 0)
    subs = []
    if assigned:
        subs.append(f"{assigned:,} {'is' if assigned == 1 else 'are'} assigned to protection with no copy yet")
    if sps.get("count"):
        subs.append(f"{sps['count']:,} {'sits' if sps['count'] == 1 else 'sit'} in an account and Region where a backup plan already "
                    f"runs, so check whether that plan can include {'it' if sps['count'] == 1 else 'them'}")
    # The other production resources with no copy are counted elsewhere, said here so the figures reconcile with the first page.
    ps = c.get("production_states") or {}
    decided, no_path = ps.get("excluded_documented", 0), ps.get("no_backup_path", 0)
    elsewhere = [x for x in ((f"{decided:,} with a decision on record" if decided else ""),
                             (f"{_n(no_path, 'Apache Iceberg table')} with no table-level recovery identified" if no_path else "")) if x]
    add(no_copy, _NO_COPY_FINDING,
        "None found by the mechanisms assessed. " + (f"Of these, {'; '.join(subs)}. " if subs else "")
        + (f"Not counted here: {' and '.join(elsewhere)}. " if elsewhere else "")
        + "Does each need a backup, or is it protected another way (another tool, or rebuilt from source)?",
        "assets.csv (recovery_evidence = none_identified, criticality = production); exclusion-worksheet.csv records the answer",
        "no_copy", view="sec-assets")
    reasons = c.get("copy_reasons") or {}
    if reasons.get("resources"):
        parts = [f"for {reasons[k]:,}, {label}" for k, label in (
            ("latest_failed", "the latest backup job failed, though an earlier copy exists"),
            ("older_than_target", "the newest copy is older than the recovery point target allows"),
            ("schedule_slower", "the backup schedule runs less often than the target, for example weekly backups against a "
                                "24-hour target")) if reasons.get(k)]
        add(reasons["resources"], "Production resources whose backups are late or failing",
            "A copy exists, but: " + "; ".join(parts) + ". The targets are default assumptions (a copy every 24 hours for all "
            "production) that the targets file changes. Is the schedule meant to be this way?",
            "assets.csv (recovery_evidence, evidence_badges, frequency_exceeds_rpo)", "automation", view="sec-jobs")
    add(c.get("retention_short", 0), "Production resources with limited retention",
        "Their copies are kept for less time than the target. In our experience, production resources are typically retained for "
        "90 days or more; the targets here (365 days for confidential production data, 90 for other production) are default "
        "assumptions the targets file changes. For databases, short-term point-in-time recovery is often all that is needed, so a "
        "short window may be intended. What recovery window does each application owner need?",
        "assets.csv (short_window_days, long_term_days, observed_oldest_days, retention_vs_target = short)", "automation",
        view="sec-targets")
    if jobs:
        cp = jobs["copy"]
        add(cp.get("resources_with_gap", 0), "Resources whose latest copy to another account or Region did not complete",
            "No later copy to that destination completed. Check whether an earlier copy meets the recovery need.",
            "assets.csv (copy_gap_destinations)", "recovery_strategy", view="sec-jobs")
        add(jobs["failures_without_alert"], "Failed backup jobs in vaults with no failure alert configured",
            "Who owns backup failures, and where do the notifications go?", "report: Backups and restores", "automation", view="sec-jobs")
    # Databases with no copy at all are already in the first item; this one names those whose only copy goes with them.
    add(copies.get("deletion_exposed_with_copy", 0), "Databases whose only copy would be deleted with them",
        "They have automated backups but no deletion protection, and automated backups are removed when the database is deleted "
        "(unless they are retained at deletion). A manual snapshot or an AWS Backup copy would outlive it. Do these need deletion protection or a copy that outlives them?",
        "assets.csv (deletion_exposed = True, recovery_evidence not none_identified)", "rds_deletion", view="sec-sharing")
    s3v = c.get("s3_backup_versioning") or {}
    add(s3v.get("off", 0), "S3 buckets selected for backup without versioning enabled",
        "AWS Backup requires versioning to back up these buckets. Is versioning meant to be on?",
        "assets.csv (s3_versioning, plan_selected = True)", "s3_backup_versioning", view="sec-coverage")
    s3c = c.get("s3_continuous") or {}
    add(s3c.get("off", 0), "Continuously backed-up S3 buckets with EventBridge notifications off",
        "New changes are not added to the continuous recovery window, and AWS Backup raises no alert. Existing recovery points "
        "and periodic backups are not affected. Are notifications meant to be on?",
        "assets.csv (s3_eventbridge = off, s3_continuous_backup = True)", "s3_eventbridge", view="sec-coverage")
    add(len(c.get("near_misses", [])), "Tags that miss a backup selection by spelling only",
        "Their tag looks like a typo of the one the plan selects (for example env versus Env). Are they meant to be selected?",
        "report: tag view and whole-estate view", "automation", view="sec-coverage")
    # Restore findings are not listed here: they rest on what AWS Backup recorded, which does not see restores done any other way,
    # so most resources would read "no restore on record" and the list would say little.  The Restores section keeps the facts.
    if drift and drift["regressions"]:
        add(len(drift["regressions"]), "Resources that had a copy last time and have none now",
            "They had a copy at the last review and do not now. On purpose?", "changes.csv", "automation",
            view="sec-change")

    # Isolation and security: whether a copy would survive stolen credentials or a bad key
    if security:
        enc, pol, res = security["encryption"], security["policies"], security["residency"]
        add(len(enc["unusable_keys"]), "Vaults whose key is disabled or pending deletion",
            "Copies in these vaults cannot be restored while the key is unusable. Are they still needed, and was the key disabled on purpose?",
            "vault-security.csv", "secure", "security", view="sec-security")
        # Accounts with no service control policy guarding backups are said in Backup copy protection, beside Vault Lock, not here:
        # the review sees SCPs only from the management account, and a missing one does not mean deletion is permitted.
        add(len(pol["external"]), "Vault policies that let other accounts in",
            "These vaults can be reached from other accounts. Are those the right accounts?", "vault-security.csv", "secure", "security",
            view="sec-security")
        add(enc["unencrypted_recovery_points"], "Recovery points that are not encrypted",
            "Is unencrypted storage acceptable for this data?", "vault-security.csv", "secure", "security", view="sec-security")
        scan = security["scan"]
        add(scan["plans"] if scan["plans"] and not scan["plans_with_scan"] else 0, "Backup plans with no malware scan",
            "Copies are not scanned for malware. Is that checked another way?", "report: Backup copy protection, malware scanning",
            "secure", "security", view="sec-security")
        add(res["sensitive_resources_with_copy_elsewhere"], "Sensitive resources with a copy in another geographic area",
            "Does a copy there fit the rules for this data?", "assets.csv (copy_geographies)",
            "recovery_strategy", "security", view="sec-security")
    kinds = [(len(x["public_ebs_snapshots"]), "EBS snapshot"), (len(x["public_images"]), "machine image"),
             (len(x["rds_public"]), "RDS snapshot")]
    public = sum(n for n, _ in kinds)
    add(public, "Publicly shared snapshots or machine images",
        "; ".join(f"{n:,} {k}{'' if n == 1 else 's'}" for n, k in kinds if n) + ". Any AWS account can restore them. "
        "Is public access intended, for example a published image?",
        "shared-backups.csv", "ebs_sharing", "security", view="sec-sharing")
    add(len(x["rds_shared"]), "RDS snapshots shared with specific other accounts",
        "Those accounts can restore them. Are they the right accounts?", "shared-backups.csv", "ebs_sharing", "security",
        view="sec-sharing")

    # Spend that may not be intended
    add(len(o["rows"]), "Copies whose source was not found in the assessed inventory",
        "Still needed? One may be the only copy of deleted data.", "orphaned-copies.csv", "no_copy",
        "spend", view="sec-copies")
    add(copies["unattached_volumes"], "EBS volumes attached to no instance",
        "No instance uses them. Still needed, and is anything backing them up?", "assets.csv (unattached = True)",
        "no_copy", "spend", view="sec-copies")

    # Classification and setup: what the figures above rest on
    add(c.get("expired_exclusions", 0), "Backup exceptions due for review",
        "Confirm the owner, the reason and the next review date.", "assets.csv (exclusion_status = expired)",
        "no_copy", "setup", view="sec-coverage")
    add(c["unknown_environment"], "Resources whose environment could not be inferred",
        "Nothing says what they are. Which hold production data? The overrides file records the answer.",
        "assets.csv (criticality_basis = none); --overrides records the answer", "no_copy", "setup", view="sec-assets")
    basis = c.get("environment_basis") or {}
    add(sum(n for b, n in basis.items() if b not in ("tag", "override", "none")),
        "Resources with no environment tag, classified from account, name or usage",
        "Is the inferred environment right? The overrides file records the answer.",
        "assets.csv (criticality_basis, has_environment_tag = False)", None, "setup", view="sec-assets")
    add(len(c.get("mismatch", [])), "Resources labelled development that look like production",
        "The label says development but they are set up like production. Is the label out of date?", "assets.csv (tag_behaviour_mismatch = True)", None, "setup",
        view="sec-coverage")
    idle_plans = c.get("plans_selecting_nothing") or {"no_assignment": []}
    add(len(idle_plans["no_assignment"]), "Backup plans with nothing assigned",
        "The plans select no resources. Left over, or waiting to be used?", "report: Recovery copies, backup plans that select nothing", None,
        "setup", view="sec-coverage")
    add(gap_count, "Calls that were denied or failed",
        "The review could not read these. Can the access be granted, or are they out of scope?",
        "coverage-gaps.csv", None, "setup", view="sec-gaps")
    return q


# ─────────────────────────────────────────────────────────────────────────────
# Census: how much of the estate has a recovery copy, counted the same way every run
# ─────────────────────────────────────────────────────────────────────────────
# These figures describe what was found.  Environment and sensitivity are inferred (the report says so and
# shows the basis), a resource that could not be assessed is left out of every denominator and counted on
# its own, and nothing here is a grade.

_GAP_STATES = ("none", "policy_only", "stale")


def _median(values: List[float]) -> Optional[float]:
    values = sorted(values)
    if not values:
        return None
    mid = len(values) // 2
    return float(values[mid]) if len(values) % 2 else (values[mid - 1] + values[mid]) / 2


def _pct(part: int, whole: int) -> Optional[float]:
    return round(100.0 * part / whole, 1) if whole else None


def selection_tag_keys(plans: List[Dict]) -> set:
    """Tag keys that any backup selection uses to pick resources (Conditions and ListOfTags)."""
    keys = set()
    for plan in plans:
        for sel in plan.get("Selections", []) or []:
            conditions = sel.get("Conditions") or {}
            for group in conditions.values():
                for cond in group or []:
                    key = str(cond.get("ConditionKey", ""))
                    if key.startswith("aws:ResourceTag/"):
                        keys.add(key.split("/", 1)[1])
            for cond in sel.get("ListOfTags") or []:
                key = str(cond.get("ConditionKey", ""))
                keys.add(key.split("/", 1)[1] if key.startswith("aws:ResourceTag/") else key)
    return {k for k in keys if k}


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def tag_near_misses(resources: List[Dict], plans: List[Dict], limit: int = 10) -> List[Dict]:
    """Tags that differ from a tag a selection uses only by case or punctuation (env vs Env, back-up vs backup).

    A resource carrying one of these misses the selection because of spelling, not because anyone decided
    to leave it out.  Reported as facts with a count; the tag value is shown only for tags that nearly match."""
    wanted: Dict[str, set] = {}
    exact: Dict[str, set] = {}
    for plan in plans:
        for sel in plan.get("Selections", []) or []:
            conditions = list((sel.get("Conditions") or {}).values())
            pairs = [c for group in conditions for c in (group or [])] + list(sel.get("ListOfTags") or [])
            for cond in pairs:
                key = str(cond.get("ConditionKey", ""))
                key = key.split("/", 1)[1] if key.startswith("aws:ResourceTag/") else key
                if key:
                    wanted.setdefault(_norm(key), set()).add(key)
                    exact.setdefault(key, set()).add(str(cond.get("ConditionValue", "")))
    found: Dict[Tuple[str, str, str], int] = {}
    for r in resources:
        if r.get("has_backup_recovery_point") and r.get("plan_selected"):
            continue
        for key, value in (r.get("tags") or {}).items():
            if key in exact:
                if value not in exact[key] and any(_norm(value) == _norm(v) for v in exact[key]):
                    found[(key, clean_text(value, 40), "value")] = found.get((key, clean_text(value, 40), "value"), 0) + 1
            elif _norm(key) in wanted:
                found[(clean_text(key, 60), "", "key")] = found.get((clean_text(key, 60), "", "key"), 0) + 1
    rows = [{"key": k, "value": v, "kind": kind, "resources": n} for (k, v, kind), n in found.items()]
    return sorted(rows, key=lambda row: (-row["resources"], row["key"]))[:limit]


def _tagging_summary(rows: List[Dict], selection_keys: set) -> Dict[str, Any]:
    """How many resources carry any tag, an environment tag, an owner tag, or a tag a backup selection uses, overall and by type."""
    def facts(r: Dict) -> Dict[str, Any]:
        return r if "has_tags" in r else {**r, **tag_facts(r)}
    prepared = [facts(r) for r in rows]

    def row(items: List[Dict]) -> Dict[str, int]:
        return {"resources": len(items), "any": sum(1 for r in items if r["has_tags"]),
                "environment": sum(1 for r in items if r["has_environment_tag"]),
                "owner": sum(1 for r in items if r["has_owner_tag"]),
                "selection": sum(1 for r in items if any(k in (r.get("tags") or {}) for k in selection_keys))}
    by_type: Dict[str, List[Dict]] = {}
    for r in prepared:
        by_type.setdefault(r.get("resourceType", ""), []).append(r)
    return {"all": row(prepared), "by_type": {t: row(v) for t, v in sorted(by_type.items())},
            "selection_keys": len(selection_keys)}


def _count_by(rows: List[Dict], key) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for row in rows:
        out[key(row)] = out.get(key(row), 0) + 1
    return out


def plans_selecting_nothing(plans: List[Dict], resources: List[Dict]) -> Dict[str, List[Dict]]:
    """Backup plans with no resource assignment (they protect nothing), and plans with assignments that select none of the
    resources assessed (they may select a kind of resource this review does not cover)."""
    used = {pid for r in resources for pid in str(r.get("matching_plan_ids", "")).split("|") if pid}
    empty, unmatched = [], []
    for plan in plans:
        row = {"name": plan.get("BackupPlanName", ""), "account_id": plan.get("account_id", ""), "region": plan.get("region", "")}
        selections = plan.get("Selections") or []
        if not selections:
            empty.append(row)
        elif any(sel.get("_detail_unavailable") for sel in selections):
            continue                                  # could not be read: not a statement about what it selects
        elif f"{plan.get('account_id', '')}:{plan.get('region', '')}:{plan.get('BackupPlanId', '')}" not in used:
            unmatched.append(row)
    return {"no_assignment": empty, "selects_none_assessed": unmatched}


def _all_buckets(n: int, noun: str = "bucket") -> str:
    """"The only bucket" or "All 12 buckets", for a sentence about every bucket a plan selects."""
    return f"The only {noun}" if n == 1 else (f"Both {noun}s" if n == 2 else f"All {n:,} {noun}s")


def compute_s3_continuous(resources: List[Dict]) -> Dict[str, Any]:
    """Buckets a plan backs up continuously, split by whether Amazon EventBridge notifications are on.  AWS documents that continuous
    backups of a bucket rely on them: with the setting off, changes are no longer tracked and AWS Backup raises no alert and no
    failed job.  A bucket whose setting was not read is counted apart, never as off."""
    buckets = [r for r in resources if r.get("resourceType") == "AWS::S3::Bucket" and r.get("protection_state") != "not_assessed"
               and r.get("plan_selected") and r.get("s3_continuous_backup")]
    off = [r for r in buckets if r.get("s3_eventbridge") == "off"]
    ordered = sorted(off, key=lambda r: (str(r.get("account_name", "")), str(r.get("resourceName") or r.get("resourceId", ""))))
    return {
        "continuous": len(buckets), "on": sum(1 for r in buckets if r.get("s3_eventbridge") == "on"), "off": len(off),
        "unknown": sum(1 for r in buckets if r.get("s3_eventbridge") in ("unknown", "", None)),
        "rows": [{"account": clean_text(str(r.get("account_name", "")), 60),
                  "bucket": clean_text(str(r.get("resourceName") or r.get("resourceId", "")), 63)} for r in ordered[:15]],
    }


def compute_backup_by_type(resources: List[Dict]) -> List[Dict]:
    """AWS Backup, one row per resource type: how many assessed resources a plan selects now, how many hold a recovery point,
    how many have backup jobs that have been failing.  Resources that could not be assessed are counted apart and are in none of the
    other columns: an unassessed resource is neither covered nor uncovered."""
    rows: Dict[str, Dict] = {}
    for r in resources:
        kind = r.get("resourceType", "")
        row = rows.setdefault(kind, {"type": kind, "assessed": 0, "not_assessed": 0, "selected": 0,
                                     "with_recovery_point": 0, "jobs_failing": 0})
        if r.get("protection_state") == "not_assessed":
            row["not_assessed"] += 1
            continue
        row["assessed"] += 1
        row["selected"] += 1 if r.get("plan_selected") else 0
        row["with_recovery_point"] += 1 if r.get("has_backup_recovery_point") else 0
        row["jobs_failing"] += 1 if r.get("job_failing") else 0
    return sorted(rows.values(), key=lambda x: (-(x["assessed"] + x["not_assessed"]), x["type"]))


S3_VERSIONING_OFF = ("suspended", "never_enabled", "not_enabled")


def compute_s3_backup_versioning(resources: List[Dict]) -> Dict[str, Any]:
    """AWS Backup for S3 needs S3 Versioning on the bucket.  Of the buckets a plan selects now, how many have it off or
    suspended, and for how many the answer was not read (neither a yes nor a no)."""
    buckets = [r for r in resources if r.get("resourceType") == "AWS::S3::Bucket" and r.get("protection_state") != "not_assessed"]
    selected = [r for r in buckets if r.get("plan_selected")]
    off = [r for r in selected if r.get("s3_versioning") in S3_VERSIONING_OFF]
    unknown = [r for r in selected if r.get("s3_versioning") in ("unknown", "", None)]
    ordered = sorted(off, key=lambda r: (str(r.get("account_name", "")), str(r.get("resourceName") or r.get("resourceId", ""))))
    return {
        "buckets": len(buckets), "selected": len(selected), "off": len(off), "unknown": len(unknown),
        "on": sum(1 for r in selected if r.get("s3_versioning") == "enabled"),
        "off_with_failed_jobs": sum(1 for r in off if r.get("backup_failures_in_window")),
        "rows": [{"account": clean_text(str(r.get("account_name", "")), 60),
                  "bucket": clean_text(str(r.get("resourceName") or r.get("resourceId", "")), 63),
                  "versioning": r.get("s3_versioning", ""), "failed_jobs": int(r.get("backup_failures_in_window") or 0)}
                 for r in ordered[:15]],
    }


def compute_copy_reasons(resources: List[Dict]) -> Dict[str, int]:
    """Production resources that have a recovery copy but an outdated one or a failing latest job, one reason each, in the order a
    person would check: the latest job failed (an earlier copy still exists), the newest copy is older than the target, or the
    schedule runs less often than the target.  Needs the job outcomes, so it runs after they are attached."""
    out = {"latest_failed": 0, "older_than_target": 0, "schedule_slower": 0}
    for r in resources:
        if r.get("criticality") != "production" or r.get("recovery_evidence") not in ("current", "outdated"):
            continue
        if r.get("latest_backup_failed") or r.get("job_failing"):
            out["latest_failed"] += 1
        elif r.get("recovery_evidence") == "outdated":
            out["older_than_target"] += 1
        elif r.get("frequency_exceeds_rpo"):
            out["schedule_slower"] += 1
    out["resources"] = sum(out.values())
    return out


def mark_same_plan_scope(resources: List[Dict]) -> Dict[str, Any]:
    """Production resources with no copy that sit in an account and Region where an AWS Backup plan already selects others.

    A backup plan lives in one account and Region, so these are the resources a plan beside them could reach.  Sets
    `same_plan_scope` and `plans_in_same_scope` (the plans' names) on every resource, and returns the figures.  A resource whose
    service is not opted in for AWS Backup in its Region is left out: a plan there would not back it up.  Safe to call twice."""
    names: Dict[Tuple[str, str], set] = {}
    for r in resources:
        if r.get("plan_selected") and r.get("protection_state") != "not_assessed" and r.get("account_id") and r.get("awsRegion"):
            names.setdefault((r["account_id"], r["awsRegion"]), set()).update(n for n in str(r.get("matching_plan_names", "")).split("|") if n)
    production_none = [r for r in resources if r.get("criticality") == "production" and r.get("recovery_copy_state") == "none"]
    none_ids = {id(r) for r in production_none}
    hits = []
    for r in resources:
        here = names.get((r.get("account_id", ""), r.get("awsRegion", "")))
        inside = bool(here) and id(r) in none_ids and r.get("backup_opted_in") is not False
        r["same_plan_scope"] = inside
        r["plans_in_same_scope"] = "|".join(sorted(here)) if inside else ""
        if inside:
            hits.append(r)
    return {"count": len(hits), "of": len(production_none),
            "scopes": len({(r["account_id"], r["awsRegion"]) for r in hits}),
            "plans": len({n for r in hits for n in r["plans_in_same_scope"].split("|")})}


def compute_census(resources: List[Dict], plans: Optional[List[Dict]] = None,
                   classification: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The census numbers.  Every denominator is stated next to its figure."""
    plans = plans or []
    classification = classification or {}
    assessed = [r for r in resources if r.get("recovery_copy_state") not in (None, "not_assessed")]
    not_assessed = [r for r in resources if r.get("recovery_copy_state") == "not_assessed"]
    production = [r for r in assessed if r.get("criticality") == "production"]
    unknown_env = [r for r in assessed if r.get("criticality") == "unknown"]
    states = {}
    for r in assessed:
        states[r["recovery_copy_state"]] = states.get(r["recovery_copy_state"], 0) + 1
    prod_states: Dict[str, int] = {}
    for r in production:
        prod_states[r["recovery_copy_state"]] = prod_states.get(r["recovery_copy_state"], 0) + 1
    # The recovery-evidence states every coverage figure counts from, so this section shows the first page's numbers.
    evidence_states: Dict[str, int] = {}
    prod_evidence: Dict[str, int] = {}
    # The same states by inferred environment, for the one table that shows them (Recovery copies).
    by_environment: Dict[str, Dict[str, int]] = {"production": prod_evidence, "development": {}, "unknown": {}}
    for r in assessed:
        k = recovery_evidence_of(r)
        evidence_states[k] = evidence_states.get(k, 0) + 1
        env = r.get("criticality") if r.get("criticality") in ("production", "development") else "unknown"
        by_environment[env][k] = by_environment[env].get(k, 0) + 1

    # Three nested counts of production data.  Each includes the one before it.
    strict = prod_states.get("none", 0)
    with_policy_only = strict + prod_states.get("policy_only", 0)
    with_stale = with_policy_only + prod_states.get("stale", 0)
    prod_n = len(production)

    documented = [r for r in production if r["recovery_copy_state"] == "excluded_documented"]
    expired = [r for r in production if r.get("exclusion_status") == "expired"]
    undecided = prod_states.get("none", 0)
    decided_pool = undecided + len(documented)

    def breakdown(key_fn):
        out: Dict[str, Dict[str, int]] = {}
        for r in production:
            row = out.setdefault(key_fn(r), {"production": 0, "no_copy": 0, "policy_only": 0, "stale": 0})
            row["production"] += 1
            if r["recovery_copy_state"] == "none":
                row["no_copy"] += 1
            elif r["recovery_copy_state"] in ("policy_only", "stale"):
                row[r["recovery_copy_state"]] += 1
        return out

    # Why a production resource has no copy.  One cause each, in the order a person would check.
    near_miss_arns = set()
    causes = {"no policy selects it": 0, "service not opted in": 0, "AWS Backup job failing": 0,
              "new in the last 30 days": 0, "no signal of any kind": 0}
    for r in production:
        if r["recovery_copy_state"] not in ("none", "policy_only"):
            continue
        if r.get("opt_in_skipped"):
            causes["service not opted in"] += 1
        elif r.get("job_failing"):
            causes["AWS Backup job failing"] += 1
        elif r.get("is_new"):
            causes["new in the last 30 days"] += 1
        elif r["recovery_copy_state"] == "none" and not r.get("plan_selected"):
            causes["no policy selects it"] += 1
        else:
            causes["no signal of any kind"] += 1

    # The tag view and the whole-estate view of the same data.
    keys = selection_tag_keys(plans)
    env_keys = {k.lower() for k in PRODUCTION_TAG_KEYS}
    tagged = [r for r in assessed if any(k in (r.get("tags") or {}) for k in keys)]
    tagged_copied = sum(1 for r in tagged if r["recovery_copy_state"] in ("current", "stale", "orphan_policy"))
    all_copied = sum(1 for r in assessed if r["recovery_copy_state"] in ("current", "stale", "orphan_policy"))
    untagged = [r for r in assessed
                if not any(k.lower() in env_keys for k in (r.get("tags") or {}))
                and not any(k in (r.get("tags") or {}) for k in keys)]

    # Age.  Only resources whose creation time is known take part; the rest are counted, not assumed.
    def ages(rows):
        return [r["age_days"] for r in rows if r.get("age_days") is not None]
    gaps = [r for r in production if r["recovery_copy_state"] in ("none", "policy_only")]
    protected_prod = [r for r in production if r["recovery_copy_state"] in ("current", "stale", "orphan_policy")]
    gap_ages, protected_ages = ages(gaps), ages(protected_prod)
    old_gaps = sum(1 for a in gap_ages if a > 365)
    new_gaps = [r for r in gaps if r.get("is_new")]

    # Sensitive data.  Counted from the inferred level, so it is a lower bound where tags are sparse.
    def is_sensitive(r):
        return (_SENSITIVITY_RANK.get(r.get("data_sensitivity", "INTERNAL"), 1) >= 2
                or "PII" in str(r.get("data_classes", "")).split(","))
    sensitive = [r for r in assessed if is_sensitive(r)]
    sensitive_gap = [r for r in sensitive if r["recovery_copy_state"] == "none"]
    pii = [r for r in assessed if "PII" in str(r.get("data_classes", "")).split(",")]
    pii_gap = [r for r in pii if r["recovery_copy_state"] == "none"]

    # What the native-snapshot check could see, by type.  S3 and others are partial or not checked.
    visible = {"AWS::EC2::Volume": "snapshots", "AWS::RDS::DBInstance": "snapshots and automated backups",
               "AWS::RDS::AuroraCluster": "snapshots and automated backups",
               "AWS::RDS::NeptuneCluster": "snapshots and automated backups",
               "AWS::RDS::DocDBCluster": "snapshots and automated backups",
               "AWS::DynamoDB::Table": "on-demand backups and point-in-time recovery",
               "AWS::S3::Bucket": "versioning and replication only"}
    type_counts: Dict[str, int] = {}
    for r in assessed:
        type_counts[r.get("resourceType", "")] = type_counts.get(r.get("resourceType", ""), 0) + 1

    return {
        "resources": len(resources), "assessed": len(assessed), "not_assessed": len(not_assessed),
        "production": prod_n, "unknown_environment": len(unknown_env),
        "states": states, "production_states": prod_states,
        "evidence_states": evidence_states, "production_evidence": prod_evidence, "evidence_by_environment": by_environment,
        "strict_no_copy": strict, "with_policy_only": with_policy_only, "with_stale": with_stale,
        # Production resources with no recovery copy identified and no decision on record: nothing assigned (strict) plus assigned
        # to protection with no copy yet.  The first item in Items to review.
        "no_copy_identified": with_policy_only, "assigned_no_copy": prod_states.get("policy_only", 0),
        "retention_short": sum(1 for r in assessed if retention_vs_target(r) == "short"),
        "strict_pct": _pct(strict, prod_n), "policy_only_pct": _pct(with_policy_only, prod_n),
        "stale_pct": _pct(with_stale, prod_n),
        "documented_exclusions": len(documented), "expired_exclusions": len(expired),
        "decided_pct": _pct(len(documented), decided_pool), "decided_pool": decided_pool,
        "by_type": breakdown(lambda r: r.get("resourceType", "")),
        "by_account": breakdown(lambda r: r.get("account_name") or r.get("account_id", "")),
        "causes": causes,
        "tag_keys_in_selections": sorted(keys),
        "tag_view": {"resources": len(tagged), "with_copy": tagged_copied, "pct": _pct(tagged_copied, len(tagged))},
        "estate_view": {"resources": len(assessed), "with_copy": all_copied, "pct": _pct(all_copied, len(assessed))},
        "untagged": len(untagged), "untagged_pct": _pct(len(untagged), len(assessed)),
        "near_misses": tag_near_misses(assessed, plans),
        "gap_median_age_days": _median(gap_ages), "protected_median_age_days": _median(protected_ages),
        "gap_age_known": len(gap_ages), "gaps": len(gaps), "gaps_over_a_year": old_gaps,
        "new_gaps": len(new_gaps),
        "sensitive": len(sensitive), "sensitive_no_copy": len(sensitive_gap),
        "sensitive_pct": _pct(len(sensitive_gap), len(sensitive)),
        "pii": len(pii), "pii_no_copy": len(pii_gap), "pii_pct": _pct(len(pii_gap), len(pii)),
        "stale_by_frequency": sum(1 for r in production if r.get("frequency_exceeds_rpo")),
        "tagging": _tagging_summary(assessed, keys),
        "plans_selecting_nothing": plans_selecting_nothing(plans, assessed),
        "plan_count": len(plans),
        "environment_basis": dict(sorted(_count_by(assessed, lambda r: str(r.get("criticality_basis", "none")).split(":")[0]).items(),
                                         key=lambda kv: -kv[1])),
        "mismatch": [{"name": clean_text(r.get("resourceName") or r.get("resourceId", ""), 60), "signals": r.get("behaviour_signals", ""),
                      "basis": str(r.get("criticality_basis", "")).split(":")[0]}
                     for r in assessed if r.get("tag_behaviour_mismatch")],
        "snapshot_visibility": {t: (visible.get(t, "not checked"), n) for t, n in sorted(type_counts.items())},
        "backup_by_type": compute_backup_by_type(resources),
        "s3_backup_versioning": compute_s3_backup_versioning(resources),
        "s3_continuous": compute_s3_continuous(resources),
        "same_plan_scope": mark_same_plan_scope(resources),
        "classification": classification,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Drift between runs
# ─────────────────────────────────────────────────────────────────────────────
SNAPSHOT_VERSION = 1


def assessment_snapshot(resources: List[Dict], vaults: List[Dict], plans: List[Dict],
                        assessed_date: str) -> Dict[str, Any]:
    """What one run found, in a form a later run can be compared against.  Written next to the report,
    and holds the same ARNs and account names the CSV already holds."""
    return {
        "version": SNAPSHOT_VERSION, "assessed_date": assessed_date,
        "resources": {r["arn"]: {"state": r.get("recovery_copy_state", ""), "protection": r.get("protection_state", ""),
                                 "criticality": r.get("criticality", ""), "tier": r.get("recovery_tier")}
                      for r in resources if r.get("arn")},
        "vaults": {f"{v.get('account_id', '')}:{v.get('region', '')}:{v.get('BackupVaultName', '')}":
                   v.get("vault_lock_mode", "none") for v in vaults},
        "plans": sorted({f"{p.get('account_id', '')}:{p.get('region', '')}:{p.get('BackupPlanName', '')}" for p in plans}),
    }


def load_baseline(path: str) -> Dict[str, Any]:
    file = Path(path)
    if not file.is_file():
        raise ValueError(f"baseline file not found: {path}")
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"{file.name}: not valid JSON ({e.msg} at line {e.lineno})")
    if not isinstance(data, dict) or data.get("version") != SNAPSHOT_VERSION or not isinstance(data.get("resources"), dict):
        raise ValueError(f"{file.name}: not an assessment file written by this tool (version {SNAPSHOT_VERSION})")
    return data


_HAS_COPY = frozenset({"current", "stale", "orphan_policy"})


def compare_runs(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """What changed between two runs.  Facts only: it does not say which changes matter.

    Resources not assessed in either run are left out of the gap counts, because a call that failed
    in one run is not a change in the environment."""
    before, after = previous["resources"], current["resources"]
    skip = {"not_assessed", "no_backup_path", ""}
    new_gaps, closed, regressions, appeared, gone = [], [], [], [], []
    for arn, now in after.items():
        was = before.get(arn)
        if now["state"] in skip:
            continue
        gap_now = now["state"] in ("none", "policy_only")
        if was is None:
            (new_gaps if gap_now else appeared).append(arn)
            continue
        if was["state"] in skip:
            continue
        gap_before = was["state"] in ("none", "policy_only")
        if gap_now and not gap_before:
            (regressions if was["state"] in _HAS_COPY else new_gaps).append(arn)
        elif gap_before and not gap_now:
            closed.append(arn)
    gone = [a for a in before if a not in after]

    def production_without_copy(snapshot: Dict[str, Any]) -> int:
        return sum(1 for v in snapshot["resources"].values()
                   if v.get("criticality") == "production" and v.get("state") in ("none", "policy_only"))
    lock_rank = {"none": 0, "governance": 1, "compliance_grace": 2, "compliance": 3}
    lock_removed = [v for v, mode in previous.get("vaults", {}).items()
                    if v in current.get("vaults", {}) and lock_rank.get(current["vaults"][v], 0) < lock_rank.get(mode, 0)]
    vaults_gone = [v for v in previous.get("vaults", {}) if v not in current.get("vaults", {})]
    plans_removed = [p for p in previous.get("plans", []) if p not in current.get("plans", [])]
    return {
        "previous_date": previous.get("assessed_date", ""), "current_date": current.get("assessed_date", ""),
        "production_without_copy": {"before": production_without_copy(previous), "after": production_without_copy(current)},
        "resources": {"before": len(before), "after": len(after)},
        "new_gaps": sorted(new_gaps), "closed_gaps": sorted(closed), "regressions": sorted(regressions),
        "new_resources_protected": len(appeared), "resources_gone": len(gone),
        "plans_removed": plans_removed, "vault_locks_weakened": lock_removed, "vaults_gone": vaults_gone,
    }


def detect_over_protection(resource: Dict, criticality: str) -> bool:
    """Flag resources where protection likely exceeds the requirement."""
    if criticality == "development" and resource.get("retention_days", 0) > DEV_LONG_RETENTION_DAYS:
        return True
    # S3 versioning enabled but no lifecycle expiry on noncurrent versions
    if resource.get("resourceType") == "AWS::S3::Bucket":
        if resource.get("has_native_protection") and not resource.get("s3_has_expiry_rule", True):
            return True
    return False


def estimate_copy_monthly(resource: Dict) -> float:
    """Estimated monthly cost (USD) to hold one basic copy of a resource, from its size and the list rate of the simplest
    mechanism for its type (MECHANISM_RATES).  An upper bound where the mechanism is incremental.  0.0 when no size was read."""
    size_gib = resource.get("size_gib", 0) or 0
    if size_gib <= 0:
        return 0.0
    res_type = resource.get("resourceType", "")
    if "RDS" in res_type or "Aurora" in res_type:
        rate = MECHANISM_RATES["rds_backup"]
    elif "DynamoDB" in res_type:
        rate = MECHANISM_RATES["dynamodb_pitr"]
    elif "Volume" in res_type or "EBS" in res_type:
        rate = MECHANISM_RATES["ebs_snapshot"]
    else:
        rate = MECHANISM_RATES["aws_backup_warm"]
    return round(size_gib * rate, 2)


def estimate_gap_protection_cost(resource: Dict) -> float:
    """
    Estimate monthly cost (USD) to protect an unprotected resource using the
    simplest appropriate mechanism for its type and size.
    Uses the same MECHANISM_RATES already in use for cost reporting.
    Returns 0.0 if the resource is already protected or has no backup path.
    """
    if resource.get("has_any_protection") or resource.get("no_backup_path"):
        return 0.0
    return estimate_copy_monthly(resource)


def evaluate_posture_controls(
    resource: Dict, controls: Optional[List[Dict]] = None
) -> List[str]:
    """
    Evaluate named posture controls against a resource.
    Returns list of violated control names (empty = compliant).
    Pass a customer-supplied list via --posture-controls; falls back to defaults.
    """
    controls = controls or DEFAULT_POSTURE_CONTROLS
    violations: List[str] = []
    sensitivity = resource.get("data_sensitivity", "INTERNAL")
    # A resource labelled development that shows production behaviour is not judged against the development controls.
    criticality = "unknown" if resource.get("tag_behaviour_mismatch") else resource.get("criticality", "unknown")
    retention = resource.get("retention_days", 0)
    rp_count = resource.get("recovery_point_count", 0)

    for ctrl in controls:
        name = ctrl.get("name", "unnamed")
        applies_sensitivity = ctrl.get("applies_to_sensitivity", [])
        if applies_sensitivity and sensitivity not in applies_sensitivity:
            continue
        applies_criticality = ctrl.get("applies_to_criticality", [])
        if applies_criticality and criticality not in applies_criticality:
            continue

        violated = False
        if "min_retention_days" in ctrl and retention < ctrl["min_retention_days"]:
            violated = True
        if "max_retention_days" in ctrl and retention > ctrl["max_retention_days"]:
            violated = True
        if ctrl.get("requires_cross_region") and not resource.get("cross_region_copy"):
            violated = True
        if ctrl.get("requires_vault_lock_compliance") and resource.get("vault_lock_mode") != "compliance":
            violated = True
        if "min_recovery_points" in ctrl and rp_count < ctrl["min_recovery_points"]:
            violated = True

        if violated:
            violations.append(name)

    return violations


def compute_scenarios(all_resources: List[Dict], vaults: List[Dict]) -> Dict:
    # A resource that could not be assessed is neither recoverable nor not recoverable.  Leaving
    # it out of the denominator keeps the percentages from understating what is protected.
    not_assessed = sum(1 for r in all_resources if r.get("protection_state") == "not_assessed")
    all_resources = [r for r in all_resources if r.get("protection_state") != "not_assessed"]
    total = len(all_resources)
    if total == 0:
        return {"not_assessed": not_assessed} if not_assessed else {}

    # Accidental deletion — any recovery point
    recoverable_accidental = sum(1 for r in all_resources if r.get("has_any_protection"))

    # Silent failure — enrolled but producing nothing
    failing = sum(1 for r in all_resources if r.get("job_failing"))

    # Compromised credentials — recovery points beyond the reach of the compromised identity.
    # Governance-mode vault lock is still removable by a principal with the right permissions (root
    # included, unless an SCP forbids it), so it does NOT protect against
    # root/admin credential compromise. Only compliance-mode locks and air-gapped vaults do.
    # Cross-account copies (same-account identity can't delete the destination) also qualify.
    credential_safe = sum(
        1 for r in all_resources
        if r.get("vault_lock_mode") == "compliance"
        or r.get("is_air_gapped")
        or r.get("cross_account_copy")
    )

    # Full account compromise — only air-gapped survive
    account_safe = sum(1 for r in all_resources if r.get("is_air_gapped"))

    # Regional — cross-region copy
    regional_safe = sum(1 for r in all_resources if r.get("cross_region_copy"))

    # Deleting the resource itself.  Only resources with a deletion-protection setting can be answered.
    deletable = [r for r in all_resources if r.get("deletion_protection") is not None
                 and r.get("resourceType") in _DELETION_PROTECTED_TYPES]

    return {
        "not_assessed": not_assessed,
        "deletion": {"total": len(deletable), "protected": sum(1 for r in deletable if r["deletion_protection"]),
                     "exposed": sum(1 for r in deletable if r.get("deletion_exposed"))},
        "accidental": {
            "recoverable": recoverable_accidental,
            "total": total,
            "pct": round(recoverable_accidental / total * 100) if total else 0,
        },
        "silent_failure": {"affected": failing},
        "credential_compromise": {
            "recoverable": credential_safe,
            "total": total,
            "pct": round(credential_safe / total * 100) if total else 0,
        },
        "account_compromise": {
            "recoverable": account_safe,
            "total": total,
        },
        "regional": {
            "recoverable": regional_safe,
            "total": total,
            "pct": round(regional_safe / total * 100) if total else 0,
        },
    }


def _restore_rung(restore_plans: List[Dict], restore_jobs: List[Dict], summary: Optional[Dict[str, Any]]) -> Dict:
    """Rung 08 in three levels: no restore on record, a restore testing plan or a restore exists, and every tier-1 resource
    restored within its target in the lookback window."""
    desc = ("Validation that recovery points actually restore, including from a copy in another account or an air-gapped "
            "vault. Three levels: no restore on record; a restore testing plan or a restore exists; tier-1 resources "
            "restored within their target time.")
    if summary:
        t1, days = summary["tiers"][1], summary["lookback_days"]
        level = summary["level"]
        detail = (f"{t1['within_rto']} of {t1['resources']} tier-1 resources had a restore job finish within the target time in {days}d"
                  if t1["resources"] else f"{summary['succeeded']} restore(s) in {days}d")
    else:
        level = 2 if (restore_jobs or restore_plans) else 1
        detail = f"{len(restore_jobs)} restore(s)" if restore_jobs else f"{len(restore_plans)} plan(s)"
    names = {1: "Level 1 of 3: no restore on record", 2: "Level 2 of 3", 3: "Level 3 of 3"}
    state = names[1] if level == 1 else f"{names[level]}: {detail}"
    return {"n": "08", "title": "Restore testing on a schedule", "desc": desc, "state": state,
            "status": {1: "flag", 2: "warn", 3: "good"}[level]}


def compute_hardening_path(
    all_resources: List[Dict],
    vaults: List[Dict],
    scps: List[Dict],
    restore_plans: List[Dict],
    vault_alarms: Dict[str, bool],
    restore_jobs: Optional[List[Dict]] = None,
    restore_summary: Optional[Dict[str, Any]] = None,
    mpa_state: Optional[Dict] = None,
    scps_assessed: bool = True,
    gaps: Optional[List[Dict]] = None,
) -> List[Dict]:
    all_resources = [r for r in all_resources if r.get("protection_state") != "not_assessed"]
    total = len(all_resources)
    protected = sum(1 for r in all_resources if r.get("has_any_protection"))
    locked_vaults = sum(1 for v in vaults if v.get("is_locked"))
    modes = [v.get("vault_lock_mode") for v in vaults if v.get("is_locked")]
    mode_parts = [f"{modes.count(m)} {label}" for m, label in
                  (("compliance", "compliance"), ("compliance_grace", "in cooling-off"), ("governance", "governance"))
                  if modes.count(m)]
    lock_mode_note = f" ({', '.join(mode_parts)})" if mode_parts else ""
    air_gapped_vaults = sum(1 for v in vaults if v.get("is_air_gapped"))
    # Count vaults with at least one monitoring path (CloudWatch alarm, SNS vault
    # notification, or an account-wide EventBridge rule for aws.backup events).
    alarmed_vaults = sum(1 for v in vaults if is_vault_monitored(v, vault_alarms))
    cross_region = sum(1 for r in all_resources if r.get("cross_region_copy"))
    air_gapped_resources = sum(1 for r in all_resources if r.get("is_air_gapped"))

    def pill(state):
        return state

    rungs = [
        {"n": "01", "title": "Recovery points exist for what matters",
         "desc": "A plan or native mechanism covering every resource the business would need back.",
         "state": f"{protected:,} of {total:,}",
         "status": ("flag" if not total else "good" if protected / total > 0.95
                    else "warn" if protected / total > 0.8 else "flag")},
        {"n": "02", "title": "Failures are visible",
         "desc": "An alarm on backup job failure so a plan that stops working announces itself.",
         "state": f"{alarmed_vaults} of {len(vaults)} vaults",
         "status": "good" if alarmed_vaults == len(vaults) else "flag"},
        {"n": "03", "title": "Vault Lock on standard vaults",
         "desc": "Vault Lock stops recovery points being deleted or shortened. In governance mode a principal with the "
                 "right permissions can still remove the lock. In compliance mode it cannot be removed once its "
                 "cooling-off period ends, by anyone, including the root user.",
         "state": f"{locked_vaults} of {len(vaults)} vaults{lock_mode_note}",
         "status": "good" if locked_vaults == len(vaults) else "flag"},
        {"n": "04", "title": "Separation of duties",
         "desc": "Service control policies that deny the actions which delete or weaken backups.",
         "state": (f"{_n(len(scps), 'SCP denies', 'SCPs deny')} these actions") if scps else "None detected",
         "status": "good" if scps else "flag"},
        {"n": "05", "title": "Copies outside the Region",
         "desc": "Cross-Region copy within existing plans for resources with a geographic requirement.",
         "state": f"{cross_region:,} of {total:,}",
         "status": "good" if total and cross_region / total > 0.5 else "warn"},
        {"n": "06", "title": "Air-gapped vault for the critical set",
         "desc": "Account-level isolation with no IAM path from the source account.",
         "state": f"{air_gapped_resources} in {air_gapped_vaults} vault(s)" if air_gapped_resources else "None",
         "status": "good" if air_gapped_resources > 0 else "warn"},
        {"n": "07", "title": "Multi-party approval on those vaults",
         "desc": "An independent authorization path when the primary identity path is unavailable.",
         "state": (f"{(mpa_state or {}).get('team_count', 0)} team(s) configured"
                   if (mpa_state or {}).get("configured") else "Not configured"),
         "status": "good" if (mpa_state or {}).get("configured") else "warn"},
        _restore_rung(restore_plans, restore_jobs, restore_summary),
    ]
    return _mark_unassessed_rungs(rungs, gaps or [], scps_assessed, mpa_state)


# Calls each rung relies on.  If any failed, the rung's state says "not fully assessed" instead
# of reporting what was found as if it were everything.
_RUNG_APIS = {
    "02": {"cloudwatch:describe_alarms", "events:list_rules", "backup:get_backup_vault_notifications"},
    "03": {"backup:list_backup_vaults", "backup:describe_backup_vault"},
    "05": {"backup:list_backup_plans", "backup:get_backup_plan"},
    "06": {"backup:list_backup_vaults", "backup:describe_backup_vault",
           "backup:list_recovery_points_by_backup_vault"},
    "07": {"mpa:list_approval_teams"},
    "08": {"backup:list_restore_testing_plans", "backup:list_restore_jobs"},
}


def _mark_unassessed_rungs(rungs: List[Dict], gaps: List[Dict], scps_assessed: bool,
                           mpa_state: Optional[Dict]) -> List[Dict]:
    failed_apis = {g["api"] for g in gaps}
    for rung in rungs:
        not_assessed = bool(_RUNG_APIS.get(rung["n"], set()) & failed_apis)
        if rung["n"] == "04" and not scps_assessed:
            rung["state"] = "Not assessed (needs an organization run)"
            rung["status"] = "warn"
            continue
        if rung["n"] == "07" and (mpa_state or {}).get("assessed") is False:
            not_assessed = True
        if not_assessed:
            rung["state"] = f"Not fully assessed: {rung['state']}"
            rung["status"] = "warn"
    return rungs


# ─────────────────────────────────────────────────────────────────────────────
# HTML report generation
# ─────────────────────────────────────────────────────────────────────────────

HTML_CSS = """
  :root{
    --bg:#090F1C;--surface:#0E1929;--card:#131F30;--raised:#1A2840;
    --border:rgba(255,255,255,0.07);--border-2:rgba(255,255,255,0.12);
    --ink:#E4ECF7;--ink-2:#8EA8CC;--ink-3:#506480;
    --teal:#00D4B0;--teal-dim:rgba(0,212,176,0.12);
    --orange:#FF8642;--orange-dim:rgba(255,134,66,0.12);
    --red:#FF4D6A;--red-dim:rgba(255,77,106,0.12);
    --blue:#4DA6FF;--blue-dim:rgba(77,166,255,0.10);
    --purple:#A78BFA;--purple-dim:rgba(167,139,250,0.12);
    --track:rgba(255,255,255,0.10);
    --good:var(--teal);--good-bg:var(--teal-dim);
    --warn:var(--orange);--warn-bg:var(--orange-dim);
    --flag:var(--red);--flag-bg:var(--red-dim);
  }
  *,*::before,*::after{box-sizing:border-box;margin:0;}
  body{background:var(--bg);color:var(--ink);
    font-family:"Helvetica Neue",Helvetica,Arial,system-ui,sans-serif;font-size:14px;line-height:1.6;}
  .page{max-width:1080px;margin:0 auto;padding:0 0 64px;}
  /* Masthead */
  .masthead{
    background:linear-gradient(135deg,#0B1A35 0%,#091628 45%,#0A1520 70%,#111A1F 100%);
    border-bottom:1px solid var(--border-2);padding:48px 64px 40px;
    position:relative;overflow:hidden;
  }
  .masthead::before{
    content:"";position:absolute;inset:0;
    background:
      radial-gradient(ellipse 60% 80% at 85% -20%,rgba(0,180,150,0.18) 0%,transparent 60%),
      radial-gradient(ellipse 50% 60% at 100% 110%,rgba(255,120,50,0.12) 0%,transparent 55%);
    pointer-events:none;
  }
  .masthead > *{position:relative;}
  .eyebrow{
    font-size:10px;letter-spacing:.18em;text-transform:uppercase;
    color:var(--teal);font-weight:700;margin-bottom:14px;
    display:flex;align-items:center;gap:8px;
  }
  .eyebrow::before{content:"";display:inline-block;width:20px;height:2px;background:var(--teal);}
  .masthead h1{
    font-family:Georgia,"Times New Roman",serif;
    font-size:38px;line-height:1.1;font-weight:400;
    letter-spacing:-.02em;color:#fff;margin-bottom:6px;
  }
  .masthead .sub{color:var(--ink-2);font-size:13px;margin-bottom:32px;}
  .factbar{display:flex;flex-wrap:wrap;gap:0;border-top:1px solid var(--border-2);padding-top:24px;}
  .factbar div{padding:0 28px 0 0;margin-right:28px;border-right:1px solid var(--border);}
  .factbar div:last-child{border-right:none;margin-right:0;padding-right:0;}
  .factbar b{display:block;font-family:Georgia,serif;font-size:22px;font-weight:400;color:#fff;line-height:1.1;}
  .factbar span{display:block;font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-3);margin-top:4px;}
  /* Content */
  .content{padding:0 64px;}
  section{margin-top:52px;}
  .sec-head{
    display:flex;align-items:baseline;gap:16px;
    border-bottom:1px solid var(--border-2);padding-bottom:10px;margin-bottom:20px;
  }
  .sec-num{
    font-family:Georgia,serif;font-size:11px;color:var(--teal);
    font-weight:700;letter-spacing:.1em;white-space:nowrap;text-transform:uppercase;
  }
  .sec-head h2{font-family:Georgia,"Times New Roman",serif;font-size:22px;font-weight:400;letter-spacing:-.01em;color:#fff;}
  h3.kicker,h4.kicker{font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--teal);font-weight:700;margin:28px 0 10px;}
  p{margin-bottom:12px;color:var(--ink-2);max-width:80ch;}
  .lede{font-size:15px;color:var(--ink);max-width:72ch;}
  /* Tables */
  table{width:100%;border-collapse:collapse;margin:14px 0 8px;font-size:12.5px;}
  th{
    text-align:left;font-size:9px;letter-spacing:.13em;text-transform:uppercase;
    color:var(--ink-3);font-weight:700;
    border-bottom:1px solid var(--border-2);padding:0 12px 9px 0;vertical-align:bottom;
  }
  td{padding:10px 12px 10px 0;border-bottom:1px solid var(--border);vertical-align:top;color:var(--ink-2);}
  td:last-child,th:last-child{padding-right:0;}
  .num{text-align:right;font-variant-numeric:tabular-nums;}
  th.num{text-align:right;}
  tr:hover td{background:rgba(255,255,255,0.02);}
  .asset{font-weight:600;color:var(--ink);}
  .asset em{display:block;font-style:normal;font-weight:400;font-size:11px;color:var(--ink-3);margin-top:3px;}
  .mono{font-family:"SF Mono",Menlo,Consolas,monospace;font-size:11px;color:var(--blue);}
  .totalrow td{font-weight:600;color:var(--ink);border-top:1px solid var(--border-2);border-bottom:none;}
  tr.rest td{color:var(--ink-3);font-style:italic;}
  /* Pills */
  .pill{display:inline-block;font-size:9.5px;letter-spacing:.06em;font-weight:700;padding:3px 9px;border-radius:3px;white-space:nowrap;text-transform:uppercase;}
  .p-good{background:rgba(0,212,176,0.16);color:var(--teal);border:1px solid rgba(0,212,176,0.7);}
  .p-warn{background:var(--warn-bg);color:var(--orange);border:1px solid rgba(255,134,66,0.25);}
  .p-flag{background:rgba(255,77,106,0.2);color:var(--red);border:1px solid rgba(255,77,106,0.85);}
  .p-neutral{background:rgba(255,255,255,0.05);color:var(--ink-2);border:1px solid var(--border);}
  .p-conf{background:var(--purple-dim);color:var(--purple);border:1px solid rgba(167,139,250,0.25);}
  .none{font-size:10.5px;color:var(--ink-3);font-style:italic;}
  /* Callouts */
  .callout{border-left:3px solid var(--blue);background:var(--card);border-radius:0 6px 6px 0;padding:16px 20px;margin:20px 0;}
  .callout.good{border-left-color:var(--teal);}
  .callout.warn{border-left-color:var(--orange);}
  .callout.flag{border-left-color:var(--red);}
  .callout h4{font-size:10px;letter-spacing:.14em;text-transform:uppercase;font-weight:700;margin-bottom:9px;color:var(--blue);}
  .callout.good h4{color:var(--teal);}
  .callout.warn h4{color:var(--orange);}
  .callout.flag h4{color:var(--red);}
  .callout p{font-size:12.5px;max-width:none;color:var(--ink-2);}
  .callout p:last-child{margin-bottom:0;}
  .callout ul{font-size:12.5px;margin:0 0 10px;padding-left:18px;color:var(--ink-2);}
  .callout li{margin-bottom:6px;}
  /* Split panels */
  .split{display:grid;grid-template-columns:1fr 1fr;border:1px solid var(--border-2);border-radius:8px;margin:20px 0;overflow:hidden;}
  .split > div{padding:20px 22px;background:var(--card);}
  .split > div:first-child{border-right:1px solid var(--border-2);}
  .split h4{margin:0 0 12px;font-size:10px;letter-spacing:.14em;text-transform:uppercase;font-weight:700;}
  .split ul{margin:0;padding-left:16px;font-size:12.5px;color:var(--ink-2);}
  .split li{margin-bottom:7px;}
  /* Hardening ladder */
  .ladder{border-top:1px solid var(--border-2);margin-top:12px;}
  .rung{display:grid;grid-template-columns:28px 1fr 180px;gap:16px;padding:14px 0;border-bottom:1px solid var(--border);align-items:start;}
  .rung .n{font-family:Georgia,serif;color:var(--ink-3);font-size:13px;padding-top:2px;}
  .rung h5{margin:0 0 4px;font-size:13.5px;font-weight:600;color:var(--ink);}
  .rung p{margin:0;font-size:12.5px;color:var(--ink-2);max-width:none;}
  .rung .state{text-align:right;}
  /* Scenarios */
  .scenario{padding:18px 0;border-bottom:1px solid var(--border);}
  .scenario:first-of-type{border-top:1px solid var(--border-2);}
  .scen-top{display:flex;justify-content:space-between;align-items:baseline;gap:20px;}
  .scen-top h5{margin:0;font-size:14px;font-weight:600;color:var(--ink);}
  .scen-top h5 em{font-style:normal;font-weight:400;font-size:12px;color:var(--ink-3);margin-left:8px;}
  .score{font-family:Georgia,serif;font-size:18px;white-space:nowrap;color:var(--ink);}
  .scenario p{margin:5px 0 0;font-size:12.5px;color:var(--ink-2);max-width:none;}
  /* Controls table */
  .controls-table td.violation{color:var(--red);font-weight:600;font-size:11px;}
  .controls-table td.ok{color:var(--teal);font-size:11px;}
  /* Footer */
  footer{margin:52px 64px 0;padding-top:20px;border-top:1px solid var(--border);font-size:10.5px;color:var(--ink-3);}
  footer p{max-width:none;font-size:10.5px;margin-bottom:8px;color:var(--ink-3);}
  /* Sidebar, panels and drilldown */
  .page{max-width:1280px;}
  .shell{display:grid;grid-template-columns:268px minmax(0,1fr);gap:40px;margin-top:36px;align-items:start;}
  .panels{min-width:0;}
  .panel{margin-top:0;overflow-x:auto;}   /* a wide table scrolls inside its panel and never widens the page */
  .rung > div{min-width:0;}
  .rung .state .pill{white-space:normal;text-align:left;}
  .panel:focus{outline:none;}
  .side{position:sticky;top:16px;max-height:calc(100vh - 32px);overflow:auto;border:1px solid var(--border-2);border-radius:8px;
    background:var(--card);padding:8px 8px 14px;}
  .side-group{font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--ink-3);font-weight:700;padding:16px 12px 6px;}
  .side-group:first-child{padding-top:8px;}
  .side a[role=tab]{display:grid;grid-template-columns:24px 1fr;gap:4px;align-items:baseline;padding:8px 12px;border-radius:6px;
    border-left:3px solid transparent;color:var(--ink-2);text-decoration:none;font-size:13px;line-height:1.35;}
  .side a[role=tab]:hover,.side a[role=tab]:focus{background:rgba(255,255,255,0.05);color:var(--ink);outline:none;}
  .side a[role=tab]:focus-visible{box-shadow:0 0 0 2px var(--teal);}
  .side a[role=tab][aria-selected=true]{background:var(--teal-dim);color:#fff;border-left-color:var(--teal);}
  .side .n{color:var(--teal);font-family:Georgia,serif;font-size:11px;font-weight:700;}
  .side-tools{border-top:1px solid var(--border);margin:14px 4px 0;padding:14px 8px 0;display:flex;flex-direction:column;gap:8px;}
  .side-tools button{font:inherit;font-size:11px;letter-spacing:.04em;font-weight:700;color:var(--teal);background:transparent;
    border:1px solid rgba(0,212,176,0.35);border-radius:4px;padding:7px 10px;cursor:pointer;text-align:left;}
  .side-tools button:hover,.side-tools button:focus{background:var(--teal-dim);}
  .side-note{font-size:11.5px;color:var(--ink-3);margin:6px 0 0;max-width:none;line-height:1.5;}
  #tab-select{display:none;width:100%;font:inherit;font-size:14px;color:var(--ink);background:var(--surface);
    border:1px solid var(--border-2);border-radius:6px;padding:10px 12px;}
  .shell.tabs .panel{display:none;}
  .shell.tabs .panel.active,.shell.tabs.showall .panel{display:block;}
  .shell.tabs.showall .panel + .panel{margin-top:52px;}
  tr[hidden]{display:none;}
  .side-search{padding:6px 6px 4px;}
  .side-search[hidden]{display:none;}
  .side-search input{width:100%;font:inherit;font-size:13px;color:var(--ink);background:var(--surface);border:1px solid var(--border-2);
    border-radius:6px;padding:8px 10px;}
  .side-search input:focus{outline:none;border-color:var(--teal);box-shadow:0 0 0 2px rgba(0,212,176,0.25);}
  #search-results{margin-top:6px;}
  #search-results button{display:flex;justify-content:space-between;gap:8px;width:100%;text-align:left;font:inherit;font-size:12.5px;
    color:var(--ink-2);background:transparent;border:0;border-radius:5px;padding:6px 8px;cursor:pointer;}
  #search-results button:hover,#search-results button:focus{background:rgba(255,255,255,0.06);color:var(--ink);outline:none;}
  #search-results .count{color:var(--teal);font-variant-numeric:tabular-nums;}
  #search-results .none{padding:4px 8px;font-size:12px;}
  .hit{outline:2px solid var(--teal);outline-offset:3px;background:var(--teal-dim);border-radius:3px;}
  figure.chart{margin:20px 0;padding:16px 18px 6px;border:1px solid var(--border-2);border-radius:8px;background:var(--card);}
  figure.chart figcaption{font-size:12.5px;color:var(--ink-2);margin-bottom:10px;max-width:none;}
  figure.chart figcaption strong{color:var(--ink);}
  .chart-svg{width:100%;height:auto;display:block;}
  .ch-t{fill:var(--ink-2);font-size:12px;}
  .ch-t2{fill:var(--ink-3);font-size:11.5px;}
  .ch-in{fill:#06101c;font-size:11px;font-weight:700;}
  .onepage-bar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px;font-size:12.5px;color:var(--ink-3);}
  .onepage-bar button{font:inherit;font-size:11px;font-weight:700;color:var(--teal);background:transparent;
    border:1px solid rgba(0,212,176,0.35);border-radius:4px;padding:6px 12px;cursor:pointer;}
  .onepage-bar button:hover,.onepage-bar button:focus{background:var(--teal-dim);}
  .figs{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px 20px;margin:6px 0 16px;}
  .figs div{border-left:2px solid var(--teal);padding-left:12px;}
  .figs b{display:block;font-family:Georgia,serif;font-size:24px;font-weight:400;color:#fff;line-height:1.15;}
  .figs span{display:block;font-size:11px;color:var(--ink-3);margin-top:3px;}
  table.compact{font-size:11.5px;}
  table.compact td,table.compact th{padding-top:6px;padding-bottom:6px;}
  .onepage-note{font-size:11.5px;color:var(--ink-3);max-width:none;margin-top:12px;}
  .table-scroll{overflow-x:auto;max-width:100%;}
  a{color:var(--blue);} a:hover{color:var(--ink);}
  /* Start here */
  .ov-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;margin:16px 0;}
  .ov-card,.ov-col{background:var(--card);border:1px solid var(--border-2);border-radius:8px;padding:18px 20px;min-width:0;}
  .ov-lens{font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--teal);font-weight:700;margin-bottom:6px;}
  .ov-q{color:var(--ink-2);font-size:12.5px;margin-bottom:12px;}
  .ov-big{font-family:Georgia,serif;font-size:40px;line-height:1;color:#fff;}
  .ov-big small{font-size:16px;color:var(--ink-2);}
  .ov-what{font-size:13px;color:var(--ink);margin:6px 0 10px;}
  .ov-est{font-size:12px;color:var(--ink-2);margin:-6px 0 10px;line-height:1.4;}
  .ov-bar{height:8px;background:var(--track);border-radius:4px;overflow:hidden;margin-bottom:14px;}
  .ov-bar span{display:block;height:100%;background:var(--teal);}
  .ov-facts,.ov-good{list-style:none;padding:0;margin:0 0 12px;display:flex;flex-direction:column;gap:6px;font-size:12.5px;color:var(--ink-2);}
  .ov-facts b{color:var(--ink);font-weight:600;}
  .ov-good li::before{content:"✓";color:var(--teal);font-weight:700;margin-right:8px;}
  .ov-link{font-size:12px;font-weight:600;text-decoration:none;}
  .ov-link::after{content:" →";}
  .ov-dr,.ov-call,.ov-rule,.ov-more,.ov-none,.ov-scope{font-size:12px;color:var(--ink-3);max-width:none;}
  .ov-h{margin-top:28px;}
  .ov-pillars{grid-template-columns:repeat(auto-fit,minmax(240px,1fr));}
  .ov-pillars .ov-big small{display:block;margin-top:4px;font-family:inherit;font-size:13px;}
  .focus-row{display:flex;gap:18px;align-items:baseline;flex-wrap:wrap;}
  .focus-row details.focus-opt{margin:2px 0;}
  .focus-row details.focus-opt[open]{flex-basis:100%;}
  .ov-tail .ov-dr{margin:6px 0 0;}
  .ov-scen{list-style:none;padding:0;margin:4px 0 12px;display:flex;flex-direction:column;gap:8px;font-size:12.5px;color:var(--ink-2);}
  .ov-scen li{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr) 44px;gap:10px;align-items:center;}
  .ov-scen .ov-bar{margin:0;}
  .ov-scen b{text-align:right;color:var(--ink);}
  .bar-pair{max-width:560px;margin:8px 0 14px;}
  .ov-bar-gap span{background:var(--red);} .ov-bar-waste span{background:var(--orange);}
  .ov-pair,.ov-cmp{list-style:none;padding:0;margin:2px 0 14px;max-width:560px;display:flex;flex-direction:column;gap:6px;font-size:12px;color:var(--ink-2);}
  .ov-pair li,.ov-cmp li{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(0,1fr) minmax(36px,auto);gap:10px;align-items:center;}
  .ov-pair .ov-bar,.ov-cmp .ov-bar{margin:0;}
  .ov-apps{list-style:none;padding:0;margin:6px 0 12px;max-width:760px;display:flex;flex-direction:column;gap:8px;font-size:12.5px;color:var(--ink-2);}
  .ov-apps li{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1.6fr) 44px;gap:12px;align-items:center;}
  .ov-apps .ov-bar{margin:0;height:14px;}
  .ov-apps em{display:block;font-style:normal;font-size:11px;color:var(--ink-3);}
  .ov-acct{list-style:none;padding:0;margin:6px 0 12px;max-width:760px;display:flex;flex-direction:column;gap:8px;font-size:12.5px;color:var(--ink-2);}
  .ov-acct li{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1.6fr) 70px;gap:12px;align-items:center;}
  .ov-acct em{display:block;font-style:normal;font-size:11px;color:var(--ink-3);}
  .ov-acct b{text-align:right;color:var(--ink);font-weight:600;}
  .ov-stack{display:flex;height:14px;border-radius:4px;overflow:hidden;background:var(--track);}
  .ov-stack span{display:block;height:100%;}
  .k-ok{background:var(--teal);} .k-paper{background:var(--orange);} .k-none{background:var(--red);}
  .k-blue{background:var(--blue);} .k-grey{background:var(--ink-3);} .k-purple{background:var(--purple);}
  table.state-key{max-width:620px;margin:6px 0 4px;} table.state-key .ov-key{margin:0 8px 0 0;}
  .ov-acct.state-bars li{grid-template-columns:minmax(0,0.8fr) minmax(0,2.2fr) 70px;}
  p.meta-line{font-size:12px;color:var(--ink-3);}
  .ov-key{display:inline-block;width:10px;height:10px;border-radius:2px;margin:0 4px 0 10px;vertical-align:-1px;}
  .ov-apps b{text-align:right;color:var(--ink);}
  .ov-pair b,.ov-cmp b{text-align:right;color:var(--ink);font-weight:600;}
  .ov-headline{font-family:Georgia,serif;font-size:24px;line-height:1.25;color:var(--ink);margin:6px 0 8px;max-width:60ch;}
  .ov-unk{font-size:12px;color:var(--ink-3);margin:0 0 10px;max-width:none;}
  .ov-good-line{font-size:12.5px;color:var(--ink-2);max-width:none;}
  .ov-good-line b{color:var(--teal);}
  .ov-spend{display:flex;flex-direction:column;gap:6px;margin:8px 0;max-width:760px;}
  .ov-sp{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr) 90px;gap:10px;align-items:center;font-size:12.5px;color:var(--ink-2);}
  .ov-sp .ov-bar{margin:0;}
  .ov-sp b{text-align:right;color:var(--ink);}
  .focus{display:grid;grid-template-columns:52px minmax(0,1fr);gap:12px;padding:12px 0;border-top:1px solid var(--border);}
  .ov-lens + .focus{border-top:0;}
  .focus-n{font-family:Georgia,serif;font-size:24px;color:var(--orange);line-height:1.1;text-align:right;}
  .focus-b b{color:var(--ink);font-size:13px;}
  .focus-b p{font-size:12.5px;margin:4px 0;max-width:none;}
  .ov-cover{padding:10px 14px;border-radius:8px;border:1px solid var(--border-2);border-left:4px solid var(--teal);background:var(--card);font-size:12.5px;max-width:none;color:var(--ink-2);}
  .ov-cover-part{border-left-color:var(--orange);}
  .ov-cover b{color:var(--ink);}
  ol.actions{list-style:none;padding:0;margin:8px 0;counter-reset:act;}
  ol.actions > li.focus{counter-increment:act;background:var(--card);border:1px solid var(--border-2);border-radius:8px;padding:14px 16px;margin-bottom:10px;}
  .chips{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0;}
  .chip{font-size:11.5px;color:var(--ink-2);background:var(--track);border-radius:10px;padding:2px 9px;}
  .chip b{color:var(--ink);}
  .focus-e{color:var(--ink-2);font-size:12.5px;}
  details.focus-opt{margin:4px 0 6px;font-size:12.5px;}
  details.focus-opt summary{cursor:pointer;color:var(--teal);font-weight:700;font-size:11px;letter-spacing:.1em;text-transform:uppercase;}
  .focus-for{font-size:12px;font-weight:700;color:var(--ink);margin:10px 0 2px;}
  .focus-o span{font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--teal);font-weight:700;margin-right:6px;}
  ol.review{list-style:none;padding:0;margin:6px 0 14px;} ol.review li{padding:6px 0;border-bottom:1px solid var(--border);}
  ol.review summary{display:flex;gap:12px;align-items:baseline;cursor:pointer;list-style:none;}
  ol.review summary::-webkit-details-marker{display:none;}
  ol.review summary::after{content:"+";margin-left:auto;color:var(--teal);font-weight:700;}
  ol.review details[open] summary::after{content:"−";}
  ol.review .review-n{min-width:52px;font-size:20px;font-weight:700;text-align:right;color:var(--ink);}
  ol.review .review-t{color:var(--ink-2);font-weight:400;} ol.review .review-t b{color:var(--ink);font-weight:700;}
  h3.keep{font-family:Georgia,"Times New Roman",serif;font-weight:400;font-size:19px;margin-top:22px;}
  ol.review .review-body{margin:4px 0 4px 64px;} ol.review p{margin:2px 0;}
  .sum-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px;margin:14px 0;}
  section.part{margin-top:28px;padding-top:16px;border-top:1px solid var(--border);} h2.part-h{font-size:17px;margin:12px 0 8px;}
  .sum-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:10px 12px;}
  .sum-card h5{margin:0 0 6px;font-size:13px;} .sum-card p{margin:4px 0;font-size:12.5px;}
  .sum-card .sum-ok span{color:var(--teal);font-weight:700;} .sum-card .sum-gap span{color:var(--orange);font-weight:700;}
  .focus-o{margin:4px 0;} .focus-o ul{margin:2px 0 0 18px;padding:0;} .focus-o li{margin:2px 0;}
  .table-scroll table{min-width:640px;}
  .waste-body .table-scroll table{min-width:0;width:100%;}                       /* three short columns: the cost stays in view */
  .waste-body td.num,.waste-body th.num{white-space:nowrap;}
  table.matrix-head td.mx-one{min-width:200px;} table.matrix-head .mx-bar{margin:2px 0 4px 0;max-width:260px;height:8px;}
  table.matrix-head td.mx-one .of{display:block;color:var(--ink-3);font-size:12px;} table.matrix-head td.mx-one .of b{color:var(--ink);font-size:14px;}
  table.matrix td.mx{min-width:84px;} table.matrix td.mx b{font-size:14px;color:var(--ink);font-weight:700;}
  table.matrix td.mx .of{display:block;color:var(--ink-3);font-size:11px;}
  .mx-bar{display:block;height:6px;margin:4px 0 2px auto;width:100%;max-width:90px;background:var(--track);border-radius:3px;overflow:hidden;}
  .mx-bar span{display:block;height:100%;background:var(--red);} 
  table.matrix td.mx-empty{color:var(--ink-3);}
  table.matrix td.unread{color:var(--ink-3);font-style:italic;}
  table.matrix tr.unassessed td{color:var(--ink-3);}
  table.matrix th em.meta{font-weight:400;}
  table.spend tr.spend-group td{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--teal);font-weight:700;padding-top:12px;}
  table.spend td{vertical-align:top;}
  em.meta{display:block;font-style:normal;font-size:11px;font-weight:400;color:var(--ink-3);margin-top:3px;}
  span.meta{font-size:11.5px;font-weight:400;color:var(--ink-3);}
  .asset-filter{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:18px 0 6px;padding:10px 14px;
    border:1px solid var(--border-2);border-radius:8px;background:var(--card);font-size:12.5px;color:var(--ink-2);}
  .asset-filter[hidden]{display:none;}
  .asset-filter button{font:inherit;font-size:12px;font-weight:600;color:var(--ink-2);background:transparent;
    border:1px solid var(--border-2);border-radius:4px;padding:5px 12px;cursor:pointer;}
  .asset-filter button:hover,.asset-filter button:focus{background:rgba(255,255,255,0.05);}
  .asset-filter button[aria-pressed=true]{background:var(--teal-dim);color:#fff;border-color:rgba(0,212,176,0.45);}
  .asset-filter label{display:flex;align-items:center;gap:6px;margin-left:8px;}
  .asset-filter input{font:inherit;font-size:12.5px;color:var(--ink);background:var(--surface);border:1px solid var(--border-2);
    border-radius:4px;padding:5px 9px;min-width:170px;}
  .asset-filter .note{flex-basis:100%;font-size:11.5px;color:var(--ink-3);}
  details.drill{border:1px solid var(--border);border-radius:6px;background:var(--surface);margin:14px 0;}
  details.drill > summary{cursor:pointer;list-style:none;padding:11px 16px;font-size:13px;font-weight:600;color:var(--ink);
    display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
  details.drill > summary::-webkit-details-marker{display:none;}
  details.drill > summary::before{content:"+";display:inline-block;width:14px;color:var(--teal);font-weight:700;}
  details.drill[open] > summary::before{content:"−";}
  details.drill > summary:hover,details.drill > summary:focus{background:rgba(255,255,255,0.03);}
  details.drill > .drill-body{padding:0 18px 12px;border-top:1px solid var(--border);}
  html{scroll-behavior:smooth;}
  section{scroll-margin-top:16px;}
  @media print{
    :root{--bg:#fff;--surface:#fff;--card:#fff;--raised:#fff;--ink:#111;--ink-2:#2b2b2b;--ink-3:#555;--teal:#006b5a;--teal-dim:rgba(0,107,90,0.10);
      --orange:#a24a00;--red:#b3123a;--blue:#0b4f99;--purple:#5b3fb5;--track:rgba(0,0,0,0.12);
      --border:rgba(0,0,0,0.18);--border-2:rgba(0,0,0,0.28);}
    body{background:#fff;color:#000;}
    .sec-head h2,.figs b{color:#000;}
    .ch-in{fill:#fff;}
    .panel{overflow:visible;}
    body.print-onepage .masthead{display:none;}
    body.print-onepage .shell .panel,body.print-onepage .shell.tabs .panel{display:none !important;}
    body.print-onepage .shell #sec-overview,body.print-onepage .shell.tabs #sec-overview{display:block !important;}
    body.print-onepage .onepage-bar button{display:none;}
    body.print-onepage .content{padding:0 4px;}
    body.print-onepage .callout{margin:3px 0;padding:4px 10px;}
    body.print-onepage .callout p{font-size:8.5px;margin:0;}
    body.print-onepage .callout h4{margin-bottom:3px;}
    body.print-onepage .sec-head{margin-bottom:6px;padding-bottom:4px;}
    body.print-onepage .sec-head h2{font-size:16px;}
    body.print-onepage .onepage-bar{margin-bottom:6px;font-size:10px;}
    body.print-onepage .figs{gap:6px 14px;margin:4px 0 8px;grid-template-columns:repeat(6,minmax(0,1fr));}
    body.print-onepage .figs b{font-size:15px;}
    body.print-onepage .figs span{font-size:8.5px;}
    body.print-onepage table.compact{font-size:8px;margin:3px 0;}
    body.print-onepage table.compact td,body.print-onepage table.compact th{padding:2px 6px 2px 0;}
    body.print-onepage figure.chart{margin:4px 0;padding:4px 10px 2px;break-inside:avoid;}
    body.print-onepage figure.chart figcaption{font-size:9px;margin-bottom:2px;}
    body.print-onepage .chart-svg{max-height:96px;}
    body.print-onepage .onepage-note{font-size:8.5px;margin-top:4px;}
    body.print-onepage .ov-link,body.print-onepage details.focus-opt,body.print-onepage .lede,body.print-onepage .ov-more{display:none;}
    body.print-onepage .ov-grid{gap:8px;margin:8px 0;}
    body.print-onepage .ov-card,body.print-onepage .ov-col{padding:8px 12px;break-inside:avoid;}
    body.print-onepage .ov-big{font-size:30px;color:#000;}
    body.print-onepage .focus-b p,body.print-onepage .ov-cover,body.print-onepage .ov-rule{margin:2px 0;}
    body.print-onepage ol.actions>li.focus{padding:5px 10px;margin-bottom:4px;break-inside:avoid;}
    body.print-onepage .focus-n{font-size:15px;}
    body.print-onepage .ov-h{margin-top:8px;}
    body.print-onepage .ov-charts{display:grid;grid-template-columns:1fr 1fr;gap:8px;}
    body.print-onepage .ov-q{display:none;}
    body.print-onepage .shell #sec-overview{zoom:.68;}
    body.print-onepage .focus-b > p:not(.focus-e){display:none;}
    body.print-onepage footer{display:none;}
    @page{margin:10mm;}
    .masthead{background:#0B1A35;-webkit-print-color-adjust:exact;print-color-adjust:exact;}
    .side{display:none;}
    .shell{display:block;margin-top:0;}
    .shell.tabs .panel{display:block !important;}
    .panel + .panel{margin-top:40px;}
    details.drill > summary::before{content:"";width:0;}
  }
  @media (max-width:820px){
    .masthead,.content,footer{padding-left:20px;padding-right:20px;}
    .split{grid-template-columns:1fr;}
    .split > div:first-child{border-right:none;border-bottom:1px solid var(--border-2);}
    .rung{grid-template-columns:24px 1fr;}
    .shell{grid-template-columns:minmax(0,1fr);gap:20px;}
    .side{position:static;max-height:none;padding:10px;}
    .side .tablist{display:none;}
    .shell.tabs #tab-select{display:block;}
    .side-tools{margin-top:10px;padding-top:10px;}
    table{display:block;max-width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;}
    .rung > div{min-width:0;}
    .rung .state .pill{white-space:normal;}
    .rung .state{grid-column:2;text-align:left;}
  }
"""


def _pill(label: str, kind: str) -> str:
    """kind: good | warn | flag | neutral"""
    return f'<span class="pill p-{kind}">{_esc(label)}</span>'


def _esc(s) -> str:
    """Escape AWS-sourced text for HTML.  Resource names and tag values are attacker-controllable."""
    return html.escape(str(s), quote=True)


# A cell that begins with one of these is read as a formula by Excel, Sheets and LibreOffice.
# Resource names and tag values come from the customer's environment and may be written by
# anyone who can create a resource, so every text cell is neutralised on the way out.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: Any) -> Any:
    """Prefix a leading formula character with an apostrophe so it is read as text."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _fmt_tib(gib: float) -> str:
    tib = gib / 1024
    if tib >= 1:
        return f"{tib:.0f} TiB"
    return f"{gib:.0f} GiB"


def _fmt_money(amount: float) -> str:
    if amount >= 1_000_000:
        return f"${amount/1_000_000:.1f}M"
    if amount >= 1_000:
        return f"${amount/1_000:.0f}K"
    return f"${amount:,.0f}"


# Every API call the collector makes, grouped by what it is used for.  This is the one list the
# report appendix is built from.  tests/test_security_review.py checks that it covers exactly the
# actions the role template allows and that docs/SECURITY_REVIEW.md agrees, so the customer-facing list
# cannot name a call the code does not make or leave one out.
API_CALLS_BY_FINDING: List[Tuple[str, List[str], str]] = [
    ("Resource inventory", [
        "config:SelectResourceConfig", "config:SelectAggregateResourceConfig",
        "config:DescribeConfigurationAggregators", "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus", "resource-explorer-2:Search",
        "resource-explorer-2:ListIndexes",
        "ec2:DescribeRegions", "ec2:DescribeVolumes", "rds:DescribeDBInstances", "rds:DescribeDBClusters",
        "dynamodb:ListTables", "dynamodb:DescribeTable", "dynamodb:ListTagsOfResource",
        "s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketTagging"],
     "creation time comes from the same calls"),
    ("Organization structure", [
        "organizations:DescribeOrganization", "organizations:ListAccounts", "organizations:ListRoots",
        "organizations:ListParents", "organizations:ListOrganizationalUnitsForParent"], ""),
    ("Application grouping", [
        "servicecatalog:ListApplications", "servicecatalog:ListAssociatedResources",
        "cloudformation:ListStacks", "cloudformation:ListStackResources",
        "ecs:ListClusters", "ecs:ListServices", "eks:ListClusters"], ""),
    ("Native mechanism state", [
        "tag:GetResources",
        "rds:DescribeDBInstances", "rds:DescribeDBClusters", "rds:DescribeDBSnapshots",
        "rds:DescribeDBClusterSnapshots", "dynamodb:DescribeContinuousBackups", "dynamodb:ListBackups",
        "dlm:GetLifecyclePolicies", "dlm:GetLifecyclePolicy", "ec2:DescribeSnapshots",
        "s3:GetBucketVersioning", "s3:GetLifecycleConfiguration", "s3:GetReplicationConfiguration",
        "s3:GetBucketObjectLockConfiguration", "s3:GetBucketNotification",
        "cloudwatch:GetMetricStatistics"], "snapshot and backup dates only, never contents; Aurora cluster size; DynamoDB write rate only with --deep"),
    ("Copies with no source, and backups visible outside the account", [
        "ec2:DescribeVolumes", "ec2:DescribeSnapshots", "ec2:DescribeImages", "rds:DescribeDBSnapshots",
        "rds:DescribeDBClusterSnapshots", "rds:DescribeDBSnapshotAttributes", "rds:DescribeDBClusterSnapshotAttributes",
        "rds:DescribeDBInstanceAutomatedBackups", "rds:DescribeDBClusterAutomatedBackups",
        "backup:ListRecoveryPointsByBackupVault", "backup:ListLegalHolds", "backup:ListRecoveryPointsByLegalHold"],
     "snapshot, backup and recovery point identifiers, sizes and dates; who a snapshot is shared with; never contents"),
    ("AWS Backup plan state", [
        "backup:ListBackupPlans", "backup:GetBackupPlan", "backup:ListBackupSelections",
        "backup:GetBackupSelection", "backup:ListProtectedResources", "backup:ListBackupJobs",
        "backup:ListCopyJobs", "backup:DescribeRegionSettings"],
     "job status, reason, resource, vault and dates (never contents); which services AWS Backup is opted in for in each Region"),
    ("Vault lock, air-gap and monitoring", [
        "backup:ListBackupVaults", "backup:DescribeBackupVault", "backup:ListRecoveryPointsByBackupVault",
        "backup:GetBackupVaultNotifications", "ram:GetResourceShares", "cloudwatch:DescribeAlarms",
        "events:ListRules"], "recovery points are listed by resource ARN and count only"),
    ("Multi-party approval", ["mpa:ListApprovalTeams"], ""),
    ("Organization backup policies", ["organizations:ListPolicies", "organizations:DescribePolicy", "organizations:ListTargetsForPolicy"],
     "policy names, plans, how they pick resources and where they are attached; the policy text is not kept"),
    ("Separation of duties", ["organizations:ListPolicies", "organizations:DescribePolicy",
                              "organizations:ListTargetsForPolicy"],
     "service control policies and where each is attached, organization runs only"),
    ("Governance tooling already in use", ["backup:ListFrameworks", "backup:DescribeFramework", "backup:ListReportPlans"],
     "framework and report plan names and the controls a framework turns on; compliance results are not read"),
    ("Backup keys and vault policies", ["backup:DescribeBackupVault", "backup:ListRecoveryPointsByBackupVault",
                                        "backup:GetBackupVaultAccessPolicy", "kms:DescribeKey"],
     "key type and state, encryption flags, scan result counts and who a vault policy names; never key policies, keys or data"),
    ("S3 size, all storage classes", [
        "s3:ListAllMyBuckets", "s3:GetBucketLocation", "cloudwatch:ListMetrics", "cloudwatch:GetMetricData"],
     "BucketSizeBytes, queried in each bucket's own Region"),
    ("Restore testing and restores", ["backup:ListRestoreTestingPlans", "backup:ListRestoreJobs",
                                      "backup:GetRestoreTestingPlan", "backup:ListRestoreTestingSelections",
                                      "backup:GetRestoreTestingSelection"],
     "restore job status, size, dates and the vault restored from; what each restore testing plan selects; never restored data"),
    ("Iceberg and S3 Tables detection", [
        "glue:GetDatabases", "glue:GetTables", "s3tables:ListTableBuckets", "s3tables:ListTables"], ""),
    ("Cost attribution (optional)", ["ce:GetCostAndUsage", "ce:GetDimensionValues"],
     "trailing 30 days by account and usage type, plus one lookup of service names; off with --no-cost"),
    ("Access check (--preflight only)", ["tag:GetResources", "ce:GetDimensionValues"],
     "proves access without collecting anything"),
]


def format_actions(actions: List[str]) -> str:
    """'rds:DescribeDBInstances,DescribeDBClusters · dynamodb:ListTables', grouped by service."""
    by_service: Dict[str, List[str]] = {}
    for action in actions:
        service, name = action.split(":", 1)
        by_service.setdefault(service, []).append(name)
    return " · ".join(f"{service}:{','.join(names)}" for service, names in by_service.items())


_STATE_LABELS = {
    "none": "no policy, recovery point or native snapshot found",
    "policy_only": "in a backup plan, but no copy yet",
    "stale": "in a backup plan, but the newest copy is older than its recovery target",
    "current": "a policy applies and a recent copy exists",
    "orphan_policy": "copies exist but no policy currently applies",
    "excluded_documented": "no copy, with a recorded decision",
    "no_backup_path": "Iceberg table with no table-level recovery identified",
    "not_assessed": "a call needed to decide was denied or failed",
}


# Each recovery-copy state in plain words, with the colour it has in the bars.  Same order as the bars: covered first, the gap last.
_STATE_PLAIN = (("current", "Has a current copy", "k-ok"),
                ("orphan_policy", "Has copies, but nothing makes new ones", "k-blue"),
                ("stale", "In a backup plan, newest copy late", "k-paper"),
                ("policy_only", "In a backup plan, no copy yet", "k-paper"),
                ("excluded_documented", "No copy, by a recorded decision", "k-grey"),
                ("no_backup_path", "Apache Iceberg table with no table-level recovery identified", "k-purple"),
                ("none", "No recovery copy", "k-none"))


# The recovery-evidence states as bars: the same three groups as the first page (not assessed is left out of both bars).
_EVIDENCE_PLAIN = (("current", "Copy identified", "k-ok"),
                   ("outdated", "Copy identified, older than the target", "k-paper"),
                   ("none_identified", "No recovery copy identified", "k-none"))


def state_bars_html(c: Dict[str, Any]) -> str:
    """Two stacked bars (production, every resource assessed) split by recovery state, with a legend that carries each
    count in text, so colour is never the only cue.  Uses the recovery-evidence states when the census has them."""
    if "evidence_states" in c:
        prod, every = c.get("production_evidence") or {}, c.get("evidence_states") or {}
        plain, gap = _EVIDENCE_PLAIN, "none_identified"
    else:
        prod, every = c.get("production_states") or {}, c.get("states") or {}
        plain, gap = _STATE_PLAIN, "none"
    rows = [("Production", prod), ("All assessed", every)]
    rows = [(label, st, sum(st.get(k, 0) for k, _, _ in plain)) for label, st in rows]
    rows = [r for r in rows if r[2]]
    if not rows:
        return ""
    out = ['<ul class="ov-acct state-bars">']
    for label, st, n in rows:
        seg = "".join(f'<span class="{cls}" style="width:{st[k] / n * 100:.1f}%" title="{_esc(name)}: {st[k]:,}"></span>'
                      for k, name, cls in plain if st.get(k))
        aria = "; ".join(f'{st[k]:,} {name.lower()}' for k, name, _ in plain if st.get(k))
        out.append(f'<li><span class="ov-an">{_esc(label)}<em>{n:,} resources</em></span>'
                   f'<div class="ov-stack" role="img" aria-label="{_esc(label)}: {_esc(aria)}">{seg}</div>'
                   f'<b>{st.get(gap, 0):,} none</b></li>')
    # One table by inferred environment: the only place these counts are shown by environment (Assets lists the resources).
    envs = c.get("evidence_by_environment") or {}
    cols = [("Production", prod)] + [(label, envs.get(key) or {}) for key, label in (("development", "Development"),
                                                                                  ("unknown", "Environment not known"))
                                     if sum((envs.get(key) or {}).values())] + [("All assessed", every)]
    out.append('</ul><table class="state-key"><thead><tr><th>State</th>'
               + "".join(f'<th class="num">{_esc(label)}</th>' for label, _ in cols) + '</tr></thead><tbody>')
    for k, name, cls in plain:
        if prod.get(k) or every.get(k):
            out.append(f'<tr><td><span class="ov-key {cls}"></span>{_esc(name)}</td>'
                       + "".join(f'<td class="num">{st.get(k, 0):,}</td>' for _, st in cols) + '</tr>')
    out.append('</tbody></table>')
    out.append('<p class="meta"><b>Older than the target:</b> a copy exists, but the newest one is older than 1.5 times the '
               'recovery point target for the resource\'s tier (by default 24 hours for production and 7 days '
               'for development; the targets file changes them). A copy whose age cannot be read, such as S3 versioning, counts as '
               'identified. <b>Schedule slower than the target:</b> the AWS Backup plan that selects the resource runs less often than that '
               'target, for example once a week against a 24-hour target.</p>')
    return "".join(out)


def census_section_html(census: Dict[str, Any], drift: Optional[Dict[str, Any]] = None) -> List[str]:
    """The headline section: how much production data has a recovery copy, how that was counted, and
    what changed since the previous run.  Facts and labelled inference, no grade."""
    c = census
    e = _esc
    out: List[str] = []
    w = out.append

    def pct(value: Optional[float]) -> str:
        return "not known" if value is None else f"{value:.1f}%"

    w('<section><div class="sec-head"><span class="sec-num">Headline</span>'
      '<h2>How much data has a recovery copy</h2></div>')
    if not c["production"]:
        w(f'<p class="lede">No resource was classified as production, so there is no production figure. '
          f'{_n(c["assessed"], "resource")} {_was(c["assessed"])} assessed; {c["unknown_environment"]:,} '
          f'{_has(c["unknown_environment"])} an environment the tool could not infer.</p>')
    else:
        if "production_evidence" in c:
            # The first page's figure: every production resource with no recovery copy identified, then the undecided part.
            none_n = (c.get("production_evidence") or {}).get("none_identified", 0)
            undecided = c.get("no_copy_identified", c["strict_no_copy"])
            w(f'<p class="lede"><strong>{none_n:,} of {c["production"]:,} production resources ({pct(_pct(none_n, c["production"]))}) '
              f'have no recovery copy identified</strong> by the mechanisms assessed'
              + (f'; {undecided:,} of them with no decision on record' if undecided != none_n else '') + '.</p>')
        else:
            w(f'<p class="lede"><strong>{c["strict_no_copy"]:,} of {c["production"]:,} production resources '
              f'({pct(c["strict_pct"])}) have no recovery copy identified</strong> by the mechanisms assessed.</p>')
    w(f'<p><em>Production is inferred</em> from tags, the account and OU, and names (<span class="mono">criticality_basis</span> in '
      f'<span class="mono">assets.csv</span>; an overrides file corrects it). '
      + (f'{_n(c["unknown_environment"], "resource")} with an environment that could not be inferred {_is(c["unknown_environment"])} '
         f'not in the production figure.' if c["unknown_environment"] else '')
      + (f' {_n(c["not_assessed"], "resource")} could not be fully assessed and {_is(c["not_assessed"])} in no figure below.' if c["not_assessed"] else '')
      + '</p>')
    w(state_bars_html(c))
    w('<p class="meta-line">One state per resource, the same as the first page; each is in <span class="mono">assets.csv</span> '
      '(<span class="mono">recovery_evidence</span>).</p>')

    # The rest is detail for whoever checks the figures, in folds opened on demand.
    w('<h3>How the figure was counted</h3>')
    w('<table><thead><tr><th>Production resources, counted three ways</th><th class="num">Resources</th>'
      '<th class="num">Share</th></tr></thead><tbody>')
    for label, n, share in (
            ("No policy, recovery point or native snapshot", c["strict_no_copy"], c["strict_pct"]),
            ("…plus those in a backup plan with no copy yet", c["with_policy_only"], c["policy_only_pct"]),
            ("…plus those whose newest copy is older than their recovery target", c["with_stale"], c["stale_pct"])):
        w(f'<tr><td>{e(label)}</td><td class="num">{n:,}</td><td class="num">{pct(share)}</td></tr>')
    w('</tbody></table>')
    w('<table><thead><tr><th>Recovery-copy state</th><th>What it means</th><th class="num">Production</th>'
      '<th class="num">All assessed</th></tr></thead><tbody>')
    for state, label in _STATE_LABELS.items():
        if state == "not_assessed":
            continue
        if c["states"].get(state) or c["production_states"].get(state):
            w(f'<tr><td class="mono">{e(state)}</td><td>{e(label)}</td>'
              f'<td class="num">{c["production_states"].get(state, 0):,}</td>'
              f'<td class="num">{c["states"].get(state, 0):,}</td></tr>')
    w('</tbody></table>')
    w(SCOPE_REMINDER)

    gap_total = sum(c["causes"].values())
    idle = c.get("plans_selecting_nothing") or {"no_assignment": [], "selects_none_assessed": []}
    if gap_total or idle["no_assignment"] or idle["selects_none_assessed"]:
        w('<h3>Why production resources have no copy</h3>')
    causes = [(cause, n) for cause, n in c["causes"].items() if n]
    if len(causes) == 1:
        w(f'<p>All {causes[0][1]:,} have the same cause: {e(causes[0][0])}.</p>')
    elif gap_total:
        w('<p>One cause each, taken in this order: service not opted in, an AWS Backup job failing, created in the '
          'last 30 days, no policy selecting it, otherwise no signal of any kind.</p>')
        w('<table><thead><tr><th>Cause</th><th class="num">Resources</th></tr></thead><tbody>')
        for cause, n in c["causes"].items():
            if n:
                w(f'<tr><td>{e(cause)}</td><td class="num">{n:,}</td></tr>')
        w('</tbody></table>')

    if idle["no_assignment"] or idle["selects_none_assessed"]:
        w('<h4>Backup plans that select nothing</h4>')
        if idle["no_assignment"]:
            w(f'<p>No resource assignment, so nothing is protected: {_n(len(idle["no_assignment"]), "plan")} of {c["plan_count"]:,} '
              f'({e(", ".join(x["name"] for x in idle["no_assignment"][:6]))}).</p>')
        if idle["selects_none_assessed"]:
            w(f'<p>Assignments that select none of the resources assessed here, perhaps a kind this review does not cover: '
              f'{_n(len(idle["selects_none_assessed"]), "plan")} ({e(", ".join(x["name"] for x in idle["selects_none_assessed"][:6]))}).</p>')
    w('<h3>Tags, and how each environment was decided</h3>')
    w('<h4>The tag view and the whole-estate view</h4>')
    tv, ev = c["tag_view"], c["estate_view"]
    if c["tag_keys_in_selections"]:
        w(f'<p>Backup selections pick resources by {len(c["tag_keys_in_selections"])} tag key(s). Of the '
          f'{tv["resources"]:,} resources carrying one, {tv["with_copy"]:,} ({pct(tv["pct"])}) have a recovery copy. '
          f'Across all {ev["resources"]:,} assessed resources the figure is {pct(ev["pct"])}. The difference is the '
          f'data that tag-based reporting cannot see. {c["untagged"]:,} resources ({pct(c["untagged_pct"])}) carry '
          f'neither an environment tag nor a tag a selection uses.</p>')
    else:
        w(f'<p>No backup selection picks resources by tag, so there is no tag-based view to compare. '
          f'Across all {ev["resources"]:,} assessed resources, {pct(ev["pct"])} have a recovery copy. '
          f'{_n(c["untagged"], "resource")} ({pct(c["untagged_pct"])}) {"carries" if c["untagged"] == 1 else "carry"} no environment tag.</p>')
    if c["near_misses"]:
        w('<p>These tags differ from one a selection uses only by case or punctuation. A resource carrying one '
          'is outside the selection because of how the tag is written.</p>')
        w('<table><thead><tr><th>Tag as written</th><th>Differs in</th><th class="num">Resources</th></tr></thead><tbody>')
        for nm in c["near_misses"]:
            shown = nm["key"] if nm["kind"] == "key" else f'{nm["key"]} = {nm["value"]}'
            w(f'<tr><td class="mono">{e(shown)}</td><td>{"key" if nm["kind"] == "key" else "value"}</td>'
              f'<td class="num">{nm["resources"]:,}</td></tr>')
        w('</tbody></table>')

    tg = c.get("tagging")
    if tg and tg["all"]["resources"]:
        def pct_of(n: int, whole: int) -> str:
            return f"{n:,} ({100 * n / whole:.0f}%)" if whole else "0"
        w('<h4>Which resources carry tags</h4>')
        a = tg["all"]
        w(f'<p>{pct_of(a["any"], a["resources"])} of {a["resources"]:,} assessed resources carry at least one tag; '
          f'{pct_of(a["environment"], a["resources"])} carry an environment tag and {pct_of(a["owner"], a["resources"])} an owner or '
          f'team tag. Tags are what environment and owner are inferred from first, so where they are missing more is inferred. '
          f'Tag keys per resource are in <span class="mono">assets.csv</span> (<span class="mono">tag_keys</span>); tag values are never listed.</p>')
        w('<table><thead><tr><th>Resource type</th><th class="num">Resources</th><th class="num">Any tag</th>'
          '<th class="num">Environment tag</th><th class="num">Owner or team tag</th>'
          + ('<th class="num">A tag a backup selection uses</th>' if tg["selection_keys"] else '') + '</tr></thead><tbody>')
        for rtype, row_ in tg["by_type"].items():
            w(f'<tr><td class="mono">{e(rtype.replace("AWS::", ""))}</td><td class="num">{row_["resources"]:,}</td>'
              f'<td class="num">{pct_of(row_["any"], row_["resources"])}</td><td class="num">{pct_of(row_["environment"], row_["resources"])}</td>'
              f'<td class="num">{pct_of(row_["owner"], row_["resources"])}</td>'
              + (f'<td class="num">{pct_of(row_["selection"], row_["resources"])}</td>' if tg["selection_keys"] else '') + '</tr>')
        w('</tbody></table>')
    labels = {"tag": "an environment tag on the resource", "account-ou": "the account's organizational unit",
              "account-name": "the account's name", "name": "the resource's name", "account-majority": "most of its account being production",
              "behaviour": "how the resource is used (low confidence)", "override": "an overrides file", "none": "nothing: environment unknown"}
    if c.get("environment_basis"):
        w('<h4>How the environment of each resource was decided</h4><table><thead><tr><th>Decided by</th>'
          '<th class="num">Resources</th></tr></thead><tbody>')
        for basis, n in c["environment_basis"].items():
            w(f'<tr><td>{e(labels.get(basis, basis))}</td><td class="num">{n:,}</td></tr>')
        w('</tbody></table>')
    if c.get("mismatch"):
        names = ", ".join(m["name"] for m in c["mismatch"][:6])
        w(f'<div class="callout warn"><h4>Labelled development, used like production</h4><p>{len(c["mismatch"]):,} resource(s) are '
          f'labelled development or test (by a tag, account or name) but show signs of production use: Multi-AZ, several cluster '
          f'members, or recent writes. Examples: <span class="mono">{e(names)}</span>. They are not counted as over-protected, since '
          f'the label may be out of date. The signal is in the <span class="mono">behaviour_signals</span> column of '
          f'<span class="mono">assets.csv</span>; an overrides file records what each one is.</p></div>')
    w('<h3>Decisions, age and sensitive data</h3>')
    w('<h4>Decisions on record</h4>')
    w(f'<p>{c["documented_exclusions"]:,} production resource(s) have a recorded decision not to protect them '
      f'(a <span class="mono">backup:exclude-reason</span> tag or an overrides-file entry), with an owner and review date '
      f'where given. '
      + (f'That is {pct(c["decided_pct"])} of the {c["decided_pool"]:,} production resources with no copy, counting these. '
         if c["decided_pool"] else 'No production resource is without a copy, so there is no share to give. ')
      + (f'Past their review date, and counted as gaps again: {c["expired_exclusions"]:,}. ' if c["expired_exclusions"] else '')
      + f'<span class="mono">exclusion-worksheet.csv</span> lists the resources with no decision yet, with blank columns to fill in.</p>')

    w('<h4>Age</h4>')
    gm, pm = c["gap_median_age_days"], c["protected_median_age_days"]
    if gm is None:
        w('<p>No production resource without a copy has a known creation time, so no age is reported.</p>')
    else:
        w(f'<p>Production resources without a copy have a median age of {gm:,.0f} days '
          f'({c["gap_age_known"]:,} of {c["gaps"]:,} {_has(c["gap_age_known"])} a known creation time); those with a copy, '
          + (f'{pm:,.0f} days' if pm is not None else 'not known')
          + f'. {c["gaps_over_a_year"]:,} of the gaps {_is(c["gaps_over_a_year"])} more than a year old; {c["new_gaps"]:,} {_was(c["new_gaps"])} created in the '
            f'last 30 days.</p>')

    if c["sensitive"]:
        w(f'<h4>Sensitive data</h4><p>{c["sensitive_no_copy"]:,} of {c["sensitive"]:,} resources classified as '
          f'CONFIDENTIAL or higher ({pct(c["sensitive_pct"])}) have no recovery copy'
          + (f'; of those whose names or tags indicate personal data, {c["pii_no_copy"]:,} of {c["pii"]:,} ({pct(c["pii_pct"])})'
             if c["pii"] else '')
          + '. Sensitivity is inferred from tags and names only, and no data was read, so these are lower bounds.</p>')

    if c["by_account"]:
        w('<h4>Production resources without a copy, by account</h4>')
        w('<table><thead><tr><th>Account</th><th class="num">Production</th><th class="num">No copy</th>'
          '<th class="num">Policy only</th><th class="num">Stale</th></tr></thead><tbody>')
        ranked = sorted(c["by_account"].items(), key=lambda kv: (-kv[1]["no_copy"], kv[0]))[:15]
        for name, row in ranked:
            w(f'<tr><td>{e(name)}</td><td class="num">{row["production"]:,}</td><td class="num">{row["no_copy"]:,}</td>'
              f'<td class="num">{row["policy_only"]:,}</td><td class="num">{row["stale"]:,}</td></tr>')
        w('</tbody></table>')

    w('<h3>What the checks could see</h3>')
    w('<h4>What the native-copy check could see</h4>')
    w('<p>"No copy" is only as complete as the checks behind it. For each resource type, this is what was checked for copies made by '
      'the service itself. AWS Backup is checked separately, for every type, in the next table.</p>')
    w('<table><thead><tr><th>Resource type</th><th>Native copies checked</th><th class="num">Resources</th></tr></thead><tbody>')
    for rtype, (what, n) in c["snapshot_visibility"].items():
        w(f'<tr><td class="mono">{e(rtype)}</td><td>{e(what)}</td><td class="num">{n:,}</td></tr>')
    w('</tbody></table>')

    by_type = c.get("backup_by_type") or []
    if by_type:
        def share(n: int, d: int) -> str:
            return f"{n:,} ({n / d:.0%})" if d else "0"
        w('<h4>AWS Backup, by resource type</h4>')
        w('<p>AWS Backup is read for every resource type, S3 buckets included. "Selected now" means a backup plan\'s selection picks the '
          'resource today (a Region where the service is not opted in is left out). "Has a recovery point" means AWS Backup holds at '
          'least one for it, which stays true after a plan stops selecting it. Resources that could not be assessed are counted apart '
          'and are in neither column.</p>')
        w('<table><thead><tr><th>Resource type</th><th class="num">Assessed</th><th class="num">Selected by a plan now</th>'
          '<th class="num">Has an AWS Backup recovery point</th><th class="num">Backup jobs failing</th>'
          '<th class="num">Not assessed</th></tr></thead><tbody>')
        for row in by_type:
            w(f'<tr><td class="mono">{e(row["type"])}</td><td class="num">{row["assessed"]:,}</td>'
              f'<td class="num">{share(row["selected"], row["assessed"])}</td>'
              f'<td class="num">{share(row["with_recovery_point"], row["assessed"])}</td>'
              f'<td class="num">{row["jobs_failing"]:,}</td><td class="num">{row["not_assessed"]:,}</td></tr>')
        w('</tbody></table>')
    s3v = c.get("s3_backup_versioning") or {}
    if s3v.get("selected"):
        ref = REFERENCES["s3_backup_versioning"]
        link = f'<a href="{e(ref[1])}" rel="noopener noreferrer">{e(ref[0])}</a>'
        unread = (f' Versioning could not be read for {s3v["unknown"]:,} of them (see Coverage gaps), so nothing is said about '
                  f'{"it" if s3v["unknown"] == 1 else "those"}.'
                  if s3v.get("unknown") else "")
        if s3v["off"]:
            failed = (f' {s3v["off_with_failed_jobs"]:,} of those have AWS Backup jobs that failed in the period read.'
                      if s3v.get("off_with_failed_jobs") else "")
            w(f'<div class="callout"><h4>S3 buckets a backup plan selects</h4><p>AWS Backup for S3 needs S3 Versioning on the bucket ({link}). '
              f'Of the {s3v["selected"]:,} buckets a backup plan selects now, {s3v["on"]:,} with versioning on and {s3v["off"]:,} with it off or '
              f'suspended.{failed}{unread}</p>')
            w('<table><thead><tr><th>Account</th><th>Bucket</th><th>Versioning</th><th class="num">Failed jobs</th></tr></thead><tbody>')
            for row in s3v["rows"]:
                w(f'<tr><td>{e(row["account"])}</td><td class="mono">{e(row["bucket"])}</td>'
                  f'<td>{e(str(row["versioning"]).replace("_", " "))}</td><td class="num">{row["failed_jobs"]:,}</td></tr>')
            w('</tbody></table>')
            if s3v["off"] > len(s3v["rows"]):
                w(f'<p class="none">The first {len(s3v["rows"])} of {s3v["off"]:,}. All are in <span class="mono">assets.csv</span> '
                  f'(s3_versioning, plan_selected = True).</p>')
            w('</div>')
        else:
            w(f'<div class="callout good"><h4>S3 buckets a backup plan selects</h4><p>AWS Backup for S3 needs S3 Versioning on the bucket '
              f'({link}). {_all_buckets(s3v["on"])} a backup plan selects now {"has" if s3v["on"] == 1 else "have"} versioning on.{unread}</p></div>')

    s3c = c.get("s3_continuous") or {}
    if s3c.get("continuous"):
        ref = REFERENCES["s3_eventbridge"]
        link = f'<a href="{e(ref[1])}" rel="noopener noreferrer">{e(ref[0])}</a>'
        unread = (f' The setting could not be read for {s3c["unknown"]:,} of them (see Coverage gaps), so nothing is said about '
                  f'{"it" if s3c["unknown"] == 1 else "those"}.'
                  if s3c.get("unknown") else "")
        how = (f'AWS documents that continuous backups of an S3 bucket rely on the bucket\'s Amazon EventBridge notification setting ({link}). '
               f'With it off, new changes are no longer tracked for point-in-time restore, and AWS Backup raises no alert and no failed job; '
               f'existing recovery points and scheduled snapshots are not affected. ')
        if s3c["off"]:
            w(f'<div class="callout"><h4>S3 buckets backed up continuously</h4><p>{how}Of the {s3c["continuous"]:,} buckets a backup plan backs '
              f'up continuously, {s3c["on"]:,} with EventBridge notifications on and {s3c["off"]:,} with them off.{unread}</p>')
            w('<table><thead><tr><th>Account</th><th>Bucket</th><th>EventBridge notifications</th></tr></thead><tbody>')
            for row in s3c["rows"]:
                w(f'<tr><td>{e(row["account"])}</td><td class="mono">{e(row["bucket"])}</td><td>off</td></tr>')
            w('</tbody></table>')
            if s3c["off"] > len(s3c["rows"]):
                w(f'<p class="none">The first {len(s3c["rows"])} of {s3c["off"]:,}. All are in <span class="mono">assets.csv</span> '
                  f'(s3_eventbridge = off, s3_continuous_backup = True).</p>')
            w('</div>')
        else:
            w(f'<div class="callout good"><h4>S3 buckets backed up continuously</h4><p>{how}{_all_buckets(s3c["on"])} a backup plan backs up '
              f'continuously {"has" if s3c["on"] == 1 else "have"} EventBridge notifications on.{unread}</p></div>')

    cl = c.get("classification") or {}
    # The recovery targets and tolerance are in "Inputs and assumptions"; only what that table does not say is here.
    w(f'<div class="callout"><h4>How this was counted</h4><p>A resource is counted once. '
      f'Overrides applied: {cl.get("overrides_used", 0):,} of {cl.get("overrides_loaded", 0):,} loaded '
      f'({cl.get("overrides_in_production", 0):,} in production). Read as production because most '
      f'of their account is: {cl.get("account_majority", 0):,}. Tier 1 is confidential production data, tier 2 other production, tier 3 '
      f'development; an unknown environment has no tier and is never called late. An attached volume is covered by its instance\'s '
      f'recovery points where it has them. '
      + (f'{cl["cluster_members_folded"]:,} database instance(s) that belong to a cluster are counted through the cluster. '
         if cl.get("cluster_members_folded") else '') + '</p></div>')
    w('</section>')

    if drift:
        w('<section><div class="sec-head"><span class="sec-num">Change</span>'
          f'<h2>What changed since {e(drift["previous_date"] or "the previous run")}</h2></div>')
        w('<p>Compared with the previous run\'s assessment file. Counts only, not a judgement of which changes matter. Resources '
          'not assessed in either run are left out, because a failed call is not a change in the environment.</p>')
        pc, rc = drift["production_without_copy"], drift["resources"]
        w(f'<p>Resources assessed: {rc["before"]:,} then, {rc["after"]:,} now. Production resources with no recovery copy: '
          f'{pc["before"]:,} then, {pc["after"]:,} now.</p>')
        w('<table><thead><tr><th>Change</th><th class="num">Count</th></tr></thead><tbody>')
        for label, key in (("Resources that now have no copy and were previously covered", "regressions"),
                           ("Resources that now have no copy and are new or were not counted before", "new_gaps"),
                           ("Resources that gained a copy", "closed_gaps"),
                           ("Backup plans no longer present", "plans_removed"),
                           ("Vaults whose lock is weaker than before", "vault_locks_weakened"),
                           ("Vaults no longer present", "vaults_gone")):
            w(f'<tr><td>{e(label)}</td><td class="num">{len(drift[key]):,}</td></tr>')
        w(f'<tr><td>New resources that arrived with a copy</td><td class="num">{drift["new_resources_protected"]:,}</td></tr>')
        w(f'<tr><td>Resources in the previous run and not in this one</td><td class="num">{drift["resources_gone"]:,}</td></tr>')
        w('</tbody></table><p>The resources behind each count are in <span class="mono">changes.csv</span>.</p></section>')
    return out


def copies_section_html(summary: Dict[str, Any], costs_note: bool = True) -> List[str]:
    """Copies whose source is gone, backups visible outside the account, volumes attached to nothing.  Facts only."""
    e = _esc
    out: List[str] = []
    w = out.append
    o, x = summary["orphans"], summary["exposure"]
    x = {**x, "unchecked": x.get("unchecked") or {"public_snapshots": [], "public_images": [], "rds_attributes": []}}
    public_n = len(x["public_ebs_snapshots"]) + len(x["public_images"]) + len(x["rds_public"])
    if not (o["rows"] or o["unverifiable"] or public_n or x["rds_shared"] or summary["unattached_volumes"]
            or summary["deletion_checked"] or any(x.get("unchecked", {}).values()) or o.get("unchecked_scopes")):
        return out
    w('<section><div class="sec-head"><span class="sec-num">Copies</span>'
      '<h2>Copies with no source, and volumes attached to nothing</h2></div>')

    w('<h3>Copies whose source resource is gone</h3>')
    if o["rows"]:
        kinds = {"ebs_snapshot": "EBS snapshots of deleted volumes", "rds_db_snapshot": "manual snapshots of deleted databases",
                 "rds_cluster_snapshot": "manual snapshots of deleted clusters",
                 "rds_retained_automated_backup": "automated backups kept after their database was deleted",
                 "recovery_point": "AWS Backup recovery points of deleted resources"}
        w('<p>Each of these was made from a resource that no longer exists in what was assessed. It may be kept on purpose, '
          'and it can be the only remaining copy of that data, so whether to keep it is the owner\'s decision.</p>')
        w('<table><thead><tr><th>Kind</th><th class="num">Copies</th><th class="num">Size</th>'
          '<th class="num">Median age</th><th class="num">Est. monthly cost</th></tr></thead><tbody>')
        for kind, label in kinds.items():
            rows = [r for r in o["rows"] if r["kind"] == kind]
            if rows:
                ages = [r["age_days"] for r in rows if r.get("age_days") is not None]
                med = _median(ages)
                w(f'<tr><td>{e(label)}</td><td class="num">{len(rows):,}</td>'
                  f'<td class="num">{_fmt_tib(sum(r.get("size_gib") or 0 for r in rows))}</td>'
                  f'<td class="num">{"not known" if med is None else f"{med:,.0f} days"}</td>'
                  f'<td class="num">{_fmt_money(sum(r["monthly_usd"] for r in rows))}</td></tr>')
        w('</tbody></table>')
        w(f'<p><em>Estimate.</em> Cost is size times the list rates assumed in this report, about '
          f'{_fmt_money(o["estimated_monthly_usd"])} a month in total. An EBS snapshot is incremental, so using the '
          f'volume size makes its figure an upper bound, except for one in the archive tier, which is a full copy priced at the '
          f'archive rate (${_rate(MECHANISM_RATES["ebs_snapshot_archive"])} per GiB-month). Recovery points in cold storage are '
          f'priced at the cold rate. ')
        if not o["legal_holds_known"]:
            w('Whether any recovery point is under a legal hold could not be read, so none is excluded. ')
        elif o["held"]:
            w(f'{o["held"]:,} recovery point group(s) are under a legal hold and are marked as held in '
              f'<span class="mono">orphaned-copies.csv</span>; {_fmt_money(o["not_held_monthly_usd"])} a month is not held. ')
        w('The full list, with identifiers, ages and sizes, is in <span class="mono">orphaned-copies.csv</span>.</p>')
    elif not o.get("unchecked_scopes"):
        w('<p>No copy was found whose source resource is missing from what was assessed.</p>')
    if o.get("unchecked_scopes"):
        w(f'<p><em>Not assessed:</em> in {len(o["unchecked_scopes"]):,} account/Region scope(s) a call needed to list snapshots, '
          f'backups or recovery points was denied or failed (see Coverage gaps), so this list may be missing copies there.</p>')
    if o["unverifiable"]:
        w(f'<p>{o["unverifiable"]:,} AWS Backup resource(s) with recovery points could not be checked: their source is in an account '
          f'or Region this run did not scan, or listing that Region failed (see Coverage gaps). They are not counted above.</p>')

    if summary["unattached_volumes"]:
        w('<h3>Volumes attached to nothing</h3>')
        w(f'<p>{summary["unattached_volumes"]:,} EBS volume(s) ({_fmt_tib(summary["unattached_gib"])}) are attached to no instance, '
          f'so a backup that works through instances does not reach them; {summary["unattached_without_copy"]:,} of them have '
          f'no snapshot or recovery point.</p>')
    w('</section>')

    # Backups visible outside the account and deletion are their own section: they bear on cyber recovery, and the section above
    # is about what copies cost.
    w('<section><div class="sec-head"><span class="sec-num">Sharing</span>'
      '<h2>Backups visible outside the account, and deletion</h2></div>')
    share_from = len(out)
    w('<h4>Backups visible outside the account</h4>')
    parts = []
    if x["public_ebs_snapshots"]:
        parts.append(f'{len(x["public_ebs_snapshots"]):,} EBS snapshot(s)')
    if x["rds_public"]:
        parts.append(f'{len(x["rds_public"]):,} RDS snapshot(s)')
    if x["public_images"]:
        parts.append(f'{len(x["public_images"]):,} AMI(s)')
    if parts:
        w(f'<div class="callout warn"><h4>Readable by any AWS account</h4><p>{e(", ".join(parts))} in the accounts assessed '
          f'can be restored or launched by any AWS account. Identifiers and Regions are in '
          f'<span class="mono">shared-backups.csv</span>. A public snapshot is sometimes intended, for example a shared image; '
          f'the file shows which resource each one is so the owner can tell.</p></div>')
    else:
        done = [label for key, label in (("public_snapshots", "EBS snapshot"), ("rds_attributes", "RDS snapshot"),
                                          ("public_images", "AMI")) if not x["unchecked"][key]]
        if len(done) == 3:
            w('<p>No public EBS snapshot, RDS snapshot or AMI was found.</p>')
        elif done:
            w(f'<p>No public {e(", ".join(done))} was found.</p>')
    for key, label in (("public_snapshots", "public EBS snapshots"), ("rds_attributes", "who RDS manual snapshots are shared with"),
                       ("public_images", "public AMIs")):
        if x["unchecked"][key]:
            w(f'<p><em>Not assessed:</em> {label} could not be checked in {len(x["unchecked"][key]):,} account/Region scope(s) '
              f'(a call was denied or failed; see Coverage gaps), so nothing is said about them there.</p>')
    if x["rds_shared"]:
        w(f'<p>{len(x["rds_shared"]):,} manual RDS snapshot(s) are shared with specific accounts (listed in '
          f'<span class="mono">shared-backups.csv</span>).</p>')
    w('<p>What was checked: whether EBS snapshots, RDS and Aurora manual snapshots and AMIs are public, and which accounts RDS '
      'and Aurora manual snapshots are shared with. EBS snapshots shared with specific accounts were not checked, because that '
      'takes one call per snapshot.</p>')

    if summary["deletion_checked"]:
        w('<h4>Deletion</h4>')
        w(f'<p>{summary["deletion_protected"]:,} of {summary["deletion_checked"]:,} databases and DynamoDB tables have deletion '
          f'protection on. {summary["deletion_exposed"]:,} have it off and no copy that would outlive the resource (a recovery '
          f'point in AWS Backup, a manual snapshot, an on-demand backup, or DynamoDB point-in-time recovery, which keeps a final '
          f'backup of a deleted table for 35 days). RDS automated backups do not count: whether they are kept is chosen when the '
          f'instance is deleted, and cannot be read beforehand.</p>')
        if summary["deletion_exposed_names"]:
            w(f'<p>Examples: <span class="mono">{e(", ".join(summary["deletion_exposed_names"][:5]))}</span>. The column '
              f'<span class="mono">deletion_exposed</span> in <span class="mono">assets.csv</span> lists all of them.</p>')
    detail = "".join(out[share_from:])
    del out[share_from:]
    w(_fold("What was checked for public backups, sharing and deletion protection", detail))
    w('</section>')
    return out


def owners_section_html(owners: List[Dict], limit: int = 15) -> List[str]:
    if not owners:
        return []
    e = _esc
    out: List[str] = []
    w = out.append
    w('<section><div class="sec-head"><span class="sec-num">Owners</span><h2>The same findings, by who they probably belong to</h2></div>')
    w('<p><em>Inferred.</em> An owner is read from an owner or team tag, then an application tag, then the application group '
      'the tool found (a CloudFormation stack, an AppRegistry application, a cluster), then the account. The basis is shown '
      'for each row. Confirm it with the people named before relying on it. All rows, and the owner of each resource, are in '
      '<span class="mono">by-owner.csv</span> and <span class="mono">assets.csv</span>.</p>')
    w('<table><thead><tr><th>Inferred owner</th><th>Basis</th><th class="num">Resources</th><th class="num">Production</th>'
      '<th class="num">No copy</th><th class="num">No recent copy</th><th class="num">One delete removes data and copies</th></tr></thead><tbody>')
    for row in owners[:limit]:
        w(f'<tr><td>{e(row["owner"])}</td><td>{e(row["basis"])}</td><td class="num">{row["resources"]:,}</td>'
          f'<td class="num">{row["production"]:,}</td><td class="num">{row["no_copy"]:,}</td>'
          f'<td class="num">{row["policy_only_or_stale"]:,}</td><td class="num">{row["deletion_exposed"]:,}</td></tr>')
    w('</tbody></table>')
    if len(owners) > limit:
        w(f'<p>{len(owners) - limit:,} more owner(s) are in <span class="mono">by-owner.csv</span>.</p>')
    w('</section>')
    return out


def questions_section_html(questions: List[Dict[str, Any]]) -> List[str]:
    if not questions:
        return []
    e = _esc
    out: List[str] = []
    w = out.append
    w('<section><div class="sec-head"><span class="sec-num">Questions</span><h2>Items to review</h2></div>')
    w('<p class="lede">Questions for the owners, in a fixed order. Open an item for what it means and where the list is. Any answer may be '
      'the intended one; AWS links are references only.</p>')
    n = 0
    for group, title in _QUESTION_GROUPS:
        items = [i for i in questions if i.get("group", "recovery") == group]
        if not items:
            continue
        # Each item is its own block: the count and the finding, with the explanation and the links in a drop-down (Alex, 2026-11-17).
        w(f'<h3 class="keep">{e(title)}</h3><ol class="review" start="{n + 1}">')
        for item in items:
            n += 1
            ref = REFERENCES.get(item["reference"]) if item.get("reference") else None
            # The practice ID (REL09-BP01) stands in for its full title, which stays in the link's tooltip.
            ref_label = (ref[0].split(" ", 1)[0] if ref and re.match(r"REL\d+-BP\d+ ", ref[0]) else "AWS docs") if ref else ""
            links = ([f'<a href="#{e(item["view"])}">View them</a>'] if item.get("view") else []) \
                + ([f'<a href="{e(ref[1])}" title="{e(ref[0])}" rel="noopener noreferrer">{e(ref_label)}</a>'] if ref else [])
            w(f'<li><details class="review-item"><summary><span class="review-n">{item["count"]:,}</span>'
              f'{_review_title(item["finding"])}</summary><div class="review-body"><p>{e(item["question"])}</p>'
              f'<p class="meta">{" · ".join(links)}{" · " if links else ""}<span class="mono">{e(item["where"])}</span></p></div>'
              f'</details></li>')
        w('</ol>')
    w('</section>')
    return out


def _review_title(finding: str) -> str:
    """The finding with its subject in bold and the rest in regular weight, so the list does not read as one block."""
    m = re.match(r"(.+?)(\s(?:with|without|whose|that|in|on|selected|attached|due|labelled|could|not)\s.*)$", finding)
    head, tail = (m.group(1), m.group(2)) if m else (finding, "")
    return f'<span class="review-t"><b>{_esc(head)}</b>{_esc(tail)}</span>'


_QUESTION_GROUPS = (("recovery", "Recovery"), ("security", "Isolation and security"), ("spend", "Spend"),
                    ("setup", "Classification and setup"))


_KEY_KIND_LABELS = {
    "aws_owned": "AWS-owned key (logically air-gapped vaults)",
    "aws_managed": "AWS-managed key. AWS-managed keys cannot be shared with another account, so copies to another account are not possible",
    "customer_same_account": "Customer-managed key in the vault's own account. Whoever can schedule that key's deletion in the account can make every copy under it unreadable",
    "customer_other_account": "Customer-managed key in a different account",
    "unknown": "Key could not be identified",
}


def copy_protection_actions(d: Dict[str, Any]) -> Dict[str, List[Tuple[int, str, str]]]:
    """What in Backup copy protection someone can act on, each as (count, what it is and why it matters, where the list is), and what is
    already working.  Only facts already collected; nothing is counted here that the detail below does not also show."""
    sec = d.get("security") or {}
    enc, pol = sec.get("encryption") or {}, sec.get("policies") or {}
    vaults = d.get("vaults") or []
    copies = d.get("copies") or {}
    x = copies.get("exposure") or {}
    todo: List[Tuple[int, str, str]] = []
    good: List[str] = []
    bad_keys = sum(k.get("recovery_points", 0) for k in enc.get("unusable_keys") or [])
    if bad_keys:
        todo.append((bad_keys, f"{'recovery point sits' if bad_keys == 1 else 'recovery points sit'} under a key that is disabled or "
                               f"pending deletion, so {'it' if bad_keys == 1 else 'they'} cannot be restored until the key is usable again",
                     "vault-security.csv"))
    standard = [v for v in vaults if not v.get("is_air_gapped")]
    unlocked = [v for v in standard if not v.get("is_locked")]
    if unlocked:
        todo.append((len(unlocked), f"of {len(standard):,} standard vaults (air-gapped ones left out) {_has(len(unlocked))} no Vault Lock, so anyone with backup permissions in the "
                                    f"account can delete their copies early", "vault-security.csv"))
    elif standard:
        good.append(f"Vault Lock on all {len(standard):,} vaults")
    cover = sec.get("scp")
    if d.get("scps_assessed", True) and cover:
        none = len(cover.get("accounts_with_none") or [])
        if none:
            todo.append((none, f"of {cover['accounts']:,} accounts {_has(none)} no service control policy that stops backups being deleted",
                               "report: Backup copy protection, guardrails"))
        elif cover.get("accounts"):
            good.append(f"a service control policy guards backups in all {cover['accounts']:,} accounts")
    public = len(x.get("public_ebs_snapshots") or []) + len(x.get("public_images") or []) + len(x.get("rds_public") or [])
    if public:
        todo.append((public, ("snapshot or image" if public == 1 else "snapshots or images") + " can be restored by any AWS account",
                     "shared-backups.csv"))
    if pol.get("external"):
        n_ext = len(pol["external"])
        todo.append((n_ext, ("vault policy lets" if n_ext == 1 else "vault policies let") + " principals from outside the accounts "
                            "assessed in", "vault-security.csv"))
    if copies.get("deletion_exposed"):
        n_del = copies["deletion_exposed"]
        todo.append((n_del, ("database or table has" if n_del == 1 else "databases and tables have") + " deletion protection off and no "
                            "copy identified that would outlive " + ("it" if n_del == 1 else "them") + ": nothing prevents the delete "
                            "and no identified copy would remain after it", "assets.csv (deletion_exposed)"))
    mg = compute_malware_gap(d)
    if mg["known"] and mg["plans"] and mg["with_scan"] < mg["plans"]:
        todo.append((mg["plans"] - mg["with_scan"], f"of {mg['plans']:,} backup plans {_has(mg['plans'] - mg['with_scan'])} no malware scan, so a restore after "
                                                    f"ransomware may start from an infected copy", "report: Backup copy protection, malware scanning"))
    if enc.get("recovery_points") and not enc.get("unencrypted_recovery_points"):
        good.append(f"all {enc['recovery_points']:,} recovery points encrypted")
    ag = sum(1 for r in d.get("resources") or [] if r.get("is_air_gapped"))
    if ag:
        good.append(f"{_n(ag, 'resource')} with copies in a logically air-gapped vault")
    if pol.get("deny_delete"):
        good.append(f"{pol['deny_delete']:,} vault {'policy denies' if pol['deny_delete'] == 1 else 'policies deny'} deleting recovery points")
    return {"todo": todo, "good": good}


def copy_protection_actions_html(acts: Dict[str, List]) -> str:
    if not acts["todo"] and not acts["good"]:
        return ""
    out = []
    if acts["todo"]:
        out.append('<h4 class="kicker">Worth a look</h4><ol class="review">')
        for n, what, where in acts["todo"]:
            out.append(f'<li><div class="review-n">{n:,}</div><div>{_esc(what)}.<p class="meta"><span class="mono">{_esc(where)}</span></p>'
                       f'</div></li>')
        out.append('</ol>')
    else:
        out.append('<p>Nothing in what was read stands out here.</p>')
    if acts["good"]:
        out.append(f'<p class="ov-good-line"><b>Working well:</b> {_esc("; ".join(acts["good"]))}.</p>')
    out.append('<p class="meta-line">Each may be intended; the owner decides. The detail behind every line is in the folds below.</p>')
    return "".join(out)


def security_section_html(sec: Dict[str, Any], scps_assessed: bool = True, malware: str = "", actions: str = "") -> List[str]:
    """Facts about how copies are protected from the credentials that made them.  No grade."""
    if not sec or not sec["vaults"] and not sec["backup_accounts"] and not sec["residency"]["moves"] \
            and not (sec.get("governance") or {}).get("frameworks") and sec.get("org_backup_policies") is None:
        return []
    e = _esc
    out: List[str] = []
    w = out.append
    enc, pol, scan, res = sec["encryption"], sec["policies"], sec["scan"], sec["residency"]
    w('<section><div class="sec-head"><span class="sec-num">Security</span>'
      '<h2>How the copies are protected from the credentials that made them</h2></div>')
    w('<p>A copy is only as safe as who can delete it, or the key that encrypts it. First what someone can act on, then the '
      'detail. Vault-level detail is in <span class="mono">vault-security.csv</span>.</p>')
    if actions:
        w(actions)
    detail_from = len(out)

    w('<h3>Encryption and keys</h3>')
    if sec["vaults"]:
        w('<table><thead><tr><th>Vault encryption</th><th class="num">Vaults</th></tr></thead><tbody>')
        for kind, label in _KEY_KIND_LABELS.items():
            if enc["kinds"].get(kind):
                w(f'<tr><td>{e(label)}</td><td class="num">{enc["kinds"][kind]:,}</td></tr>')
        w('</tbody></table>')
    if enc["unusable_keys"]:
        total = sum(k["recovery_points"] for k in enc["unusable_keys"])
        w(f'<div class="callout warn"><h4>Keys that cannot currently decrypt</h4><p>{total:,} recovery point(s), in '
          f'{_n(len(enc["unusable_keys"]), "vault and key pair", "vault and key pairs")}, sit under a key that is disabled or '
          f'pending deletion, and cannot be restored while it stays that way. The state and vault of each are in <span class="mono">vault-security.csv</span>.</p></div>')
    elif sec["vaults"]:
        w('<p>No vault key was found disabled or pending deletion.</p>' if not enc["keys_unknown"] else '')
    if enc["keys_unknown"]:
        w(f'<p><em>Not assessed:</em> the state of {enc["keys_unknown"]:,} key(s) could not be read (for example a key in another '
          f'account whose policy does not allow it), so nothing is said about them.</p>')
    if enc["recovery_points"]:
        rp = (f'{enc["unencrypted_recovery_points"]:,} of {enc["recovery_points"]:,} recovery points are not encrypted.'
              if enc["unencrypted_recovery_points"] else f'All {enc["recovery_points"]:,} recovery points are encrypted.')
        w(f'<p>{rp} {enc["unencrypted_snapshots"]:,} EBS and RDS snapshots found in the accounts assessed are not encrypted.</p>')

    w('<h3>Vault access policies</h3>')
    if sec["vaults"]:
        w(f'<p>Vaults with an access policy: {pol["readable"]:,} of {sec["vaults"]:,} ({pol["none"]:,} with none'
          + (f', {pol["unreadable"]:,} could not be read' if pol["unreadable"] else '')
          + f'). Policies that deny deleting recovery points: {pol["deny_delete"]:,}; that also deny changing a recovery point\'s '
            f'lifecycle and the vault policy itself: {pol["deny_all_three"]:,}.</p>')
        if pol["external"]:
            w('<div class="callout warn"><h4>Policies that allow principals from other accounts</h4><ul>')
            for item in pol["external"][:10]:
                who = ("any principal with no organization condition" if item["any_principal"] else "") + \
                      (", " if item["any_principal"] and item["accounts"] else "") + \
                      (f'{len(item["accounts"])} account(s) not among those assessed' if item["accounts"] else "")
                w(f'<li><span class="mono">{e(item["vault"])}</span> in {e(item["account_id"])}: {e(who)}</li>')
            w('</ul><p>Sharing a vault is sometimes intended, for example with a backup account. The accounts are in '
              '<span class="mono">vault-security.csv</span>.</p></div>')
        if pol["unreadable"]:
            w('<p><em>Not assessed:</em> some vault policies could not be read (see Coverage gaps).</p>')

    w('<h3>Guardrails: service control policies</h3>')
    cover = sec["scp"]
    if not scps_assessed or cover is None:
        w('<p><em>Not assessed:</em> the organization\'s service control policies were not read (this run did not read the '
          'organization, or a call needed to list them was denied or failed), so nothing is said about them.</p>')
    else:
        w(f'<p>For each action that would delete or weaken backups, the number of accounts where a service control policy denies '
          f'it. A policy applies to an account when it is attached to the account, an organizational unit above it, or the root. '
          f'It never applies to the management account, which is left out of the {cover["accounts"]:,} accounts counted.</p>')
        w('<table><thead><tr><th>Action</th><th class="num">Accounts where denied</th></tr></thead><tbody>')
        for action, n in cover["per_action"].items():
            w(f'<tr><td class="mono">{e(action)}</td><td class="num">{n:,} of {cover["accounts"]:,}</td></tr>')
        w('</tbody></table>')
        if cover["unattached"]:
            w(f'<p>{len(cover["unattached"]):,} policy(ies) that deny these actions are attached to nothing, so they apply to no account yet: '
              f'{e(", ".join(cover["unattached"][:5]))}.</p>')
        if any(x["conditional"] for x in cover["scps"]):
            w('<p>Some denials carry a condition (for example an exemption for a named role). The condition is not evaluated here.</p>')
        if cover["accounts_with_none"]:
            w(f'<p>{len(cover["accounts_with_none"]):,} account(s) have none of these actions denied.</p>')

    w('<h3>Accounts that hold copies for others</h3>')
    if sec["backup_accounts"]:
        w('<table><thead><tr><th>Account receiving copies</th><th>Organizational unit</th><th class="num">Resources of its own</th>'
          '<th>Assessed in this run</th></tr></thead><tbody>')
        for acct in sec["backup_accounts"]:
            label = acct["name"] or acct["account_id"]
            w(f'<tr><td>{e(label)}</td><td>{e(acct["ou"] or "not known")}</td>'
              f'<td class="num">{acct["resources"]:,}</td><td>{"yes" if acct["assessed"] else "no"}</td></tr>')
        w('</tbody></table>')
    elif not sec.get("plans_readable", True):
        w('<p><em>Not assessed:</em> backup plans could not be fully read (see Coverage gaps), so nothing is said about whether any '
          'copies recovery points to another account.</p>')
    else:
        w('<p>No backup plan copies recovery points to another account.</p>')

    w('<h3>Malware scanning</h3>')
    w(f'<p>{scan["plans_with_scan"]:,} of {scan["plans"]:,} backup plans have a malware-scan action configured. '
      f'{scan["scanned"]:,} of {scan["recovery_points"]:,} recovery points carry a scan result'
      + (f', {scan["malware"]:,} with malware reported and {scan["failed"]:,} whose scan failed' if scan["scanned"] else '')
      + '. The recoverable figures in this report assume the newest recovery point is clean unless a scan result says otherwise; '
        'this review reads scan results only where AWS Backup records them.</p>')
    if malware:
        w(malware.replace(' <a href="#sec-security">Backup copy protection</a>', ''))

    gov = sec.get("governance") or {"frameworks": [], "report_plans": 0, "known": True}
    w('<h3>Existing governance tooling</h3>')
    ob = sec.get("org_backup_policies")
    if ob is not None:
        if not ob["known"]:
            w('<p><em>Not assessed:</em> the organization\'s backup policies could not be read (see Coverage gaps).</p>')
        elif not ob["enabled"] or not ob["policies"]:
            w('<p>The organization has no backup policy. Coverage therefore depends on backup plans created in each account.</p>')
        else:
            w(f'<p>The organization has {_n(len(ob["policies"]), "backup policy", "backup policies")}, which '
              f'{"applies" if len(ob["policies"]) == 1 else "apply"} backup plans across accounts:</p>')
            w('<table><thead><tr><th>Policy</th><th>Plans it defines</th><th>Picks resources by</th><th>Attached to</th></tr></thead><tbody>')
            for pol in ob["policies"][:8]:
                targets = ", ".join(f"{n:,} {k.lower().replace('_', ' ')}" for k, n in pol["targets"].items()) or "nothing yet"
                picks = " and ".join(pol["selects_by"]) or ("not read" if not pol["readable"] else "not stated")
                w(f'<tr><td>{e(pol["name"])}</td><td>{e(", ".join(pol["plans"][:4]) or "none")}</td><td>{e(picks)}</td><td>{e(targets)}</td></tr>')
            w('</tbody></table><p>A policy that picks by tag covers a resource only if it carries that tag.</p>')
    if not gov.get("known", True):
        w('<p><em>Not assessed:</em> a call needed to list AWS Backup Audit Manager frameworks and report plans was denied or failed '
          '(see Coverage gaps), so nothing is said about whether it is in use'
          + (f'; {len(gov["frameworks"]):,} framework(s) were found in the Regions that could be read' if gov["frameworks"] else '') + '.</p>')
    elif gov["frameworks"] or gov["report_plans"]:
        w(f'<p>AWS Backup Audit Manager is in use: {len(gov["frameworks"]):,} framework(s) and {gov["report_plans"]:,} report plan(s). '
          f'Its own compliance results are not read here, so this review and Audit Manager can be compared by the people who run both.</p>')
        if gov["frameworks"]:
            w('<table><thead><tr><th>Framework</th><th>Deployment</th><th>Controls it turns on</th></tr></thead><tbody>')
            for fw in gov["frameworks"][:8]:
                w(f'<tr><td>{e(fw["name"])}</td><td>{e(fw["status"] or "not known")}</td>'
                  f'<td class="mono">{e(", ".join(fw["controls"][:6]) or "not read")}{"…" if len(fw["controls"]) > 6 else ""}</td></tr>')
            w('</tbody></table>')
    else:
        w('<p>No AWS Backup Audit Manager framework or report plan was found.</p>')

    w('<h3>Where copies are kept</h3>')
    if res["moves"]:
        w(f'<p>{res["sensitive_resources_with_copy_elsewhere"]:,} resource(s) inferred to hold sensitive data have a copy in a '
          f'different geographic area from the resource. A copy in another area can matter for rules about where data may be '
          f'stored; whether it does depends on the data and the rules that apply, which this review cannot know. Areas are broad '
          f'(by Region prefix), and sensitivity is inferred from tags and names.</p>')
        w('<table><thead><tr><th>Resource area</th><th>Copy area</th><th class="num">Resources</th></tr></thead><tbody>')
        for m in res["moves"][:10]:
            w(f'<tr><td>{e(m["from"] or "not known")}</td><td>{e(m["to"])}</td><td class="num">{m["resources"]:,}</td></tr>')
        w('</tbody></table>')
    else:
        w('<p>No resource inferred to hold sensitive data has a copy in a different geographic area.</p>')
    detail = "".join(out[detail_from:]).replace("<h3>", "<h4>").replace("</h3>", "</h4>")
    del out[detail_from:]
    w(_fold("Detail: keys, vault policies, guardrails, malware scanning and governance", detail))
    w('</section>')
    return out


def regions_appendix_html(rows: List[Dict[str, Any]]) -> List[str]:
    """Which Regions each account had scanned, found empty, or could not reach.  An unreachable Region is a gap, not an empty one."""
    if not rows:
        return []
    e = _esc
    out: List[str] = []
    w = out.append
    w('<h3>Regions</h3><p>For each account, the Regions it has enabled were probed with a few read calls (volumes, databases, tables, '
      'backup plans and vaults, Glue databases, S3 table buckets) and only those holding something were scanned. A Region that could not '
      'be reached is not the same as an empty one: it is listed under Coverage gaps and nothing is said about it.</p>')
    w('<table><thead><tr><th>Account</th><th class="num">Probed</th><th>Scanned</th><th>Found empty</th><th>Could not be reached</th></tr></thead><tbody>')
    for row in rows:
        rep_ = row["report"]
        w(f'<tr><td>{e(row["name"])}</td><td class="num">{len(rep_.get("candidates", [])):,}</td>'
          f'<td class="mono">{e(", ".join(row["scanned"]) or "none")}</td>'
          f'<td class="num">{len(rep_.get("empty", [])):,}</td>'
          f'<td class="mono">{e(", ".join(rep_.get("unreachable", [])) or "none")}</td></tr>')
    w('</tbody></table>')
    return out


def archive_restore_facts(resources: List[Dict]) -> Dict[str, int]:
    """Resources whose only copies sit in an archive or cold tier, where a restore waits before it can start."""
    assessed = [r for r in resources if r.get("protection_state") != "not_assessed"]
    return {"volumes_all_archived": sum(1 for r in assessed if r.get("snapshots_all_archived") and not r.get("has_backup_recovery_point")),
            "all_cold": sum(1 for r in assessed if (r.get("rp_count") or 0) > 0 and (r.get("rp_cold_count") or 0) >= r["rp_count"]),
            "archived_snapshots": sum(r.get("archived_snapshot_count") or 0 for r in assessed),
            "cold_points": sum(r.get("rp_cold_count") or 0 for r in assessed)}


def archive_restore_note(facts: Optional[Dict[str, int]]) -> str:
    """One paragraph on archived and cold copies: how many, and the wait and charge AWS documents for restoring them."""
    f = facts or {}
    if not (f.get("archived_snapshots") or f.get("cold_points")):
        return ""
    held = []
    if f.get("archived_snapshots"):
        held.append(f'{_n(f["archived_snapshots"], "EBS snapshot")} in the archive tier')
    if f.get("cold_points"):
        held.append(f'{_n(f["cold_points"], "AWS Backup recovery point")} in cold storage')
    only = []
    if f.get("volumes_all_archived"):
        only.append(f'{_n(f["volumes_all_archived"], "volume")} whose every snapshot is archived')
    if f.get("all_cold"):
        only.append(f'{_n(f["all_cold"], "resource")} whose every AWS Backup recovery point is cold')
    return ('<p>Copies in an archive tier: ' + " and ".join(held) + '. An archived EBS snapshot is a full copy and has to be '
            'restored to the standard tier before a volume can be made from it, which AWS says can take up to 72 hours and is '
            f'charged at ${_rate(MECHANISM_RATES["ebs_snapshot_archive_restore"])} per GB restored. Archived copies are kept at '
            'least 90 days; deleting one sooner is charged for the rest of the 90.'
            + (' ' + "; ".join(only) + ': for these the wait comes before any restore, and restore times here do '
               'not include it.' if only else '') + '</p>')


def restore_section_html(summary: Dict[str, Any], archive: Optional[Dict[str, int]] = None) -> List[str]:
    """What restores AWS Backup recorded, and what they show.  Facts and labelled estimates, no grade."""
    if not summary or not (summary["jobs"] or summary["plans"] or any(t["resources"] for t in summary["tiers"].values())):
        return []
    e = _esc
    out: List[str] = []
    w = out.append
    days = summary["lookback_days"]
    w('<section><div class="sec-head"><span class="sec-num">Restore</span><h2>What has been restored, and how long it took</h2></div>')
    w('<p>A completed restore shows a copy can be restored; whether the application works afterwards is known only where a '
      f'validation ran. These are the restores AWS Backup recorded in the last {days} days.</p>')
    w(f'<p>{summary["jobs"]:,} restore job(s) in the last {days} days: {summary["succeeded"]:,} succeeded, {summary["failed"]:,} '
      f'did not succeed' + (f', and {summary["in_progress"]:,} are still running' if summary["in_progress"] else '')
      + f'. {summary["test_jobs"]:,} were run by a restore testing plan. {summary["from_copy"]:,} successful restore(s) read a '
        f'recovery point from another account\'s vault or from an air-gapped vault. A restore counts as succeeded only if it '
        f'completed and, where a validation ran, the validation passed.</p>')
    if summary["jobs"]:
        w('<div class="bar-pair">' + _pair_bars(summary["succeeded"], summary["failed"], "Restores succeeded", "Did not succeed") + '</div>')
    detail: List[str] = []
    if summary["failed"]:
        detail.append('<table><thead><tr><th>How restores ended</th><th>Resource kind</th><th class="num">Jobs</th></tr></thead><tbody>')
        for o in summary["outcomes"][:8]:
            how = o["status"] + (f", validation {o['validation'].lower().replace('_', ' ')}" if o["validation"] else "")
            detail.append(f'<tr><td>{e(how)}</td><td>{e(o["type"] or "not known")}</td><td class="num">{o["count"]:,}</td></tr>')
        detail.append('</tbody></table>')
        if summary["reasons"]:
            detail.append('<p>The most common reasons AWS gave, as written by AWS Backup (generated identifiers replaced):</p><ul>')
            for reason in summary["reasons"]:
                detail.append(f'<li><span class="mono">{e(reason["text"])}</span> · {reason["count"]:,}</li>')
            detail.append('</ul>')
    if detail:
        w(_own_fold("How the restores ended, and why some did not", "".join(detail)))
    if not summary["from_copy"] and summary["jobs"]:
        w('<p>No successful restore read a copy held in another account or an air-gapped vault, so restoring after the loss of '
          'the source account has not been shown.</p>')

    tiers: List[str] = []
    w = tiers.append
    w('<table><thead><tr><th>Tier (inferred)</th><th>Target: copy every / restore within</th><th class="num">Resources</th>'
      f'<th class="num">Restored in {days}d</th><th class="num">Within target</th><th class="num">Longer than target</th>'
      '<th class="num">In a restore test</th></tr></thead><tbody>')
    for tier, row in summary["tiers"].items():
        t = RECOVERY_TIERS[tier]
        tested = f'{row["test_selected"]:,}' + (f' ({row["test_unknown"]:,} not assessed)' if row["test_unknown"] else "")
        w(f'<tr><td>Tier {tier}</td><td>{t["rpo_hours"]}h / {t["rto_hours"]}h</td><td class="num">{row["resources"]:,}</td>'
          f'<td class="num">{row["restored"]:,}</td><td class="num">{row["within_rto"]:,}</td>'
          f'<td class="num">{row["over_rto"]:,}</td><td class="num">{tested}</td></tr>')
    w('</tbody></table>')
    w('<p>Tiers and their targets are assumptions (see how this was counted above); a resource whose environment could not be '
      'inferred has no tier and is in no row.</p>')

    estimated = sum(t["estimated"] for t in summary["tiers"].values())
    if estimated:
        kinds = ", ".join(f"{k} ({n})" for k, n in summary["observed_kinds"].items())
        w(f'<p><em>Estimate.</em> For {estimated:,} resource(s) that have never been restored, the longest restore this estate has '
          f'completed for the same kind of resource, scaled by size, is in <span class="mono">assets.csv</span> '
          f'(<span class="mono">restore_estimate_minutes</span>). It is not a measurement. Kinds restored so far: {e(kinds)}.</p>')
    elif summary["jobs"] and not summary["observed_kinds"]:
        w('<p>No successful restore has timing recorded, so no restore time is estimated.</p>')
    note = archive_restore_note(archive)
    if note:
        w(note)
    w = out.append
    w(_own_fold("Restores by tier, against the recovery targets", "".join(tiers)))

    w(f'<h3>Restore testing plans</h3><p>{summary["plans"]:,} restore testing plan(s) exist'
      + (f'; the detail of {summary["plans_unreadable"]:,} could not be read, so what they cover is <em>not assessed</em>' if summary["plans_unreadable"] else '')
      + '.')
    if summary["plans_from_air_gapped_vault"]:
        w(f' {len(summary["plans_from_air_gapped_vault"]):,} restore from an air-gapped vault.')
    elif summary["plans"]:
        w(' None restores from an air-gapped vault.')
    w('</p></section>')
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Report layout: section order, numbering, contents and drilldown
# ─────────────────────────────────────────────────────────────────────────────
# Each section function writes a complete <section>.  The order they are written in is the order the code runs, not the
# order a reader needs, so the report is arranged afterwards: sections are put in reading order, numbered, listed in a
# contents block, and the detail behind each one is folded into <details> blocks.  Nothing is removed: a folded block
# holds exactly the HTML the section wrote, and a note that a result is "not assessed" or highlighted is flagged on the
# fold itself, so a collapsed block never hides it.

# Reading order and grouping, by the label each section writes in its heading.  A label not listed is kept, in "More".
_SECTION_GROUPS: List[Tuple[str, List[str]]] = [
    ("Start here", ["Start", "06", "Questions"]),
    ("1 · Visibility", ["Assets", "Headline", "01", "03", "Owners"]),
    ("2 · Risk", ["Under", "Security", "Sharing", "05", "Jobs", "Restore", "Targets"]),
    ("3 · Waste", ["02", "Copies"]),
    ("About this review", ["Inputs", "Purpose", "04", "Gaps", "Change", "A"]),
]
# Short sections that read better as parts of a related one: each child is shown inside its parent's panel, under its own heading
# and with its own anchor, so every link to it still lands on it.  A child whose parent is missing from a run stands on its own.
_SECTION_MERGE: Dict[str, List[str]] = {"Start": ["06"], "Headline": ["01"], "Owners": ["03"], "Security": ["Sharing", "05"],
                                        "Jobs": ["Restore", "Targets"], "02": ["Copies"], "Purpose": ["Inputs", "A"]}
# The heading a parent panel takes once its children are inside it.
_MERGED_TITLE = {"Headline": "Recovery copies", "Owners": "Owners and applications",
                 "Security": "Backup copy protection", "Jobs": "Backups, restores and recovery targets",
                 "Purpose": "How this review works"}
_SECTION_IDS = {"Start": "overview", "Purpose": "purpose", "06": "summary", "Headline": "coverage", "Change": "change", "01": "exposure",
                "02": "protection", "Copies": "copies", "Sharing": "sharing", "03": "applications", "Owners": "owners", "Questions": "questions",
                "04": "mechanisms", "05": "hardening", "Security": "security", "Jobs": "jobs", "Restore": "restore",
                "Gaps": "gaps", "A": "appendix", "Assets": "assets", "Targets": "targets", "Inputs": "inputs", "Under": "under"}
# What the sidebar calls each section (the full title stays on the panel and in the item's tooltip).
_SECTION_SHORT = {"overview": "Executive Summary", "under": "By recovery scenario", "purpose": "How this review works", "summary": "Summary", "coverage": "Recovery copies",
                  "change": "Since the last review", "assets": "Assets by criticality", "targets": "Recovery targets", "inputs": "Inputs and assumptions", "exposure": "Exposure by account", "protection": "Spend",
                  "copies": "Copies with no source", "sharing": "Sharing and deletion", "applications": "Applications", "owners": "Owners and applications",
                  "questions": "Items to review", "mechanisms": "What each mechanism covers", "hardening": "Hardening path",
                  "security": "Backup copy protection", "jobs": "Backups and restores", "restore": "Restores", "gaps": "Coverage gaps",
                  "appendix": "Appendix"}
# Sections that carry a name instead of a number.
_UNNUMBERED = {"Start": "Start", "Purpose": "Purpose", "06": "Summary", "Inputs": "Inputs", "Gaps": "Gaps", "A": "Appendix"}
_NO_DRILL = {"Assets", "06", "Start", "Security"}          # sections that already hold their own drilldown
_DRILL_MIN_CHARS = 2500      # a section shorter than this is left open
_DRILL_MIN_TAIL = 900        # detail shorter than this is not worth folding
_DRILL_MIN_SUB = 700         # a sub-heading block shorter than this stays open
_VOID_TAGS = frozenset({"br", "hr", "img", "input", "meta", "link", "wbr"})
_TAG_RE = re.compile(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)\b[^>]*?(/?)>")
_SECTION_RE = re.compile(r"<section>(.*?)</section>", re.S)
_HEAD_RE = re.compile(r'<span class="sec-num">(.*?)</span><h2>(.*?)</h2>', re.S)
_REPORT_SCRIPT = (
    "(function(){var shell=document.getElementById('report-shell');if(!shell){return;}"
    "var tabs=[].slice.call(shell.querySelectorAll('[role=tab]'));var panels={};"
    "[].forEach.call(shell.querySelectorAll('.panel'),function(p){panels[p.id]=p;});"
    "var sel=document.getElementById('tab-select');"
    "function show(id,focus,keep){if(!panels[id]){return;}shell.classList.add('tabs');"
    "tabs.forEach(function(t){var on=t.getAttribute('aria-controls')===id;t.setAttribute('aria-selected',on?'true':'false');"
    "t.tabIndex=on?0:-1;if(on&&focus){t.focus();}});"
    "for(var k in panels){panels[k].classList.toggle('active',k===id);}"
    "if(sel){sel.value=id;}"
    "if(keep&&window.history&&history.replaceState){try{history.replaceState(null,'','#'+id);}catch(x){}}"
    "var top=shell.getBoundingClientRect().top+window.pageYOffset-8;if(window.pageYOffset>top){window.scrollTo(0,top);}}"
    "tabs.forEach(function(t,i){"
    "t.addEventListener('click',function(e){e.preventDefault();show(t.getAttribute('aria-controls'),false,true);});"
    "t.addEventListener('keydown',function(e){var n=null;"
    "if(e.key==='ArrowDown'||e.key==='ArrowRight'){n=tabs[(i+1)%tabs.length];}"
    "else if(e.key==='ArrowUp'||e.key==='ArrowLeft'){n=tabs[(i-1+tabs.length)%tabs.length];}"
    "else if(e.key==='Home'){n=tabs[0];}else if(e.key==='End'){n=tabs[tabs.length-1];}"
    "if(n){e.preventDefault();show(n.getAttribute('aria-controls'),true,true);}});});"
    "if(sel){sel.addEventListener('change',function(){show(sel.value,false,true);});}"
    "function fromHash(){var id=(location.hash||'').slice(1);if(panels[id]){show(id,false,false);return true;}"
    "var el=id?document.getElementById(id):null;var p=el&&el.closest?el.closest('.panel'):null;"
    "if(p){show(p.id,false,false);el.scrollIntoView();return true;}return false;}"
    "window.addEventListener('hashchange',fromHash);"
    # A link inside the report is handled here, not left to the address bar: a viewer that shows the file inside another page (an
    # email or document preview) does not report a changed address, so the link would do nothing there.
    "function go(id){var el=id?document.getElementById(id):null;if(!el){return false;}"
    "if(panels[id]){show(id,false,true);return true;}"
    "var p=el.closest?el.closest('.panel'):null;if(p){show(p.id,false,true);el.scrollIntoView();return true;}return false;}"
    "document.addEventListener('click',function(e){var a=e.target&&e.target.closest?e.target.closest('a[href^=\"#\"]'):null;"
    "if(!a||a.getAttribute('role')==='tab'){return;}if(go(a.getAttribute('href').slice(1))){e.preventDefault();}});"
    "if(!fromHash()){show(tabs[0].getAttribute('aria-controls'),false,false);}"
    "var all=document.getElementById('show-all');"
    "if(all){all.hidden=false;all.addEventListener('click',function(){var on=!shell.classList.contains('showall');"
    "shell.classList.toggle('showall',on);all.textContent=on?'Show one section at a time':'Show all sections on one page';});}"
    "var d=document.querySelectorAll('details.drill');"
    "function set(o){for(var i=0;i<d.length;i++){d[i].open=o;}}"
    "var b=document.getElementById('toggle-all');"
    "if(b){b.hidden=false;b.addEventListener('click',function(){var o=b.getAttribute('data-open')!=='1';set(o);"
    "b.setAttribute('data-open',o?'1':'0');b.textContent=o?'Collapse all detail':'Expand all detail';});}"
    "var af=document.getElementById('asset-filter');"
    "if(af){af.hidden=false;var mode='all';var find=document.getElementById('asset-find');"
    "var apply=function(){var q=((find&&find.value)||'').toLowerCase();"
    "[].forEach.call(document.querySelectorAll('#sec-assets tr[data-p]'),function(r){"
    "var ok=(mode==='all'||(mode==='unclear'?r.getAttribute('data-env')==='unclear':r.getAttribute('data-p')===mode))&&(!q||(r.getAttribute('data-q')||'').indexOf(q)>-1);r.hidden=!ok;});"
    "if(mode!=='all'||q){[].forEach.call(document.querySelectorAll('#sec-assets details.asset-account'),function(a){a.open=true;});}};"
    "var btns=[].slice.call(af.querySelectorAll('button'));"
    "btns.forEach(function(b){b.addEventListener('click',function(){mode=b.getAttribute('data-filter');"
    "btns.forEach(function(x){x.setAttribute('aria-pressed',x===b?'true':'false');});apply();});});"
    "if(find){find.addEventListener('input',apply);}"
    "[].forEach.call(document.querySelectorAll('a[data-show]'),function(a){a.addEventListener('click',function(){"
    "var t=af.querySelector('button[data-filter=\"'+a.getAttribute('data-show')+'\"]');if(t){t.click();}});});}"
    "var qbox=document.getElementById('report-search');var rbox=document.getElementById('search-results');"
    "if(qbox&&rbox){document.getElementById('side-search').hidden=false;var cache=null;"
    "var index=function(){if(!cache){cache=[];[].forEach.call(shell.querySelectorAll('.panel'),function(p){"
    "var t=document.getElementById('tab-'+p.id.slice(4));cache.push({id:p.id,name:t?t.textContent.replace(/^\\d+/,''):p.id,text:p.textContent.toLowerCase()});});}return cache;};"
    "var jump=function(id,term){show(id,false,true);var p=panels[id];var w=document.createTreeWalker(p,NodeFilter.SHOW_TEXT,null);var n;"
    "while((n=w.nextNode())){if(n.nodeValue.toLowerCase().indexOf(term)>-1&&n.parentElement){var el=n.parentElement;"
    "for(var d=el.closest('details');d;d=d.parentElement?d.parentElement.closest('details'):null){d.open=true;}"
    "if(el.closest('tr')&&el.closest('tr').hidden){el.closest('tr').hidden=false;}"
    "el.scrollIntoView({block:'center'});el.classList.add('hit');setTimeout(function(){el.classList.remove('hit');},3000);break;}}};"
    "var run=function(){var term=qbox.value.trim().toLowerCase();rbox.textContent='';if(term.length<2){return;}var any=false;"
    "index().forEach(function(e){var c=0,at=e.text.indexOf(term);while(at>-1&&c<99){c++;at=e.text.indexOf(term,at+term.length);}"
    "if(c){any=true;var b=document.createElement('button');b.type='button';var a=document.createElement('span');a.textContent=e.name;"
    "var k=document.createElement('span');k.className='count';k.textContent=c>=99?'99+':String(c);b.appendChild(a);b.appendChild(k);"
    "b.addEventListener('click',function(){jump(e.id,term);});rbox.appendChild(b);}});"
    "if(!any){var m=document.createElement('p');m.className='none';m.textContent='No match in any section.';rbox.appendChild(m);}};"
    "qbox.addEventListener('input',run);"
    "qbox.addEventListener('keydown',function(ev){if(ev.key==='Enter'){var f=rbox.querySelector('button');if(f){ev.preventDefault();f.click();}}"
    "else if(ev.key==='Escape'){qbox.value='';rbox.textContent='';}});}"
    "var op=document.getElementById('print-onepage');"
    "if(op){op.hidden=false;op.addEventListener('click',function(){document.body.classList.add('print-onepage');window.print();});}"
    "window.addEventListener('afterprint',function(){document.body.classList.remove('print-onepage');});"
    "window.addEventListener('beforeprint',function(){if(!document.body.classList.contains('print-onepage')){set(true);}});})();"
)


def _top_level_chunks(markup: str) -> Optional[List[str]]:
    """Split markup into its top-level elements.  Whitespace stays with the element after it, so joining the chunks
    gives back the input exactly.  Returns None if the tags do not balance, in which case the caller leaves it alone."""
    chunks: List[str] = []
    depth, pos = 0, 0
    for m in _TAG_RE.finditer(markup):
        closing, tag, selfclosed = m.group(1), m.group(2).lower(), m.group(3)
        if tag in _VOID_TAGS or selfclosed:
            if depth == 0:
                chunks.append(markup[pos:m.end()])
                pos = m.end()
            continue
        if not closing:
            depth += 1
        else:
            depth -= 1
            if depth < 0:
                return None
            if depth == 0:
                chunks.append(markup[pos:m.end()])
                pos = m.end()
    if depth != 0:
        return None
    if markup[pos:]:
        chunks.append(markup[pos:])
    return chunks if "".join(chunks) == markup else None


def _fold(summary_html: str, inner: str) -> str:
    """One <details> block.  The summary says when the folded detail holds a note that must not be missed."""
    flags = ""
    if "Not assessed" in inner or "not assessed" in inner:
        flags += " " + _pill("includes not assessed", "warn")
    if re.search(r'class="callout (?:warn|flag)"', inner):
        flags += " " + _pill("includes a highlighted note", "warn")
    return f'<details class="drill"><summary>{summary_html}{flags}</summary><div class="drill-body">{inner}</div></details>'


def _own_fold(title: str, inner: str) -> str:
    """A fold a section writes itself: one click deep, kept beside the section's lead instead of inside "More detail"."""
    return f'<details class="drill own-fold"><summary>{_esc(title)}</summary><div class="drill-body">{inner}</div></details>'


def _kind(chunk: str) -> str:
    m = re.match(r"\s*<([a-zA-Z0-9]+)", chunk)
    return m.group(1).lower() if m else ""


def _drill_section(body: str) -> str:
    """Fold the detail of one section (everything after its heading) into <details> blocks.  The lead stays open: the
    heading's introduction and the first table.  Sub-headings (<h3>) each become a fold with the sub-heading as its title."""
    if len(body) < _DRILL_MIN_CHARS:
        return body
    chunks = _top_level_chunks(body)
    if not chunks:
        return body
    h3 = [i for i, c in enumerate(chunks) if _kind(c) == "h3"]
    if h3:
        out = list(chunks[:h3[0]])
        bounds = h3 + [len(chunks)]
        for a, b in zip(bounds, bounds[1:]):
            title = re.sub(r"^\s*<h3[^>]*>|</h3>\s*$", "", chunks[a])
            inner = "".join(chunks[a + 1:b])
            # A sub-heading marked "keep" stays open: its items are folds of their own (Items to review).
            if len(inner) < _DRILL_MIN_SUB or 'class="keep"' in chunks[a]:
                out.append("".join(chunks[a:b]))
            else:
                out.append(_fold(title, inner))
        return "\n".join(out)
    table = next((i for i, c in enumerate(chunks) if _kind(c) == "table"), None)
    lead_end = table + 1 if table is not None else 2
    tail = chunks[lead_end:]
    if not tail or len("".join(tail)) < _DRILL_MIN_TAIL:
        return body
    # A highlighted note or a "not assessed" line stays visible: it qualifies what the lead says.
    # The account folds are already one click deep, so they stay beside the table instead of inside "More detail".
    keep = [c for c in tail if re.match(r'\s*<div class="callout (?:warn|flag)"', c) or c.lstrip().startswith("<p><em>Not assessed")
            or c.lstrip().startswith('<details class="drill own-fold"')]
    fold = [c for c in tail if c not in keep]
    if not fold or len("".join(fold)) < _DRILL_MIN_TAIL:
        return body
    title = "Read more" if table is None and lead_end == 2 and _kind(chunks[0]) == "p" and "lede" in chunks[0] else "More detail"
    return "\n".join(chunks[:lead_end] + keep + [_fold(title, "".join(fold))])


def _arrange_report_body(body: str) -> str:
    """Put the sections in reading order, number them, group them in a sidebar, show one panel at a time (all of them
    without JavaScript and when printing), and fold the detail inside each.  If anything is unexpected the sections are
    returned as written, so a layout problem cannot lose content."""
    blocks = [m.group(1) for m in _SECTION_RE.finditer(body)]
    leftover = _SECTION_RE.sub("", body).strip()
    parsed = []
    for inner in blocks:
        h = _HEAD_RE.search(inner)
        if not h:
            return body
        parsed.append((h.group(1), h.group(2), inner))
    by_label = {}
    for item in parsed:
        by_label.setdefault(item[0], item)
    children = {c: parent for parent, kids in _SECTION_MERGE.items() if parent in by_label for c in kids if c in by_label}
    placed, groups = set(), []
    for name, labels in _SECTION_GROUPS:
        members = [by_label[label] for label in labels if label in by_label and label not in children]
        placed.update(label for label in labels if label in by_label)
        groups.append((name, members))
    extras = [item for item in parsed if item[0] not in placed or by_label[item[0]] is not item]
    if extras:                                                       # sections the layout does not know stay, before "About"
        groups.insert(len(groups) - 1, ("More", extras))
    panels, side, options, n = [], [], [], 0
    for name, members in groups:
        if not members:
            continue
        side.append(f'<div class="side-group">{_esc(name)}</div>')
        options.append(f'<optgroup label="{_esc(name)}">')
        for label, title, inner in members:
            if label in _UNNUMBERED:
                shown = _UNNUMBERED[label]
            else:
                n += 1
                shown = str(n)
            key = _SECTION_IDS.get(label, re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-") or "x")
            sid = "sec-" + key
            short = _SECTION_SHORT.get(key) or title
            head_end = inner.index("</h2></div>") + len("</h2></div>")
            head = inner[:head_end].replace(f'<span class="sec-num">{label}</span>', f'<span class="sec-num">{_esc(shown)}</span>', 1)
            parts = [c for c in _SECTION_MERGE.get(label, []) if children.get(c) == label]
            if parts and label in _MERGED_TITLE:
                head = head.replace(f"<h2>{title}</h2>", f"<h2>{_esc(_MERGED_TITLE[label])}</h2>", 1)
                title = _MERGED_TITLE[label]
            own = inner[head_end:] if label in _NO_DRILL else _drill_section(inner[head_end:])
            if parts:                                                    # the parent's own text gets its original heading back
                own = f'<h2 class="part-h">{by_label[label][1]}</h2>' + own if label in _MERGED_TITLE else own
            for child in parts:
                c_label, c_title, c_inner = by_label[child]
                c_key = _SECTION_IDS.get(child, re.sub(r"[^a-z0-9]+", "-", child.lower()).strip("-") or "x")
                c_end = c_inner.index("</h2></div>") + len("</h2></div>")
                own += (f'<section id="sec-{c_key}" class="part"><h2 class="part-h">{c_title}</h2>'
                        f'{_drill_section(c_inner[c_end:])}</section>')
            panels.append(f'<section id="{sid}" class="panel" role="tabpanel" aria-labelledby="tab-{key}" tabindex="-1">'
                          f'{head}{own}</section>')
            num = f'<span class="n">{_esc(shown) if shown.isdigit() else ""}</span>'
            side.append(f'<a role="tab" id="tab-{key}" href="#{sid}" aria-controls="{sid}" aria-selected="false" '
                        f'title="{html.escape(re.sub("<[^>]+>", "", title), quote=True)}">{num}<span>{_esc(short)}</span></a>')
            options.append(f'<option value="{sid}">{(shown + ". ") if shown.isdigit() else ""}{_esc(short)}</option>')
        options.append("</optgroup>")
    side_html = (
        '<nav class="side" aria-label="Report sections">'
        '<div class="side-search" id="side-search" hidden><input type="search" id="report-search" placeholder="Search this report" '
        'aria-label="Search every section of this report" autocomplete="off"><div id="search-results" aria-live="polite"></div></div>'
        '<select id="tab-select" aria-label="Go to section">' + "".join(options) + '</select>'
        '<div class="tablist" role="tablist" aria-orientation="vertical">' + "".join(side) + '</div>'
        '<div class="side-tools">'
        '<button type="button" id="toggle-all" data-open="0" hidden>Expand all detail</button>'
        '<button type="button" id="show-all" hidden>Show all sections on one page</button>'
        '<p class="side-note">Each section opens with what matters most. The rows and reasons behind it are in the blocks '
        'marked +. Every resource is in the companion CSV files.</p></div></nav>')
    return ('<div class="shell" id="report-shell">' + side_html + '<div class="panels">' + "\n".join(panels) + "</div></div>"
            + (leftover if leftover else ""))


def _scp_sentence(scps, scps_assessed: bool = True) -> str:
    """What the report can say about service control policies.  A run that did not read them says so: "none found" would be
    a claim about something nobody looked at."""
    if not scps_assessed:
        return "Service control policies were not read in this run."
    if not scps:
        return "No service control policy was found that denies backup lifecycle actions."
    return "At least one service control policy denies backup lifecycle actions; the Security section shows where each applies."


def _summary_row_credential_compromise(cc: Dict, air_gapped: int, assessed: int, scps, scps_assessed: bool = True,
                                       resources: Optional[List[Dict]] = None) -> Tuple[str, str, str]:
    """Summary row for stolen credentials or a lost account.  The total is the failure-scenario count (a copy the source account's
    credentials cannot delete), but each kind of copy is named on its own: an air-gapped vault, a copy in another account and a
    finalized compliance lock are different controls, and how well each is set up is not tested here."""
    area = "Stolen credentials or a lost account"
    total = cc.get("total") or assessed
    safe = cc.get("recoverable", 0)
    scp = _scp_sentence(scps, scps_assessed)
    covered, exposed = [], []
    live = [r for r in resources or [] if r.get("protection_state") != "not_assessed"]
    kinds = [(air_gapped, "in a logically air-gapped vault"),
             (sum(1 for r in live if r.get("cross_account_copy") and not r.get("is_air_gapped")),
              "with a copy seen in another account (who administers that account is not assessed)"),
             (sum(1 for r in live if r.get("vault_lock_mode") == "compliance" and not r.get("is_air_gapped")),
              "in a vault with a compliance-mode lock past its cooling-off period")]
    named = [f"{n:,} {what}" for n, what in kinds if n] if resources is not None else []
    if safe:
        covered.append(f"{safe:,} of {total:,} assessed resources {_has(safe)} a copy outside the reach of the account's own credentials"
                       + (f": {'; '.join(named)} (a resource can have more than one)." if named else ".")
                       + " How each is set up is not tested here.")
    if total - safe:
        exposed.append(f"{total - safe:,} {_has(total - safe)} no such copy.")
    configured = sum(1 for r in live if r.get("cross_account_configured"))
    if configured:
        exposed.append(f"{configured:,} {'has' if configured == 1 else 'have'} a copy to another account configured, but no copy was "
                       f"seen there (the account was not assessed, or the copy has not completed), so it is not counted.")
    if not air_gapped:
        exposed.append("None is in an air-gapped vault.")
    (covered if scps_assessed and scps else exposed).append(scp)       # a policy that denies deletion is a control in place
    return (area, " ".join(covered), " ".join(exposed))


# ─────────────────────────────────────────────────────────────────────────────
# Redacted copy of the outputs
# ─────────────────────────────────────────────────────────────────────────────
# --redact replaces the names and IDs a run reads (accounts, resources, vaults, plans, owners, groups, tag values) with stable
# labels in every file the run writes, after the analysis, so the counts and the structure are real and the identifiers are not.
# A label is the same everywhere in one run.  The labels are not written anywhere unless --redact-key asks for a file, which
# then holds the originals and must be kept as carefully as the report was.  The customer name given with --org-name is shown
# as given.  Console output is not redacted.  A redacted run writes no assessment.json (its labels would not match the next
# run's) and no exclusion worksheet (its ARNs could not be used as an overrides file).
_REDACT_KEEP = frozenset({
    "prod", "production", "prd", "live", "dev", "development", "test", "testing", "staging", "stage", "sandbox", "nonprod",
    "non-prod", "critical", "daily", "weekly", "hourly", "monthly", "confidential", "internal", "public", "true", "false", "yes",
    "no", "none", "default", "backup", "data", "current", "stale", "high", "medium", "low", "all", "any", "enabled", "disabled",
    "unknown", "customer", "aws", "rds", "ebs", "s3", "ec2", "kms", "iam", "dynamodb", "aurora", "efs", "sns", "sqs"})
_REDACT_TOKEN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_REDACT_ACCOUNT_ID = re.compile(r"(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])")
_REDACT_UUID = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9A-Za-z])")
_REDACT_RES_ID = re.compile(r"(?<![0-9A-Za-z-])(?:vol|snap|i|ami|sg|subnet|vpc|eni|fs|fsx|rtb|igw|nat)-[0-9a-f]{8,17}(?![0-9A-Za-z])")
_REDACT_PLAIN = re.compile(r"[A-Za-z_]+")           # a key like "security" or "by_account": structure, unless the whole dict is names
_REDACT_SHORT = {"AWS::RDS::DBInstance": "rds", "AWS::RDS::AuroraCluster": "aurora", "AWS::RDS::NeptuneCluster": "neptune",
                 "AWS::RDS::DocDBCluster": "docdb", "AWS::RDS::DBCluster": "rds-cluster", "AWS::DynamoDB::Table": "table",
                 "AWS::EC2::Volume": "volume", "AWS::S3::Bucket": "bucket", "AWS::S3Tables::Table": "s3table",
                 "AWS::S3::IcebergTable": "iceberg"}


class Redactor:
    """Replaces the identifiers it was told about, and any account ID, key ID or resource ID it meets, with stable labels."""

    def __init__(self) -> None:
        self._wanted: Dict[str, str] = {}          # identifier -> kind, until finish() numbers them
        self.map: Dict[str, str] = {}
        self._counts: Dict[str, int] = {}
        self._phrases: Optional["re.Pattern"] = None
        self._outputs: set = set()

    def add(self, kind: str, value: Any) -> None:
        if not isinstance(value, str):
            return
        value = value.strip()
        if len(value) < 3 or value.lower() in _REDACT_KEEP:
            return
        self._wanted.setdefault(value, kind)

    def _label(self, kind: str) -> str:
        n = self._counts[kind] = self._counts.get(kind, 0) + 1
        return f"{n:012d}" if kind == "acctid" else f"{kind}-{n:03d}"

    def finish(self) -> None:
        phrases = []
        for value in sorted(self._wanted):
            label = self._label(self._wanted[value])
            self.map[value] = label
            self._outputs.add(label)
            if not _REDACT_TOKEN.fullmatch(value):
                phrases.append(value)
        if phrases:
            self._phrases = re.compile("|".join(re.escape(p) for p in sorted(phrases, key=len, reverse=True)))

    def _auto(self, kind: str, value: str) -> str:
        if value in self._outputs:
            return value
        if value not in self.map:
            self.map[value] = self._label(kind)
            self._outputs.add(self.map[value])
        return self.map[value]

    def text(self, s: str) -> str:
        if not s:
            return s
        if s in self.map:
            return self.map[s]
        out = s
        if self._phrases:
            out = self._phrases.sub(lambda m: self.map[m.group(0)], out)
        out = _REDACT_TOKEN.sub(lambda m: self.map.get(m.group(0), m.group(0)), out)
        out = _REDACT_ACCOUNT_ID.sub(lambda m: self._auto("acctid", m.group(0)), out)
        out = _REDACT_UUID.sub(lambda m: self._auto("key", m.group(0)), out)
        out = _REDACT_RES_ID.sub(lambda m: self._auto("id", m.group(0)), out)
        return out

    def walk(self, obj: Any) -> Any:
        """Redact every string, and every string key, in place.  Returns the object, or a new one for a tuple or set."""
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            # A key made of plain words is structure ("security", "owners"), even if a team happens to share the word, unless
            # every key in the dict is a known name (a table keyed by account name).  Keys with digits, dashes, colons or
            # slashes are identifiers and are always redacted.
            names_only = bool(obj) and all(isinstance(k, str) and k in self.map for k in obj)

            def key(k: Any) -> Any:
                if not isinstance(k, str):
                    return k
                if _REDACT_PLAIN.fullmatch(k) and not names_only:
                    return k
                return self.text(k)
            items = [(key(k), self.walk(v)) for k, v in obj.items()]
            obj.clear()
            obj.update(items)
            return obj
        if isinstance(obj, list):
            for i, v in enumerate(obj):
                obj[i] = self.walk(v)
            return obj
        if isinstance(obj, tuple):
            return tuple(self.walk(v) for v in obj)
        if isinstance(obj, (set, frozenset)):
            return type(obj)(self.walk(v) for v in obj)
        return obj


def build_redactor(account_results: List[Dict], data: Dict[str, Any], extras: List[Any]) -> Redactor:
    """Collect the identifiers a run read, from the structures the report and the CSV files are built from."""
    R = Redactor()
    org = data.get("org_info") or {}
    for key in ("Id", "MasterAccountId"):
        R.add("org", org.get(key))
    for ar in account_results:
        R.add("acctid", ar.get("account_id"))
        R.add("account", ar.get("account_name"))
        for part in ar.get("ou_chain") or []:
            R.add("ou", part)
        bs = ar.get("backup_state") or {}
        for v in bs.get("vaults", []):
            R.add("vault", v.get("BackupVaultName"))
            R.add("acctid", v.get("account_id"))
        for p in bs.get("plans", []):
            R.add("plan", p.get("BackupPlanName"))
            R.add("plan", p.get("BackupPlanId"))
            for sel in p.get("Selections", []) or []:
                R.add("plan", sel.get("SelectionName"))
        for pl in bs.get("restore_testing_plans", []):
            R.add("plan", pl.get("RestoreTestingPlanName"))
        for f in bs.get("frameworks", []):
            R.add("item", f.get("name"))
        for rp in bs.get("report_plans", []):
            R.add("item", rp.get("name"))
        for g in ar.get("app_groups", []):
            R.add("app", g.get("name"))
        for t in ar.get("iceberg_tables", []):
            R.add("table", t.get("name"))
            R.add("table", t.get("database"))
    for acct in data.get("accounts") or []:
        R.add("account", acct.get("name"))
        R.add("acctid", acct.get("id"))
    for r in data.get("resources", []):
        kind = _REDACT_SHORT.get(r.get("resourceType", ""), "resource")
        R.add(kind, r.get("resourceName"))
        R.add(kind, r.get("resourceId"))
        R.add("acctid", r.get("account_id"))
        R.add("account", r.get("account_name"))
        R.add("owner", r.get("owner_hint"))
        R.add("app", r.get("group"))
        R.add("owner", r.get("exclusion_owner"))
        meta = r.get("meta") or {}
        R.add("instance", meta.get("AttachedInstance"))
        for value in (r.get("tags") or {}).values():
            R.add("value", value)
    for s in data.get("scps") or []:
        R.add("item", s.get("Name"))
        R.add("item", s.get("Id"))
        for t in s.get("targets") or []:
            R.add("item", t.get("id"))
            R.add("ou", t.get("name"))
    for o in data.get("owners") or []:
        R.add("owner", o.get("owner") if isinstance(o, dict) else None)
    for extra in extras:
        rows = extra.get("rows") if isinstance(extra, dict) and "rows" in extra else None
        for row in rows or []:
            if isinstance(row, dict):
                R.add("copy", row.get("id"))
                R.add("copy", row.get("source"))
    R.finish()
    return R


def write_redaction_key(redactor: Redactor, path: str) -> None:
    """The labels and what they stand for.  This file holds the original names: keep it where the report is not shared."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["label", "original"])
        for original, label in sorted(redactor.map.items(), key=lambda kv: kv[1]):
            writer.writerow([csv_safe(label), csv_safe(original)])


# ─────────────────────────────────────────────────────────────────────────────
# Recovery targets (customer-set) and the inputs the report used
# ─────────────────────────────────────────────────────────────────────────────
RECOVERY_TARGET_SOURCE = "default"         # "default", or the name of the file the customer supplied


def load_recovery_targets(path: str) -> Dict[int, Dict[str, float]]:
    """Read a recovery-targets file: JSON keyed by tier (1, 2 or 3), each with rpo_hours and/or rto_hours.  A tier left out
    keeps its default.  A bad file stops the run before any AWS call, with what is wrong."""
    file = Path(path)
    if not file.is_file():
        raise ValueError(f"recovery targets file not found: {path}")
    try:
        data = json.loads(file.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as e:
        raise ValueError(f"{file.name}: not valid JSON ({e.msg} at line {e.lineno})")
    if not isinstance(data, dict) or not data:
        raise ValueError(f"{file.name}: expected an object keyed by tier, for example {{\"1\": {{\"rpo_hours\": 1, \"rto_hours\": 4}}}}")
    out: Dict[int, Dict[str, float]] = {}
    for key, row in data.items():
        try:
            tier = int(key)
        except (TypeError, ValueError):
            raise ValueError(f"{file.name}: tier '{clean_text(str(key), 20)}' is not 1, 2 or 3")
        if tier not in (1, 2, 3):
            raise ValueError(f"{file.name}: tier {tier} is not 1, 2 or 3")
        days_key = "max_retention_days" if tier == 3 else "min_retention_days"
        allowed = {"rpo_hours", "rto_hours", days_key}
        if not isinstance(row, dict) or not row or not set(row) <= allowed:
            raise ValueError(f"{file.name}: tier {tier} may set only " + ", ".join(sorted(allowed)))
        merged: Dict[str, float] = {}
        for name, value in row.items():
            if name == days_key:
                if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 36500:
                    raise ValueError(f"{file.name}: tier {tier} {name} must be a whole number of days from 1 to 36,500")
                merged[name] = value
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 24 * 365:
                raise ValueError(f"{file.name}: tier {tier} {name} must be a number of hours above 0 and at most 8,760")
            merged[name] = int(value) if float(value) == int(value) else float(value)
        out[tier] = merged
    return out


def apply_recovery_targets(targets: Dict[int, Dict[str, float]], source: str) -> None:
    global RECOVERY_TARGET_SOURCE, DEV_LONG_RETENTION_DAYS
    for tier, row in targets.items():
        RECOVERY_TIERS[tier].update(row)
    # Tier 3's retention target is the development limit the Waste pillar uses, so the two always agree.
    if targets.get(3, {}).get("max_retention_days"):
        DEV_LONG_RETENTION_DAYS = int(targets[3]["max_retention_days"])
        for control in DEFAULT_POSTURE_CONTROLS:
            if "max_retention_days" in control:
                control["max_retention_days"] = DEV_LONG_RETENTION_DAYS
    RECOVERY_TARGET_SOURCE = source


_TIER_MEANING = {1: "Production, data inferred CONFIDENTIAL or higher", 2: "Other production", 3: "Development"}


def targets_section_html(resources: List[Dict], source: str = "default") -> List[str]:
    """How the newest copies, backup schedules and restores compare with the recovery targets.  The targets are the customer's
    where a file supplied them, otherwise assumptions the report states.  Facts only; no tier is graded."""
    assessed = [r for r in resources if r.get("recovery_copy_state") not in (None, "not_assessed")]
    if not assessed:
        return []
    e = _esc
    out: List[str] = []
    w = out.append
    w('<section><div class="sec-head"><span class="sec-num">Targets</span>'
      '<h2>How the copies and restores compare with the recovery targets</h2></div>')
    if source == "default":
        w('<p>A recovery target is how recent a copy is meant to be and how soon a restore is meant to finish. <strong>No targets were supplied, '
          'so these are the tool\'s default assumptions by tier</strong>, not yours; a targets file replaces them.</p>')
    else:
        w(f'<p>A recovery target is how recent a copy is meant to be (the recovery point objective) and how long a restore is meant to '
          f'take (the recovery time objective). <strong>These targets were supplied by the customer</strong> in '
          f'<span class="mono">{e(source)}</span>; a tier left out of that file keeps its default assumption.</p>')
    w(f'<p>A copy counts as older than the target only past {STALE_TOLERANCE:g} times the target, so a backup a little late is not '
      f'reported. Age says nothing about whether a copy would restore.</p>')
    w('<table><thead><tr><th>Tier</th><th>Target</th><th class="num">Resources</th><th class="num">Newest copy within target</th>'
      '<th class="num">Newest copy older than target</th><th class="num">Freshness not known</th><th class="num">No recovery copy identified</th>'
      '<th class="num">Schedule slower than target</th><th class="num">Restored within target</th>'
      '<th class="num">Restored, over target</th><th class="num">No restore on record</th></tr></thead><tbody>')
    for tier in sorted(RECOVERY_TIERS):
        rows = [r for r in assessed if r.get("recovery_tier") == tier]
        t = RECOVERY_TIERS[tier]
        ev = [recovery_evidence_of(r) for r in rows]
        # A copy whose date cannot be read is never counted as within target: it has its own column.
        unknown_age = sum(1 for r, k in zip(rows, ev) if k == "current" and r.get("copy_freshness") in ("not_measurable", "unknown"))
        within, late, nocopy = ev.count("current") - unknown_age, ev.count("outdated"), ev.count("none_identified")
        known = [r for r in rows if r.get("frequency_exceeds_rpo") is not None]
        longer = sum(1 for r in known if r.get("frequency_exceeds_rpo"))
        restored = [r for r in rows if r.get("last_successful_restore_at")]
        w(f'<tr><td class="asset">Tier {tier}<em>{e(_TIER_MEANING[tier])}</em></td>'
          f'<td style="white-space:nowrap">copy every {t["rpo_hours"]:g}h<br>restore within {t["rto_hours"]:g}h</td><td class="num">{len(rows):,}</td>'
          f'<td class="num">{within:,}</td><td class="num">{late:,}</td><td class="num">{unknown_age:,}</td><td class="num">{nocopy:,}</td>'
          f'<td class="num">{longer:,} of {len(known):,}</td>'
          f'<td class="num">{sum(1 for r in restored if r.get("restore_within_rto")):,}</td>'
          f'<td class="num">{sum(1 for r in restored if r.get("restore_within_rto") is False):,}</td>'
          f'<td class="num">{len(rows) - len(restored):,}</td></tr>')
    w('</tbody></table>')
    untiered = [r for r in assessed if not r.get("recovery_tier")]
    w(f'<p class="none">The columns are the recovery-evidence states every figure in the report uses. A copy whose date cannot be '
      f'read (S3 versioning, for example) is under "Freshness not known", never "within target". "Schedule slower than target" counts only resources whose plan schedule could be read. '
      + (f'{_n(len(untiered), "resource")} whose environment could not be inferred {"has" if len(untiered) == 1 else "have"} no tier '
         f'and {"is" if len(untiered) == 1 else "are"} not compared with a target. ' if untiered else '')
      + f'"No restore on record" means no successful restore in the window, not that a restore would fail.</p>')
    out.extend(retention_by_class_html(assessed, source))
    w('</section>')
    return out


def retention_by_class_html(resources: List[Dict], source: str = "default") -> List[str]:
    """How long copies are kept in each tier, against that tier's retention target, and how many sit where no credential in the
    account can delete them.  Retention and immutability are separate controls, shown side by side and not graded."""
    rows = []
    for tier in (1, 2, 3, None):
        group = [r for r in resources if r.get("recovery_tier") == tier and r.get("protection_state") != "not_assessed"]
        if not group:
            continue
        kept = sorted(r["retention_days"] for r in group if (r.get("retention_days") or 0) > 0)
        locked = sum(1 for r in group if r.get("is_air_gapped") or r.get("vault_lock_mode") == "compliance")
        target = retention_target(tier)
        outside = sum(1 for r in group if retention_vs_target(r))
        label = f"Tier {tier}: {_TIER_MEANING[tier]}" if tier else "No tier (criticality unknown)"
        aim = (f'at least {target[1]:,} days' if target and target[0] == "min" else f'at most {target[1]:,} days' if target else "none")
        out_label = ("" if not target else f'{outside:,} kept {"less" if target[0] == "min" else "longer"}')
        rows.append(f'<tr><td>{_esc(label)}</td><td>{aim}</td><td class="num">{len(group):,}</td>'
                    f'<td class="num">{f"{kept[0]:,} to {kept[-1]:,} days (median {_median(kept):,.0f})" if kept else "not read"}</td>'
                    f'<td class="num">{out_label or "—"}</td><td class="num">{locked:,}</td></tr>')
    if not rows:
        return []
    whose = ("<strong>These are the tool's default retention targets, not yours</strong>; the recovery targets file replaces them."
             if source == "default" else
             f"The retention targets are the ones in {_esc(source)}, with the tool's defaults for any it left out.")
    return ['<h3>How long copies are kept, against the retention target</h3>',
            f'<p>Retention is read from each resource\'s plan, lifecycle policy or service setting. {whose} The last column counts '
            'copies in a compliance-locked or air-gapped vault. A retention outside the target may be intended. A compliance framework '
            '(HIPAA, SOX, PCI DSS, GDPR) may set a minimum for some data; this report assesses against none.</p>',
            '<table><thead><tr><th>Tier (inferred)</th><th>Retention target</th><th class="num">Resources</th>'
            '<th class="num">Copies kept</th><th class="num">Outside the target</th>'
            '<th class="num">With a copy no one in the account can delete</th></tr></thead><tbody>'] + rows + ['</tbody></table>']


def _basename(path: Optional[str]) -> str:
    return Path(path).name if path else ""


def inputs_section_html(inputs: Dict[str, Any], resources: List[Dict]) -> List[str]:
    """The assumptions and inputs behind the figures, so a report that is forwarded still says how it was made."""
    if not inputs:
        return []
    e = _esc
    out: List[str] = []
    w = out.append
    w('<section><div class="sec-head"><span class="sec-num">Inputs</span><h2>Inputs and assumptions behind these figures</h2></div>')
    w('<p>What this report was built from, and what it assumed. Anything inferred is labelled as inferred where it appears, with '
      'its basis and confidence; this page gathers the settings in one place.</p>')
    prod = [r for r in resources if r.get("criticality") == "production"]
    conf = {c: sum(1 for r in prod if r.get("criticality_confidence") == c) for c in ("high", "medium", "low")}
    targets = inputs.get("targets_source", "default")
    tiers = "; ".join(f'tier {t}: copy every {v["rpo_hours"]:g}h, restore within {v["rto_hours"]:g}h' for t, v in sorted(RECOVERY_TIERS.items()))
    rows = [
        ("Assessed", f'{inputs.get("assessed_date", "")}. {inputs.get("mode", "")}.',
         "The date the metadata was read. Figures describe that day."),
        ("Accounts", f'{inputs.get("accounts_assessed", 0):,} assessed'
                     + (f', {inputs.get("accounts_failed", 0):,} could not be read' if inputs.get("accounts_failed") else "")
                     + (f', {inputs.get("accounts_not_selected", 0):,} left out by --accounts' if inputs.get("accounts_not_selected") else ""),
         "Accounts that could not be read, and accounts left out by --accounts, are in Coverage gaps and in no count."),
        ("Regions scanned", f'{len(inputs.get("regions", [])):,}: ' + ", ".join(inputs.get("regions", [])[:12])
                            + (" and more" if len(inputs.get("regions", [])) > 12 else ""),
         "Regions with no resources are listed in the Appendix."),
        ("What was read", "AWS Backup and AWS-native protection only",
         "Protection provided by other tools is not read; see What this review can and cannot see."),
        ("Recovery targets", ("default assumptions" if targets == "default" else f"supplied by the customer in {targets}") + ". " + tiers,
         "A copy counts as late after " + f"{STALE_TOLERANCE:g}" + " times its target."),
        ("Overrides", (f'file {inputs["overrides_file"]}; ' if inputs.get("overrides_file") else "no file; ")
                      + f'{inputs.get("overrides_loaded", 0):,} loaded, {inputs.get("overrides_used", 0):,} applied to resources',
         "An override corrects an inferred criticality, sensitivity or tier, or records a decision not to protect."),
        ("Production resources", f'{len(prod):,}: {conf["high"]:,} high confidence, {conf["medium"]:,} medium, {conf["low"]:,} low',
         "Inferred from tags, the account and its organizational unit, and names. The customer confirms."),
        ("Backup jobs", f'last {inputs.get("job_history_days", 0)} days', "Failures and expired jobs are counted in this window."),
        ("Restore jobs", f'last {inputs.get("restore_lookback_days", 0)} days', "A restore counts only if it completed and any validation passed."),
        ("Recovery points counted as a copy", "those AWS Backup can still restore from: expired, deleting and still-creating recovery points "
         "are left out, and so are stopped ones",
         "Stopped is an assumption: AWS Backup marks a continuous backup STOPPED when it stops (for example after versioning or a "
         "permission is removed), and AWS documentation does not say whether its earlier points can still be restored, so they are "
         "not counted. They still count toward stored size."),
        ("Cost", ("spend read from Cost Explorer for the trailing 30 days, annualized as 30 days times 12 (an estimate, not a forecast)"
                  if inputs.get("costs_assessed") else "not measured in this run"),
         f"Costs to protect a gap are estimates at AWS list rates per GiB-month (us-east-1, checked {PRICES_CHECKED})."),
        ("Previous run", (f'compared with {inputs["baseline_file"]}' if inputs.get("baseline_file") else "none supplied"),
         "A comparison states what changed; it does not say which changes matter."),
        ("Exclusion tags", inputs.get("exclusion_prefix", ""), "A tag with this prefix records a decision not to protect a resource."),
    ]
    if inputs.get("redacted"):
        rows.insert(1, ("Names", "redacted: account, resource, vault and plan names and IDs are replaced by labels",
                        "Counts and structure are real. The labels are not written anywhere unless a key file was asked for."))
    w('<table><thead><tr><th style="width:18%">Input</th><th style="width:46%">Value</th><th>Note</th></tr></thead><tbody>')
    for name, value, note in rows:
        w(f'<tr><td class="asset">{e(name)}</td><td>{e(value)}</td><td>{e(note)}</td></tr>')
    w('</tbody></table></section>')
    return out


# ─────────────────────────────────────────────────────────────────────────────
# What this review can see, and the Assets tab
# ─────────────────────────────────────────────────────────────────────────────
# The collector reads AWS Backup and AWS-native mechanisms only.  Protection that another tool provides is not read: it would
# need that tool's own catalogue, and the role has no access to one.  A resource protected only that way reads as having no
# recovery copy, unless the tool also leaves a snapshot AWS can show.  The text names no product.
SCOPE_OF_VIEW_TITLE = "What this review can and cannot see"
SCOPE_OF_VIEW = (
    "This review reads AWS Backup (plans, vaults, recovery points, jobs and restore tests, for every resource type it supports) and "
    "AWS-native protection: RDS and Aurora automated backups and snapshots, DynamoDB point-in-time recovery and backups, EBS "
    "snapshots and lifecycle policies, and S3 versioning and replication. It cannot see other backup tools, because the read-only "
    "role has no access to their records. A resource protected only by one shows here as having no recovery copy, unless that tool "
    "leaves a snapshot AWS can show. The overrides file can record it as protected elsewhere, with an owner and a review date.")


# The short reminder near the headline figures; the full note is in How this review works (said once).
SCOPE_REMINDER = ('<p class="meta">Only AWS Backup and AWS-native protection are read, so a copy made by another backup tool is not '
                  'seen. <a href="#sec-purpose">What this review can and cannot see</a></p>')


def scope_of_view_callout(folded: bool = False) -> str:
    """The note on what the review cannot see.  In full in the Summary; folded where it is repeated, so it is one click away."""
    if folded:
        return (f'<details class="drill"><summary>{_esc(SCOPE_OF_VIEW_TITLE)}</summary><div class="drill-body"><p>{_esc(SCOPE_OF_VIEW)}'
                '</p></div></details>')
    return f'<div class="callout"><h4>{_esc(SCOPE_OF_VIEW_TITLE)}</h4><p>{_esc(SCOPE_OF_VIEW)}</p></div>'


_CRIT_RANK = {"production": 0, "unknown": 1, "development": 2}
_CONF_RANK = {"high": 0, "medium": 1, "low": 2}
_SENS_RANK = {"HIGH_RISK_CONFIDENTIAL": 0, "CONFIDENTIAL": 1, "INTERNAL": 2, "PUBLIC": 3}
_CRIT_LABEL = {"production": "Production", "unknown": "Not known", "development": "Development"}
_CRIT_KIND = {"production": "conf", "unknown": "neutral", "development": "neutral"}
_SENS_LABEL = {"HIGH_RISK_CONFIDENTIAL": "High-risk", "CONFIDENTIAL": "Confidential", "INTERNAL": "Internal", "PUBLIC": "Public"}
# How a resource's recovery-copy state reads in the table: (label, pill kind, filter group).
# The four recovery-evidence states as the Assets table and the charts show them: label, colour, and the chart group.
_ASSET_STATE = {
    "current": ("Copy identified", "good", "yes"),
    "outdated": ("Copy identified, older than the target", "warn", "yes"),
    "none_identified": ("No recovery copy identified", "flag", "no"),
    "not_assessed": ("Not assessed", "neutral", "other"),
}
# For a record made before recovery_evidence existed (or a test that builds one by hand).
_LEGACY_EVIDENCE = {"current": "current", "orphan_policy": "current", "stale": "outdated", "none": "none_identified",
                    "policy_only": "none_identified", "excluded_documented": "none_identified", "no_backup_path": "none_identified"}


def environment_unclear(r: Dict) -> bool:
    """No environment tag (or override) says whether the resource is production or development: its environment is inferred from
    the account, a name or usage, or stays unknown.  The first page's "no environment tag" count uses the same rule."""
    return str(r.get("criticality_basis", "none")).split(":")[0] not in ("tag", "override")


def recovery_evidence_of(r: Dict) -> str:
    """The resource's recovery-evidence state: the one every coverage figure counts from."""
    if r.get("protection_state") == "not_assessed":
        return "not_assessed"
    return r.get("recovery_evidence") or _LEGACY_EVIDENCE.get(r.get("recovery_copy_state"), "not_assessed")


_NATIVE_LABEL = {"rds_automated_backup": "RDS automated backups", "aurora_automated_backup": "Aurora automated backups",
                 "dynamodb_pitr": "DynamoDB point-in-time recovery", "s3_versioning": "S3 versioning", "ebs_dlm": "EBS lifecycle policy"}


def _asset_state(r: Dict) -> Tuple[str, str, str]:
    return _ASSET_STATE[recovery_evidence_of(r)]


def _badge_text(r: Dict) -> str:
    """The badges beside a resource's state, in words."""
    keys = [b for b in str(r.get("evidence_badges") or "").split("|") if b] or evidence_badges(r)
    return "; ".join(EVIDENCE_BADGES[b] for b in keys if b in EVIDENCE_BADGES)


def _asset_rank(r: Dict) -> Tuple:
    """Most critical first: production, then not known, then development; within each, the more certain the label, the
    higher; then resources with no copy ahead of those with one, more sensitive data first, larger first."""
    group = _asset_state(r)[2]
    return (_CRIT_RANK.get(r.get("criticality"), 1), _CONF_RANK.get(r.get("criticality_confidence"), 3),
            {"no": 0, "other": 1, "yes": 2}[group], _SENS_RANK.get(r.get("data_sensitivity"), 4),
            -(r.get("size_gib") or 0), str(r.get("resourceName") or r.get("resourceId") or ""))


def _asset_how(r: Dict) -> str:
    parts = []
    if r.get("has_backup_recovery_point") or r.get("backup_via_instance"):
        parts.append("AWS Backup")
    native = _NATIVE_LABEL.get(r.get("native_mechanism") or "")
    if native and r.get("has_native_protection"):
        parts.append(native)
    if r.get("last_native_snapshot_at") and not native:
        parts.append("Snapshots")
    if r.get("is_air_gapped"):
        parts.append("air-gapped vault")
    elif r.get("cross_account_copy"):
        parts.append("copy in another account")
    return ", ".join(parts) or "—"


def _asset_age(hours) -> str:
    if hours in (None, ""):
        return "—"
    hours = float(hours)
    return f"{hours:.0f}h" if hours < 48 else f"{hours / 24:.0f}d"


def criticality_reason(r: Dict) -> str:
    """The reason a resource was read as production, development or unknown, in plain words.  Names the signal, never a tag value."""
    basis = str(r.get("criticality_basis") or "")
    kind, _, detail = basis.partition(":")
    crit = r.get("criticality")
    word = {"production": "production", "development": "development or test"}.get(crit, "")
    if kind == "tag":
        return f"its {detail} tag says {word}"
    if kind == "account-ou":
        return f"it sits in an account whose organizational unit is named for {word}"
    if kind == "account-name":
        return f"it sits in an account whose name says {word}"
    if kind == "name":
        return "the resource name has a non-production word in it" if detail == "nonprod" else f'"{detail}" is in the resource name, which reads as {word}'
    if kind == "account-majority":
        return f"it is in an account where most resources classified by tag or name are production ({detail})"
    if kind == "behaviour":
        return f"it is set up like production ({detail}); nothing else said what it is"
    if kind == "override":
        return "set by the overrides file"
    return "no tag, name or account signal says what it is"


def _asset_row(r: Dict, with_account: bool) -> str:
    e = _esc
    label, kind, group = _asset_state(r)
    name = str(r.get("resourceName") or r.get("resourceId") or "")
    crit = r.get("criticality") if r.get("criticality") in _CRIT_LABEL else "unknown"
    conf = r.get("criticality_confidence") or ""
    basis = criticality_reason(r)
    kind_text = str(r.get("resourceType") or "").replace("AWS::", "")
    where = " · ".join(x for x in (str(r.get("awsRegion") or ""), (str(r.get("account_name") or r.get("account_id") or "") if with_account else "")) if x)
    ret = r.get("retention_days")
    cells = [
        f'<td class="asset">{e(name[:80])}<em>{e(kind_text)}{" · " + e(where) if where else ""}</em></td>',
        f'<td>{_pill(_CRIT_LABEL[crit], _CRIT_KIND[crit])}<em class="meta">{e(conf + " confidence" if conf else "")}'
        f'{" · " + e(basis) if basis else ""}</em></td>',
        f'<td>{e(_SENS_LABEL.get(r.get("data_sensitivity"), ""))}</td>',
        f'<td>{_pill(label, kind)}' + (f'<em class="meta">{e(_badge_text(r))}</em>' if _badge_text(r) else '') + '</td>',
        f'<td>{e(_asset_how(r))}</td>',
        f'<td class="num">{e(_asset_age(r.get("copy_age_hours")))}</td>',
        f'<td class="num">{e(f"{int(ret)}d") if ret not in (None, "", 0) else "—"}</td>',
    ]
    env = ' data-env="unclear"' if environment_unclear(r) else ''
    return (f'<tr data-p="{group}"{env} data-q="{e((name + " " + kind_text).lower()[:120])}">' + "".join(cells) + "</tr>")


_ASSET_HEAD = ('<thead><tr><th>Resource</th><th>Criticality (inferred)</th><th>Data</th><th>Recovery copy</th><th>How</th>'
               '<th class="num">Newest copy</th><th class="num">Retention</th></tr></thead>')


def assets_section_html(resources: List[Dict], top: int = 25, per_account: int = 40, max_accounts: int = 30,
                        csv_name: str = "assets.csv") -> List[str]:
    """Every asset ranked by how critical it appears (from tags, the account and names), with whether each has a recovery copy.
    The top of the list, an account-by-account drilldown and a pointer to the CSV for the rest.  Facts and labelled inference."""
    if not resources:
        return []
    e = _esc
    out: List[str] = []
    w = out.append
    ranked = sorted(resources, key=_asset_rank)
    total = len(ranked)
    w('<section><div class="sec-head"><span class="sec-num">Assets</span>'
      '<h2>Assets that appear most critical first, and whether each has a recovery copy</h2></div>')
    w('<p>Production first, then unknown, then development; within each, a tag outranks an account or a name, and resources with no '
      'recovery copy come first. <strong>Criticality is inferred</strong>: each row shows the basis and confidence, for you to confirm.</p>')

    # The counts by environment are in Recovery copies; this section lists the resources (Alex, 2026-11-17: no repeated tables).
    w('<p class="none">How many in each environment have a copy is in <a href="#sec-coverage">Recovery copies</a>. This section '
      'lists the resources themselves, most critical first.</p>')
    # Resources whose environment no tag states (Alex, 2026-11-17): untagged, or production versus development not determined.
    unclear = [r for r in ranked if r.get("protection_state") != "not_assessed" and environment_unclear(r)]
    if unclear:
        untagged = sum(1 for r in unclear if not r.get("tags"))
        unknown = sum(1 for r in unclear if r.get("criticality") not in ("production", "development"))
        w(f'<p class="none" id="asset-unclear"><b>Environment unclear:</b> {len(unclear):,} of {total:,} have no environment tag'
          + (f' ({untagged:,} no tags at all)' if untagged else '') + ', so whether each is production or development is inferred '
          f'from the account, a name or usage' + (f', and {unknown:,} could not be placed' if unknown else '') + '. '
          '<a href="#asset-filter" data-show="unclear">Show them</a>; the overrides file records the answer.</p>')
    w('<p class="none">Built-in protection only, a recorded exception, an Iceberg table and unknown freshness are shown beside each '
      'resource\'s state.</p>')

    # filter controls (shown only when scripts run)
    w('<div class="asset-filter" id="asset-filter" hidden><span>Show</span>'
      '<button type="button" data-filter="all" aria-pressed="true">All</button>'
      '<button type="button" data-filter="no" aria-pressed="false">No recovery copy identified</button>'
      '<button type="button" data-filter="yes" aria-pressed="false">Recovery copy identified</button>'
      '<button type="button" data-filter="unclear" aria-pressed="false">Environment unclear</button>'
      '<label>Find <input type="search" id="asset-find" placeholder="name or type" aria-label="Find a resource on this page"></label>'
      f'<span class="note">Filters apply to the rows listed on this page. All {total:,} assets are in <span class="mono">{e(csv_name)}</span>.</span></div>')

    # the most critical gaps
    gaps = [r for r in ranked if _asset_state(r)[2] == "no"]
    w('<h3>Resources that appear most critical, with no recovery copy</h3>')
    if gaps:
        w(f'<p>The first {min(top, len(gaps)):,} of {len(gaps):,}, in rank order.</p>')
        w('<div class="table-scroll"><table class="asset-table">' + _ASSET_HEAD + '<tbody>')
        for r in gaps[:top]:
            w(_asset_row(r, with_account=True))
        w('</tbody></table></div>')
        if len(gaps) > top:
            w(f'<p>{len(gaps) - top:,} more are listed by account below and in <span class="mono">{e(csv_name)}</span> '
              f'(filter <span class="mono">recovery_copy_state</span>).</p>')
    else:
        w('<p>Every resource assessed has a recovery copy, a decision on record, or could not be assessed. '
          'Nothing is listed here for that reason, not because nothing was read.</p>')

    # by account
    by_account: Dict[Tuple[str, str], List[Dict]] = {}
    for r in ranked:
        by_account.setdefault((str(r.get("account_id") or ""), str(r.get("account_name") or r.get("account_id") or "")), []).append(r)
    ordered = sorted(by_account.items(), key=lambda kv: (-sum(1 for r in kv[1] if _asset_state(r)[2] == "no" and r.get("criticality") == "production"),
                                                         -sum(1 for r in kv[1] if _asset_state(r)[2] == "no"), kv[0][1]))
    w('<h3>By account</h3>')
    w('<p>Each account opens to its own resources in the same order. Accounts with the most production resources lacking a copy come first.</p>')
    for (acct_id, acct_name), rows in ordered[:max_accounts]:
        prod = [r for r in rows if r.get("criticality") == "production"]
        prod_no = sum(1 for r in prod if _asset_state(r)[2] == "no")
        no = sum(1 for r in rows if _asset_state(r)[2] == "no")
        title = (f'{e(acct_name[:60])} <span class="meta">{_n(len(rows), "resource")} · {len(prod):,} production · '
                 f'{no:,} with no recovery copy ({prod_no:,} production)</span>')
        body = ['<div class="table-scroll"><table class="asset-table">' + _ASSET_HEAD + '<tbody>']
        body += [_asset_row(r, with_account=False) for r in rows[:per_account]]
        body.append('</tbody></table></div>')
        if len(rows) > per_account:
            body.append(f'<p>{len(rows) - per_account:,} more in this account are in <span class="mono">{e(csv_name)}</span> '
                        f'(filter <span class="mono">account_id</span> to {e(acct_id)}).</p>')
        w(f'<details class="drill asset-account"><summary>{title}</summary><div class="drill-body">{"".join(body)}</div></details>')
    if len(ordered) > max_accounts:
        w(f'<p>{len(ordered) - max_accounts:,} more accounts are in <span class="mono">{e(csv_name)}</span>.</p>')
    w(f'<p>All {total:,} assets, with every field this review collected, are in <span class="mono">{e(csv_name)}</span>.</p>')
    w('</section>')
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Charts (inline SVG, no libraries) and the one-page summary
# ─────────────────────────────────────────────────────────────────────────────
# Two charts: how each account's resources split by recovery-copy state, and how much of the estate has a copy that would
# remain after each failure scenario.  Both carry the same facts the tables carry, in a table view beside the chart.  The
# colours are status colours (protected, no copy, other), so each segment also has a text label in the legend and a tooltip;
# the colours are never the only channel.  Gaps between segments are the surface, not strokes.
_CH_W, _CH_LABEL_W, _CH_BAR_X, _CH_BAR_W, _CH_ROW = 760, 190, 200, 400, 30
_CH_COL = {"yes": "var(--teal)", "no": "var(--red)", "other": "var(--ink-3)"}
_CH_NAME = {"yes": "Recovery copy identified", "no": "No recovery copy identified", "other": "Not assessed"}
_CH_ICON = {"yes": "✓", "no": "✕", "other": "–"}


def _svg_t(x: float, y: float, text: str, cls: str = "ch-t", anchor: str = "start") -> str:
    return f'<text x="{x:g}" y="{y:g}" class="{cls}" text-anchor="{anchor}">{_esc(text)}</text>'


def coverage_by_account_chart(resources: List[Dict], max_accounts: int = 12, table_view: bool = True) -> str:
    """One bar per account: the share of its resources that has a recovery copy, has none, or is something else."""
    by_account: Dict[str, List[str]] = {}
    for r in resources:
        by_account.setdefault(str(r.get("account_name") or r.get("account_id") or "account"), []).append(_asset_state(r)[2])
    if not by_account:
        return ""
    rows = []
    for name, groups in by_account.items():
        n = len(groups)
        rows.append((name, n, {k: groups.count(k) for k in ("yes", "no", "other")}))
    rows.sort(key=lambda x: (-x[2]["no"] / x[1], -x[2]["no"], x[0]))
    shown = rows[:max_accounts]
    height = 34 + len(shown) * _CH_ROW
    parts = [f'<svg class="chart-svg" viewBox="0 0 {_CH_W} {height}" role="img" '
             f'aria-label="Share of each account\'s resources with a recovery copy, with none, and other. The table below holds the same figures.">']
    x = 0
    for key in ("yes", "no", "other"):
        parts.append(f'<rect x="{x}" y="4" width="10" height="10" rx="2" fill="{_CH_COL[key]}"/>')
        label = f'{_CH_ICON[key]} {_CH_NAME[key]}' if key != "other" else f'{_CH_ICON[key]} Other'
        parts.append(_svg_t(x + 16, 13, label, "ch-t2"))
        x += 16 + 7 * len(label) + 22
    for i, (name, n, c) in enumerate(shown):
        y = 30 + i * _CH_ROW
        parts.append(_svg_t(_CH_LABEL_W, y + 13, name[:28] + ("…" if len(name) > 28 else ""), "ch-t", "end"))
        cursor = float(_CH_BAR_X)
        segs = [(k, c[k]) for k in ("yes", "no", "other") if c[k]]
        usable = _CH_BAR_W - 2 * (len(segs) - 1)
        for k, count in segs:
            wid = max(3.0, usable * count / n)
            tip = f'{name}: {count:,} of {n:,} resources. {_CH_NAME[k]}.'
            parts.append(f'<rect x="{cursor:.1f}" y="{y}" width="{wid:.1f}" height="18" rx="3" fill="{_CH_COL[k]}"><title>{_esc(tip)}</title></rect>')
            if wid >= 30 and k != "other":
                parts.append(_svg_t(cursor + wid / 2, y + 13, f"{count:,}", "ch-in", "middle"))
            cursor += wid + 2
        parts.append(_svg_t(_CH_BAR_X + _CH_BAR_W + 12, y + 13, f'{c["no"]:,} of {n:,} with none', "ch-t2"))
    parts.append("</svg>")
    table = ['<table><thead><tr><th>Account</th><th class="num">Resources</th><th class="num">Recovery copy identified</th>'
             '<th class="num">No recovery copy identified</th><th class="num">Not assessed</th></tr></thead><tbody>']
    for name, n, c in rows:
        table.append(f'<tr><td class="asset">{_esc(name)}</td><td class="num">{n:,}</td><td class="num">{c["yes"]:,}</td>'
                     f'<td class="num">{c["no"]:,}</td><td class="num">{c["other"]:,}</td></tr>')
    table.append("</tbody></table>")
    left = len(rows) - len(shown)
    more = (f'<p class="none">{_n(left, "more account")} {"is" if left == 1 else "are"} in the '
            f'{"table" if table_view else "full report"}.</p>' if left > 0 else "")
    return ('<figure class="chart"><figcaption><strong>Recovery copy by account</strong>, share of each account\'s resources. '
            'Accounts with the largest share lacking a copy first.</figcaption>' + "".join(parts) + more
            + ('<details class="drill"><summary>Show as a table</summary><div class="drill-body">' + "".join(table) + '</div></details>'
               if table_view else "") + '</figure>')


_SCENARIO_ROWS = (("accidental", "Accidental deletion"), ("regional", "Loss of a Region"),
                  ("credential_compromise", "Stolen credentials in the account"), ("account_compromise", "Loss of the whole account"))


def scenario_chart(scenarios: Dict[str, Any], table_view: bool = True) -> str:
    """One bar per failure scenario: how many resources would still have a copy.  From where copies sit, not from restores."""
    rows = []
    for key, label in _SCENARIO_ROWS:
        s = (scenarios or {}).get(key) or {}
        total = s.get("total", 0)
        if total:
            rows.append((label, s.get("recoverable", 0), total))
    if not rows:
        return ""
    height = 14 + len(rows) * _CH_ROW
    parts = [f'<svg class="chart-svg" viewBox="0 0 {_CH_W} {height}" role="img" '
             f'aria-label="For each failure scenario, the share of resources that would still have a copy to restore from. The table below holds the same figures.">']
    for i, (label, got, total) in enumerate(rows):
        y = 6 + i * _CH_ROW
        share = got / total
        parts.append(_svg_t(_CH_LABEL_W + 40, y + 13, label, "ch-t", "end"))
        track_x = _CH_LABEL_W + 56
        track_w = 330
        parts.append(f'<rect x="{track_x}" y="{y}" width="{track_w}" height="18" rx="3" fill="var(--track)"/>')
        if got:
            parts.append(f'<rect x="{track_x}" y="{y}" width="{max(3.0, track_w * share):.1f}" height="18" rx="3" fill="var(--teal)">'
                         f'<title>{_esc(label)}: {got:,} of {total:,} resources would still have a copy.</title></rect>')
        parts.append(_svg_t(track_x + track_w + 12, y + 13, f'{share:.0%} · {got:,} of {total:,}', "ch-t2"))
    parts.append("</svg>")
    table = ['<table><thead><tr><th>Scenario</th><th class="num">Would still have a copy</th><th class="num">Resources</th>'
             '<th class="num">Share</th></tr></thead><tbody>']
    for label, got, total in rows:
        table.append(f'<tr><td class="asset">{_esc(label)}</td><td class="num">{got:,}</td><td class="num">{total:,}</td>'
                     f'<td class="num">{got / total:.0%}</td></tr>')
    table.append("</tbody></table>")
    return ('<figure class="chart"><figcaption><strong>If this happened today, how many resources would still have a copy to restore '
            'from?</strong> Counted from where each copy sits; whether it restores is in Restores.</figcaption>' + "".join(parts)
            + ('<details class="drill"><summary>Show as a table</summary><div class="drill-body">' + "".join(table) + '</div></details>'
               if table_view else "") + '</figure>')


# ── Start here: can you recover? ─────────────────────────────────────────────
# The first panel answers the two recovery questions the review is mostly about (an operational mistake, a cyber event),
# then lists where to look first.  The order is a fixed rule written on the page, the same in every report, so it grades
# nobody.  Each item offers options AWS documents, always including recording that the current state is intended.
# Regional disaster recovery is reported in one line and in the Summary.
_NO_COPY_FINDING = "Production resources with no identified recovery copy"
_CREDENTIAL_FINDING = "Production resources with no copy that source-account credentials cannot delete"


def _assessed_production(resources: List[Dict]) -> List[Dict]:
    return [r for r in resources if r.get("criticality") == "production" and r.get("protection_state") != "not_assessed"]


def _credential_safe(r: Dict) -> bool:
    """The rule compute_scenarios uses: a copy credentials in the source account cannot delete."""
    return bool(r.get("vault_lock_mode") == "compliance" or r.get("is_air_gapped") or r.get("cross_account_copy"))


# ─────────────────────────────────────────────────────────────────────────────
# The three pillars: visibility, underprotection, overprotection
# ─────────────────────────────────────────────────────────────────────────────
# The first page is built from these.  Every figure here is either counted in the census and spend view already or counted
# from the same resource fields, so a number means the same thing wherever it appears.

def _is_sensitive(r: Dict) -> bool:
    """The census rule: an inferred sensitivity of confidential or above, or PII among the inferred data classes."""
    return (_SENSITIVITY_RANK.get(r.get("data_sensitivity", "INTERNAL"), 1) >= 2
            or "PII" in str(r.get("data_classes", "")).split(","))


def priority_of(r: Dict) -> int:
    """The fixed priority rule written on the page: 1 critical and sensitive, 2 critical, 3 sensitive, 4 criticality unknown, 5 not critical.  Critical means
    production as inferred; both halves are inferences the customer confirms."""
    crit, sens = r.get("criticality") == "production", _is_sensitive(r)
    if crit and sens:
        return 1
    if crit:
        return 2
    if sens:
        return 3
    # Unknown sits above resources known to be non-critical: no tag, name, account or usage signal decided it, so it may be critical.
    return 4 if r.get("criticality", "unknown") == "unknown" else 5


PRIORITY_LABELS = {1: "Critical and sensitive", 2: "Critical", 3: "Sensitive", 4: "Criticality unknown", 5: "Not critical"}

# Mechanisms that are real controls but not a copy that survives deleting the resource, losing the account, or a bad write that
# propagates: alone, they are protection on paper.
_PAPER_MECHANISMS = {"s3_versioning": "S3 versioning or replication", "dynamodb_pitr": "DynamoDB point-in-time recovery",
                     "rds_automated_backup": "automated database backups", "aurora_automated_backup": "automated database backups"}


def paper_only(r: Dict) -> bool:
    """True when the resource's only protection is versioning, replication, point-in-time recovery or automated backups, with no
    AWS Backup recovery point and no copy in another account."""
    if r.get("has_backup_recovery_point") or r.get("cross_account_copy") or not r.get("has_native_protection"):
        return False
    mech = r.get("native_mechanism")
    if mech not in _PAPER_MECHANISMS:
        return False
    if mech in ("rds_automated_backup", "aurora_automated_backup") and r.get("survives_deletion"):
        return False                     # a manual snapshot outlives the database
    return True


# One reason per resource, the first that applies, so each resource is counted once.  (key, lens, what the group says)
UNDER_REASONS: Tuple[Tuple[str, str, str], ...] = (
    ("no_native_path", "Operational", "are Apache Iceberg tables with no table-level recovery identified"),
    ("no_copy", "Operational", "have no recovery copy identified"),
    ("not_current", "Operational", "have a copy, but it is older than the target or the latest job failed"),
    ("paper", "Operational and cyber", "rely only on versioning, replication, point-in-time recovery or automated backups"),
    ("same_account", "Cyber", "have copies only where the account's own credentials can delete them (no logically air-gapped "
                              "vault, compliance lock or other account)"),
)
_UNDER_ORDER = {k: i for i, (k, _, _) in enumerate(UNDER_REASONS)}

# Options for each finding, in three tiers, so a reader sees what the resource relies on now and what each step up adds.
#   "for"      the resource types the options apply to (a heading when a fold lists more than one group)
#   "service"  protection built into the service itself (point-in-time recovery, automated backups, versioning, snapshots), with
#              its limits; for a "protected on paper" group this is what the resources have now
#   "backup"   AWS Backup (central plans, copies to another account or Region, logically air-gapped vaults, Vault Lock)
#   "beyond"   describes, by capability and never by product, an approach offered by the platform named in the report's
#              "powered by" header, where AWS has no native equivalent or a narrower one; each carries its tradeoff.  Capabilities
#              that platform does not offer are not listed.
#   "note"     a line that comes before the options (for example, check with the owner first)
# Recording that the state is intended is always offered, by the renderer.
OPTION_TIERS = (("service", "Built into the service"), ("backup", "AWS Backup"), ("beyond", "Beyond AWS-native tools"))

UNDER_OPTIONS: Dict[str, Dict[str, str]] = {
    "no_native_path": {"for": "Apache Iceberg tables",
                       "service": "S3 Tables replication copies the data to another table bucket, but it is not a backup with its "
                                  "own retention.",
                       "backup": "AWS Backup has no table-aware backup for Apache Iceberg tables.",
                       "beyond": "Table-aware backup that restores an Iceberg table consistently with its metadata and snapshots, to "
                                 "another account, Region or catalog."},
    "no_copy": {"for": "Any resource type",
                "service": "Each service's own backups: DynamoDB point-in-time recovery, RDS and Aurora automated backups, S3 "
                           "versioning, EBS snapshots. Quick to turn on, but the copies stay in the same account, and point-in-time "
                           "recovery and automated backups cover at most 35 days.",
                "backup": "An AWS Backup plan that selects the resources by tag, type, or account-wide through an Organizations "
                          "backup policy. A plan can also copy to another account or Region.",
                "beyond": "Policy-based backup that enrolls resources by account, tag or type as they appear, so a new resource is "
                          "covered without a change to a plan."},
    "not_current": {"for": "Resources whose backups are failing or late",
                    "backup": "The Backup jobs section gives AWS's reason for each failure; the schedule can be changed where a copy "
                              "is older than the target."},
    "paper:s3_versioning": {"for": "S3",
                            "service": "What these buckets have now: versioning or replication, which bring back an overwritten "
                                       "or deleted object. Both sit where the account's own credentials can delete them. "
                                       "Replication to another account with S3 Object Lock keeps a copy those credentials cannot.",
                            "backup": "S3 backup (it needs versioning on) to a vault in another account or a logically "
                                      "air-gapped vault.",
                            "beyond": "Backup scoped to the buckets, prefixes or objects that matter, kept in an isolated account, "
                                      "restorable as one key, a prefix or many buckets to another bucket, Region or account, with bulk "
                                      "rollback of a bucket to a point in time. The rollback relies on versioning and runs in the same "
                                      "account, so it answers a bad write, not account compromise."},
    "paper:dynamodb_pitr": {"for": "DynamoDB",
                            "service": "What these tables have now: point-in-time recovery, which restores to any second in its "
                                       "window (at most 35 days) into a new table. It stays in the account.",
                            "backup": "With advanced DynamoDB backup on, copies to another account or a logically air-gapped vault, and a "
                                      "cold tier.",
                            "beyond": "Backup through DynamoDB Streams kept in an isolated account, with a search of a backup by key and a "
                                      "download of the matching records, and a rollback of selected partitions in place (AWS "
                                      "restores of a whole table create a new table). Its recovery point is about 15 minutes, "
                                      "where point-in-time recovery is to the second within its window."},
    "paper:rds_automated_backup": {"for": "RDS and Aurora",
                                   "service": "What these databases have now: automated backups, which restore to any second in "
                                              "the retention window (at most 35 days). They stay in the account. A manual snapshot "
                                              "copied to another account is the service's own way to keep a copy outside it.",
                                   "backup": "Copies to a vault in another account. Aurora can also use a logically air-gapped "
                                             "vault; RDS DB instances cannot (AWS Backup feature-availability table), so for them "
                                             "the other account is the way out of this one.",
                                   "beyond": "Isolated copies of RDS and Aurora held outside the account, with an archive tier for "
                                             "retention beyond the 35-day ceiling of automated backups. Archived backups can be "
                                             "searched for rows after a wait of up to 48 hours; a restore is of the whole "
                                             "instance or cluster."},
    "same_account": {"for": "Any resource type",
                     "service": "EBS and RDS snapshots can be shared with another account and copied there, out of reach of this "
                                "account's credentials.",
                     "backup": "Copies to a vault in a separate account, or a logically air-gapped vault for the types that support "
                               "one (not RDS DB instances; restoring from it after losing the account can use multi-party approval). Vault Lock in compliance mode stops anyone deleting "
                               "copies early, and cannot be undone after its cooling-off period.",
                     "beyond": "Copies kept by default in a separate account with its own identity and access controls, across "
                               "S3, DynamoDB, EC2/EBS and RDS. A third party then administers that account."},
}
UNDER_OPTIONS["paper:aurora_automated_backup"] = UNDER_OPTIONS["paper:rds_automated_backup"]

# Options for each Waste item.  Not shown in the report (Alex, 2026-11-17): the report says how each figure is estimated, and
# the options are talked through with the customer when the report is reviewed.  Kept here as the partner's reference for that talk.
OVER_OPTIONS: Dict[str, Dict[str, str]] = {
    "orphans": {"note": "Check with the owner whether each copy is still needed; one may be the only copy of deleted data.",
                "service": "Amazon Data Lifecycle Manager expires EBS snapshots on a schedule.",
                "backup": "Lifecycle rules expire recovery points on a schedule."},
    "dev_retention": {"service": "A shorter Amazon Data Lifecycle Manager policy for development snapshots. For EBS, a policy can "
                                 "instead move older snapshots to the archive tier: a full copy at a lower rate, kept at least 90 "
                                 "days, and up to 72 hours to restore.",
                      "backup": "A separate plan for development resources with a shorter retention, or, for EBS backups taken "
                                "monthly or less often, a move to cold storage (the same archive tier, with the same 90 days and "
                                "restore wait)."},
    "ddb_full_copies": {"service": "Point-in-time recovery for the recent window, with fewer long-term copies.",
                        "backup": "Shorter retention for the daily copies; with advanced DynamoDB backup on, older copies can move "
                                  "to the cold tier.",
                        "beyond": "Incremental-forever backup: one seed copy, then only the changes through DynamoDB Streams. It is "
                                  "billed per GiB and per million items processed, so compare it at the table's change rate."},
    "ebs_both": {"note": "Keep both if they serve different retention or Regions; otherwise one policy covers the volume."},
    "s3_noncurrent": {"service": "An S3 lifecycle rule with NoncurrentVersionExpiration bounds how long old versions are kept.",
                      "beyond": "Backup scoped to the prefixes that matter, so old versions of the rest need not be kept as the "
                                "recovery copy."},
    "unattached": {"note": "Check with the owner.",
                   "service": "A snapshot keeps the data at a lower rate if the volume itself is not needed."},
}
_OVER_WHERE = {"orphans": "sec-copies", "dev_retention": "sec-protection", "ddb_full_copies": "sec-protection",
               "ebs_both": "sec-protection", "s3_noncurrent": "sec-protection", "old_ebs": "sec-protection",
               "unattached": "sec-copies"}


def under_reason(r: Dict) -> Optional[str]:
    """The first underprotection reason that applies to an assessed resource, or None."""
    state = r.get("recovery_copy_state")
    if r.get("protection_state") == "not_assessed" or state in (None, "not_assessed", "excluded_documented"):
        return None
    if r.get("no_backup_path"):
        return "no_native_path"
    evidence = recovery_evidence_of(r)
    if evidence == "none_identified":
        return "no_copy"
    if evidence == "outdated" or r.get("job_failing") or r.get("latest_backup_failed"):
        return "not_current"
    if paper_only(r):
        return "paper"
    if not _credential_safe(r):
        return "same_account"
    return None


def compute_pillars(d: Dict[str, Any], sv: Dict[str, Any]) -> Dict[str, Any]:
    """The three pillars, from figures the analysis already holds."""
    res = d.get("resources") or []
    assessed = [r for r in res if r.get("protection_state") != "not_assessed"]
    census = d.get("census") or {}
    # Visibility
    costs = d.get("costs_by_mechanism") or {}
    spend = sorted(({"label": v.get("label", k), "annual": round(v.get("annual", 0) or 0, 2)} for k, v in costs.items()
                    if (v.get("annual") or 0) > 0), key=lambda x: -x["annual"])
    accounts = {str(r.get("account_name") or r.get("account_id") or "") for r in res}
    vis = {
        "resources": len(res), "assessed": len(assessed),
        "accounts": (d.get("inputs") or {}).get("accounts_assessed") or len(accounts - {""}),
        "critical": sum(1 for r in assessed if r.get("criticality") == "production"),
        "sensitive": sum(1 for r in assessed if _is_sensitive(r)),
        "pii": census.get("pii", 0),
        "critical_sensitive": sum(1 for r in assessed if priority_of(r) == 1),
        "unknown_env": census.get("unknown_environment", 0),
        "no_copy": sum(1 for r in assessed if r.get("recovery_copy_state") == "none"),
        "no_protection": sum(1 for r in assessed if not r.get("has_any_protection") and not r.get("no_backup_path")),
        "paper": sum(1 for r in assessed if paper_only(r)),
        # The recovery-evidence states, which every coverage figure counts from (the failure-scenario rule for operational recovery
        # is the same: a resource with current or outdated evidence has a copy).
        "with_copy": sum(1 for r in assessed if recovery_evidence_of(r) in ("current", "outdated")),
        "current": sum(1 for r in assessed if recovery_evidence_of(r) == "current"),
        "outdated": sum(1 for r in assessed if recovery_evidence_of(r) == "outdated"),
        "none_identified": sum(1 for r in assessed if recovery_evidence_of(r) == "none_identified"),
        "spend": spend, "spend_annual": sv.get("spent_annual", 0), "costs_assessed": bool(sv.get("costs_assessed")),
        "s3_versioned": sum(1 for r in assessed if str(r.get("s3_versioning") or "").lower() == "enabled"),
        "no_env_tag": sum(1 for r in assessed if str(r.get("criticality_basis", "none")).split(":")[0] not in ("tag", "override")),
        "unknown": sum(1 for r in assessed if r.get("criticality", "unknown") == "unknown"),
        "unknown_pool": sum(1 for r in assessed if priority_of(r) == 4),
        "no_tags": sum(1 for r in assessed if not (r.get("tags") or {})),
    }
    # Underprotection
    groups: Dict[Tuple[int, str], Dict[str, Any]] = {}
    rows = []
    for r in assessed:
        why = under_reason(r)
        if not why:
            continue
        p = priority_of(r)
        rows.append((p, why, r))
        g = groups.setdefault((p, why), {"priority": p, "reason": why, "count": 0, "gib": 0.0, "accounts": {}, "mechanisms": set(),
                                         "same_plan_scope": 0})
        g["count"] += 1
        g["same_plan_scope"] += 1 if r.get("same_plan_scope") else 0
        g["gib"] += r.get("size_gib", 0) or 0
        name = str(r.get("account_name") or r.get("account_id") or "")
        if name:
            g["accounts"][name] = g["accounts"].get(name, 0) + 1
        if why == "paper":
            g["mechanisms"].add(r.get("native_mechanism"))
    ordered = []
    for key in sorted(groups, key=lambda k: (k[0], _UNDER_ORDER[k[1]])):
        g = groups[key]
        g["accounts"] = sorted(g["accounts"].items(), key=lambda kv: (-kv[1], kv[0]))
        g["mechanisms"] = sorted(m for m in g["mechanisms"] if m)
        ordered.append(g)
    rows.sort(key=lambda t: (t[0], _UNDER_ORDER[t[1]], -(t[2].get("size_gib", 0) or 0), str(t[2].get("resourceName") or "")))
    pool = [r for r in assessed if priority_of(r) <= 3]
    under = {"groups": ordered, "rows": rows, "priority_pool": len(pool),
             "priority_hits": sum(1 for p, _, _ in rows if p <= 3), "all_hits": len(rows),
             "by_reason": {k: sum(1 for _, w, _ in rows if w == k) for k, _, _ in UNDER_REASONS},
             "no_copy_in_plan_scope": sum(1 for _, w, r in rows if w == "no_copy" and r.get("same_plan_scope")),
             "scenarios": compute_scenario_gaps(assessed),
             "op_or_cyber": sum(1 for r in pool if not r.get("has_any_protection") or not _credential_safe(r))}
    # Overprotection
    over_rows = []
    for key in sv["look_at"]:
        row = sv["rows"].get(key)
        if row and row["count"]:
            over_rows.append(dict(row, where=_OVER_WHERE.get(key, "sec-protection"), up_to=key in _SPEND_UP_TO,
                                  priced=key not in _SPEND_NOT_PRICED, in_headline=key not in _SPEND_NOT_IN_HEADLINE))
    head = sv.get("headline") or {}
    over = {"rows": over_rows, "annual_usd": head.get("annual_usd", 0.0), "items": head.get("items", 0), "listed": head.get("listed", 0)}
    return {"visibility": vis, "under": under, "over": over}


def _options_html(opts: List[Dict[str, str]], basis: str = "") -> str:
    """The Options fold: how a figure was estimated (when it is one), then for each group of resource types the three tiers
    (built into the service, AWS Backup, beyond AWS-native tools), then recording the state as intended."""
    opts = [o for o in opts if o]
    parts = [f'<p class="focus-o"><span>How it was estimated</span> {_esc(basis)}</p>'] if basis else []
    groups = len([o for o in opts if o.get("for")])
    for o in opts:
        if o.get("for") and groups > 1:
            parts.append(f'<p class="focus-for">{_esc(o["for"])}</p>')
        if o.get("note"):
            parts.append(f'<p class="focus-o">{_esc(o["note"])}</p>')
        for key, label in OPTION_TIERS:
            if o.get(key):
                parts.append(f'<p class="focus-o focus-{key}"><span>{label}</span> {_esc(o[key])}</p>')
    parts.append('<p class="focus-o"><span>Or</span> Leave it as it is, if that is intended.</p>')
    return '<details class="focus-opt"><summary>Options</summary>' + "".join(parts) + '</details>'


def _estimate_html(basis: str) -> str:
    """A Waste item's fold: only how its figure was estimated.  The options are for the review conversation, not the page."""
    if not basis:
        return ""
    return ('<details class="focus-opt"><summary>How it was estimated</summary>'
            f'<p class="focus-o">{_esc(basis)} It is an estimate for the owner to check, not a saving.</p></details>')


def _under_options(g: Dict[str, Any]) -> List[Dict[str, str]]:
    if g["reason"] == "paper":
        seen, out = set(), []
        for m in g["mechanisms"]:
            o = UNDER_OPTIONS.get("paper:" + m)
            if o and id(o) not in seen:
                seen.add(id(o))
                out.append(o)
        return out
    return [UNDER_OPTIONS[g["reason"]]]


def _chips(accounts: List[Tuple[str, int]]) -> str:
    chips = "".join(f'<span class="chip">{_esc(a)} <b>{c:,}</b></span>' for a, c in accounts[:3])
    if len(accounts) > 3:
        chips += f'<span class="chip chip-more">+{len(accounts) - 3:,} more</span>'
    return f'<div class="chips">{chips}</div>' if chips else ""


_UNDER_SHOWN = 5
_OVER_SHOWN = 3
_WASTE_FOLD_FIRST_PAGE = 5      # rows in the fold under each Waste item on the first page
_WASTE_FOLD_SPEND_VIEW = 25     # rows in the fold under each item in the Spend view
_UNDER_TABLE_ROWS = 150


# Potential underprotection by recovery scenario.  Each scenario uses the same rule as the failure-scenario chart
# (compute_scenarios), so a resource counted here is one the chart counts as not recoverable in that scenario.
REGIONAL_OPTIONS = {"for": "Any resource type",
                    "service": "S3 Cross-Region Replication, and cross-Region snapshot copies (Amazon Data Lifecycle Manager for EBS).",
                    "backup": "A copy rule to another Region."}


_SINGULAR = {"have": "Has", "are": "Is", "rely": "Relies"}


_AGREE = {"have": "has", "are": "is", "rely": "relies"}


def _agree(count: int, reason: str) -> str:
    """A scenario reason written for a count ("have no copy ...") as it reads after the number 1 ("has no copy ...")."""
    head, _, rest = reason.partition(" ")
    return f"{_AGREE[head]} {rest}" if count == 1 and head in _AGREE else reason


def _one(reason: str) -> str:
    """A scenario reason written for a count ("have no copy in another Region") as it reads for one resource ("Has no copy ...")."""
    head, _, rest = reason.partition(" ")
    return f"{_SINGULAR[head]} {rest}" if head in _SINGULAR else reason.capitalize()


def _op_reason(r: Dict) -> str:
    if r.get("no_backup_path"):
        return "are Apache Iceberg tables with no table-level recovery identified"
    if r.get("opt_in_skipped"):
        return "are picked by a backup plan, but AWS Backup is not opted in for their service in that Region"
    if r.get("job_failing"):
        return "are in a backup plan whose jobs are failing"
    return "have no backup protection identified"


def _cyber_reason(r: Dict) -> str:
    if not r.get("has_any_protection"):
        return "have no backup protection identified"
    if paper_only(r):
        return "rely only on versioning, point-in-time recovery or automated backups"
    return "have copies only in the source account, none air-gapped or locked"


def _regional_reason(r: Dict) -> str:
    return "have no backup protection identified" if not r.get("has_any_protection") else "have no copy in another Region"


SCENARIOS: Tuple[Tuple[str, str, str, Any, Any], ...] = (
    ("operational", "Operational recovery", "Accidental deletion, a bad change, a failed deployment",
     lambda r: not r.get("has_any_protection"), _op_reason),
    ("cyber", "Cyber recovery", "Stolen credentials, ransomware, unauthorized deletion in the account",
     lambda r: not _credential_safe(r), _cyber_reason),
    ("regional", "Regional recovery", "Losing a whole AWS Region", lambda r: not r.get("cross_region_copy"), _regional_reason),
)


def _scenario_options(key: str, rows: List[Dict]) -> List[Dict[str, str]]:
    if key == "operational":
        return [UNDER_OPTIONS["no_copy"]]
    if key == "regional":
        return [REGIONAL_OPTIONS]
    mechs = sorted({r.get("native_mechanism") for r in rows if paper_only(r)} - {None})
    return [UNDER_OPTIONS["same_account"]] + _under_options({"reason": "paper", "mechanisms": mechs})


def compute_scenario_gaps(assessed: List[Dict]) -> List[Dict[str, Any]]:
    """For each recovery scenario: the resources that would have no usable copy, critical and sensitive first."""
    pool = [r for r in assessed if priority_of(r) <= 3]
    out = []
    for key, label, question, hit, why in SCENARIOS:
        rows = [r for r in assessed if hit(r)]
        rows.sort(key=lambda r: (priority_of(r), -(r.get("size_gib", 0) or 0), str(r.get("resourceName") or "")))
        in_pool = [r for r in rows if priority_of(r) <= 3]
        reasons: Dict[str, int] = {}
        for r in in_pool:
            reasons[why(r)] = reasons.get(why(r), 0) + 1
        out.append({"key": key, "label": label, "question": question, "count": len(in_pool), "pool": len(pool),
                    "unknown": sum(1 for r in rows if priority_of(r) == 4),
                    "critical_sensitive": sum(1 for r in in_pool if priority_of(r) == 1), "all": len(rows),
                    "reasons": sorted(reasons.items(), key=lambda kv: -kv[1]), "rows": rows, "why": why,
                    "options": _scenario_options(key, in_pool)})
    return out


def underprotection_section_html(pillars: Dict[str, Any], scenarios: Optional[Dict[str, Any]] = None) -> List[str]:
    """Risk (potential underprotection) in full: what each failure would leave across the estate, then one block per recovery scenario,
    each listing its resources critical and sensitive first.  This is the one place the scenarios are explained."""
    u = pillars["under"]
    out = ['<section><div class="sec-head"><span class="sec-num">Under</span><h2>Risk, by recovery scenario</h2></div>',
           '<p class="lede">For each recovery scenario, the resources that would have no usable copy. Each list starts with critical '
           'and sensitive resources, then critical, sensitive, criticality unknown, and the rest. Criticality and sensitivity are '
           'inferred from tags, names and behaviour, for you to confirm. A gap may be intended. How many have a copy today is in '
           '<a href="#sec-coverage">Recovery copies</a>; this section asks which copies would survive each failure. It counts where copies sit, not whether a restore has been tried.</p>']
    if scenarios:
        out.append(scenario_chart(scenarios))
    for s in u["scenarios"]:
        shown = s["rows"][:_UNDER_TABLE_ROWS]
        out.append(f'<h3>{_esc(s["label"])}: {s["count"]:,} of {s["pool"]:,} critical or sensitive resources'
                   + (f', plus {s["unknown"]:,} of unknown criticality' if s["unknown"] else '') + '</h3>')
        if s["pool"]:
            out.append(_pair_bars(s["pool"] - s["count"], s["count"], "Usable copy", "No usable copy"))
        out.append(f'<p>{_esc(s["question"])}. ' + ("; ".join(f'{c:,} {_esc(_agree(c, t))}' for t, c in s["reasons"]) or "None") + '.</p>')
        out.append(_options_html(s["options"]))
        if not shown:
            continue
        out.append('<div class="table-scroll"><table class="compact"><thead><tr><th>Priority</th><th>Resource</th><th>Type</th><th>Account</th>'
                   '<th>Region</th><th class="num">Size</th><th>Why</th></tr></thead><tbody>')
        for r in shown:
            out.append(f'<tr><td>{PRIORITY_LABELS[priority_of(r)]}</td><td class="asset">{_esc(clean_text(r.get("resourceName") or r.get("resourceId", ""), 60))}</td>'
                       f'<td>{_esc(str(r.get("resourceType", "")).replace("AWS::", ""))}</td><td>{_esc(r.get("account_name") or r.get("account_id", ""))}</td>'
                       f'<td>{_esc(r.get("awsRegion", ""))}</td><td class="num">{_fmt_tib(r.get("size_gib", 0) or 0)}</td><td>{_esc(_one(s["why"](r)))}</td></tr>')
        out.append('</tbody></table></div>')
        if len(s["rows"]) > len(shown):
            out.append(f'<p class="meta">{len(s["rows"]) - len(shown):,} more are in the companion CSV files.</p>')
    if u["no_copy_in_plan_scope"]:
        out.append(f'<p class="focus-e">{u["no_copy_in_plan_scope"]:,} of the resources with no recovery copy are in an account and Region '
                   f'where a backup plan already runs, so adding them to it is one option.</p>')
    out.append('</section>')
    return out


def _pair_bars(good: int, bad: int, good_label: str, bad_label: str, fmt=None) -> str:
    """A green bar for the share that is fine and a red bar beneath it for the gap, both of the same total and both labelled
    with their figure, so the colour is never the only cue."""
    total = good + bad
    fmt = fmt or (lambda v: f"{v:,}")
    def row(n, label, cls):
        share = n / total if total else 0
        return (f'<li><span>{_esc(label)}</span><div class="ov-bar{cls}" role="img" aria-label="{_esc(label)}: {_esc(fmt(n))} of {_esc(fmt(total))}">'
                f'<span style="width:{max(share * 100, 1.5 if n else 0):.1f}%"></span></div><b>{_esc(fmt(n))}</b></li>')
    return '<ul class="ov-pair">' + row(good, good_label, "") + row(bad, bad_label, " ov-bar-gap") + '</ul>'


_ACTIONS_SHOWN = 5


def _coverage_line(d: Dict[str, Any]) -> str:
    """One sentence on which accounts the figures describe.  Accounts that were not read are neither protected nor unprotected."""
    inp = d.get("inputs") or {}
    read, failed, left = inp.get("accounts_assessed", 0), inp.get("accounts_failed", 0), inp.get("accounts_not_selected", 0)
    total = read + failed + left
    unread_org = inp.get("organization_read") is False
    if not (failed or left):
        scope = (' The organization itself was not read, so accounts that were not named are not counted and nothing is said about them.'
                 if unread_org else "")
        return (f'<p class="ov-cover ov-cover-ok"><b>{_n(read, "account")} {"was" if read == 1 else "were"} read,</b> and the figures describe all of them.{scope} Individual API calls that '
                f'could not be made are listed in <a href="#sec-gaps">Coverage gaps</a>, and those figures read as "at least".</p>')
    parts = []
    if failed:
        parts.append(f'{failed:,} could not be read')
    if left:
        parts.append(f'{left:,} left out by --accounts')
    return (f'<p class="ov-cover ov-cover-part"><b>{read:,} of {total:,} accounts were read,</b> and the figures describe those {read:,}. '
            f'{" and ".join(parts).capitalize()}, and {"is" if failed + left == 1 else "are"} counted as neither protected nor unprotected. '
            + ('The organization itself was not read, so accounts that were not named are not counted either. ' if unread_org else '')
            + f'The detail is in <a href="#sec-gaps">Coverage gaps</a>.</p>')


def _scen_bar(n: int, pool: int) -> str:
    share = n / pool if pool else 0
    return (f'<div class="ov-bar ov-bar-gap" role="img" aria-label="{n:,} of {pool:,}"><span style="width:{max(share * 100, 1.5 if n else 0):.1f}%">'
            f'</span></div>')


# The Executive Summary's opening, as Alex worded it (2026-11-12).  The same in every report; the cards below it carry the figures,
# and an estate in good shape shows that there.
EXEC_HEADLINE = "Your AWS environment is hiding risk and waste. This assessment shows you where."
EXEC_INTRO = ("Across our customer conversations, one theme repeats: with this many accounts and application teams touching AWS, nobody "
              "has the full picture of where data is unprotected or paying for things it doesn't need. This assessment gives you that "
              "visibility across every account. It surfaces unprotected data and wasted spend in one view, so you can strengthen your "
              "data protection strategy and cut costs at the same time.")


_APP_BASES = ("application tag", "application group")
_APPS_SHOWN = 5
# Names that read as business-critical.  A ranking aid only: it orders applications, it does not mark any resource critical.
_CRITICAL_NAME_WORDS = ("payment", "billing", "checkout", "order", "customer", "identity", "auth", "account", "patient", "claim",
                        "finance", "ledger", "core", "prod")


def compute_apps_at_risk(resources: List[Dict]) -> Dict[str, Any]:
    """Applications with production resources that have no recovery copy at all.  An application is named by an application tag or by a
    grouping the tool found (stack, AppRegistry application), never by a guess; production resources with neither are counted apart."""
    apps: Dict[str, Dict[str, Any]] = {}
    ungrouped = 0
    for r in resources:
        if (r.get("protection_state") == "not_assessed" or r.get("criticality") != "production"
                or r.get("recovery_copy_state") not in ("none", "policy_only")):
            continue
        name = next((clean_text(r["tags"][k], _OWNER_TEXT_LIMIT) for k in APPLICATION_TAG_KEYS if (r.get("tags") or {}).get(k)), "")
        if not name and str(r.get("owner_basis") or "").startswith(_APP_BASES):
            name = r.get("owner_hint", "")
        if not name:
            ungrouped += 1
            continue
        a = apps.setdefault(name, {"name": name, "resources": 0, "types": set(), "sensitive": 0})
        a["resources"] += 1
        a["types"].add(_TYPE_NOUN.get(r.get("resourceType", ""), str(r.get("resourceType", "")).replace("AWS::", "")))
        a["sensitive"] += 1 if _is_sensitive(r) else 0
    for a in apps.values():
        a["critical_name"] = any(w in a["name"].lower() for w in _CRITICAL_NAME_WORDS)
    rows = sorted(apps.values(), key=lambda a: (-a["sensitive"], not a["critical_name"], -a["resources"], a["name"]))
    return {"apps": rows, "ungrouped": ungrouped}


def compute_malware_gap(d: Dict[str, Any]) -> Dict[str, Any]:
    """Whether AWS Backup malware scanning is turned on, and what one scan of the data it can cover would cost at list price (an estimate)."""
    scan = (d.get("security") or {}).get("scan") or {}
    plans = scan.get("plans", 0)
    eligible = [r for r in d.get("resources") or [] if r.get("protection_state") != "not_assessed"
                and r.get("resourceType") in MALWARE_SCAN_TYPES and r.get("has_backup_recovery_point")]
    gib = sum(r.get("size_gib") or 0 for r in eligible)
    return {"known": bool((d.get("security") or {}).get("plans_readable", True)) and bool(scan), "plans": plans,
            "with_scan": scan.get("plans_with_scan", 0), "eligible": len(eligible), "gib": gib,
            "one_scan_usd": round(gib * MALWARE_SCAN_PER_GB, 2)}


def malware_line_html(g: Dict[str, Any]) -> str:
    """One called-out line: scanning on or off, and the documented price.  Not-assessed is said as not assessed."""
    if not g["known"] or not g["plans"]:
        return ""
    price = (f' One scan of the {g["gib"]:,.0f} GiB that plans protect would cost about {_fmt_money(g["one_scan_usd"])} at the list '
             f'price (${MALWARE_SCAN_PER_GB:.2f} per GB, billed under GuardDuty), an estimate.' if g["eligible"] else
             f' The list price is ${MALWARE_SCAN_PER_GB:.2f} per GB scanned (billed under GuardDuty).')
    if not g["with_scan"]:
        head = f'<b>Malware scanning is off</b> in all {g["plans"]:,} backup plans, so no copy has been checked before a restore.'
    else:
        head = (f'<b>Malware scanning is on</b> in {g["with_scan"]:,} of {g["plans"]:,} backup plans.'
                if g["with_scan"] < g["plans"] else f'<b>Malware scanning is on</b> in all {g["plans"]:,} backup plans.')
    tail = ' Off may be intended.' if g["with_scan"] < g["plans"] else ''
    return f'<p class="ov-call">{head}{price}{tail} <a href="#sec-security">Backup copy protection</a></p>'


_GRANULARITY_TYPES = {"AWS::RDS::DBCluster": "rds", "AWS::RDS::AuroraCluster": "rds", "AWS::RDS::DBInstance": "rds",
                      "AWS::DynamoDB::Table": "ddb", "AWS::S3::Bucket": "s3"}


def recovery_granularity_rows(resources: List[Dict]) -> List[Dict[str, Any]]:
    """For each data store, what its current setup can restore, from settings already read.  Counts only."""
    rows: Dict[str, Dict[str, int]] = {}
    for r in resources:
        kind = _GRANULARITY_TYPES.get(r.get("resourceType", ""))
        if not kind or r.get("protection_state") == "not_assessed":
            continue
        c = rows.setdefault(kind, {"n": 0, "native": 0, "versioned": 0, "plan": 0, "none": 0})
        c["n"] += 1
        native = bool(r.get("native_mechanism") and r.get("has_native_protection", True))
        c["native"] += native
        c["versioned"] += str(r.get("s3_versioning") or "").lower() == "enabled"
        c["plan"] += bool(r.get("has_backup_recovery_point"))
        c["none"] += not (native or r.get("has_backup_recovery_point") or str(r.get("s3_versioning") or "").lower() == "enabled")
    return [dict(kind=k, **rows[k]) for k in ("ddb", "s3", "rds") if k in rows]


def recovery_granularity_html(resources: List[Dict]) -> List[str]:
    """One question, "What restore granularity do you need?", with what each data store can restore today.  No recommendation."""
    rows = recovery_granularity_rows(resources)
    if not rows:
        return []
    out = ['<details class="drill"><summary>What restore granularity do you need?</summary>',
           '<p class="meta">What the current setup can bring back, from the settings read. If a smaller piece than the unit shown is '
           'needed (a record, an object, a row), say so: nothing read here restores one.</p><ul>']
    for c in rows:
        n = c["n"]
        if c["kind"] == "ddb":
            line = (f'<b>DynamoDB</b> ({n:,} tables): {c["native"]:,} with point-in-time recovery and {c["plan"]:,} in a backup plan. '
                    f'Both restore a whole table into a new table.')
        elif c["kind"] == "s3":
            line = (f'<b>S3</b> ({n:,} buckets): {c["versioned"]:,} with versioning on (one object version at a time) and {c["plan"]:,} in a '
                    f'backup plan (a bucket or chosen prefixes).')
        else:
            line = (f'<b>RDS and Aurora</b> ({n:,}): {c["native"]:,} with automated backups (up to 35 days) and {c["plan"]:,} in a backup '
                    f'plan. Both restore a whole instance or cluster.')
        out.append(f'<li>{line} {c["none"]:,} {"has" if c["none"] == 1 else "have"} neither, so nothing restores.</li>')
    out.append('</ul></details>')
    return out


def apps_chart_html(apps: Dict[str, Any]) -> str:
    """A ranked bar per application: production resources with no recovery copy.  Bars start at zero and carry their figure."""
    shown = apps["apps"][:_APPS_SHOWN]
    rows = shown
    top = max(a["resources"] for a in rows) or 1
    out = ['<h3 class="ov-h">Applications with identified protection gaps</h3>',
           '<p class="ov-call">Production resources with no recovery copy, by application: sensitive data first, then business-critical '
           'names (payments, billing, identity), then the most resources. Inferred from tags and names.</p><ul class="ov-apps">']
    for a in rows:
        kinds = ", ".join(sorted(a["types"]))
        note = (f'{kinds}' + (f'; {a["sensitive"]:,} sensitive' if a["sensitive"] else '')) if kinds else ""
        out.append(f'<li><span class="ov-an">{_esc(a["name"])}<em>{_esc(note)}</em></span>'
                   f'<div class="ov-bar{"" if a.get("muted") else " ov-bar-gap"}" role="img" aria-label="{_esc(a["name"])}: '
                   f'{a["resources"]:,} resources with no recovery copy"><span style="width:{max(a["resources"] / top * 100, 2):.1f}%"></span></div>'
                   f'<b>{a["resources"]:,}</b></li>')
    out.append('</ul>')
    more = []
    if len(apps["apps"]) > len(shown):
        more.append(f'{_n(len(apps["apps"]) - len(shown), "more application")}')
    if apps["ungrouped"]:
        more.append(f'{apps["ungrouped"]:,} production resources with no copy and no application named')
    if more:
        out.append(f'<p class="ov-more">Not charted: {" and ".join(more)}. <a href="#sec-owners">Owners and applications</a></p>')
    return "".join(out)


def compute_account_coverage(resources: List[Dict]) -> List[Dict[str, Any]]:
    """Per account: resources with a recovery copy that survives, protected on paper only, and with no backup protection identified."""
    rows: Dict[str, Dict[str, Any]] = {}
    for r in resources:
        if r.get("protection_state") == "not_assessed":
            continue
        name = str(r.get("account_name") or r.get("account_id") or "")
        c = rows.setdefault(name, {"name": name, "ok": 0, "paper": 0, "none": 0})
        if not r.get("has_any_protection"):
            c["none"] += 1
        elif paper_only(r):
            c["paper"] += 1
        else:
            c["ok"] += 1
    return sorted(rows.values(), key=lambda c: (-c["none"], -c["paper"], c["name"]))


def account_chart_html(rows: List[Dict[str, Any]]) -> str:
    """One stacked bar per account, the worst first.  Each segment carries its figure in text, so colour is not the only cue."""
    if len(rows) < 2:
        return ""
    shown = rows[:6]
    out = ['<h3 class="ov-h">Coverage by account</h3>',
           '<p class="ov-call"><span class="ov-key k-ok"></span>recovery copy <span class="ov-key k-paper"></span>built-in protection only '
           '<span class="ov-key k-none"></span>no backup protection identified. Accounts with the most unprotected resources first.</p>'
           '<p class="ov-call">Built-in protection only means S3 versioning, DynamoDB point-in-time recovery or database automated '
           'backups and nothing else. They undo a bad change, but they live with the resource, so deleting it or losing the account '
           'takes them too.</p><ul class="ov-acct">']
    for c in shown:
        n = c["ok"] + c["paper"] + c["none"]
        seg = "".join(f'<span class="k-{k}" style="width:{c[k] / n * 100:.1f}%" title="{c[k]:,}"></span>' for k in ("ok", "paper", "none") if c[k])
        out.append(f'<li><span class="ov-an">{_esc(c["name"])}<em>{n:,} resources</em></span>'
                   f'<div class="ov-stack" role="img" aria-label="{_esc(c["name"])}: {c["ok"]:,} with a copy, {c["paper"]:,} built-in protection only, '
                   f'{c["none"]:,} with none">{seg}</div><b>{c["none"]:,} none</b></li>')
    out.append('</ul>')
    if len(rows) > len(shown):
        more = len(rows) - len(shown)
        out.append(f'<p class="ov-more">{_n(more, "more account")} in <a href="#sec-exposure">Exposure by account</a>.</p>')
    return "".join(out)


def protect_vs_waste_html(resources: List[Dict], waste_annual: float, money_fmt=None) -> str:
    """The list-price cost of one basic copy of each production resource with no copy, beside the Waste figure.  Both are estimates."""
    gap = [r for r in resources if r.get("protection_state") != "not_assessed" and r.get("criticality") == "production"
           and r.get("recovery_copy_state") in ("none", "policy_only")]
    cost = sum(estimate_gap_protection_cost(r) for r in gap) * 12
    priced = sum(1 for r in gap if estimate_gap_protection_cost(r) > 0)
    if not gap or cost <= 0:
        return ""
    top = max(cost, waste_annual or 0) or 1
    rows = [(f"Backing up the {_n(len(gap), 'production resource')} with no recovery copy identified", "about", cost, False),
            ("Backups you may not need", "up to", waste_annual or 0, True)]
    out = ['<h3 class="ov-h">What protecting the gap might cost, next to the waste</h3>',
           '<p class="ov-call">Two rough yearly estimates at AWS list prices, side by side: one backup copy of each production '
           'resource that has none, and the Waste figure above. Later copies usually store only changes, so the first figure is '
           'likely high.' + (f' {len(gap) - priced:,} of the {len(gap):,} have no size read, so they are not in it.' if priced < len(gap) else '')
           + '</p><ul class="ov-cmp">']
    for label, qual, v, gap_style in rows:
        out.append(f'<li><span>{_esc(label)}</span><div class="ov-bar{" ov-bar-gap" if not gap_style else " ov-bar-waste"}" role="img" '
                   f'aria-label="{_esc(label)}: {qual} {_esc(_fmt_money(v))} a year"><span style="width:{max(v / top * 100, 1.5 if v else 0):.1f}%"></span></div>'
                   f'<b>{qual} {_esc(_fmt_money(v))}</b></li>')
    out.append('</ul>')
    return "".join(out)


def got_better_line(drift: Optional[Dict[str, Any]]) -> str:
    """Credit progress since the last run: gaps closed, new resources that arrived protected."""
    if not drift:
        return ""
    closed, new_ok = len(drift.get("closed_gaps") or []), drift.get("new_resources_protected", 0) or 0
    if not (closed or new_ok):
        return ""
    parts = ([f'{closed:,} {"resource" if closed == 1 else "resources"} gained a copy'] if closed else []) + \
            ([f'{new_ok:,} new {"resource" if new_ok == 1 else "resources"} arrived with a copy'] if new_ok else [])
    return f'<p class="ov-good-line"><b>Since the last run:</b> {"; ".join(parts)}. <a href="#sec-change">What changed</a></p>'


def overview_section_html(d: Dict[str, Any], money, sv: Dict[str, Any], prepared: str = "", charts: str = "",
                          pillars: Optional[Dict[str, Any]] = None) -> List[str]:
    """Executive Summary: three cards in a fixed order (visibility; risk, that is potential underprotection by recovery scenario;
    waste, that is potential overprotection), then one short list each.  Kept short on purpose: every figure links to the section behind it."""
    res = d["resources"]
    pillars = pillars or compute_pillars(d, sv)
    vis, under, over = pillars["visibility"], pillars["under"], pillars["over"]
    jobs, sec = d.get("backup_jobs") or {}, d.get("security") or {}
    acct = (d.get("scenarios") or {}).get("account_compromise") or {}
    vaults = d.get("vaults") or []
    out = ['<section><div class="sec-head"><span class="sec-num">Start</span><h2>Executive Summary</h2></div>',
           '<div class="onepage-bar"><span>' + _esc(prepared) + '</span><button type="button" id="print-onepage" hidden>'
           'Print only this page</button></div>',
           f'<p class="ov-headline">{EXEC_HEADLINE}</p>', f'<p class="lede">{EXEC_INTRO}</p>', _coverage_line(d)]
    if not vis["assessed"]:
        out.append('<p><em>Not assessed: no resource could be assessed, so nothing is said about protection.</em></p></section>')
        return out
    n_ass = vis["assessed"]
    scen = {s["key"]: s for s in under["scenarios"]}
    pool = under["priority_pool"]
    # ── Card 1: visibility
    c1 = ['<div class="ov-card pillar"><div class="ov-lens">1 · Visibility</div>',
          f'<div class="ov-big">{vis["resources"]:,}<small>resources in {_n(vis["accounts"], "account")}</small></div>',
          f'<div class="ov-what">{vis["with_copy"]:,} of {n_ass:,} have an identified recovery copy'
          + (f' ({vis["outdated"]:,} of them older than the target)' if vis.get("outdated") else '') + '</div>',
          _pair_bars(vis["with_copy"], n_ass - vis["with_copy"], "Recovery copy identified", "No recovery copy identified"),
          '<ul class="ov-facts">',
          f'<li><b>{vis["critical"]:,}</b> critical and <b>{vis["sensitive"]:,}</b> sensitive <em class="meta">inferred</em></li>',
          (f'<li><b>{vis["no_env_tag"]:,}</b> of {n_ass:,} {_has(vis["no_env_tag"])} no environment tag'
           + (f' ({vis["no_tags"]:,} no tags at all)' if vis["no_tags"] else '') + ', so their environment is inferred; '
           + (f'<b>{vis["unknown"]:,}</b> {"remains" if vis["unknown"] == 1 else "remain"} unknown. ' if vis["unknown"] else 'none remains unknown. ')
           + '<a href="#sec-assets">See the unclear environments</a></li>' if vis["no_env_tag"] else '<li>Every resource carries an environment tag</li>'),
          (f'<li><b>{money(vis["spend_annual"])}</b> a year on protection (billed)</li>' if vis["costs_assessed"]
           else '<li>Protection spend not assessed</li>'),
          '</ul><a class="ov-link" href="#sec-assets">What was found</a></div>']
    # ── Card 2: risk (potential underprotection), by scenario
    unknown = [r for r in res if r.get("protection_state") != "not_assessed" and priority_of(r) == 4]
    unk_gap = sum(1 for r in unknown if not r.get("has_any_protection") or not _credential_safe(r))
    c2 = ['<div class="ov-card pillar"><div class="ov-lens">2 · Risk</div>']
    if pool:
        c2 += [f'<div class="ov-big">{under["op_or_cyber"]:,}<small>of {pool:,} critical or sensitive resources</small></div>',
               '<div class="ov-what">with no qualifying recovery copy identified for an operational or a cyber event</div>',
               _pair_bars(pool - under["op_or_cyber"], under["op_or_cyber"], "Recovery-copy evidence for both", "No qualifying copy identified"),
               '<ul class="ov-scen">']
        for key in ("operational", "cyber"):
            s = scen[key]
            c2.append(f'<li><span>{_esc(s["label"])}</span>{_scen_bar(s["count"], pool)}<b>{s["count"]:,}</b></li>')
        c2.append('</ul>' + (f'<p class="ov-unk"><b>+{unk_gap:,}</b> whose criticality is unknown, shown next in every list. '
                             f'The overrides file marks them critical or not.</p>' if unk_gap else ''))
    else:
        # Nothing is classified critical or sensitive (often an untagged estate): "0 of 0" would read as no gap, so lead with
        # the resources whose criticality is unknown, which the lists show first in that case.
        c2 += [f'<div class="ov-big">{unk_gap:,}<small>of {len(unknown):,} resources whose criticality is unknown</small></div>',
               '<div class="ov-what">with no qualifying recovery copy identified for an operational or a cyber event</div>',
               _pair_bars(len(unknown) - unk_gap, unk_gap, "Recovery-copy evidence for both", "No qualifying copy identified"),
               '<p class="ov-unk">No resource is classified as critical or sensitive. Criticality is inferred from tags, names, the account '
               'and usage; the overrides file records which resources are critical.</p>']
    c2.append('<a class="ov-link" href="#sec-under">By recovery scenario</a></div>')
    # ── Card 3: waste (potential overprotection)
    c3 = ['<div class="ov-card pillar"><div class="ov-lens">3 · Waste</div>',
          f'<div class="ov-big">{"up to " if over["annual_usd"] else ""}{_fmt_money(over["annual_usd"])}<small>a year on backups you may not need</small></div>',
          f'<div class="ov-what">{_n(over["items"], "item")} to look at, each counted once</div>',
          # How the figure was estimated, said on the first page so the number is understood where it is read (Alex, 2026-11-17).
          '<p class="ov-est">Estimated from resource sizes at AWS list prices, counting each resource once at its largest estimate. '
          'It is a question for the owner, not a saving.</p>']
    spent = vis["spend_annual"] or 0
    if vis["costs_assessed"] and spent > 0:
        # Two independent figures: the estimate comes from sizes at list prices, not from the bill, so it is not drawn as a share of it.
        c3.append(f'<p class="ov-est">Billed protection spend, for scale: <b>{_fmt_money(spent)}</b> a year (last 30 days times 12). '
                  'The two figures are worked out differently, so one is not a part of the other.</p>')
    c3.append('<a class="ov-link" href="#sec-protection">Spend view</a></div>')
    out.append('<div class="ov-grid ov-pillars">' + "".join(c1) + "".join(c2) + "".join(c3) + '</div>')
    # ── Risk (potential underprotection) by scenario
    out.append('<h3 class="ov-h">Risk, by recovery scenario</h3>')
    out.append('<ol class="actions">')
    for s in under["scenarios"]:
        if s["key"] == "regional":
            continue                    # less prominence by the goal file's rule: one line below
        top = s["reasons"][:2]
        out.append(f'<li class="focus"><div class="focus-n">{s["count"]:,}</div><div class="focus-b"><b>{_esc(s["label"])}</b> '
                   f'<span class="meta">{_esc(s["question"])}</span>'
                   f'<p>{"; ".join(f"{c:,} {_esc(_agree(c, t))}" for t, c in top) or "None of the critical or sensitive resources"}.'
                   + (f' {s["critical_sensitive"]:,} of them {_is(s["critical_sensitive"])} critical and sensitive.' if s["critical_sensitive"] else '')
                   + (f' Plus {s["unknown"]:,} whose criticality is unknown.' if s["unknown"] else '') + '</p>'
                   '<div class="focus-row"><a class="ov-link" href="#sec-under">See them, and the options</a></div></div></li>')
    out.append('</ol>')
    if scen.get("regional") and not pool:
        n_unk = scen["regional"]["unknown"]
        out.append(f'<p class="ov-dr">Regional recovery (losing a whole AWS Region): {n_unk:,} '
                   f'{"resource whose criticality is unknown has" if n_unk == 1 else "resources whose criticality is unknown have"} '
                   f'no copy in another Region. <a href="#sec-under">See them</a></p>')
    elif scen.get("regional"):
        out.append(f'<p class="ov-dr">Regional recovery (losing a whole AWS Region): {scen["regional"]["count"]:,} of {pool:,} critical or '
                   f'sensitive resources {_has(scen["regional"]["count"])} no copy in another Region'
                   + (f', plus {scen["regional"]["unknown"]:,} whose criticality is unknown' if scen["regional"]["unknown"] else '')
                   + '. <a href="#sec-under">See them</a></p>')
    apps = compute_apps_at_risk(res)
    if apps["apps"]:
        out.append(apps_chart_html(apps))
    # Coverage by account is in the Summary, the cost of closing the gap in the Spend view, malware scanning in Backup copy protection and
    # restore granularity in What each mechanism protects against: each is said once, where it belongs.
    # ── Waste (potential overprotection)
    out.append('<h3 class="ov-h">Waste</h3>')
    if not over["rows"]:
        out.append('<p class="ov-none">Nothing to list in what was read.</p>')
    else:
        out.append('<ol class="actions">')
        for row in over["rows"][:_OVER_SHOWN]:
            fig = (f'{"up to" if row["up_to"] else "about"} {_fmt_money(row["annual_usd"])} a year' if row["priced"] else "not priced")
            out.append(f'<li class="focus"><div class="focus-n">{row["count"]:,}</div><div class="focus-b">'
                       f'<b>{_esc(row["label"])}</b> <span class="pill p-warn">{_esc(fig)}</span>'
                       + ('' if row.get("in_headline", True) else
                          ' <em class="meta">not in the Waste figure above (volume storage, not backup spend)</em>')
                       + '<div class="focus-row">' + _estimate_html(row["basis"])
                       + f'<a class="ov-link" href="#{row["where"]}">See them</a></div>'
                       + _waste_fold(row, _WASTE_FOLD_FIRST_PAGE, "The resources behind this", "focus-opt") + '</div></li>')
        out.append('</ol>')
        rest = len(over["rows"]) - _OVER_SHOWN
        if rest > 0:
            out.append(f'<p class="ov-more">{_n(rest, "more item")} in the <a href="#sec-protection">Spend view</a>.</p>')
    # ── What is working, one line
    good = []
    enc = (sec.get("encryption") or {})
    locked = sum(1 for v in vaults if v.get("is_locked"))
    if enc.get("recovery_points") and not enc.get("unencrypted_recovery_points"):
        good.append(f'all {enc["recovery_points"]:,} recovery points encrypted')
    if jobs.get("jobs") and jobs["states"].get("COMPLETED", 0) >= 0.95 * jobs["jobs"]:
        good.append(f'{jobs["states"].get("COMPLETED", 0):,} of {jobs["jobs"]:,} backup jobs completed')
    if acct.get("recoverable"):
        good.append(f'{_n(acct["recoverable"], "resource")} in a logically air-gapped vault')
    if locked:
        good.append(f'{_n(locked, "vault")} with Vault Lock')
    out.append(got_better_line(d.get("drift")))
    if good:
        out.append('<p class="ov-good-line"><b>Working well:</b> ' + "; ".join(good) + '.</p>')
    out.append('<p class="ov-rule">The order is the same in every report: critical and sensitive first, then critical, sensitive, and '
               'criticality unknown. It is not an audit and gives no score. Each figure rests on inferred criticality and estimated cost, for the owner to '
               'confirm. Which to act on is the business\'s decision. Reads AWS Backup and AWS-native protection only. '
               '<a href="#sec-purpose">About this review</a> · <a href="#sec-gaps">Coverage gaps</a></p></section>')
    return out


_TYPE_NOUN = {"AWS::S3::Bucket": "S3 buckets", "AWS::DynamoDB::Table": "DynamoDB tables", "AWS::EC2::Volume": "EBS volumes",
              "AWS::RDS::DBInstance": "RDS instances", "AWS::RDS::DBCluster": "RDS clusters", "AWS::RDS::AuroraCluster": "Aurora clusters",
              "AWS::RDS::NeptuneCluster": "Neptune clusters", "AWS::RDS::DocDBCluster": "DocumentDB clusters"}


def _summary_row_backup_by_type(census: Optional[Dict[str, Any]]) -> List[Tuple[str, str, str]]:
    """One Summary row naming each resource type AWS Backup is read for, so S3 buckets are not left to the detail pages."""
    rows = [r for r in ((census or {}).get("backup_by_type") or []) if r["assessed"] and r["type"] in _TYPE_NOUN]
    if not rows:
        return []
    listing = "; ".join(f"{_TYPE_NOUN[r['type']]} {r['with_recovery_point']:,} of {r['assessed']:,}" for r in rows) + "."
    if any(r["with_recovery_point"] for r in rows):
        covered, exposed = "Resources with an AWS Backup recovery point, by type: " + listing, ""
    else:
        covered, exposed = "", "No resource has an AWS Backup recovery point, by type: " + listing
    s3v = (census or {}).get("s3_backup_versioning") or {}
    if s3v.get("off"):
        exposed = (exposed + f" {s3v['off']:,} of the {s3v['selected']:,} S3 buckets a plan selects {_has(s3v['off'])} versioning off or "
                   f"suspended; AWS Backup for S3 requires it.")
    elif s3v.get("selected"):
        covered = (covered + f" {_all_buckets(s3v['on'], 'S3 bucket')} a plan selects "
                   f"{_has(s3v['on'])} versioning on, which AWS Backup for S3 needs.")
        exposed = (exposed + f" Versioning could not be read for {_n(s3v['unknown'], 'S3 bucket')}.") if s3v.get("unknown") else exposed
    else:
        exposed = exposed + " No S3 bucket is in a backup plan."
    s3c = (census or {}).get("s3_continuous") or {}
    if s3c.get("off"):
        exposed = exposed + (f" {s3c['off']:,} of the {s3c['continuous']:,} S3 buckets backed up continuously {_has(s3c['off'])} "
                             f"EventBridge notifications off, so new changes are not captured for point-in-time restore.")
    return [("AWS Backup by resource type", covered.strip(), exposed.strip())]


def _count(value) -> int:
    """A count that may arrive as a list (the items) or a number."""
    return len(value) if isinstance(value, (list, tuple, set, dict)) else int(value or 0)


def _summary_row_vault_lock(vaults: List[Dict], sec: Optional[Dict] = None) -> Tuple[str, str, str]:
    """Vault Lock by mode.  Governance can be removed by anyone with enough permissions, compliance can still be removed during its
    cooling-off period, and only a compliance lock past it cannot be removed by anyone."""
    area = "Vault Lock"
    if not vaults:
        return (area, "", "No backup vault was read, so nothing is said about Vault Lock.")
    modes: Dict[str, int] = {}
    for v in vaults:
        mode = v.get("vault_lock_mode") or ("governance" if v.get("is_locked") else "none")
        modes[mode] = modes.get(mode, 0) + 1
    locked = len(vaults) - modes.get("none", 0)
    covered, exposed = [], []
    if modes.get("compliance"):
        covered.append(f"{_n(modes['compliance'], 'vault')} in compliance mode past the cooling-off period (or air-gapped): no one can "
                       f"remove the lock or delete copies early.")
    if modes.get("compliance_grace"):
        exposed.append(f"{_n(modes['compliance_grace'], 'vault')} in compliance mode still in the cooling-off period, so the lock can "
                       f"still be removed.")
    if modes.get("governance"):
        exposed.append(f"{_n(modes['governance'], 'vault')} in governance mode, which anyone with enough permissions can remove.")
    if modes.get("none"):
        exposed.append(f"{_n(modes['none'], 'vault')} {_has(modes['none'])} no lock.")
    if locked and not covered:
        covered.append(f"Vault Lock on {locked:,} of {_n(len(vaults), 'vault')}.")
    # A vault access policy that denies deletes guards against the same thing as a lock, so it is said here, beside the lock.
    pol = (sec or {}).get("policies") or {}
    if sec and sec.get("vaults"):
        if not pol.get("readable"):
            exposed.append("No vault access policy was read.")
        elif pol.get("deny_delete"):
            covered.append(f"{pol['deny_delete']:,} of {sec['vaults']:,} vaults {_has(pol['deny_delete'])} an access policy that denies "
                           f"deleting recovery points; unlike a lock, someone with enough permissions can remove the policy.")
    return (area, " ".join(covered), " ".join(exposed))


def _summary_row_backup_encryption(sec) -> Tuple[str, str, str]:
    """Summary row for the encryption of backup copies: whether they are encrypted and whether the key can still decrypt them.
    The vault access policy is said in the Vault Lock row, which covers the same risk (copies deleted early)."""
    area = "Backup encryption"
    if not sec or not sec.get("vaults"):
        return (area, "", "Not assessed: no backup vault was read, so nothing is said about how backup copies are encrypted.")
    enc = sec["encryption"]
    covered, exposed = [], []
    unusable = sum(k["recovery_points"] for k in enc["unusable_keys"])
    if enc["unusable_keys"]:
        exposed.append(f"{unusable:,} recovery {'point depends' if unusable == 1 else 'points depend'} on an encryption key that is "
                       f"disabled or pending deletion, so {'it' if unusable == 1 else 'they'} cannot be restored until the key is usable.")
    if enc["recovery_points"] and enc["unencrypted_recovery_points"]:
        exposed.append(f"{enc['unencrypted_recovery_points']:,} of {enc['recovery_points']:,} recovery points are not encrypted.")
    elif enc["recovery_points"]:
        covered.append("The recovery point is encrypted." if enc["recovery_points"] == 1
                       else f"All {enc['recovery_points']:,} recovery points are encrypted.")
    return (area, " ".join(covered), " ".join(exposed))


def _backup_retention_cell(resources: List[Dict]) -> str:
    """AWS Backup retention is set per plan, so the table says that and shows the range actually in use, not a limit."""
    days = sorted(r["retention_days"] for r in resources if r.get("has_backup_recovery_point") and (r.get("retention_days") or 0) > 0)
    return f"Set per plan ({days[0]:,} to {days[-1]:,} days in use here)" if days else "Set per plan"


def _summary_row_retention(resources: List[Dict]) -> Tuple[str, str, str]:
    """Summary row for how long copies are kept, worked out from the resources: the range of retention found, the databases that
    rely on automated backups (which the service limits to 35 days), and versioned buckets with no expiry rule for old versions."""
    area = "Retention"
    kept = sorted(r["retention_days"] for r in resources if r.get("has_any_protection") and (r.get("retention_days") or 0) > 0)
    covered = (f"Retention read for {_n(len(kept), 'protected resource')}: {kept[0]:,} to {kept[-1]:,} days "
               f"(median {_median(kept):,.0f})." if kept else "")
    capped = sum(1 for r in resources if r.get("has_native_protection") and r.get("native_ceiling_days") == 35
                 and r.get("native_mechanism") in ("rds_automated_backup", "aurora_automated_backup"))
    unbounded = sum(1 for r in resources if r.get("resourceType") == "AWS::S3::Bucket" and r.get("has_native_protection")
                    and not r.get("s3_has_expiry_rule", True))
    parts = []
    if not kept:
        parts.append("No retention period was read for a protected resource.")
    if capped:
        parts.append(f"{_n(capped, 'RDS or Aurora database', 'RDS or Aurora databases')} {'relies' if capped == 1 else 'rely'} only on "
                     f"automated backups, whose retention is capped at 35 days (manual snapshots can be kept longer).")
    if unbounded:
        parts.append(f"{_n(unbounded, 'versioned bucket')} {'has' if unbounded == 1 else 'have'} no expiry rule for old versions, so old versions can accumulate and add storage cost.")
    if kept and not (capped or unbounded):
        covered += " No database is limited to 35 days and no versioned bucket lacks an expiry rule."
    return (area, covered, " ".join(parts))


def _summary_row_operational(acc: Dict, census: Dict, resources: List[Dict], failing: int, alarmed: int,
                             vaults: int) -> Tuple[str, str, str]:
    """Summary row for operational recovery, with the first page's figures: resources with a recovery copy (the accidental-deletion
    scenario) and production resources with none.  The resources without a copy are split into the two kinds the first page's
    count is made of, so "no backup protection identified" and "no recovery copy" are each shown with their own label."""
    area = "Operational recovery"
    total = acc.get("total") or 0
    if not total:
        return (area, "", "Not assessed: no resource could be assessed, so nothing is said about recovery copies.")
    assessed = [r for r in resources if r.get("protection_state") != "not_assessed"]
    without = [r for r in assessed if not r.get("has_any_protection")]
    unprotected = sum(1 for r in without if not r.get("no_backup_path"))
    no_path = len(without) - unprotected
    covered = (f"{acc['recoverable']:,} of {total:,} assessed resources ({acc.get('pct', 0)}%) {_has(acc['recoverable'])} an identified "
               f"recovery copy (an AWS Backup recovery point or a native backup)."
               if acc["recoverable"] else "")
    exposed = []
    if without:
        sentence = (f"{_n(len(without), 'resource')} {_has(len(without))} no recovery copy identified "
                    f"({_fmt_tib(sum(r.get('size_gib', 0) for r in without))}): {unprotected:,} with no backup protection identified"
                    + (" and " + _n(no_path, "Apache Iceberg table") + " with no table-level recovery identified" if no_path else "") + ".")
        # Every production resource with no copy (the Assets table's figure), then the part with no decision on record (the first
        # item in Items to review), so the two reconcile.
        undecided = census.get("no_copy_identified", census.get("strict_no_copy")) or 0
        ps = census.get("production_states") or {}
        prod_none = undecided + ps.get("excluded_documented", 0) + ps.get("no_backup_path", 0)
        if census.get("production") and prod_none:
            sentence += (f" {prod_none:,} of {census['production']:,} production resources {_has(prod_none)} none"
                         + (f", {undecided:,} of them with no decision on record." if undecided != prod_none else "."))
        exposed.append(sentence)
    if census.get("production") and not census.get("no_copy_identified", census.get("strict_no_copy")):
        covered += " No production resource is without one."
    if failing:
        # A failing plan does not remove a copy that still exists, so these overlap the figures above rather than add to them.
        still = sum(1 for r in assessed if r.get("job_failing") and r.get("has_any_protection"))
        exposed.append(f"{_n(failing, 'resource')} in a backup plan {_has(failing)} had no successful job for over "
                       f"{FAILING_JOB_THRESHOLD_DAYS} days" + (f"; {still:,} of them still {_has(still)} an earlier copy, counted above"
                                                               if still else "") + ".")
    if vaults:
        (exposed if alarmed < vaults else []).append(f"Failure notification configuration detected on {alarmed:,} of {_n(vaults, 'vault')}.")
        if alarmed >= vaults:
            covered += f" Failure notification configuration detected on {alarmed:,} of {_n(vaults, 'vault')}."
    return (area, covered.strip(), " ".join(exposed))


def _summary_row_regional(reg: Dict, resources: List[Dict]) -> Tuple[str, str, str]:
    """Summary row for a copy in another Region, with the scenario count the first page shows (any copy in another Region, from
    AWS Backup or an AWS-native mechanism), over the resources that were assessed."""
    area = "Regional recovery"
    total = reg.get("total") or 0
    if not total:
        return (area, "", "Not assessed: no resource could be assessed, so nothing is said about copies in another Region.")
    home = [r for r in resources if r.get("protection_state") != "not_assessed" and not r.get("cross_region_copy")]
    return (area,
            f"{reg['recoverable']:,} of {total:,} assessed resources {_has(reg['recoverable'])} a copy in another Region. Whether a "
            f"regional recovery process works is not assessed." if reg["recoverable"] else "",
            f"{_n(len(home), 'resource')} ({_fmt_tib(sum(r.get('size_gib', 0) for r in home))}) {_has(len(home))} no copy identified in "
            f"another Region."
            if home else "")


def _summary_row_backup_jobs(jobs) -> Tuple[str, str, str]:
    """Summary row for whether backups ran and whether a failure would have been noticed."""
    area = "Backups running"
    if not jobs or not jobs.get("jobs"):
        return (area, "", "No backup job was recorded in the window, so nothing is said about whether scheduled backups ran.")
    done = jobs["states"].get("COMPLETED", 0)
    covered = f"{done:,} of {jobs['jobs']:,} backup jobs in the last {jobs['history_days']} days completed." if done else ""
    if not jobs["known"]:
        return (area, covered, "Not assessed in every account and Region, so these counts are a lower bound.")
    if not jobs["failed"]:
        return (area, (covered + " No backup job failed, expired or was aborted in the window.").strip(), "")
    names = {"FAILED": "failed", "EXPIRED": "expired before starting", "ABORTED": "aborted", "PARTIAL": "partly completed"}
    split = ", ".join(f"{n:,} {names[k]}" for k, n in jobs["states"].items() if k in names and n)
    return (area, covered, f"{jobs['failed']:,} did not complete" + (f" ({split})" if split else "") + f"; "
            f"{jobs['failures_without_alert']:,} of those were in a vault with no failure notification configuration detected "
            f"(a CloudWatch alarm, a vault notification or an EventBridge rule).")


def _summary_row_restores(restore) -> Tuple[str, str, str]:
    """Summary row for what has been restored.  Read from restore history, not assumed."""
    area = "Restores"
    if not restore or not (restore.get("jobs") or restore.get("plans")):
        return (area, "", "No restore job or restore testing plan was recorded, so nothing is said about how long a restore takes.")
    days, jobs = restore["lookback_days"], restore["jobs"]
    plans = _count(restore.get("plans"))
    covered, exposed = [], []
    if restore["succeeded"]:
        covered.append(f"{restore['succeeded']:,} of {jobs:,} restore jobs in the last {days} days completed "
                       f"(and passed validation where one ran).")
    if plans:
        covered.append(f"{_n(plans, 'restore testing plan')} found.")
    else:
        exposed.append("No restore testing plan found.")
    if restore.get("failed"):
        exposed.insert(0, f"{restore['failed']:,} did not succeed. A completed job alone does not show the application works.")
    if not jobs:
        exposed.insert(0, f"No restore job in the last {days} days.")
    return (area, " ".join(covered), " ".join(exposed))


_MATRIX_JOB_APIS = {"jobs": "backup:list_backup_jobs", "restore": "backup:list_restore_jobs"}


def _in_a_plan(r: Dict) -> bool:
    """A plan selects the resource, holds a recovery point for it, or backs it up through the instance it is attached to."""
    return bool(r.get("plan_selected") or r.get("has_backup_recovery_point") or r.get("backup_via_instance"))


def _outside_the_account(r: Dict) -> bool:
    """A copy in another account's vault, or in a logically air-gapped vault (held outside the account's own control)."""
    return bool(r.get("cross_account_copy") or r.get("is_air_gapped"))


def account_control_matrix(resources: List[Dict], accounts: List[Dict], accounts_failed: List[str],
                           gaps: List[Dict], lookback_days: int) -> Dict[str, Any]:
    """One row per account, one cell per control: a count and its denominator, from data already on each resource.

    Denominators are the resources assessed in the account, except the failed-jobs cell (resources with a failed backup job).
    A cell whose jobs could not be read in that account is marked unread, never counted as zero.  An account that could not be
    read at all gets a row that says so and is left out of the totals."""
    unread: Dict[str, set] = {}
    for g in gaps or []:
        if g.get("api") in _MATRIX_JOB_APIS.values():
            unread.setdefault(g.get("account_id", ""), set()).add(g["api"])

    def cell(rows: List[Dict], hit, of: Optional[List[Dict]] = None, read: bool = True) -> Dict[str, Any]:
        pool = rows if of is None else of
        return {"n": sum(1 for r in pool if hit(r)) if read else 0, "of": len(pool) if read else 0, "read": read}

    by_account: Dict[str, List[Dict]] = {}
    for r in resources:
        by_account.setdefault(str(r.get("account_id", "")), []).append(r)
    out_rows: List[Dict[str, Any]] = []
    for acct in sorted(accounts, key=lambda a: str(a.get("name") or a.get("id") or "")):
        mine = by_account.get(str(acct.get("id", "")), [])
        assessed = [r for r in mine if r.get("protection_state") != "not_assessed"]
        missing = unread.get(str(acct.get("id", "")), set()) | unread.get("", set())
        jobs_read = _MATRIX_JOB_APIS["jobs"] not in missing
        restore_read = _MATRIX_JOB_APIS["restore"] not in missing
        failed_jobs = [r for r in assessed if r.get("backup_failures_in_window")]
        out_rows.append({
            "id": acct.get("id", ""), "name": acct.get("name", "") or acct.get("id", ""), "assessed": len(assessed),
            "not_assessed": len(mine) - len(assessed), "state": "assessed",
            "cells": {
                "no_copy": cell(assessed, lambda r: not r.get("has_any_protection")),
                "no_plan": cell(assessed, lambda r: not _in_a_plan(r)),
                "no_region": cell(assessed, lambda r: not r.get("cross_region_copy")),
                "no_outside": cell(assessed, lambda r: not _outside_the_account(r)),
                "unalerted": cell(assessed, lambda r: (r.get("backup_failures_without_alert") or 0) > 0, failed_jobs, jobs_read),
                "restored": cell(assessed, lambda r: bool(r.get("last_successful_restore_at")), None, restore_read),
            }})
    for acct_id in accounts_failed or []:
        out_rows.append({"id": acct_id, "name": acct_id, "assessed": 0, "not_assessed": 0, "state": "not_assessed", "cells": {}})
    totals: Dict[str, Dict[str, Any]] = {}
    keys = ("no_copy", "no_plan", "no_region", "no_outside", "unalerted", "restored")
    live = [r for r in out_rows if r["state"] == "assessed"]
    for k in keys:
        counted = [r["cells"][k] for r in live if r["cells"][k]["read"]]
        totals[k] = {"n": sum(c["n"] for c in counted), "of": sum(c["of"] for c in counted),
                     "read": bool(counted), "accounts_unread": sum(1 for r in live if not r["cells"][k]["read"])}
    return {"rows": out_rows, "totals": totals, "lookback_days": lookback_days,
            "assessed": sum(r["assessed"] for r in live), "not_assessed": sum(r["not_assessed"] for r in live),
            "accounts_failed": len(accounts_failed or [])}


_MATRIX_SHOWN = 5          # accounts shown before the fold; the rest are one click away


def _matrix_cell(c: Dict[str, Any], unread_note: str = "") -> str:
    """One measure in the folded table: the share and the count, as text.  No bar and no colour."""
    if not c["read"]:
        return '<td class="num mx unread" title="Not read in this account">not read</td>'
    if not c["of"]:
        return f'<td class="num mx mx-empty" title="Nothing to count">–{unread_note}</td>'
    share = c["n"] / c["of"]
    return (f'<td class="num mx" title="{c["n"]:,} of {c["of"]:,} ({share:.0%})"><b>{share:.0%}</b>'
            f'<span class="of">{c["n"]:,} of {c["of"]:,}</span>{unread_note}</td>')


def _matrix_gap_cell(c: Dict[str, Any]) -> str:
    """The one figure per account: the share with no recovery copy identified, as one bar in the gap colour."""
    if not c["of"]:
        return '<td class="mx-one mx-empty" title="Nothing to count">–</td>'
    share = c["n"] / c["of"]
    return (f'<td class="mx-one" title="{c["n"]:,} of {c["of"]:,} ({share:.0%})"><span class="mx-bar"><span style="width:{share * 100:.1f}%">'
            f'</span></span><span class="of"><b>{share:.0%}</b> · {c["n"]:,} of {c["of"]:,}</span></td>')


def _matrix_worst_first(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Assessed accounts, the largest share with no recovery copy identified first, then the larger count, then the name."""
    def key(r):
        c = r["cells"]["no_copy"]
        return (not c["of"], -(c["n"] / c["of"]) if c["of"] else 0, -c["n"], str(r["name"]))
    return sorted((r for r in rows if r["state"] == "assessed"), key=key)


def account_matrix_html(m: Dict[str, Any]) -> List[str]:
    """Account by account: one figure per account (no recovery copy identified, the first page's rule), the accounts with the
    largest share first, five shown and the rest folded.  The other measures sit in one fold, as text, with no colour."""
    if not m["rows"]:
        return []
    days = m["lookback_days"]
    heads = (("no_copy", "No recovery copy identified", "of resources assessed"),
             ("no_plan", "Not in a backup plan", "of resources assessed"),
             ("no_region", "No copy in another Region", "of resources assessed"),
             ("no_outside", "No copy outside the account", "of resources assessed"),
             ("unalerted", "Failed jobs with no alert", "of resources with a failed backup job"),
             ("restored", f"Restored in {days} days", "of resources assessed"))
    ranked = _matrix_worst_first(m["rows"])
    unread = [r for r in m["rows"] if r["state"] == "not_assessed"]
    shown, rest = ranked[:_MATRIX_SHOWN], ranked[_MATRIX_SHOWN:]

    def assessed_cell(row):
        extra = f' <em class="meta">+{row["not_assessed"]:,} not assessed</em>' if row["not_assessed"] else ""
        return f'<td class="num">{row["assessed"]:,}{extra}</td>'

    def head_rows(rows):
        return [f'<tr><td class="asset">{_esc(r["name"])}</td>{assessed_cell(r)}{_matrix_gap_cell(r["cells"]["no_copy"])}</tr>' for r in rows]

    def unread_row(r, span):
        return (f'<tr class="unassessed"><td class="asset">{_esc(r["name"])}</td>'
                f'<td colspan="{span}"><em>Not assessed: the account could not be read, so nothing is said about it. '
                f'The reason is in coverage-gaps.csv.</em></td></tr>')

    thead = ('<thead><tr><th>Account</th><th class="num">Assessed</th>'
             '<th>No recovery copy identified</th></tr></thead>')
    out = ['<h4 class="kicker">Account by account</h4>',
           '<p>One figure per account: the share of its resources with no recovery copy identified, the same rule as the first '
           'page. The largest shares come first. The other measures are in the fold below, and every resource is in assets.csv.</p>',
           f'<table class="matrix matrix-head">{thead}<tbody>']
    out += head_rows(shown)
    out += [unread_row(r, 2) for r in unread]
    out.append(f'<tr class="totalrow"><td>All assessed accounts</td><td class="num">{m["assessed"]:,}</td>'
               f'{_matrix_gap_cell(m["totals"]["no_copy"])}</tr>')
    out.append('</tbody></table>')
    if rest:
        out.append(f'<details class="drill own-fold"><summary>{_n(len(rest), "more account")}</summary><div class="drill-body">'
                   f'<table class="matrix matrix-head">{thead}<tbody>' + "".join(head_rows(rest)) + '</tbody></table></div></details>')

    # The other measures, in the same order of accounts, one fold, text only.
    det = ['<details class="drill own-fold"><summary>Other measures by account: backup plan, another Region, outside the account, '
           'failed-job alerts, restores</summary><div class="drill-body">',
           '<div class="table-scroll"><table class="matrix"><thead><tr><th>Account</th><th class="num">Assessed</th>']
    det += [f'<th class="num">{_esc(h)}' + (f'<em class="meta">{_esc(sub)}</em>' if sub != "of resources assessed" else '') + '</th>'
            for _, h, sub in heads]
    det.append('</tr></thead><tbody>')
    for row in ranked:
        det.append(f'<tr><td class="asset">{_esc(row["name"])}</td>{assessed_cell(row)}'
                   + "".join(_matrix_cell(row["cells"][k]) for k, _, _ in heads) + '</tr>')
    det += [unread_row(r, 1 + len(heads)) for r in unread]
    tot = m["totals"]
    cells = []
    for k, _, _ in heads:
        note = (f'<em class="meta">{_n(tot[k]["accounts_unread"], "account")} not read</em>' if tot[k]["accounts_unread"] else "")
        cells.append(_matrix_cell(tot[k], note))
    det.append(f'<tr class="totalrow"><td>All assessed accounts</td><td class="num">{m["assessed"]:,}</td>' + "".join(cells) + '</tr>')
    det.append('</tbody></table></div>')
    det.append('<p class="onepage-note">Each cell is a share of the account\'s resources, with the count under it. "Not in a backup '
               'plan": no plan selects it or holds a recovery point for it, directly or through its instance. "Outside the account": a '
               'copy in another account\'s vault or an air-gapped vault. "Restored" counts something done, so a higher share is the '
               'better one there. Resources not assessed are in no count.</p>')
    det.append('</div></details>')
    out.append("".join(det))
    return out


_WASTE_ITEMS_KEPT = 100      # the resources kept with each Waste item for the folds; the CSV files hold them all


def _waste_resource(r: Dict, annual: Optional[float]) -> Dict[str, Any]:
    return {"name": str(r.get("resourceName") or r.get("resourceId") or ""), "type": str(r.get("resourceType") or "").replace("AWS::", ""),
            "account": str(r.get("account_name") or r.get("account_id") or ""), "region": str(r.get("awsRegion") or ""),
            "gib": round(r.get("size_gib", 0) or 0, 1), "annual": annual}


def _waste_items(entries: List[Dict]) -> List[Dict[str, Any]]:
    """The costliest first (a resource with no price, or no size read, after those that have one), then the largest."""
    ranked = sorted(entries, key=lambda e: (e["annual"] is None, -(e["annual"] or 0), -e["gib"], e["name"]))
    return ranked[:_WASTE_ITEMS_KEPT]


def volume_monthly(r: Dict) -> float:
    """List-rate monthly cost of a volume itself, from its type and provisioned performance.  gp3 when the type was not read."""
    meta = r.get("meta") or {}
    kind = str(meta.get("VolumeType") or r.get("volume_type") or "gp3")
    size = r.get("size_gib", 0) or 0
    cost = size * EBS_VOLUME_RATES.get(kind, EBS_VOLUME_RATES["gp3"])
    iops, tput = int(meta.get("Iops") or 0), int(meta.get("Throughput") or 0)
    if kind in ("io1", "io2"):
        cost += iops * EBS_IOPS_RATES[kind]
    elif kind == "gp3":
        cost += max(0, iops - 3000) * EBS_IOPS_RATES["gp3"] + max(0, tput - 125) * EBS_GP3_THROUGHPUT_RATE
    return cost


def old_snapshot_gib_estimate(r: Dict) -> float:
    """The estimate for a volume's long-retained Standard snapshots: at most one full copy of the volume (its size), or less when
    the snapshots' own sizes add up to less.  Adding each snapshot's volume size would count shared blocks many times over
    (Alex's decision, 2026-11-17: cap the estimate)."""
    total = float(r.get("old_standard_snapshot_gib") or 0)
    size = float(r.get("size_gib") or 0)
    return min(total, size) if size > 0 else total


def ddb_gib_past_target(r: Dict, now: Optional[datetime] = None) -> Optional[float]:
    """GiB of a DynamoDB table's usable recovery points older than its tier's retention target, or None when the table has no tier
    (no target to compare with).  Each DynamoDB backup is a full copy, so its size is what keeping it costs."""
    target = retention_target(r.get("recovery_tier"))
    if not target:
        return None
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=target[1])
    return sum(b for when, b in (r.get("rp_points") or []) if when and _as_dt(when) < cutoff) / 1024 ** 3


def compute_spend_view(resources: List[Dict], orphans: Dict[str, Any], costs: Dict[str, Dict], costs_assessed: bool) -> Dict[str, Any]:
    """The figures that bear on spend, each marked actual or estimated and given its pricing basis.

    Only the protection spend itself is billed cost (Cost Explorer, trailing 30 days).  Every other figure is an estimate worked
    out from resource sizes at the list rates in MECHANISM_RATES, which are AWS list prices and not the customer's rate, so none of them is
    a saving: a copy of a deleted resource may be the only copy left, and a second policy may be deliberate.  A resource with no size
    read adds nothing to a figure, so a figure is a floor on that side; the count of such resources is stated."""
    assessed = [r for r in resources if r.get("protection_state") != "not_assessed"]
    rate = MECHANISM_RATES

    def row(key: str, label: str, rows: List[Dict], monthly: float, basis: str, items: Optional[List[Dict]] = None) -> Dict[str, Any]:
        return {"key": key, "label": label, "count": len(rows), "gib": round(sum(r.get("size_gib", 0) or 0 for r in rows), 1),
                "monthly_usd": round(monthly, 2), "annual_usd": round(monthly * 12, 2), "kind": "estimated", "basis": basis,
                "unsized": sum(1 for r in rows if (r.get("size_gib", 0) or 0) <= 0), "items": _waste_items(items or [])}

    orph = (orphans or {}).get("rows") or []
    spent = sum(i.get("annual", 0) for i in costs.values()) if costs_assessed else 0.0
    dev_days = DEV_LONG_RETENTION_DAYS
    dev_long = [r for r in assessed if r.get("criticality") == "development"
                and ((r.get("retention_days") or 0) > dev_days or r.get("long_term_indefinite"))]
    old_ebs = [r for r in assessed if r.get("resourceType") == "AWS::EC2::Volume" and (r.get("old_standard_snapshot_count") or 0) > 0]
    both = [r for r in assessed if r.get("resourceType") == "AWS::EC2::Volume" and r.get("dlm_policy_id") and r.get("has_backup_recovery_point")]
    detached = [r for r in unmanaged_volumes(resources) if r.get("protection_state") != "not_assessed"]
    gap = [r for r in assessed if not r.get("has_any_protection") and not r.get("no_backup_path")]
    # DynamoDB: AWS Backup has no incremental backup for it (feature-availability table), so every backup is a full copy of the
    # table.  The figure is the backups kept longer than the table's retention target (Alex's decision, 2026-11-17): the copies
    # beyond what the target asks for.  A table with no tier has no target and is not counted.  This row also carries "kept warm
    # past 90 days", which is the same copies seen from the storage tier.
    ddb_past = {id(r): ddb_gib_past_target(r) for r in assessed if r.get("resourceType") == "AWS::DynamoDB::Table"}
    ddb_full = [r for r in assessed if (ddb_past.get(id(r)) or 0) > 0]
    ddb_extra_gib = sum(ddb_past[id(r)] for r in ddb_full)
    ddb_untiered = sum(1 for r in assessed if r.get("resourceType") == "AWS::DynamoDB::Table" and ddb_past.get(id(r)) is None
                       and (r.get("rp_count") or 0) > 1)
    ddb_warm = sum(1 for r in ddb_full if (r.get("warm_long_retention_days") or 0) > 90)
    noncurrent = [r for r in assessed if r.get("resourceType") == "AWS::S3::Bucket" and str(r.get("s3_versioning") or "").lower() == "enabled"
                  and r.get("s3_has_expiry_rule") is False]
    ebs = f"${_rate(rate['ebs_snapshot'])}"
    names = {str(r.get("account_id")): str(r.get("account_name")) for r in resources if r.get("account_id") and r.get("account_name")}
    orph_items = [{"name": str(o.get("id") or ""), "type": str(o.get("kind") or ""),
                   "account": names.get(str(o.get("account_id")), str(o.get("account_id") or "")),
                   "region": str(o.get("region") or ""), "gib": round(o.get("size_gib", 0) or 0, 1),
                   "annual": round(o["monthly_usd"] * 12, 2) if isinstance(o.get("monthly_usd"), (int, float)) else None} for o in orph]
    dev_items = [_waste_resource(r, round(estimate_copy_monthly(r) * 12, 2)) for r in dev_long]
    both_items = [_waste_resource(r, round((r.get("size_gib", 0) or 0) * rate["ebs_snapshot"] * 12, 2)) for r in both]
    detached_items = [_waste_resource(r, round(volume_monthly(r) * 12, 2)) for r in detached]
    ddb_items = [_waste_resource(r, round(ddb_past[id(r)] * rate["dynamodb_ondemand"] * 12, 2)) for r in ddb_full]
    old_items = [{**_waste_resource(r, round(old_snapshot_gib_estimate(r) * rate["ebs_snapshot"] * 12, 2)),
                  "gib": round(old_snapshot_gib_estimate(r), 1)} for r in old_ebs]
    typed = sum(1 for r in detached if (r.get("meta") or {}).get("VolumeType"))
    s3_items = [_waste_resource(r, None) for r in noncurrent]
    rows = {
        "orphans": row("orphans", "Copies whose source was not found in the assessed inventory", orph, (orphans or {}).get("estimated_monthly_usd", 0.0),
                       f"Size times the list rate for the kind of copy (EBS snapshot {ebs}, or ${_rate(rate['ebs_snapshot_archive'])} "
                       f"in the archive tier; AWS Backup recovery point ${_rate(rate['aws_backup_warm'])}, or "
                       f"${_rate(rate['aws_backup_cold'])} in cold storage; database backup ${_rate(rate['rds_backup'])} per GiB-month). "
                       f"Snapshots in the standard tier are incremental, so this is an upper bound. One of these may be the only copy of deleted data, so none is counted as a saving.",
                       orph_items),
        "dev_retention": row("dev_retention", f"Development resources with copies kept more than {dev_days} days", dev_long,
                             sum(estimate_copy_monthly(r) for r in dev_long),
                             (f"In our experience development copies are typically kept around {dev_days} days, though the right period "
                              f"depends on the resources and your own requirements. It is a default you can change "
                              f"(--dev-retention-days or the targets file), not an AWS limit. "
                              if dev_days == DEFAULT_DEV_RETENTION_DAYS else
                              f"{dev_days} days is the limit set for this review (the default is {DEFAULT_DEV_RETENTION_DAYS}). ")
                             + f"The figure is roughly one copy of each at list rates (database backup ${_rate(rate['rds_backup'])}, "
                               f"DynamoDB ${_rate(rate['dynamodb_ondemand'])}, EBS snapshot {ebs} per GiB-month).", dev_items),
        "ebs_both": row("ebs_both", "EBS volumes selected by overlapping backup policies", both,
                        sum((r.get("size_gib", 0) or 0) * rate["ebs_snapshot"] for r in both),
                        f"Size times the EBS snapshot list rate ({ebs} per GiB-month) for one extra copy, an upper bound because snapshots "
                        f"are incremental. Both may be intended, for example for different retention or a different Region.", both_items),
        "unattached": row("unattached", "EBS volumes attached to no instance", detached,
                          sum(volume_monthly(r) for r in detached),
                          f"Size and provisioned performance times the list rate for each volume's own type (gp3 "
                          f"${_rate(EBS_VOLUME_RATES['gp3'])}, gp2 ${_rate(EBS_VOLUME_RATES['gp2'])}, io1 and io2 "
                          f"${_rate(EBS_VOLUME_RATES['io1'])} per GiB-month plus ${_rate(EBS_IOPS_RATES['io1'])} per provisioned IOPS, st1 "
                          f"${_rate(EBS_VOLUME_RATES['st1'])}, sc1 ${_rate(EBS_VOLUME_RATES['sc1'])}). "
                          + (f"The type was read for {typed:,} of {len(detached):,}; the rest are priced as gp3. " if typed < len(detached) else "")
                          + "Billed volume cost is not read. An unattached volume may still be kept on purpose.", detached_items),
        "old_ebs": row("old_ebs", f"Long-retained EBS snapshots still in Standard storage (older than {OLD_SNAPSHOT_DAYS} days)", old_ebs,
                       sum(old_snapshot_gib_estimate(r) * rate["ebs_snapshot"] for r in old_ebs),
                       f"{OLD_SNAPSHOT_DAYS} days is the longest default retention target, a default assumption, not an AWS limit. The figure "
                       f"assumes the old snapshots of a volume hold at most one full copy of it (the volume size, or less when the snapshots "
                       f"are smaller), at the standard rate ({ebs} per GiB-month). Snapshots are incremental and share blocks, so what only "
                       f"the old ones hold is usually less; a volume whose data changes heavily can hold more. Age alone does not make a snapshot waste. Archiving is not priced as a saving: an "
                       f"archived snapshot is a full copy, billed for at least 90 days, and takes up to 72 hours to restore.", old_items),
        "ddb_full_copies": row("ddb_full_copies", "DynamoDB tables with substantial retained full-backup storage", ddb_full,
                               ddb_extra_gib * rate["dynamodb_ondemand"],
                               f"Each DynamoDB backup is a full copy of the table. The figure is the backups kept longer than the table's "
                               f"retention target (default assumptions: 365 days for confidential production data, 90 for other production, "
                               f"{dev_days} for development), at ${_rate(rate['dynamodb_ondemand'])} per GiB-month. Earlier copies may be "
                               f"required for reasons the targets do not capture"
                               + (f"; {_n(ddb_untiered, 'table')} with no inferred environment {'has' if ddb_untiered == 1 else 'have'} no "
                                  f"target and {'is' if ddb_untiered == 1 else 'are'} not counted" if ddb_untiered else "")
                               + (f". {_n(ddb_warm, 'of these tables keeps', 'of these tables keep')} every backup in warm storage for "
                                  f"more than 90 days; cold storage is ${_rate(rate['dynamodb_backup_cold'])}." if ddb_warm else "."), ddb_items),
        "s3_noncurrent": row("s3_noncurrent", "S3 buckets with versioning on and no rule that expires old versions", noncurrent, 0.0,
                             "Not priced: the role does not read how much of a bucket is old versions, and billing does not separate "
                             "them from current data. S3 Storage Lens shows noncurrent bytes where it is turned on.", s3_items),
        "gap": row("gap", "Resources with no backup protection identified: a basic copy", gap,
                   sum(r.get("cost_to_protect_monthly_usd", 0) or 0 for r in gap),
                   f"Size times the list rate for the simplest mechanism for the type (database backup ${_rate(rate['rds_backup'])}, "
                   f"DynamoDB point-in-time recovery ${_rate(rate['dynamodb_pitr'])}, EBS snapshot {ebs}, AWS Backup "
                   f"${_rate(rate['aws_backup_warm'])} per GiB-month). Real cost depends on change rate and retention."),
    }
    # The Waste headline counts each resource once, at the highest estimate any row gives it (Alex's decision, 2026-11-17): a
    # development volume on two policies is one thing to look at, not two.  Copies whose source was not found are not resources in
    # the inventory, so they cannot overlap the rest and are added whole.  Volumes attached to no instance are not backup spend.
    def ident(r: Dict) -> str:
        return str(r.get("arn") or "|".join(str(r.get(k) or "") for k in ("account_id", "awsRegion", "resourceType", "resourceId")))
    per: Dict[str, float] = {}
    for group, value in ((dev_long, lambda r: estimate_copy_monthly(r)),
                         (old_ebs, lambda r: old_snapshot_gib_estimate(r) * rate["ebs_snapshot"]),
                         (noncurrent, lambda r: 0.0),
                         (both, lambda r: (r.get("size_gib", 0) or 0) * rate["ebs_snapshot"]),
                         (ddb_full, lambda r: ddb_past[id(r)] * rate["dynamodb_ondemand"])):
        for r in group:
            k = ident(r)
            per[k] = max(per.get(k, 0.0), value(r) * 12)
    headline = {"annual_usd": round(sum(per.values()) + rows["orphans"]["annual_usd"], 2), "items": len(per) + len(orph),
                "listed": sum(rows[k]["count"] for k in ("dev_retention", "old_ebs", "orphans", "s3_noncurrent", "ebs_both", "ddb_full_copies"))}
    return {"spent_annual": round(spent, 2), "costs_assessed": costs_assessed, "rows": rows, "headline": headline,
            # The order Alex chose (2026-11-17): long-retained copies first, then volumes nobody uses, copies whose source was not
            # found, old S3 versions, overlapping policies and DynamoDB backup methods.
            "look_at": ("dev_retention", "old_ebs", "unattached", "orphans", "s3_noncurrent", "ebs_both", "ddb_full_copies"),
            "closing": ("gap",)}


# Where the full list of an item is, when a fold shows only the first rows.
_WASTE_WHERE = {"orphans": "orphaned-copies.csv", "dev_retention": "assets.csv (criticality = development, retention_days)",
                "ebs_both": "assets.csv (resource_type, dlm_policy_id, has_backup_recovery_point)", "unattached": "assets.csv (unattached = True)",
                "ddb_full_copies": "assets.csv (resource_type, recovery_point_count, retention_days)",
                "old_ebs": "assets.csv (old_standard_snapshot_count, old_standard_snapshot_gib)"}


def _waste_fold(row: Dict[str, Any], limit: int, summary: str, css: str) -> str:
    """A closed fold listing the resources behind one Waste item, the costliest first.  The figure above it is a count and an
    estimate; this is what it is made of.  Names come from AWS, so they are escaped."""
    items = row.get("items") or []
    if not items:
        return ""
    shown = items[:limit]
    body = ['<div class="table-scroll"><table class="compact"><thead><tr><th>Resource</th>'
            '<th class="num">Size</th><th class="num">Per year (estimate)</th></tr></thead><tbody>']
    for it in shown:
        where = " · ".join(x for x in (it["type"], it["region"], it["account"]) if x)       # as the Assets table writes it
        body.append(f'<tr><td class="asset">{_esc(it["name"][:80])}<em>{_esc(where)}</em></td><td class="num">{_fmt_tib(it["gib"])}</td>'
                    f'<td class="num">{_fmt_money(it["annual"]) if it["annual"] is not None else "–"}</td></tr>')
    body.append('</tbody></table></div>')
    if row["count"] > len(shown):
        where = _WASTE_WHERE.get(row["key"])
        body.append(f'<p class="meta">Showing {len(shown):,} of {row["count"]:,}, costliest first.'
                    + (f' All of them: {_esc(where)}.' if where else '') + '</p>')
    inner = "".join(body)
    wrap = f'<div class="drill-body">{inner}</div>' if css == "drill" else f'<div class="waste-body">{inner}</div>'
    return f'<details class="{css} waste-items"><summary>{_esc(summary)}</summary>{wrap}</details>'


_SPEND_UP_TO = ("orphans", "ebs_both")
# Rows listed under Waste whose figure is not in the Waste headline: volume storage is not backup spend, so it is not compared with
# the billed protection spend the headline sits beside.
_SPEND_NOT_IN_HEADLINE = ("unattached",)
_SPEND_NOT_PRICED = ("s3_noncurrent",)       # counted, not priced      # figures that are upper bounds because the copies are incremental


def spend_view_html(sv: Dict[str, Any], money) -> List[str]:
    """Spend to look at, beside the cost of closing gaps.  One table; every figure says whether it is actual or estimated."""
    e = _esc
    out = ['<h4 class="kicker">Spend view</h4>',
           '<p>Protection spend is billed cost. The other figures are estimates from resource sizes at AWS list prices, not your rate. '
           "None is a saving: some copies and policies are deliberate, so each is a question for the owner.</p>",
           '<div class="table-scroll"><table class="compact spend"><thead><tr><th style="width:26%">Item</th><th class="num" style="width:9%">Resources</th>'
           '<th class="num" style="width:10%">Per month</th><th class="num" style="width:10%">Per year</th><th style="width:10%">Actual or estimated</th><th>Pricing basis</th></tr></thead><tbody>']
    if sv["costs_assessed"]:
        out.append('<tr class="spend-now"><td class="asset">Protection spend now</td><td class="num">–</td>'
                   f'<td class="num">{money(sv["spent_annual"] / 12)}</td><td class="num">{money(sv["spent_annual"])}</td><td><span class="pill p-neutral">actual × 12</span></td>'
                   '<td>Billed cost from Cost Explorer for the trailing 30 days, grouped by the mechanism each usage type pays for, times 12.</td></tr>')

    def emit(key: str) -> None:
        r = sv["rows"][key]
        if key in _SPEND_NOT_PRICED:
            out.append(f'<tr><td class="asset">{e(r["label"])}</td><td class="num">{r["count"]:,}</td><td class="num">–</td><td class="num">–</td>'
                       f'<td><span class="pill p-neutral">not priced</span></td><td>{e(r["basis"])}</td></tr>')
            return
        lead = "up to " if key in _SPEND_UP_TO else "about "
        monthly = f'{lead}{_fmt_money(r["monthly_usd"])}' if r["count"] else "–"
        figure = f'{lead}{_fmt_money(r["annual_usd"])}' if r["count"] else "–"
        floor = (f' <em class="meta">{_n(r["unsized"], "resource")} with no size read, not in this figure</em>' if r["count"] and r["unsized"] else "")
        out.append(f'<tr><td class="asset">{e(r["label"])}</td><td class="num">{r["count"]:,}</td><td class="num">{monthly}{floor}</td><td class="num">{figure}</td>'
                   f'<td><span class="pill p-warn">estimated</span></td><td>{e(r["basis"])}</td></tr>')
    out.append("<tr class=\"spend-group\"><td colspan=\"6\">Spend to look at (a decision for each resource's owner)</td></tr>")
    for key in sv["look_at"]:
        emit(key)
    out.append('<tr class="spend-group"><td colspan="6">The cost of closing gaps</td></tr>')
    for key in sv["closing"]:
        emit(key)
    out.append('</tbody></table></div>')
    folds = [_waste_fold(sv["rows"][key], _WASTE_FOLD_SPEND_VIEW, f'{sv["rows"][key]["label"]} ({sv["rows"][key]["count"]:,})', "drill")
             for key in sv["look_at"] if sv["rows"][key]["count"]]
    if any(folds):
        out.append('<h4 class="kicker">The resources behind each item</h4>')
        out.extend(f for f in folds if f)
    return out


def generate_html_report(data: Dict, output_path: str, org_name: str, partner_name: str) -> None:
    d = data
    accounts = d["accounts"]
    all_res = d["resources"]
    vaults = d["vaults"]
    scenarios = d["scenarios"]
    hardening = d["hardening_path"]
    iceberg_tables = d["iceberg_tables"]
    costs = d["costs_by_mechanism"]
    scps = d["scps"]
    org_info = d["org_info"]
    assessed_date = d["assessed_date"]
    accounts_failed = d.get("accounts_failed", [])

    total_resources = len(all_res)
    not_assessed = [r for r in all_res if r.get("protection_state") == "not_assessed"]
    unprotected = [r for r in all_res if not r.get("has_any_protection") and not r.get("no_backup_path")
                   and r.get("protection_state") != "not_assessed"]
    # Resources the scenario and rung percentages are computed over.
    assessed_total = len(all_res) - len(not_assessed)
    no_backup_path = [r for r in all_res if r.get("no_backup_path")]
    over_protected = [r for r in all_res if r.get("over_protected")]
    air_gapped = [r for r in all_res if r.get("is_air_gapped")]
    total_gib = sum(r.get("size_gib", 0) for r in all_res)
    total_spend_annual = sum(costs.get(m, {}).get("annual", 0) for m in costs)
    # --no-cost, or a Cost Explorer call that failed, means spend was not measured. Showing $0 would say
    # protection costs nothing.
    costs_assessed = d.get("costs_assessed", True)

    def money(amount: float) -> str:
        return _fmt_money(amount) if costs_assessed else "not measured"

    # Every spend figure comes from here, so the first page and the cost tab show the same number.
    sv = compute_spend_view(all_res, (d.get("copies") or {}).get("orphans") or {}, costs, costs_assessed)

    org_id = org_info.get("Id", "")
    region_set = {r.get("awsRegion") for r in all_res if r.get("awsRegion") not in ("", "global")}
    num_regions = len(region_set)

    lines = []
    w = lines.append

    w('<!DOCTYPE html><html lang="en"><head>')
    w('<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    w(f'<title>Cloud Data Protection Review · {_esc(org_name)}</title>')
    w(f'<style>{HTML_CSS}</style>')
    w('</head><body><div class="page">')

    # ── Masthead ─────────────────────────────────────────────────────────────
    w('<div class="masthead">')
    w(f'<div class="eyebrow">{"Prepared by " + _esc(partner_name) + " · powered by Commvault" if partner_name else "Powered by Commvault"}</div>')
    w('<div class="eyebrow">Cloud Data Protection Review · Read-only · nothing was deployed, modified, or read at the object level</div>')
    w(f'<h1>{_esc(org_name)}</h1>')
    w(f'<div class="sub">Assessed {assessed_date} · AWS Organization {_esc(org_id)} · {_n(len(accounts), "account")} · {_n(num_regions, "Region")}</div>')
    w('<div class="factbar">')
    w(f'<div><b>{total_resources:,}</b><span>resources</span></div>')
    w(f'<div><b>{_fmt_tib(total_gib)}</b><span>under management</span></div>')
    # The masthead shows the Visibility card's figure (the recovery-evidence state), so the page carries one number for it.
    no_copy_identified = sum(1 for r in all_res if r.get("protection_state") != "not_assessed" and (
        recovery_evidence_of(r) == "none_identified" if (r.get("recovery_evidence") or r.get("recovery_copy_state"))
        else not r.get("has_any_protection")))
    w(f'<div><b>{no_copy_identified:,}</b><span>with no recovery copy identified</span></div>')
    w(f'<div><b>{len(air_gapped)}</b><span>in a logically air-gapped vault</span></div>')
    w(f'<div><b>{money(total_spend_annual)}</b><span>a year on protection (30 days × 12)</span></div>')
    w('</div></div>')  # factbar, masthead
    w('<div class="content">')
    coverage_gaps = d.get("coverage_gaps", [])
    if coverage_gaps or not_assessed:
        gap_scopes = {(g["account_id"], g["region"]) for g in coverage_gaps}
        w('<div class="callout"><h4>Some data could not be read</h4>')
        w((f'<p>{len(coverage_gaps):,} API call(s) across {len(gap_scopes):,} account/Region '
           f'scope(s) were denied or failed, so the counts in this report are a <strong>lower '
           f'bound</strong>: a resource that could not be listed cannot appear as a gap. '
           f'See <em>Coverage gaps</em> before relying on any total.' if coverage_gaps else '<p>')
          + (f' {len(not_assessed):,} resource(s) found nothing protecting them but could not be fully '
             f'assessed; they are shown as <em>not assessed</em>, not as unprotected.' if not_assessed else '')
          + '</p></div>')

    body_start = len(lines)
    # ── Purpose ──────────────────────────────────────────────────────────────
    w('<section><div class="sec-head"><span class="sec-num">Purpose</span><h2>Why this review exists</h2></div>')
    w('<p class="lede">Which resources matter most to the business, what each could recover from, and where protection may fall short or '
      'cost more than it needs to.</p>')
    w('<p>AWS gives you many ways to protect data: automated backups, point-in-time recovery, snapshots, versioning, backup plans, vault locking, air-gapped vaults, cross-Region copies. Each is reasonable on its own. Together they make one question hard to answer from any console: across every account, what is protected, how well, and at what cost?</p>')
    w('<p><strong>Drift is normal when many teams share an estate.</strong> Accounts accumulate, teams set protection for their own '
      'workloads, and sandboxes become production. None of this reflects poorly on anyone; usually no one has had the whole picture at '
      'once.</p>')
    w('<p>This review is that picture: your own metadata, read back in one place and organized around recovery. It is not a score. '
      'Where a finding differs from what you intended, that difference is the useful part.</p>')
    w(f'<p>The report names individual resources only where they are the reason for a finding. All {total_resources:,} are in the '
      f'CSV files for the teams doing the work.</p>')
    w(scope_of_view_callout())
    w('</section>')

    lines.extend(assets_section_html(all_res))
    lines.extend(targets_section_html(all_res, (d.get("inputs") or {}).get("targets_source", "default")))
    lines.extend(inputs_section_html(d.get("inputs") or {}, all_res))
    if d.get("census"):
        lines.extend(census_section_html(d["census"], d.get("drift")))
    if d.get("copies"):
        lines.extend(copies_section_html(d["copies"]))
    lines.extend(security_section_html(d.get("security") or {}, d.get("scps_assessed", True),
                                       malware_line_html(compute_malware_gap(d)),
                                       copy_protection_actions_html(copy_protection_actions(d))))
    lines.extend(backup_jobs_section_html(d.get("backup_jobs") or {}))
    lines.extend(restore_section_html(d.get("restore") or {}, archive_restore_facts(all_res)))
    lines.extend(owners_section_html(d.get("owners") or []))
    lines.extend(questions_section_html(d.get("questions") or []))

    # ── 01 Account table ─────────────────────────────────────────────────────
    w('<section><div class="sec-head"><span class="sec-num">01</span><h2>Where the exposure sits across the estate</h2></div>')
    w('<p>Which accounts hold the gaps, so it is clear who to talk to.</p>')
    # The matrix comes before the first table: the layout keeps a section's introduction and first table open and folds the rest.
    lines.extend(account_matrix_html(account_control_matrix(
        all_res, accounts, accounts_failed, d.get("coverage_gaps", []),
        (d.get("restore") or {}).get("lookback_days") or RESTORE_LOOKBACK_DAYS)))
    w('<h4 class="kicker">Resources, tags and spend by account</h4>')
    w('<table><thead><tr>')
    w('<th style="width:20%">Account</th><th style="width:10%">Org unit</th>')
    w('<th class="num" style="width:8%">Resources</th><th class="num" style="width:8%">Data</th>')
    w('<th class="num" style="width:10%">Tag coverage</th><th class="num" style="width:10%">No protection</th>')
    w('<th class="num" style="width:10%">Sensitive (CONF+)</th><th class="num" style="width:9%">Spend/yr</th>')
    w('</tr></thead><tbody>')

    # Sort accounts by unprotected count desc
    acct_rows = sorted(accounts, key=lambda a: a.get("unprotected_count", 0), reverse=True)
    for acct in acct_rows:
        empty = acct.get("resource_count", 1) == 0
        w(f'<tr><td class="asset">{_esc(acct["name"])}</td>')
        w(f'<td>{_esc(acct.get("ou", ""))}</td>')
        w(f'<td class="num">{acct.get("resource_count", 0):,}'
          + ('<em class="meta">No resources found</em>' if empty else '') + '</td>')
        w(f'<td class="num">{_fmt_tib(acct.get("total_gib", 0))}</td>')
        w(f'<td class="num">{"–" if empty else format(acct.get("tag_coverage_pct", 0), ".0%")}</td>')
        w(f'<td class="num">{acct.get("unprotected_count", 0):,}</td>')
        w(f'<td class="num">{acct.get("conf_plus_count", 0):,}</td>')
        w(f'<td class="num">{money(acct.get("annual_spend", 0))}</td></tr>')

    w(f'<tr class="totalrow"><td>Organization total</td><td></td>')
    w(f'<td class="num">{total_resources:,}</td><td class="num">{_fmt_tib(total_gib)}</td>')
    # The share of resources that carry a tag.  An average of each account's percentage would give a small account the same weight as a large one.
    tagged_total = sum(1 for r in all_res if r.get("tags"))
    tag_cov_all = tagged_total / len(all_res) if all_res else 0
    conf_plus_total = sum(
        1 for r in all_res
        if r.get("data_sensitivity") in ("CONFIDENTIAL", "HIGH_RISK_CONFIDENTIAL")
    )
    w(f'<td class="num">{tag_cov_all:.0%}</td>')
    w(f'<td class="num">{len(unprotected):,}</td><td class="num">{conf_plus_total:,}</td>')
    w(f'<td class="num">{money(total_spend_annual)}</td></tr>')
    w('</tbody></table>')
    w('<div class="callout"><h4>What "Sensitive (CONF+)" means</h4>')
    w('<p><strong>CONF+</strong> means CONFIDENTIAL or HIGH_RISK_CONFIDENTIAL. Sensitivity is inferred from tag keys, tag values and '
      'resource names; no data was read. Where an account has few tags, more of its resources default to INTERNAL than is likely '
      'accurate, so its CONF+ count is a lower bound.</p></div>')

    if accounts_failed:
        w(f'<div class="callout warn"><h4>Accounts where role assumption failed</h4>')
        w(f'<p>{len(accounts_failed)} account(s) could not be read: {_esc(", ".join(accounts_failed[:10]))}. The reason for each is '
          f'in <span class="mono">coverage-gaps.csv</span>; usually the role is not deployed there or does not trust the caller. '
          f'They count as neither protected nor unprotected.</p></div>')

    w('</section>')

    # ── 02 Spend ──────────────────────────────────────────────────────────────
    # One table.  Underprotection has its own section (by recovery scenario), so it is not listed again here with other counts.
    w('<section><div class="sec-head"><span class="sec-num">02</span><h2>What protection costs, and where spend may not be intended</h2></div>')
    lines.extend(spend_view_html(sv, money))
    w(protect_vs_waste_html(all_res, compute_pillars(d, sv)["over"]["annual_usd"]))
    failing_res = [r for r in all_res if r.get("job_failing")]
    locked_count = sum(1 for v in vaults if v.get("is_locked"))
    alarmed_count = sum(1 for v in vaults if is_vault_monitored(v, d.get("vault_alarms", {})))

    # Cost table
    w('<h3 class="kicker">What protection costs today</h3>')
    if costs_assessed:
        w('<p>Actual billed cost from Cost Explorer for the trailing 30 days, grouped by the mechanism each usage type pays for. '
          f'Annualized is that figure times 12, an estimate. List rate is the AWS list price in us-east-1 (checked {PRICES_CHECKED}), not '
          'your negotiated rate; cold storage varies by type (EBS $0.0125, DynamoDB $0.03).</p>')
    else:
        w('<p>Cost was not measured in this run, so no spend figures are shown. Run without <span class="mono">--no-cost</span> '
          'to include them.</p>')
    w('<table><thead><tr><th style="width:34%">Mechanism</th><th class="num" style="width:14%">Protected</th><th class="num" style="width:16%">30-day cost</th><th class="num" style="width:18%">List rate (assumed)</th><th class="num" style="width:18%">Annualized (× 12)</th></tr></thead><tbody>')

    for mech, info in (costs.items() if costs_assessed else []):
        if info.get("monthly", 0) == 0:
            continue
        w(f'<tr><td>{_esc(info.get("label", mech))}</td>')
        # 0 means no resource field tells us the size, not that nothing is protected.
        w(f'<td class="num">{_fmt_tib(info["gib"]) if info.get("gib") else "—"}</td>')
        w(f'<td class="num">{_fmt_money(info.get("monthly", 0))}</td>')
        rate = info.get("rate")
        w(f'<td class="num">{"$" + _rate(rate) if rate else "—"}</td>')
        w(f'<td class="num">{_fmt_money(info.get("annual", 0))}</td></tr>')

    w(f'<tr class="totalrow"><td>Total</td><td></td><td class="num">{money(total_spend_annual/12)}</td><td></td><td class="num">{money(total_spend_annual)}</td></tr>')
    w('</tbody></table></section>')

    # ── 03 Application groups ────────────────────────────────────────────────
    w('<section><div class="sec-head"><span class="sec-num">03</span><h2>Applications: which resources differ from their peers?</h2></div>')
    groups = d.get("app_groups", [])
    w(f'<p>An application is only as recoverable as its least protected component, so resources were grouped and each group is shown with the state of its weakest member. {len(groups)} groups were formed.</p>')
    w('<div class="callout"><h4>Different data often warrants different protection</h4>')
    w('<p>Two things are flagged: a resource with <strong>no recovery point</strong> while its peers have one, and a resource with '
      '<strong>no copy outside the account</strong> while its peers have one. Both are questions, not findings.</p></div>')
    w('<table><thead><tr><th style="width:19%">Application group</th><th style="width:11%">Grouped by</th><th class="num" style="width:8%">Resources</th><th style="width:24%">Weakest member</th><th style="width:22%">Differs from peers</th><th style="width:16%">Exposure</th></tr></thead><tbody>')

    conf_pill = {"high": "good", "medium": "warn", "low": "flag"}
    shown = 0
    for grp in groups[:12]:
        members = grp.get("resource_ids", [])
        method = grp.get("grouping_method", "")
        conf = grp.get("grouping_confidence", "low")
        # Find weakest member
        member_resources = [r for r in all_res
                            if r.get("arn") in members or r.get("resourceId") in members]
        unprotected_members = [r for r in member_resources if not r.get("has_any_protection")]
        no_cross = [r for r in member_resources if not r.get("cross_region_copy") and
                    any(m.get("cross_region_copy") for m in member_resources)]

        if not member_resources:
            continue

        weakest = unprotected_members[0] if unprotected_members else member_resources[0]
        wname = weakest.get("resourceName") or weakest.get("resourceId", "?")
        wtype = weakest.get("resourceType", "").split("::")[-1]
        if unprotected_members:
            wdesc = "No recovery point exists"
            exposure_label, exposure_kind = "Confirm criticality", "flag"
        elif no_cross:
            wdesc = "No copy outside the account while peers do"
            exposure_label, exposure_kind = "Confirm intent", "warn"
        else:
            wdesc = "No peer differences found"
            exposure_label, exposure_kind = "No finding", "neutral"

        peer_diff = ""
        if conf in ("high",) and unprotected_members:
            peer_diff = f"{len(unprotected_members)} of {len(member_resources)} have no recovery point while peers do"
        elif conf in ("high",) and no_cross:
            peer_diff = f"{len(no_cross)} of {len(member_resources)} have no copy outside the account while peers do"
        elif conf == "high":
            peer_diff = "None. Members are consistent with each other"
        else:
            peer_diff = '<span class="none">Not assessed</span>'

        w(f'<tr><td class="asset">{_esc(grp["name"])}</td>')
        w(f'<td>{_pill(method, conf_pill.get(conf, "neutral"))}</td>')
        w(f'<td class="num">{len(member_resources)}</td>')
        w(f'<td class="mono">{_esc(wname)} ({wtype})<em>{_esc(wdesc)}</em></td>')
        w(f'<td>{peer_diff}</td>')
        w(f'<td>{_pill(exposure_label, exposure_kind)}</td></tr>')
        shown += 1

    if len(groups) > shown:
        w(f'<tr class="rest"><td colspan="6">{len(groups) - shown} further groups in the companion CSV.</td></tr>')
    w('</tbody></table></section>')

    # ── 04 Mechanisms and scenarios ──────────────────────────────────────────
    w('<section><div class="sec-head"><span class="sec-num">04</span><h2>What each mechanism protects against</h2></div>')
    w('<p>For each mechanism: how long it can keep copies, where they sit, and what it cannot withstand. These are properties of the '
      'mechanism, not of how it is set up.</p>')
    lines.extend(recovery_granularity_html(all_res))
    w('<table><thead><tr><th style="width:18%">Mechanism</th><th style="width:13%">Applied to</th><th style="width:13%">Retention ceiling</th><th style="width:18%">Where the copy lives</th><th style="width:38%">What it does not withstand</th></tr></thead><tbody>')

    rds_count = sum(1 for r in all_res if "RDS" in r.get("resourceType","") and r.get("has_native_protection"))
    ddb_pitr_count = sum(1 for r in all_res if "DynamoDB" in r.get("resourceType","") and r.get("has_native_protection"))
    ebs_count = sum(1 for r in all_res if "EC2::Volume" in r.get("resourceType","") and r.get("has_native_protection"))
    s3_v_count = sum(1 for r in all_res if r.get("resourceType","") == "AWS::S3::Bucket" and r.get("has_native_protection"))
    backup_count = sum(1 for r in all_res if r.get("has_backup_recovery_point"))
    xr_count = sum(1 for r in all_res if r.get("cross_region_copy") and r.get("has_backup_recovery_point"))
    ag_count = sum(1 for r in all_res if r.get("is_air_gapped"))
    archived_vols = sum(1 for r in all_res if r.get("archived_snapshot_count"))

    mechs = [
        ("RDS / Aurora automated backups", _n(rds_count, "database"), "Up to 35 days (configurable)", "Same account and Region",
         "Region loss, account compromise, deletion of the source instance"),
        ("DynamoDB point-in-time recovery", f"{ddb_pitr_count} of {sum(1 for r in all_res if 'DynamoDB' in r.get('resourceType',''))} tables", "Up to 35 days (configurable)", "Same account and Region",
         "Region loss, account compromise. Deleting the table keeps a final backup for 35 days"),
        ("EBS snapshots (DLM)", _n(ebs_count, "volume"), "Configured per policy", "Same account and Region",
         "Region loss, account compromise"),
    ] + ([
        ("EBS Snapshots Archive", _n(archived_vols, "volume"), "At least 90 days; up to 72 hours to restore to the standard tier",
         "Same account and Region", "Region loss, account compromise. Each archived snapshot is a full copy, and a restore waits for it")
    ] if archived_vols else []) + [
        ("S3 versioning", f"{s3_v_count} of {sum(1 for r in all_res if r.get('resourceType','') == 'AWS::S3::Bucket')} buckets", "Lifecycle rules only", "Same bucket",
         "Bucket deletion, Region loss, account compromise"),
        ("AWS Backup vault (standard)", f"{backup_count:,} across {_n(len(vaults), 'vault')}", _backup_retention_cell(all_res), "Same account and Region",
         f"Vault Lock on {locked_count} of {len(vaults)}. In the other {len(vaults)-locked_count}, recovery points can be deleted by any principal with backup permissions"),
        ("AWS Backup cross-Region copy", _n(xr_count, "resource"), "Inherits plan", "Second Region, same account",
         "Account compromise, since the copy stays inside the same identity boundary"),
        ("Logically air-gapped vault", _n(ag_count, "resource"), "Compliance-mode locked", "Held by AWS apart from your accounts; shared for recovery through AWS RAM",
         "None of the above. Recovery after losing the account needs the vault shared to an account you still control"),
    ]
    for m in mechs:
        w(f'<tr><td class="asset">{_esc(m[0])}</td><td>{_esc(m[1])}</td><td>{_esc(m[2])}</td><td>{_esc(m[3])}</td><td>{_esc(m[4])}</td></tr>')
    w('</tbody></table>')

    # Air-gapped callout
    if ag_count > 0:
        w('<div class="callout good"><h4>✓ Logically air-gapped vault</h4>')
        cmk = sum(1 for v in vaults if v.get("is_air_gapped") and v.get("EncryptionKeyType") == "CUSTOMER_MANAGED_KMS_KEY")
        w(f'<p>{_n(ag_count, "resource has", "resources have")} copies in a logically air-gapped vault. AWS keeps it in a '
          f'service-owned account, always locked in compliance mode, so no credential in the source account, root included, can delete '
          f'its recovery points or shorten their retention. Restoring after losing this account needs the vault shared to an account '
          f'you still control (AWS RAM) or multi-party approval, set up beforehand; this review does not confirm either.'
          + (f' {_n(cmk, "air-gapped vault uses", "air-gapped vaults use")} a customer-managed key, so a restore also depends on that key '
             f'being usable.' if cmk else '') + '</p></div>')

    # What each failure would leave is shown once, in Risk, by recovery scenario; failing jobs are in Backups and restores.
    sc = scenarios
    acc = sc.get("accidental", {})
    reg = sc.get("regional", {})
    w('</section>')

    # ── 05 Hardening path ────────────────────────────────────────────────────
    w('<section><div class="sec-head"><span class="sec-num">05</span><h2>Where this organization sits on the hardening path</h2></div>')
    w('<p>Each rung addresses a different threat. The thresholds are common starting points, not requirements.</p>')
    w('<div class="ladder">')
    status_pill_map = {"good": "p-good", "warn": "p-warn", "flag": "p-flag"}
    for rung in hardening:
        pill_class = status_pill_map.get(rung["status"], "p-neutral")
        w(f'<div class="rung"><span class="n">{_esc(rung["n"])}</span>')
        w(f'<div><h5>{_esc(rung["title"])}</h5><p>{_esc(rung["desc"])}</p></div>')
        w(f'<div class="state"><span class="pill {pill_class}">{_esc(rung["state"])}</span></div></div>')
    w('</div>')
    w('<p class="meta">Rungs 6 and 7 are for resources that must survive losing a whole account: a scoping decision, not a target '
      'for every resource. The per-resource checks are in <span class="mono">assets.csv</span> '
      '(<span class="mono">posture_violations</span>).</p>')
    w('</section>')

    # ── 06 Summary ───────────────────────────────────────────────────────────
    prod_res = [r for r in all_res if r.get("criticality") == "production"]
    w('<section><div class="sec-head"><span class="sec-num">06</span><h2>Where you are covered, and where you are exposed</h2></div>')
    w('<p>Area by area: ✓ is in place, ! is a gap. What each failure would leave is in <a href="#sec-under">Risk, by recovery '
      'scenario</a>; the decisions are in <a href="#sec-questions">Items to review</a>.</p>')
    # What each failure would leave is in Risk, by recovery scenario, and coverage by account is on the Executive Summary (compact) and
    # in Recovery copies (account by account): neither is repeated here.
    # The rows follow the first page: operational recovery, then cyber recovery, then Regional recovery and the rest.  Each figure is
    # the one the first page shows (the scenario counts over assessed resources), so a number means one thing wherever it appears.
    summary_rows = [
        _summary_row_operational(acc, d.get("census") or {}, all_res, len(failing_res), alarmed_count, len(vaults)),
        _summary_row_backup_jobs(d.get("backup_jobs")),
        _summary_row_restores(d.get("restore")),
        *_summary_row_backup_by_type(d.get("census")),
        _summary_row_credential_compromise(sc.get("credential_compromise") or {}, ag_count, assessed_total, scps, d.get("scps_assessed", True),
                                           all_res),
        _summary_row_vault_lock(vaults, d.get("security")),
        _summary_row_backup_encryption(d.get("security")),
        _summary_row_regional(reg, all_res),
        _summary_row_retention(all_res),
        ("Classification",
         f"{tagged_total:,} of {len(all_res):,} resources ({tag_cov_all:.0%}) carry at least one tag." if tagged_total else "",
         "Tags may not say who owns a resource or how critical it is. Where tags are sparse, production is inferred with less confidence."),
    ]
    # The area cards repeat figures the Executive Summary, Risk and Backup copy protection show, so they sit behind one fold; the chart
    # above stays in view (Alex's decision, 2026-11-17).
    w(f'<details class="drill sum-fold"><summary>Area by area: what is in place and what is a gap ({len(summary_rows)} areas)</summary>'
      '<div class="drill-body">')
    w('<div class="sum-grid">')
    for area, covered, exposed in summary_rows:
        ok = f'<p class="sum-ok"><span aria-hidden="true">✓</span> {_esc(covered)}</p>' if covered else ''
        gap = f'<p class="sum-gap"><span aria-hidden="true">!</span> {_esc(exposed)}</p>' if exposed else ''
        w(f'<div class="sum-card"><h5>{_esc(area)}</h5>{ok}{gap}</div>')
    w('</div>')
    w('</div></details>')
    w('</section>')
    compact_charts = coverage_by_account_chart(all_res, max_accounts=5, table_view=False) + scenario_chart(sc, table_view=False)
    prepared = (f'Prepared for {org_name}' + (f' by {partner_name}' if partner_name else '') + f' · assessed {assessed_date}')
    pillars = compute_pillars(d, sv)
    lines.extend(overview_section_html(d, money, sv, prepared, compact_charts, pillars))
    lines.extend(underprotection_section_html(pillars, sc))

    # ── Appendix ─────────────────────────────────────────────────────────────
    # ── Coverage gaps ────────────────────────────────────────────────────────
    w('<section><div class="sec-head"><span class="sec-num">Gaps</span><h2>Coverage gaps: what this review could not see</h2></div>')
    if not coverage_gaps:
        w('<p>Every API call made during collection succeeded, so no scope was skipped.</p>')
    else:
        w('<p>These calls were denied or failed. Each one is a place where resources may exist that '
          'this report does not count. Once the missing permission is granted (or the connectivity restored), a re-run '
          'closes the gap. The full list is in <span class="mono">coverage-gaps.csv</span>.</p>')
        by_scope: Dict[Tuple[str, str], List[Dict]] = {}
        for g in coverage_gaps:
            by_scope.setdefault((g["account_id"], g["region"]), []).append(g)
        w('<table><thead><tr><th style="width:18%">Account</th><th style="width:14%">Region</th>'
          '<th style="width:10%">Calls</th><th style="width:58%">What failed</th></tr></thead><tbody>')
        for (acct, region), rows in sorted(by_scope.items())[:60]:
            sample = "; ".join(f"{g['api']} ({g['status']})" for g in rows[:4])
            more = f" and {len(rows) - 4} more" if len(rows) > 4 else ""
            w(f'<tr><td class="mono">{_esc(acct)}</td><td class="mono">{_esc(region or "-")}</td>'
              f'<td>{len(rows)}</td><td class="mono">{_esc(sample + more)}</td></tr>')
        w('</tbody></table>')
        if len(by_scope) > 60:
            w(f'<p>{len(by_scope) - 60} more scope(s) are in the CSV.</p>')
    w('</section>')

    w('<section><div class="sec-head"><span class="sec-num">A</span><h2>Appendix: how this was collected</h2></div>')
    w('<p>Every figure maps to a read-only API call made under an assumed IAM role. No object data, table item, or database record was read at any point.</p>')
    w('<p>The role is deployed by CloudFormation (one stack, or a StackSet across the organization), with an ExternalId on its trust '
      'policy. Accounts where it could not be assumed are listed under Coverage gaps.</p>')
    w('<table><thead><tr><th style="width:22%">Finding</th><th style="width:78%">Source API</th></tr></thead><tbody>')
    for finding, actions, note in API_CALLS_BY_FINDING:
        apis = format_actions(actions) + (f" ({note})" if note else "")
        w(f'<tr><td class="asset">{_esc(finding)}</td><td class="mono">{_esc(apis)}</td></tr>')
    w('</tbody></table>')
    lines.extend(regions_appendix_html(d.get("regions") or []))
    w('<div class="callout"><h4>Explicitly not requested by the collector role</h4>')
    w('<p><span class="mono">s3:GetObject</span>, <span class="mono">dynamodb:GetItem</span>, <span class="mono">dynamodb:Scan</span>, <span class="mono">dynamodb:Query</span>, <span class="mono">rds:DownloadDBLogFilePortion</span>, <span class="mono">kms:Decrypt</span>, or any write, delete, or modify action against any service.</p></div>')
    w('</section>')

    lines[body_start:] = [_arrange_report_body("\n".join(lines[body_start:]))]

    w('</div>')  # close .content

    # ── Footer ────────────────────────────────────────────────────────────────
    w('<footer>')
    w(f'<p><strong>Companion files:</strong> <span class="mono">assets.csv</span> contains all {total_resources:,} resources with account, group, criticality confidence, protection state, retention, copy location, lock state, and monthly cost. <span class="mono">proposed-groups.csv</span> lists all {len(groups)} groups in editable form.</p>')
    w(f'<p>Cloud Data Protection Review · Prepared by {_esc(partner_name)} · {assessed_date}</p>')
    w('</footer>')

    w(f'<script>{_REPORT_SCRIPT}</script>')
    w('</div></body></html>')

    Path(output_path).write_text(_tidy_counts("\n".join(lines)), encoding="utf-8")
    log(f"Report written → {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# CSV output
# ─────────────────────────────────────────────────────────────────────────────

def generate_assets_csv(resources: List[Dict], output_path: str) -> None:
    fields = [
        "account_id", "account_name", "region", "resource_type", "resource_id",
        "resource_name", "arn", "size_gib", "criticality", "criticality_confidence",
        "data_sensitivity", "data_classes",
        "recovery_evidence", "evidence_badges", "copy_freshness",
        "protection_state", "has_any_protection", "has_native_protection",
        "has_backup_recovery_point", "listed_without_usable_point", "backup_evidence_unverified", "no_backup_path", "job_failing", "consecutive_failures",
        "is_air_gapped", "vault_locked", "vault_lock_mode",
        "cross_region_copy", "cross_account_copy", "cross_account_configured", "recovery_point_count",
        "retention_days", "short_window_days", "long_term_days", "long_term_indefinite", "observed_oldest_days", "over_protected", "posture_violations",
        "group", "grouping_method", "monthly_cost_usd", "cost_to_protect_monthly_usd",
        "hosts_iceberg", "size_measured",
        "plan_selected", "selection_match_reason", "matching_plan_names", "same_plan_scope", "plans_in_same_scope",
        "recovery_without_selection", "backup_via_instance", "copy_scope", "dlm_policy_id", "assessment_blockers",
        "backup_opted_in", "opt_in_skipped", "copy_withheld_reason",
        "criticality_basis", "criticality_reason", "sensitivity_basis",
        "owner_hint", "owner_basis", "behaviour_signals", "tag_behaviour_mismatch", "copy_regions", "copy_geographies",
        "backup_jobs_in_window", "backup_failures_in_window", "backup_success_rate", "last_successful_backup_job_at",
        "last_backup_failure_at", "last_backup_failure_state", "last_backup_failure_reason", "latest_backup_failed",
        "backup_failures_without_alert", "copy_jobs_in_window", "copy_failures_in_window", "copy_gap_destinations", "last_copy_failure_reason",
        "tag_count", "has_tags", "has_environment_tag", "has_owner_tag", "tag_keys",
        "restore_jobs_in_window", "last_successful_restore_at", "last_restore_duration_minutes", "restore_success_rate",
        "restore_within_rto", "restore_from_copy", "restore_estimate_minutes", "restore_test_selected",
        "deletion_protection", "object_lock", "mfa_delete", "s3_versioning", "s3_eventbridge", "s3_continuous_backup", "survives_deletion", "deletion_exposed", "unattached",
        "unmanaged_data",
        "recovery_copy_state", "policy_assigned", "last_recovery_point_at", "last_native_snapshot_at",
        "archived_snapshot_count", "old_standard_snapshot_count", "old_standard_snapshot_gib", "rp_cold_count",
        "copy_age_hours", "recovery_tier", "retention_vs_target", "rpo_hours", "backup_interval_hours", "frequency_exceeds_rpo",
        "created_at", "age_days",
        "exclusion_status", "exclusion_reason", "exclusion_owner", "exclusion_review_date", "exclusion_source",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for r in resources:
            row = {k: r.get(k, "") for k in fields}
            # Resource records use camelCase keys; the CSV columns are snake_case.
            row["region"] = r.get("awsRegion", "")
            row["retention_vs_target"] = retention_vs_target(r)
            row["criticality_reason"] = criticality_reason(r)
            row["resource_type"] = r.get("resourceType", "")
            row["resource_id"] = r.get("resourceId", "")
            row["resource_name"] = r.get("resourceName", "")
            writer.writerow({k: csv_safe(v) for k, v in row.items()})
    log(f"Assets CSV written → {output_path}")


def generate_exclusion_worksheet(resources: List[Dict], output_path: str) -> int:
    """One row per production resource with no recovery copy and no recorded decision, with blank decision
    columns.  Fill it in and pass it back with --overrides; the column names match that file."""
    rows = [r for r in resources if r.get("criticality") == "production"
            and r.get("recovery_copy_state") in ("none", "policy_only")]
    fields = ["arn", "account_id", "resource_type", "region", "recovery_copy_state", "criticality", "data_sensitivity",
              "excluded", "reason", "owner", "review_date"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            row = {"arn": r.get("arn", ""), "account_id": r.get("account_id", ""),
                   "resource_type": r.get("resourceType", ""), "region": r.get("awsRegion", ""),
                   "recovery_copy_state": r.get("recovery_copy_state", ""), "criticality": r.get("criticality", ""),
                   "data_sensitivity": r.get("data_sensitivity", ""), "excluded": "", "reason": "", "owner": "",
                   "review_date": ""}
            writer.writerow({k: csv_safe(v) for k, v in row.items()})
    return len(rows)


def generate_orphans_csv(orphans: Dict[str, Any], output_path: str) -> None:
    fields = ["account_id", "region", "kind", "id", "source", "size_gib", "created", "age_days", "copies", "held",
              "monthly_usd"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in orphans["rows"]:
            writer.writerow({k: csv_safe(row.get(k, "")) for k in fields})


def generate_shared_backups_csv(exposure: Dict[str, Any], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["account_id", "region", "kind", "id", "visible_to", "accounts"])
        for group, visible in (("public_ebs_snapshots", "any AWS account"), ("public_images", "any AWS account"),
                               ("rds_public", "any AWS account"), ("rds_shared", "listed accounts")):
            for item in exposure[group]:
                writer.writerow([csv_safe(item["account_id"]), csv_safe(item["region"]), csv_safe(item["kind"]),
                                 csv_safe(item["id"]), visible, csv_safe(" ".join(item.get("accounts", [])))])


def generate_vault_security_csv(vaults: List[Dict], key_info: Dict[str, Dict], known_accounts: set, output_path: str) -> None:
    fields = ["account_id", "region", "vault", "lock_mode", "air_gapped", "key_kind", "key_state", "recovery_points",
              "unencrypted_recovery_points", "policy_state", "policy_denies", "policy_other_accounts",
              "policy_any_principal", "scanned_recovery_points", "recovery_points_with_malware"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for v in vaults:
            stats = v.get("rp_stats") or {}
            pol = vault_policy_findings(v, known_accounts | {v.get("account_id", "")})
            states = sorted({(key_info.get(k) or {}).get("state", "") for k in
                             ([v.get("EncryptionKeyArn")] + list((stats.get("by_key") or {}))) if k} - {""})
            row = {"account_id": v.get("account_id", ""), "region": v.get("region", ""), "vault": v.get("BackupVaultName", ""),
                   "lock_mode": v.get("vault_lock_mode", ""), "air_gapped": v.get("is_air_gapped", False),
                   "key_kind": classify_vault_key(v, key_info), "key_state": "|".join(states),
                   "recovery_points": stats.get("total", 0), "unencrypted_recovery_points": stats.get("unencrypted", 0),
                   "policy_state": pol["state"], "policy_denies": "|".join(a.split(":")[1] for a in pol["denied"]),
                   "policy_other_accounts": " ".join(pol["external"]), "policy_any_principal": pol["any_principal"],
                   "scanned_recovery_points": stats.get("scanned", 0), "recovery_points_with_malware": stats.get("scan_malware", 0)}
            writer.writerow({k: csv_safe(val) for k, val in row.items()})


def generate_owners_csv(owners: List[Dict], output_path: str) -> None:
    fields = ["owner", "basis", "resources", "production", "no_copy", "policy_only_or_stale", "not_assessed",
              "deletion_exposed", "unmanaged_volumes"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in owners:
            writer.writerow({k: csv_safe(row.get(k, "")) for k in fields})


def generate_changes_csv(drift: Dict[str, Any], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["change", "identifier"])
        for label, key in (("now has no copy, previously covered", "regressions"), ("now has no copy, new or uncounted", "new_gaps"),
                           ("gained a copy", "closed_gaps"), ("backup plan no longer present", "plans_removed"),
                           ("vault lock weakened", "vault_locks_weakened"), ("vault no longer present", "vaults_gone")):
            for item in drift[key]:
                writer.writerow([label, csv_safe(item)])


def generate_coverage_gaps_csv(gaps: List[Dict], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["account_id", "region", "api", "subject", "status"])
        writer.writeheader()
        writer.writerows([{k: csv_safe(v) for k, v in g.items()} for g in gaps])
    log(f"Coverage gaps CSV written → {output_path}")


def generate_groups_csv(groups: List[Dict], resources: List[Dict], output_path: str) -> None:
    """The proposed application groups, limited to resources that are in the inventory.  A CloudFormation stack also holds roles,
    policies and other things the review does not assess, and a group with none of the inventory in it proposes nothing to
    confirm, so those ids and groups are left out (the Applications section still sees the full groups)."""
    inventory = {v for r in resources for v in (r.get("arn"), r.get("resourceId"), r.get("resourceName")) if v}
    kept = 0
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["group_name", "grouping_method", "grouping_confidence",
                          "account_id", "resource_count", "resource_ids"])
        for g in groups:
            ids = [rid for rid in g.get("resource_ids", []) if rid in inventory]
            if not ids:
                continue
            kept += 1
            writer.writerow([csv_safe(v) for v in [
                g.get("name", ""),
                g.get("grouping_method", ""),
                g.get("grouping_confidence", ""),
                g.get("account_id", ""),
                len(ids),
                "|".join(ids),
            ]])
    log(f"Groups CSV written → {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Per-account collection orchestration
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Preflight: verify access before committing to a full run
# ─────────────────────────────────────────────────────────────────────────────

PREFLIGHT_CHECKS = [
    # (label, service, method, kwargs, required_for)
    ("Resource tagging",        "resourcegroupstaggingapi", "get_resources",      {"ResourcesPerPage": 1}, "inventory"),
    ("RDS / Aurora",            "rds",                      "describe_db_instances", {"MaxRecords": 20},   "inventory"),
    ("DynamoDB",                "dynamodb",                 "list_tables",        {"Limit": 1},            "inventory"),
    ("EBS volumes",             "ec2",                      "describe_volumes",   {"MaxResults": 5},       "inventory"),
    ("S3 buckets",              "s3",                       "list_buckets",       {},                      "inventory"),
    ("AWS Backup plans",        "backup",                   "list_backup_plans",  {},                      "protection state"),
    ("AWS Backup vaults",       "backup",                   "list_backup_vaults", {},                      "vault lock and air-gap detection"),
    ("AWS Backup jobs",         "backup",                   "list_backup_jobs",   {"MaxResults": 1},       "silent failure detection"),
    ("Protected resources",     "backup",                   "list_protected_resources", {},                "coverage analysis"),
    ("RAM shares",              "ram",                      "get_resource_shares", {"resourceOwner": "OTHER-ACCOUNTS"}, "air-gapped vault verification"),
    ("CloudWatch alarms",       "cloudwatch",               "describe_alarms",    {"MaxRecords": 1},       "backup alarm coverage"),
    ("CloudWatch metrics",      "cloudwatch",               "list_metrics",       {},                      "S3 size and object counts"),
    ("CloudFormation stacks",   "cloudformation",           "list_stacks",        {},                      "application grouping"),
    ("Glue catalog",            "glue",                     "get_databases",      {"MaxResults": 1},       "Iceberg detection"),
    ("Cost Explorer",           "ce",                       "get_dimension_values",
        {"TimePeriod": {"Start": (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d"),
                        "End": datetime.now(timezone.utc).strftime("%Y-%m-%d")},
         "Dimension": "SERVICE"}, "cost and over-protection analysis"),
]

OPTIONAL_CHECKS = {"Cost Explorer", "Glue catalog", "RAM shares", "CloudFormation stacks"}


def run_preflight(session: boto3.Session, region: str, account_id: str) -> bool:
    """
    Call one cheap, harmless API per permission group and report what works.
    Returns True when nothing essential is missing.
    """
    print()
    print(f"  Preflight against account {account_id} in {region}")
    print("  " + "─" * 68)

    ok, degraded, blocked = [], [], []

    for label, service, method, kwargs, required_for in PREFLIGHT_CHECKS:
        svc_region = "us-east-1" if service == "ce" else region
        try:
            client = session.client(service, region_name=svc_region)
            getattr(client, method)(**kwargs)
            ok.append(label)
            print(f"  \033[32m  ok\033[0m  {label}")
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                        "AuthFailure", "SubscriptionRequiredException"):
                if label in OPTIONAL_CHECKS:
                    degraded.append((label, required_for))
                    print(f"  \033[33mskip\033[0m  {label:<24} {required_for} will be omitted")
                else:
                    blocked.append((label, required_for))
                    print(f"  \033[31mFAIL\033[0m  {label:<24} {required_for} unavailable")
            else:
                # Service not enabled, no resources, or similar. Not a permission problem.
                ok.append(label)
                print(f"  \033[32m  ok\033[0m  {label} (no data: {code})")
        except Exception as e:
            degraded.append((label, required_for))
            print(f"  \033[33mskip\033[0m  {label:<24} {type(e).__name__}")

    print("  " + "─" * 68)
    print(f"  {len(ok)} working, {len(degraded)} degraded, {len(blocked)} blocked")

    if blocked:
        print()
        print("  Blocked permissions will leave gaps in the report:")
        for label, why in blocked:
            print(f"    - {label}: {why}")
        print()
        print("  Redeploy the CloudFormation template, or update the existing stack, then")
        print("  wait a minute for IAM to propagate and re-run --preflight.")
        return False

    if degraded:
        print()
        print("  The run will work but these sections will be omitted:")
        for label, why in degraded:
            print(f"    - {why} (needs {label})")

    print()
    print("  Ready. Re-run without --preflight to collect.")
    return True


def get_enabled_regions(session: boto3.Session, fallback: List[str],
                        probe_region: str = "us-east-1") -> List[str]:
    """Regions the account can use: opt-in-not-required plus opted-in.

    Falls back to the static list if the call fails, and says so in the ledger rather
    than quietly scanning a stale list.
    """
    try:
        ec2 = make_client(session, "ec2", probe_region)
        resp = ec2.describe_regions(Filters=[
            {"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
        regions = sorted(r["RegionName"] for r in resp.get("Regions", []))
        if regions:
            return regions
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        status = _gap_status(e) or "Error"
        record_gap(probe_region, "ec2:describe_regions", status)
        warn(f"Could not list enabled Regions ({status}); using the default set")
    return list(fallback)


# Probing must fail fast: an unreachable Region would otherwise stall for minutes on the
# default 60s timeouts and 6 adaptive retries, per call.
_PROBE_CONFIG = BotocoreConfig(connect_timeout=5, read_timeout=15,
                               retries={"max_attempts": 2, "mode": "standard"})
# Glue and S3 Tables are probed only to catch a Region holding nothing but Iceberg tables.  Where the service has no endpoint the call
# just waits, so these get a short timeout: a Region that is merely slow costs seconds, not a minute.
_FAST_PROBE_SERVICES = frozenset({"glue", "s3tables"})
_FAST_PROBE_CONFIG = BotocoreConfig(connect_timeout=3, read_timeout=5, retries={"max_attempts": 1, "mode": "standard"})
_NETWORK_ERRORS = (
    botocore.exceptions.ConnectTimeoutError, botocore.exceptions.ReadTimeoutError,
    botocore.exceptions.EndpointConnectionError, botocore.exceptions.SSLError,
)

# (service, method, kwargs, result key).  Anything that holds data we inventory.
_REGION_PROBES = (
    ("ec2", "describe_volumes", {"MaxResults": 5}, "Volumes"),
    ("rds", "describe_db_instances", {"MaxRecords": 20}, "DBInstances"),
    ("rds", "describe_db_clusters", {"MaxRecords": 20}, "DBClusters"),
    ("dynamodb", "list_tables", {"Limit": 5}, "TableNames"),
    ("backup", "list_backup_plans", {"MaxResults": 5}, "BackupPlansList"),
    ("backup", "list_backup_vaults", {"MaxResults": 5}, "BackupVaultList"),
    ("glue", "get_databases", {"MaxResults": 5}, "DatabaseList"),
    ("s3tables", "list_table_buckets", {"maxBuckets": 5}, "tableBuckets"),
)


def _probe_region(session: boto3.Session, region: str) -> str:
    """Return 'active', 'empty' or 'failed' for one region.

    'failed' means every probe call errored, so we do not know what is there.  That is
    different from 'empty' and is recorded as a coverage gap.
    """
    answered = 0
    found = False
    for service, method, kwargs, key in _REGION_PROBES:
        try:
            client = make_client(session, service, region, config=_FAST_PROBE_CONFIG if service in _FAST_PROBE_SERVICES else _PROBE_CONFIG)
            items = getattr(client, method)(**kwargs).get(key) or []
            if service == "backup" and method == "list_backup_vaults":
                # Every account tends to carry an empty Default vault, and that is not data. But a
                # cross-Region copy can land in the Default vault of a Region that has nothing
                # else, and that Region is exactly where the evidence of the copy is.
                items = [v for v in items
                         if v.get("BackupVaultName") != "Default" or v.get("NumberOfRecoveryPoints", 0) > 0]
            if service == "glue":
                # Athena creates a database called "default" in the Glue catalog on first use; an empty one is not data.
                items = [d for d in items if d.get("Name") != "default"]
            answered += 1
            if items:
                found = True
                break
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            status = _gap_status(e)
            if status:
                record_gap(region, f"{service}:{method}", status)
            if isinstance(e, _NETWORK_ERRORS):
                break       # the endpoint is unreachable; the other services will be too
    if found:
        return "active"
    return "empty" if answered else "failed"


def discover_active_regions(session: boto3.Session, candidates: List[str],
                            max_workers: int = 16, report: Optional[Dict[str, List[str]]] = None) -> List[str]:
    """
    Narrow the candidate regions to those that hold something worth scanning.
    Scanning empty regions is the biggest waste of wall-clock time on a first run.
    Regions that could not be probed at all are NOT treated as empty: they are
    recorded in the coverage ledger and left out of the scan.
    """
    account_id = getattr(_ledger_ctx, "account_id", "")

    def probe(region: str) -> Tuple[str, str]:
        set_ledger_account(account_id)      # worker threads do not inherit the context
        return region, _probe_region(session, region)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        states = dict(pool.map(probe, candidates))
    for region, state in states.items():
        if state == "failed":
            record_gap(region, "region:skipped", "Unreachable")
    active = [r for r in candidates if states.get(r) == "active"]
    if report is not None:
        report["candidates"] = list(candidates)
        report["active"] = list(active)
        report["empty"] = [r for r in candidates if states.get(r) == "empty"]
        report["unreachable"] = [r for r in candidates if states.get(r) == "failed"]
    return active or candidates[:1]


def resolve_regions(
    session: boto3.Session,
    explicit: Optional[List[str]],
    all_regions: bool,
    auto_regions: bool,
    primary_region: str = "us-east-1",
    report: Optional[Dict[str, List[str]]] = None,
) -> List[str]:
    """Decide which regions to scan for one account.

    --regions        scan exactly these.
    --all-regions    every enabled region (ignores --regions).
    --auto-regions   probe the candidates and keep those holding data; combines with
                     either of the above.
    (nothing given)  probe every enabled region.  No fixed list can be right for every
                     account, and a fixed list silently misses data elsewhere.
    """
    if explicit and not all_regions:
        candidates = list(explicit)
    else:
        candidates = get_enabled_regions(session, DEFAULT_REGIONS, primary_region)
    probe = auto_regions or (not explicit and not all_regions)
    if probe and len(candidates) > 1:
        return discover_active_regions(session, candidates, report=report)
    if report is not None:
        report.update({"candidates": list(candidates), "active": list(candidates), "empty": [], "unreachable": []})
    return candidates


def copy_destination_regions(plans: List[Dict], account_id: str, scanned: List[str]) -> List[str]:
    """Regions in this account that backup plans copy into, and that are not scanned yet.

    A disaster-recovery Region often holds only recovery points, so the probe may call it empty.
    Its vaults are still where the evidence of a cross-Region copy lives.  Destinations in other
    accounts are read when that account is scanned.
    """
    found = {d.get("region") for plan in plans for d in plan.get("copy_destinations", [])
             if d.get("account_id") == account_id and d.get("region")}
    return sorted(found - set(scanned))


def merge_backup_states(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    """Combine backup state collected for two sets of Regions."""
    merged = dict(base)
    for key, value in extra.items():
        current = merged.get(key)
        if isinstance(value, list):
            merged[key] = list(current or []) + value
        elif key == "recovery_points":
            merged[key] = merge_recovery_points([current or {}, value])
        elif key == "governance_known":
            merged[key] = bool(current if current is not None else True) and value
        elif key == "legal_holds_known":
            merged[key] = bool(current if current is not None else True) and value      # any unread Region makes it unknown
        elif key == "resource_vault_map":
            # Same merge as the organization-wide map: strongest lock mode, summed counts, and the
            # accounts and Regions the copies sit in.
            merged[key] = merge_vault_maps([current or {}, value])
        elif isinstance(value, dict):
            merged[key] = {**(current or {}), **value}
        elif isinstance(value, bool):
            merged[key] = bool(current) or value
        else:
            merged[key] = value
    return merged


def collect_backup_with_copy_regions(session: boto3.Session, account_id: str,
                                     regions: List[str]) -> Dict[str, Any]:
    """Backup state for the scanned Regions plus the Regions their plans copy into."""
    state = collect_backup_state(session, account_id, regions)
    extra = copy_destination_regions(state.get("plans", []), account_id, regions)
    if extra:
        log(f"  {account_id}: reading backup state in copy-destination Region(s): {', '.join(extra)}")
        state = merge_backup_states(state, collect_backup_state(session, account_id, extra))
        state["copy_destination_regions"] = extra
    return state


def collect_account(
    account: Dict,
    sts_client,
    role_name: str,
    external_id: str,
    region_request: Dict[str, Any],
    primary_region: str,
    role_arn: Optional[str] = None,
    direct_session: Optional[boto3.Session] = None,
    deep: bool = False,
) -> Optional[Dict]:
    account_id = account["Id"]
    account_name = account.get("Name", account_id)
    set_ledger_account(account_id)
    log(f"Collecting {account_name} ({account_id}) …")

    if direct_session is not None:
        session = direct_session
    else:
        session = assume_role(sts_client, account_id, role_name, external_id,
                              primary_region, role_arn=role_arn)
    if not session:
        return None

    region_report: Dict[str, List[str]] = {}
    regions = resolve_regions(session, region_request.get("explicit"),
                              region_request.get("all_regions", False),
                              region_request.get("auto_regions", False),
                              primary_region, report=region_report)
    log(f"  {account_id}: scanning {len(regions)} Region(s): {', '.join(regions)}")

    resources = collect_resources(session, account_id, regions)
    native_state = collect_native_mechanisms(session, account_id, regions, deep=deep)
    backup_state = collect_backup_with_copy_regions(session, account_id, regions)
    app_groups = get_application_groups(session, account_id, regions, resources)
    iceberg_tables = collect_iceberg_tables(session, account_id, regions)
    s3_sizes = collect_s3_sizes(session)

    return {
        "account_id": account_id,
        "account_name": account_name,
        "ou": account.get("OUName", ""),
        "ou_path": account.get("OUPath", account.get("OUName", "")),
        "ou_chain": account.get("OUChain", []),
        "regions": regions,
        "region_report": region_report,
        "resources": resources,
        "native_state": native_state,
        "backup_state": backup_state,
        "app_groups": app_groups,
        "iceberg_tables": iceberg_tables,
        "s3_sizes": s3_sizes,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def _configure_console() -> None:
    """Make progress output safe on consoles whose default encoding is not UTF-8.

    The collector prints box-drawing characters.  On Windows the default console
    encoding (cp1252) cannot encode them and the run dies with UnicodeEncodeError
    before any work is done.  Replace unencodable characters instead of crashing.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def build_parser() -> argparse.ArgumentParser:
    """The command line, built apart from main() so tests can check every documented command."""
    # allow_abbrev=False: argparse otherwise reads an unknown flag that is a prefix of a real one (for
    # example --org for --org-name) as that flag, and the run fails with a confusing message.
    parser = argparse.ArgumentParser(
        description="Cloud Data Protection Collector — generates a protection review report.",
        allow_abbrev=False,
    )
    parser.add_argument("--external-id",   default="",     help="ExternalId on the IAM role trust policy. Not needed with --use-current-credentials")
    parser.add_argument("--role-name",     default=DEFAULT_ROLE_NAME, help="IAM role name in each account")
    parser.add_argument("--regions",       nargs="+", default=None,
                        help="AWS regions to scan. Default: every enabled Region, probed so only "
                             "those holding resources are scanned")
    parser.add_argument("--output-dir",    default="./output", help="Directory to write report and CSVs")
    parser.add_argument("--org-name",      default="Your Organization", help="Customer or org display name")
    parser.add_argument("--partner-name",  default="", help="Partner or preparer name for the footer")
    parser.add_argument("--profile",       default=None, help="AWS CLI profile for the management account")
    parser.add_argument("--single-account", action="store_true", help="Run against the current account only")
    parser.add_argument("--max-workers",   type=int, default=8, help="Accounts scanned at once")
    parser.add_argument("--region-workers", type=int, default=REGION_WORKERS,
                        help="Regions scanned at once within each account. Lower it if AWS throttles "
                             "the run; 1 scans one Region at a time")
    parser.add_argument("--item-workers",  type=int, default=ITEM_WORKERS,
                        help="Buckets or tables read at once within each Region")
    parser.add_argument("--role-arn",      default=None,
                        help="Full ARN of the collector role. Overrides --role-name. With --single-account it is the one role assumed. In an organization run give the management account's role: it lists the organization and reads costs, and its name is assumed in every member account")
    parser.add_argument("--use-current-credentials", action="store_true",
                        help="Skip AssumeRole entirely and use your current credentials. "
                             "For sandbox testing where you already have read access")
    parser.add_argument("--org-with-current-credentials", action="store_true",
                        help="Organization run for an account that cannot have a collector role: list the organization with your "
                             "own credentials (it needs read access to AWS Organizations; Cost Explorer and the organization's "
                             "policies are read the same way) and assume the collector role only in the member accounts. The "
                             "management account is then not assessed, because it has no role. The usual way is a role there. "
                             "With --accounts, an identity that cannot read the organization (a reviewer role in another "
                             "account) still works: the accounts named are assessed")
    parser.add_argument("--sso-profile",   default=None, metavar="PROFILE",
                        help="Read every account through IAM Identity Center instead of sts:AssumeRole, for organizations that do not "
                             "allow role assumption. PROFILE is your AWS CLI profile for IAM Identity Center (aws configure sso), signed "
                             "in with aws sso login. Each account is read with the permission set named by --sso-permission-set, in every "
                             "account where it is assigned to you. No --external-id is needed")
    parser.add_argument("--sso-permission-set", default=DEFAULT_ROLE_NAME, metavar="NAME",
                        help="With --sso-profile: the reviewer permission set to read each account with (default: %(default)s)")
    parser.add_argument("--accounts",      nargs="+", default=None, metavar="ID",
                        help="Organization runs: assess only these member accounts (12-digit IDs, separated by spaces or commas). "
                             "For a rollout where the role is in some accounts only. The others are left out and the report says how many. "
                             "If your credentials cannot read the organization (a reviewer role in a separate account, for example), "
                             "these accounts are assessed directly, and OUs, SCPs, costs and multi-party approval are reported as not assessed")
    parser.add_argument("--dev-retention-days", type=int, default=DEV_LONG_RETENTION_DAYS, metavar="DAYS",
                        help="Development copies kept longer than this are listed as potential overprotection (default "
                             f"{DEV_LONG_RETENTION_DAYS}, a default assumption, not an AWS limit)")
    parser.add_argument("--account-names", default=None, metavar="FILE",
                        help="A file with one '12-digit account ID,name' pair per line. The report shows the name instead of the bare "
                             "ID, for runs where the organization is not read and accounts would otherwise be numbers only")
    parser.add_argument("--overrides",     default=None, metavar="FILE",
                        help="CSV or JSON file, keyed by resource ARN, that corrects the inferred "
                             "criticality, data_sensitivity or tier and records documented exclusions "
                             "(excluded, reason, owner, review_date)")
    parser.add_argument("--recovery-targets", default=None, metavar="FILE",
                        help="JSON file that sets the recovery targets by tier, for example "
                             "{\"1\": {\"rpo_hours\": 1, \"rto_hours\": 4, \"min_retention_days\": 90}, "
                             "\"3\": {\"max_retention_days\": 35}}. Tiers 1 and 2 take min_retention_days, tier 3 max_retention_days. "
                             "Anything left out keeps its default")
    parser.add_argument("--redact", action="store_true",
                        help="Replace account, resource, vault and plan names and IDs in every file the run writes with stable "
                             "labels, so a real run can be shown to others. Counts and structure stay real. The --org-name you "
                             "give is shown as given, and console output is not redacted")
    parser.add_argument("--redact-key", default=None, metavar="FILE",
                        help="With --redact, also write the labels and the originals to this CSV. It holds the real names: keep it "
                             "away from the redacted report")
    parser.add_argument("--baseline",      default=None, metavar="FILE",
                        help="assessment.json from a previous run. The report then lists what changed since")
    parser.add_argument("--job-history-days", type=int, default=JOB_HISTORY_DAYS,
                        help="How many days of backup and copy jobs to report on (default 30)")
    parser.add_argument("--restore-lookback-days", type=int, default=RESTORE_LOOKBACK_DAYS,
                        help="How many days of restore jobs to read (default 90)")
    parser.add_argument("--exclusion-tag-prefix", default=EXCLUSION_TAG_PREFIX,
                        help="Tag key prefix that records a decision not to protect a resource: "
                             "<prefix>reason, <prefix>owner, <prefix>review-date")
    parser.add_argument("--preflight",     action="store_true",
                        help="Check permissions and exit without collecting anything")
    parser.add_argument("--all-regions",   action="store_true",
                        help="Scan every enabled Region, without probing for resources first")
    parser.add_argument("--auto-regions",  action="store_true",
                        help="Probe the candidate Regions and scan only those holding resources. "
                             "Combine with --all-regions or --regions to probe that set")
    parser.add_argument("--no-cost",       action="store_true",
                        help="Skip Cost Explorer. Avoids the $0.01-per-request charge and the spend sections")
    parser.add_argument("--deep",          action="store_true",
                        help="Enable deeper (and costlier) checks such as DynamoDB CloudWatch write-rate metrics")
    return parser


# The oldest boto3 the collector has been run on.  AWS CloudShell ships this version or a newer one, so nothing needs installing there.
MIN_BOTO3 = (1, 43, 83)


def boto3_is_too_old(version: str, minimum: Tuple[int, ...] = MIN_BOTO3) -> bool:
    """True when `version` is older than the oldest tested one.  A version this cannot read is not called too old."""
    parts = []
    for piece in version.split(".")[:len(minimum)]:
        digits = re.match(r"\d+", piece)
        if not digits:
            return False
        parts.append(int(digits.group(0)))
    return tuple(parts) < tuple(minimum)


def main() -> None:
    _configure_console()
    if boto3_is_too_old(boto3.__version__):
        needed = ".".join(str(n) for n in MIN_BOTO3)
        print(f"\nThis machine has boto3 {boto3.__version__}; the collector needs {needed} or newer, because older versions "
              f"do not know some of the AWS calls it makes.\nInstall the pinned libraries with: pip3 install -r requirements.txt\n"
              f"(AWS CloudShell already has a new enough boto3, so nothing needs installing there.)\n")
        sys.exit(2)
    args = build_parser().parse_args()
    args.role_name = args.role_name or DEFAULT_ROLE_NAME      # the guide passes "$ROLE", which is empty in a new shell
    set_parallelism(args.region_workers, args.item_workers)
    global RESTORE_LOOKBACK_DAYS, JOB_HISTORY_DAYS, DEV_LONG_RETENTION_DAYS
    DEV_LONG_RETENTION_DAYS = max(1, args.dev_retention_days)
    for control in DEFAULT_POSTURE_CONTROLS:
        if control["name"] == "DevOverprotection":
            control["max_retention_days"] = DEV_LONG_RETENTION_DAYS
    RESTORE_LOOKBACK_DAYS = max(1, args.restore_lookback_days)
    JOB_HISTORY_DAYS = max(1, args.job_history_days)
    try:
        overrides = load_overrides(args.overrides) if args.overrides else {}
        baseline = load_baseline(args.baseline) if args.baseline else None
        account_names = load_account_names(args.account_names) if args.account_names else {}
        if args.recovery_targets:
            apply_recovery_targets(load_recovery_targets(args.recovery_targets), _basename(args.recovery_targets))
    except ValueError as e:                  # fail before any AWS call, with the file and line
        print(f"\n  {e}\n")
        sys.exit(2)

    if args.sso_profile and (args.use_current_credentials or args.single_account or args.role_arn
                             or args.org_with_current_credentials or args.profile):
        print("\n  --sso-profile reads each account through IAM Identity Center. It cannot be combined with --single-account, "
              "--role-arn, --profile, --use-current-credentials or --org-with-current-credentials (use --accounts to pick "
              "accounts).\n")
        sys.exit(2)
    if args.sso_profile:
        args.profile = args.sso_profile
    if args.org_with_current_credentials and (args.use_current_credentials or args.single_account or args.role_arn):
        print("\n  --org-with-current-credentials runs a whole organization. It cannot be combined with --single-account, "
              "--role-arn or --use-current-credentials.\n")
        sys.exit(2)
    if args.accounts is not None:
        args.accounts = [a for chunk in args.accounts for a in chunk.replace(",", " ").split()]
        bad = [a for a in args.accounts if not re.fullmatch(r"[0-9]{12}", a)]
        if bad or not args.accounts or args.single_account or args.use_current_credentials:
            print("\n  --accounts takes 12-digit account IDs and applies to an organization run, so it cannot be combined "
                  "with --single-account or --use-current-credentials."
                  + (f" Not an account ID: {', '.join(bad[:5])}" if bad else "") + "\n")
            sys.exit(2)
    if args.use_current_credentials:
        args.single_account = True

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    reset_coverage_ledger()

    assessed_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    t_start = time.time()

    # Management account session
    try:
        mgmt_session = boto3.Session(profile_name=args.profile)
        sts = mgmt_session.client("sts")
        caller = sts.get_caller_identity()
    except botocore.exceptions.NoCredentialsError:
        print("\nNo AWS credentials found. Configure them with 'aws configure', or set "
              "AWS_PROFILE, then try again.\n")
        sys.exit(2)
    except botocore.exceptions.ClientError as e:
        print(f"\nYour credentials were rejected: {e.response['Error']['Code']}. "
              "Refresh them and try again.\n")
        sys.exit(2)
    except botocore.exceptions.BotoCoreError as e:
        # For example an IAM Identity Center profile whose sign-in has expired.  The type is enough; the text may hold paths.
        print(f"\nYour credentials could not be loaded ({type(e).__name__}). If you sign in through IAM Identity Center, "
              f"run: aws sso login --profile {args.profile or 'default'}\n")
        sys.exit(2)

    log(f"Running as {caller['Arn']}")
    sso_accounts: List[Dict] = []
    sso_sessions: Dict[str, boto3.Session] = {}
    if args.sso_profile:
        try:
            portal, sso_token = sso_sign_in(mgmt_session)
            sso_accounts, sso_sessions = sso_account_sessions(portal, sso_token, args.sso_permission_set,
                                                              args.regions[0] if args.regions else (mgmt_session.region_name or "us-east-1"))
        except SSOSignInError as e:
            print(f"\n{e}\n")
            sys.exit(2)
        except _AWS_ERRORS as e:
            print(f"\nThe IAM Identity Center access portal could not be read ({type(e).__name__}). Sign in again with "
                  f"aws sso login --profile {args.sso_profile} and retry.\n")
            sys.exit(2)
        if args.accounts:
            sso_sessions = {a: v for a, v in sso_sessions.items() if a in set(args.accounts)}
        log(f"IAM Identity Center: {len(sso_accounts)} account(s) open to you; the permission set "
            f"{args.sso_permission_set} is assigned to you in {len(sso_sessions)}")
        if not sso_sessions:
            print(f"\nThe permission set {args.sso_permission_set} is not assigned to you in any account"
                  + (" named with --accounts" if args.accounts else "") + ". An IAM Identity Center administrator assigns it "
                  "(see the guide's Organization section, \"No sts:AssumeRole\"). If it has another name, pass "
                  "--sso-permission-set NAME.\n")
            sys.exit(1)
    if not args.role_arn and not args.use_current_credentials and not args.org_with_current_credentials and not args.sso_profile:
        # The role the stack creates, in the account you are signed in to: the guide's commands need no ARN.
        partition = caller["Arn"].split(":")[1] or "aws"
        args.role_arn = f"arn:{partition}:iam::{caller['Account']}:role/{args.role_name}"

    primary_region = args.regions[0] if args.regions else (
        mgmt_session.region_name or "us-east-1")
    region_request = {"explicit": args.regions, "all_regions": args.all_regions,
                      "auto_regions": args.auto_regions}

    # ── Preflight ────────────────────────────────────────────────────────────
    if args.preflight:
        # --accounts with an identity that cannot read the organization (a reviewer role in a separate account, for
        # example): the accounts named are the ones assessed, so the check probes those.
        listed_without_org = bool(args.accounts) and not args.sso_profile and not args.role_arn and not organization_reachable(mgmt_session)
        if args.sso_profile:
            probe_account = sorted(sso_sessions)[0]
            probe_session = sso_sessions[probe_account]
            log(f"Using the permission set {args.sso_permission_set} in {probe_account} "
                f"({len(sso_sessions)} account(s) have it; no sts:AssumeRole is used)")
            if organization_reachable(mgmt_session):
                log("Your sign-in can also list the organization, so account names, OUs, policies and costs will be read")
            else:
                log("Your sign-in cannot list the organization, so organization-wide figures will be reported as not assessed")
        elif args.org_with_current_credentials or listed_without_org:
            if listed_without_org:
                members = list(dict.fromkeys(args.accounts))
            else:
                if not organization_reachable(mgmt_session):
                    print("\nPreflight stopped: your credentials cannot list the organization (AWS Organizations ListAccounts), "
                          "or this account has none.\n")
                    sys.exit(1)
                members = [a["Id"] for a in get_org_accounts(mgmt_session) if a["Id"] != caller["Account"]]
                if args.accounts:
                    members = [m for m in members if m in set(args.accounts)]
            if not members:
                print("\nPreflight stopped: the organization has no member account to assess.\n")
                sys.exit(1)
            # The roles may be in only some of the members, so the first account without one is not a failure.
            probe_session, probe_account, tried = None, "", 0
            for member in members:
                tried += 1
                probe_session = assume_role(sts, member, args.role_name, args.external_id, primary_region, hint=False)
                if probe_session:
                    probe_account = member
                    break
            if not probe_session:
                print(f"\nPreflight stopped: the collector role could not be assumed in any of the {tried} member account(s) tried "
                      f"(of {len(members)}). Either the role is not deployed in them, or it does not trust you.\n"
                      "Check where it is deployed with the StackSet's instance list, and compare the ExternalId and TrustedPrincipalArn.\n")
                sys.exit(1)
            listed = (f"Using the {len(members)} account(s) given with --accounts (your credentials cannot list the organization)"
                      if listed_without_org else f"Listed the organization with your credentials ({len(members) + 1} accounts)")
            log(f"{listed}; the role could be assumed in {probe_account} (after {tried - 1} account(s) without a usable role)"
                if tried > 1 else f"{listed}; the role could be assumed in {probe_account}")
        elif args.use_current_credentials:
            probe_session = mgmt_session
            probe_account = caller["Account"]
        else:
            target = args.role_arn or f"arn:aws:iam::{caller['Account']}:role/{args.role_name}"
            probe_account = target.split(":")[4]
            probe_session = assume_role(sts, probe_account, args.role_name,
                                        args.external_id, primary_region,
                                        role_arn=target)
            if not probe_session:
                print("\nPreflight stopped: could not assume the collector role.\n")
                sys.exit(1)
            log(f"Assumed {target}")
        ok = run_preflight(probe_session, primary_region, probe_account)
        sys.exit(0 if ok else 1)

    # ── Discover org and accounts ────────────────────────────────────────────
    # `reader` makes the account-wide reads (organization, costs, SCPs, multi-party approval).  It is the collector
    # role whenever one is in use, so those calls hold only what the role allows; it is the caller's own credentials
    # only when the caller asked for that (--use-current-credentials) or gave no role to assume.
    reader = mgmt_session
    explicit_accounts = False       # True when the accounts came from --accounts because the organization could not be read
    org_read = True          # False when the organization itself is not read (an IAM Identity Center run without it)
    if args.sso_profile:
        mgmt_account_id = caller["Account"]
        if organization_reachable(mgmt_session):
            # The organization is listed with your own sign-in, as with --org-with-current-credentials, so accounts keep
            # their names and OUs and the organization's policies and costs are read.  Each account is still read only
            # with the reviewer permission set.
            log("Discovering organization accounts with your sign-in …")
            org_info = get_org_info(mgmt_session)
            accounts = get_org_accounts(mgmt_session) or [dict(a, OUName="", OUChain=[]) for a in sso_accounts]
        else:
            org_read = False
            org_info = {}
            accounts = [dict(a, OUName="", OUChain=[]) for a in sso_accounts]
            log("Your sign-in cannot list the organization, so the accounts are the ones the access portal offers you. "
                "Organization-wide policies and costs are reported as not assessed.")
    elif args.single_account:
        target_account = args.role_arn.split(":")[4] if args.role_arn else caller["Account"]
        accounts = [{"Id": target_account, "Name": "current-account", "OUName": "", "OUChain": []}]
        org_info = {}
        if not args.use_current_credentials:
            reader = assume_role(sts, target_account, args.role_name, args.external_id, primary_region,
                                 role_arn=args.role_arn) or mgmt_session
    else:
        mgmt_account_id = caller["Account"]
        if args.role_arn:
            # The guide's organization path gives the management account's role.  That role reads the organization
            # and the costs, and its name is the one assumed in every member account.  Passing the ARN on to each
            # account would read the management account once for every name in the organization.
            org_role_name = args.role_arn.rsplit("/", 1)[-1]
            mgmt_account_id = args.role_arn.split(":")[4]
            org_session = assume_role(sts, mgmt_account_id, org_role_name, args.external_id, primary_region,
                                      role_arn=args.role_arn)
            if not org_session:
                print("\nCould not assume the role in the management account, so the organization cannot be read.\n"
                      "AWS answers AccessDenied both when that role does not exist and when it does not trust you. A StackSet "
                      "does not deploy to the management account: create the role there from the role template with "
                      "IsManagementAccount=true, or, if you cannot create a role there, sign in to the management account "
                      "and run with --org-with-current-credentials. Otherwise check the ARN and the ExternalId, or run with "
                      "--single-account to assess that account alone.\n")
                sys.exit(2)
            reader = org_session
            args.role_name = org_role_name
            args.role_arn = None
        if organization_reachable(reader):
            log("Discovering organization accounts …")
            org_info = get_org_info(reader)
            accounts = get_org_accounts(reader)
            if not accounts:
                print("\nNo organization accounts were returned. If this is not an "
                      "organization management account, run with --single-account.\n")
                sys.exit(2)
            log(f"Found {len(accounts)} active accounts")
        elif args.accounts:
            # These credentials cannot read the organization (a reviewer role in a separate account, or a person who may
            # not read Organizations), but the accounts to assess were named.  Assess those.  What only the organization
            # can answer (OUs, SCPs, organization backup policies, costs, multi-party approval) is said to be not assessed.
            explicit_accounts = True
            names = list(dict.fromkeys(args.accounts))
            accounts = [{"Id": a, "Name": a, "OUName": "", "OUPath": "", "OUChain": []} for a in names]
            org_info = {}
            org_read = False
            log(f"Your credentials cannot list the organization, so the accounts given with --accounts ({len(accounts)}) are "
                "assessed. OUs, SCPs, organization backup policies, costs and multi-party approval are not read in this mode.")
            record_gap("", "organizations:list_accounts",
                       "NotAssessed: these credentials cannot read the organization; the accounts come from --accounts",
                       account_id="organization")
        elif args.org_with_current_credentials:
            print("\nYour credentials cannot list the organization (AWS Organizations ListAccounts was denied, or this "
                  "account is not in an organization). Sign in to the management account with read access to AWS "
                  "Organizations, use the role in the management account (the guide's Organization section), or name "
                  "the accounts to assess with --accounts.\n")
            sys.exit(2)
        else:
            # A role deployed without IsManagementAccount=true has no Organizations access, and an account outside an
            # organization has nothing to list.  Either way this one account is what can be assessed, and the run says so.
            target_account = mgmt_account_id
            log(f"This account cannot list an organization, so only account {target_account} is assessed. "
                "For a whole organization, run in the management account with a stack deployed with IsManagementAccount=true.")
            args.single_account = True
            accounts = [{"Id": target_account, "Name": "current-account", "OUName": "", "OUChain": []}]
            org_info = {}

    # Names the reader supplied are shown in place of the ID, or of the name Organizations gave.
    for acct in accounts:
        if acct["Id"] in account_names:
            acct["Name"] = account_names[acct["Id"]]

    # --accounts: the rest of the organization is left out, listed as such, and counted in the Inputs page.
    not_selected: List[str] = []
    if args.accounts and not explicit_accounts:
        wanted = set(args.accounts)
        unknown = sorted(wanted - {a["Id"] for a in accounts})
        if unknown:
            warn(f"Not in the organization, so ignored: {', '.join(unknown)}")
        not_selected = [a["Id"] for a in accounts if a["Id"] not in wanted]
        accounts = [a for a in accounts if a["Id"] in wanted]
        if not accounts:
            print("\n  None of the accounts given to --accounts is in the organization. Nothing to assess.\n")
            sys.exit(2)
        for acct_id in not_selected:
            record_gap("", "collect_account", "NotSelected: left out by --accounts", account_id=acct_id)
        log(f"{len(accounts)} account(s) selected with --accounts; {len(not_selected)} left out")

    # Collect per account (parallel)
    account_results: List[Dict] = []
    accounts_failed: List[str] = []

    to_collect = accounts
    if args.sso_profile:
        for acct in accounts:
            if acct["Id"] not in sso_sessions:
                record_gap("", "sso:GetRoleCredentials", f"NotAssigned: permission set {args.sso_permission_set} "
                           "is not assigned to you in this account", account_id=acct["Id"])
                accounts_failed.append(acct["Id"])
        to_collect = [a for a in accounts if a["Id"] in sso_sessions]
        if accounts_failed:
            log(f"{len(accounts_failed)} account(s) do not have the permission set assigned to you, so they are not assessed")
    elif args.org_with_current_credentials and not explicit_accounts:
        # This mode has no collector role in the management account, so that account is left out and the report says so.
        log(f"Management account {mgmt_account_id} has no collector role in this mode, so it is not assessed")
        record_gap("", "sts:AssumeRole", "NotAssumed: no collector role in the management account "
                   "(--org-with-current-credentials)", account_id=mgmt_account_id)
        accounts_failed.append(mgmt_account_id)
        to_collect = [a for a in accounts if a["Id"] != mgmt_account_id]

    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        futures = {
            pool.submit(
                collect_account, acct, sts, args.role_name,
                args.external_id, region_request, primary_region,
                args.role_arn,
                sso_sessions.get(acct["Id"]) if args.sso_profile else
                (mgmt_session if args.use_current_credentials else None),
                args.deep,
            ): acct
            for acct in to_collect
        }
        for future in as_completed(futures):
            acct = futures[future]
            try:
                result = future.result()
                if result:
                    account_results.append(result)
                else:
                    accounts_failed.append(acct["Id"])
            except Exception as exc:
                warn(f"Account {acct['Id']} raised {type(exc).__name__}")
                record_gap("", "collect_account", f"Error:{type(exc).__name__}", account_id=acct["Id"])
                accounts_failed.append(acct["Id"])

    # Collect costs from management account
    if args.no_cost or not org_read:
        log("Skipping Cost Explorer (--no-cost)" if args.no_cost else
            "Skipping Cost Explorer (the organization could not be read with your sign-in)")
        raw_costs = {}   # empty dict; .items() used below
    else:
        log("Collecting cost data …")
        raw_costs = collect_costs(reader, [a["Id"] for a in accounts])

    # Collect SCPs
    log("Checking SCPs …")
    # A single-account run never reads the organization's SCPs, so "none found" would be a
    # claim about something that was not looked at.
    scps_assessed = not args.single_account and org_read
    scps = collect_scps(reader) if scps_assessed else []
    org_backup_policies = collect_org_backup_policies(reader) if scps_assessed else None

    if not account_results:
        print()
        print("  No account produced any data. Nothing to report.")
        print("  Run with --preflight to see which permissions are missing.")
        print()
        sys.exit(1)

    # ── Merge and analyse ────────────────────────────────────────────────────
    all_resources: List[Dict] = []
    all_vaults: List[Dict] = []
    all_groups: List[Dict] = []
    all_iceberg: List[Dict] = []
    all_vault_alarms: Dict[str, bool] = {}
    all_restore_plans: List[Dict] = []
    all_restore_jobs: List[Dict] = []
    all_backup_jobs: List[Dict] = []
    all_copy_jobs: List[Dict] = []

    # How the environment and sensitivity of resources were decided, and how far overrides were used.
    classification: Dict[str, Any] = {"overrides_loaded": len(overrides)}
    folded_members = 0

    # What failed during collection.  A resource with no protection found, where a call that
    # could have found it failed, is "not assessed", never "unprotected".
    gap_snapshot = ledger_snapshot()

    # One map across every account.  A cross-account copy lives in the backup account's
    # vault, so a per-account map would never show it against the source resource.
    org_vault_map = merge_vault_maps(
        [ar["backup_state"].get("resource_vault_map", {}) for ar in account_results])
    # The same for every recovery point: a copy in another account's vault is evidence for the source resource.
    org_points = merge_recovery_points([ar["backup_state"].get("recovery_points", {}) for ar in account_results])

    for ar in account_results:
        bs = ar["backup_state"]
        _backup_index(bs)       # build the lookup once, so each resource is a dict lookup
        bs_view = {**bs, "resource_vault_map": org_vault_map, "org_recovery_points": org_points}
        dlm_policies = dlm_policies_from(ar["native_state"])
        s3_sizes = ar.get("s3_sizes", {})
        # Build the set of S3 bucket ARNs that back Iceberg tables. These are the
        # resources for which "no AWS Backup path" is the correct finding — not Glue
        # table ARNs, which never appear in the S3 resource inventory.
        # Only the table rows carry "no table-level recovery identified".  The bucket that holds a Glue Iceberg table keeps its
        # own S3 evidence (object backup, versioning) and is marked "Iceberg table recovery not validated" beside it: object
        # backup is real, but it does not show the table, its metadata and its catalog entry restore together.
        iceberg_arns: set = set()
        bucket_tables: Dict[str, List[str]] = {}
        for t in ar["iceberg_tables"]:
            if t.get("type") == "glue_iceberg" and t.get("s3_bucket"):
                bucket_tables.setdefault(t["s3_bucket"], []).append(
                    f"{t.get('database', '')}.{t.get('name', '')}")
        # Each Iceberg table is its own inventory row.  Its size is not measured, so it
        # adds nothing to size totals; the backing bucket row keeps the bucket's size.
        iceberg_rows = iceberg_resources(ar["iceberg_tables"], ar["account_id"])
        iceberg_arns.update(row["arn"] for row in iceberg_rows if row.get("arn"))
        ar["resources"], folded = fold_cluster_members(list(ar["resources"]) + iceberg_rows)
        folded_members += folded
        for r in ar["resources"]:
            r["account_id"] = ar["account_id"]
            r["account_name"] = ar["account_name"]
        class_stats = classify_resources(
            ar["resources"], {"name": ar["account_name"], "ou": ar["ou"], "ou_path": ar.get("ou_path", "")},
            overrides, args.exclusion_tag_prefix, native_state=ar["native_state"])
        for key, value in class_stats.items():
            classification[key] = classification.get(key, 0) + value
        for r in ar["resources"]:
            criticality = r["criticality"]
            if r.get("resourceType") == "AWS::S3::Bucket":
                r["hosts_iceberg"] = "|".join(bucket_tables.get(r.get("resourceName") or r.get("resourceId", ""), []))
            protection = analyze_protection(r, ar["native_state"], bs_view, iceberg_arns,
                                            dlm_policies)
            r.update(protection)
            r["assessment_blockers"] = "; ".join(assessment_blockers(r, gap_snapshot))
            r["protection_state"] = classify_protection_state(r)
            r.update(recovery_copy_state(r))
            r.update(resource_age(r))
            r.update(tag_facts(r))
            meta = r.get("meta") or {}
            r["unattached"] = bool(r.get("resourceType") == "AWS::EC2::Volume" and "AttachedInstance" in meta
                                   and not meta["AttachedInstance"])
            r["unmanaged_data"] = bool(r["unattached"] and not r.get("has_any_protection"))
            r["over_protected"] = detect_over_protection(r, "unknown" if r.get("tag_behaviour_mismatch") else criticality)
            violations = evaluate_posture_controls(r)
            r["posture_violations"] = "|".join(violations) if violations else ""
            r.setdefault("size_gib", r.get("meta", {}).get("SizeGiB", 0))
            # Apply CloudWatch-sourced S3 sizes (previously always 0 since the S3
            # API does not expose bucket size and describe_s3 hard-coded 0).
            if r.get("resourceType") == "AWS::S3::Bucket":
                bucket_name = r.get("resourceName") or r.get("resourceId", "")
                if bucket_name in s3_sizes:
                    r["size_gib"] = s3_sizes[bucket_name]
            r["size_measured"] = r.get("meta", {}).get("SizeMeasured", True)
            # Apply CloudWatch-sourced Aurora cluster sizes (previously hardcoded 0).
            if r.get("resourceType") in RDS_CLUSTER_TYPES:
                native_r = ar["native_state"].get(r.get("arn", "")) or \
                           ar["native_state"].get(r.get("resourceId", ""))
                if native_r and native_r.get("size_gib", 0) > 0:
                    r["size_gib"] = native_r["size_gib"]
            r["cost_to_protect_monthly_usd"] = estimate_gap_protection_cost(r)
            all_resources.append(r)

        all_vaults.extend(bs["vaults"])
        all_groups.extend(ar["app_groups"])
        all_iceberg.extend(ar["iceberg_tables"])
        all_vault_alarms.update(bs.get("vault_alarms", {}))
        all_restore_plans.extend(bs.get("restore_testing_plans", []))
        all_restore_jobs.extend(bs.get("restore_jobs", []))
        all_backup_jobs.extend(bs.get("jobs", []))
        all_copy_jobs.extend(bs.get("copy_jobs", []))
        for eb_region in bs.get("eventbridge_regions", []):
            all_vault_alarms[eventbridge_key(ar["account_id"], eb_region)] = True

    groups_by_resource = group_index(all_groups)
    for r in all_resources:
        r["owner_hint"], r["owner_basis"] = owner_hint(r, groups_by_resource)

    # Build per-account summary rows
    account_summaries: List[Dict] = []
    for ar in account_results:
        acct_res = [r for r in all_resources if r.get("account_id") == ar["account_id"]]
        # An account that was read and holds no data-bearing resource still appears: leaving it out would make an
        # organization of ten accounts read as three.
        tagged = sum(1 for r in acct_res if r.get("tags"))
        account_summaries.append({
            "id": ar["account_id"],
            "name": ar["account_name"],
            "ou": ar["ou"],
            "resource_count": len(acct_res),
            "total_gib": sum(r.get("size_gib", 0) for r in acct_res),
            "tag_coverage_pct": tagged / len(acct_res) if acct_res else 0,
            "unprotected_count": sum(1 for r in acct_res if not r.get("has_any_protection")
                                    and r.get("protection_state") != "not_assessed"),
            "not_assessed_count": sum(1 for r in acct_res if r.get("protection_state") == "not_assessed"),
            "over_protected_count": sum(1 for r in acct_res if r.get("over_protected")),
            "conf_plus_count": sum(
                1 for r in acct_res
                if r.get("data_sensitivity") in ("CONFIDENTIAL", "HIGH_RISK_CONFIDENTIAL")
            ),
            "annual_spend": 0,  # filled in once costs are allocated, below
        })

    # Summarise costs into mechanism buckets
    costs_by_mechanism, account_monthly = allocate_costs(raw_costs, all_resources)

    # Annualized is the trailing 30 days times 12: an estimate, not a forecast.
    for summary in account_summaries:
        summary["annual_spend"] = account_monthly.get(summary["id"], 0.0) * 12
    costs_assessed = (not args.no_cost) and org_read and not any(
        g["api"].startswith("ce:get_cost") for g in coverage_gap_rows())

    scenarios = compute_scenarios(all_resources, all_vaults)
    if org_read:
        log("Checking multi-party approval …")
        mpa_state = collect_mpa_state(reader)
    else:
        mpa_state = {"configured": False, "team_count": 0, "assessed": False}    # read in the management account, not done here

    all_plans = [p for ar in account_results for p in ar["backup_state"].get("plans", [])]
    classification["cluster_members_folded"] = folded_members
    census = compute_census(all_resources, all_plans, classification)
    native_findings = [v for ar in account_results for k, v in ar["native_state"].items() if k.startswith("findings:")]
    inventory = {r["arn"] for r in all_resources if r.get("arn")}
    attach_recovery_point_totals(all_resources, org_points)
    scanned = {(ar["account_id"], region) for ar in account_results for region in ar["regions"]}
    orphans = find_orphans(native_findings, org_points, inventory, scanned, {ar["account_id"] for ar in account_results},
                           coverage_gap_rows(), all(ar["backup_state"].get("legal_holds_known", False) for ar in account_results))
    exposure = find_exposure(native_findings, scanned)
    copies = compute_copies_summary(all_resources, orphans, exposure)
    owners_view = compute_owner_view(all_resources)
    known_accounts = {a["Id"] for a in accounts} | {ar["account_id"] for ar in account_results}
    key_info: Dict[str, Dict] = {}
    for ar in account_results:
        key_info.update(ar["backup_state"].get("key_info", {}))
    gap_apis = {g["api"] for g in coverage_gap_rows()}
    scps_read = scps_assessed and not (gap_apis & {"organizations:list_policies", "organizations:describe_policy",
                                                    "organizations:list_targets_for_policy"})
    scp_cover = (scp_coverage(scps, accounts, org_info.get("MasterAccountId") or org_info.get("ManagementAccountId", ""))
                 if scps_read else None)
    security = compute_backup_security(all_vaults, key_info, all_plans, known_accounts, scp_cover, accounts, all_resources,
                                       sum(f.get("unencrypted_snapshots", 0) for f in native_findings),
                                       [fw for ar in account_results for fw in ar["backup_state"].get("frameworks", [])],
                                       [rp_ for ar in account_results for rp_ in ar["backup_state"].get("report_plans", [])],
                                       all(ar["backup_state"].get("governance_known", True) for ar in account_results),
                                       not (gap_apis & {"backup:list_backup_plans", "backup:get_backup_plan"}),
                                       org_backup_policies)
    snapshot = assessment_snapshot(all_resources, all_vaults, all_plans, assessed_date)
    drift = compare_runs(baseline, snapshot) if baseline else None

    restore_summary = apply_restore_evidence(all_resources, all_restore_jobs, all_restore_plans, all_vaults,
                                             RESTORE_LOOKBACK_DAYS)
    job_summary = apply_backup_job_evidence(all_resources, all_backup_jobs, all_copy_jobs, all_vault_alarms,
                                            "backup:list_backup_jobs" not in gap_apis, JOB_HISTORY_DAYS,
                                            "backup:list_copy_jobs" not in gap_apis)
    # The census was computed before the job outcomes were attached to the resources; the count of failed jobs among the
    # buckets with versioning off needs them.
    census["s3_backup_versioning"] = compute_s3_backup_versioning(all_resources)
    for r in all_resources:
        r["evidence_badges"] = "|".join(evidence_badges(r))
    census["copy_reasons"] = compute_copy_reasons([r for r in all_resources if r.get("protection_state") != "not_assessed"])
    questions = compute_questions(census, copies, owners_view, drift, len(coverage_gap_rows()), security, restore_summary,
                                  job_summary)

    hardening = compute_hardening_path(
        all_resources, all_vaults, scps, all_restore_plans, all_vault_alarms,
        restore_jobs=all_restore_jobs, restore_summary=restore_summary,
        mpa_state=mpa_state,
        scps_assessed=scps_assessed,
        gaps=coverage_gap_rows(),
    )

    # ── Write outputs ────────────────────────────────────────────────────────
    data = {
        "org_info": org_info,
        "assessed_date": assessed_date,
        "accounts": account_summaries,
        "resources": all_resources,
        "vaults": all_vaults,
        "app_groups": all_groups,
        "iceberg_tables": all_iceberg,
        "costs_by_mechanism": costs_by_mechanism,
        "scps": scps,
        "vault_alarms": all_vault_alarms,
        "scenarios": scenarios,
        "hardening_path": hardening,
        "accounts_failed": accounts_failed,
        "coverage_gaps": coverage_gap_rows(),
        "scps_assessed": scps_assessed,
        "costs_assessed": costs_assessed,
        "census": census,
        "drift": drift,
        "copies": copies,
        "owners": owners_view,
        "questions": questions,
        "security": security,
        "restore": restore_summary,
        "backup_jobs": job_summary,
        "regions": [{"name": ar["account_name"], "scanned": ar["regions"], "report": ar.get("region_report") or {}}
                    for ar in account_results],
        "inputs": {
            "assessed_date": assessed_date,
            "mode": ("A single account" if args.single_account else
                     "The accounts named with --accounts (the organization itself was not read)" if explicit_accounts else
                     "Accounts read through IAM Identity Center, with the organization not read" if not org_read else
                     "An AWS Organization, each account read through IAM Identity Center" if args.sso_profile else
                     "An AWS Organization"),
            "accounts_assessed": len(account_results), "accounts_failed": len(accounts_failed),
            "accounts_not_selected": len(not_selected),
            "organization_read": bool(org_read) or bool(args.single_account),
            "regions": sorted({region for ar in account_results for region in ar["regions"]}),
            "targets_source": RECOVERY_TARGET_SOURCE,
            "overrides_file": _basename(args.overrides), "overrides_loaded": classification.get("overrides_loaded", 0),
            "overrides_used": classification.get("overrides_used", 0), "baseline_file": _basename(args.baseline),
            "job_history_days": JOB_HISTORY_DAYS, "restore_lookback_days": RESTORE_LOOKBACK_DAYS,
            "costs_assessed": costs_assessed, "exclusion_prefix": args.exclusion_tag_prefix,
        },
    }

    if args.redact:
        redactor = build_redactor(account_results, data, [orphans])
        for root in (data, orphans, exposure, key_info):
            redactor.walk(root)
        known_accounts = redactor.walk(known_accounts)
        data["inputs"]["redacted"] = True
        if args.redact_key:
            write_redaction_key(redactor, args.redact_key)
            print("  A key to the labels was written. It holds the real names: keep it away from the redacted report.")

    report_path = str(out_dir / "report.html")
    assets_path = str(out_dir / "assets.csv")
    groups_path = str(out_dir / "proposed-groups.csv")

    generate_html_report(data, report_path, args.org_name, args.partner_name)
    generate_assets_csv(all_resources, assets_path)
    generate_groups_csv(all_groups, all_resources, groups_path)
    gaps_path = str(out_dir / "coverage-gaps.csv")
    generate_coverage_gaps_csv(data["coverage_gaps"], gaps_path)
    if not args.redact:
        (out_dir / "assessment.json").write_text(json.dumps(snapshot, indent=1, sort_keys=True), encoding="utf-8")
        generate_exclusion_worksheet(all_resources, str(out_dir / "exclusion-worksheet.csv"))
    generate_orphans_csv(orphans, str(out_dir / "orphaned-copies.csv"))
    generate_owners_csv(owners_view, str(out_dir / "by-owner.csv"))
    generate_vault_security_csv(all_vaults, key_info, known_accounts, str(out_dir / "vault-security.csv"))
    generate_shared_backups_csv(exposure, str(out_dir / "shared-backups.csv"))
    if drift:
        generate_changes_csv(drift, str(out_dir / "changes.csv"))

    elapsed = time.time() - t_start
    unprotected = sum(1 for r in all_resources
                      if not r.get("has_any_protection") and not r.get("no_backup_path")
                      and r.get("protection_state") != "not_assessed")
    not_assessed_total = sum(1 for r in all_resources if r.get("protection_state") == "not_assessed")

    print()
    print("  " + "─" * 68)
    print(f"  Done in {elapsed/60:.1f} min")
    print(_tidy_counts(f"  {len(all_resources):,} resources across {len(account_results)} account(s)"))
    if unprotected:
        print(f"  {unprotected:,} with no protection mechanism of any kind")
    if not_assessed_total:
        print(f"  {not_assessed_total:,} could not be fully assessed (a call was denied or failed); "
              "they are not counted as unprotected")
    if data["coverage_gaps"]:
        print(_tidy_counts(f"  {len(data['coverage_gaps'])} API call(s) were denied or failed; counts are a lower "
              f"bound. See {gaps_path}"))
    if accounts_failed:
        print(_tidy_counts(f"  {len(accounts_failed)} account(s) could not be read: {', '.join(accounts_failed)}"))
        print("  These are recorded in the report rather than silently omitted.")
    print("  " + "─" * 68)
    print()
    print(f"  Report   {report_path}")
    print(f"  Data     {assets_path}")
    print(f"  Groups   {groups_path}")
    print()
    print(f"  Open it:  open {report_path}          (macOS)")
    print(f"            xdg-open {report_path}      (Linux)")
    print(f"            start {report_path}         (Windows)")
    print()


if __name__ == "__main__":
    main()