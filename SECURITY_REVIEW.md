# Security review: IAM permissions and data handling

This document explains every permission the collector role is granted, where the collector uses it, and what data it touches. It describes `data_risk_assessment_role.yaml` (and, in its own section, the organization template built from it). `tests/test_security_review.py` fails if the actions listed here and the actions in the template stop matching, so a permission cannot be added or removed without updating this document.

## Summary

- The role has **87 allowed actions**: 87 are called by the collector today, 0 only by the `--preflight` access check, 0 are reserved for planned work, and 0 have no use. Every allowed action is one the code calls. Permissions that planned work would need are not granted; they are listed under 'Permissions deliberately not requested' and are added only when the code that uses them ships.
- **No allowed action is a wildcard, mutates anything, or reads data contents.** There is no `s3:GetObject*`, `dynamodb:GetItem`, `Query` or `Scan`, `kms:Decrypt` or `GenerateDataKey*`, `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `rds-data:*`, `athena:StartQueryExecution` or `lambda:GetFunction`, and no `Create*`, `Put*`, `Update*`, `Delete*`, `Modify*`, `Copy*`, `Restore*`, `Start*` or tag-writing action. `tests/test_security_review.py` checks this against the template.
- An explicit **Deny** policy blocks data reads and every mutating action, and overrides every Allow.
- The role is assumed by a principal the customer chooses, with an ExternalId and optional MFA, and the customer can revoke it at any time.

## Access model

| Control | How it works |
|---|---|
| Who can assume the role | Only the principal in `TrustedPrincipalArn` (a user, a role, or an account root). The customer sets it. |
| ExternalId | Required on the assume-role call. It guards against a third party tricking the collector into using the role. AWS treats an ExternalId as an identifier, not a secret, and assume-role calls typically appear in CloudTrail with it; the trusted principal is the real authentication. |
| MFA | Optional (`RequireMFA`). A machine run cannot satisfy it, so it defaults to off. |
| Permissions boundary | Optional (`PermissionsBoundaryArn`), for organizations that require one on every role. |
| Session length | `MaxSessionDuration` is 4 hours. A session started from another role is capped at 1 hour by AWS role chaining. |
| Revocation | Delete the stack. The role and its policies are removed. |
| What the person running the tool needs | In a single account, nothing beyond being the trusted principal: the trust policy names them. In an organization, assuming the role in *another* account also needs their own permission to call `sts:AssumeRole` on it, for example this statement in their IAM Identity Center permission set or IAM policy: `{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::*:role/DataProtectionReviewer*"}`. Where the organization does not allow that, the IAM Identity Center path below needs no `sts:AssumeRole` at all. |
| Organization use | The same role name is deployed into every member account (StackSet); the management account stack sets `IsManagementAccount` to add organization read access. In an organization run the tool assumes the management account's role to list the organization, read the service control policies and read the costs, then assumes the same role name in each member account. The credentials of the person running the tool are used only to assume those roles (or for the whole run when `--use-current-credentials` is given). For an organization whose management account cannot hold the role, `--org-with-current-credentials` reads the organization, the service control policies and the costs with the person's own credentials, makes the same read calls listed here, and assumes the role only in the member accounts; the management account is then reported as not assessed. Those reads are bounded by the person's permissions, not by the role's explicit Deny statements, so the role in the management account is the documented default. |

| Deploying the role | The tool itself creates nothing. The role is created by the customer, with their own credentials, from the template: through the console, or with the plain `aws cloudformation` commands in the guide (one stack for a single account; one stack plus one service-managed StackSet for an organization). Before that, the guide's first line reads who is signed in (`sts get-caller-identity`) and, for a role login such as IAM Identity Center, that role's own ARN (`iam get-role`), so the stack trusts exactly that role. It also reads whether the stack exists (`cloudformation describe-stacks`) and whether a role of the default name exists outside it (`iam get-role`): an existing stack is updated with the role name it has, and a role the stack did not create is never changed or deleted; the new role gets its own name instead. The one change that line can make is deleting the stack when it is in `ROLLBACK_COMPLETE`, a failed first attempt that holds no resources. The commands create only that stack or StackSet and can be read line by line; the guide's "Removing access" section has the `delete-stack` and `delete-stack-instances` lines that remove everything. The person running them needs permission to create the IAM role and the CloudFormation stack, which is the customer's decision. |

## What is collected and where it goes

- **Metadata only.** Identifiers, names, tags, configuration settings, sizes, retention periods, lock states, job states and counts. Never object contents, table items, database rows, secrets, parameter values, snapshot blocks or log events, and nothing is decrypted.
- **Output stays local.** The collector writes the report and its CSV and JSON files (the guide lists each) to a directory the user chooses. The report loads no external scripts, fonts or images. It contains one small inline script that runs the sidebar and the expandable blocks; it makes no network requests (a test checks this), and the report is complete without it.
- **No network destinations other than AWS APIs.** No telemetry, no phone-home, no upload.
- **AWS Config is asked for named fields only.** The query selects `configuration.engine`, `allocatedStorage`, `dBClusterIdentifier`, `size` and `attachments`, plus the resource's creation time (see `CONFIG_FIELDS_USED`), not whole configuration documents. That keeps the S3 bucket policy and ACL, and an RDS instance's endpoint and master username, out of the collector's memory.
- **The report appendix lists the same calls.** It is built from `API_CALLS_BY_FINDING` in `collector.py`, and `tests/test_security_review.py` fails if that list and the template differ.
- **Not logged:** credentials, session tokens and the ExternalId. Progress messages contain account IDs, Regions, counts and API names, and the ARN of the identity the tool runs as (which can include a user's session name or email).
- **Sensitive in the output:** account IDs, resource names and tag values. They are in the report and the CSVs, so the files should be handled as customer data.

## Permissions

Status values: **used** (called by the collector), **preflight only** (called only by `--preflight`), **reserved** (needed by planned work named in the last column), **unused** (no use; to be removed).


### Inventory: what exists and how it is tagged

| Action | Status | Called from / reserved for | What it is for |
|---|---|---|---|
| `tag:GetResources` | used | `collect_native_mechanisms`, preflight check | Tags of EC2 instances (ARN and tags only), for backup policies that snapshot the volumes of instances carrying certain tags. Also proves in the preflight that the tagging API is reachable. |
| `resource-explorer-2:Search` | used | `_try_resource_explorer` | Lists resource ARNs and tags per allowlisted type (second discovery source after AWS Config). |
| `resource-explorer-2:ListIndexes` | used | `_resource_explorer_regions` | Which Region holds the Resource Explorer aggregator index (or which Regions have an index), so the search runs where the index is. Region names and index types only. |
| `config:SelectResourceConfig` | used | `_try_config` | Reads recorded configuration of allowlisted resource types in one Region. |
| `config:SelectAggregateResourceConfig` | used | `_try_config` | Same, across an organization aggregator. |
| `config:DescribeConfigurationAggregators` | used | `_try_config` | Finds whether an aggregator exists. |
| `config:DescribeConfigurationRecorders` | used | `_config_region_state` | Checks which resource types a Region's recorder covers, so a partial recorder is not trusted. |
| `config:DescribeConfigurationRecorderStatus` | used | `_config_region_state` | Checks that the recorder is actually recording. |
| `ec2:DescribeRegions` | used | `get_enabled_regions` | Lists the Regions the account has enabled. |
| `ec2:DescribeVolumes` | used | `_describe_ebs`, `collect_native_mechanisms`, preflight check | Lists EBS volumes: id, size, state, attachment, tags. |
| `ec2:DescribeSnapshots` | used | `collect_native_mechanisms` | Counts and dates snapshots per volume (own snapshots only); never reads snapshot blocks. |
| `rds:DescribeDBInstances` | used | `_describe_rds`, `collect_native_mechanisms`, preflight check | Lists instances: engine, storage, backup retention, cluster membership, tags. |
| `rds:DescribeDBClusters` | used | `_describe_rds`, `collect_native_mechanisms`, preflight check | Lists clusters: engine, backup retention, tags. |
| `rds:DescribeDBSnapshots` | used | `collect_native_mechanisms` | Dates of manual and automated snapshots per instance (never snapshot contents), so a database with a manual snapshot is not reported as having no copy. |
| `rds:DescribeDBClusterSnapshots` | used | `collect_native_mechanisms` | The same for Aurora, Neptune and DocumentDB clusters. |
| `dynamodb:ListTables` | used | `_describe_dynamodb`, `collect_native_mechanisms`, preflight check | Lists table names. |
| `dynamodb:DescribeTable` | used | `_describe_dynamodb`, `collect_native_mechanisms` | Table ARN, size, class. Never table items. |
| `dynamodb:ListTagsOfResource` | used | `_describe_dynamodb` | Reads table tags. |
| `s3:ListAllMyBuckets` | used | `_describe_s3`, `collect_native_mechanisms`, `collect_s3_sizes`, preflight check | Lists bucket names. Does not list objects. |
| `s3:GetBucketLocation` | used | `for_bucket`, `collect_s3_sizes` | Which Region each bucket is in. |
| `s3:GetBucketTagging` | used | `_describe_s3` | Bucket tags. |

### Native protection mechanisms: point-in-time recovery, DLM, versioning, retention

| Action | Status | Called from / reserved for | What it is for |
|---|---|---|---|
| `dynamodb:DescribeContinuousBackups` | used | `collect_native_mechanisms` | Whether point-in-time recovery is on, and its retention period. |
| `dynamodb:ListBackups` | used | `collect_native_mechanisms` | Dates of on-demand backups per table (summaries only, never items). |
| `rds:DescribeDBSnapshotAttributes` | used | `_shared_snapshots` | Who a manual snapshot is shared with, and whether it is public. Attribute names and account ids only. |
| `rds:DescribeDBClusterSnapshotAttributes` | used | `_shared_snapshots` | The same for cluster snapshots. |
| `rds:DescribeDBInstanceAutomatedBackups` | used | `_retained_backups`, `collect_native_mechanisms` | Automated backups kept after their database was deleted: id, size and dates. |
| `rds:DescribeDBClusterAutomatedBackups` | used | `_retained_backups` | The same for clusters. |
| `ec2:DescribeImages` | used | `collect_native_mechanisms` | Which of the account's own AMIs are public. Image ids only. |
| `s3:GetBucketObjectLockConfiguration` | used | `collect_native_mechanisms` | Whether Object Lock is on (a setting, not objects). |
| `s3:GetBucketNotification` | used | `collect_native_mechanisms` | Whether Amazon EventBridge notifications are on for the bucket, which AWS Backup's continuous backup of S3 relies on. Only that yes or no is kept; the notification targets in the response (SNS, SQS and Lambda ARNs) are discarded, and no object, event or message is read. |
| `dlm:GetLifecyclePolicies` | used | `collect_native_mechanisms` | Lists EBS snapshot lifecycle policies. |
| `dlm:GetLifecyclePolicy` | used | `collect_native_mechanisms` | Policy schedule, retention, target tags and state. |
| `s3:GetBucketVersioning` | used | `collect_native_mechanisms` | Whether versioning is enabled. |
| `s3:GetLifecycleConfiguration` | used | `collect_native_mechanisms` | Whether noncurrent-version expiry rules exist (lifecycle rules, not contents). |
| `s3:GetReplicationConfiguration` | used | `collect_native_mechanisms` | Whether replication exists, and whether its destination is in another account. |

### AWS Backup: plans, vaults, lock state, job health

| Action | Status | Called from / reserved for | What it is for |
|---|---|---|---|
| `backup:ListBackupPlans` | used | `collect_backup_state`, preflight check | Lists backup plans. |
| `backup:GetBackupPlan` | used | `collect_backup_state` | Plan rules: schedule, retention, copy destinations. |
| `backup:ListBackupSelections` | used | `collect_backup_state` | Lists which selections each plan has. |
| `backup:GetBackupSelection` | used | `collect_backup_state` | A selection's resources, tag conditions and exclusions, to decide which resources a plan covers. |
| `backup:ListBackupVaults` | used | `collect_backup_state`, preflight check, `_probe_region` | Lists vaults. |
| `backup:DescribeRegionSettings` | used | `collect_backup_state` | Which services AWS Backup is opted in for in each Region, and whether it fully manages DynamoDB backups. |
| `backup:DescribeBackupVault` | used | `collect_backup_state` | Lock state, lock date and vault type (air-gapped). |
| `backup:ListProtectedResources` | used | `collect_backup_state`, preflight check | Which resources have a recovery point. |
| `backup:ListRecoveryPointsByBackupVault` | used | `collect_backup_state` | Which resources have recovery points, with counts, sizes and dates, to find copies whose source no longer exists and to see locked or air-gapped copies. Never contents. |
| `backup:ListBackupJobs` | used | `collect_backup_state`, preflight check | Recent job states, to detect plans that are failing. |
| `backup:ListCopyJobs` | used | `collect_backup_state` | How recent copy jobs (to another Region or account) ended, so a failing copy is visible. Status, resource, vault and dates. |
| `backup:ListRestoreJobs` | used | `collect_backup_state` | Whether any restore has been exercised. |
| `backup:ListRestoreTestingPlans` | used | `collect_backup_state` | Whether restore testing is configured. |
| `backup:GetRestoreTestingPlan` | used | `_read_restore_testing_plan` | Which vaults a restore testing plan restores from (names only). |
| `backup:ListRestoreTestingSelections` | used | `_read_restore_testing_plan` | Which selections a restore testing plan has. |
| `backup:GetRestoreTestingSelection` | used | `_read_restore_testing_plan` | The resource type, ARN patterns and tag conditions a selection uses, to tell which resources a restore test covers. |
| `backup:GetBackupVaultNotifications` | used | `collect_backup_state` | Whether a vault notifies on failed jobs. |
| `backup:GetBackupVaultAccessPolicy` | used | `collect_backup_state` | Which principals a vault policy names and which delete actions it denies. Reduced to those facts; the policy text is not kept. |
| `backup:ListFrameworks` | used | `collect_backup_state` | Whether AWS Backup Audit Manager frameworks exist: names and deployment status. |
| `backup:DescribeFramework` | used | `collect_backup_state` | Which controls a framework turns on (control names only). Compliance results are not read. |
| `backup:ListReportPlans` | used | `collect_backup_state` | Whether Audit Manager report plans exist: names only. |
| `backup:ListLegalHolds` | used | `collect_backup_state` | Which legal holds exist, so held recovery points are never counted as removable. |
| `backup:ListRecoveryPointsByLegalHold` | used | `collect_backup_state` | Which recovery points a hold covers (ARNs only). |
| `kms:DescribeKey` | used | `collect_backup_state` | A key's manager (AWS or customer), state (enabled, disabled, pending deletion) and account. Metadata only: not the key, not its policy. |
| `ram:GetResourceShares` | used | `collect_backup_state`, preflight check | Resource shares the account owns, to confirm a vault is shared for air-gap use. |
| `mpa:ListApprovalTeams` | used | `collect_mpa_state` | Whether Multi-Party Approval teams exist. |

### Context: grouping, monitoring and analytics table formats

| Action | Status | Called from / reserved for | What it is for |
|---|---|---|---|
| `servicecatalog:ListApplications` | used | `_appregistry_groups` | AppRegistry application names, for grouping. |
| `servicecatalog:ListAssociatedResources` | used | `_appregistry_groups` | Which resources belong to an AppRegistry application. |
| `cloudformation:ListStacks` | used | `_cfn_stack_groups` | Stack names and status, for grouping. |
| `cloudformation:ListStackResources` | used | `_cfn_stack_groups` | Which physical resources a stack owns, for grouping. |
| `ecs:ListClusters` | used | `_ecs_groups` | Cluster names, for grouping. |
| `ecs:ListServices` | used | `_ecs_groups` | Service names per cluster, for grouping. |
| `eks:ListClusters` | used | `_eks_groups` | Cluster names, for grouping. |
| `cloudwatch:GetMetricData` | used | `collect_s3_sizes` | Bucket size metric (BucketSizeBytes), batched. |
| `cloudwatch:GetMetricStatistics` | used | `collect_native_mechanisms` | Aurora cluster volume size and, with --deep, DynamoDB write rate. |
| `cloudwatch:ListMetrics` | used | `collect_s3_sizes`, preflight check | Which (bucket, storage class) metrics exist. |
| `cloudwatch:DescribeAlarms` | used | `collect_backup_state`, preflight check | Whether an alarm watches backup job failures per vault. |
| `events:ListRules` | used | `collect_backup_state` | Whether a rule routes aws.backup events (monitoring), per Region. |
| `glue:GetDatabases` | used | `collect_iceberg_tables` | Glue database names, to find Iceberg tables. |
| `glue:GetTables` | used | `collect_iceberg_tables` | Table type and location, to find Iceberg tables. |
| `s3tables:ListTableBuckets` | used | `collect_iceberg_tables` | S3 Tables table buckets. |
| `s3tables:ListTables` | used | `collect_iceberg_tables` | Tables in each table bucket. |

### Cost (optional, parameter EnableCostExplorer)

| Action | Status | Called from / reserved for | What it is for |
|---|---|---|---|
| `ce:GetCostAndUsage` | used | `_cost_pages`, `collect_costs` | Trailing-30-day spend by account and usage type. Optional (EnableCostExplorer). |
| `ce:GetDimensionValues` | used | `_warn_about_unmapped_backup_services`, preflight check | Lists service names in the billing data, so a backup-related service the report does not map is reported instead of dropped. Also used by the preflight. |

### Organization structure (optional, parameter IsManagementAccount)

| Action | Status | Called from / reserved for | What it is for |
|---|---|---|---|
| `organizations:DescribeOrganization` | used | `get_org_info` | Organization id. |
| `organizations:ListAccounts` | used | `sso_account_sessions`, `organization_reachable`, `get_org_accounts` | Account ids and names. |
| `organizations:ListOrganizationalUnitsForParent` | used | `_build_ou_map` | Org unit tree, for the account table. |
| `organizations:ListRoots` | used | `get_org_accounts` | The organization root. |
| `organizations:ListParents` | used | `get_org_accounts` | Which org unit an account sits in. |
| `organizations:ListPolicies` | used | `collect_scps`, `collect_org_backup_policies` | Lists service control policies. |
| `organizations:DescribePolicy` | used | `collect_scps`, `collect_org_backup_policies` | SCP content, to see whether it denies backup lifecycle actions. |
| `organizations:ListTargetsForPolicy` | used | `collect_scps`, `collect_org_backup_policies` | Where each service control policy is attached (root, organizational unit or account), to tell a guardrail that applies from one that is attached nowhere. |

## Permissions deliberately not requested

These were in earlier versions of the template or are expected to be needed by planned work. The code does not call them, so the role does not grant them. Each is added, with its row above, in the same change as the code that uses it.

- `ec2:DescribeInstances`: Phase 7l and 8b: group volumes under their instance
- `backup:ListRecoveryPointsByResource`: Phase 7a: newest recovery point per resource
- `backup:DescribeRecoveryPoint`: Phase 9a: recovery point encryption
- `organizations:ListPoliciesForTarget`: Phase 9c: where an SCP is attached

The other permissions removed because nothing used them were `tag:GetTagKeys`, `tag:GetTagValues`, `ec2:DescribeTags`, `ec2:DescribeSubnets`, `ec2:DescribeVpcs`, `rds:DescribeDBSubnetGroups`, `rds:ListTagsForResource`, `ce:GetTags`, `ram:ListResources`, and the unused `kms:`, `glue:`, `s3tables:`, `organizations:`, `cloudformation:`, `ecs:`, `eks:`, `events:` and `backup:` describe and list actions.


## Why `Resource` is `*`

Every allow statement uses `Resource: "*"`. Most of these read APIs either do not support resource-level restrictions or must enumerate resources whose ARNs are unknown when the stack is deployed. Because every action is read-only metadata, narrowing the resource would not change what the role can read about any one resource. Reason per statement:

| Statement | Reason |
|---|---|
| `AnalyticsTableFormats` | Databases and table buckets are discovered, not known in advance. |
| `ApplicationGrouping` | Stacks, applications and clusters are discovered, not known in advance. |
| `BackupConfiguration` | AWS Backup list calls (plans, vaults, jobs, protected resources) do not support resource-level restrictions, and the contents of an account are unknown at deploy time. |
| `BackupKeyState` | KMS DescribeKey is called on the keys that encrypt vaults and recovery points. Those are discovered, not known when the template is deployed, and can be in other Regions or accounts. |
| `CostAttribution` | Cost Explorer does not support resource-level permissions. |
| `CriticalityAndMonitoring` | Alarms, metrics and rules are read across the account to see which vaults and resources have monitoring. |
| `MultiPartyApprovalState` | Approval team listing is not restrictable by resource. |
| `NativeProtectionState` | Applied to every volume, table, database and bucket found. Several of these calls (for example DescribeContinuousBackups on an unknown table) cannot be limited to ARNs known in advance. |
| `OrgStructureAndSCPs` | Organizations read actions do not support resource-level restrictions for these calls. |
| `PerServiceInventory` | The same: the tool must discover which volumes, databases, tables and buckets exist. A list of ARNs would defeat discovery. |
| `ResourceDiscovery` | These calls enumerate every resource in the account by design. The resources are not known when the template is deployed, so they cannot be listed as ARNs. |
| `VerifyAirGappedVaultSharing` | AWS RAM share listing is not restrictable by resource. |

## The explicit Deny

`ExplicitDenyPolicy` has two statements and overrides every Allow, including any policy attached later.

- **`NeverReadCustomerData`** denies the data-read actions of every service. For services the collector does not use at all it denies the whole service: `secretsmanager:*`, `ssm:*`, `logs:*`, `athena:*`, `lambda:*`, `rds-data:*` and `ebs:*`. For KMS, which it uses only to read a key's state, it names every key-use action and `GetKeyPolicy`. For services it does use it names only the data-read actions: `s3:GetObject*`, DynamoDB `GetItem`, `BatchGet*`, `Query`, `Scan`, `PartiQL*` (which controls `ExecuteStatement`), the export actions and the stream reads, `rds:Download*`, and three EC2 console and password reads. A wildcard in a Deny only blocks more, so an action AWS adds later in a service-wide-denied service is denied too.
- **`NeverMutateAnything`** denies the mutating verbs for the services the role can see (`Create*`, `Delete*`, `Put*`, `Modify*`, `Update*`, `Start*`, `Stop*`, `Copy*`, `Restore*` and similar), all of `iam:*`, and `ebs:GetSnapshotBlock`.
- **A test checks it.** `tests/test_security_review.py` confirms no allowed action is blocked by the Deny, and that every data read the goal file forbids is covered by it.
- **Limits.** Mutating actions are still listed by verb, so a new verb AWS invents could be missed (the Allow list grants none). KMS is denied by action, not whole: the collector calls `kms:DescribeKey` (metadata) and nothing else, so every key use (`Decrypt`, `Encrypt`, `ReEncrypt*`, `GenerateDataKey*`, `Sign`, `Verify` and the rest) and `GetKeyPolicy` are denied by name, and every key-changing verb by pattern. Anyone who can edit the role can detach the deny policy itself; a permissions boundary or an SCP is the durable form of the guarantee.

## Dependencies

The collector needs Python 3 and `boto3` (which brings `botocore`). Nothing else is imported. Versions are pinned in `requirements.txt`; AWS CloudShell's preinstalled boto3 is new enough, so nothing is installed there. Test tooling (`pytest`, `moto`, `cfn-lint`, `pyyaml`) is in `requirements-dev.txt` and is not needed to run the collector.

## The organization template

`data_risk_assessment_org.yaml` is the one template for an organization, deployed in the management account. `tools/build_org_template.py` generates it from `data_risk_assessment_role.yaml`, and `tests/test_org_template.py` fails if the committed file is out of date.

- **It adds no permission to the role.** The role resources in the stack are the role template's, unchanged, with `IsManagementAccount` fixed at true (the management account's role can read the organization's structure and service control policies). The template the StackSet carries is the role template itself, line for line, with `IsManagementAccount` set to false, so a member account's role has no organization access. A test compares both against the role template.
- **It adds one resource**, an `AWS::CloudFormation::StackSet` with service-managed permissions that creates the role in each member account of the organization root or organizational unit named in `OrganizationRootId`, and in accounts that join later. One account failing does not stop the others.
- **What the person deploying needs** is permission to create a StackSet and to turn on trusted access between CloudFormation StackSets and AWS Organizations. Those are the deployer's permissions, not the collector role's. Trusted access lets CloudFormation create its own service-linked roles for StackSets in the management account and in each member account; the collector role does not use them.
- **The External ID** is a `NoEcho` parameter in the stack and in the StackSet's template, so CloudFormation does not show it in describe calls or the console.
- **Size.** The role template is embedded whole, so the organization template is close to CloudFormation's 51,200 byte limit for a template passed directly; the generator and a test stop if the role template grows past it.
- **Not yet tested in a real organization:** moto cannot create a StackSet resource, so the stack's role and the template the StackSet carries were deployed separately in tests, and the StackSet itself is untested until a run in a real organization.

## Organizations that do not allow sts:AssumeRole (IAM Identity Center)

Some organizations do not let the person running the review assume a role in another account (an SCP or their permission set denies `sts:AssumeRole`). For them, `data_risk_assessment_permission_set.yaml` creates an **IAM Identity Center permission set** with the same read-only policy and assigns it to one reviewer in the accounts listed. `tools/build_permission_set_template.py` generates it from `data_risk_assessment_role.yaml`, and `tests/test_permission_set_template.py` fails if it is out of date.

- **The same policy, minus the management-only reads.** The permission set's inline policy is every statement of the role's always-attached policies, copied unchanged, including the explicit Deny on data reads and every write. The Organizations and Cost Explorer statements, which only the management account's role holds, are left out. A test compares the two.
- **What it creates.** One `AWS::SSO::PermissionSet` and one `AWS::SSO::Assignment` per account listed, for the one user or group given. IAM Identity Center then creates the matching role (`AWSReservedSSO_DataProtectionReviewer_...`) in each assigned account itself. No IAM role or StackSet is created by hand. The stack is deployed where IAM Identity Center is administered (the management account or its delegated administrator), by an IAM Identity Center administrator.
- **How the collector uses it** (`--sso-profile`). The reviewer signs in with the AWS CLI (`aws sso login`). The collector reads that sign-in's access token from the AWS CLI's own cache (`~/.aws/sso/cache`), as the AWS CLI does, and asks the IAM Identity Center access portal (`portal.sso.<region>.amazonaws.com`, an AWS endpoint) for the accounts it may open (`ListAccounts`, `ListAccountRoles`) and, in each account where the permission set is assigned, its credentials (`GetRoleCredentials`). These portal calls are authorized by the sign-in, not by IAM, and need no `sts:AssumeRole`. The token and the credentials stay in memory; they are never written, logged or printed. Accounts without the permission set are listed as not assessed.
- **No External ID.** An External ID protects a role that trusts another party's account. Here nothing trusts another account: IAM Identity Center hands credentials only to the person it is assigned to, after their own sign-in (with whatever MFA the organization enforces there). Revocation is deleting the stack, which removes every assignment and the permission set.
- **Organization-wide reads** (the account list with names and OUs, service control policies, backup policies, multi-party approval, costs) are made with the reviewer's own sign-in in the management account, as with `--org-with-current-credentials`, when it can list the organization. Otherwise they are reported as not assessed and the account list comes from the portal. Those reads are bounded by the reviewer's permissions, not by the explicit Deny.
- **Not yet tested against real AWS.** moto has no IAM Identity Center; the portal is faked in `tests/test_sso_mode.py`.

## Known gaps in this review

These are tracked in `docs/PROJECT_STATUS.md`; none is hidden.

- **Failed calls outside the discovery paths** can still be swallowed without a trace, so a resource could be treated as having no finding when its data could not be read (T-11, T-31).
- **CSV cells are not neutralised** against spreadsheet formula injection from resource names and tag values (T-29).
- **Permissions that planned work would need and that are not requested:** IAM read and simulation, Security Hub, Macie, GuardDuty and IAM Access Analyzer (plan items 9g, 11a, 11d). Adding any of them needs a decision against the goal file first (T-35).

## How to check this yourself

```bash
cfn-lint data_risk_assessment_role.yaml      # template is valid
cfn-lint data_risk_assessment_org.yaml       # the organization template is valid
python tools/build_org_template.py --check   # the organization template is the role template plus one StackSet
pytest tests/test_org_template.py            # its role and its StackSet's template are the role template
cfn-lint data_risk_assessment_permission_set.yaml      # the IAM Identity Center template is valid
python tools/build_permission_set_template.py --check  # its policy is the role's, generated
pytest tests/test_security_review.py          # this document matches the template and has no forbidden actions
```

To read the permissions straight from the template, open `data_risk_assessment_role.yaml` and read the `Action` lists under each `Allow` statement. The deny lists are under `ExplicitDenyPolicy`.
