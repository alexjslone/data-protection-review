# Cloud Data Protection Review

A read-only collector and report generator that shows a customer how their AWS data is protected, how well, and at what cost.
It runs in the customer's own AWS environment, through a read-only IAM role the customer deploys and can revoke at any time.
It reads configuration metadata only: never object contents, table items, database rows or secrets. Nothing leaves the
customer's environment; the only network calls are to AWS APIs.

## Get it

Download **DataProtectionReview_Bundle.zip** from the [latest release](../../releases/latest). It holds everything below in one file.

Then follow `START_HERE.txt` in the zip, or open `Deployment_Guide.html`. In short: upload the zip to AWS CloudShell, then run

```bash
unzip -o DataProtectionReview_Bundle.zip && bash run.sh
```

`run.sh` asks a few questions, shows the plan and creates nothing until you say yes. `cleanup.sh` removes what it created.

## What is here

| File | What it is |
|---|---|
| `Deployment_Guide.html` | Step-by-step deployment for one account, an organization, or an organization without `sts:AssumeRole` (IAM Identity Center) |
| `data_risk_assessment_role.yaml` | CloudFormation template for the read-only role. Read it before deploying |
| `data_risk_assessment_org.yaml` | The same role for a whole organization (management account role plus a StackSet) |
| `data_risk_assessment_permission_set.yaml` | The same read-only policy as an IAM Identity Center permission set |
| `SECURITY_REVIEW.md` | Explains every IAM permission, for a customer security review |
| `run.sh`, `cleanup.sh` | Deploy the role and run the assessment; find and remove what was created |
| `collector.py` | The collector and report generator (Python 3.9+, needs only `boto3`) |
| `Sample_*_made_up_data.html` | Sample reports built from made-up data |

## Notes

- This repository is a published copy of the files a partner hands a customer. It is not the development repository.
- Sample reports contain made-up data only.
- Questions or feedback: open an issue.
