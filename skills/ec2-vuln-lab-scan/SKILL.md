---
name: ec2-vuln-lab-scan
description: Runs the read-only CLD-xx cloud checks against the lab target instance and writes the latest scan JSON; use it whenever you need the current open or closed state of the lab findings.
---

# ec2-vuln-lab-scan

## Purpose

Evaluate every CLD-xx entry in `vulns\manifest.yaml` against the live sandbox
account and record the result. The scan finds the running instance tagged
`Project=ec2-vuln-lab` and `Name=vuln-lab-target`, runs each check (IMDSv2,
open security group ports, root volume encryption, IAM inline policy, user
data secrets, VPC flow logs, detailed monitoring), and writes one finding per
check with a status of `open`, `closed`, or `error`. It only calls AWS
describe and get APIs, so it is safe to run at any time.

## Inputs

| Input | Source | Default |
|-------|--------|---------|
| `--profile` | CLI argument | `sandbox-tf` |
| `--region` | CLI argument | `us-east-1` |
| Check metadata (title, severity, layer) | `vulns\manifest.yaml` | required |

## Outputs

| Path | Contents |
|------|----------|
| `results\cloud-scan-latest.json` | Latest scan: `run_id`, `timestamp_utc`, `account_id`, `region`, `instance_id`, `findings[]` |
| `results\history\cloud-scan-<YYYYMMDDTHHMMSSZ>.json` | Identical copy kept for history |

A summary table (ID, STATUS, SEVERITY) and totals are printed to stdout.

## Safety rules

- Never call an AWS API that creates, modifies, tags, or deletes anything. Only describe, get, and `sts:GetCallerIdentity` calls are allowed.
- Never print or store the value of a secret found in user data. Report presence of the key only (value redacted).
- Never scan an instance that lacks both the `Project=ec2-vuln-lab` and `Name=vuln-lab-target` tags.
- Never write outside `results\` and `results\history\`.
- Never change `vulns\manifest.yaml` or any rule file.

## Entry point

`scanner\cloud_checks.py` (function `main()`; individual checks are
`check_cld01` through `check_cld09`, listed in `CHECKS`).

## Test

The scan has no separate dry-run mode because it is read-only by design. Run it
directly:

```
python scanner\cloud_checks.py --profile sandbox-tf --region us-east-1
```

Confirm it prints `Account <id>, region us-east-1, instance <id>`, a summary
table, and the two `Wrote ...` lines. The only side effect is the two local
JSON files listed under Outputs.
