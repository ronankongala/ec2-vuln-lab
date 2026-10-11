---
name: ec2-vuln-lab-verify
description: Re-checks a single CLD-xx finding read-only and reports whether it is open, closed, or error; use it after a remediation or rollback to confirm the live state of one finding.
---

# ec2-vuln-lab-verify

## Purpose

Check the live state of one finding without running a full scan and without
changing anything. Given a rule ID (for example `CLD-01`) or a check ID (for
example `check_cld01`), it resolves the matching scanner check, finds the lab
target instance, runs the check, prints the status and evidence, and appends a
verify entry to the audit log. A rule ID is mapped to its check through the
rule's `verify.check` field.

## Inputs

| Input | Source | Notes |
|-------|--------|-------|
| Rule ID or check ID | CLI argument | `CLD-01` or `check_cld01` |
| `--profile` | CLI argument | Default `sandbox-tf` |
| `--region` | CLI argument | Default `us-east-1` |
| Rule to check mapping | `remediations\rules\<RULE_ID>.yaml` (`verify.check`, `verify.expect`) | Used when a rule ID is given |
| Check functions | `scanner\cloud_checks.py` | `check_cld01` through `check_cld09`, `find_instance()` |

## Outputs

| Output | Contents |
|--------|----------|
| stdout | `<check>: status=<open, closed, or error>` and the evidence string |
| `results\remediation-log.jsonl` | One appended line with `mode: verify`, `action: verify:<check>`, `after: {status, evidence}` |

## Safety rules

- Never call an AWS API that creates, modifies, tags, or deletes anything.
- Never run fix or rollback steps, even if the finding is open.
- Never check an instance that lacks the `Project=ec2-vuln-lab` and `Name=vuln-lab-target` tags.
- Never print or log secret values. Evidence for CLD-07 reports key presence only.
- Never overwrite or truncate the audit log. Append only.
- Never write `results\cloud-scan-latest.json`. That file belongs to the scan skill.

## Entry point

To be extracted from `remediations\engine.py` (`run_verify()`, which already
imports `scanner.cloud_checks`, builds the check context, retries, and audits
the result). The check logic itself lives in `scanner\cloud_checks.py` and
needs no changes. The planned command is:

```
python remediations\verify.py <RULE_ID or CHECK_ID> [--profile sandbox-tf] [--region us-east-1]
```

## Test (current)

This skill is read-only, so testing it is the same as running it.

Interim command that works with the existing code today (runs one check
read-only and prints the result; it does not append to the log):

```
python -c "import boto3, scanner.cloud_checks as c; s=boto3.Session(profile_name='sandbox-tf', region_name='us-east-1'); e=s.client('ec2'); i=c.find_instance(e); print(c.check_cld01({'ec2': e, 'iam': s.client('iam'), 'instance': i, 'instance_id': i['InstanceId']}))"
```

Run it from the project root. Expected output is a tuple such as
`('open', 'MetadataOptions.HttpTokens = optional')`.

## Test (planned)

Not runnable yet: `remediations\verify.py` does not exist. Once extracted:

```
python remediations\verify.py CLD-01 --profile sandbox-tf --region us-east-1
```
