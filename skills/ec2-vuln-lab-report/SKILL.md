---
name: ec2-vuln-lab-report
description: Combines the latest scan JSON and the remediation audit log into dashboard data with no AWS calls; use it after scan, remediate, or verify to refresh what the dashboard shows.
---

# ec2-vuln-lab-report

## Purpose

Build a single data file for the dashboard from local results only. It reads
the latest scan findings and the remediation audit log, then produces per
finding status, severity, the latest remediation action and result, the latest
verify result, and summary counts (open, closed, error, by severity). It never
contacts AWS, so it can run offline and as often as needed.

## Inputs

| Input | Path |
|-------|------|
| Scan results | `results\cloud-scan-latest.json` |
| Audit log | `results\remediation-log.jsonl` (may be missing or empty) |
| Optional history | `results\history\cloud-scan-*.json` for trend data |

## Outputs

| Path | Contents |
|------|----------|
| `results\dashboard-data.json` | Generated timestamp, source scan `run_id` and `timestamp_utc`, `findings[]` merged with latest remediation and verify entries, and summary counts |

## Safety rules

- Never make any AWS call or import boto3.
- Never modify the scan JSON, the history files, or the audit log. Read only.
- Never write any file other than `results\dashboard-data.json`.
- Never copy redacted values back in or add secret values from any source.
- Never fail silently on a malformed log line. Skip it and report the line number.

## Entry point

To be extracted from `scanner\cloud_checks.py` (JSON layout of
`write_results()`) and `remediations\engine.py` (audit entry layout of
`audit()`). No report code exists yet. The planned command is:

```
python reports\build_dashboard_data.py
```

## Test (current)

The report script does not exist yet, so the only runnable check is that the
inputs parse:

```
python -c "import json; d=json.load(open('results/cloud-scan-latest.json')); print(d['run_id'], len(d['findings']))"
```

## Test (planned)

Not runnable yet: `reports\build_dashboard_data.py` does not exist. This skill
is read-only on inputs and makes no AWS calls, so once extracted, running it is
the test:

```
python reports\build_dashboard_data.py
```

Confirm `results\dashboard-data.json` is written and that its finding count
matches the scan file.
