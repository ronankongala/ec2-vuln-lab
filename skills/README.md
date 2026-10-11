# ec2-vuln-lab skills

Four skills cover the lab workflow. Each has its own folder with a `SKILL.md`
that defines its inputs, outputs, safety rules, entry point, and test command.

| Skill | What it does | AWS access | Writes |
|-------|--------------|------------|--------|
| [ec2-vuln-lab-scan](ec2-vuln-lab-scan/SKILL.md) | Runs the CLD-xx checks against the lab instance | Read-only | `results\cloud-scan-latest.json`, `results\history\` |
| [ec2-vuln-lab-remediate](ec2-vuln-lab-remediate/SKILL.md) | Lists, applies, rolls back, or dry-runs one approved rule | Changes AWS (apply, rollback only) | `results\remediation-log.jsonl` |
| [ec2-vuln-lab-verify](ec2-vuln-lab-verify/SKILL.md) | Re-checks one finding: open, closed, or error | Read-only | `results\remediation-log.jsonl` (append) |
| [ec2-vuln-lab-report](ec2-vuln-lab-report/SKILL.md) | Builds dashboard data from local results | None | `results\dashboard-data.json` |

## How they chain

```
scan  ->  remediate  ->  verify  ->  report
```

1. **scan** finds which findings are open.
2. **remediate** fixes one open finding that has an approved rule.
3. **verify** confirms that finding is now closed.
4. **report** merges the scan and the audit log into dashboard data.

## Independence

Each skill is independent and can run alone. None of them calls another. They
share state only through files in `results\`:

- scan can run any time to refresh the current state.
- remediate `list` and `dry-run` need no prior scan.
- verify can check any finding at any time, with or without a prior remediation.
- report works with whatever scan and log files exist.

Only remediate `apply` and `rollback` change AWS, and only for rules with a
real name in `approved_by`.
