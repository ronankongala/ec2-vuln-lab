---
name: ec2-vuln-lab-remediate
description: Lists, applies, rolls back, or dry-runs one approved CLD-xx remediation rule inside the lab account; use it when a scan shows an open finding that has an approved rule.
---

# ec2-vuln-lab-remediate

## Purpose

Run a single remediation rule from `remediations\rules\<RULE_ID>.yaml` against
the sandbox account. Every safety gate is checked for every step before the
first change is made, and every action, refusal, and verify result is written
to the audit log. After a successful apply, the engine runs the rule's verify
check and expects the finding to be `closed`. Rules with `fix.type: manual`
only print their description and make no changes.

## Inputs

| Input | Source | Notes |
|-------|--------|-------|
| Rule ID | CLI argument | For example `CLD-01`. Not needed for `list`. |
| Mode | CLI argument | One of `list`, `apply`, `rollback`, `dry-run` |
| `--profile` | CLI argument | Default `sandbox-tf` |
| `--region` | CLI argument | Default `us-east-1` |
| Rule definitions | `remediations\rules\*.yaml` | Keys: `id`, `match`, `scope`, `fix`, `rollback`, `verify`, `approved_by`, `approved_on`, `version` |
| Rule titles | `vulns\manifest.yaml` | Used by `list` only |

## Outputs

| Path | Contents |
|------|----------|
| `results\remediation-log.jsonl` | One JSON line per action: `timestamp`, `rule_id`, `rule_version`, `mode`, `action`, `target`, `params` (redacted), `result`, `before`, `after`, optional `detail` |

`result` is one of `success`, `noop`, `failed`, `refused`, `skipped`,
`manual`, `passed`, `pending`. Exit codes: `0` ok, `1` failed, `2` refused.
`list` writes nothing.

## Safety rules

- Never run a rule whose `approved_by` is empty or `pending`. Only a real person's name counts as approval.
- Never run a step whose action is not listed in the rule's `scope.allowed_actions`.
- Never run a step whose action has no handler in the engine.
- Never act on a target outside account `145443243505`, or on credentials for any other account.
- Never act on a target that lacks the tag `Project=ec2-vuln-lab` plus any extra tags in `scope.tags`.
- Never guess between multiple matching targets. Refuse instead.
- Never start changes until all gates pass for all steps (fail closed).
- Never write secrets to the log. Sensitive keys are redacted.
- Never edit rule files, including `approved_by`, from this skill.
- In `dry-run` mode, never call a mutating AWS API.

## Entry point

`remediations\engine.py` (functions `main()`, `run_rule()`, `validate_steps()`,
`run_steps()`, `run_verify()`).

| Mode | Command form | Status |
|------|--------------|--------|
| list | `python remediations\engine.py --list` | exists |
| apply | `python remediations\engine.py --apply <RULE_ID>` | exists |
| rollback | `python remediations\engine.py --rollback <RULE_ID>` | exists |
| dry-run | `python remediations\engine.py --dry-run <RULE_ID>` | to be extracted from `remediations\engine.py` (run `validate_steps()`, target resolution, and `check_target_scope()`, read `before` state, then stop before the mutating call) |

## Test (current)

Read-only, no AWS credentials needed:

```
python remediations\engine.py --list
```

Confirm it prints the rule table and the line
`<N> rules loaded from ...\remediations\rules, <M> pending approval.`

Do not use `--apply` or `--rollback` as a test.

## Test (planned)

Not runnable yet: `--dry-run` is not implemented in `remediations\engine.py`.
Once it is added, test a rule without changing AWS:

```
python remediations\engine.py --dry-run CLD-01 --profile sandbox-tf --region us-east-1
```
