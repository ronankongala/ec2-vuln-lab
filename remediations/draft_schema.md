# Draft rule format

A draft is a remediation rule that has not been approved. It uses the same
keys as an approved rule (see `remediations/rules/CLD-02.yaml`) plus four
draft-only fields. Drafts live in `remediations/drafts/` and are named
`<RULE_ID>.draft.yaml`.

## Keys shared with approved rules

| Key | Required | Notes |
|---|---|---|
| `id` | yes | Rule ID, for example `CLD-02`. Must match the file name without `.draft.yaml`. |
| `version` | yes | Integer. |
| `match` | yes | `source`, `check`, and any check-specific fields such as `port`. |
| `scope` | yes | `tags`, `account` (must be `"145443243505"`), and `allowed_actions`. |
| `fix` | yes | `type` (`automated` or `manual`), `description`, and `steps`. Manual fixes must have empty `steps`. |
| `rollback` | yes | `description` and `steps`, in the same shape as `fix.steps`. |
| `verify` | yes | `check` (a scanner function name) and `expect` (usually `closed`). |
| `approved_by` | yes | Always `pending` in a draft. |
| `approved_on` | yes | Always `""` in a draft. |

Each step has `action` (must be listed in `scope.allowed_actions`), `target`
(`type` and `name`), and `params`.

## Draft-only keys

| Key | Value | Meaning |
|---|---|---|
| `draft` | `true` | Marks the file as a draft. The engine refuses `--apply` for any rule that has this key, even if `approved_by` is set. |
| `drafted_by` | `"ai"` or `"manual"` | Who wrote the draft. |
| `source_finding` | `{ source, control, finding_id }` | The finding the draft was written for. Example: `source: "securityhub"`, `control: "EC2.18"`, `finding_id: "<Security Hub finding ARN>"`. |
| `preview_required` | `true` | A reminder for the reviewer: run a dry-run of the draft before approving it. |

## Rules the engine enforces

- `--apply` refuses any rule file with a `draft` key and prints:
  "This is a draft. Preview it, then approve it by moving it to remediations/rules."
  The check looks only at whether the key is present, so `draft: false` is
  still refused. Remove the key.
- `--apply` also refuses any rule whose `approved_by` is empty, `pending`,
  or `ai`. Approval must be recorded by a person.
- `--list`, `--apply` by rule ID, and `--rollback` only load
  `remediations/rules/`. Files in `remediations/drafts/` are never loaded by
  rule ID.
- `--dry-run` works on drafts. Pass the draft file path:
  `python remediations/engine.py --dry-run remediations/drafts/CLD-02.draft.yaml`.
  Draft paths are only accepted from `remediations/drafts/`, and every file
  there must have `draft: true`.

## Turning a draft into an approved rule

A draft can be applied only after all of these are true:

1. A person has previewed it with `--dry-run`.
2. The `draft` key is removed. Remove `preview_required` too.
   `drafted_by` and `source_finding` may stay as a record of where the rule
   came from.
3. `approved_by` is set to the approving person's name and `approved_on`
   to the date, for example `approved_on: "2026-10-11"`.
4. The file is moved to `remediations/rules/<RULE_ID>.yaml`.
