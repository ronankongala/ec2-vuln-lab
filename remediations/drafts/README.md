# Draft rules

This folder holds remediation rules that are not approved yet.

- Drafts are written by the AI step (or by hand, for examples like
  `CLD-02.draft.yaml`). Each file is named `<RULE_ID>.draft.yaml`.
- Every draft is saved with `approved_by: pending`, `approved_on: ""`, and
  `draft: true`.
- A draft cannot run until a person approves it. The engine's `--apply`
  never loads rules from this folder: `--list`, `--apply`, and `--rollback`
  only read `remediations/rules/`. If you pass a draft file to `--apply`, the
  engine refuses it because it has `draft: true`.
- You can preview a draft with a dry-run, which uses read-only AWS calls:

      python remediations/engine.py --dry-run remediations/drafts/CLD-02.draft.yaml

## Approving a draft

1. Run the dry-run above and read what it would change.
2. Remove the `draft` and `preview_required` keys.
3. Set `approved_by` to your name and `approved_on` to today's date.
4. Move the file to `remediations/rules/<RULE_ID>.yaml`. This replaces any
   existing rule with the same ID, so compare the two first.

See `remediations/draft_schema.md` for the full format.
