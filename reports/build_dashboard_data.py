"""Build results/dashboard-data.json from local scan, audit, and rule files.

Read-only with respect to the lab: this script never calls AWS and never runs
terraform, the remediation engine, or the scanner. It only reads files under
the project directory and writes results/dashboard-data.json.

Usage:
    py -3.13 reports/build_dashboard_data.py
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
LATEST_SCAN = RESULTS_DIR / "cloud-scan-latest.json"
AUDIT_LOG = RESULTS_DIR / "remediation-log.jsonl"
HISTORY_DIR = RESULTS_DIR / "history"
MANIFEST = ROOT / "vulns" / "manifest.yaml"
RULES_DIR = ROOT / "remediations" / "rules"
OUTPUT = RESULTS_DIR / "dashboard-data.json"

AUDIT_LIMIT = 200
AUDIT_FIELDS = ("timestamp", "rule_id", "mode", "action", "result")
SECRET_MARKERS = ("password", "secret", "token")
STATUSES = ("closed", "open", "error")


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_secret_key(name):
    lowered = str(name).lower()
    return any(marker in lowered for marker in SECRET_MARKERS)


def strip_secrets(value):
    """Recursively drop any dict key whose name looks like a secret."""
    if isinstance(value, dict):
        return {k: strip_secrets(v) for k, v in value.items() if not is_secret_key(k)}
    if isinstance(value, list):
        return [strip_secrets(v) for v in value]
    return value


def load_latest_scan():
    if not LATEST_SCAN.is_file():
        sys.exit(
            f"ERROR: {LATEST_SCAN} not found.\n"
            "Run the scanner first (scanner/cloud_checks.py) to produce it, "
            "then re-run this script."
        )
    with LATEST_SCAN.open(encoding="utf-8") as fh:
        return json.load(fh)


def load_manifest():
    """Map finding ID to {title, severity}. Display fields only."""
    if not MANIFEST.is_file():
        return {}
    with MANIFEST.open(encoding="utf-8") as fh:
        entries = yaml.safe_load(fh) or []
    out = {}
    for entry in entries:
        if isinstance(entry, dict) and entry.get("id"):
            out[entry["id"]] = {
                "title": entry.get("title"),
                "severity": entry.get("severity"),
            }
    return out


def load_rules():
    """Map rule ID to {fix_type, approved_by}."""
    rules = {}
    if not RULES_DIR.is_dir():
        return rules
    for path in sorted(RULES_DIR.glob("*.yaml")):
        try:
            with path.open(encoding="utf-8") as fh:
                rule = yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError) as exc:
            print(f"WARNING: could not read rule {path.name}: {exc}", file=sys.stderr)
            continue
        if not isinstance(rule, dict):
            continue
        rule_id = rule.get("id") or path.stem
        fix = rule.get("fix") if isinstance(rule.get("fix"), dict) else {}
        approved_by = rule.get("approved_by")
        rules[rule_id] = {
            "fix_type": fix.get("type"),
            "approved_by": str(approved_by) if approved_by is not None else None,
        }
    return rules


def load_audit():
    """Return (entries, parse_errors). Blank lines are skipped."""
    entries = []
    parse_errors = 0
    if not AUDIT_LOG.is_file():
        return entries, parse_errors
    with AUDIT_LOG.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if not isinstance(record, dict):
                parse_errors += 1
                continue
            entry = {k: record.get(k) for k in AUDIT_FIELDS}
            entries.append(strip_secrets(entry))
    return entries[-AUDIT_LIMIT:], parse_errors


def count_statuses(findings):
    counts = {status: 0 for status in STATUSES}
    for finding in findings:
        status = finding.get("status")
        if status in counts:
            counts[status] += 1
    return counts


def load_history():
    runs = []
    if not HISTORY_DIR.is_dir():
        return runs
    for path in HISTORY_DIR.glob("cloud-scan-*.json"):
        try:
            with path.open(encoding="utf-8") as fh:
                scan = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"WARNING: skipping history file {path.name}: {exc}", file=sys.stderr)
            continue
        counts = count_statuses(scan.get("findings") or [])
        runs.append({
            "run_id": scan.get("run_id"),
            "timestamp_utc": scan.get("timestamp_utc"),
            **counts,
            "_sort": (scan.get("timestamp_utc") or "", path.name),
        })
    runs.sort(key=lambda r: r["_sort"])
    for run in runs:
        del run["_sort"]
    return runs


def build_findings(scan, manifest, rules):
    findings = []
    for f in scan.get("findings") or []:
        fid = f.get("id")
        meta = manifest.get(fid, {})
        rule = rules.get(fid)
        fix_type = rule["fix_type"] if rule else None
        approved_by = rule["approved_by"] if rule else None
        fix_available = bool(
            rule
            and fix_type == "automated"
            and approved_by
            and approved_by != "pending"
        )
        findings.append({
            "id": fid,
            "layer": f.get("layer"),
            "title": meta.get("title") or f.get("title"),
            "severity": meta.get("severity") or f.get("severity"),
            "status": f.get("status"),
            "evidence": f.get("evidence"),
            "fix_type": fix_type,
            "approved_by": approved_by,
            "fix_available": fix_available,
        })
    return findings


def main():
    scan = load_latest_scan()
    manifest = load_manifest()
    rules = load_rules()
    audit, audit_parse_errors = load_audit()

    findings = build_findings(scan, manifest, rules)
    counts = count_statuses(findings)
    total = len(findings)
    compliance_pct = round(counts["closed"] / total * 100, 1) if total else 0.0

    data = {
        "generated_at_utc": utc_now(),
        "account_id": scan.get("account_id"),
        "region": scan.get("region"),
        "instance_id": scan.get("instance_id"),
        "summary": {**counts, "total": total, "compliance_pct": compliance_pct},
        "findings": findings,
        "history": load_history(),
        "audit": audit,
        "audit_parse_errors": audit_parse_errors,
    }

    OUTPUT.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    s = data["summary"]
    print(f"Wrote {OUTPUT}")
    print(
        f"closed={s['closed']} open={s['open']} error={s['error']} "
        f"total={s['total']} compliance_pct={s['compliance_pct']}"
    )
    print(
        f"history_runs={len(data['history'])} audit_entries={len(audit)} "
        f"audit_parse_errors={audit_parse_errors}"
    )


if __name__ == "__main__":
    main()
