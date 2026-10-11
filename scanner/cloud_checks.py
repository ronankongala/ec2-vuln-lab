#!/usr/bin/env python3
"""Read-only cloud checks for the ec2-vuln-lab target instance.

Evaluates the CLD-xx entries from vulns/manifest.yaml against the live
sandbox account. Only describe/get APIs are called; nothing is created,
modified, or deleted.

Usage:
    python scanner/cloud_checks.py [--profile sandbox-tf] [--region us-east-1]
"""

import argparse
import base64
import gzip
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import boto3
import yaml
from botocore.exceptions import BotoCoreError, ClientError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = PROJECT_ROOT / "vulns" / "manifest.yaml"
RESULTS_DIR = PROJECT_ROOT / "results"
HISTORY_DIR = RESULTS_DIR / "history"

TAG_PROJECT = "ec2-vuln-lab"
TAG_NAME = "vuln-lab-target"
ROLE_NAME = "vuln-lab-target-role"
POLICY_NAME = "overly-permissive-s3"
SECRET_KEY = "DB_ADMIN_PASSWORD"
OPEN_WORLD = "0.0.0.0/0"


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_manifest():
    """Return {id: {title, severity, layer}} for every CLD-xx entry."""
    with MANIFEST_PATH.open(encoding="utf-8") as fh:
        entries = yaml.safe_load(fh) or []
    return {
        e["id"]: {
            "title": e.get("title", ""),
            "severity": e.get("severity", "unknown"),
            "layer": e.get("layer", "cloud"),
        }
        for e in entries
        if str(e.get("id", "")).startswith("CLD-")
    }


def find_instance(ec2):
    resp = ec2.describe_instances(
        Filters=[
            {"Name": "tag:Project", "Values": [TAG_PROJECT]},
            {"Name": "tag:Name", "Values": [TAG_NAME]},
            {"Name": "instance-state-name", "Values": ["running"]},
        ]
    )
    instances = [i for r in resp["Reservations"] for i in r["Instances"]]
    if not instances:
        return None
    if len(instances) > 1:
        ids = ", ".join(i["InstanceId"] for i in instances)
        print(f"Warning: multiple matching instances ({ids}); using the first.")
    return instances[0]


# Each check returns (status, evidence) where status is "open" or "closed".

def check_cld01(ctx):
    tokens = ctx["instance"].get("MetadataOptions", {}).get("HttpTokens", "<missing>")
    status = "closed" if tokens == "required" else "open"
    return status, f"MetadataOptions.HttpTokens = {tokens}"


def _sg_permissions(ctx):
    if "sg_perms" not in ctx:
        group_ids = [g["GroupId"] for g in ctx["instance"].get("SecurityGroups", [])]
        resp = ctx["ec2"].describe_security_groups(GroupIds=group_ids)
        ctx["sg_perms"] = [
            (sg["GroupId"], perm)
            for sg in resp["SecurityGroups"]
            for perm in sg.get("IpPermissions", [])
        ]
    return ctx["sg_perms"]


def _port_open_to_world(ctx, port):
    group_ids = [g["GroupId"] for g in ctx["instance"].get("SecurityGroups", [])]
    hits = []
    for gid, perm in _sg_permissions(ctx):
        proto = perm.get("IpProtocol")
        if proto == "-1":
            covers = True
        elif proto == "tcp":
            covers = perm.get("FromPort", -1) <= port <= perm.get("ToPort", -1)
        else:
            covers = False
        if not covers:
            continue
        if any(r.get("CidrIp") == OPEN_WORLD for r in perm.get("IpRanges", [])):
            if proto == "-1":
                hits.append(f"{gid} all traffic from {OPEN_WORLD}")
            else:
                hits.append(
                    f"{gid} tcp {perm.get('FromPort')}-{perm.get('ToPort')} from {OPEN_WORLD}"
                )
    if hits:
        return "open", f"tcp/{port} reachable: " + "; ".join(hits)
    return "closed", f"No {OPEN_WORLD} ingress covering tcp/{port} in {', '.join(group_ids)}"


def check_cld02(ctx):
    return _port_open_to_world(ctx, 22)


def check_cld03(ctx):
    return _port_open_to_world(ctx, 3306)


def check_cld04(ctx):
    return _port_open_to_world(ctx, 6379)


def check_cld05(ctx):
    inst = ctx["instance"]
    root_name = inst.get("RootDeviceName")
    volume_id = None
    for bdm in inst.get("BlockDeviceMappings", []):
        if bdm.get("DeviceName") == root_name and "Ebs" in bdm:
            volume_id = bdm["Ebs"]["VolumeId"]
            break
    if not volume_id:
        raise RuntimeError(f"Root EBS volume not found for device {root_name}")
    vol = ctx["ec2"].describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    encrypted = bool(vol.get("Encrypted"))
    status = "closed" if encrypted else "open"
    return status, f"Root volume {volume_id} ({root_name}) Encrypted = {encrypted}"


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def check_cld06(ctx):
    iam = ctx["iam"]
    try:
        iam.get_role(RoleName=ROLE_NAME)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return "error", f"Role {ROLE_NAME} not found"
        raise
    try:
        resp = iam.get_role_policy(RoleName=ROLE_NAME, PolicyName=POLICY_NAME)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return "closed", f"{POLICY_NAME} policy not present on {ROLE_NAME}"
        raise
    doc = resp["PolicyDocument"]
    if isinstance(doc, str):
        doc = json.loads(doc)
    offending = []
    for idx, stmt in enumerate(_as_list(doc.get("Statement"))):
        if stmt.get("Effect", "Allow") != "Allow":
            continue
        actions = _as_list(stmt.get("Action"))
        resources = _as_list(stmt.get("Resource"))
        if "s3:*" in actions and "*" in resources:
            offending.append(stmt.get("Sid") or f"Statement[{idx}]")
    if offending:
        return "open", (
            f"{ROLE_NAME}/{POLICY_NAME} allows Action s3:* on Resource * "
            f"in {', '.join(offending)}"
        )
    return "closed", f"{ROLE_NAME}/{POLICY_NAME} has no statement allowing s3:* on *"


def check_cld07(ctx):
    resp = ctx["ec2"].describe_instance_attribute(
        InstanceId=ctx["instance_id"], Attribute="userData"
    )
    encoded = resp.get("UserData", {}).get("Value")
    if not encoded:
        return "closed", "No user data set on instance"
    raw = base64.b64decode(encoded)
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", errors="replace")
    # Report presence only; the secret value is never extracted or printed.
    if SECRET_KEY in text:
        return "open", f"User data contains key {SECRET_KEY} (value redacted)"
    return "closed", f"User data ({len(raw)} bytes) does not contain {SECRET_KEY}"


def check_cld08(ctx):
    vpc_id = ctx["instance"].get("VpcId")
    resp = ctx["ec2"].describe_flow_logs(
        Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
    )
    logs = resp.get("FlowLogs", [])
    if logs:
        ids = ", ".join(f"{fl['FlowLogId']} ({fl.get('FlowLogStatus', '?')})" for fl in logs)
        return "closed", f"{len(logs)} flow log(s) on {vpc_id}: {ids}"
    return "open", f"0 flow logs on {vpc_id}"


def check_cld09(ctx):
    state = ctx["instance"].get("Monitoring", {}).get("State", "<missing>")
    status = "closed" if state == "enabled" else "open"
    return status, f"Monitoring.State = {state}"


CHECKS = [
    ("CLD-01", check_cld01),
    ("CLD-02", check_cld02),
    ("CLD-03", check_cld03),
    ("CLD-04", check_cld04),
    ("CLD-05", check_cld05),
    ("CLD-06", check_cld06),
    ("CLD-07", check_cld07),
    ("CLD-08", check_cld08),
    ("CLD-09", check_cld09),
]


def run_checks(ctx, manifest):
    findings = []
    for check_id, func in CHECKS:
        meta = manifest.get(check_id)
        if meta is None:
            print(f"Warning: {check_id} not found in {MANIFEST_PATH.name}; using placeholders.")
            meta = {"title": "", "severity": "unknown", "layer": "cloud"}
        try:
            status, evidence = func(ctx)
        except Exception as exc:  # ClientError, BotoCoreError, or parse errors; keep scanning
            status, evidence = "error", f"{type(exc).__name__}: {exc}"
        findings.append(
            {
                "id": check_id,
                "layer": meta["layer"],
                "title": meta["title"],
                "severity": meta["severity"],
                "status": status,
                "evidence": evidence,
                "checked_at": utc_now(),
            }
        )
    return findings


def write_results(report, stamp):
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    latest = RESULTS_DIR / "cloud-scan-latest.json"
    history = HISTORY_DIR / f"cloud-scan-{stamp}.json"
    payload = json.dumps(report, indent=2)
    latest.write_text(payload + "\n", encoding="utf-8")
    history.write_text(payload + "\n", encoding="utf-8")
    return latest, history


def print_summary(findings):
    headers = ("ID", "STATUS", "SEVERITY")
    rows = [(f["id"], f["status"], f["severity"]) for f in findings]
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    line = "+".join("-" * (w + 2) for w in widths)
    fmt = " | ".join(f"{{:<{w}}}" for w in widths)
    print()
    print(fmt.format(*headers))
    print(line)
    for row in rows:
        print(fmt.format(*row))
    counts = {}
    for f in findings:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    print()
    print("Totals: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))


def main():
    parser = argparse.ArgumentParser(description="Read-only cloud checks for ec2-vuln-lab")
    parser.add_argument("--profile", default="sandbox-tf", help="AWS profile (default: sandbox-tf)")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    args = parser.parse_args()

    manifest = load_manifest()
    if not manifest:
        sys.exit(f"No CLD-xx entries found in {MANIFEST_PATH}")

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        account_id = session.client("sts").get_caller_identity()["Account"]
        ec2 = session.client("ec2")
        iam = session.client("iam")
        instance = find_instance(ec2)
    except (ClientError, BotoCoreError) as exc:
        sys.exit(f"AWS error during setup: {type(exc).__name__}: {exc}")

    if instance is None:
        sys.exit(
            f"No running instance found with tags Project={TAG_PROJECT} and "
            f"Name={TAG_NAME} in {args.region} (profile {args.profile})."
        )

    instance_id = instance["InstanceId"]
    print(f"Account {account_id}, region {args.region}, instance {instance_id}")

    ctx = {"ec2": ec2, "iam": iam, "instance": instance, "instance_id": instance_id}
    findings = run_checks(ctx, manifest)

    now = datetime.now(timezone.utc)
    report = {
        "run_id": str(uuid.uuid4()),
        "timestamp_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "account_id": account_id,
        "region": args.region,
        "instance_id": instance_id,
        "findings": findings,
    }
    latest, history = write_results(report, now.strftime("%Y%m%dT%H%M%SZ"))

    print_summary(findings)
    print(f"\nWrote {latest}")
    print(f"Wrote {history}")


if __name__ == "__main__":
    main()
