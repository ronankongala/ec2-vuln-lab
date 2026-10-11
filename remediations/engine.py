#!/usr/bin/env python3
"""Rule-based remediation engine for the ec2-vuln-lab cloud findings (CLD-xx).

Loads remediations/rules/*.yaml and applies or rolls back one rule at a time
against the sandbox account. Safety gates, all fail-closed:

  * a rule whose approved_by is "pending", "ai" (or empty) is never run
  * a rule with a draft key is never applied, even if approved_by is set
  * every step action must be listed in the rule's scope.allowed_actions
  * every target must be owned by account 145443243505 and carry the tag
    Project=ec2-vuln-lab (plus any extra tags in scope.tags)
  * all gates are checked for every step before the first change is made
  * fix.type "manual" rules only print their description

Every action, refusal, and verify result is appended to
results/remediation-log.jsonl.

--dry-run runs the same gates (except approval, so pending rules can be
reviewed), reads current state with describe/get calls only, and prints what
each fix step would change. AWS clients are wrapped so any other call is
refused. One audit entry is written per dry-run.

Drafts (remediations/drafts/*.draft.yaml) are never loaded by rule ID. Pass a
draft's file path to --dry-run to preview it; --apply refuses it.

Usage:
    python remediations/engine.py --list
    python remediations/engine.py --dry-run CLD-01 [--profile sandbox-tf] [--region us-east-1]
    python remediations/engine.py --dry-run remediations/drafts/CLD-02.draft.yaml
    python remediations/engine.py --apply CLD-01 [--profile sandbox-tf] [--region us-east-1]
    python remediations/engine.py --rollback CLD-01 [--profile sandbox-tf] [--region us-east-1]
"""

import argparse
import importlib
import json
import sys
import time
from collections import namedtuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

ENGINE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = ENGINE_DIR.parent
RULES_DIR = ENGINE_DIR / "rules"
DRAFTS_DIR = ENGINE_DIR / "drafts"
DRAFT_SUFFIX = ".draft.yaml"
DRAFT_MESSAGE = "This is a draft. Preview it, then approve it by moving it to remediations/rules."
MANIFEST_PATH = PROJECT_ROOT / "vulns" / "manifest.yaml"
AUDIT_LOG = PROJECT_ROOT / "results" / "remediation-log.jsonl"

ALLOWED_ACCOUNT = "145443243505"
REQUIRED_TAGS = {"Project": "ec2-vuln-lab"}
REQUIRED_KEYS = (
    "id", "match", "scope", "fix", "rollback", "verify",
    "approved_by", "approved_on", "version",
)
FIX_TYPES = ("automated", "manual")
SENSITIVE_MARKERS = ("password", "secret", "credential", "privatekey", "accesskey", "sessiontoken")

VERIFY_ATTEMPTS = 3
VERIFY_DELAY_S = 5

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_REFUSED = 2


class RuleError(Exception):
    """A rule file is malformed."""


class Refused(Exception):
    """A safety gate rejected the run. Nothing was changed."""


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def _load_rule_file(path, expected_id):
    with path.open(encoding="utf-8") as fh:
        rule = yaml.safe_load(fh) or {}
    missing = [k for k in REQUIRED_KEYS if k not in rule]
    if missing:
        raise RuleError(f"{path.name}: missing keys {', '.join(missing)}")
    if rule["id"] != expected_id:
        raise RuleError(f"{path.name}: id {rule['id']} does not match file name")
    fix_type = rule["fix"].get("type")
    if fix_type not in FIX_TYPES:
        raise RuleError(f"{path.name}: fix.type must be one of {', '.join(FIX_TYPES)}")
    if fix_type == "manual" and rule["fix"].get("steps"):
        raise RuleError(f"{path.name}: manual rules must have empty fix.steps")
    return rule


def load_rules():
    rules = {}
    for path in sorted(RULES_DIR.glob("*.yaml")):
        rule = _load_rule_file(path, path.stem)
        rules[rule["id"]] = rule
    return rules


def find_draft(arg):
    """Return the draft file path if arg names a *.draft.yaml file, else None.

    A bare file name is looked up in DRAFTS_DIR. Draft files outside
    DRAFTS_DIR are rejected.
    """
    path = Path(arg)
    if not path.name.endswith(DRAFT_SUFFIX):
        return None
    if path.parent == Path("."):
        path = DRAFTS_DIR / path.name
    path = path.resolve()
    if path.parent != DRAFTS_DIR.resolve():
        raise RuleError(f"{arg}: drafts are only read from {DRAFTS_DIR}")
    if not path.is_file():
        raise RuleError(f"{arg}: draft file not found")
    return path


def load_draft(path):
    rule = _load_rule_file(path, path.name[: -len(DRAFT_SUFFIX)])
    if rule.get("draft") is not True:
        raise RuleError(f"{path.name}: files in {DRAFTS_DIR.name}/ must have draft: true")
    return rule


def is_draft(rule):
    # Any draft key counts, so approval means removing the key, not setting it false.
    return "draft" in rule


def load_titles():
    try:
        with MANIFEST_PATH.open(encoding="utf-8") as fh:
            entries = yaml.safe_load(fh) or []
    except OSError:
        return {}
    return {e["id"]: e.get("title", "") for e in entries if "id" in e}


def is_pending(rule):
    approver = str(rule.get("approved_by") or "").strip().lower()
    return approver in ("", "pending", "ai")


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def _is_sensitive(key):
    k = str(key).lower().replace("_", "").replace("-", "")
    return any(marker in k for marker in SENSITIVE_MARKERS)


def redact(value):
    if isinstance(value, dict):
        return {k: ("<redacted>" if _is_sensitive(k) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def audit(rule, mode, action, result, params=None, target=None, before=None, after=None, detail=None):
    entry = {
        "timestamp": utc_now(),
        "rule_id": rule["id"],
        "rule_version": rule.get("version"),
        "mode": mode,
        "action": action,
        "target": target.summary() if target else None,
        "params": redact(params or {}),
        "result": result,
        "before": redact(before),
        "after": redact(after),
    }
    if detail:
        entry["detail"] = redact(detail)
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, default=str) + "\n")


# ---------------------------------------------------------------------------
# AWS access
# ---------------------------------------------------------------------------

class Aws:
    """Lazily creates only the clients a rule actually uses."""

    def __init__(self, profile, region):
        import boto3  # deferred so --list works without AWS libraries or credentials

        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.region = region
        self._clients = {}

    def client(self, name):
        if name not in self._clients:
            self._clients[name] = self.session.client(name)
        return self._clients[name]


READ_ONLY_PREFIXES = ("describe_", "get_")


class _ReadOnlyClient:
    """Wraps a boto3 client and refuses any API call that is not a describe or get."""

    def __init__(self, name, client):
        self._name = name
        self._client = client

    def __getattr__(self, attr):
        if attr == "exceptions" or attr.startswith(READ_ONLY_PREFIXES):
            return getattr(self._client, attr)
        raise Refused(f"dry-run blocked {self._name}.{attr}: only describe and get calls are allowed")


class ReadOnlyAws(Aws):
    """Aws whose clients can only make describe and get calls. Used by --dry-run."""

    def client(self, name):
        if name not in self._clients:
            self._clients[name] = _ReadOnlyClient(name, self.session.client(name))
        return self._clients[name]


@dataclass
class Target:
    type: str
    name: str
    id: str
    account: str
    tags: dict = field(default_factory=dict)

    def summary(self):
        return {"type": self.type, "name": self.name, "id": self.id, "account": self.account}


def _tag_map(tag_list):
    return {t["Key"]: t["Value"] for t in tag_list or []}


def resolve_instance(aws, name):
    resp = aws.client("ec2").describe_instances(
        Filters=[
            {"Name": "tag:Name", "Values": [name]},
            {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
        ]
    )
    found = [(r["OwnerId"], i) for r in resp["Reservations"] for i in r["Instances"]]
    if not found:
        raise Refused(f"No instance named {name} found")
    if len(found) > 1:
        ids = ", ".join(i["InstanceId"] for _, i in found)
        raise Refused(f"Multiple instances named {name} ({ids}); refusing to guess")
    owner, inst = found[0]
    return Target("instance", name, inst["InstanceId"], owner, _tag_map(inst.get("Tags")))


def resolve_security_group(aws, name):
    resp = aws.client("ec2").describe_security_groups(
        Filters=[{"Name": "group-name", "Values": [name]}]
    )
    groups = resp["SecurityGroups"]
    if not groups:
        raise Refused(f"No security group named {name} found")
    if len(groups) > 1:
        ids = ", ".join(g["GroupId"] for g in groups)
        raise Refused(f"Multiple security groups named {name} ({ids}); refusing to guess")
    sg = groups[0]
    return Target("security_group", name, sg["GroupId"], sg["OwnerId"], _tag_map(sg.get("Tags")))


def resolve_iam_role(aws, name):
    iam = aws.client("iam")
    try:
        role = iam.get_role(RoleName=name)["Role"]
    except iam.exceptions.NoSuchEntityException:
        raise Refused(f"No IAM role named {name} found") from None
    account = role["Arn"].split(":")[4]
    return Target("iam_role", name, role["RoleId"], account, _tag_map(role.get("Tags")))


RESOLVERS = {
    "instance": resolve_instance,
    "security_group": resolve_security_group,
    "iam_role": resolve_iam_role,
}


def check_target_scope(rule, target):
    if target.account != ALLOWED_ACCOUNT:
        raise Refused(
            f"{target.type} {target.name} ({target.id}) is in account {target.account}, "
            f"not {ALLOWED_ACCOUNT}"
        )
    required = dict(REQUIRED_TAGS)
    required.update(rule["scope"].get("tags") or {})
    for key, value in required.items():
        if target.tags.get(key) != value:
            raise Refused(
                f"{target.type} {target.name} ({target.id}) lacks tag {key}={value}"
            )


# ---------------------------------------------------------------------------
# Action handlers
#
# Each handler declares the target type it accepts, how to build the API
# call, how to read the relevant before/after state, and when the desired
# state is already in place (so the step is a no-op).
# ---------------------------------------------------------------------------

Handler = namedtuple("Handler", "service method target_type build_call read is_done check_response")


def _describe_instance(aws, target):
    resp = aws.client("ec2").describe_instances(InstanceIds=[target.id])
    return resp["Reservations"][0]["Instances"][0]


def _no_response_check(resp):
    return None


# Instance metadata options (CLD-01)

def _metadata_call(target, params):
    return {"InstanceId": target.id, **params}


def _metadata_read(aws, target, params):
    opts = _describe_instance(aws, target).get("MetadataOptions", {})
    return {key: opts.get(key) for key in params}


def _metadata_done(state, params):
    return all(state.get(k) == v for k, v in params.items())


# Security group ingress (CLD-02, CLD-03, CLD-04)

def _ip_permission(params, with_description):
    ip_range = {"CidrIp": params["CidrIp"]}
    if with_description and params.get("Description"):
        ip_range["Description"] = params["Description"]
    return {
        "IpProtocol": params["IpProtocol"],
        "FromPort": int(params["FromPort"]),
        "ToPort": int(params["ToPort"]),
        "IpRanges": [ip_range],
    }


def _revoke_call(target, params):
    return {"GroupId": target.id, "IpPermissions": [_ip_permission(params, False)]}


def _authorize_call(target, params):
    call = {"GroupId": target.id, "IpPermissions": [_ip_permission(params, True)]}
    tags = params.get("Tags") or {}
    if tags:
        call["TagSpecifications"] = [
            {
                "ResourceType": "security-group-rule",
                "Tags": [{"Key": k, "Value": str(v)} for k, v in tags.items()],
            }
        ]
    return call


def _ingress_read(aws, target, params):
    sg = aws.client("ec2").describe_security_groups(GroupIds=[target.id])["SecurityGroups"][0]
    matches = []
    for perm in sg.get("IpPermissions", []):
        if (
            perm.get("IpProtocol") != params["IpProtocol"]
            or perm.get("FromPort") != int(params["FromPort"])
            or perm.get("ToPort") != int(params["ToPort"])
        ):
            continue
        for ip_range in perm.get("IpRanges", []):
            if ip_range.get("CidrIp") == params["CidrIp"]:
                matches.append(
                    {
                        "IpProtocol": perm["IpProtocol"],
                        "FromPort": perm["FromPort"],
                        "ToPort": perm["ToPort"],
                        "CidrIp": ip_range["CidrIp"],
                        "Description": ip_range.get("Description"),
                    }
                )
    return {"matching_rules": matches}


def _sg_response_check(resp):
    if resp.get("Return") is False:
        return "API returned Return=false"
    if resp.get("UnknownIpPermissions"):
        return f"API reported unknown permissions: {resp['UnknownIpPermissions']}"
    return None


# IAM inline role policy (CLD-06)

def _role_policy_read(aws, target, params):
    iam = aws.client("iam")
    try:
        doc = iam.get_role_policy(RoleName=target.name, PolicyName=params["PolicyName"])["PolicyDocument"]
    except iam.exceptions.NoSuchEntityException:
        return {"exists": False}
    if isinstance(doc, str):
        doc = json.loads(doc)
    return {"exists": True, "PolicyDocument": doc}


def _delete_policy_call(target, params):
    return {"RoleName": target.name, "PolicyName": params["PolicyName"]}


def _put_policy_call(target, params):
    return {
        "RoleName": target.name,
        "PolicyName": params["PolicyName"],
        "PolicyDocument": json.dumps(params["PolicyDocument"]),
    }


# Detailed monitoring (CLD-09)

def _monitoring_call(target, params):
    return {"InstanceIds": [target.id]}


def _monitoring_read(aws, target, params):
    return {"MonitoringState": _describe_instance(aws, target).get("Monitoring", {}).get("State")}


HANDLERS = {
    "ec2:ModifyInstanceMetadataOptions": Handler(
        "ec2", "modify_instance_metadata_options", "instance",
        _metadata_call, _metadata_read, _metadata_done, _no_response_check,
    ),
    "ec2:RevokeSecurityGroupIngress": Handler(
        "ec2", "revoke_security_group_ingress", "security_group",
        _revoke_call, _ingress_read,
        lambda state, params: not state["matching_rules"],
        _sg_response_check,
    ),
    "ec2:AuthorizeSecurityGroupIngress": Handler(
        "ec2", "authorize_security_group_ingress", "security_group",
        _authorize_call, _ingress_read,
        lambda state, params: bool(state["matching_rules"]),
        _sg_response_check,
    ),
    "iam:DeleteRolePolicy": Handler(
        "iam", "delete_role_policy", "iam_role",
        _delete_policy_call, _role_policy_read,
        lambda state, params: not state["exists"],
        _no_response_check,
    ),
    "iam:PutRolePolicy": Handler(
        "iam", "put_role_policy", "iam_role",
        _put_policy_call, _role_policy_read,
        lambda state, params: state["exists"] and state["PolicyDocument"] == params["PolicyDocument"],
        _no_response_check,
    ),
    "ec2:MonitorInstances": Handler(
        "ec2", "monitor_instances", "instance",
        _monitoring_call, _monitoring_read,
        lambda state, params: state["MonitoringState"] in ("enabled", "pending"),
        _no_response_check,
    ),
    "ec2:UnmonitorInstances": Handler(
        "ec2", "unmonitor_instances", "instance",
        _monitoring_call, _monitoring_read,
        lambda state, params: state["MonitoringState"] in ("disabled", "disabling"),
        _no_response_check,
    ),
}


# State each action would leave behind, in the same shape its handler's read
# returns. Used only by --dry-run to show "would set" next to "current".

def _ingress_desired_rule(params):
    return {
        "IpProtocol": params["IpProtocol"],
        "FromPort": int(params["FromPort"]),
        "ToPort": int(params["ToPort"]),
        "CidrIp": params["CidrIp"],
        "Description": params.get("Description"),
    }


DESIRED_STATE = {
    "ec2:ModifyInstanceMetadataOptions": lambda params: dict(params),
    "ec2:RevokeSecurityGroupIngress": lambda params: {"matching_rules": []},
    "ec2:AuthorizeSecurityGroupIngress": lambda params: {"matching_rules": [_ingress_desired_rule(params)]},
    "iam:DeleteRolePolicy": lambda params: {"exists": False},
    "iam:PutRolePolicy": lambda params: {"exists": True, "PolicyDocument": params["PolicyDocument"]},
    "ec2:MonitorInstances": lambda params: {"MonitoringState": "enabled"},
    "ec2:UnmonitorInstances": lambda params: {"MonitoringState": "disabled"},
}


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

def validate_steps(rule, steps):
    """Static checks that need no AWS access. Raises Refused on the first problem."""
    scope_account = str(rule["scope"].get("account", ""))
    if scope_account != ALLOWED_ACCOUNT:
        raise Refused(f"scope.account is {scope_account or '<empty>'}, engine only allows {ALLOWED_ACCOUNT}")
    allowed = set(rule["scope"].get("allowed_actions") or [])
    for idx, step in enumerate(steps):
        action = step.get("action")
        if action not in allowed:
            raise Refused(f"step {idx + 1}: action {action} is not in scope.allowed_actions")
        handler = HANDLERS.get(action)
        if handler is None:
            raise Refused(f"step {idx + 1}: action {action} is not supported by this engine")
        target_type = (step.get("target") or {}).get("type")
        if target_type != handler.target_type:
            raise Refused(
                f"step {idx + 1}: action {action} needs target type {handler.target_type}, "
                f"rule says {target_type}"
            )
        if not (step.get("target") or {}).get("name"):
            raise Refused(f"step {idx + 1}: target.name is missing")


def check_caller_account(aws):
    account = aws.client("sts").get_caller_identity()["Account"]
    if account != ALLOWED_ACCOUNT:
        raise Refused(f"credentials are for account {account}, engine only allows {ALLOWED_ACCOUNT}")
    return account


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def run_steps(aws, rule, mode, steps):
    """Resolve and gate every target first, then execute steps in order."""
    resolved = []
    cache = {}
    for step in steps:
        tgt = step["target"]
        key = (tgt["type"], tgt["name"])
        if key not in cache:
            target = RESOLVERS[tgt["type"]](aws, tgt["name"])
            check_target_scope(rule, target)
            cache[key] = target
        resolved.append((step, cache[key]))

    for idx, (step, target) in enumerate(resolved, start=1):
        action = step["action"]
        handler = HANDLERS[action]
        params = step.get("params") or {}
        call = handler.build_call(target, params)
        label = f"[{idx}/{len(resolved)}] {action} on {target.type} {target.name} ({target.id})"

        before = handler.read(aws, target, params)
        if handler.is_done(before, params):
            print(f"{label}: already in desired state, no change")
            audit(rule, mode, action, "noop", call, target, before, before)
            continue

        try:
            resp = getattr(aws.client(handler.service), handler.method)(**call)
        except Exception as exc:
            print(f"{label}: FAILED: {type(exc).__name__}: {exc}")
            audit(rule, mode, action, "failed", call, target, before, None,
                  {"error": f"{type(exc).__name__}: {exc}"})
            return False
        resp = {k: v for k, v in (resp or {}).items() if k != "ResponseMetadata"}
        problem = handler.check_response(resp)
        after = handler.read(aws, target, params)
        if problem:
            print(f"{label}: FAILED: {problem}")
            audit(rule, mode, action, "failed", call, target, before, after, {"error": problem})
            return False
        print(f"{label}: done")
        print(f"    before: {json.dumps(redact(before), default=str)}")
        print(f"    after:  {json.dumps(redact(after), default=str)}")
        audit(rule, mode, action, "success", call, target, before, after, {"response": resp} if resp else None)
    return True


def run_verify(aws, rule):
    check_name = rule["verify"].get("check")
    expect = rule["verify"].get("expect", "closed")
    action = f"verify:{check_name}"
    try:
        if str(PROJECT_ROOT) not in sys.path:
            sys.path.insert(0, str(PROJECT_ROOT))
        scanner = importlib.import_module("scanner.cloud_checks")
        func = getattr(scanner, check_name)
    except (ImportError, AttributeError) as exc:
        print(f"Verify pending: scanner check {check_name} not available ({exc}).")
        audit(rule, "apply", action, "pending", {"check": check_name}, detail={"error": str(exc)})
        return True

    status, evidence = "error", "not run"
    for attempt in range(1, VERIFY_ATTEMPTS + 1):
        ec2 = aws.client("ec2")
        instance = scanner.find_instance(ec2)
        if instance is None:
            status, evidence = "error", "No running vuln-lab-target instance found for verify"
            break
        ctx = {"ec2": ec2, "iam": aws.client("iam"), "instance": instance,
               "instance_id": instance["InstanceId"]}
        try:
            status, evidence = func(ctx)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if check_name == "check_cld06" and code == "NoSuchEntity":
                # The inline policy (or its role) is gone, so the s3:* grant is too.
                status, evidence = "closed", f"Checked resource no longer exists ({code})"
            else:
                status, evidence = "error", f"{type(exc).__name__}: {exc}"
        if status == expect or attempt == VERIFY_ATTEMPTS:
            break
        print(f"Verify attempt {attempt}: status {status}, retrying in {VERIFY_DELAY_S}s")
        time.sleep(VERIFY_DELAY_S)

    passed = status == expect
    print(f"Verify {check_name}: status={status} (expected {expect}) {'PASS' if passed else 'FAIL'}")
    print(f"    evidence: {evidence}")
    audit(rule, "apply", action, "passed" if passed else "failed",
          {"check": check_name, "expect": expect}, after={"status": status, "evidence": evidence})
    return passed


def run_rule(rule, mode, profile, region):
    rule_id = rule["id"]
    section = rule["fix"] if mode == "apply" else rule["rollback"]
    steps = section.get("steps") or []

    if mode == "apply" and is_draft(rule):
        print(f"{rule_id}: REFUSED: {DRAFT_MESSAGE}")
        audit(rule, mode, "none", "refused", detail={"reason": "draft"})
        return EXIT_REFUSED

    if is_pending(rule):
        print(f"{rule_id}: approval pending (approved_by={rule.get('approved_by')!r}). Skipping.")
        audit(rule, mode, "none", "skipped", detail={"reason": "approval pending"})
        return EXIT_REFUSED

    if rule["fix"]["type"] == "manual":
        print(f"{rule_id}: manual {mode}. The engine makes no changes for this rule.")
        print()
        print(section.get("description", "(no description)"))
        audit(rule, mode, "none", "manual", detail={"reason": "fix.type manual"})
        return EXIT_OK

    if not steps:
        print(f"{rule_id}: no {mode} steps defined. Nothing to do.")
        audit(rule, mode, "none", "noop", detail={"reason": "no steps"})
        return EXIT_OK

    try:
        validate_steps(rule, steps)
    except Refused as exc:
        print(f"{rule_id}: REFUSED: {exc}")
        audit(rule, mode, "none", "refused", detail={"reason": str(exc)})
        return EXIT_REFUSED

    from botocore.exceptions import BotoCoreError, ClientError

    print(f"{rule_id}: {mode} ({section.get('description', '').strip()})")
    try:
        aws = Aws(profile, region)
        account = check_caller_account(aws)
        print(f"Account {account}, region {region}, profile {profile}")
        ok = run_steps(aws, rule, mode, steps)
    except Refused as exc:
        print(f"{rule_id}: REFUSED: {exc}")
        audit(rule, mode, "none", "refused", detail={"reason": str(exc)})
        return EXIT_REFUSED
    except (BotoCoreError, ClientError) as exc:
        print(f"{rule_id}: AWS error: {type(exc).__name__}: {exc}")
        audit(rule, mode, "none", "failed", detail={"error": f"{type(exc).__name__}: {exc}"})
        return EXIT_FAILED

    if not ok:
        print(f"{rule_id}: stopped after a failed step. Review the audit log before retrying.")
        return EXIT_FAILED

    if mode == "apply":
        try:
            verified = run_verify(aws, rule)
        except (BotoCoreError, ClientError) as exc:
            print(f"Verify error: {type(exc).__name__}: {exc}")
            audit(rule, mode, f"verify:{rule['verify'].get('check')}", "failed",
                  detail={"error": f"{type(exc).__name__}: {exc}"})
            return EXIT_FAILED
        return EXIT_OK if verified else EXIT_FAILED
    return EXIT_OK


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------

def plan_steps(aws, rule, steps):
    """Resolve and gate every target, then read current state for each step.

    Makes describe/get calls only. Returns one plan entry per step.
    """
    resolved = []
    cache = {}
    for step in steps:
        tgt = step["target"]
        key = (tgt["type"], tgt["name"])
        if key not in cache:
            target = RESOLVERS[tgt["type"]](aws, tgt["name"])
            check_target_scope(rule, target)
            cache[key] = target
        resolved.append((step, cache[key]))

    plan = []
    for idx, (step, target) in enumerate(resolved, start=1):
        action = step["action"]
        handler = HANDLERS[action]
        params = step.get("params") or {}
        current = handler.read(aws, target, params)
        would_set = DESIRED_STATE[action](params)
        status = "already in desired state" if handler.is_done(current, params) else "would change"
        print(f"[{idx}/{len(resolved)}] {action}")
        print(f"    target:    {target.type} {target.name} ({target.id})")
        print(f"    current:   {json.dumps(redact(current), default=str)}")
        print(f"    would set: {json.dumps(redact(would_set), default=str)}")
        print(f"    status:    {status}")
        plan.append({
            "step": idx,
            "action": action,
            "target": target.summary(),
            "current": current,
            "would_set": would_set,
            "status": status,
            "call": handler.build_call(target, params),
        })
    return plan


def run_dry_run(rule, profile, region, aws_factory=ReadOnlyAws):
    """Show what --apply would change. Ignores approval; writes exactly one audit entry."""
    rule_id = rule["id"]
    mode = "dry-run"
    section = rule["fix"]
    steps = section.get("steps") or []

    if rule["fix"]["type"] == "manual":
        print(f"{rule_id}: manual fix. The engine makes no changes for this rule.")
        print()
        print(section.get("description", "(no description)"))
        audit(rule, mode, "none", "manual", detail={"reason": "fix.type manual"})
        return EXIT_OK

    if is_pending(rule):
        print(f"{rule_id}: approval pending (approved_by={rule.get('approved_by')!r}). "
              f"Dry-run continues; --apply would refuse this rule.")

    if is_draft(rule):
        print(f"{rule_id}: {DRAFT_MESSAGE} Dry-run continues; --apply would refuse this rule.")

    if not steps:
        print(f"{rule_id}: no fix steps defined. Nothing to do.")
        audit(rule, mode, "none", "noop", detail={"reason": "no steps"})
        return EXIT_OK

    try:
        validate_steps(rule, steps)
        for idx, step in enumerate(steps, start=1):
            if step["action"] not in DESIRED_STATE:
                raise Refused(f"step {idx}: action {step['action']} has no dry-run support")
    except Refused as exc:
        print(f"{rule_id}: REFUSED: {exc}")
        audit(rule, mode, "none", "refused", detail={"reason": str(exc)})
        return EXIT_REFUSED

    from botocore.exceptions import BotoCoreError, ClientError

    print(f"{rule_id}: dry-run of fix ({section.get('description', '').strip()})")
    print("Read-only: no changes will be made.")
    try:
        aws = aws_factory(profile, region)
        account = check_caller_account(aws)
        print(f"Account {account}, region {region}, profile {profile}")
        plan = plan_steps(aws, rule, steps)
    except Refused as exc:
        print(f"{rule_id}: REFUSED: {exc}")
        audit(rule, mode, "none", "refused", detail={"reason": str(exc)})
        return EXIT_REFUSED
    except (BotoCoreError, ClientError) as exc:
        print(f"{rule_id}: AWS error: {type(exc).__name__}: {exc}")
        audit(rule, mode, "none", "failed", detail={"error": f"{type(exc).__name__}: {exc}"})
        return EXIT_FAILED

    changes = sum(1 for p in plan if p["status"] == "would change")
    print()
    print(f"{rule_id}: {changes} of {len(plan)} step(s) would change. Nothing was changed.")
    audit(rule, mode, "plan", "planned", detail={
        "approved_by": str(rule.get("approved_by") or "pending"),
        "would_change": changes,
        "planned_changes": plan,
    })
    return EXIT_OK


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_list(rules):
    titles = load_titles()
    headers = ("ID", "FIX TYPE", "STEPS", "APPROVED BY", "VER", "TITLE")
    rows = []
    for rule_id, rule in rules.items():
        rows.append((
            rule_id,
            rule["fix"]["type"],
            str(len(rule["fix"].get("steps") or [])),
            str(rule.get("approved_by") or "pending"),
            str(rule.get("version")),
            titles.get(rule_id, ""),
        ))
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    fmt = " | ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print("+".join("-" * (w + 2) for w in widths))
    for row in rows:
        print(fmt.format(*row))
    pending = sum(1 for r in rules.values() if is_pending(r))
    print()
    print(f"{len(rules)} rules loaded from {RULES_DIR}, {pending} pending approval.")


def main():
    parser = argparse.ArgumentParser(description="Rule-based remediation engine for ec2-vuln-lab")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list", action="store_true", help="show rules and their fix type")
    mode.add_argument("--dry-run", metavar="RULE_ID",
                      help="show what a rule's fix steps would change, using read-only calls "
                           "(RULE_ID may also be a remediations/drafts/*.draft.yaml path)")
    mode.add_argument("--apply", metavar="RULE_ID", help="run a rule's fix steps, then verify")
    mode.add_argument("--rollback", metavar="RULE_ID", help="run a rule's rollback steps")
    parser.add_argument("--profile", default="sandbox-tf", help="AWS profile (default: sandbox-tf)")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    args = parser.parse_args()

    try:
        rules = load_rules()
    except (RuleError, yaml.YAMLError) as exc:
        sys.exit(f"Rule load error: {exc}")
    if not rules:
        sys.exit(f"No rule files found in {RULES_DIR}")

    if args.list:
        print_list(rules)
        return EXIT_OK

    # Drafts are loaded only when named by file path, and only for --dry-run
    # and --apply. --apply then refuses them in run_rule.
    draft_arg = args.dry_run or args.apply
    if draft_arg:
        try:
            draft_path = find_draft(draft_arg)
            draft = load_draft(draft_path) if draft_path else None
        except (RuleError, yaml.YAMLError) as exc:
            sys.exit(f"Rule load error: {exc}")
        if draft is not None:
            if args.dry_run:
                return run_dry_run(draft, args.profile, args.region)
            return run_rule(draft, "apply", args.profile, args.region)

    if args.dry_run:
        rule_id = args.dry_run.upper()
        if rule_id not in rules:
            sys.exit(f"Unknown rule {rule_id}. Known: {', '.join(rules)}")
        return run_dry_run(rules[rule_id], args.profile, args.region)

    rule_id = (args.apply or args.rollback).upper()
    if rule_id not in rules:
        sys.exit(f"Unknown rule {rule_id}. Known: {', '.join(rules)}")
    return run_rule(rules[rule_id], "apply" if args.apply else "rollback", args.profile, args.region)


if __name__ == "__main__":
    sys.exit(main())
