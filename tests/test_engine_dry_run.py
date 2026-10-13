"""Tests for remediations/engine.py --dry-run. Uses fake AWS clients; makes no AWS calls.

Run: py -3.13 -m unittest discover -s tests
"""

import contextlib
import copy
import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "remediations"))

import engine  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webapp"))

import server  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ACCOUNT = engine.ALLOWED_ACCOUNT
GOOD_TAGS = [{"Key": "Project", "Value": "ec2-vuln-lab"}]


class NoSuchEntityException(Exception):
    pass


class FakeClient:
    """Records every method called on it. Mutating methods exist so the guard is what stops them."""

    def __init__(self, log, name, responses):
        self._log = log
        self._name = name
        self._responses = responses
        self.exceptions = mock.Mock(NoSuchEntityException=NoSuchEntityException)

    def __getattr__(self, method):
        def call(**kwargs):
            self._log.append(f"{self._name}.{method}")
            resp = self._responses.get(method)
            if isinstance(resp, Exception):
                raise resp
            return resp if resp is not None else {}
        return call


class FakeSession:
    def __init__(self, log, responses):
        self._log = log
        self._responses = responses

    def client(self, name):
        return FakeClient(self._log, name, self._responses.get(name, {}))


def instance(http_tokens="optional", owner=ACCOUNT, tags=GOOD_TAGS):
    inst = {
        "InstanceId": "i-0123456789abcdef0",
        "Tags": [{"Key": "Name", "Value": "vuln-lab-target"}] + tags,
        "MetadataOptions": {"HttpTokens": http_tokens, "HttpEndpoint": "enabled"},
        "Monitoring": {"State": "disabled"},
    }
    return {"Reservations": [{"OwnerId": owner, "Instances": [inst]}]}


def responses(caller=ACCOUNT, **ec2):
    return {
        "sts": {"get_caller_identity": {"Account": caller}},
        "ec2": {"describe_instances": instance(), **ec2},
        "iam": {},
    }


class DryRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit_log = Path(self.tmp.name) / "remediation-log.jsonl"
        patcher = mock.patch.object(engine, "AUDIT_LOG", self.audit_log)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        self.rule_hashes = self._hash_rules()
        self.rules = engine.load_rules()
        self.calls = []
        self.factory_used = False

    def tearDown(self):
        self.assertEqual(self.rule_hashes, self._hash_rules(), "a rule file was modified")

    @staticmethod
    def _hash_rules():
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(engine.RULES_DIR.glob("*.yaml"))}

    def _factory(self, resp):
        def make(profile, region):
            self.factory_used = True
            aws = engine.ReadOnlyAws.__new__(engine.ReadOnlyAws)
            aws.session = FakeSession(self.calls, resp)
            aws.region = region
            aws._clients = {}
            return aws
        return make

    def _run(self, rule, resp):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = engine.run_dry_run(rule, "test-profile", "us-east-1", self._factory(resp))
        return code, out.getvalue()

    def _audit_entries(self):
        lines = self.audit_log.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines]

    def _assert_read_only(self):
        for call in self.calls:
            method = call.split(".", 1)[1]
            self.assertTrue(method.startswith(engine.READ_ONLY_PREFIXES), call)

    def test_pending_rule_plans_change(self):
        rule = dict(self.rules["CLD-01"], approved_by="pending", approved_on="")
        self.assertTrue(engine.is_pending(rule))
        code, out = self._run(rule, responses())
        self.assertEqual(code, engine.EXIT_OK)
        self.assertIn("would change", out)
        self.assertIn('"HttpTokens": "optional"', out)
        self.assertIn('"HttpTokens": "required"', out)
        self._assert_read_only()
        entries = self._audit_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["mode"], "dry-run")
        self.assertEqual(entries[0]["result"], "planned")
        step = entries[0]["detail"]["planned_changes"][0]
        self.assertEqual(step["status"], "would change")
        self.assertEqual(step["would_set"], {"HttpTokens": "required", "HttpEndpoint": "enabled"})

    def test_already_in_desired_state(self):
        code, out = self._run(self.rules["CLD-01"],
                              responses(describe_instances=instance(http_tokens="required")))
        self.assertEqual(code, engine.EXIT_OK)
        self.assertIn("already in desired state", out)
        self.assertEqual(self._audit_entries()[0]["detail"]["would_change"], 0)

    def test_security_group_revoke(self):
        sg = {
            "GroupId": "sg-0123", "OwnerId": ACCOUNT, "Tags": GOOD_TAGS,
            "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                               "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        }
        code, out = self._run(self.rules["CLD-02"],
                              responses(describe_security_groups={"SecurityGroups": [sg]}))
        self.assertEqual(code, engine.EXIT_OK)
        self.assertIn("would change", out)
        self.assertNotIn("ec2.revoke_security_group_ingress", self.calls)
        self._assert_read_only()

    def test_iam_policy_already_deleted(self):
        resp = responses()
        resp["iam"] = {
            "get_role": {"Role": {"Arn": f"arn:aws:iam::{ACCOUNT}:role/vuln-lab-target-role",
                                  "RoleId": "AROA123", "Tags": GOOD_TAGS}},
            "get_role_policy": NoSuchEntityException(),
        }
        code, out = self._run(self.rules["CLD-06"], resp)
        self.assertEqual(code, engine.EXIT_OK)
        self.assertIn("already in desired state", out)
        self._assert_read_only()

    def test_wrong_caller_account_refused(self):
        code, out = self._run(self.rules["CLD-01"], responses(caller="111111111111"))
        self.assertEqual(code, engine.EXIT_REFUSED)
        self.assertIn("REFUSED", out)
        entries = self._audit_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["result"], "refused")

    def test_wrong_target_account_refused(self):
        code, _ = self._run(self.rules["CLD-01"],
                            responses(describe_instances=instance(owner="111111111111")))
        self.assertEqual(code, engine.EXIT_REFUSED)

    def test_missing_tag_refused(self):
        code, out = self._run(self.rules["CLD-01"], responses(describe_instances=instance(tags=[])))
        self.assertEqual(code, engine.EXIT_REFUSED)
        self.assertIn("lacks tag Project=ec2-vuln-lab", out)
        self.assertEqual(len(self._audit_entries()), 1)

    def test_action_not_allowed_refused_before_aws(self):
        rule = copy.deepcopy(self.rules["CLD-01"])
        rule["scope"]["allowed_actions"] = []
        code, _ = self._run(rule, responses())
        self.assertEqual(code, engine.EXIT_REFUSED)
        self.assertFalse(self.factory_used)

    def test_unsupported_action_refused_before_aws(self):
        rule = copy.deepcopy(self.rules["CLD-01"])
        rule["fix"]["steps"][0]["action"] = "ec2:StopInstances"
        rule["scope"]["allowed_actions"] = ["ec2:StopInstances"]
        code, out = self._run(rule, responses())
        self.assertEqual(code, engine.EXIT_REFUSED)
        self.assertIn("not supported", out)
        self.assertFalse(self.factory_used)

    def test_manual_rule_prints_description(self):
        code, out = self._run(self.rules["CLD-05"], responses())
        self.assertEqual(code, engine.EXIT_OK)
        self.assertIn("Rebuild required", out)
        self.assertFalse(self.factory_used)
        entries = self._audit_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["result"], "manual")

    def test_guard_blocks_mutating_calls(self):
        aws = self._factory(responses())("p", "r")
        for service, method in [("ec2", "modify_instance_metadata_options"),
                                ("ec2", "authorize_security_group_ingress"),
                                ("ec2", "revoke_security_group_ingress"),
                                ("iam", "put_role_policy"),
                                ("iam", "delete_role_policy"),
                                ("iam", "attach_role_policy"),
                                ("ec2", "create_tags"),
                                ("ec2", "monitor_instances"),
                                ("ec2", "unmonitor_instances"),
                                ("ec2", "create_flow_logs"),
                                ("ec2", "delete_flow_logs"),
                                ("ec2", "create_volume"),
                                ("ec2", "delete_volume"),
                                ("ssm", "send_command")]:
            with self.assertRaises(engine.Refused):
                getattr(aws.client(service), method)
        self.assertEqual(self.calls, [])

    def test_every_handler_has_desired_state(self):
        self.assertEqual(set(engine.HANDLERS), set(engine.DESIRED_STATE))


def sg_responses():
    sg = {
        "GroupId": "sg-0123", "OwnerId": ACCOUNT, "Tags": GOOD_TAGS,
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                           "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    }
    return responses(describe_security_groups={"SecurityGroups": [sg]})


class DraftTests(unittest.TestCase):
    """Draft rules. Drafts are written to a temporary folder patched in as DRAFTS_DIR."""

    # Shared with DryRunTests without inheriting (and re-running) its tests.
    tearDown = DryRunTests.tearDown
    _hash_rules = staticmethod(DryRunTests._hash_rules)
    _factory = DryRunTests._factory
    _audit_entries = DryRunTests._audit_entries
    _assert_read_only = DryRunTests._assert_read_only

    def setUp(self):
        DryRunTests.setUp(self)
        self.drafts_dir = (Path(self.tmp.name) / "drafts").resolve()
        self.drafts_dir.mkdir()
        patcher = mock.patch.object(engine, "DRAFTS_DIR", self.drafts_dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        # Any real AWS session would be a test failure.
        patcher = mock.patch.object(engine, "Aws", side_effect=AssertionError("real AWS used"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _write_draft(self, folder, **overrides):
        source = engine.ENGINE_DIR / "drafts" / "CLD-02.draft.yaml"
        draft = engine.yaml.safe_load(source.read_text(encoding="utf-8"))
        draft.update(overrides)
        path = folder / "CLD-02.draft.yaml"
        path.write_text(engine.yaml.safe_dump(draft, sort_keys=False), encoding="utf-8")
        return path

    def _main(self, *args, resp=None):
        real_dry_run = engine.run_dry_run

        def dry_run(rule, profile, region):
            return real_dry_run(rule, profile, region, self._factory(resp or responses()))

        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["engine.py", *args]), \
                mock.patch.object(engine, "run_dry_run", dry_run), \
                contextlib.redirect_stdout(out):
            code = engine.main()
        return code, out.getvalue()

    def test_apply_refuses_draft_even_when_approved(self):
        path = self._write_draft(self.drafts_dir, approved_by="ronan", approved_on="2026-10-11")
        code, out = self._main("--apply", path.as_posix())
        self.assertEqual(code, engine.EXIT_REFUSED)
        self.assertIn(engine.DRAFT_MESSAGE, out)
        self.assertFalse(self.factory_used)
        self.assertEqual(self.calls, [])
        entries = self._audit_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["mode"], "apply")
        self.assertEqual(entries[0]["result"], "refused")
        self.assertEqual(entries[0]["detail"], {"reason": "draft"})

    def test_dry_run_works_on_draft(self):
        path = self._write_draft(self.drafts_dir)
        code, out = self._main("--dry-run", path.as_posix(), resp=sg_responses())
        self.assertEqual(code, engine.EXIT_OK)
        self.assertIn(engine.DRAFT_MESSAGE, out)
        self.assertIn("would change", out)
        self.assertTrue(self.factory_used)
        self._assert_read_only()
        entries = self._audit_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["mode"], "dry-run")
        self.assertEqual(entries[0]["result"], "planned")

    def test_ai_approver_counts_as_pending(self):
        rule = dict(self.rules["CLD-01"], approved_by="ai")
        self.assertTrue(engine.is_pending(rule))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = engine.run_rule(rule, "apply", "test-profile", "us-east-1")
        self.assertEqual(code, engine.EXIT_REFUSED)
        self.assertIn("approval pending", out.getvalue())
        self.assertEqual(self._audit_entries()[0]["result"], "skipped")

    def test_dry_run_rejects_draft_outside_drafts_dir(self):
        other = Path(self.tmp.name) / "elsewhere"
        other.mkdir()
        path = self._write_draft(other)
        with self.assertRaises(SystemExit) as ctx:
            self._main("--dry-run", path.as_posix())
        self.assertIn("drafts are only read from", str(ctx.exception.code))
        self.assertFalse(self.factory_used)
        self.assertFalse(self.audit_log.exists())


def make_rule(action, target_type, name, params=None):
    step = {"action": action, "target": {"type": target_type, "name": name}, "params": params or {}}
    return {
        "id": "TST-01", "version": 1, "match": {},
        "scope": {"account": ACCOUNT, "tags": {}, "allowed_actions": [action]},
        "fix": {"type": "automated", "description": "test", "steps": [step]},
        "rollback": {"description": "test", "steps": []},
        "verify": {"check": "none", "expect": "closed"},
        "approved_by": "pending", "approved_on": "",
    }


LAB_VPC = {"VpcId": "vpc-0123", "OwnerId": ACCOUNT,
           "Tags": [{"Key": "Name", "Value": "vuln-lab-vpc"}] + GOOD_TAGS}
FLOW_LOG_PARAMS = {"TrafficType": "ALL", "LogDestinationType": "s3",
                   "LogDestination": "arn:aws:s3:::vuln-lab-flow-logs"}


def volume(attached=False, tags=GOOD_TAGS):
    vol = {"VolumeId": "vol-0123", "Size": 8, "State": "in-use" if attached else "available",
           "Tags": [{"Key": "Name", "Value": "vuln-lab-scratch"}] + tags,
           "Attachments": [{"InstanceId": "i-0123456789abcdef0", "State": "attached"}] if attached else []}
    return {"Volumes": [vol]}


class HandlerTests(unittest.TestCase):
    """Dry-run and gate tests for each handler, using the fake AWS clients."""

    tearDown = DryRunTests.tearDown
    _hash_rules = staticmethod(DryRunTests._hash_rules)
    _factory = DryRunTests._factory
    _run = DryRunTests._run
    _audit_entries = DryRunTests._audit_entries
    _assert_read_only = DryRunTests._assert_read_only

    def setUp(self):
        DryRunTests.setUp(self)

    def _planned(self):
        entries = self._audit_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["result"], "planned")
        return entries[0]["detail"]["planned_changes"][0]

    def _assert_refused_before_aws(self, rule, text):
        code, out = self._run(rule, responses())
        self.assertEqual(code, engine.EXIT_REFUSED)
        self.assertIn(text, out)
        self.assertFalse(self.factory_used)
        self.assertEqual(self.calls, [])

    def test_monitor_instances_dry_run(self):
        code, out = self._run(self.rules["CLD-09"], responses())
        self.assertEqual(code, engine.EXIT_OK)
        self.assertIn("would change", out)
        self.assertEqual(self._planned()["current"], {"MonitoringState": "disabled"})
        self._assert_read_only()

    def test_unmonitor_instances_dry_run(self):
        rule = make_rule("ec2:UnmonitorInstances", "instance", "vuln-lab-target")
        code, out = self._run(rule, responses())
        self.assertEqual(code, engine.EXIT_OK)
        self.assertIn("already in desired state", out)
        self._assert_read_only()

    def test_create_flow_logs_dry_run(self):
        rule = make_rule("ec2:CreateFlowLogs", "vpc", "vuln-lab-vpc", FLOW_LOG_PARAMS)
        code, out = self._run(rule, responses(describe_vpcs={"Vpcs": [LAB_VPC]},
                                              describe_flow_logs={"FlowLogs": []}))
        self.assertEqual(code, engine.EXIT_OK)
        self.assertIn("would change", out)
        call = self._planned()["call"]
        self.assertEqual(call["ResourceIds"], ["vpc-0123"])
        self.assertIn({"Key": "Project", "Value": "ec2-vuln-lab"}, call["TagSpecifications"][0]["Tags"])
        self.assertIn("ec2.describe_flow_logs", self.calls)
        self._assert_read_only()

    def test_delete_flow_logs_dry_run(self):
        rule = make_rule("ec2:DeleteFlowLogs", "vpc", "vuln-lab-vpc", FLOW_LOG_PARAMS)
        existing = {"FlowLogId": "fl-0123", **FLOW_LOG_PARAMS}
        code, out = self._run(rule, responses(describe_vpcs={"Vpcs": [LAB_VPC]},
                                              describe_flow_logs={"FlowLogs": [existing]}))
        self.assertEqual(code, engine.EXIT_OK)
        self.assertIn("would change", out)
        self.assertEqual(self._planned()["call"], {"FlowLogIds": ["fl-0123"]})
        self._assert_read_only()

    def test_flow_logs_refused_for_other_vpc(self):
        rule = make_rule("ec2:CreateFlowLogs", "vpc", "default-vpc", FLOW_LOG_PARAMS)
        self._assert_refused_before_aws(rule, "limited to VPC vuln-lab-vpc")

    def test_flow_logs_refused_for_untagged_vpc(self):
        vpc = dict(LAB_VPC, Tags=[{"Key": "Name", "Value": "vuln-lab-vpc"}])
        rule = make_rule("ec2:CreateFlowLogs", "vpc", "vuln-lab-vpc", FLOW_LOG_PARAMS)
        code, out = self._run(rule, responses(describe_vpcs={"Vpcs": [vpc]}))
        self.assertEqual(code, engine.EXIT_REFUSED)
        self.assertIn("lacks tag Project=ec2-vuln-lab", out)

    def test_create_volume_dry_run(self):
        resp = responses(describe_volumes={"Volumes": []})
        resp["ec2"]["describe_instances"]["Reservations"][0]["Instances"][0]["Placement"] = {
            "AvailabilityZone": "us-east-1a"}
        rule = make_rule("ec2:CreateVolume", "instance", "vuln-lab-target",
                         {"VolumeName": "vuln-lab-scratch", "Size": 8, "Encrypted": True})
        code, out = self._run(rule, resp)
        self.assertEqual(code, engine.EXIT_OK)
        self.assertIn("would change", out)
        call = self._planned()["call"]
        self.assertEqual(call["AvailabilityZone"], "us-east-1a")
        tags = call["TagSpecifications"][0]["Tags"]
        self.assertIn({"Key": "Project", "Value": "ec2-vuln-lab"}, tags)
        self.assertIn({"Key": "Name", "Value": "vuln-lab-scratch"}, tags)
        self._assert_read_only()

    def test_create_volume_needs_name(self):
        rule = make_rule("ec2:CreateVolume", "instance", "vuln-lab-target", {"Size": 8})
        self._assert_refused_before_aws(rule, "needs params.VolumeName")

    def test_delete_volume_dry_run(self):
        rule = make_rule("ec2:DeleteVolume", "volume", "vuln-lab-scratch")
        code, out = self._run(rule, responses(describe_volumes=volume()))
        self.assertEqual(code, engine.EXIT_OK)
        self.assertIn("would change", out)
        self.assertEqual(self._planned()["call"], {"VolumeId": "vol-0123"})
        self._assert_read_only()

    def test_delete_volume_refused_when_attached(self):
        rule = make_rule("ec2:DeleteVolume", "volume", "vuln-lab-scratch")
        code, out = self._run(rule, responses(describe_volumes=volume(attached=True)))
        self.assertEqual(code, engine.EXIT_REFUSED)
        self.assertIn("is attached to i-0123456789abcdef0", out)
        self._assert_read_only()

    def test_delete_volume_refused_when_untagged(self):
        rule = make_rule("ec2:DeleteVolume", "volume", "vuln-lab-scratch")
        code, out = self._run(rule, responses(describe_volumes=volume(tags=[])))
        self.assertEqual(code, engine.EXIT_REFUSED)
        self.assertIn("lacks tag Project=ec2-vuln-lab", out)

    def test_apply_never_deletes_attached_volume(self):
        aws = engine.Aws.__new__(engine.Aws)
        aws.session = FakeSession(self.calls, responses(describe_volumes=volume(attached=True)))
        aws.region = "us-east-1"
        aws._clients = {}
        rule = make_rule("ec2:DeleteVolume", "volume", "vuln-lab-scratch")
        with self.assertRaises(engine.Refused):
            engine.run_steps(aws, rule, "apply", rule["fix"]["steps"])
        self.assertNotIn("ec2.delete_volume", self.calls)

    def test_role_policy_refused_for_other_role(self):
        for action in ("iam:PutRolePolicy", "iam:DeleteRolePolicy"):
            with self.subTest(action=action):
                self.calls.clear()
                self.factory_used = False
                rule = make_rule(action, "iam_role", "admin-role",
                                 {"PolicyName": "p", "PolicyDocument": {}})
                self._assert_refused_before_aws(rule, "limited to role vuln-lab-target-role")

    def test_put_role_policy_dry_run(self):
        resp = responses()
        resp["iam"] = {
            "get_role": {"Role": {"Arn": f"arn:aws:iam::{ACCOUNT}:role/vuln-lab-target-role",
                                  "RoleId": "AROA123", "Tags": GOOD_TAGS}},
            "get_role_policy": NoSuchEntityException(),
        }
        rule = make_rule("iam:PutRolePolicy", "iam_role", "vuln-lab-target-role",
                         {"PolicyName": "p", "PolicyDocument": {"Version": "2012-10-17", "Statement": []}})
        code, out = self._run(rule, resp)
        self.assertEqual(code, engine.EXIT_OK)
        self.assertIn("would change", out)
        self._assert_read_only()

    def test_send_command_dry_run(self):
        resp = responses()
        resp["ssm"] = {"describe_instance_information": {
            "InstanceInformationList": [{"InstanceId": "i-0123456789abcdef0", "PingStatus": "Online"}]}}
        rule = make_rule("ssm:SendCommand", "instance", "vuln-lab-target", {"Command": "show-os-release"})
        code, out = self._run(rule, resp)
        self.assertEqual(code, engine.EXIT_OK)
        self.assertIn("would change", out)
        call = self._planned()["call"]
        self.assertEqual(call["DocumentName"], "AWS-RunShellScript")
        self.assertEqual(call["Parameters"], {"commands": engine.SSM_COMMANDS["show-os-release"]})
        self.assertIn("ssm.describe_instance_information", self.calls)
        self._assert_read_only()

    def test_send_command_rejects_unlisted_command(self):
        rule = make_rule("ssm:SendCommand", "instance", "vuln-lab-target", {"Command": "rm -rf /"})
        self._assert_refused_before_aws(rule, "is not on the allowlist")

    def test_send_command_rejects_extra_params(self):
        rule = make_rule("ssm:SendCommand", "instance", "vuln-lab-target",
                         {"Command": "show-os-release", "DocumentName": "AWS-RunPowerShellScript"})
        self._assert_refused_before_aws(rule, "only accepts params.Command")

    def test_send_command_refused_for_untagged_instance(self):
        rule = make_rule("ssm:SendCommand", "instance", "vuln-lab-target", {"Command": "show-os-release"})
        code, out = self._run(rule, responses(describe_instances=instance(tags=[])))
        self.assertEqual(code, engine.EXIT_REFUSED)
        self.assertIn("lacks tag Project=ec2-vuln-lab", out)

    def test_forbidden_actions_refused(self):
        for action, target_type in [("ec2:TerminateInstances", "instance"),
                                    ("ec2:DeleteVpc", "vpc"),
                                    ("iam:CreateUser", "iam_role"),
                                    ("iam:AttachUserPolicy", "iam_role"),
                                    ("iam:DeleteRole", "iam_role"),
                                    ("organizations:DetachPolicy", "instance"),
                                    ("aws-portal:ModifyBilling", "instance"),
                                    ("billing:UpdateBillingPreferences", "instance")]:
            with self.subTest(action=action):
                self.calls.clear()
                self.factory_used = False
                rule = make_rule(action, target_type, "vuln-lab-target")
                self._assert_refused_before_aws(rule, "always refused")

    def test_forbidden_action_in_allowed_list_refuses_rule(self):
        rule = copy.deepcopy(self.rules["CLD-01"])
        rule["scope"]["allowed_actions"].append("ec2:TerminateInstances")
        self._assert_refused_before_aws(rule, "scope.allowed_actions lists ec2:TerminateInstances")


# CLD-09 has its rule file removed in ServerFullDraftTests, so the server drafts it from scratch.
SCRATCH_ID = "CLD-09"
SG_PARAMS = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0",
             "Description": "lab ssh"}


def full_draft_step(action="ec2:MonitorInstances", target_type="instance", name="vuln-lab-target"):
    return {"action": action, "target": {"type": target_type, "name": name}, "params": {}}


def full_draft_reply(fix_step=None, check="check_cld09", allowed=None):
    """A stubbed model reply for a full draft. Valid unless an argument changes it."""
    fix_step = fix_step or full_draft_step()
    reply = {
        "match": {"check": check},
        "scope": {"allowed_actions": allowed or [fix_step["action"], "ec2:UnmonitorInstances"],
                  "account": "111111111111"},
        "fix": {"type": "automated", "description": "Enable detailed monitoring.", "steps": [fix_step]},
        "rollback": {"description": "Disable detailed monitoring.",
                     "steps": [full_draft_step("ec2:UnmonitorInstances")]},
        "verify": {"check": check, "expect": "closed"},
    }
    return engine.yaml.safe_dump(reply, sort_keys=False)


class ServerFullDraftTests(unittest.TestCase):
    """POST /api/drafts for a finding with no approved rule. The model reply is stubbed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.rule_hashes = DryRunTests._hash_rules()
        tmp = Path(self.tmp.name)
        rules_dir = tmp / "rules"
        rules_dir.mkdir()
        for path in engine.RULES_DIR.glob("*.yaml"):
            if path.stem != SCRATCH_ID:
                shutil.copy(path, rules_dir / path.name)
        self.drafts_dir = tmp / "drafts"
        self.request_draft = mock.Mock()
        settings = {"DRAFT_API_BASE": "https://model.invalid/v1", "DRAFT_API_KEY": "k", "DRAFT_MODEL": "m"}
        for target, value in [(server, {"RULES_DIR": rules_dir}),
                              (server, {"DRAFTS_DIR": self.drafts_dir}),
                              (server, {"load_draft_settings": mock.Mock(return_value=settings)}),
                              (server, {"request_draft": self.request_draft}),
                              (server.urllib.request, {"urlopen": mock.Mock(side_effect=AssertionError("real model call"))})]:
            patcher = mock.patch.multiple(target, **value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = TestClient(server.app)

    def tearDown(self):
        self.assertEqual(self.rule_hashes, DryRunTests._hash_rules(), "a rule file was modified")

    def _post(self, reply):
        self.request_draft.return_value = reply
        resp = self.client.post(f"/api/drafts/{SCRATCH_ID}")
        self.request_draft.assert_called_once()
        return resp

    def _assert_rejected(self, reply, text):
        resp = self._post(reply)
        self.assertEqual(resp.status_code, 422, resp.text)
        self.assertIn(text, resp.json()["detail"])
        self.assertFalse(self.drafts_dir.exists(), "a rejected draft was saved")

    def test_rejects_action_not_on_engine_allowed_list(self):
        step = full_draft_step("ec2:StopInstances")
        self._assert_rejected(full_draft_reply(step, allowed=["ec2:UnmonitorInstances"]),
                              "fix.steps[0] action 'ec2:StopInstances' is not on the engine's allowed list")

    def test_rejects_target_outside_lab(self):
        self._assert_rejected(full_draft_reply(full_draft_step(name="prod-web-server")),
                              "target instance prod-web-server is not a lab resource tagged Project=ec2-vuln-lab")

    def test_rejects_unknown_verify_check(self):
        self._assert_rejected(full_draft_reply(check="check_cld99"),
                              "verify.check 'check_cld99' is not a check in scanner/cloud_checks.py")

    def test_rejects_forbidden_action(self):
        step = full_draft_step("ec2:TerminateInstances")
        self._assert_rejected(full_draft_reply(step, allowed=["ec2:UnmonitorInstances"]),
                              "action ec2:TerminateInstances is forbidden by the engine")

    def test_valid_draft_saved_as_pending_and_not_applied(self):
        resp = self._post(full_draft_reply())
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertIs(body["applied"], False)
        self.assertEqual(body["path"], f"remediations/drafts/{SCRATCH_ID}.draft.yaml")
        saved = engine.yaml.safe_load((self.drafts_dir / f"{SCRATCH_ID}.draft.yaml").read_text(encoding="utf-8"))
        self.assertEqual(saved, body["draft"])
        self.assertIs(saved["draft"], True)
        self.assertEqual(saved["approved_by"], "pending")
        self.assertEqual(saved["scope"]["account"], "145443243505")
        self.assertEqual(saved["scope"]["allowed_actions"], ["ec2:MonitorInstances", "ec2:UnmonitorInstances"])

    def _assert_target_accepted(self, step):
        resp = self._post(full_draft_reply(step))
        self.assertEqual(resp.status_code, 200, resp.text)
        saved = engine.yaml.safe_load((self.drafts_dir / f"{SCRATCH_ID}.draft.yaml").read_text(encoding="utf-8"))
        self.assertEqual(saved["fix"]["steps"][0]["target"], step["target"])
        return saved

    def test_accepts_lab_security_group(self):
        step = full_draft_step("ec2:RevokeSecurityGroupIngress", "security_group", "vuln-lab-target-sg")
        step["params"] = SG_PARAMS
        saved = self._assert_target_accepted(step)
        self.assertEqual(saved["fix"]["steps"][0]["target"]["name"], "vuln-lab-target-sg")

    def test_accepts_lab_role(self):
        step = full_draft_step("iam:DeleteRolePolicy", "iam_role", "vuln-lab-target-role")
        step["params"] = {"PolicyName": "lab-inline-policy"}
        self._assert_target_accepted(step)

    def test_accepts_lab_vpc(self):
        self._assert_target_accepted(full_draft_step("ec2:CreateFlowLogs", "vpc", "vuln-lab-vpc"))

    def test_accepts_lab_instance(self):
        self._assert_target_accepted(full_draft_step("ec2:MonitorInstances", "instance", "vuln-lab-target"))

    def test_rejects_security_group_outside_lab(self):
        step = full_draft_step("ec2:RevokeSecurityGroupIngress", "security_group", "prod-db-sg")
        step["params"] = SG_PARAMS
        self._assert_rejected(full_draft_reply(step),
                              "target security_group prod-db-sg is not a lab resource tagged Project=ec2-vuln-lab")

    def test_rejects_fix_that_adds_access(self):
        step = full_draft_step("ec2:AuthorizeSecurityGroupIngress", "security_group", "vuln-lab-target-sg")
        step["params"] = SG_PARAMS
        self._assert_rejected(full_draft_reply(step), "AI drafts may only remove access")

    def test_accepts_fix_that_only_revokes(self):
        step = full_draft_step("ec2:RevokeSecurityGroupIngress", "security_group", "vuln-lab-target-sg")
        step["params"] = SG_PARAMS
        resp = self._post(full_draft_reply(step))
        self.assertEqual(resp.status_code, 200, resp.text)
        saved = engine.yaml.safe_load((self.drafts_dir / f"{SCRATCH_ID}.draft.yaml").read_text(encoding="utf-8"))
        self.assertEqual(saved["fix"]["steps"][0]["action"], "ec2:RevokeSecurityGroupIngress")

    def test_accepts_rollback_that_re_adds_rule(self):
        step = full_draft_step("ec2:RevokeSecurityGroupIngress", "security_group", "vuln-lab-target-sg")
        step["params"] = SG_PARAMS
        undo = full_draft_step("ec2:AuthorizeSecurityGroupIngress", "security_group", "vuln-lab-target-sg")
        undo["params"] = SG_PARAMS
        reply = engine.yaml.safe_load(full_draft_reply(
            step, allowed=["ec2:RevokeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupIngress"]))
        reply["fix"]["description"] = "Revoke the open SSH rule."
        reply["rollback"] = {"description": "Authorize the SSH rule again.", "steps": [undo]}
        resp = self._post(engine.yaml.safe_dump(reply, sort_keys=False))
        self.assertEqual(resp.status_code, 200, resp.text)
        saved = engine.yaml.safe_load((self.drafts_dir / f"{SCRATCH_ID}.draft.yaml").read_text(encoding="utf-8"))
        self.assertEqual(saved["rollback"]["steps"][0]["action"], "ec2:AuthorizeSecurityGroupIngress")


def rule_draft_reply(fix_extra=None):
    """A stubbed model reply for a finding with an approved rule: wording, plus optional extra steps."""
    reply = {
        "fix": {"description": "Enable detailed monitoring on the lab instance."},
        "rollback": {"description": "Return the lab instance to basic monitoring."},
    }
    if fix_extra is not None:
        reply["fix"]["extra_steps"] = fix_extra
    return engine.yaml.safe_dump(reply, sort_keys=False)


class ServerRuleDraftTests(unittest.TestCase):
    """POST /api/drafts for a finding that has an approved rule. The model reply is stubbed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.rule_hashes = DryRunTests._hash_rules()
        tmp = Path(self.tmp.name)
        rules_dir = tmp / "rules"
        rules_dir.mkdir()
        for path in engine.RULES_DIR.glob("*.yaml"):
            shutil.copy(path, rules_dir / path.name)
        self.rule = engine.yaml.safe_load((rules_dir / f"{SCRATCH_ID}.yaml").read_text(encoding="utf-8"))
        self.drafts_dir = tmp / "drafts"
        self.request_draft = mock.Mock()
        settings = {"DRAFT_API_BASE": "https://model.invalid/v1", "DRAFT_API_KEY": "k", "DRAFT_MODEL": "m"}
        for target, value in [(server, {"RULES_DIR": rules_dir}),
                              (server, {"DRAFTS_DIR": self.drafts_dir}),
                              (server, {"load_draft_settings": mock.Mock(return_value=settings)}),
                              (server, {"request_draft": self.request_draft}),
                              (server, {"draft_from_scratch": mock.Mock(side_effect=AssertionError("scratch path"))}),
                              (server.urllib.request, {"urlopen": mock.Mock(side_effect=AssertionError("real model call"))})]:
            patcher = mock.patch.multiple(target, **value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = TestClient(server.app)

    def tearDown(self):
        self.assertEqual(self.rule_hashes, DryRunTests._hash_rules(), "a rule file was modified")

    def _post(self, reply):
        self.request_draft.return_value = reply
        resp = self.client.post(f"/api/drafts/{SCRATCH_ID}")
        self.request_draft.assert_called_once()
        self.assertEqual(resp.status_code, 200, resp.text)
        saved = engine.yaml.safe_load((self.drafts_dir / f"{SCRATCH_ID}.draft.yaml").read_text(encoding="utf-8"))
        return resp.json(), saved

    def test_extra_step_ignored_and_reported(self):
        body, saved = self._post(rule_draft_reply([full_draft_step("ec2:MonitorInstances")]))
        self.assertEqual(body["ignored_extra_steps"], ["ec2:MonitorInstances"])
        self.assertNotIn("ignored_extra_steps", saved)
        self.assertEqual(saved, body["draft"])
        self.assertEqual(saved["fix"]["steps"], self.rule["fix"]["steps"])
        self.assertEqual(saved["rollback"]["steps"], self.rule["rollback"]["steps"])
        self.assertNotIn("extra_steps", saved["fix"])
        self.assertNotIn("extra_steps", saved["rollback"])

    def test_steps_and_structure_copied_exactly_from_rule(self):
        body, saved = self._post(rule_draft_reply())
        self.assertEqual(body["ignored_extra_steps"], [])
        self.assertEqual(saved["fix"]["steps"], self.rule["fix"]["steps"])
        self.assertEqual(saved["rollback"]["steps"], self.rule["rollback"]["steps"])
        for key in ("match", "scope", "verify"):
            self.assertEqual(saved[key], self.rule[key], key)
        self.assertEqual(saved["fix"]["description"], "Enable detailed monitoring on the lab instance.")
        self.assertIs(saved["draft"], True)
        self.assertEqual(saved["drafted_by"], "ai")
        self.assertEqual(saved["approved_by"], "pending")
        self.assertEqual(saved["approved_on"], "")
        self.assertIs(saved["preview_required"], True)
        self.assertIs(body["applied"], False)

    def test_prompt_lists_rule_steps_and_limits_wording(self):
        self._post(rule_draft_reply())
        _, user = self.request_draft.call_args.args[1:]
        self.assertIn("ec2:MonitorInstances on instance vuln-lab-target", user)
        self.assertIn("ec2:UnmonitorInstances on instance vuln-lab-target", user)
        self.assertIn("You only write the description wording", user)
        self.assertIn("must not name any action, target, or IP address that is not listed above", user)
        self.assertNotIn("extra_steps: []", user)


if __name__ == "__main__":
    unittest.main()
