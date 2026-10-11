"""Tests for remediations/engine.py --dry-run. Uses fake AWS clients; makes no AWS calls.

Run: py -3.13 -m unittest discover -s tests
"""

import contextlib
import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "remediations"))

import engine  # noqa: E402

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
        rule = self.rules["CLD-01"]
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
        rule["fix"]["steps"][0]["action"] = "ec2:TerminateInstances"
        rule["scope"]["allowed_actions"] = ["ec2:TerminateInstances"]
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
                                ("ec2", "create_tags")]:
            with self.assertRaises(engine.Refused):
                getattr(aws.client(service), method)
        self.assertEqual(self.calls, [])

    def test_every_handler_has_desired_state(self):
        self.assertEqual(set(engine.HANDLERS), set(engine.DESIRED_STATE))


if __name__ == "__main__":
    unittest.main()
