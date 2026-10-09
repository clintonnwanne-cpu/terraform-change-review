import copy
import json
import subprocess
import sys
import unittest

from review import AWS, analyze, exit_code, markdown


def change(kind="aws_security_group", before=None, after=None, actions=None, **extra):
    return {"address": kind + ".synthetic", "type": kind, "mode": "managed", "provider_name": AWS,
            "change": {"before": before, "after": after, "actions": actions or ["create"], **extra}}


def sg(cidr="0.0.0.0/0", low=22, high=22, protocol="tcp"):
    return {"ingress": [{"cidr_blocks": [cidr], "ipv6_cidr_blocks": [], "protocol": protocol, "from_port": low, "to_port": high}]}


def report(*changes, **extra):
    return analyze({"format_version": "1.2", "planned_values": {}, "resource_changes": list(changes), **extra})


class ReviewTests(unittest.TestCase):
    def test_introduced_existing_and_resolved_are_distinct(self):
        for before, after, expected in [(sg("10.0.0.0/8"), sg(), "introduced"), (sg(), sg(), "existing"), (sg(), sg("10.0.0.0/8"), "resolved_by_plan")]:
            with self.subTest(expected=expected):
                self.assertEqual(report(change(before=before, after=after, actions=["update"]))["results"][0]["status"], expected)

    def test_public_https_and_private_ssh_are_not_flagged(self):
        for value in [sg(low=443, high=443), sg("10.0.0.0/8")]:
            self.assertEqual(report(change(after=value))["results"], [])

    def test_ipv6_port_range_and_all_protocols(self):
        v6 = sg(low=3000, high=4000); v6["ingress"][0].update(cidr_blocks=[], ipv6_cidr_blocks=["::/0"])
        for value in [v6, sg(low=0, high=0, protocol="-1")]:
            self.assertEqual(report(change(after=value))["results"][0]["status"], "introduced")

    def test_udp_port_22_is_not_ssh_tcp(self):
        self.assertEqual(report(change(after=sg(protocol="udp")))["results"], [])

    def test_unknown_ingress_is_manual_review(self):
        r = report(change(after={"ingress": []}, after_unknown={"ingress": True}))
        self.assertEqual(r["results"][0]["status"], "manual_review")
        self.assertEqual(exit_code(r), 2)

    def test_unrelated_unknown_id_does_not_block_known_check(self):
        self.assertEqual(report(change(after=sg(), after_unknown={"id": True}))["results"][0]["status"], "introduced")

    def test_sensitive_policy_never_leaks(self):
        secret = "DO_NOT_PRINT_SYNTHETIC_SECRET"
        r = report(change("aws_iam_policy", after={"policy": secret}, after_sensitive={"policy": True}))
        self.assertNotIn(secret, json.dumps(r) + markdown(r))
        self.assertEqual(r["results"][0]["status"], "manual_review")

    def test_policy_allow_and_deny_are_distinct(self):
        for effect, expected in [("Allow", 1), ("Deny", 0)]:
            p = json.dumps({"Statement": {"Effect": effect, "Action": "*", "Resource": "*"}})
            self.assertEqual(len(report(change("aws_iam_policy", after={"policy": p}))["results"]), expected)

    def test_malformed_policy_is_not_a_pass(self):
        r = report(change("aws_iam_policy", after={"policy": "bad json"}))
        self.assertEqual(exit_code(r), 2)

    def test_deleting_a_safeguard_is_not_a_fix(self):
        r = report(change("aws_s3_bucket_public_access_block", before={"block_public_acls": False}, actions=["delete"]))
        self.assertEqual(r["results"][0]["status"], "control_removal_review")

    def test_replacement_still_checks_future_state(self):
        r = report(change(before=sg("10.0.0.0/8"), after=sg(), actions=["delete", "create"]))
        self.assertEqual(r["results"][0]["status"], "introduced")

    def test_modern_ingress_rule_supported(self):
        r = report(change("aws_vpc_security_group_ingress_rule", after={"cidr_ipv4": "0.0.0.0/0", "ip_protocol": "tcp", "from_port": 22, "to_port": 22}))
        self.assertEqual(exit_code(r), 1)

    def test_egress_is_not_ingress(self):
        rule = sg()["ingress"][0]; rule["type"] = "egress"
        self.assertEqual(exit_code(report(change("aws_security_group_rule", after=rule))), 0)

    def test_missing_pab_values_are_unknown(self):
        self.assertEqual(exit_code(report(change("aws_s3_bucket_public_access_block", after={}))), 2)

    def test_disabled_logging_detected(self):
        self.assertEqual(exit_code(report(change("aws_cloudtrail", after={"enable_logging": False}))), 1)

    def test_unsupported_provider_and_resource_cannot_get_clean_exit(self):
        r = change(after=sg()); r["provider_name"] = "other/aws"
        self.assertEqual(exit_code(report(r)), 2)
        self.assertEqual(exit_code(report(change("aws_lambda_function", after={}))), 2)

    def test_new_major_format_is_rejected(self):
        with self.assertRaises(ValueError): report(format_version="2.0")

    def test_incomplete_plan_requires_review(self):
        self.assertEqual(exit_code(report(complete=False)), 2)

    def test_missing_after_on_update_is_not_a_fix(self):
        r = report(change(before=sg(), after=None, actions=["update"]))
        self.assertEqual(r["results"][0]["status"], "manual_review")

    def test_missing_before_does_not_invent_new_risk(self):
        r = report(change(before=None, after=sg(), actions=["update"]))
        self.assertEqual(r["results"][0]["status"], "present_prior_unknown")

    def test_markdown_image_syntax_is_escaped(self):
        r = change(after=sg()); r["address"] = "![link](https://example.com)"
        self.assertNotIn("![", markdown(report(r)))

    def test_output_escapes_untrusted_resource_label(self):
        r = change(after=sg()); r["address"] = "<script>|synthetic"
        self.assertNotIn("<script>", markdown(report(r)))

    def test_cli_matches_saved_demo(self):
        run = subprocess.run([sys.executable, "review.py", "examples/plan.json"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        with open("examples/report.json") as f: self.assertEqual(json.loads(run.stdout), json.load(f))


if __name__ == "__main__": unittest.main()
