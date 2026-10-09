"""Offline, deliberately narrow security review of Terraform plan JSON."""
from __future__ import annotations

import argparse
from collections import Counter
import html
import json
from pathlib import Path
import sys

AWS = "registry.terraform.io/hashicorp/aws"
PAB_FIELDS = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
RULES = {
    "aws_security_group": ("NET001", "Internet-wide SSH/RDP ingress", ("ingress",)),
    "aws_security_group_rule": ("NET001", "Internet-wide SSH/RDP ingress", ("type", "protocol", "from_port", "to_port", "cidr_blocks", "ipv6_cidr_blocks")),
    "aws_vpc_security_group_ingress_rule": ("NET001", "Internet-wide SSH/RDP ingress", ("ip_protocol", "from_port", "to_port", "cidr_ipv4", "cidr_ipv6")),
    "aws_s3_bucket_public_access_block": ("S3001", "Bucket public-access safeguard disabled", PAB_FIELDS),
    "aws_cloudtrail": ("LOG001", "CloudTrail logging disabled", ("enable_logging",)),
    "aws_iam_policy": ("IAM001", "Allow statement with Action=* and Resource=*", ("policy",)),
    "aws_iam_role_policy": ("IAM001", "Allow statement with Action=* and Resource=*", ("policy",)),
}


def flagged(mask):
    if mask is True:
        return True
    if isinstance(mask, dict):
        return any(flagged(v) for v in mask.values())
    if isinstance(mask, list):
        return any(flagged(v) for v in mask)
    return False


def relevant_mask(mask, fields):
    if mask is True:
        return True
    return isinstance(mask, dict) and any(flagged(mask.get(f)) for f in fields)


def ingress_risk(rule, modern=False):
    if not isinstance(rule, dict):
        return None
    if modern:
        public = rule.get("cidr_ipv4") == "0.0.0.0/0" or rule.get("cidr_ipv6") == "::/0"
        protocol = rule.get("ip_protocol")
    else:
        v4, v6 = rule.get("cidr_blocks"), rule.get("ipv6_cidr_blocks")
        if v4 is not None and not isinstance(v4, list) or v6 is not None and not isinstance(v6, list):
            return None
        public = "0.0.0.0/0" in (v4 or []) or "::/0" in (v6 or [])
        protocol = rule.get("protocol")
    if not public:
        return False
    if protocol in (-1, "-1"):
        return True
    if protocol not in ("tcp", "6", 6):
        return None if protocol is None else False
    low, high = rule.get("from_port"), rule.get("to_port")
    if type(low) is not int or type(high) is not int or not 0 <= low <= high <= 65535:
        return None
    return any(low <= port <= high for port in (22, 3389))


def evaluate(resource_type, value):
    if value is None:
        return False
    if not isinstance(value, dict):
        return None
    if resource_type == "aws_security_group":
        ingress = value.get("ingress")
        if not isinstance(ingress, list):
            return None
        states = [ingress_risk(rule) for rule in ingress]
        return True if True in states else None if None in states else False
    if resource_type == "aws_security_group_rule":
        if value.get("type") == "egress":
            return False
        if value.get("type") != "ingress":
            return None
        return ingress_risk(value)
    if resource_type == "aws_vpc_security_group_ingress_rule":
        return ingress_risk(value, modern=True)
    if resource_type == "aws_s3_bucket_public_access_block":
        if any(value.get(k) is False for k in PAB_FIELDS):
            return True
        return False if all(value.get(k) is True for k in PAB_FIELDS) else None
    if resource_type == "aws_cloudtrail":
        state = value.get("enable_logging")
        return not state if type(state) is bool else None
    try:
        policy = value.get("policy")
        if isinstance(policy, str):
            policy = json.loads(policy)
        if not isinstance(policy, dict) or "Statement" not in policy:
            return None
        statements = policy["Statement"]
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            return None
        malformed = False
        for statement in statements:
            if not isinstance(statement, dict):
                malformed = True
                continue
            if statement.get("Effect") not in {"Allow", "Deny"}:
                malformed = True
                continue
            actions, resources = statement.get("Action"), statement.get("Resource")
            actions = [actions] if isinstance(actions, str) else actions
            resources = [resources] if isinstance(resources, str) else resources
            if not isinstance(actions, list) or not isinstance(resources, list):
                malformed = True
                continue
            if statement["Effect"] == "Allow" and "*" in actions and "*" in resources:
                return True
        return None if malformed else False
    except (ValueError, TypeError):
        return None


def analyze(plan):
    if not isinstance(plan, dict) or not isinstance(plan.get("format_version"), str) or plan["format_version"].split(".")[0] != "1":
        raise ValueError("expected supported Terraform JSON format major version 1")
    changes = plan.get("resource_changes", [])
    if not isinstance(changes, list) or "planned_values" not in plan:
        raise ValueError("expected a plan with planned_values and optional resource_changes list")
    results, skipped = [], []
    supported = 0
    for index, resource in enumerate(changes):
        if not isinstance(resource, dict) or not isinstance(resource.get("address"), str):
            raise ValueError(f"resource_changes[{index}] lacks an address")
        address, resource_type = resource["address"], resource.get("type")
        if resource.get("mode") != "managed" or resource.get("provider_name") != AWS or resource_type not in RULES:
            skipped.append({"address": address, "reason": "resource/provider outside this tool's rule coverage"})
            continue
        supported += 1
        change = resource.get("change")
        if not isinstance(change, dict):
            raise ValueError(f"resource_changes[{index}] lacks a change object")
        actions = change.get("actions")
        if actions not in [["no-op"], ["create"], ["update"], ["delete"], ["read"], ["delete", "create"], ["create", "delete"]]:
            raise ValueError(f"resource_changes[{index}] has unsupported actions")
        rule_id, message, fields = RULES[resource_type]
        before = None if relevant_mask(change.get("before_sensitive", {}), fields) else (
            False if actions == ["create"] and change.get("before") is None
            else None if change.get("before") is None else evaluate(resource_type, change["before"])
        )
        unknown = relevant_mask(change.get("after_unknown", {}), fields)
        sensitive = relevant_mask(change.get("after_sensitive", {}), fields)
        deletion = actions == ["delete"]
        after = False if deletion else None if unknown or sensitive or change.get("after") is None else evaluate(resource_type, change["after"])
        if deletion:
            status = "control_removal_review" if resource_type in {"aws_s3_bucket_public_access_block", "aws_cloudtrail"} else "resource_removal_review"
        elif after is None:
            status = "manual_review"
        elif after:
            status = "existing" if before is True else "introduced" if before is False else "present_prior_unknown"
        elif before is True:
            status = "resolved_by_plan"
        elif before is None:
            status = "prior_state_unknown"
        else:
            continue
        results.append({"address": address, "rule": rule_id, "message": message, "status": status,
                        "actions": actions, "after_unknown": unknown, "sensitive_input_withheld": sensitive,
                        "before_matches_rule": before, "after_matches_rule": after})
    results.sort(key=lambda r: (r["address"], r["rule"]))
    return {"scope": "Plan evidence only; no deployment, reachability or effective-permission verification.",
            "coverage": {"resources_in_plan": len(changes), "supported_resources": supported, "skipped_resources": len(skipped)},
            "plan_complete": plan.get("complete"), "summary": dict(Counter(r["status"] for r in results)),
            "results": results, "skipped": sorted(skipped, key=lambda r: r["address"])}


def exit_code(report):
    if report["plan_complete"] is False or report["coverage"]["skipped_resources"] or any(
        r["status"] in {"manual_review", "prior_state_unknown", "control_removal_review", "resource_removal_review", "present_prior_unknown"}
        for r in report["results"]
    ):
        return 2
    return 1 if any(r["status"] in {"introduced", "existing"} for r in report["results"]) else 0


def markdown(report):
    def safe(value):
        text = html.escape(str(value)).replace("\n", " ").replace("\r", " ")
        for char in "|[]()`":
            text = text.replace(char, f"&#{ord(char)};")
        return text
    lines = ["# Terraform change review", "", report["scope"], "",
             "| Resource | Rule | Result | Review focus |", "|---|---|---|---|"]
    for row in report["results"]:
        lines.append("| " + " | ".join(safe(row[k]) for k in ("address", "rule", "status", "message")) + " |")
    lines += ["", "Coverage: " + json.dumps(report["coverage"], sort_keys=True),
              "", "Exit status: " + str(exit_code(report)), "", "A plan is proposed state; resolved_by_plan does not mean deployed or verified.", ""]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    args = parser.parse_args(argv)
    try:
        report = analyze(json.loads(args.plan.read_text()))
    except (OSError, ValueError, TypeError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    print(markdown(report) if args.format == "markdown" else json.dumps(report, indent=2, sort_keys=True))
    return exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
