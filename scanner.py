import argparse
import json
import os
import re
import sys

import hcl2

SEVERITY_SCORES = {
    "critical": 9,
    "high": 7,
    "medium": 4,
    "low": 2,
}

RULES = [
    {
        "id": "s3-public-bucket",
        "name": "Public S3 bucket",
        "description": "S3 buckets should not use a public ACL or allow public access.",
        "severity": "high",
        "remediation": "Set bucket ACL to private and enable block public access.",
    },
    {
        "id": "security-group-open",
        "name": "Open security group",
        "description": "Security groups should not allow unrestricted inbound access from 0.0.0.0/0 or ::/0.",
        "severity": "high",
        "remediation": "Restrict ingress rules to known IP ranges or private subnets.",
    },
    {
        "id": "iam-wildcard-policy",
        "name": "Wildcard IAM permissions",
        "description": "IAM policies should use least privilege instead of wildcard actions or resources.",
        "severity": "critical",
        "remediation": "Replace '*' actions and resources with scoped permissions.",
    },
]


def parse_hcl_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return hcl2.load(f)


def unquote_value(value):
    if not isinstance(value, str):
        return value
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def normalize_value(value):
    if isinstance(value, str):
        return unquote_value(value)
    if isinstance(value, list):
        return [normalize_value(item) for item in value]
    if isinstance(value, dict):
        normalized = {}
        for key, item in value.items():
            if key == "__is_block__":
                continue
            normalized_key = unquote_value(key)
            normalized[normalized_key] = normalize_value(item)
        return normalized
    return value


def contains_wildcard(value):
    if isinstance(value, str):
        return value.strip() == "*"
    if isinstance(value, list):
        return any(contains_wildcard(item) for item in value)
    if isinstance(value, dict):
        return any(contains_wildcard(v) for v in value.values())
    return False


def analyze_s3_bucket(name, attrs):
    findings = []
    attrs = normalize_value(attrs)
    acl = attrs.get("acl")
    if acl and isinstance(acl, str) and acl in {"public-read", "public-read-write", "website"}:
        findings.append("S3 bucket uses public ACL: %s" % acl)

    public_access_block = attrs.get("public_access_block")
    if isinstance(public_access_block, dict):
        if public_access_block.get("ignore_public_acls") is False:
            findings.append("S3 bucket ignores public ACL restrictions.")
        if public_access_block.get("block_public_policy") is False:
            findings.append("S3 bucket does not block public policies.")

    return findings


def analyze_security_group(name, attrs):
    findings = []
    attrs = normalize_value(attrs)
    ingress = attrs.get("ingress")
    if isinstance(ingress, list):
        for rule in ingress:
            if not isinstance(rule, dict):
                continue
            cidr_blocks = rule.get("cidr_blocks") or []
            ipv6_cidr_blocks = rule.get("ipv6_cidr_blocks") or []
            if any(block == "0.0.0.0/0" for block in cidr_blocks):
                findings.append("Security group allows 0.0.0.0/0 inbound.")
            if any(block == "::/0" for block in ipv6_cidr_blocks):
                findings.append("Security group allows ::/0 inbound.")
    return findings


def analyze_iam_policy(name, attrs):
    findings = []
    attrs = normalize_value(attrs)
    policy = attrs.get("policy")
    if isinstance(policy, str):
        if re.search(r'"Action"\s*:\s*"\*"', policy) and re.search(r'"Resource"\s*:\s*"\*"', policy):
            findings.append("IAM policy document grants wildcard action and resource.")
        if "Action = \"*\"" in policy and "Resource = \"*\"" in policy:
            findings.append("IAM policy document grants wildcard action and resource.")
    if isinstance(policy, dict):
        statements = policy.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]
        if isinstance(statements, list):
            for statement in statements:
                action = statement.get("Action")
                resource = statement.get("Resource")
                effect = statement.get("Effect")
                if effect == "Allow" and contains_wildcard(action) and contains_wildcard(resource):
                    findings.append("IAM policy statement allows '*' for action and resource.")
    return findings


def evaluate_findings(findings):
    score = 0
    details = []
    for finding in findings:
        if finding["rule_id"] == "iam-wildcard-policy":
            score += SEVERITY_SCORES["critical"]
        elif finding["rule_id"] == "security-group-open":
            score += SEVERITY_SCORES["high"]
        elif finding["rule_id"] == "s3-public-bucket":
            score += SEVERITY_SCORES["high"]
        else:
            score += SEVERITY_SCORES["medium"]
        details.append(finding)
    return score, details


def analyze_terraform(path):
    config = parse_hcl_file(path)
    findings = []
    for block_type, blocks in config.items():
        if block_type != "resource":
            continue
        resource_block_maps = []
        if isinstance(blocks, list):
            for item in blocks:
                if isinstance(item, dict):
                    resource_block_maps.append(item)
        elif isinstance(blocks, dict):
            resource_block_maps.append(blocks)
        for resource_map in resource_block_maps:
            for resource_type, resources in resource_map.items():
                if not isinstance(resources, dict):
                    continue
                resource_type = unquote_value(resource_type)
                for name, attrs in resources.items():
                    name = unquote_value(name)
                    if resource_type == "aws_s3_bucket":
                        issues = analyze_s3_bucket(name, attrs)
                        for issue in issues:
                            findings.append({
                                "rule_id": "s3-public-bucket",
                                "resource": "%s.%s" % (resource_type, name),
                                "issue": issue,
                                "severity": "high",
                                "remediation": RULES[0]["remediation"],
                            })
                    elif resource_type == "aws_security_group":
                        issues = analyze_security_group(name, attrs)
                        for issue in issues:
                            findings.append({
                                "rule_id": "security-group-open",
                                "resource": "%s.%s" % (resource_type, name),
                                "issue": issue,
                                "severity": "high",
                                "remediation": RULES[1]["remediation"],
                            })
                    elif resource_type == "aws_iam_policy":
                        issues = analyze_iam_policy(name, attrs)
                        for issue in issues:
                            findings.append({
                                "rule_id": "iam-wildcard-policy",
                                "resource": "%s.%s" % (resource_type, name),
                                "issue": issue,
                                "severity": "critical",
                                "remediation": RULES[2]["remediation"],
                            })
    return findings


def compare_deployed_state(scan_findings, state_path):
    if not os.path.exists(state_path):
        return [
            {
                "resource": state_path,
                "issue": "Deployed state file does not exist.",
                "severity": "medium",
                "remediation": "Create or provide a valid deployed state JSON file.",
            }
        ]

    with open(state_path, "r", encoding="utf-8") as f:
        state = json.load(f)

    drift_finding = []
    deployed_buckets = {item["name"]: item for item in state.get("aws_s3_bucket", [])}
    for item in deployed_buckets.values():
        if item.get("acl") == "public-read":
            drift_finding.append({
                "resource": "deployed.aws_s3_bucket.%s" % item["name"],
                "issue": "Deployed bucket is public in live state.",
                "severity": "high",
                "remediation": "Ensure the deployed bucket is made private or removed from public access.",
            })
    return drift_finding


def print_report(findings, drift_findings=None):
    score, details = evaluate_findings(findings)
    print("\nCloud Security Scan Report")
    print("--------------------------")
    if not details:
        print("No insecure Terraform findings detected.")
    else:
        for item in details:
            print(f"- [{item['severity'].upper()}] {item['resource']}: {item['issue']}")
            print(f"  Remediation: {item['remediation']}")
    print(f"\nTotal risk score: {score}")
    if score >= 15:
        print("Risk level: HIGH")
    elif score >= 8:
        print("Risk level: MEDIUM")
    else:
        print("Risk level: LOW")

    if drift_findings:
        print("\nDrift Detection Findings")
        print("------------------------")
        for item in drift_findings:
            print(f"- [{item['severity'].upper()}] {item['resource']}: {item['issue']}")
            print(f"  Remediation: {item['remediation']}")


def parse_args():
    parser = argparse.ArgumentParser(description="Terraform IaC security scanner")
    parser.add_argument("--scan", required=True, help="Path to a Terraform .tf file")
    parser.add_argument("--deployed-state", help="Optional JSON file with simulated deployed state")
    return parser.parse_args()


def main():
    args = parse_args()
    if not os.path.exists(args.scan):
        print("Error: terraform file not found:", args.scan)
        sys.exit(1)

    findings = analyze_terraform(args.scan)
    drift_findings = None
    if args.deployed_state:
        drift_findings = compare_deployed_state(findings, args.deployed_state)

    print_report(findings, drift_findings)


if __name__ == "__main__":
    main()
