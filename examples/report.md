# Terraform change review

Plan evidence only; no deployment, reachability or effective-permission verification.

| Resource | Rule | Result | Review focus |
|---|---|---|---|
| aws_cloudtrail.synthetic | LOG001 | resolved_by_plan | CloudTrail logging disabled |
| aws_iam_policy.synthetic | IAM001 | manual_review | Allow statement with Action=* and Resource=* |
| aws_s3_bucket_public_access_block.synthetic | S3001 | control_removal_review | Bucket public-access safeguard disabled |
| aws_security_group.synthetic | NET001 | introduced | Internet-wide SSH/RDP ingress |

Coverage: {"resources_in_plan": 5, "skipped_resources": 1, "supported_resources": 4}

Exit status: 2

A plan is proposed state; resolved_by_plan does not mean deployed or verified.

