from src.cloudguard.cli import check_iam_wildcards

def test_iam_wildcard_detected():
    inv = {
        "iam_policies": [
            {"name": "AllowAll", "statements": [{"Action": "*", "Resource": "*"}]},
            {"name": "ReadOnly", "statements": [{"Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::bucket/*"}]}
        ]
    }
    findings = check_iam_wildcards(inv)
    assert any(f["rule_id"] == "IAM-WILDCARD-001" for f in findings)
