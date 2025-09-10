from src.cloudguard.cli import check_s3_public_buckets


def test_public_bucket_finding():
    inv = {"buckets": [
        {"name": "private-data", "public": False},
        {"name": "public-assets", "public": True}
    ]}
    findings = check_s3_public_buckets(inv)
    assert any(f["rule_id"] == "S3-PUBLIC-001" for f in findings)
    assert any("public-assets" in f["message"] for f in findings)
