from pathlib import Path
from src.cloudguard.cli import render_html

def test_render_html_creates_file(tmp_path):
    findings = [{
        "rule_id": "S3-PUBLIC-001",
        "severity": "HIGH",
        "message": "Public bucket detected: demo",
        "resource": "demo"
    }]
    out = tmp_path / "report.html"
    render_html(findings, out)
    assert out.exists()
    assert "S3-PUBLIC-001" in out.read_text()
