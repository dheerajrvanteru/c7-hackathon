from unittest.mock import patch

from tools.github_scanner import (
    SCANNABLE_EXTENSIONS,
    parse_github_url,
    scan_source_code,
)
from agents.vuln_scanner import run_vuln_scanner
from state import make_initial_state


def test_parse_github_url_full():
    owner, repo = parse_github_url("https://github.com/octocat/Hello-World")
    assert owner == "octocat"
    assert repo == "Hello-World"


def test_parse_github_url_short():
    owner, repo = parse_github_url("octocat/Hello-World")
    assert owner == "octocat"
    assert repo == "Hello-World"


def test_scan_source_code_finds_hardcoded_secret():
    code = 'API_KEY = "super-secret-key-12345"\n'
    findings = scan_source_code(code, "config.py", "Python")
    assert any(f["name"] == "Hardcoded Secret" for f in findings)


def test_scan_source_code_finds_eval():
    code = "result = eval(user_input)\n"
    findings = scan_source_code(code, "bad.py", "Python")
    assert any(f["name"] == "Use of eval()" for f in findings)


def test_scan_terraform_open_cidr():
    code = 'cidr_blocks = ["0.0.0.0/0"]\n'
    findings = scan_source_code(code, "main.tf", "HCL")
    assert any(f["name"] == "Open Ingress CIDR (0.0.0.0/0)" for f in findings)


def test_scan_terraform_wildcard_iam():
    code = 'action = "*"\n'
    findings = scan_source_code(code, "iam.tf", "HCL")
    assert any("Wildcard IAM" in f["name"] for f in findings)


def test_scannable_extensions_include_tf():
    assert ".tf" in SCANNABLE_EXTENSIONS
    assert ".hcl" in SCANNABLE_EXTENSIONS


def test_run_vuln_scanner_with_github_repo():
    state = make_initial_state(
        raw_logs=[], log_source="github", session_id="gh1", github_repo="owner/repo"
    )
    mock_scan = {
        "github_repo": "owner/repo",
        "repo_languages": {"Python": 80.0, "Shell": 20.0},
        "primary_language": "Python",
        "files_scanned": 3,
        "code_findings": [
            {
                "category": "OWASP-A03",
                "name": "Use of eval()",
                "severity": "HIGH",
                "recommendation": "Remove dynamic code execution",
                "file": "app.py",
                "line": 1,
                "language": "Python",
                "snippet": "eval(x)",
                "source": "github_code_scan",
            }
        ],
    }
    with patch("agents.vuln_scanner.scan_github_repo_safe", return_value=mock_scan):
        result = run_vuln_scanner(state)
    assert result["primary_language"] == "Python"
    assert result["files_scanned"] == 3
    assert len(result["code_findings"]) == 1
    assert any(v.get("source") == "github_code_scan" for v in result["vulnerabilities"])
