from typing import TypedDict


class SecurityState(TypedDict):
    raw_logs: list[str]
    log_source: str
    session_id: str
    anomalies: list[dict]
    severity_map: dict[str, str]
    cve_matches: list[dict]
    threat_score: int
    vulnerabilities: list[dict]
    risk_level: str
    action_plan: list[str]
    runbook_md: str
    compliance_gaps: list[dict]
    compliance_score: int
    github_repo: str
    repo_languages: dict[str, float]
    primary_language: str
    files_scanned: int
    code_findings: list[dict]
    scan_error: str


def make_initial_state(
    raw_logs: list[str],
    log_source: str,
    session_id: str,
    github_repo: str = "",
) -> SecurityState:
    return SecurityState(
        raw_logs=raw_logs,
        log_source=log_source,
        session_id=session_id,
        anomalies=[],
        severity_map={},
        cve_matches=[],
        threat_score=0,
        vulnerabilities=[],
        risk_level="low",
        action_plan=[],
        runbook_md="",
        compliance_gaps=[],
        compliance_score=0,
        github_repo=github_repo,
        repo_languages={},
        primary_language="",
        files_scanned=0,
        code_findings=[],
        scan_error="",
    )
