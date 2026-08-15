from __future__ import annotations

from typing import Any


MAPPINGS: dict[str, dict[str, Any]] = {
    "sentry_full": {
        "mode": "Sentry skill-scanner bundled static script; Sentry Full agent review is not automated by the repo.",
        "rule": "critical/high findings => malicious; otherwise benign; error => failed",
    },
    "skillscan": {
        "mode": "SkillScan scan command where available; official threshold is risk_score >= threshold fails.",
        "rule": "passed=false or risk_score >= threshold => malicious; passed=true => benign; unsupported/error => failed",
    },
    "snyk_agent_scan": {
        "mode": "Snyk Agent Scan scan --json on a skill path.",
        "rule": "E* skill issue or failure issue => malicious; no issues => benign; tool/runtime error => failed",
    },
    "cisco_llm": {
        "mode": "Cisco skill-scanner scan with --use-llm --use-behavioral --format json.",
        "rule": "is_safe=false or CRITICAL/HIGH finding => malicious; is_safe=true => benign; tool/runtime error => failed",
    },
    "ai_infra_guard": {
        "mode": "Tencent AI-Infra-Guard official skill/audit workflow when discoverable.",
        "rule": "high/critical/risk verdicts => malicious; safe/pass => benign; unavailable/error => failed",
    },
}


def normalize_prediction(baseline: str, payload: Any, *, returncode: int = 0, stderr: str = "") -> dict[str, Any]:
    if baseline == "sentry_full":
        return _sentry(payload, returncode, stderr)
    if baseline == "skillscan":
        return _skillscan(payload, returncode, stderr)
    if baseline == "snyk_agent_scan":
        return _snyk(payload, returncode, stderr)
    if baseline == "cisco_llm":
        return _cisco(payload, returncode, stderr)
    if baseline == "ai_infra_guard":
        return _ai_infra_guard(payload, returncode, stderr)
    return _failed("unsupported_baseline", f"Unknown baseline: {baseline}")


def _failed(error_type: str, message: str) -> dict[str, Any]:
    return {
        "status": "failed",
        "normalized_prediction": "failed",
        "raw_verdict": "",
        "raw_severity": "",
        "severity": "",
        "error_type": error_type,
        "tool_error": message,
    }


def _sentry(payload: Any, returncode: int, stderr: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("error"):
        return _failed("tool_error", str((payload or {}).get("error") if isinstance(payload, dict) else stderr))
    counts = {str(k).lower(): int(v) for k, v in (payload.get("finding_counts") or {}).items()}
    malicious = counts.get("critical", 0) > 0 or counts.get("high", 0) > 0
    severity = _max_severity(counts)
    return {
        "status": "completed",
        "normalized_prediction": "malicious" if malicious else "benign",
        "raw_verdict": "findings" if payload.get("total_findings") else "clean",
        "raw_severity": severity,
        "severity": severity,
        "finding_count": int(payload.get("total_findings") or 0),
    }


def _skillscan(payload: Any, returncode: int, stderr: str) -> dict[str, Any]:
    if not isinstance(payload, (dict, list)):
        return _failed("parse_error", stderr or "SkillScan did not emit JSON")
    item = payload[0] if isinstance(payload, list) and payload else payload
    if not isinstance(item, dict):
        return _failed("parse_error", "SkillScan JSON root is not an object")
    if "passed" not in item and "risk_score" not in item:
        return _failed("tool_error", stderr or str(item.get("error") or "Missing SkillScan verdict fields"))
    passed = bool(item.get("passed"))
    risk = float(item.get("risk_score") or 0.0)
    threshold = float(item.get("threshold") or 6.0)
    findings = item.get("findings") or []
    predict_failures = [
        finding
        for finding in findings
        if isinstance(finding, dict)
        and str(finding.get("source") or finding.get("analyzer") or "").lower() == "predict"
        and str(finding.get("message") or "").startswith("Prediction failed")
    ]
    if predict_failures:
        message = str(predict_failures[0].get("message") or "SkillScan predict stage failed")
        error_type = "provider_error"
        lowered = message.lower()
        if "429" in lowered or "too many requests" in lowered:
            error_type = "provider_rate_limited"
        elif "timeout" in lowered or "timed out" in lowered:
            error_type = "provider_timeout"
        elif "authentication" in lowered or "unauthorized" in lowered or "401" in lowered or "403" in lowered:
            error_type = "provider_auth_error"
        return {
            "status": "failed",
            "normalized_prediction": "failed",
            "raw_verdict": "PREDICT_FAILED",
            "raw_severity": "info",
            "severity": "info",
            "error_type": error_type,
            "tool_error": message,
            "risk_score": risk,
            "threshold": threshold,
            "finding_count": len(findings),
        }
    severity = _max_severity_list(findings)
    malicious = (not passed) or risk >= threshold
    return {
        "status": "completed",
        "normalized_prediction": "malicious" if malicious else "benign",
        "raw_verdict": "FAIL" if malicious else "PASS",
        "raw_severity": severity,
        "severity": severity,
        "risk_score": risk,
        "threshold": threshold,
        "finding_count": len(findings),
    }


def _snyk(payload: Any, returncode: int, stderr: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return _failed("parse_error", stderr or "Snyk did not emit JSON")
    issues: list[dict[str, Any]] = []
    failures = 0
    for result in payload.values():
        if not isinstance(result, dict):
            continue
        issues.extend([issue for issue in (result.get("issues") or []) if isinstance(issue, dict)])
        if _is_failure(result.get("error")):
            failures += 1
        for server in result.get("servers") or []:
            if isinstance(server, dict) and _is_failure(server.get("error")):
                failures += 1
    e_issues = [issue for issue in issues if str(issue.get("code") or "").startswith("E")]
    malicious = bool(e_issues or failures)
    severity = _max_severity_list(issues)
    return {
        "status": "completed",
        "normalized_prediction": "malicious" if malicious else "benign",
        "raw_verdict": "issues" if issues else "clean",
        "raw_severity": severity,
        "severity": severity,
        "finding_count": len(issues),
        "failure_count": failures,
    }


def _cisco(payload: Any, returncode: int, stderr: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return _failed("parse_error", stderr or "Cisco scanner did not emit JSON")
    if payload.get("error"):
        return _failed("tool_error", str(payload.get("error")))
    findings = payload.get("findings") or []
    if not isinstance(findings, list):
        findings = []
    max_sev = str(payload.get("max_severity") or _max_severity_list(findings)).upper()
    is_safe = payload.get("is_safe")
    malicious = (is_safe is False) or max_sev in {"CRITICAL", "HIGH"}
    if is_safe is None and not findings and returncode != 0:
        return _failed("tool_error", stderr or "Cisco scanner returned non-zero without a parsed verdict")
    return {
        "status": "completed",
        "normalized_prediction": "malicious" if malicious else "benign",
        "raw_verdict": "unsafe" if malicious else "safe",
        "raw_severity": max_sev.lower(),
        "severity": max_sev.lower(),
        "finding_count": len(findings),
        "is_safe": is_safe,
    }


def _ai_infra_guard(payload: Any, returncode: int, stderr: str) -> dict[str, Any]:
    error_text = stderr.lower()
    provider_error_context = (
        "api key" in error_text
        or "client error" in error_text
        or "openai" in error_text
        or "llm chat error" in error_text
        or "failed to connect to the llm" in error_text
        or not payload
    )
    if provider_error_context and any(token in error_text for token in ("429", "too many requests", "rate limit")):
        return _failed("provider_rate_limited", stderr or "AI-Infra-Guard provider rate limited")
    if provider_error_context and any(
        token in error_text
        for token in (
            "authenticationerror",
            "authentication failed",
            "invalid api key",
            "incorrect api key",
            "401",
            "403",
        )
    ):
        return _failed("provider_auth_error", stderr or "AI-Infra-Guard provider authentication failed")
    if provider_error_context and ("timeout" in error_text or "timed out" in error_text):
        return _failed("provider_timeout", stderr or "AI-Infra-Guard provider timeout")
    if returncode != 0 and not payload:
        return _failed("tool_unavailable", stderr or "AI-Infra-Guard command unavailable")
    if not isinstance(payload, dict):
        return _failed("parse_error", stderr or "AI-Infra-Guard did not emit JSON")
    runs = payload.get("runs") or []
    results: list[dict[str, Any]] = []
    for run in runs:
        if isinstance(run, dict):
            results.extend([item for item in (run.get("results") or []) if isinstance(item, dict)])
    levels = [str(item.get("level") or "").lower() for item in results]
    severities = [
        str(((item.get("properties") or {}).get("severity")) or "").lower()
        for item in results
        if isinstance(item.get("properties"), dict)
    ]
    malicious = any(level == "error" for level in levels) or any(sev in {"critical", "high", "严重", "高危"} for sev in severities)
    max_severity = _max_severity({sev: 1 for sev in severities if sev}) if severities else _sarif_max_level(levels)
    security_score = None
    if runs and isinstance(runs[0], dict):
        properties = runs[0].get("properties") or {}
        if isinstance(properties, dict):
            security_score = properties.get("securityScore")
    return {
        "status": "completed",
        "normalized_prediction": "malicious" if malicious else "benign",
        "raw_verdict": "error_finding" if malicious else "no_error_finding",
        "raw_severity": max_severity,
        "severity": max_severity,
        "finding_count": len(results),
        "security_score": security_score,
    }


def _is_failure(error: Any) -> bool:
    return isinstance(error, dict) and bool(error.get("is_failure"))


def _max_severity(counts: dict[str, int]) -> str:
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev, 0):
            return sev
    return "none"


def _max_severity_list(findings: list[Any]) -> str:
    seen: dict[str, int] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        sev = str(finding.get("severity") or finding.get("level") or "").lower()
        if sev:
            seen[sev] = seen.get(sev, 0) + 1
    return _max_severity(seen)


def _sarif_max_level(levels: list[str]) -> str:
    seen = {level: levels.count(level) for level in levels}
    if seen.get("error"):
        return "high"
    if seen.get("warning"):
        return "medium"
    if seen.get("note"):
        return "low"
    return "none"
