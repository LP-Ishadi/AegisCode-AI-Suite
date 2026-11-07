"""Bounded scanner evidence shared by manual and automated AI reviews."""

from collections import Counter

from app.models.schemas import Finding
from app.services.redaction import redact

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SAMPLE_LIMITS = {"code": 12, "dependency": 8, "secret": 8, "image": 8, "other": 4}


def finding_source(rule_id: str) -> str:
    if rule_id.startswith("trivy.image."):
        return "image"
    if rule_id.startswith("trivy."):
        return "dependency"
    if rule_id.startswith("semgrep."):
        return "code"
    if rule_id.startswith("trufflehog."):
        return "secret"
    return "other"


def scanner_evidence(findings: list[Finding], *, status: str = "completed") -> dict:
    """Show counts for every finding, but cap the text sent to a model."""
    counts = Counter(finding_source(item.rule_id) for item in findings)
    samples = []
    for source, limit in SAMPLE_LIMITS.items():
        group = sorted(
            (item for item in findings if finding_source(item.rule_id) == source),
            key=lambda item: (
                SEVERITY_ORDER[item.severity.value],
                item.file_path,
                item.line,
                item.rule_id,
            ),
        )
        for item in group[:limit]:
            samples.append(
                {
                    "source": source,
                    "rule_id": redact(item.rule_id),
                    "file_path": item.file_path,
                    "line": item.line,
                    "severity": item.severity.value,
                    "message": redact(item.message)[:500],
                }
            )
    return {
        "status": status,
        "counts": {source: counts[source] for source in SAMPLE_LIMITS},
        "sampled_findings": samples,
        "omitted_findings": len(findings) - len(samples),
        "guidance": (
            "Scanner findings are leads, not verified exploits. Image findings concern "
            "referenced base images, not a built PR image. Check whether a finding is "
            "relevant to this PR before reporting a new code issue."
        ),
    }
