from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingOrigin(str, Enum):
    unknown = "unknown"
    scanner = "scanner"
    ai = "ai"


class ReviewMode(str, Enum):
    unknown = "unknown"
    scanner_only = "scanner_only"
    manual = "manual"
    automated = "automated"
    legacy_ai = "legacy_ai"


class EvidenceStatus(str, Enum):
    scanner_reported = "scanner_reported"
    unverified = "unverified"
    location_checked = "location_checked"


class CoverageStatus(str, Enum):
    pending = "pending"
    complete = "complete"
    partial = "partial"
    failed = "failed"


class CoverageFileOutcome(str, Enum):
    snapshot_acquired = "snapshot_acquired"
    diff_only = "diff_only"
    supplied_context = "supplied_context"
    read_file = "read_file"
    omitted = "omitted"


class CoverageFile(StrictModel):
    path: str = Field(min_length=1, max_length=1024)
    outcome: CoverageFileOutcome
    reason: str | None = Field(default=None, max_length=100)


class EvidenceReference(StrictModel):
    """A location reference; existence does not prove the security claim."""

    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    file_path: str = Field(min_length=1, max_length=1024)
    line: int = Field(ge=1)
    role: str = Field(min_length=1, max_length=40)
    source: str = Field(min_length=1, max_length=40)


class ReviewCoverage(StrictModel):
    """Bounded accounting for a defined review scope, not whole-repo safety."""

    mode: ReviewMode
    status: CoverageStatus
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    selected_files: list[str] = Field(default_factory=list, max_length=2000)
    supplied_files: list[str] = Field(default_factory=list, max_length=2000)
    read_files: list[str] = Field(default_factory=list, max_length=2000)
    skipped: list[dict[str, str]] = Field(default_factory=list, max_length=2000)
    scanner_stages: dict[str, str] = Field(default_factory=dict)
    files: list[CoverageFile] = Field(default_factory=list, max_length=2000)
    reason: str | None = Field(default=None, max_length=100)
    selection: str | None = Field(default=None, max_length=200)
    graph_status: str | None = Field(default=None, max_length=40)


class ScanRequest(StrictModel):
    repository_id: UUID
    pull_request_number: int = Field(gt=0)
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")


class Finding(StrictModel):
    rule_id: str = Field(min_length=1, max_length=255)
    file_path: str = Field(min_length=1, max_length=1024)
    line: int = Field(ge=1)
    severity: Severity
    message: str = Field(min_length=1, max_length=8000)
    origin: FindingOrigin = FindingOrigin.scanner
    review_mode: ReviewMode = ReviewMode.scanner_only
    evidence_status: EvidenceStatus = EvidenceStatus.scanner_reported
    evidence: list[EvidenceReference] = Field(default_factory=list, max_length=8)
    cross_file_required: bool = False


class AIReviewRequest(StrictModel):
    finding: Finding
    # Must be redacted and tenant-approved before calling a provider.
    code_context: str = Field(min_length=1, max_length=16000)


class AIReview(StrictModel):
    explanation: str = Field(min_length=1, max_length=8000)
    suggested_patch: str | None = Field(default=None, max_length=16000)
    requires_human_review: bool = True


# GitHub adds fields over time; validate the consumed subset, ignore extras.
class GitHubRepository(BaseModel):
    id: int = Field(gt=0)
    full_name: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class GitHubHead(BaseModel):
    sha: str = Field(pattern=r"^[0-9a-f]{40}$")


class GitHubPullRequest(BaseModel):
    number: int = Field(gt=0)
    head: GitHubHead
    merged: bool = False


class PullRequestWebhook(BaseModel):
    action: str = Field(min_length=1, max_length=64)
    repository: GitHubRepository
    pull_request: GitHubPullRequest
