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


class PullRequestWebhook(BaseModel):
    action: str = Field(min_length=1, max_length=64)
    repository: GitHubRepository
    pull_request: GitHubPullRequest
