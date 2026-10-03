"""Validated GitHub metadata and worker contracts; source content is never queued."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, Field, field_validator, model_validator

from app.models.schemas import Finding, StrictModel

Sha = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
RepoName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", max_length=255)]


class RepositoryRef(BaseModel):
    id: int = Field(gt=0)
    full_name: RepoName

    @field_validator("full_name")
    @classmethod
    def safe_segments(cls, value: str) -> str:
        if any(part in {".", ".."} for part in value.split("/")):
            raise ValueError("Invalid repository name")
        return value


class Revision(BaseModel):
    sha: Sha
    ref: str = Field(min_length=1, max_length=255)
    repo: RepositoryRef | None = None


class Actor(BaseModel):
    login: str = Field(min_length=1, max_length=100)


class Installation(BaseModel):
    id: int = Field(gt=0)


class PRDetails(BaseModel):
    number: int = Field(gt=0)
    title: str = Field(min_length=1, max_length=1000)
    user: Actor
    head: Revision
    base: Revision
    merged: bool = False
    draft: bool = False
    merge_commit_sha: Sha | None = None
    updated_at: AwareDatetime


class PRDispatchEvent(BaseModel):
    action: str
    repository: RepositoryRef
    installation: Installation
    pull_request: PRDetails

    @model_validator(mode="after")
    def check_repositories(self):
        base = self.pull_request.base.repo
        if base is not None and base.id != self.repository.id:
            raise ValueError("Base repository must match webhook repository")
        if self.pull_request.merged:
            if self.pull_request.merge_commit_sha is None:
                raise ValueError("Merged PR requires merge commit SHA")
        return self


class ScanMetadata(StrictModel):
    github_repository_id: int = Field(gt=0)
    installation_id: int = Field(gt=0)
    repository_full_name: RepoName
    head_repository_id: int | None = Field(gt=0)
    head_repository_full_name: RepoName | None
    pull_request_number: int = Field(gt=0)
    title: str = Field(min_length=1, max_length=1000)
    author: str = Field(min_length=1, max_length=100)
    action: str
    merged: bool
    draft: bool
    base_sha: Sha
    head_sha: Sha
    commit_sha: Sha
    merge_commit_sha: Sha | None
    base_ref: str
    head_ref: str
    event_updated_at: datetime
    clone_url: str
    head_clone_url: str | None
    patch_url: str
    diff_url: str
    compare_url: str

    @classmethod
    def from_event(cls, event: PRDispatchEvent) -> "ScanMetadata":
        pr = event.pull_request
        name = event.repository.full_name
        head_name = pr.head.repo.full_name if pr.head.repo else None
        commit = pr.merge_commit_sha if pr.merged else pr.head.sha
        # Derive canonical GitHub URLs; never trust arbitrary webhook URL fields.
        return cls(
            github_repository_id=event.repository.id,
            installation_id=event.installation.id,
            head_repository_id=pr.head.repo.id if pr.head.repo else None,
            repository_full_name=name,
            head_repository_full_name=head_name,
            pull_request_number=pr.number,
            title=pr.title,
            author=pr.user.login,
            action=event.action,
            merged=pr.merged,
            draft=pr.draft,
            base_sha=pr.base.sha,
            head_sha=pr.head.sha,
            commit_sha=commit,
            merge_commit_sha=pr.merge_commit_sha,
            base_ref=pr.base.ref,
            head_ref=pr.head.ref,
            event_updated_at=pr.updated_at,
            clone_url=f"https://github.com/{name}.git",
            head_clone_url=f"https://github.com/{head_name}.git" if head_name else None,
            patch_url=f"https://github.com/{name}/pull/{pr.number}.patch",
            diff_url=f"https://github.com/{name}/pull/{pr.number}.diff",
            compare_url=f"https://api.github.com/repos/{name}/compare/{pr.base.sha}...{commit}",
        )


class ScanJob(StrictModel):
    id: UUID
    scan_id: UUID
    lease_token: UUID
    payload: ScanMetadata


class SourceBundle(StrictModel):
    """Bounded, in-memory source prepared/redacted by a trusted acquisition adapter."""

    commit_sha: Sha
    diff: str = Field(min_length=1, max_length=200_000)
    files: list[str] = Field(default_factory=list, max_length=1000)


class ScanResult(StrictModel):
    findings: list[Finding] = Field(max_length=1000)
    engine_version: str = Field(min_length=1, max_length=100)
