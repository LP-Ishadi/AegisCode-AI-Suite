"""Internal scanner endpoint. This process has no GitHub or Supabase credentials."""

import re
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.services.adapter_errors import AdapterError
from app.services.code_graph import rank_related
from app.services.repository_snapshot import Snapshot, safe_path
from app.services.scanner_suite import ScannerSuite

ROOT = Path("/scan-data")
DIRECTORY = re.compile(r"^aegis-scan-[A-Za-z0-9_-]+$")


class ScanRequest(BaseModel):
    directory: str = Field(max_length=100)
    paths: list[str] = Field(min_length=1, max_length=2000)
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")


class GraphRequest(ScanRequest):
    changed_paths: list[str] = Field(max_length=80)


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def verified_snapshot(request: ScanRequest) -> Snapshot:
    if not DIRECTORY.fullmatch(request.directory):
        raise HTTPException(422, "source_incomplete")
    source = ROOT / request.directory / "source"
    if not source.is_dir() or not all(safe_path(path) for path in request.paths):
        raise HTTPException(422, "source_incomplete")
    actual = set()
    for path in source.rglob("*"):
        if path.is_symlink():
            raise HTTPException(422, "source_incomplete")
        if path.is_file():
            actual.add(path.relative_to(source).as_posix())
            if len(actual) > 2000:
                raise HTTPException(422, "source_incomplete")
    if actual != set(request.paths) or len(actual) != len(request.paths):
        raise HTTPException(422, "source_incomplete")
    return Snapshot(source, frozenset(actual), request.commit_sha)


@app.post("/scan")
async def scan(request: ScanRequest):
    snapshot = verified_snapshot(request)
    try:
        result = await ScannerSuite().scan(snapshot)
        return result.model_dump(mode="json")
    except AdapterError as exc:
        raise HTTPException(422 if exc.code == "source_incomplete" else 503, exc.code) from exc


@app.post("/graph/related")
async def graph_related(request: GraphRequest):
    snapshot = verified_snapshot(request)
    if not all(safe_path(path) for path in request.changed_paths):
        raise HTTPException(422, "source_incomplete")
    try:
        return rank_related(snapshot, request.changed_paths)
    except ValueError:
        raise HTTPException(422, "source_incomplete") from None
