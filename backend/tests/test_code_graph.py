import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.models.dispatch import ScanMetadata, ScanResult
from app.services.code_graph import rank_related
from app.services.manual_review import automatic_context
from app.services.repository_snapshot import Snapshot
from app.services.scan_pipeline import ScannerPipeline


def test_one_hop_graph_finds_python_callers_and_javascript_imports(tmp_path: Path):
    files = {
        "backend/app/auth.py": "def check(): return True\n",
        "backend/app/route.py": "from app.auth import check\n",
        "backend/app/broken.py": "def broken(\n",
        "frontend/src/changed.ts": "export const value = 1;\n",
        "frontend/src/caller.ts": "import {value} from './changed';\n",
    }
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    snapshot = Snapshot(tmp_path, frozenset(files), "a" * 40)
    result = rank_related(snapshot, ["backend/app/auth.py", "frontend/src/changed.ts"])
    assert result["commit"] == snapshot.commit_sha
    assert {item["path"] for item in result["candidates"]} == {
        "backend/app/route.py", "frontend/src/caller.ts"
    }
    assert result["skipped_files"] == 1
    assert "content" not in json.dumps(result)


def test_graph_selection_has_priority_and_falls_back_to_heuristic(monkeypatch):
    monkeypatch.setattr("app.services.manual_review.MAX_RELATED_FILES", 1)
    metadata = ScanMetadata.model_construct(commit_sha="a" * 40)
    tools = SimpleNamespace(
        metadata=metadata,
        list_files=AsyncMock(return_value=[
            "app/main.py", "app/permissions.py", "app/unusual.py"
        ]),
        read_file=AsyncMock(side_effect=lambda path: {
            "path": path,
            "content": {
                "app/main.py": "from app.permissions import check\n",
                "app/permissions.py": "def check(): return True\n",
                "app/unusual.py": "def related(): pass\n",
            }[path],
        }),
    )
    diff = json.dumps([{"file": "app/main.py", "status": "modified"}])
    graph = {"commit": metadata.commit_sha, "candidates": [
        {"path": "app/unusual.py", "relation": "imports_change"}
    ], "indexed_files": 3, "skipped_files": 0, "candidate_count": 1,
        "truncated": False}
    with_graph = asyncio.run(automatic_context(tools, diff, graph))
    fallback = asyncio.run(automatic_context(tools, diff))
    assert [item["path"] for item in with_graph["included"]] == [
        "app/main.py", "app/unusual.py"
    ]
    assert [item["path"] for item in fallback["included"]] == [
        "app/main.py", "app/permissions.py"
    ]
    assert with_graph["graph"]["status"] == "used"
    assert fallback["graph"]["status"] == "fallback"


def test_scanner_pipeline_carries_graph_hints_without_changing_scan_result():
    metadata = ScanMetadata.model_construct(commit_sha="a" * 40)
    graph = {"commit": metadata.commit_sha, "candidates": [], "indexed_files": 1,
             "skipped_files": 0, "candidate_count": 0, "truncated": False}
    snapshot = SimpleNamespace(fetch_into=AsyncMock(side_effect=lambda _, root:
        Snapshot(root, frozenset({"app.py"}), metadata.commit_sha)))
    scanners = SimpleNamespace(scan=AsyncMock(return_value=ScanResult(
        findings=[], engine_version="scanner-test"
    )))
    remote_graph = SimpleNamespace(rank=AsyncMock(return_value=graph))
    pipeline = ScannerPipeline(snapshot=snapshot, scanners=scanners, graph=remote_graph)
    with patch("app.services.scan_pipeline.get_settings", return_value=SimpleNamespace(
        ai_scanning_enabled=False, openai_api_key=None, scanner_service_url=None
    )):
        result = asyncio.run(pipeline.run(metadata))
    assert result.findings == []
    assert result.context_graph == graph
    remote_graph.rank.assert_awaited_once()


def test_graph_failure_does_not_change_scanner_result():
    metadata = ScanMetadata.model_construct(commit_sha="a" * 40)
    snapshot = SimpleNamespace(fetch_into=AsyncMock(side_effect=lambda _, root:
        Snapshot(root, frozenset({"app.py"}), metadata.commit_sha)))
    scanners = SimpleNamespace(scan=AsyncMock(return_value=ScanResult(
        findings=[], engine_version="scanner-test"
    )))
    graph = SimpleNamespace(rank=AsyncMock(side_effect=ValueError("graph unavailable")))
    pipeline = ScannerPipeline(snapshot=snapshot, scanners=scanners, graph=graph)
    with patch("app.services.scan_pipeline.get_settings", return_value=SimpleNamespace(
        ai_scanning_enabled=False, openai_api_key=None, scanner_service_url=None
    )):
        result = asyncio.run(pipeline.run(metadata))
    assert result.context_graph is None
    assert result.findings == []
    assert result.coverage[0].status.value == "complete"
