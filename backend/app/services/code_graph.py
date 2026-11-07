"""Bounded, read-only one-hop import graph for a pinned repository snapshot.

Edges are routing hints. They do not prove reachability or a security claim.
"""

import ast
import re
from pathlib import PurePosixPath

from app.services.repository_snapshot import Snapshot

MAX_GRAPH_FILES = 2000
MAX_GRAPH_SOURCE_BYTES = 100_000
MAX_GRAPH_CANDIDATES = 32
IMPORT_JS = re.compile(
    r"(?m)^\s*(?:import\s+(?:[^;\n]*?\s+from\s+)?|export\s+[^;\n]*?\s+from\s+|"
    r"(?:const|let|var)\s+[^;\n]*?=\s*require\s*\()"
    r"['\"](\.[^'\"]+)['\"]"
)
JS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")


def _python_target(module: str, paths: set[str]) -> str | None:
    suffix = module.replace(".", "/")
    matches = [path for path in paths if path.endswith("/" + suffix + ".py")
               or path == suffix + ".py"
               or path.endswith("/" + suffix + "/__init__.py")
               or path == suffix + "/__init__.py"]
    return matches[0] if len(matches) == 1 else None


def _relative_python_module(path: str, node: ast.ImportFrom) -> str:
    parts = list(PurePosixPath(path).parent.parts)
    if node.level > len(parts) + 1:
        return ""
    prefix = parts[:len(parts) - node.level + 1] if node.level else []
    return ".".join([*prefix, *(node.module.split(".") if node.module else [])])


def _javascript_target(path: str, spec: str, paths: set[str]) -> str | None:
    base = PurePosixPath(path).parent
    parts = []
    for part in (base / spec).parts:
        if part == ".":
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    stem = "/".join(parts)
    matches = [candidate for candidate in (stem, *(stem + ext for ext in JS_SUFFIXES),
               *(stem + "/index" + ext for ext in JS_SUFFIXES)) if candidate in paths]
    return matches[0] if len(matches) == 1 else None


def rank_related(snapshot: Snapshot, changed: list[str]) -> dict:
    """Return only path relations; no source text leaves the scanner service."""
    paths = set(snapshot.paths)
    if len(paths) > MAX_GRAPH_FILES or any(path not in paths for path in changed):
        raise ValueError("Invalid or oversized graph snapshot")
    edges: set[tuple[str, str]] = set()
    parsed = skipped = 0
    for path in sorted(paths):
        if not path.endswith((".py", *JS_SUFFIXES)):
            continue
        source_path = snapshot.root / path
        try:
            if source_path.stat().st_size > MAX_GRAPH_SOURCE_BYTES:
                skipped += 1
                continue
            content = source_path.read_text(encoding="utf-8")
            if "\x00" in content:
                skipped += 1
                continue
            if path.endswith(".py"):
                tree = ast.parse(content, filename=path)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        modules = [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom):
                        base = (_relative_python_module(path, node) if node.level
                                else node.module or "")
                        modules = [base, *(base + "." + alias.name
                                           for alias in node.names if base)]
                    else:
                        continue
                    for module in modules:
                        target = _python_target(module, paths) if module else None
                        if target and target != path:
                            edges.add((path, target))
            else:
                for spec in IMPORT_JS.findall(content):
                    target = _javascript_target(path, spec, paths)
                    if target and target != path:
                        edges.add((path, target))
            parsed += 1
        except (OSError, UnicodeError, SyntaxError, ValueError):
            skipped += 1
    changed_set = set(changed)
    candidates: dict[str, tuple[int, str]] = {}
    for source, target in edges:
        if source in changed_set and target not in changed_set:
            candidates[target] = max(candidates.get(target, (0, "")), (10, "imported_by_change"))
        if target in changed_set and source not in changed_set:
            candidates[source] = max(candidates.get(source, (0, "")), (12, "imports_change"))
    ranked = sorted(candidates, key=lambda path: (-candidates[path][0], path))
    return {
        "commit": snapshot.commit_sha,
        "candidates": [{"path": path, "relation": candidates[path][1]}
                       for path in ranked[:MAX_GRAPH_CANDIDATES]],
        "indexed_files": parsed,
        "skipped_files": skipped,
        "candidate_count": len(ranked),
        "truncated": len(ranked) > MAX_GRAPH_CANDIDATES,
    }
