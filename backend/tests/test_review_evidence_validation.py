import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.models.dispatch import ScanMetadata
from app.models.schemas import (
    EvidenceReference,
    EvidenceStatus,
    Finding,
    ReviewMode,
)
from app.services.manual_review import AIProposal, checked_findings

SHA = "a" * 40
OTHER_SHA = "b" * 40


def setup():
    metadata = ScanMetadata.model_construct(commit_sha=SHA)
    files = {
        "app/route.py": "def route():\n    return authorize()\n",
        "app/auth.py": "def authorize():\n    return True\n",
        "app/secret.py": "token = '[REDACTED]'\n",
    }

    async def read_file(path):
        return {"path": path, "commit": SHA, "content": files[path]}

    tools = SimpleNamespace(read_file=AsyncMock(side_effect=read_file))
    scope = {
        "commit": SHA,
        "diff_lines": {"app/route.py": [(1, 2)]},
        "auto_context_paths": ["app/auth.py", "app/secret.py"],
        "read_file_paths": ["app/route.py"],
    }
    return metadata, tools, scope


def ref(path="app/route.py", line=2, source="diff", sha=SHA):
    return EvidenceReference(
        commit_sha=sha,
        file_path=path,
        line=line,
        role="changed_code" if path == "app/route.py" else "authorization",
        source=source,
    )


def proposal(*, evidence=None, cross_file_required=False, message="Check authorization"):
    return Finding(
        rule_id="security.authorization",
        file_path="app/route.py",
        line=2,
        severity="high",
        message=message,
        evidence=evidence if evidence is not None else [ref()],
        cross_file_required=cross_file_required,
    )


@pytest.mark.parametrize("mode", [ReviewMode.manual, ReviewMode.automated])
def test_single_file_and_necessary_cross_file_evidence(mode):
    metadata, tools, scope = setup()
    single = asyncio.run(
        checked_findings(
            metadata,
            [proposal()],
            tools,
            mode=mode,
            evidence_scope=scope,
        )
    )
    assert single[0].evidence_status is EvidenceStatus.location_checked
    assert single[0].review_mode is mode
    cross = proposal(
        evidence=[ref(), ref("app/auth.py", 2, "auto_context")], cross_file_required=True
    )
    validated = asyncio.run(
        checked_findings(
            metadata,
            [cross],
            tools,
            mode=mode,
            evidence_scope=scope,
        )
    )
    assert len(validated[0].evidence) == 2


@pytest.mark.parametrize(
    ("finding", "scope_change", "error"),
    [
        (proposal(evidence=[ref(sha=OTHER_SHA)]), None, "different commit"),
        (proposal(evidence=[ref(line=99)]), None, "not cited"),
        (
            proposal(evidence=[ref("app/auth.py", 99, "auto_context"), ref()]),
            None,
            "outside the file",
        ),
        (proposal(evidence=[ref("app/auth.py", 2, "auto_context")]), None, "not cited"),
        (proposal(cross_file_required=True), None, "another file"),
        (proposal(evidence=[ref("app/auth.py", 2, "read_file"), ref()]), None, "not supplied"),
        (proposal(), {"diff_lines": {}}, "not supplied"),
    ],
)
def test_rejects_unsupported_evidence(finding, scope_change, error):
    metadata, tools, scope = setup()
    if scope_change:
        scope.update(scope_change)
    with pytest.raises(ValueError, match=error):
        asyncio.run(checked_findings(metadata, [finding], tools, evidence_scope=scope))


def test_duplicate_finding_is_rejected_and_secret_value_is_redacted():
    metadata, tools, scope = setup()
    secret = "sk-" + "a" * 25
    item = proposal(message=f"The exposed key is {secret}")
    checked = asyncio.run(checked_findings(metadata, [item], tools, evidence_scope=scope))
    assert secret not in checked[0].message
    assert "[REDACTED]" in checked[0].message
    with pytest.raises(ValueError, match="Duplicate"):
        asyncio.run(checked_findings(metadata, [item, item], tools, evidence_scope=scope))


def test_redacted_file_can_be_cited_without_persisting_secret_text():
    metadata, tools, scope = setup()
    item = Finding(
        rule_id="security.secret",
        file_path="app/secret.py",
        line=1,
        severity="high",
        message="Secret should be rotated",
        evidence=[ref("app/secret.py", 1, "auto_context")],
    )
    checked = asyncio.run(checked_findings(metadata, [item], tools, evidence_scope=scope))
    assert checked[0].evidence[0].file_path == "app/secret.py"
    assert "content" not in checked[0].evidence[0].model_dump()


def test_wrong_line_excerpt_is_rejected_and_correct_one_is_not_persisted():
    metadata, tools, scope = setup()
    scope["require_line_excerpt"] = True
    wrong = AIProposal(
        rule_id="security.authorization", file_path="app/route.py", line=2,
        severity="high", message="Check authorization", cross_file_required=True,
        evidence=[
            EvidenceReference(commit_sha=SHA, file_path="app/route.py", line=2,
                                role="changed code", source="diff",
                                line_excerpt="return authorize()"),
            EvidenceReference(commit_sha=SHA, file_path="app/auth.py", line=2,
                                role="authorization call", source="auto_context",
                                line_excerpt="return authorize()"),
        ],
    )
    # The AI claimed this line calls authorize, but line 2 actually returns True.
    with pytest.raises(ValueError, match="app/auth.py:2.*does not match"):
        asyncio.run(checked_findings(metadata, [wrong], tools, evidence_scope=scope))

    wrong.evidence[1] = wrong.evidence[1].model_copy(update={
        "line_excerpt": "return True"
    })
    checked = asyncio.run(checked_findings(metadata, [wrong], tools, evidence_scope=scope))
    assert checked[0].evidence[0].line_excerpt is None
    assert "return authorize()" not in str(checked[0].model_dump())
