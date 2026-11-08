import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

from fastapi import HTTPException
from postgrest.exceptions import APIError
from pydantic import ValidationError

from app.api import manual_reviews
from app.main import manual_review_validation_detail
from app.models.dispatch import ScanMetadata
from app.services.manual_review import (
    ModelReply,
    RepositoryTools,
    ToolCall,
    automatic_context,
    prompt,
    require_context_for_clean,
    require_file_read,
)


class ManualReviewTests(unittest.TestCase):
    def test_read_file_rejects_paths_that_escape_or_change_github_request(self):
        for path in ("../config", "/etc/passwd", "src/file.py?ref=main", "x/%2e%2e/y"):
            with self.subTest(path=path), self.assertRaises(ValidationError):
                ToolCall(name="read_file", path=path)

    def test_model_cannot_mix_tool_request_and_final_findings(self):
        with self.assertRaises(ValidationError):
            ModelReply.model_validate(
                {"kind": "final", "findings": [], "tool": {"name": "list_files"}}
            )

    def test_final_finding_requires_explicit_evidence(self):
        with self.assertRaises(ValidationError):
            ModelReply.model_validate(
                {
                    "kind": "final",
                    "findings": [
                        {
                            "rule_id": "security.issue",
                            "file_path": "app.py",
                            "line": 1,
                            "severity": "medium",
                            "message": "Check this behavior",
                        }
                    ],
                }
            )

    def test_prompt_contains_actual_response_schema(self):
        metadata = ScanMetadata.model_construct(
            repository_full_name="owner/repo",
            pull_request_number=3,
            commit_sha="a" * 40,
            base_sha="b" * 40,
        )
        request = prompt(metadata, "redacted diff", step=0)
        self.assertEqual(request["pr_diff"], "redacted diff")
        self.assertIn("properties", request["output_schema"])
        self.assertFalse(request["file_read_completed"])
        self.assertIn("must request read_file", request["system"])
        self.assertEqual(request["example_next_reply"]["tool"]["name"], "list_files")
        self.assertIn("120 characters", request["security_rules"][-1])
        self.assertEqual(request["output_limits"]["evidence_role_max_characters"], 120)
        self.assertEqual(request["output_limits"]["evidence_line_excerpt_max_characters"], 240)
        self.assertIn("line_excerpt", request["response_examples"]["finding_evidence"])

    def test_new_review_schema_requires_evidence_excerpt(self):
        metadata = ScanMetadata.model_construct(
            repository_full_name="owner/repo", pull_request_number=3,
            commit_sha="a" * 40, base_sha="b" * 40,
        )
        request = prompt(metadata, "", step=0,
                         evidence_scope={"require_line_excerpt": True})
        reference = request["output_schema"]["$defs"]["EvidenceReference"]
        self.assertIn("line_excerpt", reference["required"])
        self.assertEqual(reference["properties"]["line_excerpt"]["type"], "string")
        old_request = prompt(metadata, "", step=0, evidence_scope={})
        old_reference = old_request["output_schema"]["$defs"]["EvidenceReference"]
        self.assertNotIn("line_excerpt", old_reference["required"])

    def test_invalid_ai_response_names_field_without_echoing_content(self):
        secret = "sensitive-value-" + "x" * 120
        with self.assertRaises(ValidationError) as caught:
            manual_reviews.Submission.model_validate({
                "step": 0,
                "response": {
                    "kind": "final",
                    "findings": [{
                        "rule_id": "security.issue", "file_path": "app.py", "line": 1,
                        "severity": "high", "message": "A concrete finding",
                        "evidence": [{"commit_sha": "a" * 40, "file_path": "app.py",
                                      "line": 1, "role": secret, "source": "diff",
                                      "line_excerpt": "print('ok')"}],
                    }],
                },
            })
        from fastapi.exceptions import RequestValidationError
        detail = manual_review_validation_detail(RequestValidationError(caught.exception.errors()))
        self.assertIn("response.findings.0.evidence.0.role", detail)
        self.assertIn("120 characters or fewer", detail)
        self.assertNotIn(secret, detail)

    def test_evidence_role_allows_short_explanation_over_old_limit(self):
        role = "service client documented as trusted-only"
        self.assertGreater(len(role), 40)
        reply = ModelReply.model_validate({
            "kind": "final",
            "findings": [{
                "rule_id": "security.issue", "file_path": "app.py", "line": 1,
                "severity": "high", "message": "A concrete finding",
                "evidence": [{"commit_sha": "a" * 40, "file_path": "app.py",
                              "line": 1, "role": role, "source": "diff",
                              "line_excerpt": "print('ok')"}],
            }],
        })
        self.assertEqual(reply.findings[0].evidence[0].role, role)

    def test_old_ai_reply_without_excerpt_remains_parseable(self):
        reply = ModelReply.model_validate({
                "kind": "final", "findings": [{
                    "rule_id": "security.issue", "file_path": "app.py", "line": 1,
                    "severity": "high", "message": "A concrete finding",
                    "evidence": [{"commit_sha": "a" * 40, "file_path": "app.py",
                                  "line": 1, "role": "changed code", "source": "diff"}],
                }],
            })
        self.assertIsNone(reply.findings[0].evidence[0].line_excerpt)

    def test_final_requires_successful_read_file_tool_call(self):
        with self.assertRaisesRegex(ValueError, "Call read_file"):
            require_file_read(False)
        require_file_read(True)

    def test_final_is_rejected_before_read_file_without_saving(self):
        review_id = UUID("11111111-1111-1111-1111-111111111111")
        scan_id = UUID("22222222-2222-2222-2222-222222222222")
        review = {
            "scan_id": str(scan_id),
            "status": "active",
            "step": 0,
            "prompt": {"coverage_pending": [], "file_read_completed": False,
                       "evidence_scope": {"commit": "a" * 40, "diff_lines": {},
                                          "auto_context_paths": [], "read_file_paths": []}},
        }
        tools = MagicMock()
        tools.ready = AsyncMock()
        submission = manual_reviews.Submission(step=0, response={"kind": "final", "findings": []})
        with (
            patch.object(manual_reviews, "load_review", return_value=review),
            patch.object(manual_reviews, "metadata_for_scan", return_value=object()),
            patch.object(manual_reviews, "RepositoryTools", return_value=tools),
            patch.object(manual_reviews, "get_service_client") as service,
        ):
            with self.assertRaises(HTTPException) as error:
                asyncio.run(manual_reviews.submit_response(review_id, submission, object()))
        self.assertEqual(error.exception.status_code, 422)
        self.assertIn("read_file", error.exception.detail)
        service.assert_not_called()

    def test_successful_read_file_allows_final(self):
        review_id = UUID("11111111-1111-1111-1111-111111111111")
        scan_id = UUID("22222222-2222-2222-2222-222222222222")
        metadata = ScanMetadata.model_construct(
            repository_full_name="owner/repo",
            pull_request_number=3,
            commit_sha="a" * 40,
            base_sha="b" * 40,
        )
        review = {
            "scan_id": str(scan_id),
            "status": "active",
            "step": 0,
            "prompt": {"coverage_pending": [], "file_read_completed": False,
                       "evidence_scope": {"commit": "a" * 40, "diff_lines": {},
                                          "auto_context_paths": [], "read_file_paths": []}},
        }
        tools = MagicMock()
        tools.ready = AsyncMock()
        tools.execute = AsyncMock(
            return_value={"path": "app/auth.py", "commit": "a" * 40, "content": "pass"}
        )
        service = MagicMock()
        service.rpc.return_value.execute.return_value.data = True
        with (
            patch.object(manual_reviews, "load_review", return_value=review),
            patch.object(manual_reviews, "metadata_for_scan", return_value=metadata),
            patch.object(manual_reviews, "RepositoryTools", return_value=tools),
            patch.object(manual_reviews, "get_service_client", return_value=service),
            patch.object(manual_reviews, "checked_findings", new=AsyncMock(return_value=[])),
        ):
            tool_result = asyncio.run(
                manual_reviews.submit_response(
                    review_id,
                    manual_reviews.Submission(
                        step=0,
                        response={
                            "kind": "tool",
                            "tool": {"name": "read_file", "path": "app/auth.py"},
                        },
                    ),
                    object(),
                )
            )
            self.assertTrue(tool_result["prompt"]["file_read_completed"])
            review["step"] = 1
            review["prompt"] = tool_result["prompt"]
            final_result = asyncio.run(
                manual_reviews.submit_response(
                    review_id,
                    manual_reviews.Submission(step=1, response={"kind": "final", "findings": []}),
                    object(),
                )
            )
        self.assertEqual(final_result["status"], "completed")

    def test_read_file_uses_immutable_commit_and_rejects_invalid_path(self):
        metadata = ScanMetadata.model_construct(
            repository_full_name="owner/repo", pull_request_number=3,
            commit_sha="a" * 40, base_sha="b" * 40,
        )
        tools = RepositoryTools(metadata)
        tools.token = "test-token"
        calls = []

        async def request(method, path, token):
            calls.append(path)
            return {"type": "file", "encoding": "base64", "size": 7, "content": "cHJp\nbnQoKQ=="}

        tools.api.request = request
        result = asyncio.run(tools.read_file("src/app.py"))
        self.assertEqual(result["content"], "print()")
        request = prompt(metadata, "", step=1, tool_result=result)
        self.assertEqual(request["tool_result"]["content"], "1: print()")
        self.assertTrue(all(metadata.commit_sha in path for path in calls))
        with self.assertRaises(ValueError):
            asyncio.run(tools.read_file("../other.py"))

    def test_automatic_context_includes_related_unchanged_file(self):
        metadata = ScanMetadata.model_construct(
            repository_full_name="owner/repo", pull_request_number=3,
            commit_sha="a" * 40, base_sha="b" * 40,
        )
        tools = RepositoryTools(metadata)
        tools.paths = ["app/auth.py", "app/permissions.py", "tests/test_auth.py"]
        contents = {
            "app/auth.py": "from app.permissions import can_access\n",
            "app/permissions.py": "def can_access(user): return True\n",
            "tests/test_auth.py": "def test_auth(): pass\n",
        }

        async def read_file(path):
            return {"path": path, "commit": metadata.commit_sha, "content": contents[path]}

        tools.read_file = read_file
        diff = json.dumps([{"file": "app/auth.py", "status": "modified"}])
        context = asyncio.run(automatic_context(tools, diff))
        included = {item["path"]: item["kind"] for item in context["included"]}
        self.assertEqual(included["app/auth.py"], "changed")
        self.assertEqual(included["app/permissions.py"], "related_unchanged")
        self.assertEqual(context["pending_changed_files"], [])
        request = prompt(metadata, diff, step=0, auto_context=context)
        numbered = {item["path"]: item["content"]
                    for item in request["auto_context"]["included"]}
        self.assertEqual(numbered["app/auth.py"],
                         "1: from app.permissions import can_access")

    def test_unreadable_changed_file_remains_pending(self):
        metadata = ScanMetadata.model_construct(
            repository_full_name="owner/repo",
            pull_request_number=3,
            commit_sha="a" * 40,
            base_sha="b" * 40,
        )
        tools = RepositoryTools(metadata)
        tools.paths = ["app/large.py"]

        async def unreadable(_path):
            raise ValueError("too large")

        tools.read_file = unreadable
        diff = json.dumps([{"file": "app/large.py", "status": "modified"}])
        context = asyncio.run(automatic_context(tools, diff))
        self.assertEqual(context["pending_changed_files"], ["app/large.py"])
        request = prompt(
            metadata,
            diff,
            step=0,
            auto_context=context,
            coverage_pending=context["pending_changed_files"],
        )
        self.assertEqual(request["coverage_pending"], ["app/large.py"])
        with self.assertRaisesRegex(ValueError, "pending changed files"):
            require_context_for_clean([], request["coverage_pending"])
        require_context_for_clean([], [])

    def test_concurrent_start_reuses_review_created_by_first_request(self):
        class ReviewTable:
            selects = 0
            operation = ""

            def select(self, _columns):
                self.operation = "select"
                return self

            def eq(self, *_args):
                return self

            def limit(self, _limit):
                return self

            def insert(self, _row):
                self.operation = "insert"
                return self

            def execute(self):
                if self.operation == "insert":
                    raise APIError({"code": "23505", "message": "duplicate scan_id"})
                self.selects += 1
                data = [] if self.selects == 1 else [{"id": "existing-review"}]
                return SimpleNamespace(data=data)

        table = ReviewTable()
        service = SimpleNamespace(table=lambda _name: table)
        scan_id = UUID("11111111-1111-1111-1111-111111111111")
        user = SimpleNamespace(user_id=scan_id)
        with (
            patch.object(
                manual_reviews,
                "operator_scan",
                return_value={
                    "status": "completed",
                    "organization_id": str(scan_id),
                },
            ),
            patch.object(manual_reviews, "get_service_client", return_value=service),
            patch.object(manual_reviews, "metadata_for_scan", return_value=object()),
            patch.object(manual_reviews, "scanner_findings_for_scan", return_value=[]),
            patch.object(manual_reviews, "graph_for_scan", return_value=None),
            patch.object(manual_reviews, "initial_prompt", new=AsyncMock(return_value={})),
        ):
            result = asyncio.run(manual_reviews.start_review(scan_id, user))
        self.assertEqual(result, {"id": "existing-review"})
        self.assertEqual(table.selects, 2)


if __name__ == "__main__":
    unittest.main()
