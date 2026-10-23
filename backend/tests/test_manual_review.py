import asyncio
import unittest

from pydantic import ValidationError

from app.models.dispatch import ScanMetadata
from app.services.manual_review import ModelReply, RepositoryTools, ToolCall, prompt


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

    def test_read_file_uses_immutable_commit_and_rejects_invalid_path(self):
        metadata = ScanMetadata.model_construct(
            repository_full_name="owner/repo", commit_sha="a" * 40
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
        self.assertTrue(all(metadata.commit_sha in path for path in calls))
        with self.assertRaises(ValueError):
            asyncio.run(tools.read_file("../other.py"))


if __name__ == "__main__":
    unittest.main()
