"""Bounded OpenAI review of PR, scanner evidence, and immutable repository files."""

import json

from openai import APIConnectionError, APIStatusError, AsyncOpenAI
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.models.dispatch import ScanMetadata, ScanResult, SourceBundle
from app.models.schemas import Finding, ReviewMode
from app.services.adapter_errors import AdapterError
from app.services.coverage_ledger import ai_coverage
from app.services.manual_review import (
    ModelReply,
    RepositoryTools,
    checked_findings,
    prepared_prompt,
    prompt,
    record_file_read,
    require_context_for_clean,
    require_file_read,
)

MAX_MODEL_STEPS = 5
MAX_CONVERSATION_CHARS = 180_000


class ContextReviewEngine:
    def __init__(self, settings: Settings | None = None, *, client_factory=AsyncOpenAI):
        self.settings = settings or get_settings()
        self.client_factory = client_factory

    async def analyze(
        self,
        metadata: ScanMetadata,
        source: SourceBundle,
        scanner_findings: list[Finding],
        graph_result: dict | None = None,
    ) -> ScanResult:
        if not self.settings.ai_scanning_enabled or not self.settings.openai_api_key:
            raise AdapterError("ai_configuration")
        if source.commit_sha != metadata.commit_sha:
            raise AdapterError("source_incomplete")
        tools = RepositoryTools(metadata)
        await tools.ready()
        request = await prepared_prompt(
            metadata, source, tools, scanner_findings, graph_result=graph_result
        )
        instructions = request["system"]
        messages = [{"role": "user", "content": json.dumps(request)}]
        pending = list(request["coverage_pending"])
        file_read_completed = False
        evidence_scope = request["evidence_scope"]
        coverage_context = request.get("coverage_context")

        try:
            async with self.client_factory(
                api_key=self.settings.openai_api_key.get_secret_value(),
                timeout=35,
                max_retries=0,
            ) as client:
                for step in range(MAX_MODEL_STEPS):
                    if len(json.dumps(messages)) > MAX_CONVERSATION_CHARS:
                        raise AdapterError("source_incomplete")
                    response = await client.responses.parse(
                        model=self.settings.openai_model,
                        instructions=instructions,
                        input=messages,
                        text_format=ModelReply,
                        max_output_tokens=4000,
                        store=False,
                    )
                    if response.status != "completed" or response.output_parsed is None:
                        raise AdapterError("invalid_ai_output")
                    reply = ModelReply.model_validate(response.output_parsed)
                    if reply.kind == "final":
                        try:
                            require_file_read(file_read_completed)
                            require_context_for_clean(reply.findings, pending)
                            findings = await checked_findings(
                                metadata,
                                reply.findings,
                                tools,
                                mode=ReviewMode.automated,
                                evidence_scope=evidence_scope,
                            )
                        except ValueError as exc:
                            messages.extend(
                                [
                                    {"role": "assistant", "content": reply.model_dump_json()},
                                    {"role": "user", "content": str(exc)},
                                ]
                            )
                            continue
                        return ScanResult(
                            findings=findings,
                            engine_version=f"openai-context/{self.settings.openai_model}",
                            review_mode=ReviewMode.automated,
                            coverage=[ai_coverage(
                                metadata.commit_sha, ReviewMode.automated,
                                evidence_scope, coverage_context, pending,
                            )],
                        )
                    try:
                        result = await tools.execute(reply.tool)
                    except ValueError:
                        # Unsupported files are not counted as reviewed evidence.
                        result = {"error": "unsupported_file_or_tree", "path": reply.tool.path}
                    if reply.tool.name == "read_file" and "content" in result:
                        file_read_completed = (
                            record_file_read(evidence_scope, pending, result)
                            or file_read_completed
                        )
                    next_request = prompt(
                        metadata,
                        "",
                        step=step + 1,
                        tool_result=result,
                        coverage_pending=pending,
                        file_read_completed=file_read_completed,
                        evidence_scope=evidence_scope,
                        coverage_context=coverage_context,
                    )
                    messages.extend(
                        [
                            {"role": "assistant", "content": reply.model_dump_json()},
                            {"role": "user", "content": json.dumps(next_request)},
                        ]
                    )
        except AdapterError:
            raise
        except APIConnectionError:
            raise AdapterError("upstream_unavailable", retryable=True) from None
        except APIStatusError as exc:
            raise AdapterError(
                "upstream_unavailable"
                if exc.status_code == 429 or exc.status_code >= 500
                else "ai_configuration",
                retryable=exc.status_code == 429 or exc.status_code >= 500,
            ) from None
        except (ValidationError, ValueError, TypeError):
            raise AdapterError("invalid_ai_output") from None
        raise AdapterError("invalid_ai_output")
