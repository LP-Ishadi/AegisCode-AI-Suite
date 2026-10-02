"""Provider adapters are deliberately inert until data-sharing controls exist."""

from typing import Literal

from app.models.schemas import AIReview, AIReviewRequest


class AIServiceUnavailable(RuntimeError):
    pass


class AIService:
    def __init__(self, provider: Literal["openai", "anthropic"] = "openai") -> None:
        self.provider = provider

    async def explain_finding(self, request: AIReviewRequest) -> AIReview:
        """Future: redact secrets, enforce tenant opt-in and token/time budgets,
        use OpenAI/Anthropic structured outputs, validate the returned AIReview.
        Treat code/comments as untrusted data, never instructions or tool calls.
        Require human approval of patches; do not execute model-generated code.
        """
        raise AIServiceUnavailable(f"{self.provider} review adapter is not configured")
