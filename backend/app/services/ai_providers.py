"""Resolve an explicitly selected AI provider without requiring paid credentials."""

from dataclasses import dataclass

from app.services.adapter_errors import AdapterError


@dataclass(frozen=True)
class Provider:
    name: str
    model: str
    api_key: str
    base_url: str | None = None
    chat_completions: bool = False


def selected_provider(settings) -> Provider:
    name = getattr(settings, "ai_provider", "openai")
    if name == "openai":
        secret = settings.openai_api_key
        model = settings.openai_model
        base_url = None
        chat = False
    elif name == "groq":
        secret = settings.groq_api_key
        model = settings.groq_model
        base_url = "https://api.groq.com/openai/v1"
        chat = True
    elif name == "ollama":
        secret = None
        model = settings.ollama_model
        base_url = str(settings.ollama_base_url).rstrip("/")
        chat = True
    else:
        raise AdapterError("ai_configuration")
    key = "ollama" if name == "ollama" else (
        secret.get_secret_value() if secret is not None else ""
    )
    if not key.strip() or not model.strip():
        raise AdapterError("ai_configuration")
    return Provider(name, model, key, base_url, chat)
