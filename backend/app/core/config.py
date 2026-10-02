from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AnyHttpUrl, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[3] / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"
    cors_origins: list[AnyHttpUrl] = [AnyHttpUrl("http://localhost:5173")]
    supabase_url: AnyHttpUrl | None = None
    supabase_anon_key: SecretStr | None = None
    supabase_service_key: SecretStr | None = None
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    github_webhook_secret: SecretStr | None = None
    redis_url: SecretStr | None = None
    max_webhook_bytes: int = Field(default=1_048_576, ge=1024, le=5_242_880)

    @model_validator(mode="after")
    def secure_production(self) -> "Settings":
        if self.environment == "production":
            if not all(
                (
                    self.supabase_url,
                    self.supabase_anon_key,
                    self.supabase_service_key,
                    self.github_webhook_secret,
                )
            ):
                raise ValueError("Production requires Supabase credentials and webhook secret")
            if self.supabase_url.scheme != "https":
                raise ValueError("Production Supabase URL must use HTTPS")
            if not self.cors_origins or any(o.scheme != "https" for o in self.cors_origins):
                raise ValueError("Production CORS origins must use HTTPS")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
