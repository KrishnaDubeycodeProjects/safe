"""
config.py — Typed settings loader via pydantic-settings.

All values are read from environment variables or a .env file at startup.
Access anywhere in the app via:  from app.config import settings
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── AWS Bedrock ────────────────────────────────────────────────────────────
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_region: str = "us-east-1"
    bedrock_model_id: str = "anthropic.claude-3-haiku-20240307-v1:0"
    bedrock_anthropic_version: str = "bedrock-2023-05-31"
    # Bedrock Mantle API key (OpenAI-compatible endpoint for Gemma 4, etc.)
    bedrock_mantle_api_key: str = ""


    # ── OCR.space ─────────────────────────────────────────────────────────────
    ocr_space_api_key: str = "K84422890888957"
    ocr_space_api_url: str = "https://api.ocr.space/parse/image"
    ocr_language: str = "eng"

    # ── OpenAI ─────────────────────────────────────────────────────────────────
    openai_api_key: str = ""
    openai_base_url: str = ""

    # ── FastAPI App ────────────────────────────────────────────────────────────
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    app_log_level: str = "info"

    # ── CORS ───────────────────────────────────────────────────────────────────
    cors_origins: str = "*"

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v: str) -> str:
        return v  # kept as raw string; split in main.py

    def get_cors_origins(self) -> List[str]:
        # In production: CORS must be explicitly set — never allow wildcard
        if self.is_production and self.cors_origins == "*":
            raise ValueError(
                "CORS_ORIGINS must be explicitly set in production. "
                "Set it to your frontend domain e.g. https://yourdomain.com"
            )
        if self.cors_origins == "*":
            return ["*"]
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    # ── Rate Limiting ──────────────────────────────────────────────────────────
    rate_limit_requests: int = 30
    rate_limit_window_seconds: int = 60

    # ── Security ───────────────────────────────────────────────────────────────
    api_secret_key: str = ""  # empty = auth disabled
    # Comma-separated list of allowed hostnames (for TrustedHostMiddleware in prod)
    trusted_hosts: str = "*"  # e.g. "yourdomain.com,www.yourdomain.com"

    # ── Admin Blog Management ─────────────────────────────────────────────────
    # Strong key required in X-Admin-Key header for blog approve/reject/pending
    admin_blog_key: str = ""
    # Path to JSON file where approved/pending blogs are persisted
    blog_storage_path: str = "/app/data/blogs_store.json"

    # ── AI Backend (Digital-arrest-detector) ──────────────────────────────────
    ai_api_base_url: str = "http://localhost:8001"

    @property
    def auth_enabled(self) -> bool:
        return bool(self.api_secret_key)

    @property
    def blog_admin_enabled(self) -> bool:
        return bool(self.admin_blog_key)

    @property
    def trusted_hosts_list(self) -> List[str]:
        if self.trusted_hosts == "*":
            return ["*"]
        return [h.strip() for h in self.trusted_hosts.split(",") if h.strip()]

    @property
    def docs_enabled(self) -> bool:
        # Hide API docs in production to reduce attack surface
        return not self.is_production

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


settings = Settings()
