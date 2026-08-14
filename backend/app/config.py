# SPDX-License-Identifier: Apache-2.0
"""All configuration via environment variables (12-factor). No hardcoded values."""
from __future__ import annotations

from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    database_url: str = Field(
        default="sqlite:///./secure_collab.db",
        description="Database URL",
        validation_alias=AliasChoices("database_url", "DATABASE_URL", "SECURECOLLAB_DATABASE_URL"),
    )
    upload_dir: str = Field(
        default="./uploads",
        description="Base directory for uploads",
        validation_alias=AliasChoices(
            "upload_dir", "UPLOAD_DIR", "SECURECOLLAB_UPLOAD_DIR", "SECURECOLLAB_UPLOADS_DIR"
        ),
    )
    max_upload_size_mb: int = Field(
        default=500,
        ge=1,
        le=2000,
        description="Max upload size in MB",
        validation_alias=AliasChoices("max_upload_size_mb", "MAX_UPLOAD_SIZE_MB", "SECURECOLLAB_MAX_UPLOAD_MB"),
    )
    secret_key: str = Field(
        default="dev-secret-key-change-in-production",
        min_length=16,
        validation_alias=AliasChoices("secret_key", "SECRET_KEY", "SECURECOLLAB_SECRET_KEY"),
    )
    allowed_origins: list[str] = Field(
        default=["http://localhost:3000"],
        description="Allowed CORS origins",
        validation_alias=AliasChoices("allowed_origins", "ALLOWED_ORIGINS"),
    )
    max_concurrent_computations: int = Field(
        default=3,
        ge=1,
        le=32,
        validation_alias=AliasChoices(
            "max_concurrent_computations",
            "MAX_CONCURRENT_COMPUTATIONS",
            "SECURECOLLAB_MAX_CONCURRENT_COMPUTATIONS",
        ),
    )
    compute_codebase_hash_on_startup: bool = Field(
        default=True,
        description="Compute codebase hash at startup",
        validation_alias=AliasChoices(
            "compute_codebase_hash_on_startup", "COMPUTE_CODEBASE_HASH_ON_STARTUP"
        ),
    )
    production_flag: bool = Field(
        default=False,
        description="Set SECURECOLLAB_PRODUCTION=1 to enable HSTS and production checks",
        validation_alias=AliasChoices("production_flag", "SECURECOLLAB_PRODUCTION"),
    )
    admin_emails: list[str] = Field(
        default_factory=list,
        description="Emails treated as admins when using header-based pilot auth",
        validation_alias=AliasChoices("admin_emails", "ADMIN_EMAILS"),
    )
    provider_emails: list[str] = Field(
        default_factory=list,
        description="Emails treated as data providers in pilot auth",
        validation_alias=AliasChoices("provider_emails", "PROVIDER_EMAILS"),
    )
    researcher_emails: list[str] = Field(
        default_factory=list,
        description="Emails treated as researchers in pilot auth",
        validation_alias=AliasChoices("researcher_emails", "RESEARCHER_EMAILS"),
    )
    # Planned (unused): blockchain anchoring. Kept so operators can set secrets
    # without code changes when the feature lands. Do not treat as active.
    polygon_rpc_url: str | None = Field(
        default=None,
        description="Polygon RPC URL for planned anchoring (unused)",
        validation_alias=AliasChoices("polygon_rpc_url", "POLYGON_RPC_URL"),
    )
    polygon_private_key: str | None = Field(
        default=None,
        description="Private key for planned anchoring (unused; never commit)",
        validation_alias=AliasChoices("polygon_private_key", "POLYGON_PRIVATE_KEY"),
    )

    @property
    def upload_dir_path(self) -> Path:
        return Path(self.upload_dir)

    @property
    def studies_upload_dir_path(self) -> Path:
        return self.upload_dir_path / "studies"

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    @property
    def production(self) -> bool:
        if self.production_flag:
            return True
        return self.secret_key != "dev-secret-key-change-in-production"


settings = Settings()

UPLOADS_DIR = settings.upload_dir_path
STUDIES_UPLOADS_DIR = settings.studies_upload_dir_path
MAX_UPLOAD_MB = settings.max_upload_size_mb
MAX_UPLOAD_BYTES = settings.max_upload_bytes
SQLITE_URL = settings.database_url
MAX_CONCURRENT_COMPUTATIONS = settings.max_concurrent_computations
PRODUCTION = settings.production
ALLOWED_UPLOAD_EXTENSIONS = {".bin"}
CKKS_BYTES_PER_SLOT_HEURISTIC = 8000
INITIAL_HASH = "0" * 64
