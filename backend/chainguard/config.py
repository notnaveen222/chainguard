"""Central configuration for ChainGuard.

All tunable behaviour lives here rather than being scattered as literals through
the codebase. Values may be overridden by environment variables (prefix
``CHAINGUARD_``) or by a ``.env`` file at the repository root.

The resource limits in :class:`AnalysisLimits` are security controls, not
performance tuning — the scanner processes deliberately hostile archives and
source files, so every ingestion path needs a ceiling. See ARCHITECTURE.md §5.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

# config.py -> chainguard/ -> backend/ -> repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
DOCS_DIR = REPO_ROOT / "docs"


class AnalysisLimits(BaseSettings):
    """Hard ceilings applied when ingesting and analysing untrusted packages.

    These exist because a malicious package can attack the scanner itself: a zip
    bomb, a multi-gigabyte source file, or a pathological expression that makes
    the AST parser hang. Every limit below corresponds to one of those threats.
    """

    model_config = SettingsConfigDict(env_prefix="CHAINGUARD_LIMIT_", extra="ignore")

    # --- Archive extraction (zip bombs, path traversal) --------------------- #
    max_archive_bytes: int = Field(
        default=80 * 1024 * 1024,
        description="Reject a downloaded distribution larger than this (compressed).",
    )
    max_uncompressed_bytes: int = Field(
        default=400 * 1024 * 1024,
        description="Reject an archive whose members exceed this total when expanded.",
    )
    max_compression_ratio: float = Field(
        default=200.0,
        description=(
            "Reject an archive whose uncompressed:compressed ratio exceeds this. "
            "Legitimate source tarballs sit well under 50:1; a zip bomb is 1000:1+."
        ),
    )
    max_archive_members: int = Field(
        default=20_000,
        description="Reject an archive containing more members than this.",
    )

    # --- Per-file analysis (parser DoS) ------------------------------------ #
    max_file_bytes: int = Field(
        default=2 * 1024 * 1024,
        description="Skip analysing any single source file larger than this.",
    )
    max_files_per_package: int = Field(
        default=3_000,
        description="Stop analysing a package after this many candidate files.",
    )
    analysis_timeout_seconds: float = Field(
        default=60.0,
        description="Wall-clock ceiling for static analysis of one package.",
    )

    # --- Dependency resolution --------------------------------------------- #
    max_dependency_depth: int = Field(
        default=6,
        description="Maximum transitive depth walked when resolving a dep tree.",
    )
    max_packages_per_scan: int = Field(
        default=750,
        description="Safety ceiling on total packages resolved in a single scan.",
    )


class Settings(BaseSettings):
    """Top-level application settings."""

    model_config = SettingsConfigDict(
        env_prefix="CHAINGUARD_",
        env_file=REPO_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application ------------------------------------------------------- #
    app_name: str = "ChainGuard"
    environment: str = Field(default="development")
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")

    # --- Storage locations ------------------------------------------------- #
    data_dir: Path = Field(default=DATA_DIR)
    cache_dir: Path = Field(default=DATA_DIR / "cache")
    corpus_dir: Path = Field(default=DATA_DIR / "corpus")
    quarantine_dir: Path = Field(default=DATA_DIR / "quarantine")
    models_dir: Path = Field(default=DATA_DIR / "models")
    reports_dir: Path = Field(default=DATA_DIR / "reports")
    database_url: str = Field(default=f"sqlite:///{DATA_DIR / 'chainguard.db'}")

    # --- Registry endpoints ------------------------------------------------ #
    npm_registry_url: str = "https://registry.npmjs.org"
    pypi_url: str = "https://pypi.org"
    osv_api_url: str = "https://api.osv.dev"

    # --- HTTP behaviour ---------------------------------------------------- #
    http_timeout_seconds: float = 30.0
    http_max_retries: int = 3
    http_max_connections: int = 16
    http_user_agent: str = (
        "ChainGuard/0.1 (academic supply-chain security research; static analysis only)"
    )
    cache_enabled: bool = True
    cache_ttl_seconds: int = 7 * 24 * 3600  # registry metadata is stable enough

    # --- Detection thresholds ---------------------------------------------- #
    malicious_threshold: float = Field(
        default=0.60,
        description="Classifier probability at or above which a package is flagged.",
    )
    suspicious_threshold: float = Field(
        default=0.30,
        description="Probability at or above which a package is marked for review.",
    )

    # --- Optional AI layer (OpenAI or Gemini) ------------------------------- #
    # The system is fully functional with no API key and no network: scans use
    # the trained classifier and local explanations. With a key, the LLM reviews
    # flagged packages (hybrid verdict), writes explanations and powers the
    # assistant chat. Switch provider with AI_PROVIDER=openai|gemini plus the
    # matching key; nothing else changes. See BUILD_LOG.md D-003.
    llm_enabled: bool = Field(default=True)
    ai_provider: str = Field(
        default="openai",
        validation_alias=AliasChoices("CHAINGUARD_AI_PROVIDER", "AI_PROVIDER"),
    )
    llm_model_override: str | None = Field(
        default=None,
        validation_alias=AliasChoices("CHAINGUARD_LLM_MODEL"),
        description="Model name for the active provider; unset uses that provider's default.",
    )
    openai_model: str = Field(default="gpt-5.6-luna")
    gemini_model: str = Field(default="gemini-3.1-flash-lite")
    llm_max_tokens: int = Field(default=1200)
    ai_review_max_packages: int = Field(
        default=30,
        description="Most flagged/suspicious packages the LLM reviews per scan (highest score first).",
    )
    openai_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("CHAINGUARD_OPENAI_API_KEY", "OPENAI_API_KEY"),
    )
    gemini_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("CHAINGUARD_GEMINI_API_KEY", "GEMINI_API_KEY"),
    )

    # --- Optional Jev layer (TypeSafe System One) -------------------------- #
    # Jev returns typed judgments (a verdict distribution plus yes/no
    # probabilities) instead of prose. It runs *beside* the GPT review so the two
    # can be compared; it records its answer and never changes the verdict.
    jev_enabled: bool = Field(default=True)
    jev_model: str = Field(default="jev-latest")
    jev_timeout_seconds: float = Field(default=20.0)
    typesafe_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("CHAINGUARD_TYPESAFE_API_KEY", "TYPESAFE_API_KEY"),
    )

    # --- Nested limits ----------------------------------------------------- #
    limits: AnalysisLimits = Field(default_factory=AnalysisLimits)

    # ---------------------------------------------------------------------- #

    @field_validator("log_level")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    @field_validator("ai_provider")
    @classmethod
    def _known_provider(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in ("openai", "gemini"):
            raise ValueError(f"AI_PROVIDER must be 'openai' or 'gemini', got {v!r}")
        return v

    @property
    def llm_available(self) -> bool:
        """True only when the LLM layer is both enabled *and* usable.

        Callers check this rather than ``llm_enabled`` so that a missing key
        degrades gracefully to the local-only path instead of raising at runtime.
        """
        return bool(self.llm_enabled and self.resolved_api_key)

    @property
    def llm_provider_label(self) -> str:
        return "Gemini" if self.ai_provider == "gemini" else "OpenAI"

    @property
    def llm_key_env_name(self) -> str:
        return "GEMINI_API_KEY" if self.ai_provider == "gemini" else "OPENAI_API_KEY"

    @property
    def jev_available(self) -> bool:
        """True only when Jev is enabled and a TypeSafe key is configured."""
        return bool(self.jev_enabled and self.resolved_typesafe_key)

    @property
    def resolved_typesafe_key(self) -> str | None:
        """TypeSafe API key from settings/.env, falling back to the process env."""
        return self.typesafe_api_key or os.environ.get("TYPESAFE_API_KEY")

    @property
    def resolved_api_key(self) -> str | None:
        """API key for the active provider, from settings/.env or the process env."""
        if self.ai_provider == "gemini":
            return self.gemini_api_key or os.environ.get("GEMINI_API_KEY")
        return self.openai_api_key or os.environ.get("OPENAI_API_KEY")

    @property
    def llm_base_url(self) -> str | None:
        """OpenAI-compatible endpoint override; None means the SDK default (OpenAI)."""
        if self.ai_provider == "gemini":
            return "https://generativelanguage.googleapis.com/v1beta/openai/"
        return None

    @property
    def llm_model(self) -> str:
        """Model for the active provider.

        An override naming the *other* provider's family (e.g. a leftover
        ``gpt-*`` while AI_PROVIDER=gemini) is ignored, so switching provider
        never needs a second edit.
        """
        default = self.gemini_model if self.ai_provider == "gemini" else self.openai_model
        override = (self.llm_model_override or "").strip()
        if not override:
            return default
        other_family = "gpt" if self.ai_provider == "gemini" else "gemini"
        if override.lower().startswith(other_family):
            return default
        return override

    def ensure_directories(self) -> None:
        """Create the runtime data directories if they do not exist."""
        for path in (
            self.data_dir,
            self.cache_dir,
            self.corpus_dir,
            self.quarantine_dir,
            self.models_dir,
            self.reports_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    settings = Settings()
    settings.ensure_directories()
    return settings
