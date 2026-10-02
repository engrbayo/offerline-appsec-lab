"""Runtime settings. Secrets come from the environment, which in AWS is
populated from Secrets Manager at task start (see terraform/secrets.tf).
Nothing secret has a default value, so a missing secret fails closed."""
import os
from dataclasses import dataclass, field


def _require(name: str, min_length: int = 1) -> str:
    value = os.environ.get(name)
    if not value or len(value.encode()) < min_length:
        raise RuntimeError(f"required setting {name} is missing or shorter than {min_length} bytes")
    return value


@dataclass(frozen=True)
class Settings:
    # HS256 needs a key of at least 256 bits (32 bytes); shorter keys are brute-forceable.
    jwt_secret: str = field(default_factory=lambda: _require("OFFERLINE_JWT_SECRET", min_length=32))
    jwt_issuer: str = os.environ.get("OFFERLINE_JWT_ISSUER", "https://auth.offerline.example")
    jwt_audience: str = os.environ.get("OFFERLINE_JWT_AUDIENCE", "offerline-partner-api")
    # SR-6: outbound calls only to hosts partners have registered with us.
    webhook_allowed_hosts: frozenset = frozenset(
        h.strip() for h in os.environ.get("OFFERLINE_WEBHOOK_HOSTS", "hooks.bank-a.example,hooks.bank-b.example").split(",") if h.strip()
    )
    # API docs are exposed only in test environments (used by the nightly DAST scan).
    enable_docs: bool = os.environ.get("OFFERLINE_ENABLE_DOCS", "false").lower() == "true"
    max_ingest_bytes: int = 1_000_000


def get_settings() -> Settings:
    return Settings()
