"""Environment-driven runtime config.

Reads from ``.env`` or process env. Twelve-factor friendly:

  * ``BIJOTEL_FED_DB_PATH`` — SQLite file. Default ``./federation.db``.
  * ``BIJOTEL_FED_PRIVATE_KEY_PEM`` — federation's Ed25519 private key
    PEM, **inline** as an env var (Docker secrets / k8s secrets).
    No default — required. Generate with ``bijotel keygen``.
  * ``BIJOTEL_FED_PUBLIC_KEY_PEM`` — matching public key PEM.
  * ``BIJOTEL_FED_REKOR_URL`` — Rekor base URL. Default
    ``https://rekor.sigstore.dev``. Set empty string to disable
    Rekor anchoring (development / air-gapped mode).
  * ``BIJOTEL_FED_REKOR_PRIVATE_KEY_PEM`` — **ECDSA P-256** private key
    PEM (inline) used to sign cross-anchor hashes for Rekor. Separate
    from the Ed25519 receipt-signing key above: Rekor verifies Ed25519
    via Ed25519ph (which Python cannot emit), so anchoring uses ECDSA.
    Empty disables Rekor anchoring even when ``rekor_url`` is set.
    Generate with ``bijotel keygen --type ecdsa``.
  * ``BIJOTEL_FED_ANCHOR_INTERVAL_SECONDS`` — how often the cross-
    anchor builder runs. Default ``3600`` (1 hour).
  * ``BIJOTEL_FED_MIN_PARTICIPANTS`` — minimum operators in one
    cross-anchor batch. Default ``2``. Batches below this stay
    pending until enough operators have submitted.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Federation operator config — read once at app start."""

    model_config = SettingsConfigDict(
        env_prefix="BIJOTEL_FED_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    db_path: str = "./federation.db"
    private_key_pem: str = ""
    public_key_pem: str = ""
    rekor_url: str = "https://rekor.sigstore.dev"
    rekor_private_key_pem: str = ""
    anchor_interval_seconds: int = 3600
    min_participants: int = 2
    bind_host: str = "0.0.0.0"
    bind_port: int = 8088


_settings: Settings | None = None


def get_settings() -> Settings:
    """Cached settings — instantiate once, return the same object."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
