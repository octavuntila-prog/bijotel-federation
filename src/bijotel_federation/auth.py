"""Ed25519 challenge-response auth + Bearer-token verification.

No passwords, no API keys: every authenticated call carries a
signature over a server-issued (registration) or client-issued
(submit) nonce. The federation only ever needs the operator's public
key — same trust model as SSH.

Nonces are 32 hex chars (16 random bytes) and stored in memory with
a 5-minute TTL. A real production deployment would replace this with
a small SQLite table + cleanup cron, but for the skeleton an in-
memory dict is enough.
"""

from __future__ import annotations

import secrets
import time

from bijotel.crypto.ed25519 import verify as ed25519_verify
from fastapi import HTTPException, status

# nonce → expiry timestamp (unix seconds)
_NONCES: dict[str, float] = {}
_NONCE_TTL_SECONDS = 300


def issue_nonce() -> str:
    """Mint a fresh registration nonce. Returned as hex (32 chars)."""
    _gc_nonces()
    nonce = secrets.token_hex(16)
    _NONCES[nonce] = time.time() + _NONCE_TTL_SECONDS
    return nonce


def consume_nonce(nonce: str) -> bool:
    """One-shot — remove + return whether it was still valid."""
    _gc_nonces()
    expiry = _NONCES.pop(nonce, None)
    return expiry is not None and expiry > time.time()


def _gc_nonces() -> None:
    """Drop expired nonces lazily — cheap and good enough at this scale."""
    now = time.time()
    expired = [n for n, exp in _NONCES.items() if exp <= now]
    for n in expired:
        _NONCES.pop(n, None)


def verify_signature(
    *, public_key_pem: bytes | str, message: bytes, signature_b64: str
) -> bool:
    """True if ``signature_b64`` is a valid Ed25519 sig over ``message``."""
    import base64

    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("ascii")
    try:
        sig = base64.b64decode(signature_b64)
    except (ValueError, TypeError):
        return False
    return ed25519_verify(message, sig, public_key_pem)


def parse_bearer_token(authorization_header: str | None) -> tuple[str, str, str]:
    """Parse ``Bearer <operator_id>.<nonce>.<signature_b64>``.

    Returns ``(operator_id, nonce, signature_b64)``. Raises 401 if
    the header is missing or malformed.
    """
    if not authorization_header or not authorization_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or malformed Authorization header",
        )
    token = authorization_header.removeprefix("Bearer ").strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="bearer token must be <operator_id>.<nonce>.<sig>",
        )
    return parts[0], parts[1], parts[2]
