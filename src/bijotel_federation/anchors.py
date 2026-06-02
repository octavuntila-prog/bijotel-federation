"""Cross-anchor builder + Rekor upload.

Periodically (every ``anchor_interval_seconds``) groups recent
unanchored submissions into one cross-anchor record, signs it with
the federation's Ed25519 key, and optionally uploads the signature
to Rekor for public timestamping.

The cross-anchor hash is computed exactly the same way the client
verifier in ``bijotel.federation.verify_cross_anchor_receipt`` does
it — that's the seam that makes external auditing possible without
trusting the federation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time

from bijotel.crypto.ed25519 import sign as ed25519_sign

from bijotel_federation import db
from bijotel_federation.settings import Settings

_LOG = logging.getLogger("bijotel_federation.anchors")


def build_pending_cross_anchor(settings: Settings) -> dict[str, str] | None:
    """Build one cross-anchor from currently-pending submissions.

    Returns ``None`` if there are fewer than ``min_participants`` to
    anchor. Otherwise:

      1. Collects the latest pending submission per operator.
      2. Builds the canonical participants list sorted by operator_id.
      3. Computes ``cross_anchor_hash = sha256(sorted_sigs || anchored_at)``.
      4. Signs the canonical receipt payload with the federation key.
      5. (Optionally) anchors the cross-anchor hash in Rekor.
      6. Persists the anchor + marks submissions as anchored.
    """
    pending = db.submissions_pending_anchor(settings.db_path)
    if len(pending) < settings.min_participants:
        return None

    anchored_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    participants = sorted(
        [
            {"operator_id": s["operator_id"], "chain_signature": s["chain_head_signature"]}
            for s in pending
        ],
        key=lambda p: p["operator_id"],
    )

    blob = "".join(p["chain_signature"] for p in participants).encode("utf-8")
    blob += anchored_at.encode("utf-8")
    cross_anchor_hash = hashlib.sha256(blob).hexdigest()
    anchor_id = f"anchor_{anchored_at.replace(':', '').replace('-', '')}_{secrets.token_hex(3)}"

    # Optional Rekor anchoring of the cross-anchor hash itself.
    rekor_log_index, rekor_url = _maybe_anchor_in_rekor(settings, cross_anchor_hash)

    # Build + sign the canonical receipt payload — same scheme the
    # client uses to verify, so external parties can recompute.
    payload = _canonical_receipt_payload(
        anchor_id=anchor_id,
        cross_anchor_hash=cross_anchor_hash,
        anchored_at=anchored_at,
        participants=participants,
        rekor_log_index=rekor_log_index,
        rekor_url=rekor_url,
        federation_public_key_pem=settings.public_key_pem,
    )
    signature = ed25519_sign(payload, settings.private_key_pem.encode("ascii"))
    federation_signature = base64.b64encode(signature).decode("ascii")

    db.cross_anchor_create(
        settings.db_path,
        anchor_id=anchor_id,
        cross_anchor_hash=cross_anchor_hash,
        anchored_at=anchored_at,
        participants=participants,
        rekor_log_index=rekor_log_index,
        rekor_url=rekor_url,
        federation_signature=federation_signature,
    )
    db.submissions_mark_anchored(
        settings.db_path,
        submission_ids=[s["submission_id"] for s in pending],
        cross_anchor_id=anchor_id,
    )

    return {
        "anchor_id": anchor_id,
        "cross_anchor_hash": cross_anchor_hash,
        "anchored_at": anchored_at,
        "participant_count": str(len(participants)),
        "rekor_log_index": str(rekor_log_index) if rekor_log_index else "",
    }


def _maybe_anchor_in_rekor(
    settings: Settings, cross_anchor_hash: str
) -> tuple[int | None, str | None]:
    """Upload the cross-anchor hash to Rekor for public timestamping.

    Returns ``(log_index, url)`` on success, or ``(None, None)`` when Rekor
    is disabled (no ``rekor_url``), no ECDSA key is configured, or the upload
    fails. Rekor is a convenience, not a hard requirement — the federation
    keeps running and the cross-anchor stays locally + Ed25519 verifiable
    either way.

    Signs the cross-anchor hash with an **ECDSA P-256** key — Rekor's
    canonical ``hashedrekord`` path. (Rekor verifies Ed25519 via Ed25519ph,
    which Python's ``cryptography`` cannot emit; see ``bijotel.crypto
    .ecdsa_p256``. This was the v2.9 compat-gap; fixed upstream in BIJOTEL
    2.13.2, which is what unblocks this wiring.) The Ed25519 federation key
    still signs the receipt the client verifies; this is a separate,
    Rekor-only key (``BIJOTEL_FED_REKOR_PRIVATE_KEY_PEM``).
    """
    if not settings.rekor_url:
        return None, None
    if not settings.rekor_private_key_pem:
        _LOG.warning(
            "rekor_url is set but BIJOTEL_FED_REKOR_PRIVATE_KEY_PEM is empty — "
            "skipping Rekor anchoring (generate one: bijotel keygen --type ecdsa)"
        )
        return None, None

    try:
        log_index, url = _rekor_upload_hash(
            rekor_url=settings.rekor_url,
            ecdsa_private_pem=settings.rekor_private_key_pem.encode("ascii"),
            digest_hex=cross_anchor_hash,
        )
        _LOG.info("rekor: cross-anchor anchored at logIndex=%s", log_index)
        return log_index, url
    except Exception as exc:  # best-effort: never let Rekor break anchoring
        msg = str(exc)
        # 409 = entry already exists. Rekor is idempotent on (hash, sig, key),
        # so the hash IS anchored — treat as a non-fatal already-done.
        if "HTTP 409" in msg or " 409:" in msg:
            _LOG.info("rekor: cross-anchor already present (409) — treating as anchored")
            return None, None
        _LOG.warning(
            "rekor anchoring failed (non-fatal: %s): %s", type(exc).__name__, msg
        )
        return None, None


def _rekor_upload_hash(
    *, rekor_url: str, ecdsa_private_pem: bytes, digest_hex: str
) -> tuple[int, str]:
    """Sign ``bytes.fromhex(digest_hex)`` with ECDSA P-256 and upload a
    hashedrekord entry to Rekor. Returns ``(log_index, entry_url)``.

    Mirrors ``bijotel.anchoring.rekor.anchor_chain_head`` but for an arbitrary
    digest (the federation cross-anchor hash) instead of a chain-db head, so an
    external auditor re-verifies with the identical ``SHA-256(digest)`` recipe.
    """
    from bijotel.anchoring.rekor import RekorClient
    from bijotel.crypto.ecdsa_p256 import sign_digest
    from cryptography.hazmat.primitives import serialization

    data_bytes = bytes.fromhex(digest_hex)
    data_hash = hashlib.sha256(data_bytes).hexdigest()
    signature_b64 = base64.b64encode(
        sign_digest(data_bytes, ecdsa_private_pem)
    ).decode("ascii")

    priv = serialization.load_pem_private_key(ecdsa_private_pem, password=None)
    public_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_pem_b64 = base64.b64encode(public_pem).decode("ascii")

    resp = RekorClient(rekor_url).upload(
        data_hash_hex=data_hash,
        signature_b64=signature_b64,
        public_key_pem_b64=public_pem_b64,
    )
    if not isinstance(resp, dict) or not resp:
        raise RuntimeError(f"Rekor returned unexpected payload: {resp!r}")
    _uuid, entry = next(iter(resp.items()))
    log_index = int(entry.get("logIndex", -1))
    entry_url = f"{rekor_url.rstrip('/')}/api/v1/log/entries?logIndex={log_index}"
    return log_index, entry_url


def _canonical_receipt_payload(
    *,
    anchor_id: str,
    cross_anchor_hash: str,
    anchored_at: str,
    participants: list[dict[str, str]],
    rekor_log_index: int | None,
    rekor_url: str | None,
    federation_public_key_pem: str,
) -> bytes:
    """Exact same canonical form the client recomputes — protocol seam.

    Mirrors ``bijotel.federation.types._canonical_receipt_payload``.
    Sorted-key compact JSON, everything except the signature itself.
    """
    payload = {
        "anchor_id": anchor_id,
        "anchored_at": anchored_at,
        "cross_anchor_hash": cross_anchor_hash,
        "federation_public_key_pem": federation_public_key_pem,
        "participating_operators": participants,
        "rekor_log_index": rekor_log_index,
        "rekor_url": rekor_url,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
