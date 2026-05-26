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
import secrets
import time

from bijotel.crypto.ed25519 import sign as ed25519_sign

from bijotel_federation import db
from bijotel_federation.settings import Settings


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

    Returns ``(log_index, url)`` or ``(None, None)`` if disabled or
    upload failed (the federation keeps running — Rekor is a
    convenience, not a hard requirement).
    """
    if not settings.rekor_url:
        return None, None
    # NOTE (M2 honesty): the BIJOTEL Rekor library has a known
    # signature-encoding gap against the live Rekor service at v2.9
    # (see CHANGELOG). The skeleton therefore stores the *intent* to
    # anchor and the hash; live upload arrives when sigstore-python is
    # wired in. Until then this branch is a no-op shim.
    return None, None


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
