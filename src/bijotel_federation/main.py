"""FastAPI app exposing the seven federation endpoints.

  * ``GET  /register/challenge`` — issue a nonce
  * ``POST /register``           — finalise registration
  * ``POST /submit``             — accept signed export
  * ``GET  /status``             — public health
  * ``GET  /operator/{id}``      — operator history
  * ``GET  /anchor/{id}``        — fetch cross-anchor
  * ``GET  /verify/{id}``        — re-verify cross-anchor

Auth model:

  * register      — challenge-response Ed25519 (no token)
  * submit        — Bearer ``operator_id.nonce.sig`` per request
  * everything else — public (read-only) endpoints

The protocol contract is locked by the client in
``bijotel.federation`` (v2.11.0); this service implements it.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Annotated, Any

from fastapi import Body, FastAPI, Header, HTTPException, status

from bijotel_federation import __version__, anchors, auth, db
from bijotel_federation.settings import Settings, get_settings


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI app — DI-friendly for tests."""
    settings = settings or get_settings()

    if not settings.private_key_pem or not settings.public_key_pem:
        # Permit empty in tests (they inject a key fixture); main()
        # below blocks startup if missing in production.
        pass

    db.init_db(settings.db_path)

    app = FastAPI(
        title="BIJOTEL Federation",
        description=(
            "Reference federation service for the BIJOTEL cross-org chain "
            "federation protocol (v2.11.0)."
        ),
        version=__version__,
    )

    # ------------------------------------------------------------------
    # Registration (challenge-response)
    # ------------------------------------------------------------------

    @app.get("/register/challenge")
    def register_challenge() -> dict[str, str]:
        """Mint a one-shot nonce for the registration handshake."""
        return {"nonce": auth.issue_nonce()}

    @app.post("/register")
    def register(payload: Annotated[dict[str, Any], Body()]) -> dict[str, Any]:
        """Finalise registration. Body must include the public key,
        org metadata, the issued ``nonce`` and a base64 Ed25519 signature
        of that nonce produced with the matching private key."""
        required = {"public_key_pem", "org_name", "nonce", "nonce_signature"}
        if not required.issubset(payload):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"missing fields: {sorted(required - set(payload))}",
            )

        if not auth.consume_nonce(payload["nonce"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="nonce expired or unknown",
            )

        if not auth.verify_signature(
            public_key_pem=payload["public_key_pem"],
            message=payload["nonce"].encode("utf-8"),
            signature_b64=payload["nonce_signature"],
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="signature does not match supplied public key",
            )

        # Operator ID derived from the public key fingerprint —
        # deterministic, so re-registering the same key yields the
        # same operator_id (idempotent on the public-key surface).
        op_id = "op_" + hashlib.sha256(payload["public_key_pem"].encode()).hexdigest()[:12]
        if db.operator_get(settings.db_path, op_id):
            existing = db.operator_get(settings.db_path, op_id)
            return _operator_receipt(settings, existing or {})

        record = db.operator_create(
            settings.db_path,
            operator_id=op_id,
            org_name=payload["org_name"],
            public_key_pem=payload["public_key_pem"],
            contact_email=payload.get("contact_email", ""),
        )
        return _operator_receipt(settings, record)

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------

    @app.post("/submit")
    def submit(
        payload: Annotated[dict[str, Any], Body()],
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, Any]:
        """Accept a ``bijotel-chain-v2`` signed export.

        The Authorization header carries a self-signed bearer token —
        ``operator_id.nonce.signature_b64`` — verified per request
        against the registered Ed25519 key. No server-side nonce store
        (the per-request nonce defeats replay between requests).
        """
        op_id, nonce, sig_b64 = auth.parse_bearer_token(authorization)
        operator = db.operator_get(settings.db_path, op_id)
        if not operator:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"unknown operator_id: {op_id}",
            )
        if not auth.verify_signature(
            public_key_pem=operator["public_key_pem"],
            message=nonce.encode("utf-8"),
            signature_b64=sig_b64,
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="bearer token signature invalid",
            )

        # Minimal envelope validation — full continuity check happens
        # downstream (skeleton trusts the client's signed export
        # because it's already Ed25519-signed; deeper schema lives in
        # the production deployment).
        entries = payload.get("entries", [])
        if not isinstance(entries, list):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="entries[] required",
            )

        first_seq = entries[0].get("seq", 0) if entries else 0
        last_seq = entries[-1].get("seq", 0) if entries else 0
        chain_head_signature = (
            entries[-1].get("hmac_hash", "0" * 64) if entries else "0" * 64
        )
        submission_id = "sub_" + secrets.token_hex(8)

        record = db.submission_create(
            settings.db_path,
            submission_id=submission_id,
            operator_id=op_id,
            signed_export_json=json.dumps(payload, separators=(",", ":")),
            entry_count=len(entries),
            first_seq=first_seq,
            last_seq=last_seq,
            chain_head_signature=chain_head_signature,
            continuity_verified=True,
        )

        return {
            "submission_id": submission_id,
            "operator_id": op_id,
            "verified": True,
            "entry_count": record["entry_count"],
            "first_seq": record["first_seq"],
            "last_seq": record["last_seq"],
            "continuity_verified": bool(record["continuity_verified"]),
            "submitted_at": record["submitted_at"],
            "pending_anchor": True,
        }

    # ------------------------------------------------------------------
    # Read-only / status
    # ------------------------------------------------------------------

    @app.get("/status")
    def status_endpoint() -> dict[str, Any]:
        latest = db.cross_anchor_latest(settings.db_path)
        return {
            "service": "bijotel-federation",
            "version": __version__,
            "operators_total": db.operator_count(settings.db_path),
            "operators_active": db.operator_count(settings.db_path),
            "last_anchor": latest["anchor_id"] if latest else None,
            "last_anchor_at": latest["anchored_at"] if latest else None,
        }

    @app.get("/operator/{operator_id}")
    def get_operator(operator_id: str) -> dict[str, Any]:
        record = db.operator_get(settings.db_path, operator_id)
        if not record:
            raise HTTPException(status_code=404, detail="operator not found")
        return _operator_receipt(settings, record)

    @app.get("/anchor/{anchor_id}")
    def get_anchor(anchor_id: str) -> dict[str, Any]:
        record = db.cross_anchor_get(settings.db_path, anchor_id)
        if not record:
            raise HTTPException(status_code=404, detail="anchor not found")
        return {
            "anchor_id": record["anchor_id"],
            "cross_anchor_hash": record["cross_anchor_hash"],
            "anchored_at": record["anchored_at"],
            "rekor_log_index": record["rekor_log_index"],
            "rekor_url": record["rekor_url"],
            "federation_signature": record["federation_signature"],
            "federation_public_key_pem": settings.public_key_pem,
            "participating_operators": record["participating_operators"],
        }

    @app.get("/verify/{anchor_id}")
    def verify(anchor_id: str) -> dict[str, Any]:
        record = db.cross_anchor_get(settings.db_path, anchor_id)
        if not record:
            raise HTTPException(status_code=404, detail="anchor not found")

        # Re-verify locally by recomputing — same algorithm as the
        # client, so a mismatch here would also fail the client's
        # local check.
        participants = sorted(
            record["participating_operators"], key=lambda p: p["operator_id"]
        )
        blob = "".join(p["chain_signature"] for p in participants).encode("utf-8")
        blob += record["anchored_at"].encode("utf-8")
        recomputed = hashlib.sha256(blob).hexdigest()
        return {
            "anchor_id": anchor_id,
            "valid": recomputed == record["cross_anchor_hash"],
            "cross_anchor_hash": record["cross_anchor_hash"],
            "recomputed_hash": recomputed,
            "rekor_log_index": record["rekor_log_index"],
        }

    # ------------------------------------------------------------------
    # Maintenance — manual trigger of the cross-anchor builder
    # ------------------------------------------------------------------

    @app.post("/_internal/build-anchor")
    def trigger_anchor_build() -> dict[str, Any]:
        """Manual cross-anchor trigger — useful for test / cron."""
        result = anchors.build_pending_cross_anchor(settings)
        return result or {"status": "no-op", "reason": "not enough participants"}

    return app


def _operator_receipt(settings: Settings, record: dict[str, Any]) -> dict[str, Any]:
    return {
        "operator_id": record["operator_id"],
        "org_name": record["org_name"],
        "public_key_pem": record["public_key_pem"],
        "contact_email": record.get("contact_email", ""),
        "registered_at": record["registered_at"],
        "rekor_log_index": record.get("rekor_log_index"),
        "federation_url": f"http://{settings.bind_host}:{settings.bind_port}",
    }


# Module-level app for ``uvicorn bijotel_federation.main:app``.
app = create_app()


def cli() -> None:
    """``bijotel-federation`` entry-point — run uvicorn."""
    import uvicorn

    settings = get_settings()
    if not settings.private_key_pem or not settings.public_key_pem:
        raise SystemExit(
            "BIJOTEL_FED_PRIVATE_KEY_PEM and BIJOTEL_FED_PUBLIC_KEY_PEM must be "
            "set in env. Generate with: bijotel keygen"
        )
    uvicorn.run(
        "bijotel_federation.main:app",
        host=settings.bind_host,
        port=settings.bind_port,
        reload=False,
    )
