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
import tempfile
from pathlib import Path
from typing import Annotated, Any

from bijotel.federation import CrossAnchorReceipt, verify_cross_anchor_receipt
from bijotel.processors.export import verify_export
from fastapi import Body, FastAPI, Header, HTTPException, status

from bijotel_federation import __version__, anchors, auth, db
from bijotel_federation.settings import Settings, get_settings


def _verify_submitted_export(
    payload: dict[str, Any], operator_public_key_pem: str
) -> tuple[bool, str | None]:
    """Cryptographically verify a submitted ``bijotel-chain-v2`` export
    against the operator's REGISTERED Ed25519 public key (auditor mode).

    The ISSUE-1 fix: the federation only witnesses (and Rekor-anchors) chain
    heads it has verified are authentically signed by the registering
    operator — not whatever an authenticated caller pastes in. Returns
    ``(ok, reason)``.
    """
    with tempfile.TemporaryDirectory() as d:
        export_path = Path(d) / "export.json"
        key_path = Path(d) / "operator.pem"
        export_path.write_text(json.dumps(payload), encoding="utf-8")
        key_path.write_text(operator_public_key_pem, encoding="utf-8")
        return verify_export(str(export_path), public_key_path=str(key_path))


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

        Auth: a self-signed bearer token ``operator_id.nonce.sig`` verified
        against the registered Ed25519 key, with the nonce consumed one-shot
        to blunt replay (ISSUE-2). The submitted export is then
        cryptographically verified against the operator's registered key
        before its head is witnessed (ISSUE-1); the body is bounded (ISSUE-17).
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
        # ISSUE-2: one-shot nonce — reject a replayed bearer token.
        if not auth.consume_submit_nonce(nonce):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="bearer token replay detected (nonce already used)",
            )

        entries = payload.get("entries", [])
        if not isinstance(entries, list) or not entries:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="entries[] required and must be non-empty",
            )
        # ISSUE-17: bound the work before verifying/storing.
        if len(entries) > settings.max_entry_count:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"too many entries ({len(entries)} > {settings.max_entry_count})",
            )
        body_json = json.dumps(payload, separators=(",", ":"))
        if len(body_json.encode("utf-8")) > settings.max_submission_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="submission body too large",
            )

        # ISSUE-1: verify the signed export against the operator's REGISTERED
        # key before witnessing its head — never trust the submitter blindly.
        ok, reason = _verify_submitted_export(payload, operator["public_key_pem"])
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"export verification failed: {reason}",
            )

        first_seq = entries[0].get("seq", 0)
        last_seq = entries[-1].get("seq", 0)
        chain_head_signature = entries[-1].get("hmac_hash", "0" * 64)
        submission_id = "sub_" + secrets.token_hex(8)

        record = db.submission_create(
            settings.db_path,
            submission_id=submission_id,
            operator_id=op_id,
            signed_export_json=body_json,
            entry_count=len(entries),
            first_seq=first_seq,
            last_seq=last_seq,
            chain_head_signature=chain_head_signature,
            continuity_verified=True,  # justified: export verified above
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

        # ISSUE-9: verify the federation's Ed25519 signature, not just the
        # hash recompute. Reuse the hardened client verifier, bound to the
        # federation's own public key — so an edited participant list (even
        # with a recomputed hash) fails on the signature.
        receipt = CrossAnchorReceipt(
            anchor_id=record["anchor_id"],
            cross_anchor_hash=record["cross_anchor_hash"],
            participating_operators=record["participating_operators"],
            anchored_at=record["anchored_at"],
            rekor_log_index=record["rekor_log_index"],
            rekor_url=record["rekor_url"],
            federation_signature=record["federation_signature"],
            federation_public_key_pem=settings.public_key_pem,
        )
        result = verify_cross_anchor_receipt(
            receipt,
            federation_public_key_pem=settings.public_key_pem.encode("ascii"),
        )
        return {
            "anchor_id": anchor_id,
            "valid": result["valid"],
            "cross_anchor_hash": record["cross_anchor_hash"],
            "checks": result["checks"],
            "reason": result["reason"],
            "rekor_log_index": record["rekor_log_index"],
        }

    # ------------------------------------------------------------------
    # Maintenance — manual trigger of the cross-anchor builder
    # ------------------------------------------------------------------

    @app.post("/_internal/build-anchor")
    def trigger_anchor_build(
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, Any]:
        """Manual cross-anchor trigger (cron). ISSUE-10: admin-token gated —
        no longer an unauthenticated state-mutating endpoint."""
        auth.require_admin(authorization, settings.admin_token)
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
