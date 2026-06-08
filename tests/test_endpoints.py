"""Integration tests for every federation endpoint.

These exercise the FastAPI app end-to-end against a fresh SQLite
database, with real Ed25519 challenge-response + Bearer-token auth.
The BIJOTEL client (``FederationClient``) is **not** mocked — it is
imported and pointed at the in-memory test app via ``httpx``, so the
client/server contract is exercised by both sides.
"""

from __future__ import annotations

import base64

from bijotel.crypto.ed25519 import sign as ed25519_sign


def _register_operator(client, priv: bytes, pub: bytes, org: str = "OrgA") -> str:
    """Helper — do a full challenge-response register call.
    Returns the assigned operator_id."""
    nonce = client.get("/register/challenge").json()["nonce"]
    sig = ed25519_sign(nonce.encode("utf-8"), priv)
    resp = client.post(
        "/register",
        json={
            "public_key_pem": pub.decode("ascii"),
            "org_name": org,
            "contact_email": f"{org.lower()}@example.com",
            "nonce": nonce,
            "nonce_signature": base64.b64encode(sig).decode("ascii"),
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["operator_id"]


def _bearer(operator_id: str, priv: bytes) -> str:
    """Build a self-signed bearer token."""
    import secrets

    nonce = secrets.token_hex(16)
    sig = base64.b64encode(ed25519_sign(nonce.encode("utf-8"), priv)).decode("ascii")
    return f"Bearer {operator_id}.{nonce}.{sig}"


_ADMIN = {"Authorization": "Bearer test-admin-token"}


def _signed_export(tmp_path, op_priv: bytes, label: str, n: int = 2) -> dict:
    """Build a real ``bijotel-chain-v2`` export signed by the operator's key,
    so the federation's ``verify_export(operator_pubkey)`` accepts it (ISSUE-1).
    """
    import json as _json

    from bijotel.processors import HmacChainSpanProcessor, export_chain
    from opentelemetry.sdk.trace import TracerProvider

    secret = b"opsecret_32_bytes_for_hmac_xxxxx"[:32]
    chain_db = tmp_path / f"op_{label}.db"
    provider = TracerProvider()
    provider.add_span_processor(
        HmacChainSpanProcessor(db_path=chain_db, secret_key=secret)
    )
    tracer = provider.get_tracer(f"op-{label}")
    for i in range(n):
        with tracer.start_as_current_span(f"call-{label}-{i}") as s:
            s.set_attribute("gen_ai.request.model", "claude-haiku-4-5")
            s.set_attribute("gen_ai.usage.input_tokens", 1)
            s.set_attribute("gen_ai.usage.output_tokens", 1)
    provider.shutdown()
    kp = tmp_path / f"op_{label}_priv.pem"
    kp.write_bytes(op_priv)
    out = tmp_path / f"op_{label}_export.json"
    export_chain(str(chain_db), str(out), secret, sign_key_path=str(kp))
    return _json.loads(out.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------
# Status / health
# ---------------------------------------------------------------------


def test_status_unauthenticated(client) -> None:
    r = client.get("/status")
    assert r.status_code == 200
    data = r.json()
    assert data["service"] == "bijotel-federation"
    assert data["operators_total"] == 0
    assert data["last_anchor"] is None


# ---------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------


def test_register_challenge_response_happy_path(client, operator_keys) -> None:
    priv, pub = operator_keys
    op_id = _register_operator(client, priv, pub, "Acme")
    assert op_id.startswith("op_")

    # Re-registering the same key is idempotent.
    op_id_2 = _register_operator(client, priv, pub, "Acme")
    assert op_id == op_id_2


def test_register_rejects_unknown_nonce(client, operator_keys) -> None:
    priv, pub = operator_keys
    sig = base64.b64encode(ed25519_sign(b"deadbeef", priv)).decode("ascii")
    r = client.post(
        "/register",
        json={
            "public_key_pem": pub.decode("ascii"),
            "org_name": "Spoofer",
            "nonce": "deadbeef",  # never issued
            "nonce_signature": sig,
        },
    )
    assert r.status_code == 401
    assert "nonce" in r.json()["detail"]


def test_register_rejects_bad_signature(client, operator_keys, second_operator_keys) -> None:
    """Signing with the wrong key for the supplied public key fails."""
    _priv_a, pub_a = operator_keys
    priv_b, _pub_b = second_operator_keys

    nonce = client.get("/register/challenge").json()["nonce"]
    # Sign with key B but claim public key A.
    sig = base64.b64encode(ed25519_sign(nonce.encode("utf-8"), priv_b)).decode("ascii")
    r = client.post(
        "/register",
        json={
            "public_key_pem": pub_a.decode("ascii"),
            "org_name": "Bad",
            "nonce": nonce,
            "nonce_signature": sig,
        },
    )
    assert r.status_code == 401


def test_register_400_on_missing_fields(client) -> None:
    r = client.post("/register", json={"org_name": "x"})
    assert r.status_code == 400
    assert "missing fields" in r.json()["detail"]


# ---------------------------------------------------------------------
# Submission
# ---------------------------------------------------------------------


def test_submit_happy_path(client, operator_keys, tmp_path) -> None:
    priv, pub = operator_keys
    op_id = _register_operator(client, priv, pub)
    export = _signed_export(tmp_path, priv, "happy", n=3)
    r = client.post(
        "/submit",
        json=export,
        headers={"Authorization": _bearer(op_id, priv)},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["verified"] is True
    assert data["continuity_verified"] is True
    assert data["entry_count"] == 3
    assert data["pending_anchor"] is True


def test_submit_rejects_unsigned_export(client, operator_keys) -> None:
    """ISSUE-1: a plain entries[] body (no Ed25519 signature) is no longer
    witnessed — the federation requires a verifiable signed export."""
    priv, pub = operator_keys
    op_id = _register_operator(client, priv, pub)
    r = client.post(
        "/submit",
        json={"entries": [{"seq": 1, "hmac_hash": "aa" * 32}]},
        headers={"Authorization": _bearer(op_id, priv)},
    )
    assert r.status_code == 422, r.text
    assert "export verification failed" in r.json()["detail"]


def test_submit_rejects_export_signed_by_wrong_key(
    client, operator_keys, second_operator_keys, tmp_path
) -> None:
    """ISSUE-1: an export signed by a DIFFERENT key than the operator
    registered is rejected (embedded pubkey != registered pubkey)."""
    priv_a, pub_a = operator_keys
    priv_b, _pub_b = second_operator_keys
    op_id = _register_operator(client, priv_a, pub_a)
    export = _signed_export(tmp_path, priv_b, "wrongkey")  # signed by B
    r = client.post(
        "/submit",
        json=export,
        headers={"Authorization": _bearer(op_id, priv_a)},  # authed as A
    )
    assert r.status_code == 422, r.text


def test_submit_rejects_replayed_bearer(client, operator_keys, tmp_path) -> None:
    """ISSUE-2: replaying the same bearer token (same nonce) is rejected."""
    priv, pub = operator_keys
    op_id = _register_operator(client, priv, pub)
    export = _signed_export(tmp_path, priv, "replay")
    token = _bearer(op_id, priv)
    r1 = client.post("/submit", json=export, headers={"Authorization": token})
    assert r1.status_code == 200, r1.text
    r2 = client.post("/submit", json=export, headers={"Authorization": token})
    assert r2.status_code == 401
    assert "replay" in r2.json()["detail"]


def test_submit_rejects_too_many_entries(client, operator_keys) -> None:
    """ISSUE-17: an over-count submission is rejected before verify/store."""
    priv, pub = operator_keys
    op_id = _register_operator(client, priv, pub)
    body = {"entries": [{"seq": i, "hmac_hash": "aa" * 32} for i in range(10_001)]}
    r = client.post(
        "/submit", json=body, headers={"Authorization": _bearer(op_id, priv)}
    )
    assert r.status_code == 413


def test_submit_rejects_missing_bearer(client, operator_keys) -> None:
    r = client.post("/submit", json={"entries": []})
    assert r.status_code == 401


def test_submit_rejects_unknown_operator(client, operator_keys) -> None:
    priv, _pub = operator_keys
    r = client.post(
        "/submit",
        json={"entries": []},
        headers={"Authorization": _bearer("op_ghost123", priv)},
    )
    assert r.status_code == 401


def test_submit_rejects_token_signed_with_wrong_key(
    client, operator_keys, second_operator_keys
) -> None:
    priv_a, pub_a = operator_keys
    priv_b, _ = second_operator_keys
    op_id = _register_operator(client, priv_a, pub_a)
    # Bearer signed with the wrong key.
    r = client.post(
        "/submit",
        json={"entries": []},
        headers={"Authorization": _bearer(op_id, priv_b)},
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------
# Operator / anchor read
# ---------------------------------------------------------------------


def test_get_operator_404(client) -> None:
    r = client.get("/operator/op_nope")
    assert r.status_code == 404


def test_get_operator_happy_path(client, operator_keys) -> None:
    priv, pub = operator_keys
    op_id = _register_operator(client, priv, pub, "OrgA")
    r = client.get(f"/operator/{op_id}")
    assert r.status_code == 200
    assert r.json()["org_name"] == "OrgA"


# ---------------------------------------------------------------------
# Cross-anchor builder + verify
# ---------------------------------------------------------------------


def test_anchor_build_requires_admin_token(client) -> None:
    """ISSUE-10: the build-anchor trigger is no longer unauthenticated."""
    r = client.post("/_internal/build-anchor")
    assert r.status_code == 401


def test_anchor_build_requires_min_participants(
    client, operator_keys, tmp_path
) -> None:
    priv, pub = operator_keys
    op_id = _register_operator(client, priv, pub)
    client.post(
        "/submit",
        json=_signed_export(tmp_path, priv, "minp"),
        headers={"Authorization": _bearer(op_id, priv)},
    )
    # Only 1 operator submitted; min_participants=2 → no-op.
    r = client.post("/_internal/build-anchor", headers=_ADMIN)
    assert r.json()["status"] == "no-op"


def test_anchor_build_with_two_operators(
    client, operator_keys, second_operator_keys, tmp_path
) -> None:
    priv_a, pub_a = operator_keys
    priv_b, pub_b = second_operator_keys
    op_a = _register_operator(client, priv_a, pub_a, "OrgA")
    op_b = _register_operator(client, priv_b, pub_b, "OrgB")
    client.post(
        "/submit",
        json=_signed_export(tmp_path, priv_a, "a"),
        headers={"Authorization": _bearer(op_a, priv_a)},
    )
    client.post(
        "/submit",
        json=_signed_export(tmp_path, priv_b, "b"),
        headers={"Authorization": _bearer(op_b, priv_b)},
    )

    r = client.post("/_internal/build-anchor", headers=_ADMIN)
    data = r.json()
    assert data["anchor_id"].startswith("anchor_")
    assert int(data["participant_count"]) == 2

    # Fetch it and verify.
    anchor_id = data["anchor_id"]
    r2 = client.get(f"/anchor/{anchor_id}")
    assert r2.status_code == 200
    receipt = r2.json()
    assert receipt["cross_anchor_hash"] == data["cross_anchor_hash"]
    assert len(receipt["participating_operators"]) == 2

    # ISSUE-9: server-side verify checks the signature, not just the hash.
    r3 = client.get(f"/verify/{anchor_id}")
    assert r3.status_code == 200
    body = r3.json()
    assert body["valid"] is True
    assert body["checks"]["signature_verified"] is True


def test_verify_detects_tampered_participant(
    client, operator_keys, second_operator_keys, tmp_path
) -> None:
    """ISSUE-9: editing a participant signature in the DB and recomputing the
    stored hash still fails /verify — the federation Ed25519 signature no
    longer matches (the old /verify only re-hashed and would have passed)."""
    import hashlib as _h
    import sqlite3

    priv_a, pub_a = operator_keys
    priv_b, pub_b = second_operator_keys
    op_a = _register_operator(client, priv_a, pub_a, "OrgA")
    op_b = _register_operator(client, priv_b, pub_b, "OrgB")
    client.post("/submit", json=_signed_export(tmp_path, priv_a, "ta"),
                headers={"Authorization": _bearer(op_a, priv_a)})
    client.post("/submit", json=_signed_export(tmp_path, priv_b, "tb"),
                headers={"Authorization": _bearer(op_b, priv_b)})
    anchor_id = client.post(
        "/_internal/build-anchor", headers=_ADMIN
    ).json()["anchor_id"]
    assert client.get(f"/verify/{anchor_id}").json()["valid"] is True

    db_path = str(tmp_path / "federation.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE anchor_participants SET chain_signature=? "
        "WHERE anchor_id=? AND operator_id=?",
        ("ff" * 32, anchor_id, op_a),
    )
    anchored_at = conn.execute(
        "SELECT anchored_at FROM cross_anchors WHERE anchor_id=?", (anchor_id,)
    ).fetchone()[0]
    parts = conn.execute(
        "SELECT chain_signature FROM anchor_participants WHERE anchor_id=? "
        "ORDER BY operator_id",
        (anchor_id,),
    ).fetchall()
    blob = "".join(p[0] for p in parts).encode() + anchored_at.encode()
    conn.execute(
        "UPDATE cross_anchors SET cross_anchor_hash=? WHERE anchor_id=?",
        (_h.sha256(blob).hexdigest(), anchor_id),
    )
    conn.commit()
    conn.close()

    body = client.get(f"/verify/{anchor_id}").json()
    assert body["valid"] is False
    assert body["checks"]["cross_anchor_hash_recomputed"] is True
    assert body["checks"]["signature_verified"] is False


def test_anchor_receipt_verifies_with_bijotel_client(
    client, operator_keys, second_operator_keys, federation_keys, tmp_path
) -> None:
    """End-to-end: the federation issues a receipt the BIJOTEL client's local
    verifier accepts when bound to the federation's out-of-band public key
    (ISSUE-3 contract). This is the protocol seam."""
    from bijotel.federation import CrossAnchorReceipt, verify_cross_anchor_receipt

    _fed_priv, fed_pub = federation_keys
    priv_a, pub_a = operator_keys
    priv_b, pub_b = second_operator_keys
    op_a = _register_operator(client, priv_a, pub_a)
    op_b = _register_operator(client, priv_b, pub_b)
    client.post("/submit", json=_signed_export(tmp_path, priv_a, "sa"),
                headers={"Authorization": _bearer(op_a, priv_a)})
    client.post("/submit", json=_signed_export(tmp_path, priv_b, "sb"),
                headers={"Authorization": _bearer(op_b, priv_b)})
    anchor_id = client.post(
        "/_internal/build-anchor", headers=_ADMIN
    ).json()["anchor_id"]
    receipt_data = client.get(f"/anchor/{anchor_id}").json()

    receipt = CrossAnchorReceipt(
        anchor_id=receipt_data["anchor_id"],
        cross_anchor_hash=receipt_data["cross_anchor_hash"],
        participating_operators=receipt_data["participating_operators"],
        anchored_at=receipt_data["anchored_at"],
        rekor_log_index=receipt_data.get("rekor_log_index"),
        rekor_url=receipt_data.get("rekor_url"),
        federation_signature=receipt_data["federation_signature"],
        federation_public_key_pem=receipt_data["federation_public_key_pem"],
    )
    # Bound to the federation's out-of-band public key (ISSUE-3 contract).
    result = verify_cross_anchor_receipt(receipt, federation_public_key_pem=fed_pub)
    assert result["valid"], result
    assert result["checks"]["signature_verified"] is True
    assert result["checks"]["cross_anchor_hash_recomputed"] is True
    assert result["checks"]["bound"] is True
