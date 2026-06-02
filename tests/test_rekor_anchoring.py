"""Rekor anchoring of cross-anchors (v0.2.0).

Unit tests drive a real 2-operator cross-anchor through the FastAPI app with
``RekorClient.upload`` mocked, and assert the cross-anchor record carries the
Rekor ``logIndex`` + URL — proving ``_maybe_anchor_in_rekor`` wired the real
ECDSA P-256 signing path (not the old no-op shim).

The live test (env-gated ``BIJOTEL_FED_REKOR_LIVE=1``) anchors a real
cross-anchor hash in the public Sigstore Rekor and asserts a real ``logIndex``
comes back — the M2 "prove it against the real thing" guard that the v0.1.0
shim never had (and that the BIJOTEL 2.13.2 fix made possible).
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from pathlib import Path

import pytest
from bijotel.crypto.ecdsa_p256 import generate_keypair as ecdsa_generate_keypair
from bijotel.crypto.ed25519 import generate_keypair
from bijotel.crypto.ed25519 import sign as ed25519_sign
from fastapi.testclient import TestClient

from bijotel_federation.main import create_app
from bijotel_federation.settings import Settings


def _register(client: TestClient, priv: bytes, pub: bytes, org: str) -> str:
    nonce = client.get("/register/challenge").json()["nonce"]
    sig = base64.b64encode(ed25519_sign(nonce.encode("utf-8"), priv)).decode("ascii")
    r = client.post(
        "/register",
        json={
            "public_key_pem": pub.decode("ascii"),
            "org_name": org,
            "nonce": nonce,
            "nonce_signature": sig,
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["operator_id"]


def _bearer(op_id: str, priv: bytes) -> str:
    nonce = secrets.token_hex(16)
    sig = base64.b64encode(ed25519_sign(nonce.encode("utf-8"), priv)).decode("ascii")
    return f"Bearer {op_id}.{nonce}.{sig}"


def _rekor_settings(tmp_path: Path, *, rekor_url: str, with_ecdsa_key: bool = True) -> Settings:
    fed_priv, fed_pub = generate_keypair()  # Ed25519 — receipt signing (unchanged)
    ec_priv, _ec_pub = ecdsa_generate_keypair()  # ECDSA P-256 — Rekor only
    return Settings(
        db_path=str(tmp_path / "federation.db"),
        private_key_pem=fed_priv.decode("ascii"),
        public_key_pem=fed_pub.decode("ascii"),
        rekor_url=rekor_url,
        rekor_private_key_pem=ec_priv.decode("ascii") if with_ecdsa_key else "",
        anchor_interval_seconds=60,
        min_participants=2,
    )


def _seed_two_submissions(client: TestClient) -> None:
    pa, ua = generate_keypair()
    pb, ub = generate_keypair()
    op_a = _register(client, pa, ua, "OrgA")
    op_b = _register(client, pb, ub, "OrgB")
    client.post(
        "/submit",
        json={"entries": [{"seq": 1, "hmac_hash": "aa" * 32}]},
        headers={"Authorization": _bearer(op_a, pa)},
    )
    client.post(
        "/submit",
        json={"entries": [{"seq": 1, "hmac_hash": "bb" * 32}]},
        headers={"Authorization": _bearer(op_b, pb)},
    )


def test_cross_anchor_records_rekor_logindex(tmp_path: Path, monkeypatch) -> None:
    """Rekor enabled + ECDSA key → the cross-anchor stores logIndex + URL.

    Uploads are mocked, but the ECDSA signing + SHA-256 digest path is real.
    """
    from bijotel.anchoring import rekor as rekor_mod

    fake = {"uuid-abc": {"logIndex": 987654, "integratedTime": 1234567890}}
    captured: dict[str, str] = {}

    def fake_upload(self, *, data_hash_hex, signature_b64, public_key_pem_b64):
        captured["data_hash_hex"] = data_hash_hex
        captured["signature_b64"] = signature_b64
        captured["public_key_pem_b64"] = public_key_pem_b64
        return fake

    monkeypatch.setattr(rekor_mod.RekorClient, "upload", fake_upload)

    settings = _rekor_settings(tmp_path, rekor_url="https://rekor.example")
    client = TestClient(create_app(settings))
    _seed_two_submissions(client)

    data = client.post("/_internal/build-anchor").json()
    assert int(data["participant_count"]) == 2
    assert data["rekor_log_index"] == "987654"

    anchor = client.get(f"/anchor/{data['anchor_id']}").json()
    assert anchor["rekor_log_index"] == 987654
    assert "logIndex=987654" in anchor["rekor_url"]

    # ECDSA upload signed over SHA-256(cross_anchor_hash bytes) — same recipe
    # bijotel.anchoring.rekor uses, so an external auditor can re-verify.
    expected = hashlib.sha256(bytes.fromhex(data["cross_anchor_hash"])).hexdigest()
    assert captured["data_hash_hex"] == expected


def test_rekor_skipped_without_ecdsa_key(tmp_path: Path) -> None:
    """rekor_url set but no ECDSA key → anchoring is skipped, no crash, and
    the receipt is still produced (Rekor is best-effort)."""
    settings = _rekor_settings(
        tmp_path, rekor_url="https://rekor.example", with_ecdsa_key=False
    )
    client = TestClient(create_app(settings))
    _seed_two_submissions(client)

    data = client.post("/_internal/build-anchor").json()
    assert int(data["participant_count"]) == 2
    assert data["rekor_log_index"] == ""  # no anchor recorded
    anchor = client.get(f"/anchor/{data['anchor_id']}").json()
    assert anchor["rekor_log_index"] is None


def test_rekor_failure_is_non_fatal(tmp_path: Path, monkeypatch) -> None:
    """A Rekor upload error must not break cross-anchor building."""
    from bijotel.anchoring import rekor as rekor_mod

    def boom(self, **_kw):
        raise RuntimeError("Rekor upload HTTP 500: backend on fire")

    monkeypatch.setattr(rekor_mod.RekorClient, "upload", boom)

    settings = _rekor_settings(tmp_path, rekor_url="https://rekor.example")
    client = TestClient(create_app(settings))
    _seed_two_submissions(client)

    data = client.post("/_internal/build-anchor").json()
    assert int(data["participant_count"]) == 2  # anchor still built
    assert data["rekor_log_index"] == ""  # but no Rekor index
    # Server-side verify still passes (Ed25519 receipt is independent of Rekor).
    assert client.get(f"/verify/{data['anchor_id']}").json()["valid"] is True


@pytest.mark.skipif(
    os.environ.get("BIJOTEL_FED_REKOR_LIVE") != "1",
    reason="set BIJOTEL_FED_REKOR_LIVE=1 to hit the public Sigstore Rekor",
)
def test_live_rekor_cross_anchor(tmp_path: Path) -> None:
    """LIVE: anchor a real cross-anchor in public Rekor; expect a real logIndex."""
    settings = _rekor_settings(tmp_path, rekor_url="https://rekor.sigstore.dev")
    client = TestClient(create_app(settings))
    _seed_two_submissions(client)

    data = client.post("/_internal/build-anchor").json()
    assert data["rekor_log_index"], "no logIndex returned from live Rekor"
    assert int(data["rekor_log_index"]) > 0
    anchor = client.get(f"/anchor/{data['anchor_id']}").json()
    assert anchor["rekor_log_index"] and anchor["rekor_log_index"] > 0
    assert "logIndex=" in (anchor["rekor_url"] or "")
