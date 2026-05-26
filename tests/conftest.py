"""Test fixtures — fresh DB + federation key per test."""

from __future__ import annotations

from pathlib import Path

import pytest
from bijotel.crypto.ed25519 import generate_keypair
from fastapi.testclient import TestClient

from bijotel_federation.main import create_app
from bijotel_federation.settings import Settings


@pytest.fixture()
def federation_keys() -> tuple[bytes, bytes]:
    """One Ed25519 keypair for the federation operator under test."""
    return generate_keypair()


@pytest.fixture()
def settings(tmp_path: Path, federation_keys: tuple[bytes, bytes]) -> Settings:
    priv, pub = federation_keys
    return Settings(
        db_path=str(tmp_path / "federation.db"),
        private_key_pem=priv.decode("ascii"),
        public_key_pem=pub.decode("ascii"),
        rekor_url="",  # skip Rekor in tests
        anchor_interval_seconds=60,
        min_participants=2,
    )


@pytest.fixture()
def client(settings: Settings) -> TestClient:
    app = create_app(settings)
    return TestClient(app)


@pytest.fixture()
def operator_keys() -> tuple[bytes, bytes]:
    """A second Ed25519 keypair, used by a test client acting as an
    operator registering against the federation."""
    return generate_keypair()


@pytest.fixture()
def second_operator_keys() -> tuple[bytes, bytes]:
    return generate_keypair()
