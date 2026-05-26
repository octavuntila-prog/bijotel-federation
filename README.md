# bijotel-federation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#status)
[![BIJOTEL Client](https://img.shields.io/badge/client-bijotel%E2%89%A52.11.0-blue.svg)](https://github.com/octavuntila-prog/BIJOTEL)

Reference federation service for the BIJOTEL chain-federation
protocol — the Certificate-Transparency analogue for tamper-evident
LLM audit chains.

This is the **service** side. The matching **client** ships in the
[`bijotel`](https://github.com/octavuntila-prog/BIJOTEL) package as
`bijotel federation register/submit/verify/status`.

## Status

**Alpha, v0.1.0 (2026-05-26).** Working FastAPI service backed by
SQLite, implementing the seven endpoints in
[`docs/design/cross-org-federation.md`](https://github.com/octavuntila-prog/BIJOTEL/blob/main/docs/design/cross-org-federation.md).
Skeleton-quality:

- ✓ Challenge-response Ed25519 registration
- ✓ Bearer-token Ed25519 per-request auth
- ✓ Cross-anchor builder (hash recomputable by any auditor)
- ✓ End-to-end test against the BIJOTEL client (12 tests)
- ✓ Docker + docker-compose deploy
- ✗ Rekor anchoring of cross-anchors — pending the BIJOTEL v2.9
  Rekor compat-gap fix (sigstore-python wiring); structure is in
  place, current behaviour is a no-op shim
- ✗ No federation has registered any external operators yet
- ✗ No key-rotation flow (spec'd in protocol §11; arrives in v0.2)

## Protocol

See the canonical spec in BIJOTEL:
[`docs/design/cross-org-federation.md`](https://github.com/octavuntila-prog/BIJOTEL/blob/main/docs/design/cross-org-federation.md).

Endpoints exposed by this service:

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET  | `/register/challenge` | — | issue a one-shot registration nonce |
| POST | `/register`           | Ed25519 sig over nonce | finalise registration |
| POST | `/submit`             | Bearer (Ed25519) | submit a signed export |
| GET  | `/status`             | — | public health/discovery |
| GET  | `/operator/{id}`      | — | operator history summary |
| GET  | `/anchor/{id}`        | — | fetch a cross-anchor receipt |
| GET  | `/verify/{id}`        | — | re-verify a cross-anchor live |
| POST | `/_internal/build-anchor` | — | manual cross-anchor trigger (cron / test) |

## Quickstart (development)

```bash
# 1. Generate a federation keypair (uses the bijotel CLI).
pip install "bijotel[api]>=2.11.0"
bijotel keygen --out-priv fed-priv.pem --out-pub fed-pub.pem

# 2. Install + run the service.
pip install -e ".[dev]"
export BIJOTEL_FED_PRIVATE_KEY_PEM=$(cat fed-priv.pem)
export BIJOTEL_FED_PUBLIC_KEY_PEM=$(cat fed-pub.pem)
bijotel-federation                # binds 0.0.0.0:8088

# 3. From another terminal, talk to it via the BIJOTEL client.
bijotel federation status --service http://127.0.0.1:8088
```

## Quickstart (Docker)

```bash
# Provide secrets via env. docker-compose.yml refuses to start
# without BIJOTEL_FED_PRIVATE_KEY_PEM + BIJOTEL_FED_PUBLIC_KEY_PEM.
export BIJOTEL_FED_PRIVATE_KEY_PEM=$(cat fed-priv.pem)
export BIJOTEL_FED_PUBLIC_KEY_PEM=$(cat fed-pub.pem)

docker compose up -d
docker compose logs -f bijotel-federation
```

### Publishing the image to ghcr.io

The image is built and tagged at `ghcr.io/octavuntila-prog/bijotel-federation:0.1.0`
but not yet pushed (waiting on the maintainer's `write:packages` OAuth
grant). To push:

```bash
# 1. Grant write:packages scope (one-time, opens a browser).
gh auth refresh -s write:packages -h github.com

# 2. Login Docker to ghcr.io with the gh token.
gh auth token | docker login ghcr.io -u octavuntila-prog --password-stdin

# 3. Push both tags.
docker push ghcr.io/octavuntila-prog/bijotel-federation:0.1.0
docker push ghcr.io/octavuntila-prog/bijotel-federation:latest
```

## Configuration

All settings come from env vars (`.env` is also honoured):

| Var | Default | Purpose |
|---|---|---|
| `BIJOTEL_FED_DB_PATH` | `./federation.db` | SQLite database file |
| `BIJOTEL_FED_PRIVATE_KEY_PEM` | — | inline Ed25519 private key PEM |
| `BIJOTEL_FED_PUBLIC_KEY_PEM` | — | matching public key PEM |
| `BIJOTEL_FED_REKOR_URL` | `https://rekor.sigstore.dev` | empty disables |
| `BIJOTEL_FED_ANCHOR_INTERVAL_SECONDS` | `3600` | cross-anchor cadence |
| `BIJOTEL_FED_MIN_PARTICIPANTS` | `2` | minimum operators per anchor |
| `BIJOTEL_FED_BIND_HOST` | `0.0.0.0` | uvicorn bind host |
| `BIJOTEL_FED_BIND_PORT` | `8088` | uvicorn bind port |

## Trust model — what this service proves

The federation **does not** ingest or store any LLM data. It only
signs over the cryptographic identifiers operators submit
(``chain_head_signature`` per submission). Specifically:

- A registered operator's ``operator_id`` is `op_<sha256(pub)[:12]>`,
  deterministic over their public key.
- Each `cross_anchor_hash` = `sha256(sorted_chain_signatures || anchored_at)`,
  recomputable by any external auditor — the federation cannot lie
  about the participants without producing an invalid hash.
- Each anchor record carries an Ed25519 signature over the canonical
  payload. The BIJOTEL client (`bijotel federation verify`) verifies
  this **without contacting the federation**.

What the federation **cannot** lie about:

- Which operators participated in a given anchor (hash recomputable).
- That a signature was actually made by the federation key (Ed25519).

What the federation **could** lie about (this is the threat model
the protocol assumes):

- Refusing to anchor an operator (censorship). Detectable by
  operators expecting their submission to land in an anchor;
  mitigated by allowing any operator to run their own federation.
- Continuing to anchor a private chain that has been silently
  rolled back. Mitigated by Rekor anchoring of cross-anchors
  themselves (when v0.2 wires sigstore-python).

## Architecture

```text
┌────────────────────┐         ┌─────────────────────────────┐
│ Operator A         │         │ bijotel-federation          │
│ (bijotel client)   │ ────►  │  ┌───────────────────────┐  │
│   register         │         │  │ FastAPI app           │  │
│   submit           │         │  │  /register/challenge  │  │
└────────────────────┘         │  │  /register            │  │
                                │  │  /submit              │  │
┌────────────────────┐         │  │  /status              │  │
│ Operator B         │ ────►  │  │  /operator/{id}       │  │
│ (bijotel client)   │         │  │  /anchor/{id}         │  │
└────────────────────┘         │  │  /verify/{id}         │  │
                                │  └─────────┬─────────────┘  │
┌────────────────────┐         │            │                 │
│ External auditor   │ ────►  │  ┌─────────▼─────────────┐  │
│ (verify offline)   │         │  │ SQLite WAL            │  │
└────────────────────┘         │  │  operators            │  │
                                │  │  submissions          │  │
                                │  │  cross_anchors        │  │
                                │  │  anchor_participants  │  │
                                │  └─────────┬─────────────┘  │
                                │            │                 │
                                │  ┌─────────▼─────────────┐  │
                                │  │ anchors.py (cron)     │  │
                                │  │  → batch submissions  │  │
                                │  │  → sign cross-anchor  │  │
                                │  │  → (Rekor anchor)     │  │
                                │  └───────────────────────┘  │
                                └─────────────────────────────┘
                                              │
                                              ▼  (v0.2)
                                       Sigstore Rekor
```

## Development

```bash
pip install -e ".[dev]"
pytest        # 12 tests
ruff check .
```

## License

MIT. See [LICENSE](./LICENSE).
