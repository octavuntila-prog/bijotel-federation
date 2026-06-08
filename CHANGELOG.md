# Changelog

All notable changes to bijotel-federation will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-06-08 — Security hardening from the BIJOTEL technical audit

Remediation of the 2026-06-08 BIJOTEL technical audit. 23 tests pass; ruff
clean. Live-deployed on the ARA federation host and verified end-to-end (two
Ed25519-signed operator submits → cross-anchor #6 in Rekor → `/verify` valid).

### Security

- **`/submit` cryptographically verifies the operator's signed export (ISSUE-1).**
  The service previously witnessed (and Rekor-anchored) any chain head an
  authenticated caller submitted, never verifying it, and hardcoded
  `continuity_verified=True`. It now runs `verify_export` against the operator's
  REGISTERED Ed25519 key (auditor mode) and sets `verified`/`continuity_verified`
  from the result — rejecting unverifiable or wrong-key exports (422). Operators
  must sign the submitted export (`bijotel export --sign-key`).
- **Submit bearer nonces are one-shot (ISSUE-2).** A server-side seen-nonce
  store rejects a replayed token within the TTL window. (Full body+timestamp
  binding needs the bijotel 2.16.0 client — tracked.)
- **`/verify` checks the federation Ed25519 signature (ISSUE-9),** not just the
  hash recompute — reusing the hardened client verifier bound to the federation
  key, so an edited participant list fails even with a recomputed hash.
- **`/_internal/build-anchor` requires an admin bearer token (ISSUE-10);** with
  no `BIJOTEL_FED_ADMIN_TOKEN` set the endpoint is disabled (fail-closed).
- **Submissions are bounded (ISSUE-17):** `max_entry_count` + `max_submission_bytes`
  reject oversized bodies before verify/store.

### Added

- Settings: `BIJOTEL_FED_ADMIN_TOKEN`, `max_entry_count`, `max_submission_bytes`.

## [0.2.0] — 2026-06-02 — Live Rekor anchoring of cross-anchors

### Added

- **Cross-anchors are now published to Sigstore Rekor.** When `rekor_url` is
  set and `BIJOTEL_FED_REKOR_PRIVATE_KEY_PEM` (an ECDSA P-256 key) is
  configured, each cross-anchor hash is signed and uploaded as a
  `hashedrekord` entry; the returned `logIndex` + entry URL are stored in the
  cross-anchor record and the signed receipt. Any auditor can re-fetch the
  entry from Rekor and confirm `sha256(cross_anchor_hash)` matches. Verified
  by a real round-trip to `rekor.sigstore.dev` (logIndex returned, fetched
  back, hash MATCH).
- `BIJOTEL_FED_REKOR_PRIVATE_KEY_PEM` setting — the ECDSA P-256 key used for
  Rekor, kept **separate** from the Ed25519 key that signs receipts (Rekor
  cannot verify pure Ed25519 — it uses Ed25519ph). Generate with
  `bijotel keygen --type ecdsa`.
- Tests: mocked anchoring (records logIndex), skip-without-key, non-fatal
  upload-failure, and an env-gated live test (`BIJOTEL_FED_REKOR_LIVE=1`)
  that anchors in the public Sigstore Rekor. 18 tests total.

### Changed

- Replaced the v0.1.0 `_maybe_anchor_in_rekor` **no-op shim** with the real
  ECDSA path. The shim existed because BIJOTEL's Rekor client had a
  signature-encoding gap against live Rekor (Ed25519ph); that was fixed in
  **BIJOTEL 2.13.2**, which this release now requires (`bijotel>=2.13.2`).
- Rekor remains **best-effort**: an upload failure (or no key) logs a warning
  and the cross-anchor is still built, signed, and served — the receipt is
  independently Ed25519-verifiable without Rekor. A `409` (entry already
  exists) is treated as a non-fatal already-anchored.
- Fixed stale `/federation/`-prefixed paths in the app docstring (the service
  serves root paths, matching the client and the README endpoint table).

## [0.1.0] — 2026-05-26 — Skeleton service

- Initial FastAPI + SQLite service: challenge-response Ed25519 registration,
  bearer-token submit, cross-anchor builder, seven endpoints, Docker deploy.
  Rekor anchoring stubbed as a no-op pending the BIJOTEL Rekor compat fix.
