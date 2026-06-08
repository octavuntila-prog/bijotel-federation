"""Reference federation service for the BIJOTEL chain-federation protocol.

This package is the **service** side of the protocol whose **client**
ships in ``bijotel.federation`` (v2.11.0). The two are intentionally
in separate repos:

  * ``bijotel`` — the library every LLM-operator embeds. Includes the
    federation HTTP client and local-only verification helpers.
  * ``bijotel-federation`` — the federation operator's service. One
    deployment per federation; multiple federations can co-exist.

v0.3.0 — security hardening from the 2026-06-08 BIJOTEL technical audit:
``/submit`` now cryptographically verifies the operator's signed export
before witnessing it (ISSUE-1), ``/verify`` checks the federation Ed25519
signature (ISSUE-9), ``/_internal/build-anchor`` requires an admin token
(ISSUE-10), submissions are size/count-bounded (ISSUE-17), and submit
bearer nonces are one-shot to blunt replay (ISSUE-2, partial — full
body/timestamp binding tracked for the bijotel 2.16.0 client).

v0.2.0 — adds live Sigstore Rekor anchoring of cross-anchors (ECDSA
P-256), unblocked by the BIJOTEL 2.13.2 Rekor compat-gap fix. See
``docs/design/cross-org-federation.md`` in the BIJOTEL repo for the
protocol spec.
"""

__version__ = "0.3.0"
