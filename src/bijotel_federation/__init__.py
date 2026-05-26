"""Reference federation service for the BIJOTEL chain-federation protocol.

This package is the **service** side of the protocol whose **client**
ships in ``bijotel.federation`` (v2.11.0). The two are intentionally
in separate repos:

  * ``bijotel`` — the library every LLM-operator embeds. Includes the
    federation HTTP client and local-only verification helpers.
  * ``bijotel-federation`` — the federation operator's service. One
    deployment per federation; multiple federations can co-exist.

Skeleton at v0.1.0. See ``docs/design/cross-org-federation.md`` in
the BIJOTEL repo for the protocol spec.
"""

__version__ = "0.1.0"
