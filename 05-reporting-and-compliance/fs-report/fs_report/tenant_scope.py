"""Tenant-boundary identity for anything cached on disk.

The confidentiality boundary for cached platform data is the **account**,
identified by the API token — NOT the host. One host serves many accounts: the
shared multi-tenant domain fronts every tenant, so a cache keyed by domain lets
one account's records be served under another's name.

This module is the single source of truth for that identity. It lives on its own
(rather than in ``llm_client``, where it started) so ``sqlite_cache`` can depend
on it without pulling in the LLM client, and so the AI narrative cache and the
API-response cache cannot drift apart on what "same tenant" means.

``llm_client`` re-exports ``build_tenant_scope`` for its existing callers.
"""

from __future__ import annotations

import hashlib
import hmac

# Keyed digest, 128-bit (32 hex). The scope IS the confidentiality boundary, so
# accidental cross-account collisions must stay far out of reach.
#
# On what the HMAC does and does not buy: the salt below is a hardcoded public
# constant, so it is NOT a secret and keying adds no strength against an
# attacker holding this source. What actually makes a digest non-reversible here
# is the entropy of the API token itself — a `fsa_`-prefixed random string is not
# brute-forceable, whereas a low-entropy input would fall to a dictionary attack
# with or without the salt. The HMAC construction is retained for domain
# separation (these digests cannot be replayed against another consumer of the
# same token) and for continuity with the AI cache; do not describe it as a
# secret-keyed MAC.
#
# The salt is deliberately the one the AI cache has always used, so tenant scopes
# already minted there stay valid — changing it would silently invalidate every
# existing AI narrative cache entry.
_SCOPE_HMAC_SALT = b"fs-report/ai-cache-scope/v1"
_SCOPE_DIGEST_HEX = 32

# Placeholder API tokens that do NOT identify a real account. Offline/data-file
# runs use "dummy_token" (see cli/run.py); such runs have no account boundary, so
# build_tenant_scope must not mint a (constant) tenant token from them — that
# would hand every offline user on earth the same "tenant".
_PLACEHOLDER_AUTH_TOKENS = frozenset({"", "dummy_token"})


def scope_digest(data: str) -> str:
    """Keyed, non-reversible digest of a cache-scope string."""
    return hmac.new(_SCOPE_HMAC_SALT, data.encode(), hashlib.sha256).hexdigest()[
        :_SCOPE_DIGEST_HEX
    ]


def build_tenant_scope(domain: str | None, auth_token: str | None) -> str:
    """Build a stable tenant-boundary token from the platform host + API token.

    A real token is REQUIRED; without one this returns ``""`` (no tenant
    boundary), which covers domain-only callers and offline/data-file runs whose
    token is the shared placeholder ``dummy_token``.

    An empty scope is safe for its original caller (the AI cache), where
    cross-project isolation still comes from the per-item ``project_version_id``
    scope. Callers that use the scope as their ONLY isolation — e.g. the
    API-response cache filename — get the pre-existing domain-only behaviour
    when it is empty, which is no worse than before and only reachable when
    there is no account to isolate.

    The domain is folded in so the same token against staging and prod differs,
    but only once a real token is present.
    """
    token = (auth_token or "").strip()
    if token in _PLACEHOLDER_AUTH_TOKENS:
        return ""
    domain = (domain or "").strip().lower()
    return scope_digest(f"{domain}\x1f{token}")


#: Hex characters of the scope digest kept in the cache FILENAME. This suffix is
#: the whole file-level tenant boundary, so its collision space is the boundary's
#: strength: two accounts whose suffixes collide silently share a cache file and
#: the isolation this module exists to provide is gone. 8 hex (32 bits) is too
#: close for something guarding cross-account data — a birthday collision needs
#: only ~77k distinct scopes, and the digest is attacker-influenceable on a
#: shared host. 16 hex (64 bits) puts it out of reach while keeping the filename
#: legible in a directory listing.
TENANT_SUFFIX_HEX = 16


def tenant_cache_suffix(domain: str | None, auth_token: str | None) -> str:
    """Filename suffix isolating one tenant's cache file, or ``""`` if unknown.

    Truncated from the full scope for legibility — see ``TENANT_SUFFIX_HEX`` for why
    the width is what it is. Callers matching these filenames should expect
    exactly ``TENANT_SUFFIX_HEX`` lowercase hex characters after a hyphen.
    """
    scope = build_tenant_scope(domain, auth_token)
    return f"-{scope[:TENANT_SUFFIX_HEX]}" if scope else ""
