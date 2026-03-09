# Copyright (c) 2024 Finite State, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Copilot API authentication.

Handles the two-step auth flow required by GitHub Copilot's API:
1. Obtain a GitHub token (PAT, ``gh auth token``, or OAuth device flow)
2. Exchange it for a short-lived Copilot API token via the internal token endpoint

The module caches both the GitHub OAuth token and the Copilot API token
to avoid redundant exchanges and device-flow prompts.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

_TOKEN_EXCHANGE_URL = "https://api.github.com/copilot_internal/v2/token"
_DEVICE_CODE_URL = "https://github.com/login/device/code"
_OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token"

# Well-known GitHub OAuth client ID for VS Code / Copilot
_OAUTH_CLIENT_ID = "Iv1.b507a08c87ecfe98"

# Re-exchange when the Copilot token expires within this many seconds
_REFRESH_MARGIN_SECS = 300  # 5 minutes

_CACHE_DIR = Path.home() / ".fs-report"
_CACHE_FILE = _CACHE_DIR / "copilot_oauth.json"


def get_copilot_token(github_token: str | None = None) -> tuple[str, str]:
    """Return ``(copilot_api_token, base_url)`` for the Copilot API.

    Resolution order:
    1. If *github_token* is provided, exchange it directly.
    2. Try a cached Copilot token (if still valid).
    3. Try a cached GitHub OAuth token → exchange.
    4. Try ``gh auth token`` for a CLI-based token → exchange.
    5. Run the interactive OAuth device flow → cache + exchange.
    """
    # 1. Explicit token provided
    if github_token:
        data = _exchange_for_copilot_token(github_token)
        return data["token"], data["endpoints"]["api"]

    # 2. Check cache for a still-valid Copilot token
    cache = _load_cached_token()
    if cache:
        copilot = cache.get("copilot_token")
        expires = cache.get("copilot_expires_at", 0)
        base_url = cache.get("copilot_base_url")
        if copilot and base_url and time.time() < expires - _REFRESH_MARGIN_SECS:
            logger.debug("Using cached Copilot token (expires_at=%s)", expires)
            return copilot, base_url

        # 3. Cached GitHub OAuth token → re-exchange
        gh_token = cache.get("github_token")
        if gh_token:
            try:
                data = _exchange_for_copilot_token(gh_token)
                _save_cached_token(
                    github_token=gh_token,
                    copilot_token=data["token"],
                    copilot_expires_at=data["expires_at"],
                    copilot_base_url=data["endpoints"]["api"],
                )
                return data["token"], data["endpoints"]["api"]
            except requests.HTTPError:
                logger.debug("Cached GitHub token rejected, will try other sources")

    # 4. Try `gh auth token`
    gh_cli_token = _try_gh_cli_token()
    if gh_cli_token:
        try:
            data = _exchange_for_copilot_token(gh_cli_token)
            _save_cached_token(
                github_token=gh_cli_token,
                copilot_token=data["token"],
                copilot_expires_at=data["expires_at"],
                copilot_base_url=data["endpoints"]["api"],
            )
            return data["token"], data["endpoints"]["api"]
        except requests.HTTPError:
            logger.debug("gh CLI token rejected for Copilot exchange")

    # 5. Interactive device flow
    oauth_token = _run_device_flow()
    data = _exchange_for_copilot_token(oauth_token)
    _save_cached_token(
        github_token=oauth_token,
        copilot_token=data["token"],
        copilot_expires_at=data["expires_at"],
        copilot_base_url=data["endpoints"]["api"],
    )
    return data["token"], data["endpoints"]["api"]


def _exchange_for_copilot_token(github_token: str) -> dict:
    """Exchange a GitHub token for a short-lived Copilot API token.

    Returns the full JSON response containing ``token``, ``expires_at``,
    and ``endpoints``.

    Raises ``ValueError`` if the response is missing required fields.
    """
    resp = requests.get(
        _TOKEN_EXCHANGE_URL,
        headers={
            "Authorization": f"token {github_token}",
            "Accept": "application/json",
        },
        timeout=30,
    )
    resp.raise_for_status()
    data: dict = resp.json()
    # Validate required fields
    try:
        _ = data["token"], data["expires_at"], data["endpoints"]["api"]
    except (KeyError, TypeError) as exc:
        raise ValueError(
            f"Unexpected Copilot token exchange response — missing field: {exc}. "
            f"Response keys: {list(data.keys())}"
        ) from exc
    return data


def _try_gh_cli_token() -> str | None:
    """Try to get a token from the GitHub CLI."""
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _run_device_flow() -> str:
    """Run the GitHub OAuth device flow interactively.

    Displays a user code and verification URL, then polls until the user
    completes authorization. Returns the ``gho_xxx`` OAuth access token.
    """
    # Request a device code
    resp = requests.post(
        _DEVICE_CODE_URL,
        data={"client_id": _OAUTH_CLIENT_ID, "scope": "read:user"},
        headers={"Accept": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    device = resp.json()

    device_code = device["device_code"]
    user_code = device["user_code"]
    verification_uri = device["verification_uri"]
    interval = device.get("interval", 5)
    expires_in = device.get("expires_in", 900)

    logger.warning(
        "GitHub Copilot authentication required. " "Open: %s — Enter code: %s",
        verification_uri,
        user_code,
    )

    deadline = time.time() + expires_in
    while time.time() < deadline:
        time.sleep(interval)
        token_resp = requests.post(
            _OAUTH_TOKEN_URL,
            data={
                "client_id": _OAUTH_CLIENT_ID,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
            headers={"Accept": "application/json"},
            timeout=30,
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()

        error = token_data.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        if error:
            raise RuntimeError(f"OAuth device flow error: {error}")

        access_token: str | None = token_data.get("access_token")
        if access_token:
            return access_token

    logger.error(
        "OAuth device flow timed out. "
        "Please re-run and complete authorization within %d seconds.",
        expires_in,
    )
    raise TimeoutError("OAuth device flow timed out waiting for authorization")


# ── Token cache ─────────────────────────────────────────────────────


def _load_cached_token() -> dict | None:
    """Load the cached token file, or return None."""
    try:
        return json.loads(_CACHE_FILE.read_text())  # type: ignore[no-any-return]
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _save_cached_token(
    *,
    github_token: str,
    copilot_token: str,
    copilot_expires_at: int,
    copilot_base_url: str,
) -> None:
    """Persist tokens to the cache file with restricted permissions."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "github_token": github_token,
        "copilot_token": copilot_token,
        "copilot_expires_at": copilot_expires_at,
        "copilot_base_url": copilot_base_url,
    }
    # Atomically create file with 0o600 to avoid TOCTOU race where the file
    # is briefly world-readable before chmod.
    fd = os.open(str(_CACHE_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
