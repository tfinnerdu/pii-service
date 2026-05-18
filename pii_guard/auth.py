"""
pii_guard.auth - API key authentication middleware.

Reads API_KEY from the environment. If not set, auth is disabled with a
startup warning — acceptable for local development, never for production.

Clients authenticate via either:
  Authorization: Bearer <key>
  X-API-Key: <key>

The key prefix (first 4 chars) is logged for audit purposes; the full key is never logged.
"""

import logging
import os
from functools import wraps
from typing import Optional

from flask import request, jsonify, g

logger = logging.getLogger("pii_guard.auth")

_API_KEY: Optional[str] = None
_AUTH_ENABLED: bool = False


def init_auth() -> None:
    """
    Called once at app startup. Reads API_KEY from env.
    Logs a warning if auth is disabled (no key configured).
    """
    global _API_KEY, _AUTH_ENABLED
    _API_KEY = os.getenv("API_KEY", "").strip() or None
    _AUTH_ENABLED = _API_KEY is not None

    if _AUTH_ENABLED:
        logger.info("API key authentication enabled")
    else:
        logger.warning(
            "API_KEY not set — authentication DISABLED. "
            "Set API_KEY in .env before deploying to production."
        )


def is_auth_enabled() -> bool:
    return _AUTH_ENABLED


def _extract_key() -> Optional[str]:
    """Extract the bearer token or X-API-Key header value."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return request.headers.get("X-API-Key", "").strip() or None


def key_prefix() -> Optional[str]:
    """
    Return the first 4 characters of the authenticated key for audit logs.
    Returns None if auth is disabled or no key was presented.
    """
    key = _extract_key()
    if key and len(key) >= 4:
        return key[:4] + "..."
    return None


def require_api_key(f):
    """
    Decorator: enforce API key auth if enabled.
    Attach key_prefix to g for downstream audit logging.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _AUTH_ENABLED:
            g.api_key_prefix = None
            return f(*args, **kwargs)

        provided = _extract_key()
        if not provided:
            return jsonify({
                "error": "Authentication required. Provide 'Authorization: Bearer <key>' or 'X-API-Key: <key>'.",
                "code": "AUTH_REQUIRED",
                "request_id": g.get("request_id", "unknown"),
            }), 401

        if provided != _API_KEY:
            logger.warning("Invalid API key attempt from %s", request.remote_addr)
            return jsonify({
                "error": "Invalid API key.",
                "code": "AUTH_INVALID",
                "request_id": g.get("request_id", "unknown"),
            }), 403

        g.api_key_prefix = key_prefix()
        return f(*args, **kwargs)

    return decorated
