"""
pii_guard.auth - API key authentication middleware.

Supports two auth modes (merged at startup, both active simultaneously):

  Single key (backward-compatible):
    API_KEY=<value>  →  stored as name "default"

  Named multi-key:
    API_KEYS="name1:key1,name2:key2,..."
    Names identify callers in audit logs and /api/v1/keys responses.

Clients authenticate via either:
  Authorization: Bearer <key>
  X-API-Key: <key>

g.caller_name is set to the matching key name for audit logging.
g.api_key_prefix (first 4 chars) is kept for backward compatibility.
"""

import logging
import os
import secrets
from functools import wraps
from typing import Optional

from flask import request, jsonify, g

logger = logging.getLogger("pii_guard.auth")

_NAMED_KEYS: dict[str, str] = {}   # name -> key value
_AUTH_ENABLED: bool = False


def init_auth() -> None:
    global _NAMED_KEYS, _AUTH_ENABLED
    _NAMED_KEYS.clear()

    named_raw = os.getenv("API_KEYS", "").strip()
    if named_raw:
        for pair in named_raw.split(","):
            pair = pair.strip()
            if ":" not in pair:
                continue
            name, _, key = pair.partition(":")
            name, key = name.strip(), key.strip()
            if name and key:
                _NAMED_KEYS[name] = key

    single_key = os.getenv("API_KEY", "").strip()
    if single_key and "default" not in _NAMED_KEYS:
        _NAMED_KEYS["default"] = single_key

    _AUTH_ENABLED = bool(_NAMED_KEYS)

    if _AUTH_ENABLED:
        logger.info("API key authentication enabled (%d key(s): %s)",
                    len(_NAMED_KEYS), ", ".join(sorted(_NAMED_KEYS)))
    else:
        logger.warning(
            "API_KEY / API_KEYS not set — authentication DISABLED. "
            "Set API_KEY in .env before deploying to production."
        )


def is_auth_enabled() -> bool:
    return _AUTH_ENABLED


def list_key_names() -> list[str]:
    return sorted(_NAMED_KEYS.keys())


def generate_key(prefix: str = "sk") -> str:
    token = secrets.token_urlsafe(32)
    return f"{prefix}_{token}" if prefix else token


def get_caller_name(provided_key: str) -> Optional[str]:
    for name, key in _NAMED_KEYS.items():
        if secrets.compare_digest(key, provided_key):
            return name
    return None


def _extract_key() -> Optional[str]:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip() or None
    return request.headers.get("X-API-Key", "").strip() or None


def key_prefix() -> Optional[str]:
    key = _extract_key()
    if key and len(key) >= 4:
        return key[:4] + "..."
    return None


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _AUTH_ENABLED:
            g.api_key_prefix = None
            g.caller_name = None
            return f(*args, **kwargs)

        provided = _extract_key()
        if not provided:
            return jsonify({
                "error": "Authentication required. Provide 'Authorization: Bearer <key>' or 'X-API-Key: <key>'.",
                "code": "AUTH_REQUIRED",
                "request_id": g.get("request_id", "unknown"),
            }), 401

        caller = get_caller_name(provided)
        if not caller:
            logger.warning("Invalid API key attempt from %s", request.remote_addr)
            return jsonify({
                "error": "Invalid API key.",
                "code": "AUTH_INVALID",
                "request_id": g.get("request_id", "unknown"),
            }), 403

        g.caller_name = caller
        g.api_key_prefix = key_prefix()
        return f(*args, **kwargs)

    return decorated
