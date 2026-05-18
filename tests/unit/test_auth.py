"""
tests/unit/test_auth.py - Unit tests for the API key authentication module.

Auth state is module-level in auth.py, so tests must call init_auth() when
they mutate the environment, and restore state afterward.
"""

import os
import pytest
from unittest.mock import patch

from flask import Flask
from pii_guard.auth import init_auth, require_api_key, is_auth_enabled, key_prefix
import pii_guard.auth as _auth_module


@pytest.fixture(autouse=True)
def reset_auth():
    """Restore auth state after each test."""
    original_key = os.environ.get("API_KEY")
    yield
    if original_key is None:
        os.environ.pop("API_KEY", None)
    else:
        os.environ["API_KEY"] = original_key
    init_auth()


class TestInitAuth:
    def test_no_key_disables_auth(self):
        os.environ.pop("API_KEY", None)
        init_auth()
        assert not is_auth_enabled()

    def test_empty_key_disables_auth(self):
        os.environ["API_KEY"] = ""
        init_auth()
        assert not is_auth_enabled()

    def test_valid_key_enables_auth(self):
        os.environ["API_KEY"] = "my-test-key-12345"
        init_auth()
        assert is_auth_enabled()


class TestRequireApiKeyDecorator:
    """Test the decorator using a minimal Flask app context."""

    def _make_app(self, key: str = None):
        if key:
            os.environ["API_KEY"] = key
        else:
            os.environ.pop("API_KEY", None)
        init_auth()

        mini_app = Flask(__name__)

        @mini_app.route("/protected")
        @require_api_key
        def protected_view():
            from flask import jsonify, g
            return jsonify({"ok": True, "key_prefix": g.get("api_key_prefix")})

        return mini_app

    def test_auth_disabled_allows_all_requests(self):
        app = self._make_app(key=None)
        with app.test_client() as client:
            resp = client.get("/protected")
            assert resp.status_code == 200

    def test_auth_enabled_rejects_missing_key(self):
        app = self._make_app(key="secret-key-xyz")
        with app.test_client() as client:
            resp = client.get("/protected")
            assert resp.status_code == 401
            data = resp.get_json()
            assert data["code"] == "AUTH_REQUIRED"

    def test_auth_enabled_rejects_wrong_key(self):
        app = self._make_app(key="correct-key")
        with app.test_client() as client:
            resp = client.get("/protected", headers={"Authorization": "Bearer wrong-key"})
            assert resp.status_code == 403
            assert resp.get_json()["code"] == "AUTH_INVALID"

    def test_bearer_token_accepted(self):
        app = self._make_app(key="my-secret-key")
        with app.test_client() as client:
            resp = client.get("/protected", headers={"Authorization": "Bearer my-secret-key"})
            assert resp.status_code == 200

    def test_x_api_key_header_accepted(self):
        app = self._make_app(key="my-secret-key")
        with app.test_client() as client:
            resp = client.get("/protected", headers={"X-API-Key": "my-secret-key"})
            assert resp.status_code == 200

    def test_key_prefix_attached_to_g(self):
        app = self._make_app(key="abcd-efgh-1234")
        with app.test_client() as client:
            resp = client.get("/protected", headers={"Authorization": "Bearer abcd-efgh-1234"})
            data = resp.get_json()
            assert data["key_prefix"] is not None
            assert data["key_prefix"].startswith("abcd")

    def test_full_key_not_in_prefix(self):
        app = self._make_app(key="abcdefghijklmn")
        with app.test_client() as client:
            resp = client.get("/protected", headers={"Authorization": "Bearer abcdefghijklmn"})
            data = resp.get_json()
            # Prefix should be truncated — the full key must not appear
            assert data["key_prefix"] != "abcdefghijklmn"
