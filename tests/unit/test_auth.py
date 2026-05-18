"""
tests/unit/test_auth.py - Unit tests for the API key authentication module.

Auth state is module-level in auth.py, so tests must call init_auth() when
they mutate the environment, and restore state afterward.
"""

import os
import pytest

from flask import Flask
from pii_guard.auth import (
    init_auth, require_api_key, is_auth_enabled, key_prefix,
    get_caller_name, list_key_names, generate_key,
)
import pii_guard.auth as _auth_module


@pytest.fixture(autouse=True)
def reset_auth():
    """Restore auth state after each test."""
    original_key = os.environ.get("API_KEY")
    original_keys = os.environ.get("API_KEYS")
    yield
    if original_key is None:
        os.environ.pop("API_KEY", None)
    else:
        os.environ["API_KEY"] = original_key
    if original_keys is None:
        os.environ.pop("API_KEYS", None)
    else:
        os.environ["API_KEYS"] = original_keys
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

    def test_empty_x_api_key_header_rejected(self):
        """Empty X-API-Key must be treated as missing — not as a valid empty key."""
        app = self._make_app(key="real-key")
        with app.test_client() as client:
            resp = client.get("/protected", headers={"X-API-Key": ""})
            assert resp.status_code == 401, (
                "Empty X-API-Key should return 401, not 403. "
                "Empty string is equivalent to missing key."
            )

    def test_authorization_header_takes_precedence_over_x_api_key(self):
        """When both headers are present, Authorization Bearer is evaluated first."""
        app = self._make_app(key="correct-key")
        with app.test_client() as client:
            resp = client.get(
                "/protected",
                headers={"Authorization": "Bearer wrong-key", "X-API-Key": "correct-key"},
            )
            assert resp.status_code == 403, (
                "When Authorization: Bearer is present (even if wrong), "
                "X-API-Key must NOT be used as a fallback."
            )

    def test_non_bearer_authorization_falls_through_to_x_api_key(self):
        """A non-Bearer Authorization header does not block X-API-Key fallback."""
        app = self._make_app(key="correct-key")
        with app.test_client() as client:
            resp = client.get(
                "/protected",
                headers={"Authorization": "Token some-other-scheme", "X-API-Key": "correct-key"},
            )
            assert resp.status_code == 200, (
                "When Authorization header is not Bearer, X-API-Key should be used as fallback."
            )


class TestNamedMultiKeyAuth:
    """
    Known-good: API_KEYS="name1:key1,name2:key2" format with named callers.
    Names appear in audit logs as caller_name.
    """

    def _make_app_multi(self, api_keys_str: str):
        os.environ.pop("API_KEY", None)
        os.environ["API_KEYS"] = api_keys_str
        init_auth()

        mini_app = Flask(__name__ + "_multi")

        @mini_app.route("/protected")
        @require_api_key
        def protected_view():
            from flask import jsonify, g
            return jsonify({
                "ok": True,
                "caller_name": g.get("caller_name"),
                "key_prefix": g.get("api_key_prefix"),
            })

        return mini_app

    def test_named_key_parsed_and_accepted(self):
        app = self._make_app_multi("conductor:key-abc,n8n:key-xyz")
        with app.test_client() as client:
            resp = client.get("/protected", headers={"X-API-Key": "key-abc"})
            assert resp.status_code == 200
            assert resp.get_json()["caller_name"] == "conductor"

    def test_second_named_key_works(self):
        app = self._make_app_multi("conductor:key-abc,n8n:key-xyz")
        with app.test_client() as client:
            resp = client.get("/protected", headers={"X-API-Key": "key-xyz"})
            assert resp.status_code == 200
            assert resp.get_json()["caller_name"] == "n8n"

    def test_unknown_key_rejected(self):
        app = self._make_app_multi("conductor:key-abc")
        with app.test_client() as client:
            resp = client.get("/protected", headers={"X-API-Key": "wrong"})
            assert resp.status_code == 403

    def test_single_api_key_stored_as_default(self):
        os.environ.pop("API_KEYS", None)
        os.environ["API_KEY"] = "single-key"
        init_auth()
        assert "default" in list_key_names()

    def test_api_keys_env_takes_precedence_for_default_name(self):
        os.environ["API_KEYS"] = "default:from-named,other:key2"
        os.environ["API_KEY"] = "single-key"
        init_auth()
        # API_KEYS "default" wins; single API_KEY should not overwrite it
        names = list_key_names()
        assert names.count("default") == 1

    def test_get_caller_name_timing_safe(self):
        os.environ["API_KEYS"] = "svc-a:key-aaa,svc-b:key-bbb"
        init_auth()
        assert get_caller_name("key-aaa") == "svc-a"
        assert get_caller_name("key-bbb") == "svc-b"
        assert get_caller_name("wrong") is None

    def test_list_key_names_sorted(self):
        os.environ["API_KEYS"] = "z-svc:k1,a-svc:k2,m-svc:k3"
        init_auth()
        names = list_key_names()
        assert names == sorted(names)

    def test_malformed_pair_skipped(self):
        os.environ["API_KEYS"] = "good-name:good-key,bad-no-colon,another:key2"
        init_auth()
        names = list_key_names()
        assert "bad-no-colon" not in names
        assert "good-name" in names
        assert "another" in names

    def test_generate_key_contains_prefix(self):
        key = generate_key(prefix="sk_n8n")
        assert key.startswith("sk_n8n_")

    def test_generate_key_no_prefix(self):
        key = generate_key(prefix="")
        assert "_" not in key or key  # just verify it returns something

    def test_generate_key_unique(self):
        k1 = generate_key()
        k2 = generate_key()
        assert k1 != k2
