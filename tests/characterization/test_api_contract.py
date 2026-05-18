"""
tests/characterization/test_api_contract.py

Pins the shape of every API response. These tests are tripwires:
if a response key is renamed or removed, the test fails and forces a conscious
decision about whether the change is safe for existing callers.

These tests use the Flask test client, not a live server. They do NOT verify
spaCy-dependent behavior — only response shape and required fields.

Failure message guidance: when one of these fails, it means an API contract
changed. Update the expected value AND update the comment to note when + why.
If the change affects callers (Conductor workers, Doane platform services),
update those callers in the same PR.
"""

import io
import pytest
import json
import os

os.environ.setdefault("API_KEY", "")  # disable auth for contract tests

from app import app

try:
    import presidio_analyzer  # noqa: F401
    _HAS_PRESIDIO = True
except ImportError:
    _HAS_PRESIDIO = False

_presidio_required = pytest.mark.skipif(
    not _HAS_PRESIDIO,
    reason="presidio_analyzer not installed — install requirements.txt for full contract tests",
)


@pytest.fixture(scope="module")
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# /health response shape — pinned 2025-05
# ---------------------------------------------------------------------------

class TestHealthContract:
    """
    Known-good: /health returns 200 with exactly these top-level keys.
    If this fails, update monitoring config (Uptime Kuma, Grafana) in the same commit.
    """
    EXPECTED_KEYS = {"status", "service", "version", "uptime_seconds"}
    EXPECTED_SERVICE = "pii-service"

    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200, (
            "/health contract broken: expected 200. "
            "K8s liveness/readiness probes will fail if this changes."
        )

    def test_health_has_required_keys(self, client):
        data = client.get("/health").get_json()
        missing = self.EXPECTED_KEYS - set(data.keys())
        assert not missing, (
            f"/health response is missing keys: {missing}. "
            "Update Uptime Kuma and Grafana dashboard queries if this changes."
        )

    def test_health_service_name(self, client):
        data = client.get("/health").get_json()
        assert data["status"] == "ok"
        assert data["service"] == self.EXPECTED_SERVICE, (
            f"Service name changed from '{self.EXPECTED_SERVICE}' to '{data['service']}'. "
            "Update K8s deployment labels and monitoring config."
        )

    def test_health_uptime_is_numeric(self, client):
        data = client.get("/health").get_json()
        assert isinstance(data["uptime_seconds"], (int, float))


# ---------------------------------------------------------------------------
# /api/v1/scan response shape — pinned 2025-05
# ---------------------------------------------------------------------------

@_presidio_required
class TestScanContract:
    EXPECTED_KEYS = {"pii_found", "hit_count", "risk_level", "entity_types", "hits", "request_id"}
    HIT_EXPECTED_KEYS = {"entity_type", "start", "end", "score", "risk_level"}
    MUST_NOT_CONTAIN = {"original", "text", "matched_text", "raw"}  # no raw PII ever

    def test_scan_clean_text_shape(self, client):
        resp = client.post("/api/v1/scan", json={"text": "No PII here."})
        assert resp.status_code == 200
        data = resp.get_json()
        missing = self.EXPECTED_KEYS - set(data.keys())
        assert not missing, f"/api/v1/scan response missing keys: {missing}"

    def test_scan_hit_shape(self, client):
        resp = client.post("/api/v1/scan", json={"text": "SSN: 123-45-6789"})
        data = resp.get_json()
        if data["hits"]:
            hit = data["hits"][0]
            missing = self.HIT_EXPECTED_KEYS - set(hit.keys())
            assert not missing, f"Hit object missing keys: {missing}"

    def test_scan_hits_never_contain_raw_pii(self, client):
        resp = client.post("/api/v1/scan", json={"text": "SSN: 123-45-6789"})
        data = resp.get_json()
        for hit in data.get("hits", []):
            for forbidden_key in self.MUST_NOT_CONTAIN:
                assert forbidden_key not in hit, (
                    f"Hit object contains '{forbidden_key}' — this would expose raw PII in API responses. "
                    "This is a FERPA violation. Do not add raw matched text to hit objects."
                )

    def test_scan_risk_level_values(self, client):
        """risk_level must be one of the known enum values."""
        resp = client.post("/api/v1/scan", json={"text": "SSN: 123-45-6789"})
        data = resp.get_json()
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert data["risk_level"] in valid, (
            f"risk_level '{data['risk_level']}' is not a valid RiskLevel value. "
            "Callers may break if this changes without a migration."
        )

    def test_scan_request_id_present(self, client):
        resp = client.post("/api/v1/scan", json={"text": "test"})
        assert "request_id" in resp.get_json()


# ---------------------------------------------------------------------------
# /api/v1/sanitize response shape — pinned 2025-05
# ---------------------------------------------------------------------------

@_presidio_required
class TestSanitizeContract:
    EXPECTED_KEYS = {
        "sanitized_text", "excluded", "pii_found", "risk_level",
        "entity_types", "hit_count", "mode", "request_id"
    }

    def test_sanitize_shape(self, client):
        resp = client.post("/api/v1/sanitize", json={"text": "SSN: 123-45-6789", "mode": "mask"})
        assert resp.status_code == 200
        data = resp.get_json()
        missing = self.EXPECTED_KEYS - set(data.keys())
        assert not missing, f"/api/v1/sanitize missing keys: {missing}"

    def test_sanitize_exclude_mode_null_text(self, client):
        resp = client.post("/api/v1/sanitize", json={"text": "SSN: 123-45-6789", "mode": "exclude"})
        data = resp.get_json()
        assert data["excluded"] is True
        assert data["sanitized_text"] is None, (
            "exclude mode with PII must return sanitized_text=null. "
            "Callers checking 'if sanitized_text is None' will break if this changes."
        )

    def test_sanitize_invalid_mode_returns_400(self, client):
        resp = client.post("/api/v1/sanitize", json={"text": "test", "mode": "vaporize"})
        assert resp.status_code == 400
        assert resp.get_json()["code"] == "INVALID_MODE"


# ---------------------------------------------------------------------------
# /api/v1/sanitize/batch response shape — pinned 2025-05
# ---------------------------------------------------------------------------

@_presidio_required
class TestBatchContract:
    EXPECTED_TOP_KEYS = {"results", "total", "excluded_count", "clean_count", "request_id"}
    EXPECTED_RESULT_KEYS = {
        "index", "sanitized_text", "excluded", "pii_found", "hit_count", "risk_level", "entity_types"
    }

    def test_batch_shape(self, client):
        resp = client.post("/api/v1/sanitize/batch", json={
            "texts": ["No PII.", "SSN: 123-45-6789"],
            "mode": "mask",
        })
        assert resp.status_code == 200
        data = resp.get_json()
        missing = self.EXPECTED_TOP_KEYS - set(data.keys())
        assert not missing, f"Batch response missing top-level keys: {missing}"

    def test_batch_result_items_shape(self, client):
        resp = client.post("/api/v1/sanitize/batch", json={
            "texts": ["SSN: 123-45-6789"],
            "mode": "mask",
        })
        data = resp.get_json()
        if data["results"]:
            item = data["results"][0]
            missing = self.EXPECTED_RESULT_KEYS - set(item.keys())
            assert not missing, f"Batch result item missing keys: {missing}"

    def test_batch_index_matches_position(self, client):
        texts = ["first", "SSN: 123-45-6789", "third"]
        resp = client.post("/api/v1/sanitize/batch", json={"texts": texts, "mode": "mask"})
        data = resp.get_json()
        for item in data["results"]:
            assert item["index"] < len(texts)

    def test_batch_too_large_returns_400(self, client):
        texts = ["x"] * 501
        resp = client.post("/api/v1/sanitize/batch", json={"texts": texts, "mode": "mask"})
        assert resp.status_code == 400
        assert resp.get_json()["code"] == "BATCH_TOO_LARGE"


# ---------------------------------------------------------------------------
# /api/v1/preflight response shape — pinned 2025-05
# ---------------------------------------------------------------------------

@_presidio_required
class TestPreflightContract:
    EXPECTED_KEYS = {
        "safe_to_send", "risk_level", "hit_count", "blocking_entities",
        "warning_entities", "recommendation", "sanitized_suggestion", "request_id"
    }

    def test_preflight_shape(self, client):
        resp = client.post("/api/v1/preflight", json={"text": "SSN: 123-45-6789"})
        assert resp.status_code == 200
        data = resp.get_json()
        missing = self.EXPECTED_KEYS - set(data.keys())
        assert not missing, f"/api/v1/preflight missing keys: {missing}"

    def test_preflight_safe_to_send_is_bool(self, client):
        resp = client.post("/api/v1/preflight", json={"text": "SSN: 123-45-6789"})
        assert isinstance(resp.get_json()["safe_to_send"], bool)

    def test_preflight_clean_text_returns_safe(self, client):
        resp = client.post("/api/v1/preflight", json={"text": "CSCI 101 has 30 students."})
        data = resp.get_json()
        assert data["safe_to_send"] is True
        assert data["sanitized_suggestion"] is None


# ---------------------------------------------------------------------------
# /api/v1/policies response shape — pinned 2025-05
# ---------------------------------------------------------------------------

class TestPoliciesContract:
    EXPECTED_POLICY_KEYS = {
        "name", "description", "default_mode",
        "block_entity_types", "pass_through_entity_types", "exclude_any_pii"
    }
    REQUIRED_POLICY_NAMES = {
        "ai_prompt", "embedding", "log_safe", "export_internal",
        "export_external", "ferpa_strict", "analytics"
    }

    def test_policies_shape(self, client):
        resp = client.get("/api/v1/policies")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "policies" in data
        assert "count" in data

    def test_all_required_policies_in_catalog(self, client):
        resp = client.get("/api/v1/policies")
        names = {p["name"] for p in resp.get_json()["policies"]}
        missing = self.REQUIRED_POLICY_NAMES - names
        assert not missing, (
            f"Policy catalog is missing: {missing}. "
            "Callers that reference these by name will break."
        )

    def test_policy_object_shape(self, client):
        resp = client.get("/api/v1/policies")
        for policy in resp.get_json()["policies"]:
            missing = self.EXPECTED_POLICY_KEYS - set(policy.keys())
            assert not missing, f"Policy '{policy.get('name')}' missing keys: {missing}"


# ---------------------------------------------------------------------------
# /api/v1/stats response shape — pinned 2025-05
# ---------------------------------------------------------------------------

class TestStatsContract:
    EXPECTED_KEYS = {
        "total_requests", "total_pii_hits", "total_excluded", "total_clean",
        "entity_type_counts", "mode_counts", "risk_level_counts",
        "endpoint_counts", "uptime_seconds", "auth_enabled", "version"
    }

    def test_stats_shape(self, client):
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        missing = self.EXPECTED_KEYS - set(data.keys())
        assert not missing, f"/api/v1/stats missing keys: {missing}"


# ---------------------------------------------------------------------------
# Error response shape — pinned 2025-05
# ---------------------------------------------------------------------------

class TestErrorResponseContract:
    """All error responses must have {error, code, request_id}."""
    EXPECTED_KEYS = {"error", "code", "request_id"}

    def test_400_has_error_shape(self, client):
        resp = client.post("/api/v1/scan", json={"text": 12345})
        assert resp.status_code == 400
        data = resp.get_json()
        missing = self.EXPECTED_KEYS - set(data.keys())
        assert not missing, f"Error response missing keys: {missing}"

    def test_404_on_unknown_route(self, client):
        resp = client.get("/api/v1/does-not-exist")
        assert resp.status_code == 404

    def test_text_too_long_returns_400(self, client, monkeypatch):
        monkeypatch.setenv("MAX_TEXT_LENGTH", "10")
        resp = client.post("/api/v1/scan", json={"text": "a" * 11})
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["code"] == "TEXT_TOO_LONG"
        missing = self.EXPECTED_KEYS - set(data.keys())
        assert not missing, f"TEXT_TOO_LONG error missing keys: {missing}"


# ---------------------------------------------------------------------------
# /api/v1/schemas response shape — pinned 2025-05
# No presidio needed — schemas are pure config.
# ---------------------------------------------------------------------------

class TestSchemasContract:
    """
    Known-good: /api/v1/schemas returns these top-level keys and includes
    all six built-in schema profiles. If a profile is renamed or removed,
    update callers that reference it by name (n8n workflows, Conductor tasks).
    """
    EXPECTED_KEYS = {"schemas", "count"}
    EXPECTED_SCHEMA_KEYS = {"name", "description", "field_count", "default_mode", "fields"}
    REQUIRED_PROFILES = {
        "banner_student", "colleague_person", "salesforce_contact",
        "ethos_person", "n8n_generic", "conductor_ethos",
    }

    def test_schemas_returns_200(self, client):
        resp = client.get("/api/v1/schemas")
        assert resp.status_code == 200

    def test_schemas_top_level_shape(self, client):
        data = client.get("/api/v1/schemas").get_json()
        missing = self.EXPECTED_KEYS - set(data.keys())
        assert not missing, f"/api/v1/schemas missing keys: {missing}"

    def test_all_required_profiles_present(self, client):
        names = {s["name"] for s in client.get("/api/v1/schemas").get_json()["schemas"]}
        missing = self.REQUIRED_PROFILES - names
        assert not missing, (
            f"Schema catalog missing profiles: {missing}. "
            "Callers that reference these by name (n8n, Conductor) will break."
        )

    def test_schema_object_shape(self, client):
        for schema in client.get("/api/v1/schemas").get_json()["schemas"]:
            missing = self.EXPECTED_SCHEMA_KEYS - set(schema.keys())
            assert not missing, f"Schema '{schema.get('name')}' missing keys: {missing}"

    def test_count_matches_list(self, client):
        data = client.get("/api/v1/schemas").get_json()
        assert data["count"] == len(data["schemas"]), (
            "Schema count field does not match actual list length. "
            "Callers using count for pagination will get wrong results."
        )

    def test_banner_student_has_ssn_field(self, client):
        schemas = {s["name"]: s for s in client.get("/api/v1/schemas").get_json()["schemas"]}
        banner = schemas["banner_student"]
        assert "SPBPERS_SSN" in banner["fields"], (
            "banner_student schema must map SPBPERS_SSN. "
            "This is how Banner's SSN column is identified for masking."
        )


# ---------------------------------------------------------------------------
# /api/v1/stats/reset contract — pinned 2025-05
# ---------------------------------------------------------------------------

class TestStatsResetContract:
    def test_reset_returns_200(self, client):
        resp = client.post("/api/v1/stats/reset")
        assert resp.status_code == 200

    def test_reset_response_shape(self, client):
        data = client.post("/api/v1/stats/reset").get_json()
        assert data.get("reset") is True


# ---------------------------------------------------------------------------
# /api/v1/config/reload contract — pinned 2025-05
# ---------------------------------------------------------------------------

class TestConfigReloadContract:
    EXPECTED_KEYS = {"reloaded", "entity_thresholds", "custom_patterns", "schema_profiles"}

    def test_reload_returns_200(self, client):
        resp = client.post("/api/v1/config/reload")
        assert resp.status_code == 200

    def test_reload_response_shape(self, client):
        data = client.post("/api/v1/config/reload").get_json()
        missing = self.EXPECTED_KEYS - set(data.keys())
        assert not missing, f"/api/v1/config/reload missing keys: {missing}"

    def test_reloaded_is_true(self, client):
        assert client.post("/api/v1/config/reload").get_json()["reloaded"] is True


# ---------------------------------------------------------------------------
# /api/v1/file error response contracts — no presidio needed
# ---------------------------------------------------------------------------

class TestFileUploadErrorContract:
    """
    Known-good: file endpoint error codes for pre-processing failures.
    These fire before PII detection so they work without presidio installed.
    """

    def test_no_file_returns_400(self, client):
        resp = client.post("/api/v1/file")
        assert resp.status_code == 400
        assert resp.get_json()["code"] == "NO_FILE"

    def test_unsupported_extension_returns_400(self, client):
        data = {"file": (io.BytesIO(b"hello"), "document.xyz")}
        resp = client.post("/api/v1/file", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400
        assert resp.get_json()["code"] == "INVALID_FILE_TYPE"

    def test_invalid_mode_returns_400(self, client):
        data = {"file": (io.BytesIO(b"name,notes\n"), "data.csv"), "mode": "vaporize"}
        resp = client.post("/api/v1/file", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400
        assert resp.get_json()["code"] == "INVALID_MODE"

    def test_file_too_large_returns_400(self, client, monkeypatch):
        monkeypatch.setenv("FILE_SIZE_LIMIT_MB", "0")
        data = {"file": (io.BytesIO(b"small content here"), "data.csv")}
        resp = client.post("/api/v1/file", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400
        assert resp.get_json()["code"] == "FILE_TOO_LARGE"
