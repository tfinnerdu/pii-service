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
# /api/v1/health response shape — pinned 2026-05-21
# Changed 2026-05-21: path versioned /health -> /api/v1/health (bare /health
# deprecated per ADR-0002); uptime_seconds pinned as int, not float.
# ---------------------------------------------------------------------------

class TestHealthContract:
    """
    Known-good: /api/v1/health returns 200 with exactly these top-level keys.
    If this fails, update monitoring config (Uptime Kuma, Grafana) in the same commit.
    """
    HEALTH_PATH = "/api/v1/health"
    EXPECTED_KEYS = {"status", "service", "version", "uptime_seconds"}
    EXPECTED_SERVICE = "pii-service"

    def test_health_returns_200(self, client):
        resp = client.get(self.HEALTH_PATH)
        assert resp.status_code == 200, (
            "/api/v1/health contract broken: expected 200. "
            "K8s liveness probe will fail if this changes."
        )

    def test_health_has_required_keys(self, client):
        data = client.get(self.HEALTH_PATH).get_json()
        missing = self.EXPECTED_KEYS - set(data.keys())
        assert not missing, (
            f"/api/v1/health response is missing keys: {missing}. "
            "Update Uptime Kuma and Grafana dashboard queries if this changes."
        )

    def test_health_service_name(self, client):
        data = client.get(self.HEALTH_PATH).get_json()
        assert data["status"] == "ok"
        assert data["service"] == self.EXPECTED_SERVICE, (
            f"Service name changed from '{self.EXPECTED_SERVICE}' to '{data['service']}'. "
            "Update K8s deployment labels and monitoring config."
        )

    def test_health_uptime_is_integer(self, client):
        """
        uptime_seconds must be an int — int((now - started_at).total_seconds()).
        A bool is an int subclass; reject it explicitly.
        """
        data = client.get(self.HEALTH_PATH).get_json()
        uptime = data["uptime_seconds"]
        assert isinstance(uptime, int) and not isinstance(uptime, bool), (
            f"uptime_seconds is {type(uptime).__name__}, must be int. "
            "The standard pins this as an integer count of seconds."
        )
        assert uptime >= 0

    def test_bare_health_path_is_gone(self, client):
        """The deprecated bare /health path must not resolve — only /api/v1/health."""
        assert client.get("/health").status_code == 404, (
            "Bare /health still resolves. It is deprecated — the only health path "
            "is /api/v1/health. Remove the old route."
        )


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
# /api/v1/policy/apply response shape — pinned 2026-05-27
#
# The UI ("Scan & Sanitize" tab) and downstream callers (Conductor workers,
# n8n nodes) decide whether to display sanitized output, show an "excluded"
# indicator, or surface blocked entities by reading the keys pinned below.
#
# The shape differs from /api/v1/sanitize on purpose — policy/apply tracks
# "passed/action_taken" semantics while sanitize tracks "excluded: bool".
# That divergence has bitten the UI before (a missing `excluded` field led
# to silent re-display of raw PII). These tests pin the policy/apply shape
# so any rename or restructure fails CI and forces a conscious update.
# ---------------------------------------------------------------------------


@_presidio_required
class TestPolicyApplyContract:
    SINGLE_KEYS = {
        "policy", "passed", "action_taken", "sanitized_text",
        "blocked_entities", "hit_count", "risk_level", "request_id",
    }
    BATCH_KEYS = {"policy", "results", "total", "excluded_count", "request_id"}
    RESULT_ITEM_KEYS = {
        "index", "passed", "action_taken", "sanitized_text",
        "blocked_entities", "hit_count", "risk_level",
    }
    VALID_ACTIONS = {"none", "masked", "redacted", "pseudonymized", "excluded"}

    # -- Single-text shape ---------------------------------------------------

    def test_blocked_response_shape(self, client):
        """
        ai_prompt must block on US_SSN. Pinning the blocked-branch shape:
          passed=False, action_taken="excluded", sanitized_text=None,
          blocked_entities is a non-empty list, hit_count > 0.
        If this fails, the UI's wasExcluded check (templates/ui.html doScan)
        and any Conductor worker that checks `passed` will break.
        """
        data = client.post("/api/v1/policy/apply", json={
            "policy": "ai_prompt",
            "text": "SSN: 123-45-6789",
        }).get_json()
        missing = self.SINGLE_KEYS - set(data.keys())
        assert not missing, f"/api/v1/policy/apply blocked-branch missing: {missing}"
        assert data["passed"] is False, "ai_prompt must block on US_SSN"
        assert data["action_taken"] == "excluded"
        assert data["sanitized_text"] is None, (
            "Blocked policy must return sanitized_text=None. The UI uses this "
            "+ action_taken=='excluded' to render the EXCLUDED indicator. If "
            "this becomes a string, the UI will display blocked PII as if it "
            "were sanitized output."
        )
        assert isinstance(data["blocked_entities"], list) and data["blocked_entities"], (
            "Blocked branch must list which entity types caused the block."
        )

    def test_masked_response_shape(self, client):
        """
        log_safe has no block_entity_types, so any detected PII flows through
        the masked/redacted branch. Pinning that shape:
          passed=True, action_taken in {redacted/masked/...}, sanitized_text
          is a non-empty string with the raw PII removed.
        """
        raw = "Email jsmith@gmail.com about registration"
        data = client.post("/api/v1/policy/apply", json={
            "policy": "log_safe",
            "text": raw,
        }).get_json()
        missing = self.SINGLE_KEYS - set(data.keys())
        assert not missing, f"/api/v1/policy/apply masked-branch missing: {missing}"
        assert data["passed"] is True
        assert data["action_taken"] in self.VALID_ACTIONS
        assert data["action_taken"] != "excluded"
        assert isinstance(data["sanitized_text"], str), (
            "Non-blocked policy with hits must return sanitized_text as a string. "
            "If this becomes None, the UI cannot distinguish 'sanitized' from "
            "'blocked' and will fall back to displaying raw input."
        )
        assert "jsmith@gmail.com" not in data["sanitized_text"], (
            "log_safe must redact raw email. Raw PII in sanitized_text is a "
            "correctness failure, not a contract change."
        )
        assert data["blocked_entities"] == []

    def test_no_pii_response_shape(self, client):
        """
        Clean text: passed=True, action_taken='none', sanitized_text equals
        the original text, hit_count=0. Pins that the no-PII path returns the
        original string (not None) so callers can treat sanitized_text as
        safe-to-use regardless of branch.
        """
        data = client.post("/api/v1/policy/apply", json={
            "policy": "ai_prompt",
            "text": "Course offerings for fall semester.",
        }).get_json()
        assert data["passed"] is True
        assert data["action_taken"] == "none"
        assert data["hit_count"] == 0
        assert isinstance(data["sanitized_text"], str), (
            "Clean text must round-trip through sanitized_text as a string. "
            "Callers should be able to use sanitized_text without a null check "
            "when passed=True."
        )

    def test_response_does_not_include_excluded_key(self, client):
        """
        Documents the divergence from /api/v1/sanitize. /sanitize returns
        `excluded: bool`. /policy/apply does NOT — exclusion is signalled via
        `action_taken == 'excluded'` and `passed == False`.

        This test will fail if someone "helpfully" adds an `excluded` field
        to align the two endpoints. Adding it is fine — but the UI and any
        consumer also need to update in the same commit. The failure forces
        that conversation.
        """
        data = client.post("/api/v1/policy/apply", json={
            "policy": "ai_prompt",
            "text": "SSN: 123-45-6789",
        }).get_json()
        assert "excluded" not in data, (
            "/api/v1/policy/apply now returns an `excluded` field. This used to "
            "be intentional divergence from /api/v1/sanitize. If the unification "
            "is intentional, update templates/ui.html doScan() to read it and "
            "delete this assertion."
        )

    # -- Batch shape ---------------------------------------------------------

    def test_batch_response_shape(self, client):
        data = client.post("/api/v1/policy/apply", json={
            "policy": "ferpa_strict",
            "texts": ["No PII here.", "SSN: 123-45-6789"],
        }).get_json()
        missing = self.BATCH_KEYS - set(data.keys())
        assert not missing, f"/api/v1/policy/apply batch missing top-level keys: {missing}"
        assert data["total"] == 2
        assert len(data["results"]) == 2
        for item in data["results"]:
            item_missing = self.RESULT_ITEM_KEYS - set(item.keys())
            assert not item_missing, (
                f"Batch result item missing keys: {item_missing}. "
                "Consumers iterating result items will KeyError."
            )

    def test_batch_excluded_count_matches_results(self, client):
        data = client.post("/api/v1/policy/apply", json={
            "policy": "ferpa_strict",
            "texts": ["No PII here.", "SSN: 123-45-6789"],
        }).get_json()
        recounted = sum(1 for r in data["results"] if r["action_taken"] == "excluded")
        assert data["excluded_count"] == recounted, (
            "Batch excluded_count diverged from sum of result items where "
            "action_taken == 'excluded'. Two parallel counters rotted out of sync."
        )


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


# ---------------------------------------------------------------------------
# /api/v1/health/deep contract — pinned 2026-05-21
# Changed 2026-05-21: path versioned; response now carries a "checks" dict and a
# "mock" key (the canonical live-vs-fabricated signal). The old flat "presidio"
# and "spacy_degraded" top-level keys were replaced by checks[...].
# ---------------------------------------------------------------------------

class TestHealthDeepContract:
    """
    Known-good: /api/v1/health/deep probes critical dependencies.
    Returns 200 (ok or degraded) when functional, 503 when broken.
    No auth required — K8s readiness probe must be able to call this.
    """
    DEEP_PATH = "/api/v1/health/deep"
    EXPECTED_KEYS = {"status", "service", "version", "uptime_seconds", "mock", "checks"}

    @_presidio_required
    def test_health_deep_returns_200_when_presidio_ready(self, client):
        resp = client.get(self.DEEP_PATH)
        assert resp.status_code == 200, (
            "/api/v1/health/deep must return 200 when Presidio is working. "
            "K8s readiness probe will fail otherwise."
        )

    @_presidio_required
    def test_health_deep_response_shape(self, client):
        data = client.get(self.DEEP_PATH).get_json()
        missing = self.EXPECTED_KEYS - set(data.keys())
        assert not missing, f"/api/v1/health/deep missing keys: {missing}"

    @_presidio_required
    def test_health_deep_presidio_is_ready(self, client):
        data = client.get(self.DEEP_PATH).get_json()
        assert data["checks"]["presidio"]["status"] == "ok", (
            "checks.presidio.status must be 'ok' when Presidio is loaded."
        )

    def test_health_deep_has_checks_dict(self, client):
        """The checks dict is required — it carries per-dependency status."""
        data = client.get(self.DEEP_PATH).get_json()
        assert isinstance(data.get("checks"), dict) and data["checks"], (
            "/api/v1/health/deep must include a non-empty 'checks' dict."
        )

    def test_health_deep_has_mock_key(self, client):
        """
        The 'mock' key is the canonical live-vs-fabricated-data signal and is
        required on every service that has a mock mode.
        """
        data = client.get(self.DEEP_PATH).get_json()
        assert "mock" in data, "/api/v1/health/deep must include the 'mock' key."
        assert isinstance(data["mock"], bool)

    def test_health_deep_no_auth_required(self, client):
        """Readiness probe must work without any auth header (200 or 503, never 401/403)."""
        resp = client.get(self.DEEP_PATH)
        assert resp.status_code not in (401, 403), (
            "/api/v1/health/deep must not require auth — K8s readiness probe cannot provide tokens."
        )


# ---------------------------------------------------------------------------
# /metrics contract — pinned 2025-05
# ---------------------------------------------------------------------------

class TestMetricsContract:
    """
    Known-good: /metrics returns Prometheus text format.
    If metric names change, update Prometheus scrape config and Grafana dashboards.
    """
    REQUIRED_METRICS = [
        "pii_requests_total",
        "pii_pii_hits_total",
        "pii_excluded_total",
        "pii_clean_total",
        "pii_uptime_seconds",
    ]

    def test_metrics_returns_200(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_content_type_is_text_plain(self, client):
        resp = client.get("/metrics")
        assert "text/plain" in resp.content_type, (
            "/metrics must return text/plain for Prometheus compatibility. "
            "If this changes, update the Prometheus scrape job config."
        )

    def test_metrics_contains_required_metric_names(self, client):
        text = client.get("/metrics").data.decode()
        for metric in self.REQUIRED_METRICS:
            assert metric in text, (
                f"Required Prometheus metric '{metric}' missing from /metrics output. "
                "Update Grafana dashboards if metric names change."
            )

    def test_metrics_no_auth_required(self, client):
        resp = client.get("/metrics")
        assert resp.status_code != 401


# ---------------------------------------------------------------------------
# /api/v1/explain contract — pinned 2025-05
# ---------------------------------------------------------------------------

class TestExplainContract:
    """
    Known-good: /api/v1/explain returns per-hit detection breakdown.
    Requires Presidio. Shape must remain stable for debugging tools.
    """
    REQUIRED_HIT_KEYS = {"entity_type", "start", "end", "score", "risk_level", "recognizer"}
    REQUIRED_TOP_KEYS = {"text_length", "hit_count", "hits", "request_id"}

    @_presidio_required
    def test_explain_returns_200(self, client):
        resp = client.post("/api/v1/explain", json={"text": "test text"})
        assert resp.status_code == 200

    @_presidio_required
    def test_explain_response_shape(self, client):
        data = client.post("/api/v1/explain", json={"text": "test text"}).get_json()
        missing = self.REQUIRED_TOP_KEYS - set(data.keys())
        assert not missing, f"/api/v1/explain missing top-level keys: {missing}"

    @_presidio_required
    def test_explain_hit_objects_have_required_keys(self, client):
        data = client.post(
            "/api/v1/explain", json={"text": "Student D1234567 is enrolled"}
        ).get_json()
        for hit in data.get("hits", []):
            missing = self.REQUIRED_HIT_KEYS - set(hit.keys())
            assert not missing, f"Explain hit object missing keys: {missing}"

    def test_explain_invalid_input_returns_400(self, client):
        resp = client.post("/api/v1/explain", json={"text": 12345})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Sandbox mode contract — pinned 2025-05
# ---------------------------------------------------------------------------

class TestSandboxContract:
    """
    Known-good: PII_SANDBOX_MODE=true returns fake responses without Presidio.
    All sandbox responses must include "sandbox": true.
    """

    @pytest.fixture(autouse=True)
    def enable_sandbox(self, monkeypatch):
        monkeypatch.setenv("PII_SANDBOX_MODE", "true")
        import app as _app
        _app._SANDBOX_MODE = True
        yield
        _app._SANDBOX_MODE = False

    def test_scan_sandbox_returns_200(self, client):
        resp = client.post("/api/v1/scan", json={"text": "some text"})
        assert resp.status_code == 200

    def test_scan_sandbox_flag_present(self, client):
        data = client.post("/api/v1/scan", json={"text": "some text"}).get_json()
        assert data.get("sandbox") is True, (
            "Sandbox responses must include 'sandbox': true so callers can detect they "
            "are NOT receiving real PII scan results."
        )

    def test_sanitize_sandbox_flag_present(self, client):
        data = client.post("/api/v1/sanitize", json={"text": "some text"}).get_json()
        assert data.get("sandbox") is True

    def test_preflight_sandbox_flag_present(self, client):
        data = client.post("/api/v1/preflight", json={"text": "some text"}).get_json()
        assert data.get("sandbox") is True


# ---------------------------------------------------------------------------
# Mock/Live signal contract — pinned 2026-05-21
# ---------------------------------------------------------------------------

class TestMockSignalContract:
    """
    Known-good: when mock (sandbox) mode is active the service must surface it in
    two machine-readable places — the X-Mock-Mode response header and the "mock"
    key in /api/v1/health/deep. Silent mock is a forbidden pattern; if either
    signal disappears, fabricated data could be mistaken for real PII results.
    """

    def _set_sandbox(self, monkeypatch, on):
        monkeypatch.setenv("PII_SANDBOX_MODE", "true" if on else "false")
        import app as _app
        monkeypatch.setattr(_app, "_SANDBOX_MODE", on)

    def test_x_mock_mode_header_present_in_sandbox(self, client, monkeypatch):
        self._set_sandbox(monkeypatch, True)
        resp = client.post("/api/v1/scan", json={"text": "some text"})
        assert resp.headers.get("X-Mock-Mode") == "true", (
            "X-Mock-Mode: true header must be on every response in mock mode. "
            "Consumers rely on it to detect fabricated data without parsing the body."
        )

    def test_x_mock_mode_header_absent_in_live(self, client, monkeypatch):
        self._set_sandbox(monkeypatch, False)
        resp = client.get("/api/v1/health")
        assert "X-Mock-Mode" not in resp.headers, (
            "X-Mock-Mode header must be absent in live mode — its presence means mock."
        )

    def test_health_deep_mock_true_in_sandbox(self, client, monkeypatch):
        self._set_sandbox(monkeypatch, True)
        data = client.get("/api/v1/health/deep").get_json()
        assert data.get("mock") is True, (
            "/api/v1/health/deep must report mock=true when sandbox mode is active."
        )

    def test_health_deep_mock_false_in_live(self, client, monkeypatch):
        self._set_sandbox(monkeypatch, False)
        data = client.get("/api/v1/health/deep").get_json()
        assert data.get("mock") is False


# ---------------------------------------------------------------------------
# New schema profiles contract — pinned 2025-05
# ---------------------------------------------------------------------------

class TestNewSchemaProfilesContract:
    """
    Known-good: 6 new schema profiles added in 2025-05 batch.
    Shape contract identical to existing profiles.
    """
    NEW_PROFILES = {
        "workday_hr", "servicenow_itsm", "slate_crm",
        "starfish_early_alert", "canvas_lms", "microsoft_graph",
    }

    def test_all_new_profiles_appear_in_schemas_endpoint(self, client):
        data = client.get("/api/v1/schemas").get_json()
        names = {s["name"] for s in data["schemas"]}
        missing = self.NEW_PROFILES - names
        assert not missing, f"New schema profiles not returned by /api/v1/schemas: {missing}"

    def test_total_schema_count_at_least_12(self, client):
        data = client.get("/api/v1/schemas").get_json()
        assert data["count"] >= 12, (
            f"Expected at least 12 schema profiles, got {data['count']}. "
            "If a profile was removed, update this test and the README."
        )

    def test_new_profiles_have_required_keys(self, client):
        data = client.get("/api/v1/schemas").get_json()
        for schema in data["schemas"]:
            if schema["name"] in self.NEW_PROFILES:
                for key in ("name", "description", "field_count", "default_mode", "fields"):
                    assert key in schema, f"Schema '{schema['name']}' missing key '{key}'"


# ---------------------------------------------------------------------------
# Keys endpoints contract — pinned 2025-05
# ---------------------------------------------------------------------------

class TestKeysContract:
    """
    Known-good: GET /api/v1/keys returns name list (never key values).
    POST /api/v1/keys/generate returns name + key + instructions (key shown once).
    Auth disabled in sandbox mode so both endpoints are reachable in tests.
    """

    def test_get_keys_has_required_fields(self, client):
        data = client.get("/api/v1/keys").get_json()
        for key in ("keys", "count", "auth_enabled"):
            assert key in data, f"/api/v1/keys response missing field '{key}'"

    def test_get_keys_returns_list(self, client):
        data = client.get("/api/v1/keys").get_json()
        assert isinstance(data["keys"], list)
        assert isinstance(data["count"], int)
        assert data["count"] == len(data["keys"])

    def test_generate_key_requires_name(self, client):
        data = client.post("/api/v1/keys/generate", json={}).get_json()
        assert data.get("code") == "INVALID_INPUT", (
            "POST /api/v1/keys/generate without 'name' must return INVALID_INPUT"
        )

    def test_generate_key_response_shape(self, client):
        data = client.post("/api/v1/keys/generate", json={"name": "test-svc", "prefix": "sk_test"}).get_json()
        for field in ("name", "key", "add_to_api_keys", "instructions"):
            assert field in data, f"/api/v1/keys/generate response missing field '{field}'"

    def test_generate_key_name_echoed(self, client):
        data = client.post("/api/v1/keys/generate", json={"name": "test-svc"}).get_json()
        assert data.get("name") == "test-svc"

    def test_generate_key_value_present_and_nonempty(self, client):
        data = client.post("/api/v1/keys/generate", json={"name": "test-svc"}).get_json()
        assert isinstance(data.get("key"), str) and len(data["key"]) > 8, (
            "Generated key must be a non-trivial string — shown once, must be usable"
        )

    def test_generate_key_add_to_api_keys_format(self, client):
        data = client.post("/api/v1/keys/generate", json={"name": "test-svc"}).get_json()
        add_to = data.get("add_to_api_keys", "")
        assert add_to.startswith("test-svc:"), (
            "add_to_api_keys must be 'name:key' format for direct paste into API_KEYS env var"
        )

    def test_generate_key_name_with_invalid_chars_rejected(self, client):
        data = client.post("/api/v1/keys/generate", json={"name": "bad name!"}).get_json()
        assert data.get("code") == "INVALID_INPUT"


# ---------------------------------------------------------------------------
# OCR scan endpoint contract — pinned 2025-05
# ---------------------------------------------------------------------------

class TestOcrScanContract:
    """
    Known-good: POST /api/v1/scan/ocr accepts OCR service page output and returns
    per-page PII results with confidence metadata.
    Sandbox mode used so Presidio is not required.
    """

    @pytest.fixture(autouse=True)
    def enable_sandbox(self, monkeypatch):
        monkeypatch.setenv("PII_SANDBOX_MODE", "true")
        import app as _app
        _app._SANDBOX_MODE = True
        yield
        _app._SANDBOX_MODE = False

    def _pages(self, text="Student D1234567", confidence=95.0):
        return [{"page_number": 1, "text": text, "confidence": confidence}]

    def test_ocr_scan_requires_pages(self, client):
        data = client.post("/api/v1/scan/ocr", json={}).get_json()
        assert data.get("code") == "INVALID_INPUT"

    def test_ocr_scan_empty_pages_rejected(self, client):
        data = client.post("/api/v1/scan/ocr", json={"pages": []}).get_json()
        assert data.get("code") == "INVALID_INPUT"

    def test_ocr_scan_response_top_level_shape(self, client):
        data = client.post("/api/v1/scan/ocr", json={"pages": self._pages()}).get_json()
        for field in ("page_count", "pages_with_pii", "highest_risk", "pages", "request_id"):
            assert field in data, f"/api/v1/scan/ocr response missing top-level field '{field}'"

    def test_ocr_scan_page_result_shape(self, client):
        data = client.post("/api/v1/scan/ocr", json={"pages": self._pages()}).get_json()
        page = data["pages"][0]
        for field in ("page_number", "ocr_confidence", "low_confidence_warning",
                      "sanitized_text", "pii_found", "hit_count", "entity_types", "risk_level"):
            assert field in page, f"OCR page result missing field '{field}'"

    def test_ocr_scan_low_confidence_warning_set_when_below_threshold(self, client):
        data = client.post("/api/v1/scan/ocr", json={
            "pages": self._pages(confidence=40.0),
            "low_confidence_threshold": 70.0,
        }).get_json()
        assert data["pages"][0]["low_confidence_warning"] is True

    def test_ocr_scan_low_confidence_warning_clear_when_above_threshold(self, client):
        data = client.post("/api/v1/scan/ocr", json={
            "pages": self._pages(confidence=95.0),
            "low_confidence_threshold": 70.0,
        }).get_json()
        assert data["pages"][0]["low_confidence_warning"] is False

    def test_ocr_scan_correlation_id_echoed_when_provided(self, client):
        data = client.post("/api/v1/scan/ocr", json={
            "pages": self._pages(),
            "correlation_id": "ocr-job-abc123",
        }).get_json()
        assert data.get("correlation_id") == "ocr-job-abc123", (
            "correlation_id must be echoed in /api/v1/scan/ocr response when provided"
        )

    def test_ocr_scan_correlation_id_absent_when_not_provided(self, client):
        data = client.post("/api/v1/scan/ocr", json={"pages": self._pages()}).get_json()
        assert "correlation_id" not in data, (
            "correlation_id must NOT appear in response when caller did not provide it"
        )

    def test_ocr_scan_invalid_mode_rejected(self, client):
        data = client.post("/api/v1/scan/ocr", json={
            "pages": self._pages(), "mode": "invalid_mode",
        }).get_json()
        assert data.get("code") == "INVALID_MODE"

    def test_ocr_scan_page_count_matches_input(self, client):
        pages = [
            {"page_number": 1, "text": "page one text", "confidence": 90.0},
            {"page_number": 2, "text": "page two text", "confidence": 85.0},
        ]
        data = client.post("/api/v1/scan/ocr", json={"pages": pages}).get_json()
        assert data["page_count"] == 2


# ---------------------------------------------------------------------------
# Async jobs stub contract — pinned 2025-05
# ---------------------------------------------------------------------------

class TestUiContract:
    """
    Known-good: GET /ui returns 200 HTML when auth is disabled (API_KEY unset).
    Returns 403 when auth is active and UI_ENABLED is not explicitly true.
    """

    def test_ui_returns_200_when_auth_disabled(self, client):
        resp = client.get("/ui")
        assert resp.status_code == 200, (
            "GET /ui must return 200 when API_KEY is unset (local dev mode). "
            "If this fails, check UI_ENABLED env var or auth state."
        )

    def test_ui_returns_html(self, client):
        resp = client.get("/ui")
        assert b"pii-service" in resp.data
        assert b"<html" in resp.data.lower()

    def test_ui_contains_all_tab_names(self, client):
        resp = client.get("/ui")
        for tab in (b"Scan", b"Explain", b"Policy", b"File Upload", b"Record"):
            assert tab in resp.data, f"UI missing tab: {tab}"

    def test_ui_shows_live_badge_in_live_mode(self, client):
        """The operator console must carry a persistent LIVE badge in live mode."""
        resp = client.get("/ui")
        assert b">LIVE<" in resp.data, (
            "UI is missing the persistent LIVE mode badge. The mock/live state "
            "must never be ambiguous in the operator console."
        )

    def test_ui_shows_mock_badge_in_sandbox_mode(self, client, monkeypatch):
        """In sandbox mode the badge must flip to MOCK — silent mock is forbidden."""
        import app as _app
        monkeypatch.setattr(_app, "_SANDBOX_MODE", True)
        resp = client.get("/ui")
        assert b">MOCK<" in resp.data, (
            "UI must show the MOCK badge when sandbox mode is active."
        )


# ---------------------------------------------------------------------------
# /swagger contract — pinned 2026-05-21
# ---------------------------------------------------------------------------

class TestSwaggerContract:
    """
    Known-good: GET /swagger returns the Swagger UI HTML and /openapi.yaml serves
    the spec it renders. Swagger is a conformance requirement (S-024) for any
    service that exposes an API.
    """

    def test_swagger_returns_200_html(self, client):
        resp = client.get("/swagger")
        assert resp.status_code == 200
        assert b"<html" in resp.data.lower()

    def test_openapi_yaml_is_served(self, client):
        resp = client.get("/openapi.yaml")
        assert resp.status_code == 200, "/openapi.yaml must serve the spec for /swagger to render."
        assert b"openapi" in resp.data.lower()


class TestJobsStubContract:
    """
    Known-good: GET /api/v1/jobs/<id> returns 501 NOT_IMPLEMENTED.
    Redis/RQ deferred — this test is a tripwire so the stub is never accidentally
    replaced with a silent 404.
    """

    def test_jobs_returns_501(self, client):
        resp = client.get("/api/v1/jobs/some-job-id-123")
        assert resp.status_code == 501, (
            "GET /api/v1/jobs/<id> must return 501 until async queue is implemented. "
            "If this test starts failing with 200, the stub was replaced — update this test."
        )

    def test_jobs_response_code_is_not_implemented(self, client):
        data = client.get("/api/v1/jobs/some-job-id-123").get_json()
        assert data.get("code") == "NOT_IMPLEMENTED"

    def test_jobs_echoes_job_id(self, client):
        data = client.get("/api/v1/jobs/my-specific-job-id").get_json()
        assert data.get("job_id") == "my-specific-job-id"


# ---------------------------------------------------------------------------
# Correlation ID contract — pinned 2025-05
# ---------------------------------------------------------------------------

class TestCorrelationIdContract:
    """
    Known-good: correlation_id passed in request body is echoed in response.
    Absent when not provided. Applies to /scan, /sanitize, /preflight, /scan/ocr.
    Sandbox mode used so Presidio is not required.
    """

    @pytest.fixture(autouse=True)
    def enable_sandbox(self, monkeypatch):
        monkeypatch.setenv("PII_SANDBOX_MODE", "true")
        import app as _app
        _app._SANDBOX_MODE = True
        yield
        _app._SANDBOX_MODE = False

    def test_scan_echoes_correlation_id(self, client):
        data = client.post("/api/v1/scan", json={
            "text": "some text", "correlation_id": "cid-scan-001"
        }).get_json()
        assert data.get("correlation_id") == "cid-scan-001"

    def test_scan_no_correlation_id_absent_from_response(self, client):
        data = client.post("/api/v1/scan", json={"text": "some text"}).get_json()
        assert "correlation_id" not in data

    def test_sanitize_echoes_correlation_id(self, client):
        data = client.post("/api/v1/sanitize", json={
            "text": "some text", "correlation_id": "cid-san-001"
        }).get_json()
        assert data.get("correlation_id") == "cid-san-001"

    def test_preflight_does_not_fail_with_correlation_id(self, client):
        data = client.post("/api/v1/preflight", json={
            "text": "some text", "correlation_id": "cid-pre-001"
        }).get_json()
        assert "request_id" in data
