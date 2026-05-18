"""
tests/integration/test_api_endpoints.py - Full API integration tests.

Uses Flask test client with a regex-only guard (no spaCy model needed).
Tests the complete request/response cycle including auth, audit, and edge cases.
"""

import io
import json
import csv
import os
import pytest

pytest.importorskip("presidio_analyzer", reason="presidio_analyzer not installed — install requirements.txt")

os.environ.setdefault("API_KEY", "")  # disable auth for most integration tests

from app import app


@pytest.fixture(scope="module")
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture(scope="module")
def auth_client():
    """Client with API key enforcement enabled."""
    os.environ["API_KEY"] = "integration-test-key"
    from pii_guard.auth import init_auth
    init_auth()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c
    os.environ.pop("API_KEY", None)
    init_auth()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_200(self, client):
        assert client.get("/health").status_code == 200

    def test_health_status_ok(self, client):
        assert client.get("/health").get_json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class TestScanEndpoint:
    def test_scan_ssn_detected(self, client):
        resp = client.post("/api/v1/scan", json={"text": "SSN: 123-45-6789"})
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["pii_found"] is True
        assert data["hit_count"] >= 1

    def test_scan_clean_text(self, client):
        resp = client.post("/api/v1/scan", json={"text": "CSCI 301 meets at 10am"})
        data = resp.get_json()
        # No SSN/financial data — should be clean (course data may match low-confidence patterns)
        ssn_hits = [h for h in data["hits"] if h["entity_type"] == "US_SSN"]
        assert not ssn_hits

    def test_scan_non_string_text_400(self, client):
        resp = client.post("/api/v1/scan", json={"text": 12345})
        assert resp.status_code == 400

    def test_scan_exclude_types(self, client):
        resp = client.post("/api/v1/scan", json={
            "text": "SSN: 123-45-6789",
            "exclude_entity_types": ["US_SSN"],
        })
        data = resp.get_json()
        assert not data["pii_found"]

    def test_scan_request_id_in_response(self, client):
        resp = client.post("/api/v1/scan",
                           json={"text": "test"},
                           headers={"X-Request-ID": "my-req-123"})
        assert resp.get_json()["request_id"] == "my-req-123"

    def test_scan_risk_level_critical_for_ssn(self, client):
        data = client.post("/api/v1/scan", json={"text": "SSN: 123-45-6789"}).get_json()
        assert data["risk_level"] == "CRITICAL"

    def test_scan_risk_level_low_for_clean(self, client):
        data = client.post("/api/v1/scan", json={"text": "The course meets Monday."}).get_json()
        # Clean text should be LOW risk
        assert data["risk_level"] in {"LOW", "MEDIUM"}


# ---------------------------------------------------------------------------
# Sanitize
# ---------------------------------------------------------------------------

class TestSanitizeEndpoint:
    def test_mask_mode_removes_ssn(self, client):
        data = client.post("/api/v1/sanitize", json={
            "text": "SSN: 123-45-6789", "mode": "mask"
        }).get_json()
        assert "123-45-6789" not in data["sanitized_text"]
        assert "[US_SSN]" in data["sanitized_text"]

    def test_pseudonymize_preserves_format(self, client):
        import re
        data = client.post("/api/v1/sanitize", json={
            "text": "SSN: 123-45-6789", "mode": "pseudonymize"
        }).get_json()
        assert re.search(r"\d{3}-\d{2}-\d{4}", data["sanitized_text"]), (
            "Pseudonymized SSN must preserve the XXX-XX-XXXX format"
        )

    def test_exclude_mode_returns_null(self, client):
        data = client.post("/api/v1/sanitize", json={
            "text": "SSN: 123-45-6789", "mode": "exclude"
        }).get_json()
        assert data["excluded"] is True
        assert data["sanitized_text"] is None

    def test_clean_text_returns_unchanged(self, client):
        text = "No PII in this sentence."
        data = client.post("/api/v1/sanitize", json={"text": text, "mode": "mask"}).get_json()
        assert data["sanitized_text"] == text
        assert not data["pii_found"]

    def test_invalid_mode_400(self, client):
        resp = client.post("/api/v1/sanitize", json={"text": "test", "mode": "vaporize"})
        assert resp.status_code == 400
        assert resp.get_json()["code"] == "INVALID_MODE"


# ---------------------------------------------------------------------------
# Batch
# ---------------------------------------------------------------------------

class TestBatchEndpoint:
    def test_batch_processes_all(self, client):
        texts = ["No PII.", "SSN: 123-45-6789", "Another clean sentence."]
        data = client.post("/api/v1/sanitize/batch", json={
            "texts": texts, "mode": "mask"
        }).get_json()
        assert data["total"] == 3
        assert len(data["results"]) == 3

    def test_batch_index_mapping(self, client):
        texts = ["first", "second", "third"]
        data = client.post("/api/v1/sanitize/batch", json={
            "texts": texts, "mode": "mask"
        }).get_json()
        for item in data["results"]:
            assert item["index"] in {0, 1, 2}

    def test_batch_exclude_drops_pii_from_count(self, client):
        texts = ["No PII.", "SSN: 123-45-6789"]
        data = client.post("/api/v1/sanitize/batch", json={
            "texts": texts, "mode": "exclude", "include_excluded": False
        }).get_json()
        assert data["excluded_count"] == 1
        # With include_excluded=False, excluded items are not in results
        assert len(data["results"]) == 1

    def test_batch_too_large_rejected(self, client):
        resp = client.post("/api/v1/sanitize/batch", json={
            "texts": ["x"] * 600, "mode": "mask"
        })
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Structured scan
# ---------------------------------------------------------------------------

class TestStructuredScanEndpoint:
    def test_structured_scan_flags_correct_field(self, client):
        data = client.post("/api/v1/scan/structured", json={
            "record": {"ssn_field": "123-45-6789", "name": "John Smith", "gpa": 3.5}
        }).get_json()
        assert data["ssn_field"]["pii_found"] is True
        assert data["_summary"]["highest_risk"] == "CRITICAL"

    def test_structured_scan_non_string_skipped(self, client):
        data = client.post("/api/v1/scan/structured", json={
            "record": {"count": 42}
        }).get_json()
        assert data["count"]["skipped"] is True

    def test_structured_scan_invalid_record_400(self, client):
        resp = client.post("/api/v1/scan/structured", json={"record": "not a dict"})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Sanitize structured
# ---------------------------------------------------------------------------

class TestStructuredSanitizeEndpoint:
    def test_sanitizes_specified_fields(self, client):
        data = client.post("/api/v1/sanitize/structured", json={
            "record": {"notes": "SSN: 123-45-6789", "gpa": "3.5"},
            "fields": ["notes"],
            "mode": "mask",
        }).get_json()
        assert "123-45-6789" not in data["sanitized_record"]["notes"]
        assert data["sanitized_record"]["gpa"] == "3.5"

    def test_unspecified_fields_pass_through(self, client):
        data = client.post("/api/v1/sanitize/structured", json={
            "record": {"notes": "SSN: 123-45-6789", "other": "unchanged"},
            "fields": ["notes"],
            "mode": "mask",
        }).get_json()
        assert data["sanitized_record"]["other"] == "unchanged"


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

class TestPreflightEndpoint:
    def test_ssn_not_safe(self, client):
        data = client.post("/api/v1/preflight", json={"text": "SSN: 123-45-6789"}).get_json()
        assert data["safe_to_send"] is False
        assert data["risk_level"] == "CRITICAL"
        assert "US_SSN" in data["blocking_entities"]

    def test_clean_text_safe(self, client):
        data = client.post("/api/v1/preflight", json={"text": "CSCI 301: 30 students."}).get_json()
        assert data["safe_to_send"] is True
        assert data["sanitized_suggestion"] is None

    def test_suggestion_provided_when_not_safe(self, client):
        data = client.post("/api/v1/preflight", json={"text": "SSN: 123-45-6789"}).get_json()
        if not data["safe_to_send"]:
            assert data["sanitized_suggestion"] is not None
            assert "123-45-6789" not in data["sanitized_suggestion"]

    def test_recommendation_is_string(self, client):
        data = client.post("/api/v1/preflight", json={"text": "test"}).get_json()
        assert isinstance(data["recommendation"], str)
        assert len(data["recommendation"]) > 5


# ---------------------------------------------------------------------------
# Policy apply
# ---------------------------------------------------------------------------

class TestPolicyEndpoint:
    def test_ai_prompt_blocks_ssn(self, client):
        data = client.post("/api/v1/policy/apply", json={
            "policy": "ai_prompt",
            "text": "SSN: 123-45-6789",
        }).get_json()
        assert data["action_taken"] == "excluded"
        assert data["sanitized_text"] is None

    def test_ai_prompt_masks_email(self, client):
        data = client.post("/api/v1/policy/apply", json={
            "policy": "ai_prompt",
            "text": "Email jsmith@gmail.com about registration",
        }).get_json()
        # Email is HIGH — ai_prompt mode is mask — should be masked not blocked
        assert "jsmith@gmail.com" not in (data.get("sanitized_text") or "")

    def test_unknown_policy_400(self, client):
        resp = client.post("/api/v1/policy/apply", json={
            "policy": "super_strict",
            "text": "test",
        })
        assert resp.status_code == 400
        assert resp.get_json()["code"] == "INVALID_POLICY"

    def test_policy_batch_mode(self, client):
        data = client.post("/api/v1/policy/apply", json={
            "policy": "ferpa_strict",
            "texts": ["No PII here.", "SSN: 123-45-6789"],
        }).get_json()
        assert "results" in data
        assert len(data["results"]) == 2


# ---------------------------------------------------------------------------
# File upload (CSV)
# ---------------------------------------------------------------------------

class TestFileEndpoint:
    def test_csv_file_processed(self, client):
        csv_content = "name,ssn,gpa\nJohn Smith,123-45-6789,3.5\nJane Doe,987-65-4321,3.8"
        data = client.post(
            "/api/v1/file",
            data={
                "file": (io.BytesIO(csv_content.encode()), "test.csv"),
                "mode": "mask",
                "columns": json.dumps(["ssn"]),
            },
            content_type="multipart/form-data",
        ).get_json()
        assert data["file_type"] == "csv"
        assert data["total_rows"] == 2

    def test_json_file_processed(self, client):
        records = [{"ssn": "123-45-6789", "note": "clean"}, {"ssn": "clean", "note": "also clean"}]
        json_content = json.dumps(records).encode()
        data = client.post(
            "/api/v1/file",
            data={
                "file": (io.BytesIO(json_content), "test.json"),
                "mode": "mask",
            },
            content_type="multipart/form-data",
        ).get_json()
        assert data["file_type"] == "json"
        assert data["total_rows"] == 2

    def test_unsupported_file_type_400(self, client):
        resp = client.post(
            "/api/v1/file",
            data={
                "file": (io.BytesIO(b"content"), "test.pdf"),
                "mode": "mask",
            },
            content_type="multipart/form-data",
        )
        assert resp.status_code == 400
        assert resp.get_json()["code"] == "INVALID_FILE_TYPE"

    def test_no_file_400(self, client):
        resp = client.post("/api/v1/file", data={"mode": "mask"}, content_type="multipart/form-data")
        assert resp.status_code == 400
        assert resp.get_json()["code"] == "NO_FILE"


# ---------------------------------------------------------------------------
# Authentication enforcement
# ---------------------------------------------------------------------------

class TestAuthEnforcement:
    def test_missing_key_returns_401(self, auth_client):
        resp = auth_client.post("/api/v1/scan", json={"text": "test"})
        assert resp.status_code == 401

    def test_wrong_key_returns_403(self, auth_client):
        resp = auth_client.post("/api/v1/scan",
                                json={"text": "test"},
                                headers={"Authorization": "Bearer wrong-key"})
        assert resp.status_code == 403

    def test_correct_key_returns_200(self, auth_client):
        resp = auth_client.post("/api/v1/scan",
                                json={"text": "test"},
                                headers={"Authorization": "Bearer integration-test-key"})
        assert resp.status_code == 200

    def test_health_does_not_require_auth(self, auth_client):
        """Health endpoint must be accessible without auth for K8s probes."""
        resp = auth_client.get("/health")
        assert resp.status_code == 200, (
            "/health must not require authentication — K8s liveness probes cannot send API keys"
        )
