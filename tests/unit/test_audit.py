"""
tests/unit/test_audit.py - Unit tests for the audit logging module.
"""

import pytest
from pii_guard import audit


def _emit(overrides: dict = None):
    base = {
        "endpoint": "/api/v1/scan",
        "request_id": "test-req-1",
        "client_ip": "127.0.0.1",
        "api_key_prefix": None,
        "mode": "scan",
        "hit_count": 2,
        "excluded_count": 0,
        "entity_types": ["US_SSN", "PERSON"],
        "risk_level": "CRITICAL",
        "duration_ms": 12.5,
        "action": "scan",
    }
    if overrides:
        base.update(overrides)
    audit.log_event(**base)


class TestAuditStats:
    def test_stats_has_required_keys(self):
        stats = audit.get_stats()
        required = [
            "total_requests", "total_pii_hits", "total_excluded", "total_clean",
            "entity_type_counts", "mode_counts", "risk_level_counts",
            "endpoint_counts", "uptime_seconds",
        ]
        for key in required:
            assert key in stats, f"Stats missing key '{key}'"

    def test_emit_increments_total_requests(self):
        before = audit.get_stats()["total_requests"]
        _emit()
        after = audit.get_stats()["total_requests"]
        assert after == before + 1

    def test_emit_accumulates_hits(self):
        before = audit.get_stats()["total_pii_hits"]
        _emit({"hit_count": 5})
        after = audit.get_stats()["total_pii_hits"]
        assert after == before + 5

    def test_emit_accumulates_excluded(self):
        before = audit.get_stats()["total_excluded"]
        _emit({"excluded_count": 3})
        after = audit.get_stats()["total_excluded"]
        assert after == before + 3

    def test_entity_type_counts_accumulated(self):
        before = dict(audit.get_stats()["entity_type_counts"])
        _emit({"entity_types": ["FERPA_MARKER"]})
        after = audit.get_stats()["entity_type_counts"]
        assert after.get("FERPA_MARKER", 0) >= before.get("FERPA_MARKER", 0) + 1

    def test_stats_snapshot_is_independent(self):
        """Modifying the returned dict should not affect internal state."""
        stats = audit.get_stats()
        original_count = stats["total_requests"]
        stats["total_requests"] = 99999
        assert audit.get_stats()["total_requests"] == original_count

    def test_uptime_seconds_positive(self):
        assert audit.get_stats()["uptime_seconds"] > 0

    def test_emit_with_policy_name(self):
        before = audit.get_stats()["total_requests"]
        _emit({"action": "masked", "policy_name": "ai_prompt"})
        assert audit.get_stats()["total_requests"] == before + 1
