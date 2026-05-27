"""
tests/unit/test_audit.py - Unit tests for the audit logging module.
"""

import dataclasses

import pytest
from pii_guard import audit
from pii_guard.audit import AuditEvent


def _emit(overrides: dict = None) -> AuditEvent:
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
    return audit.log_event(**base)


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

    def test_uptime_seconds_is_non_negative_int(self):
        """
        uptime_seconds is an integer count of seconds. It is legitimately 0
        during the first second of process life — assert >= 0, not > 0.
        """
        uptime = audit.get_stats()["uptime_seconds"]
        assert isinstance(uptime, int) and not isinstance(uptime, bool)
        assert uptime >= 0

    def test_emit_with_policy_name(self):
        before = audit.get_stats()["total_requests"]
        _emit({"action": "masked", "policy_name": "ai_prompt"})
        assert audit.get_stats()["total_requests"] == before + 1

    def test_emit_with_subject_id_and_destination(self):
        before = audit.get_stats()["total_requests"]
        _emit({"subject_id": "hashed-pidm-abc", "destination": "openai-gpt4"})
        assert audit.get_stats()["total_requests"] == before + 1

    def test_emit_with_caller_name(self):
        """caller_name (named API key label) must be accepted without error."""
        before = audit.get_stats()["total_requests"]
        _emit({"caller_name": "n8n-prod"})
        assert audit.get_stats()["total_requests"] == before + 1

    def test_emit_with_correlation_id(self):
        """correlation_id (opaque caller-supplied GUID) must be accepted without error."""
        before = audit.get_stats()["total_requests"]
        _emit({"correlation_id": "colleague-personid-1234567"})
        assert audit.get_stats()["total_requests"] == before + 1

    def test_emit_caller_name_none_accepted(self):
        """None caller_name (auth disabled or key unnamed) must not raise."""
        before = audit.get_stats()["total_requests"]
        _emit({"caller_name": None})
        assert audit.get_stats()["total_requests"] == before + 1

    def test_emit_correlation_id_none_accepted(self):
        """None correlation_id (caller did not supply one) must not raise."""
        before = audit.get_stats()["total_requests"]
        _emit({"correlation_id": None})
        assert audit.get_stats()["total_requests"] == before + 1


class TestAuditEvent:
    """
    The canonical frozen AuditEvent shape. log_event builds one per request.
    The frozen dataclass — not an inline dict — is the standard so the audit
    trail migrates to a shared doane-audit library as a find-replace.
    """

    CANONICAL_FIELDS = {
        "action", "actor", "resource_type", "resource_id",
        "outcome", "detail", "correlation_id", "occurred_at",
    }

    def test_event_has_canonical_fields(self):
        names = {f.name for f in dataclasses.fields(AuditEvent)}
        assert names == self.CANONICAL_FIELDS, (
            f"AuditEvent fields drifted from the canonical shape. Got {names}."
        )

    def test_event_is_frozen(self):
        ev = _emit()
        with pytest.raises(dataclasses.FrozenInstanceError):
            ev.action = "tampered"

    def test_log_event_returns_audit_event(self):
        assert isinstance(_emit(), AuditEvent)

    def test_actor_from_caller_name(self):
        assert _emit({"caller_name": "n8n-prod"}).actor == "n8n-prod"

    def test_actor_defaults_to_system(self):
        assert _emit({"caller_name": None}).actor == "system"

    def test_resource_type_is_text_for_single(self):
        assert _emit().resource_type == "pii_text"

    def test_resource_type_is_batch_for_batch(self):
        assert _emit({"batch_size": 50}).resource_type == "pii_batch"

    def test_resource_id_prefers_subject_id(self):
        assert _emit({"subject_id": "hashed-pidm-abc"}).resource_id == "hashed-pidm-abc"

    def test_resource_id_falls_back_to_request_id(self):
        assert _emit().resource_id == "test-req-1"

    def test_outcome_defaults_to_success(self):
        assert _emit().outcome == "success"

    def test_outcome_is_overridable(self):
        assert _emit({"outcome": "partial"}).outcome == "partial"

    def test_explicit_correlation_id_is_threaded(self):
        assert _emit({"correlation_id": "colleague-personid-1234567"}).correlation_id == "colleague-personid-1234567"

    def test_correlation_id_auto_generated_when_absent(self):
        """Absent correlation_id mints a fresh non-empty uuid via the default factory."""
        ev = _emit({"correlation_id": None})
        assert isinstance(ev.correlation_id, str) and len(ev.correlation_id) >= 16

    def test_occurred_at_is_iso_timestamp(self):
        from datetime import datetime
        # datetime.fromisoformat must parse it — raises if the shape is wrong.
        datetime.fromisoformat(_emit().occurred_at)

    def test_detail_carries_pii_domain_fields(self):
        detail = _emit().detail
        for key in ("endpoint", "hit_count", "entity_types", "risk_level", "duration_ms"):
            assert key in detail, f"AuditEvent.detail missing '{key}'"
        assert detail["endpoint"] == "/api/v1/scan"
