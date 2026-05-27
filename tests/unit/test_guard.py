"""
tests/unit/test_guard.py - Unit tests for PiiGuard core logic.

Regex-only mode (use_spacy=False) for CI speed.
PERSON/LOCATION detection accuracy is an integration-test concern.
"""

import re
import pytest

pytest.importorskip("presidio_analyzer", reason="presidio_analyzer not installed — install requirements.txt")

from pii_guard import PiiGuard, SanitizeMode, RiskLevel


# ---------------------------------------------------------------------------
# Clean text passthrough
# ---------------------------------------------------------------------------

class TestCleanText:
    def test_clean_passthrough_mask(self, guard):
        text = "The quick brown fox jumped over the lazy dog."
        result = guard.sanitize(text, SanitizeMode.MASK)
        assert result.is_clean
        assert result.sanitized_text == text
        assert not result.excluded
        assert result.risk_level == RiskLevel.LOW

    def test_empty_string_returns_empty(self, guard):
        result = guard.sanitize("", SanitizeMode.MASK)
        assert result.is_clean
        assert result.sanitized_text == ""

    def test_whitespace_only_is_clean(self, guard):
        result = guard.sanitize("   ", SanitizeMode.MASK)
        assert result.is_clean

    def test_course_data_no_false_positives(self, guard):
        text = "CSCI 301 meets MWF at 10am in SC 204. 24 students enrolled."
        result = guard.scan(text)
        # Course/room numbers should NOT trigger student ID at threshold 0.4 without context
        ssn_hits = [h for h in result.hits if h.entity_type == "US_SSN"]
        assert not ssn_hits, f"False positive SSN hit on course data: {result.hits}"


# ---------------------------------------------------------------------------
# SSN detection and sanitization
# ---------------------------------------------------------------------------

class TestSSN:
    def test_ssn_detected_in_scan(self, guard):
        result = guard.scan("My SSN is 123-45-6789")
        assert not result.is_clean
        assert "US_SSN" in {h.entity_type for h in result.hits}

    def test_ssn_risk_is_critical(self, guard):
        result = guard.scan("SSN 123-45-6789")
        ssn_hit = next(h for h in result.hits if h.entity_type == "US_SSN")
        assert ssn_hit.risk_level == RiskLevel.CRITICAL
        assert result.risk_level == RiskLevel.CRITICAL

    def test_ssn_masked(self, guard):
        result = guard.sanitize("SSN: 123-45-6789", SanitizeMode.MASK)
        assert "123-45-6789" not in result.sanitized_text
        assert "[US_SSN]" in result.sanitized_text

    def test_ssn_redacted(self, guard):
        result = guard.sanitize("SSN: 123-45-6789", SanitizeMode.REDACT)
        assert "123-45-6789" not in result.sanitized_text

    def test_ssn_pseudonymized_format(self, guard):
        result = guard.sanitize("SSN: 123-45-6789", SanitizeMode.PSEUDONYMIZE)
        assert "123-45-6789" not in result.sanitized_text
        assert re.search(r"\d{3}-\d{2}-\d{4}", result.sanitized_text), (
            "Pseudonymized SSN should preserve XXX-XX-XXXX format"
        )

    def test_ssn_excluded_mode(self, guard):
        result = guard.sanitize("SSN: 123-45-6789", SanitizeMode.EXCLUDE)
        assert result.excluded
        assert result.sanitized_text is None


# ---------------------------------------------------------------------------
# Email detection
# ---------------------------------------------------------------------------

class TestEmail:
    def test_personal_email_detected(self, guard):
        result = guard.scan("contact jsmith@gmail.com")
        entity_types = {h.entity_type for h in result.hits}
        assert "EMAIL_ADDRESS" in entity_types

    def test_doane_email_detected(self, guard):
        result = guard.scan("email me at jsmith@doane.edu")
        entity_types = {h.entity_type for h in result.hits}
        assert "EMAIL_ADDRESS" in entity_types or "DOANE_EMAIL" in entity_types

    def test_email_masked(self, guard):
        result = guard.sanitize("Email: jsmith@doane.edu", SanitizeMode.MASK)
        assert "jsmith@doane.edu" not in result.sanitized_text

    def test_email_pseudonymized_has_at_sign(self, guard):
        result = guard.sanitize("Email: jsmith@gmail.com", SanitizeMode.PSEUDONYMIZE)
        assert "jsmith@gmail.com" not in result.sanitized_text
        assert "@" in result.sanitized_text


# ---------------------------------------------------------------------------
# Phone number detection
# ---------------------------------------------------------------------------

class TestPhone:
    def test_us_phone_detected(self, guard):
        result = guard.scan("Call me at 402-555-1234")
        assert not result.is_clean

    def test_phone_pseudonymized_not_original(self, guard):
        result = guard.sanitize("Phone: 402-555-1234", SanitizeMode.PSEUDONYMIZE)
        assert "402-555-1234" not in result.sanitized_text


# ---------------------------------------------------------------------------
# Credit card detection
# ---------------------------------------------------------------------------

class TestCreditCard:
    def test_cc_detected(self, guard):
        result = guard.scan("Card: 4111111111111111")
        entity_types = {h.entity_type for h in result.hits}
        assert "CREDIT_CARD" in entity_types

    def test_cc_risk_is_critical(self, guard):
        result = guard.scan("Card: 4111111111111111")
        cc_hit = next(h for h in result.hits if h.entity_type == "CREDIT_CARD")
        assert cc_hit.risk_level == RiskLevel.CRITICAL

    def test_cc_pseudonymized_to_test_number(self, guard):
        result = guard.sanitize("Card: 4111111111111111", SanitizeMode.PSEUDONYMIZE)
        assert "4111111111111111" not in result.sanitized_text
        # Should be replaced with the Luhn-valid test number
        assert "4111-1111-1111-1111" in result.sanitized_text


# ---------------------------------------------------------------------------
# Student ID (custom recognizer)
# ---------------------------------------------------------------------------

class TestStudentId:
    def test_numeric_with_context_detected(self, guard):
        result = guard.scan("Student id 1234567 enrolled in CSCI101")
        assert "STUDENT_ID" in {h.entity_type for h in result.hits}

    def test_letter_prefixed_detected(self, guard):
        result = guard.scan("Student id S1234567 enrolled")
        assert "STUDENT_ID" in {h.entity_type for h in result.hits}

    def test_student_id_risk_is_high(self, guard):
        result = guard.scan("Student id 1234567")
        sid_hits = [h for h in result.hits if h.entity_type == "STUDENT_ID"]
        if sid_hits:
            assert sid_hits[0].risk_level == RiskLevel.HIGH

    def test_student_id_masked(self, guard):
        result = guard.sanitize("Student id 1234567", SanitizeMode.MASK)
        assert "1234567" not in result.sanitized_text

    def test_student_id_pseudonymized(self, guard):
        # Pseudonym format isn't pinned here — Presidio's DATE_TIME recognizer
        # also fires on bare 7-digit strings, and which entity "wins" the
        # overlap is a separate calibration concern. What this test guards is
        # the floor: the original ID must not survive into the sanitized output.
        result = guard.sanitize("Student id 1234567", SanitizeMode.PSEUDONYMIZE)
        assert "1234567" not in result.sanitized_text, (
            "Pseudonym must differ from input — same number = no pseudonymization."
        )


# ---------------------------------------------------------------------------
# Pseudonymization consistency
# ---------------------------------------------------------------------------

class TestPseudoConsistency:
    def test_same_input_same_output_within_session(self, guard):
        r1 = guard.sanitize("SSN: 123-45-6789", SanitizeMode.PSEUDONYMIZE)
        r2 = guard.sanitize("SSN: 123-45-6789", SanitizeMode.PSEUDONYMIZE)
        assert r1.sanitized_text == r2.sanitized_text, (
            "Same input must produce same pseudonym within a session"
        )

    def test_different_inputs_produce_different_outputs(self, guard):
        r1 = guard.sanitize("SSN: 123-45-6789", SanitizeMode.PSEUDONYMIZE)
        r2 = guard.sanitize("SSN: 987-65-4321", SanitizeMode.PSEUDONYMIZE)
        assert r1.sanitized_text != r2.sanitized_text

    def test_cache_reset_preserves_determinism(self, guard):
        """MD5 hash seed is deterministic — cache reset should give same result."""
        r1 = guard.sanitize("SSN: 123-45-6789", SanitizeMode.PSEUDONYMIZE)
        guard.reset_pseudo_cache()
        r2 = guard.sanitize("SSN: 123-45-6789", SanitizeMode.PSEUDONYMIZE)
        assert r1.sanitized_text == r2.sanitized_text


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------

class TestBatch:
    def test_batch_exclude_mixed(self, guard):
        texts = ["Clean text", "SSN: 123-45-6789", "Another clean"]
        results = guard.sanitize_batch(texts, SanitizeMode.EXCLUDE)
        assert results[0].is_clean and not results[0].excluded
        assert results[1].excluded
        assert results[2].is_clean and not results[2].excluded

    def test_batch_preserves_count(self, guard):
        texts = ["Email: a@b.com", "No PII here"]
        assert len(guard.sanitize_batch(texts, SanitizeMode.MASK)) == 2

    def test_batch_empty_list(self, guard):
        assert guard.sanitize_batch([], SanitizeMode.MASK) == []


# ---------------------------------------------------------------------------
# Dict sanitization
# ---------------------------------------------------------------------------

class TestDictSanitize:
    def test_specified_fields_sanitized(self, guard):
        record = {"name": "John Smith", "note": "SSN is 123-45-6789", "gpa": "3.5"}
        sanitized, excluded = guard.sanitize_dict(record, fields=["note"], mode=SanitizeMode.MASK)
        assert "123-45-6789" not in sanitized["note"]
        assert sanitized["gpa"] == "3.5"  # untouched non-specified field
        assert excluded == []

    def test_exclude_mode_marks_field(self, guard):
        record = {"bio": "SSN 123-45-6789", "dept": "Engineering"}
        sanitized, excluded = guard.sanitize_dict(record, fields=["bio", "dept"], mode=SanitizeMode.EXCLUDE)
        assert "bio" in excluded
        assert sanitized["bio"] is None
        assert sanitized["dept"] == "Engineering"

    def test_non_string_fields_pass_through(self, guard):
        record = {"count": 42, "flag": True, "text": "SSN 123-45-6789"}
        sanitized, _ = guard.sanitize_dict(record, fields=["count", "flag", "text"], mode=SanitizeMode.MASK)
        assert sanitized["count"] == 42
        assert sanitized["flag"] is True


# ---------------------------------------------------------------------------
# exclude_entity_types
# ---------------------------------------------------------------------------

class TestExcludeEntityTypes:
    def test_date_passthrough_ssn_still_caught(self, guard):
        text = "Born on 01/15/1990, SSN 123-45-6789"
        result = guard.sanitize(text, SanitizeMode.MASK, exclude_entity_types=["DATE_TIME", "DATE_OF_BIRTH"])
        assert "123-45-6789" not in result.sanitized_text
        assert result.sanitized_text is not None

    def test_exclude_all_makes_clean(self, guard):
        text = "SSN 123-45-6789"
        result = guard.sanitize(text, SanitizeMode.MASK, exclude_entity_types=["US_SSN"])
        assert result.is_clean
        assert result.sanitized_text == text


# ---------------------------------------------------------------------------
# Preflight check
# ---------------------------------------------------------------------------

class TestPreflight:
    def test_clean_text_is_safe(self, guard):
        result = guard.preflight("The course CSCI 301 has 24 seats available.")
        assert result.safe_to_send
        assert result.hit_count == 0
        assert result.sanitized_suggestion is None

    def test_ssn_not_safe(self, guard):
        result = guard.preflight("Student SSN is 123-45-6789")
        assert not result.safe_to_send
        assert result.risk_level == RiskLevel.CRITICAL
        assert "US_SSN" in result.blocking_entities
        assert result.sanitized_suggestion is not None

    def test_preflight_suggestion_masks_pii(self, guard):
        result = guard.preflight("SSN: 123-45-6789")
        if result.sanitized_suggestion:
            assert "123-45-6789" not in result.sanitized_suggestion

    def test_recommendation_populated(self, guard):
        result = guard.preflight("SSN: 123-45-6789")
        assert isinstance(result.recommendation, str)
        assert len(result.recommendation) > 10


# ---------------------------------------------------------------------------
# Structured scan
# ---------------------------------------------------------------------------

class TestScanStructured:
    def test_flagged_fields_identified(self, guard):
        record = {"name": "John Smith", "ssn": "123-45-6789", "gpa": "3.5"}
        report = guard.scan_structured(record)
        assert report["ssn"]["pii_found"]
        assert "ssn" in report["_summary"]["flagged_fields"]

    def test_summary_highest_risk(self, guard):
        record = {"ssn": "123-45-6789", "note": "generic text"}
        report = guard.scan_structured(record)
        # SSN is CRITICAL so highest_risk should be CRITICAL
        assert report["_summary"]["highest_risk"] == "CRITICAL"

    def test_non_string_field_skipped(self, guard):
        record = {"count": 42, "text": "SSN 123-45-6789"}
        report = guard.scan_structured(record)
        assert report["count"]["skipped"] is True

    def test_empty_record(self, guard):
        report = guard.scan_structured({})
        assert report["_summary"]["total_hits"] == 0


# ---------------------------------------------------------------------------
# ScanResult.summary() - safe for logging
# ---------------------------------------------------------------------------

class TestScanResultSummary:
    def test_summary_no_raw_pii(self, guard):
        result = guard.scan("SSN: 123-45-6789")
        summary_str = str(result.summary())
        assert "123-45-6789" not in summary_str

    def test_summary_has_required_keys(self, guard):
        summary = guard.scan("SSN: 123-45-6789").summary()
        for key in ["mode", "pii_found", "entity_types", "hit_count", "risk_level", "excluded"]:
            assert key in summary, f"Missing key '{key}' in summary"
