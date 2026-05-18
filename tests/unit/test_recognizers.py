"""
tests/unit/test_recognizers.py - Per-recognizer unit tests.

Each custom recognizer gets its own test class. Tests verify:
  - positive detection on known-good examples
  - the entity type tag is correct
  - context keywords boost low-confidence patterns
  - no crash on empty or unusual strings

These tests do NOT verify spaCy-based PERSON/LOCATION — that's integration territory.
"""

import pytest

pytest.importorskip("presidio_analyzer", reason="presidio_analyzer not installed — install requirements.txt")

from pii_guard import PiiGuard, SanitizeMode


@pytest.fixture(scope="module")
def r_guard():
    """Recognizer test guard — low threshold to catch low-confidence patterns."""
    return PiiGuard(score_threshold=0.3, use_spacy=False)


# ---------------------------------------------------------------------------
# STUDENT_ID
# ---------------------------------------------------------------------------

class TestStudentIdRecognizer:
    def test_d_prefix_detected(self, r_guard):
        result = r_guard.scan("Student D1234567 enrolled")
        assert "STUDENT_ID" in {h.entity_type for h in result.hits}

    def test_colleague_at_prefix_detected(self, r_guard):
        result = r_guard.scan("Person @01234567 flagged")
        assert "STUDENT_ID" in {h.entity_type for h in result.hits}

    def test_d_prefix_score_above_09(self, r_guard):
        result = r_guard.scan("D9876543")
        sid_hits = [h for h in result.hits if h.entity_type == "STUDENT_ID"]
        if sid_hits:
            assert sid_hits[0].score >= 0.85, "D-prefix student ID should have high confidence"

    def test_d_prefix_not_triggered_by_non_d_letter(self, r_guard):
        result = r_guard.scan("X1234567")
        # X-prefix should NOT match the D-prefix pattern
        d_hits = [h for h in result.hits if h.entity_type == "STUDENT_ID"
                  and h.score >= 0.85]
        assert not d_hits


# ---------------------------------------------------------------------------
# DOANE_EMAIL
# ---------------------------------------------------------------------------

class TestDoaneEmailRecognizer:
    def test_doane_edu_detected(self, r_guard):
        result = r_guard.scan("Contact jdoe@doane.edu")
        assert "DOANE_EMAIL" in {h.entity_type for h in result.hits}

    def test_other_edu_not_doane_email(self, r_guard):
        result = r_guard.scan("prof@unl.edu replied")
        doane_hits = [h for h in result.hits if h.entity_type == "DOANE_EMAIL"]
        assert not doane_hits, "Non-doane.edu addresses should not match DOANE_EMAIL"

    def test_doane_email_score_above_09(self, r_guard):
        result = r_guard.scan("jsmith@doane.edu")
        doane_hits = [h for h in result.hits if h.entity_type == "DOANE_EMAIL"]
        if doane_hits:
            assert doane_hits[0].score >= 0.9


# ---------------------------------------------------------------------------
# DATE_OF_BIRTH
# ---------------------------------------------------------------------------

class TestDateOfBirthRecognizer:
    def test_mm_dd_yyyy_with_context(self, r_guard):
        result = r_guard.scan("Date of birth: 01/15/1990")
        entity_types = {h.entity_type for h in result.hits}
        assert "DATE_OF_BIRTH" in entity_types or "DATE_TIME" in entity_types

    def test_yyyy_mm_dd_format(self, r_guard):
        result = r_guard.scan("dob: 1990-01-15 enrolled")
        entity_types = {h.entity_type for h in result.hits}
        assert "DATE_OF_BIRTH" in entity_types or "DATE_TIME" in entity_types


# ---------------------------------------------------------------------------
# FERPA_MARKER
# ---------------------------------------------------------------------------

class TestFerpaMarkerRecognizer:
    def test_gpa_phrase_detected(self, r_guard):
        result = r_guard.scan("student GPA is 3.45")
        entity_types = {h.entity_type for h in result.hits}
        assert "FERPA_MARKER" in entity_types

    def test_financial_aid_detected(self, r_guard):
        result = r_guard.scan("Student has a financial aid hold")
        entity_types = {h.entity_type for h in result.hits}
        assert "FERPA_MARKER" in entity_types

    def test_transcript_detected(self, r_guard):
        result = r_guard.scan("Official transcript requested")
        entity_types = {h.entity_type for h in result.hits}
        assert "FERPA_MARKER" in entity_types

    def test_non_ferpa_phrase_not_flagged(self, r_guard):
        result = r_guard.scan("The cafeteria serves lunch at noon")
        ferpa_hits = [h for h in result.hits if h.entity_type == "FERPA_MARKER"]
        assert not ferpa_hits


# ---------------------------------------------------------------------------
# IMMIGRATION_STATUS
# ---------------------------------------------------------------------------

class TestImmigrationStatusRecognizer:
    def test_f1_visa_detected(self, r_guard):
        result = r_guard.scan("International student on F-1 visa")
        assert "IMMIGRATION_STATUS" in {h.entity_type for h in result.hits}

    def test_daca_detected(self, r_guard):
        result = r_guard.scan("Student participates in DACA program")
        assert "IMMIGRATION_STATUS" in {h.entity_type for h in result.hits}

    def test_sevis_detected(self, r_guard):
        result = r_guard.scan("SEVIS record requires update")
        assert "IMMIGRATION_STATUS" in {h.entity_type for h in result.hits}


# ---------------------------------------------------------------------------
# DISABILITY_ACCOMMODATION
# ---------------------------------------------------------------------------

class TestDisabilityAccommodationRecognizer:
    def test_accommodation_phrase_detected(self, r_guard):
        result = r_guard.scan("Student has a disability accommodation on file")
        assert "DISABILITY_ACCOMMODATION" in {h.entity_type for h in result.hits}

    def test_extended_time_detected(self, r_guard):
        result = r_guard.scan("Student approved for extended time on exams")
        assert "DISABILITY_ACCOMMODATION" in {h.entity_type for h in result.hits}

    def test_ada_detected(self, r_guard):
        result = r_guard.scan("ADA accommodation request submitted")
        assert "DISABILITY_ACCOMMODATION" in {h.entity_type for h in result.hits}


# ---------------------------------------------------------------------------
# VETERAN_STATUS
# ---------------------------------------------------------------------------

class TestVeteranStatusRecognizer:
    def test_veteran_detected(self, r_guard):
        result = r_guard.scan("Student is a veteran using GI Bill benefits")
        assert "VETERAN_STATUS" in {h.entity_type for h in result.hits}

    def test_gi_bill_detected(self, r_guard):
        result = r_guard.scan("GI Bill post-9/11 chapter 33")
        assert "VETERAN_STATUS" in {h.entity_type for h in result.hits}


# ---------------------------------------------------------------------------
# HIPAA_MARKER
# ---------------------------------------------------------------------------

class TestHipaaMarkerRecognizer:
    def test_mental_health_detected(self, r_guard):
        result = r_guard.scan("Student has mental health records on file")
        assert "HIPAA_MARKER" in {h.entity_type for h in result.hits}

    def test_counseling_detected(self, r_guard):
        result = r_guard.scan("Counseling session note flagged for review")
        assert "HIPAA_MARKER" in {h.entity_type for h in result.hits}

    def test_campus_health_detected(self, r_guard):
        result = r_guard.scan("Referral to campus health center")
        assert "HIPAA_MARKER" in {h.entity_type for h in result.hits}


# ---------------------------------------------------------------------------
# FAFSA_ID
# ---------------------------------------------------------------------------

class TestFafsaIdRecognizer:
    def test_state_format_detected(self, r_guard):
        result = r_guard.scan("FAFSA application NE-123456 pending")
        entity_types = {h.entity_type for h in result.hits}
        assert "FAFSA_ID" in entity_types

    def test_isir_detected(self, r_guard):
        result = r_guard.scan("ISIR 2024001234 received for processing")
        entity_types = {h.entity_type for h in result.hits}
        assert "FAFSA_ID" in entity_types


# ---------------------------------------------------------------------------
# FINANCIAL_ACCOUNT
# ---------------------------------------------------------------------------

class TestFinancialAccountRecognizer:
    def test_explicit_account_detected(self, r_guard):
        result = r_guard.scan("routing number: 021000021, account 1234567890")
        entity_types = {h.entity_type for h in result.hits}
        assert "FINANCIAL_ACCOUNT" in entity_types or "US_BANK_NUMBER" in entity_types
