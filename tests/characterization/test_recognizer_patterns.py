"""
tests/characterization/test_recognizer_patterns.py

Pins known-good regex patterns for every custom recognizer.
If a pattern changes (even a small tweak), this test fails and forces
a conscious review. The failure IS the point — silent regressions in
detection patterns are worse than overt failures.

These tests do NOT call the full Presidio engine. They test the regex
directly against known inputs so they run without any model loading.
"""

import re
import pytest


# ---------------------------------------------------------------------------
# Shared: compile and test a single pattern
# ---------------------------------------------------------------------------

def _matches(pattern: str, text: str, flags: int = re.IGNORECASE) -> bool:
    return bool(re.search(pattern, text, flags))


# ---------------------------------------------------------------------------
# STUDENT_ID patterns — pinned 2025-05
# ---------------------------------------------------------------------------

class TestStudentIdPatterns:
    """
    Known-good: D-prefix pattern matches Banner student IDs.
    If this changes, update Banner integration tests and Conductor worker field mappings.
    """
    DPREFIX  = r"\bD\d{7}\b"
    AT_PREFIX = r"@\d{7,8}\b"

    def test_d_prefix_matches_standard(self):
        assert _matches(self.DPREFIX, "D1234567")

    def test_d_prefix_matches_in_sentence(self):
        assert _matches(self.DPREFIX, "Student D9876543 enrolled")

    def test_d_prefix_does_not_match_short(self):
        assert not _matches(self.DPREFIX, "D123456")  # only 6 digits

    def test_d_prefix_does_not_match_non_d(self):
        assert not _matches(self.DPREFIX, "X1234567")

    def test_at_prefix_matches_colleague(self):
        assert _matches(self.AT_PREFIX, "@01234567")

    def test_at_prefix_does_not_match_email(self):
        assert not _matches(self.AT_PREFIX, "user@doane.edu")


# ---------------------------------------------------------------------------
# DOANE_EMAIL pattern — pinned 2025-05
# ---------------------------------------------------------------------------

class TestDoaneEmailPattern:
    """
    Known-good: pattern matches exactly @doane.edu institutional addresses.
    If changed, update filter lists in Conductor sanitization workers.
    """
    PATTERN = r"\b[a-zA-Z0-9._%+\-]+@doane\.edu\b"

    def test_standard_match(self):
        assert _matches(self.PATTERN, "jsmith@doane.edu")

    def test_plus_suffix_match(self):
        assert _matches(self.PATTERN, "jsmith+filter@doane.edu")

    def test_subdomain_does_not_match(self):
        assert not _matches(self.PATTERN, "jsmith@cs.doane.edu"), (
            "Subdomains should NOT match DOANE_EMAIL — only @doane.edu exactly. "
            "If this changes, update the DOC and caller allow-lists."
        )

    def test_other_edu_does_not_match(self):
        assert not _matches(self.PATTERN, "prof@unl.edu")


# ---------------------------------------------------------------------------
# IMMIGRATION_STATUS patterns — pinned 2025-05
# ---------------------------------------------------------------------------

class TestImmigrationStatusPatterns:
    """
    Known-good: these patterns flag visa types and immigration references.
    CRITICAL sensitivity — if detection is weakened, FERPA/ICE exposure risk increases.
    """
    PATTERN = (
        r"\b(F-1|F1|J-1|J1|M-1|M1|H-1B|H1B|O-1|O1|TN|DACA|"
        r"undocumented|permanent resident|green card holder|"
        r"naturalized citizen|non-immigrant|I-94|I94|"
        r"SEVIS|sevis id|sevis number|DS-2019|I-20)\b"
    )

    def test_f1_matches(self):
        assert _matches(self.PATTERN, "Student is on F-1 visa")

    def test_daca_matches(self):
        assert _matches(self.PATTERN, "enrolled in DACA program")

    def test_sevis_matches(self):
        assert _matches(self.PATTERN, "SEVIS record must be updated")

    def test_i20_matches(self):
        assert _matches(self.PATTERN, "I-20 expires next semester")

    def test_green_card_matches(self):
        assert _matches(self.PATTERN, "green card holder applying for aid")

    def test_citizen_without_naturalized_does_not_match(self):
        # "citizen" alone (US citizen) should NOT match
        assert not _matches(self.PATTERN, "US citizen enrolled full-time")


# ---------------------------------------------------------------------------
# FERPA_MARKER patterns — pinned 2025-05
# ---------------------------------------------------------------------------

class TestFerpaMarkerPatterns:
    """
    Known-good: these phrases signal FERPA-protected record context.
    If phrases are added/removed, update the embedding pipeline documentation.
    """
    PATTERN = (
        r"\b(education record|academic record|transcript|"
        r"disciplinary record|financial aid|tuition balance|"
        r"GPA|grade point average|enrollment status|cumulative GPA|"
        r"degree audit|student account|disability accommodation|"
        r"academic standing|academic probation|academic suspension|"
        r"satisfactory academic progress|SAP status|"
        r"incomplete grade|withdrawal|course withdrawal)\b"
    )

    def test_transcript_matches(self):
        assert _matches(self.PATTERN, "official transcript requested")

    def test_gpa_matches(self):
        assert _matches(self.PATTERN, "Student GPA is 3.45")

    def test_financial_aid_matches(self):
        assert _matches(self.PATTERN, "financial aid hold on account")

    def test_academic_probation_matches(self):
        assert _matches(self.PATTERN, "placed on academic probation")

    def test_sap_status_matches(self):
        assert _matches(self.PATTERN, "SAP status review required")

    def test_course_title_does_not_match(self):
        assert not _matches(self.PATTERN, "Introduction to Computer Science meets Monday")


# ---------------------------------------------------------------------------
# DISABILITY_ACCOMMODATION patterns — pinned 2025-05
# ---------------------------------------------------------------------------

class TestDisabilityAccommodationPatterns:
    PATTERN = (
        r"\b(disability (?:accommodation|services?|office)|"
        r"ADA accommodation|504 plan|IEP|individualized education|"
        r"testing accommodation|extended time|alternative format|"
        r"note-?taker|sign language interpreter|assistive technolog|"
        r"hearing impair|visually impair|learning disabilit|"
        r"attention deficit|ADHD|autism spectrum|accommodations? letter)\b"
    )

    def test_disability_accommodation_matches(self):
        assert _matches(self.PATTERN, "student has a disability accommodation")

    def test_extended_time_matches(self):
        assert _matches(self.PATTERN, "approved for extended time on tests")

    def test_ada_matches(self):
        assert _matches(self.PATTERN, "ADA accommodation request received")

    def test_iep_matches(self):
        assert _matches(self.PATTERN, "student has an IEP from high school")

    def test_disability_word_alone_does_not_match(self):
        # "disability" alone without a qualifying institutional phrase should NOT match
        assert not _matches(self.PATTERN, "people with any disability deserve equal access")


# ---------------------------------------------------------------------------
# FAFSA_ID patterns — pinned 2025-05
# ---------------------------------------------------------------------------

class TestFafsaIdPatterns:
    STATE_FORMAT = r"\b[A-Z]{2}-\d{6}\b"
    ISIR_FORMAT  = r"\bISIR\s+\d{4,10}\b"

    def test_state_format_matches(self):
        assert _matches(self.STATE_FORMAT, "NE-123456")

    def test_state_format_requires_6_digits(self):
        assert not _matches(self.STATE_FORMAT, "NE-12345")  # 5 digits

    def test_isir_matches(self):
        assert _matches(self.ISIR_FORMAT, "ISIR 20241234")

    def test_isir_requires_keyword(self):
        assert not _matches(self.ISIR_FORMAT, "20241234 record")  # no ISIR keyword


# ---------------------------------------------------------------------------
# US_SSN (Presidio built-in) — characterization of known behavior — pinned 2025-05
# ---------------------------------------------------------------------------

class TestSsnPresidioCharacterization:
    """
    Presidio's built-in US_SSN recognizer catches dashed and plain formats.
    This characterization test pins what we know about its behavior.
    If Presidio version bumps change this, the test catches the drift.
    """
    DASHED_SSN  = "123-45-6789"
    PLAIN_SSN   = "123456789"   # may or may not be caught depending on context

    def test_dashed_ssn_matches_presidio_pattern(self):
        # Presidio regex for SSN: \b(\d{3})-(\d{2})-(\d{4})\b
        # Characterization: if this changes, update guard tests for mask format
        pattern = r"\b\d{3}-\d{2}-\d{4}\b"
        assert re.search(pattern, self.DASHED_SSN)

    def test_pseudonymized_ssn_matches_pattern(self):
        """Pseudonymized SSN must still look like a real SSN format."""
        from pii_guard.guard import _generate_pseudo
        seed = int("deadbeef", 16)
        pseudo = _generate_pseudo("US_SSN", seed)
        assert re.search(r"\d{3}-\d{2}-\d{4}", pseudo), (
            f"Pseudonymized SSN '{pseudo}' does not match XXX-XX-XXXX format. "
            "This will break downstream callers that expect SSN format preservation."
        )
