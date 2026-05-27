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
# STUDENT_ID patterns — re-pinned 2026-05-27
#
# Replaced the original Doane-D-prefix pattern. Doane does NOT use a D prefix
# (that was a wrong assumption in v1). Real Doane IDs are 7-digit numerics
# with leading zeros allowed. Peer institutions and external SIS feeds also
# send 5-9 digit numerics, sometimes with a single letter prefix.
#
# If either pattern changes, update the field-context-hint table in
# pii_guard/config.py — the hint mechanism boosts these patterns via the
# context vocabulary and a regex change can silently break hint-driven scans.
# ---------------------------------------------------------------------------

class TestStudentIdPatterns:
    NUMERIC         = r"\b\d{5,9}\b"
    LETTER_PREFIXED = r"\b[A-Z]\d{5,9}\b"

    def test_numeric_matches_7_digit(self):
        assert _matches(self.NUMERIC, "1234567")

    def test_numeric_matches_leading_zero(self):
        # Doane's canonical form. If this fails, leading-zero Doane IDs go uncaught.
        assert _matches(self.NUMERIC, "0001234")

    def test_numeric_matches_5_through_9_digits(self):
        for n in (5, 6, 7, 8, 9):
            assert _matches(self.NUMERIC, "1" * n), f"failed at length {n}"

    def test_numeric_does_not_match_4_digits(self):
        # 4 digits is below the range — too noisy to flag (years, course codes).
        assert not _matches(self.NUMERIC, "1234")

    def test_numeric_does_not_match_10_digits(self):
        # 10+ digits leaves SSN/phone territory. Out of scope for STUDENT_ID.
        assert not _matches(self.NUMERIC, "1234567890")

    def test_letter_prefixed_matches_s_prefix(self):
        # External-system IDs like S1234567 must be caught. The S prefix was
        # the bug report that drove this redesign.
        assert _matches(self.LETTER_PREFIXED, "S1234567")

    def test_letter_prefixed_matches_other_letters(self):
        for letter in ("A", "B", "P", "T", "X"):
            assert _matches(self.LETTER_PREFIXED, f"{letter}1234567"), (
                f"{letter}-prefix ID not matched"
            )

    def test_letter_prefixed_does_not_match_lowercase(self):
        # Letter prefix is uppercase only. Lower-case would conflict with
        # word-internal substrings (e.g., "s1234567" inside "abcs1234567").
        assert not _matches(self.LETTER_PREFIXED, "s1234567", flags=0)

    def test_d_prefix_no_longer_special(self):
        """
        Documents the v2 change: D-prefix was a wrong assumption about Doane's
        ID format and is removed as a special-case pattern. D1234567 is now
        matched only by the generic letter_prefixed pattern at lower confidence,
        not by a Doane-specific high-confidence regex. If the old DPREFIX
        pattern is re-introduced, this test will start passing for the wrong
        reason and should be re-evaluated.
        """
        # The generic letter_prefixed pattern still matches D1234567 — that's
        # correct behavior. The point of the test is the *absence* of a
        # high-confidence D-specific pattern in the recognizer spec.
        from pii_guard.recognizers import _RECOGNIZER_SPECS
        student_id = next(s for s in _RECOGNIZER_SPECS if s["entity"] == "STUDENT_ID")
        pattern_names = {p[0] for p in student_id["patterns"]}
        assert "doane_d_prefix" not in pattern_names, (
            "doane_d_prefix re-introduced. Doane does NOT use a D-prefix on "
            "real student IDs; reinstating this pattern bakes a wrong assumption "
            "back into detection."
        )

    def test_at_prefix_no_longer_present(self):
        """
        Documents the v2 change: the @-prefix pattern (@1234567) is removed
        because Doane has never seen this notation in real text. If it shows
        up in a feed later, re-add as a new pattern with a fresh confidence.
        """
        from pii_guard.recognizers import _RECOGNIZER_SPECS
        student_id = next(s for s in _RECOGNIZER_SPECS if s["entity"] == "STUDENT_ID")
        pattern_names = {p[0] for p in student_id["patterns"]}
        assert "colleague_at" not in pattern_names

    def test_colleague_id_recognizer_removed(self):
        """
        Documents the v2 change: COLLEAGUE_ID was a separate recognizer with
        an overlapping numeric pattern. Collapsed into STUDENT_ID — same number,
        same handling, single canonical entity type. BANNER_ID was already
        dead code (referenced in models/policy but no recognizer existed).
        """
        from pii_guard.recognizers import _RECOGNIZER_SPECS
        entities = {s["entity"] for s in _RECOGNIZER_SPECS}
        assert "COLLEAGUE_ID" not in entities, (
            "COLLEAGUE_ID recognizer re-added. The v2 design folds it into "
            "STUDENT_ID. If we genuinely need separate semantics, plumb the "
            "new entity through models.py, policy.py, and config.py field hints "
            "in the same commit."
        )


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

# ---------------------------------------------------------------------------
# TITLE_IX_CASE_ID patterns — pinned 2025-05
# ---------------------------------------------------------------------------

class TestTitleIXCaseIdPatterns:
    """
    Known-good: TIX case ID format is TIX-YYYY-NNNNNN.
    If changed, update Title IX case management integration documentation.
    """
    TIX_ID = r"\bTIX[-_]\d{4}[-_]\d{4,6}\b"
    TIX_PHRASE = r"\bTitle\s+IX\s+(?:case|complaint|investigation)\s+#?\s*\d{3,8}\b"

    def test_tix_id_format_matches(self):
        assert _matches(self.TIX_ID, "TIX-2024-001234")

    def test_tix_id_underscore_matches(self):
        assert _matches(self.TIX_ID, "TIX_2023_5678")

    def test_tix_id_short_seq_does_not_match(self):
        assert not _matches(self.TIX_ID, "TIX-2024-123")  # only 3 digits in seq

    def test_tix_phrase_matches_case(self):
        assert _matches(self.TIX_PHRASE, "Title IX case 20240001 is pending")

    def test_tix_phrase_matches_complaint(self):
        assert _matches(self.TIX_PHRASE, "Title IX complaint #1234 received")

    def test_generic_number_without_tix_does_not_match(self):
        assert not _matches(self.TIX_ID, "20241234")  # no TIX prefix


# ---------------------------------------------------------------------------
# IRB_PROTOCOL patterns — pinned 2025-05
# ---------------------------------------------------------------------------

class TestIrbProtocolPatterns:
    """
    Known-good: IRB protocol IDs follow IRB-YYYY-NNN format.
    If changed, update research compliance documentation.
    """
    IRB_PATTERN = r"\bIRB[-_#]?\s*\d{4}[-_]\d{3,6}\b"
    HS_PATTERN = r"\bHS[-_]\d{4}[-_]\d{3,6}\b"

    def test_irb_dashed_matches(self):
        assert _matches(self.IRB_PATTERN, "IRB-2024-001")

    def test_irb_hash_matches(self):
        assert _matches(self.IRB_PATTERN, "IRB#2024-001")

    def test_irb_space_matches(self):
        assert _matches(self.IRB_PATTERN, "IRB 2024-001")

    def test_hs_protocol_matches(self):
        assert _matches(self.HS_PATTERN, "HS-2024-001")

    def test_random_number_does_not_match_irb(self):
        assert not _matches(self.IRB_PATTERN, "12345678")  # no IRB prefix


# ---------------------------------------------------------------------------
# FINANCIAL_AID_AWARD patterns — pinned 2025-05
# ---------------------------------------------------------------------------

class TestFinancialAidAwardPatterns:
    NAMED_AWARD = (
        r"\b(?:Pell\s+Grant|Subsidized\s+Loan|Unsubsidized\s+Loan|Direct\s+(?:Subsidized|Unsubsidized|PLUS)\s+Loan|"
        r"Federal\s+(?:Pell|SEOG|Work[- ]Study)|PLUS\s+Loan|Parent\s+PLUS|Grad\s+PLUS|"
        r"Yellow\s+Ribbon\s+Grant|TEACH\s+Grant|Iraq\s+and\s+Afghanistan\s+Service\s+Grant)"
        r"\s+(?:of\s+|amount[:\s]+)?\$[\d,]+(?:\.\d{2})?\b"
    )

    def test_pell_grant_with_amount_matches(self):
        assert _matches(self.NAMED_AWARD, "Pell Grant of $7,395.00")

    def test_subsidized_loan_matches(self):
        assert _matches(self.NAMED_AWARD, "Subsidized Loan $3,500")

    def test_plus_loan_matches(self):
        assert _matches(self.NAMED_AWARD, "PLUS Loan $10,000")

    def test_pell_grant_without_amount_does_not_match(self):
        assert not _matches(self.NAMED_AWARD, "Pell Grant eligibility determined")


# ---------------------------------------------------------------------------
# New entity types registered in DOANE_RECOGNIZER_REGISTRY — pinned 2025-05
# ---------------------------------------------------------------------------

class TestNewEntityRegistration:
    """Verify all 5 new entity types are in the exported registry."""
    NEW_ENTITIES = {
        "TITLE_IX_CASE_ID",
        "IRB_PROTOCOL",
        "FINANCIAL_AID_AWARD",
        "STUDENT_ACCOUNT_ID",
        "LICENSE_PLATE",
    }

    def test_all_new_entities_in_registry(self):
        from pii_guard.recognizers import DOANE_RECOGNIZER_REGISTRY
        missing = self.NEW_ENTITIES - set(DOANE_RECOGNIZER_REGISTRY)
        assert not missing, f"New entities not in registry: {missing}"

    def test_get_context_for_entity_returns_list(self):
        from pii_guard.recognizers import get_context_for_entity
        ctx = get_context_for_entity("TITLE_IX_CASE_ID")
        assert isinstance(ctx, list)
        assert len(ctx) > 0

    def test_get_context_for_presidio_builtin(self):
        from pii_guard.recognizers import get_context_for_entity
        ctx = get_context_for_entity("US_SSN")
        assert isinstance(ctx, list)
        assert "ssn" in ctx or "social security" in ctx

    def test_get_context_for_unknown_entity_returns_empty(self):
        from pii_guard.recognizers import get_context_for_entity
        assert get_context_for_entity("NONEXISTENT_TYPE") == []


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


# ---------------------------------------------------------------------------
# Claimed-SSN (verbal-claim anchor) — pinned 2026-05-27
#
# The strict US_SSN patterns reject malformed SSNs by design (3-3-4 typo,
# bare 9 digits without context). When the surrounding text verbally claims
# the number is an SSN ("ssn:", "social security number", "soc sec"), we
# trust the claim and flag it anyway. This catches user-typed SSNs that
# don't match the canonical format and bare-9-digit SSNs in form data.
#
# Anchor list is intentionally narrow: "social" alone matches "social media",
# "number" alone matches "phone number". Anchoring to specific phrases keeps
# false-positive risk low.
# ---------------------------------------------------------------------------

class TestClaimedSsnPattern:
    # Uses the third-party `regex` module (same backend Presidio uses) to evaluate
    # the variable-width lookbehind. Python's built-in `re` would reject it. If
    # this test ever migrates to plain `re`, the lookbehind has to be flattened
    # and the match span will grow to include the anchor phrase.
    PATTERN = (
        r"(?i)(?<=\b(?:ssn|social\s+security(?:\s+number|\s+#)?|soc\s+sec)\b"
        r"[^\d\n]{0,15})"
        r"\d{3}[-\s.]?\d{2,3}[-\s.]?\d{4}\b"
    )

    @staticmethod
    def _claimed_matches(text: str) -> bool:
        import regex
        return bool(regex.search(TestClaimedSsnPattern.PATTERN, text))

    def test_canonical_format_with_ssn_anchor(self):
        assert self._claimed_matches("SSN: 123-45-6789")

    def test_malformed_3_3_4_with_anchor(self):
        # The original bug-report case: "social security number is 123-654-9898".
        # Strict patterns reject 3-3-4 grouping. With anchor phrase, we catch it.
        assert self._claimed_matches("my social security number is 123-654-9898")

    def test_bare_9_digits_with_anchor(self):
        assert self._claimed_matches("SSN 123456789")

    def test_soc_sec_abbreviation_anchor(self):
        assert self._claimed_matches("soc sec 123-45-6789")

    def test_no_match_without_anchor(self):
        # Malformed SSN with no verbal claim looks like a phone — leave it.
        assert not self._claimed_matches("call me at 123-654-9898 tomorrow")

    def test_no_match_with_weak_anchor(self):
        # "social" alone is not an SSN anchor — too noisy.
        assert not self._claimed_matches("social media handle 123-456-7890")

    def test_no_match_when_number_too_short(self):
        assert not self._claimed_matches("SSN: 123-45")
