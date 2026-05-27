"""
pii_guard.rules_metadata - Descriptive metadata that enriches the Rules UI.

These dictionaries live separately from `recognizers.py` and `models.py` so the
detection-critical files stay focused on detection. This file holds prose and
example data that the Rules page surfaces but no runtime detection depends on.

Keys are entity-type strings. Values are short, narrative descriptions (one to
three sentences) modelled on the policy descriptions — written for the operator,
not the spec.
"""

from __future__ import annotations
from typing import Iterable


# ---------------------------------------------------------------------------
# Recognizer / entity descriptions
# ---------------------------------------------------------------------------

# Custom recognizers built into pii_guard.recognizers._RECOGNIZER_SPECS.
# Every entity in that list MUST have a description here. The Rules page
# uses this verbatim — write it for a smart non-expert.
RECOGNIZER_DESCRIPTIONS: dict[str, str] = {
    "TITLE_IX_CASE_ID": (
        "Title IX case identifiers, both the formatted TIX-YYYY-NNNN form and "
        "narrative references like 'Title IX investigation #12345'. Title IX "
        "records are categorically sensitive — a single match should be enough "
        "to redact a downstream payload."
    ),
    "IRB_PROTOCOL": (
        "Institutional Review Board protocol numbers (IRB-YYYY-NNNN, HS-YYYY-NNNN). "
        "These identify human-subjects research and pair to participants and "
        "investigators — treat them as research-sensitive identifiers."
    ),
    "FINANCIAL_AID_AWARD": (
        "Named federal aid awards paired with a dollar amount ('Pell Grant of "
        "$3,500', 'Subsidized Loan amount: $7,500'). Captures aid disclosures "
        "in narrative form — useful before logging or LLM hand-off."
    ),
    "STUDENT_ACCOUNT_ID": (
        "Payment-system identifiers from TouchNet, CashNet, and the Student "
        "Account Receivable system, plus explicit 'transaction id' / 'payment "
        "#' phrasing. Distinct from STUDENT_ID — these are billing keys, not "
        "person IDs."
    ),
    "LICENSE_PLATE": (
        "US license-plate patterns (state-issued formats like AB-1234) and "
        "explicit 'plate #' / 'tag #' phrasing. Used in parking and campus-"
        "safety workflows; gated on context to avoid matching random alphanumeric "
        "tokens."
    ),
    "STUDENT_ID": (
        "Numeric institutional student IDs in the 5-9 digit range — Doane's "
        "canonical 7-digit form (leading zeros allowed) plus peer-institution "
        "variations. Also catches single-letter-prefixed external-system IDs "
        "(S1234567, A1234567) seen in feeds from non-Doane SIS systems. Low "
        "base score; context words like 'id', 'student', 'banner', 'colleague' "
        "boost detection over the threshold."
    ),
    "DOANE_EMAIL": (
        "Email addresses on Doane's own domain (@doane.edu). Tagged separately "
        "from generic EMAIL_ADDRESS so policies can pass institutional email "
        "through (e.g., for internal exports) while still blocking external "
        "personal addresses."
    ),
    "DATE_OF_BIRTH": (
        "Birth dates in MM/DD/YYYY, YYYY-MM-DD, or written-month formats, "
        "with context words like 'dob', 'born', 'birthday'. Distinct from "
        "general DATE_TIME so it can be redacted on its own without losing "
        "calendar context elsewhere in the text."
    ),
    "FERPA_MARKER": (
        "Phrases that signal FERPA-protected content — academic records, "
        "transcripts, disciplinary records, GPA, financial aid, enrollment "
        "status, accommodations. Captures the *context* of student educational "
        "records even when no specific identifier is present."
    ),
    "FAFSA_ID": (
        "FAFSA-specific identifiers: state DOE numbers (NE-123456), FSA IDs, "
        "ISIR references, EFC dollar values. Federally restricted; treat as "
        "CRITICAL alongside SSN."
    ),
    "IMMIGRATION_STATUS": (
        "Visa types (F-1, J-1, H-1B, etc.), legal-status terms (DACA, "
        "undocumented, green card holder, naturalized citizen), and SEVIS / "
        "I-20 / DS-2019 references. CRITICAL risk: combining this signal with "
        "any identifier creates immigration-enforcement exposure."
    ),
    "DISABILITY_ACCOMMODATION": (
        "Phrases naming disability accommodations, IEPs, 504 plans, ADA "
        "services, assistive technology, and named impairments. CRITICAL "
        "because accommodations records carry both ADA and FERPA protections."
    ),
    "VETERAN_STATUS": (
        "Veteran / active-duty references, VA benefit programs (GI Bill, "
        "Chapter 33/30, Yellow Ribbon), DD-214 mentions, and VA payment "
        "amounts. Veteran-status disclosures are independently regulated by "
        "the VA's privacy rules."
    ),
    "HIPAA_MARKER": (
        "Healthcare phrasing covered by HIPAA — medical / mental health / "
        "counseling records, diagnoses, prescriptions, immunization status, "
        "and crisis indicators (suicidality, self-harm). Captures the HIPAA "
        "category even when no specific patient identifier is present."
    ),
    "FINANCIAL_ACCOUNT": (
        "Bank account / ACH routing numbers and explicit 'account #' / "
        "'routing' phrasing. Low-confidence bare-numeric patterns rely on "
        "context to avoid matching invoice numbers."
    ),
    "MEDICAL_LICENSE": (
        "Medical-provider license numbers — DEA, NPI (10-digit), state ML "
        "prefixes. Useful for student health center workflows that may name "
        "the prescriber."
    ),
    "US_SSN": (
        "US Social Security Numbers. Strict-format branches catch canonical "
        "XXX-XX-XXXX, spaced, dotted, and bare 9-digit forms. A separate "
        "'claimed-SSN' branch catches malformed numbers (XXX-XXX-XXXX typos, "
        "bare digits) when the surrounding text verbally claims they are SSNs "
        "('SSN:', 'social security number'). Anchor phrases are deliberately "
        "narrow — 'social' or 'number' alone are not enough."
    ),
}


# Presidio's built-in recognizers (those we expose via /api/v1/recognizers's
# presidio_builtins list). Describes what the built-in actually catches.
# Adding/removing built-ins in build_registry should sync this dict.
BUILTIN_DESCRIPTIONS: dict[str, str] = {
    "PERSON": (
        "Named people detected by spaCy's NER model. Catches first+last name "
        "combinations and known single-name forms. Pure-NLP signal — no regex "
        "— so coverage depends on the model. May over-fire on capitalized "
        "common words ('Fox' tagged as a name)."
    ),
    "EMAIL_ADDRESS": (
        "Generic email-address pattern. Captures any address shape "
        "local-part@domain.tld. Pairs with DOANE_EMAIL, which fires "
        "separately on @doane.edu addresses for institutional pass-through."
    ),
    "PHONE_NUMBER": (
        "US and international phone-number patterns (E.164, parenthesized "
        "area code, dash-separated). Will sometimes catch malformed SSNs in "
        "3-3-4 grouping — the claimed-SSN recognizer is the safety net for that."
    ),
    "CREDIT_CARD": (
        "Major-network credit card numbers with Luhn validation. Catches "
        "Visa/Mastercard/Amex/Discover formats; rejects test numbers."
    ),
    "LOCATION": (
        "Geographic locations from spaCy NER — cities, states, countries, "
        "addresses. Pure-NLP signal; granularity varies by context."
    ),
    "DATE_TIME": (
        "Calendar dates and times from Presidio's date recognizer plus spaCy "
        "NER. Will sometimes fire on bare digit strings that look date-shaped "
        "to the model. DATE_OF_BIRTH is a separate, narrower recognizer."
    ),
    "IP_ADDRESS": "IPv4 and IPv6 address patterns.",
    "URL": "Web URLs with scheme (http/https/ftp). Useful for log-safe scrubbing.",
    "US_PASSPORT": "US passport numbers (9-character alphanumeric).",
    "US_DRIVER_LICENSE": "US driver-license patterns (state-specific formats).",
    "US_BANK_NUMBER": "US bank routing numbers (9-digit ABA routing).",
    "US_ITIN": "Individual Taxpayer Identification Number (9XX-XX-XXXX format).",
    "IBAN_CODE": "International Bank Account Numbers (country code + check digits + account).",
    "CRYPTO": "Cryptocurrency wallet addresses (Bitcoin, Ethereum, etc.).",
    "NRP": (
        "Nationality / religious affiliation / political affiliation — spaCy NER "
        "labels. Catches sensitive demographic phrasing even when not explicitly "
        "marked."
    ),
    "ORGANIZATION": (
        "Organization names from spaCy NER. Not PII per se — but can correlate "
        "with employment / affiliation context. Note: the model occasionally "
        "tags short acronyms like 'SSN' or 'FBI' as organizations."
    ),
    "MEDICAL_LICENSE": "Medical-provider license numbers (overlapping with the custom recognizer above).",
}


# Entity-level descriptions — what KIND of PII this is and why we care.
# Used by the Entities section of the Rules page. Falls back to recognizer or
# built-in description if not set explicitly.
ENTITY_DESCRIPTIONS: dict[str, str] = {
    # Custom-recognizer entities mostly reuse the recognizer description.
    # Explicit overrides go here when the entity-level framing differs.
}


# ---------------------------------------------------------------------------
# Example matches per pattern
# ---------------------------------------------------------------------------

# Keyed by (entity_type, pattern_name). Each entry is two lists:
#   matches    — strings the pattern WILL match (positive examples)
#   no_matches — strings the pattern WILL NOT match (negative examples,
#                useful for boundary cases)
# Strings here should also appear in a characterization test where possible —
# the examples and the tests should not drift.
PATTERN_EXAMPLES: dict[tuple[str, str], dict[str, list[str]]] = {
    ("TITLE_IX_CASE_ID", "tix_case_id"): {
        "matches":    ["TIX-2024-001234", "TIX_2023_5678"],
        "no_matches": ["TIX-24-1234", "Title IX case file"],
    },
    ("TITLE_IX_CASE_ID", "tix_case_phrase"): {
        "matches":    ["Title IX investigation 12345", "Title IX case #98765"],
        "no_matches": ["Title IX office", "Title IX coordinator"],
    },
    ("IRB_PROTOCOL", "irb_number"): {
        "matches":    ["IRB-2024-123", "IRB_2023_4567"],
        "no_matches": ["IRB office", "IRB 12"],
    },
    ("IRB_PROTOCOL", "hs_protocol"): {
        "matches":    ["HS-2024-123", "HS_2025_98765"],
        "no_matches": ["HS room 2024-123"],
    },
    ("FINANCIAL_AID_AWARD", "named_award"): {
        "matches":    ["Pell Grant of $3,500", "Subsidized Loan amount: $5,500.00"],
        "no_matches": ["received a grant", "Pell-eligible student"],
    },
    ("STUDENT_ACCOUNT_ID", "touchnet_id"): {
        "matches":    ["TN-12345678", "TN_987654321012"],
        "no_matches": ["TN identifier", "tennessee 12345678"],
    },
    ("STUDENT_ACCOUNT_ID", "txn_explicit"): {
        "matches":    ["transaction id: 12345678", "payment #98765432"],
        "no_matches": ["transaction processed", "id 12345678"],
    },
    ("LICENSE_PLATE", "plate_explicit"): {
        "matches":    ["plate #: ABC1234", "tag number: XYZ-456"],
        "no_matches": ["license to drive"],
    },
    ("STUDENT_ID", "numeric"): {
        "matches":    ["1234567 (with 'id' nearby)", "0001234", "9876543"],
        "no_matches": ["1234 (too short)", "1234567890 (too long, looks like phone)"],
    },
    ("STUDENT_ID", "letter_prefixed"): {
        "matches":    ["S1234567", "A0001234", "P9876543"],
        "no_matches": ["s1234567 (lowercase)", "AB1234567 (multi-letter prefix)"],
    },
    ("DOANE_EMAIL", "doane_edu"): {
        "matches":    ["jsmith@doane.edu", "first.last+tag@doane.edu"],
        "no_matches": ["jsmith@cs.doane.edu (subdomain)", "jsmith@doane.com"],
    },
    ("DATE_OF_BIRTH", "mm_dd_yyyy"): {
        "matches":    ["03/15/1990", "11-02-1985"],
        "no_matches": ["3/15/90 (no year padding)", "13/01/2000 (invalid month)"],
    },
    ("DATE_OF_BIRTH", "written_dob"): {
        "matches":    ["March 15, 1990", "December 2 1985"],
        "no_matches": ["this March", "March of 1990"],
    },
    ("FERPA_MARKER", "ferpa_phrase"): {
        "matches":    ["GPA 3.5", "education record", "disciplinary record"],
        "no_matches": ["good record (no FERPA context)"],
    },
    ("FAFSA_ID", "fafsa_number"): {
        "matches":    ["NE-123456", "TX-987654"],
        "no_matches": ["NE 123 (no dash, too short)"],
    },
    ("FAFSA_ID", "isir_reference"): {
        "matches":    ["ISIR 12345678", "ISIR 4567"],
        "no_matches": ["ISIR was processed"],
    },
    ("IMMIGRATION_STATUS", "visa_types"): {
        "matches":    ["F-1 student", "DACA recipient", "I-20 expires soon"],
        "no_matches": ["F minor (different F)"],
    },
    ("DISABILITY_ACCOMMODATION", "accommodation_phrases"): {
        "matches":    ["504 plan", "ADHD diagnosis", "ADA accommodation", "extended time"],
        "no_matches": ["504 area code"],
    },
    ("VETERAN_STATUS", "veteran_phrases"): {
        "matches":    ["GI Bill recipient", "DD-214 required", "Chapter 33 benefits"],
        "no_matches": ["chapter 1 (book)"],
    },
    ("HIPAA_MARKER", "health_phrases"): {
        "matches":    ["medical record", "counseling session", "mental health appointment", "PHI"],
        "no_matches": ["health center hours"],
    },
    ("FINANCIAL_ACCOUNT", "account_explicit"): {
        "matches":    ["account: 1234567890", "routing 021000021"],
        "no_matches": ["account access"],
    },
    ("MEDICAL_LICENSE", "npi_10digit"): {
        "matches":    ["NPI: 1234567890", "NPI 9876543210"],
        "no_matches": ["NPI office"],
    },
    ("US_SSN", "ssn_dashed"): {
        "matches":    ["123-45-6789", "234-56-7890"],
        "no_matches": ["666-12-3456 (invalid area)", "123-00-4567 (invalid group)"],
    },
    ("US_SSN", "ssn_claimed"): {
        "matches":    ["SSN: 123-654-9898 (malformed 3-3-4)", "social security number is 123456789"],
        "no_matches": ["call 123-654-9898 (no SSN anchor)", "social media post 123-456-7890"],
    },
}


# ---------------------------------------------------------------------------
# Cross-data helpers
# ---------------------------------------------------------------------------

def reverse_field_hint_index(schemas: Iterable[dict]) -> dict[str, list[dict]]:
    """
    Given the schema catalog (list of dicts with 'name' and 'fields'), return
    a mapping of entity_type -> [{schema, field}, ...] so the Entities view
    can answer 'which fields across all schemas hint to STUDENT_ID?'
    """
    index: dict[str, list[dict]] = {}
    for schema in schemas:
        schema_name = schema.get("name")
        for field_name, entity_type in (schema.get("fields") or {}).items():
            index.setdefault(entity_type, []).append({
                "schema": schema_name,
                "field":  field_name,
            })
    for entries in index.values():
        entries.sort(key=lambda e: (e["schema"] or "", e["field"] or ""))
    return index


def policy_treatment(entity_type: str, policies: Iterable) -> list[dict]:
    """
    Given an entity type and the BUILT_IN_POLICIES dict values, return a list
    of {policy, treatment} explaining what each policy will do with this entity.

    treatment is one of: "block", "pass-through", "<mode>" (the policy's
    default_mode if the entity is neither blocked nor passed through), or
    "exclude-any" for ferpa_strict-style total-exclusion policies.
    """
    rows = []
    for p in policies:
        if entity_type in p.block_entity_types:
            t = "block"
        elif entity_type in p.pass_through_entity_types:
            t = "pass-through"
        elif p.exclude_any_pii:
            t = "exclude-any"
        else:
            t = p.default_mode.value
        rows.append({"policy": p.name, "treatment": t})
    return rows
