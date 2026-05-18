"""
pii_guard.recognizers - Custom Presidio recognizers for education-sector PII patterns.

Presidio imports are deferred to build_registry() so this module can be imported
without presidio-analyzer installed — critical for unit tests that test regex patterns
directly and for fast imports in non-Presidio contexts.

Design note: low-confidence patterns use low scores and rely on context keywords
to boost detection. This reduces false positives on course numbers and section IDs.
"""

import re


# ---------------------------------------------------------------------------
# Recognizer specifications (pure data — no Presidio types at module load time)
#
# Each spec: { entity, name, patterns: [(name, regex, score), ...], context: [...] }
# ---------------------------------------------------------------------------

_RECOGNIZER_SPECS = [
    {
        "entity": "STUDENT_ID",
        "name": "StudentIdRecognizer",
        "patterns": [
            ("doane_d_prefix",   r"\bD\d{7}\b",    0.9),
            ("colleague_at",     r"@\d{7,8}\b",    0.85),
            ("banner_numeric",   r"\b[0-9]{7}\b",  0.35),
        ],
        "context": ["student", "id", "banner", "colleague", "sis", "person", "account", "enrollee"],
    },
    {
        "entity": "COLLEAGUE_ID",
        "name": "ColleagueIdRecognizer",
        "patterns": [
            ("colleague_numeric", r"\b\d{6,8}\b", 0.3),
        ],
        "context": ["colleague", "person.id", "person_id", "ellucian", "erp", "record id", "colleague id"],
    },
    {
        "entity": "DOANE_EMAIL",
        "name": "DoaneEmailRecognizer",
        "patterns": [
            ("doane_edu", r"\b[a-zA-Z0-9._%+\-]+@doane\.edu\b", 0.95),
        ],
        "context": [],
    },
    {
        "entity": "DATE_OF_BIRTH",
        "name": "DateOfBirthRecognizer",
        "patterns": [
            ("mm_dd_yyyy",   r"\b(0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])[-/](19|20)\d{2}\b",  0.55),
            ("yyyy_mm_dd",   r"\b(19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b",  0.55),
            ("written_dob",  r"\b(January|February|March|April|May|June|July|August|September|"
                             r"October|November|December)\s+\d{1,2},?\s+(?:19|20)\d{2}\b",       0.5),
        ],
        "context": ["dob", "born", "birth", "birthdate", "date of birth", "birthday", "age", "born on"],
    },
    {
        "entity": "FERPA_MARKER",
        "name": "FerpaMarkerRecognizer",
        "patterns": [
            ("ferpa_phrase",
             r"\b(education record|academic record|transcript|"
             r"disciplinary record|financial aid|tuition balance|"
             r"GPA|grade point average|enrollment status|cumulative GPA|"
             r"degree audit|student account|disability accommodation|"
             r"academic standing|academic probation|academic suspension|"
             r"satisfactory academic progress|SAP status|"
             r"incomplete grade|withdrawal|course withdrawal)\b",
             0.65),
        ],
        "context": ["student", "confidential", "restricted", "protected", "ferpa", "record"],
    },
    {
        "entity": "FAFSA_ID",
        "name": "FafsaIdRecognizer",
        "patterns": [
            ("fafsa_number",    r"\b[A-Z]{2}-\d{6}\b",              0.7),
            ("fsa_id",          r"\bFSA[-\s]?ID\b",                  0.55),
            ("isir_reference",  r"\bISIR\s+\d{4,10}\b",              0.75),
            ("efc_value",       r"\bEFC[:\s]+\$?\d{1,6}(?:\.\d{2})?\b", 0.6),
        ],
        "context": ["fafsa", "financial aid", "fsa", "federal", "aid", "efc", "expected family", "isir"],
    },
    {
        "entity": "IMMIGRATION_STATUS",
        "name": "ImmigrationStatusRecognizer",
        "patterns": [
            ("visa_types",
             r"\b(F-1|F1|J-1|J1|M-1|M1|H-1B|H1B|O-1|O1|TN|DACA|"
             r"undocumented|permanent resident|green card holder|"
             r"naturalized citizen|non-immigrant|I-94|I94|"
             r"SEVIS|sevis id|sevis number|DS-2019|I-20)\b",
             0.8),
            ("visa_expiry",
             r"\b(visa|I-20|DS-2019)\s+(?:expires?|expiration|exp\.?)\s*:?\s*\d",
             0.85),
        ],
        "context": ["international", "student", "visa", "immigration", "status", "dhs", "sevis", "uscis"],
    },
    {
        "entity": "DISABILITY_ACCOMMODATION",
        "name": "DisabilityAccommodationRecognizer",
        "patterns": [
            ("accommodation_phrases",
             r"\b(disability (?:accommodation|services?|office)|"
             r"ADA accommodation|504 plan|IEP|individualized education|"
             r"testing accommodation|extended time|alternative format|"
             r"note-?taker|sign language interpreter|assistive technolog|"
             r"hearing impair|visually impair|learning disabilit|"
             r"attention deficit|ADHD|autism spectrum|accommodations? letter)\b",
             0.75),
        ],
        "context": ["student", "disability", "accommodation", "ada", "504", "services", "support"],
    },
    {
        "entity": "VETERAN_STATUS",
        "name": "VeteranStatusRecognizer",
        "patterns": [
            ("veteran_phrases",
             r"\b(veteran|active duty|military|VA benefit|GI Bill|"
             r"Post-9/11|Chapter 33|Chapter 30|Chapter 1606|"
             r"Yellow Ribbon|military leave|deployment|servicemember|"
             r"National Guard|Reserve component|DD-214|DD214)\b",
             0.65),
            ("va_payment",
             r"\bVA\s+(?:payment|benefit|allowance|stipend)\s+of\s+\$[\d,]+",
             0.85),
        ],
        "context": ["veteran", "military", "va", "gi", "benefit", "service", "deployment"],
    },
    {
        "entity": "HIPAA_MARKER",
        "name": "HipaaMarkerRecognizer",
        "patterns": [
            ("health_phrases",
             r"\b(health record|medical record|mental health|"
             r"counseling (?:record|note|session)|psychiatric|"
             r"diagnosis|prescription|medication|treatment plan|"
             r"protected health information|PHI|HIPAA|"
             r"immunization record|vaccination|allergy|"
             r"campus health|student health center|"
             r"behavioral health|substance (?:abuse|use)|"
             r"eating disorder|suicid|self-harm)\b",
             0.7),
        ],
        "context": ["health", "medical", "patient", "student", "counseling", "hipaa", "phi"],
    },
    {
        "entity": "FINANCIAL_ACCOUNT",
        "name": "FinancialAccountRecognizer",
        "patterns": [
            ("ach_routing",      r"\b0[0-9]{8}\b",                                0.45),
            ("account_number",   r"\b\d{10,17}\b",                                0.3),
            ("account_explicit", r"\b(?:account|routing|acct)[\s#:]*\d{8,17}\b", 0.75),
        ],
        "context": ["routing", "account", "ach", "bank", "direct deposit", "checking", "savings", "wire"],
    },
    {
        "entity": "MEDICAL_LICENSE",
        "name": "MedicalLicenseRecognizer",
        "patterns": [
            ("ml_prefix",    r"\b(ML|DEA)[- ]?\d{6,10}\b", 0.75),
            ("npi_10digit",  r"\bNPI[: ]\d{10}\b",          0.9),
            ("npi_bare",     r"\b\d{10}\b",                 0.35),
        ],
        "context": ["license", "npi", "dea", "medical", "provider", "prescriber", "physician", "nurse"],
    },
]


# ---------------------------------------------------------------------------
# Regex-only accessors (no Presidio needed) — used by characterization tests
# ---------------------------------------------------------------------------

def get_patterns_for_entity(entity_type: str) -> list[tuple[str, str, float]]:
    """Return the raw (name, regex, score) patterns for a given entity type."""
    for spec in _RECOGNIZER_SPECS:
        if spec["entity"] == entity_type:
            return list(spec["patterns"])
    return []


# ---------------------------------------------------------------------------
# Registry builder — only function that needs Presidio
# ---------------------------------------------------------------------------

def build_registry():
    """
    Build a RecognizerRegistry with all default Presidio recognizers plus
    Doane/education-specific custom recognizers.
    Passed to AnalyzerEngine at initialization.
    """
    from presidio_analyzer import PatternRecognizer, Pattern, RecognizerRegistry

    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()

    for spec in _RECOGNIZER_SPECS:
        patterns = [Pattern(n, rx, sc) for n, rx, sc in spec["patterns"]]
        recognizer = PatternRecognizer(
            supported_entity=spec["entity"],
            name=spec["name"],
            patterns=patterns,
            context=spec.get("context", []),
        )
        registry.add_recognizer(recognizer)

    return registry


# Exported for introspection, tests, and the /api/v1/entities endpoint
DOANE_RECOGNIZER_REGISTRY: list[str] = [spec["entity"] for spec in _RECOGNIZER_SPECS]
