"""
pii_guard.guard - Core PII scanning, sanitization, and preflight logic.

FERPA note: Presidio runs fully local. No text leaves the machine.

Modes:
  MASK         - Replace PII with [ENTITY_TYPE] tokens. Use before LLM calls.
  REDACT       - Replace with *** stars. Use for logs. Destroys embedding semantics.
  PSEUDONYMIZE - Consistent fake-but-plausible values. Best for RAG embeddings.
  EXCLUDE      - Return None if ANY PII found. Drop the chunk entirely.

Pseudonymization is deterministic within a session (same input -> same fake output)
via MD5-seeded substitution. Call reset_pseudo_cache() between unrelated document batches.
"""

import hashlib
import logging
from typing import Optional

from .models import (
    SanitizeMode, RiskLevel, EntityHit, ScanResult, PreflightResult,
    entity_risk,
)

logger = logging.getLogger("pii_guard")


# ---------------------------------------------------------------------------
# Preflight thresholds
# ---------------------------------------------------------------------------

_PREFLIGHT_BLOCK_RISK = RiskLevel.HIGH   # risk >= HIGH -> not safe_to_send without sanitization
_PREFLIGHT_WARN_RISK  = RiskLevel.MEDIUM # risk >= MEDIUM -> warn

_PREFLIGHT_RECOMMENDATIONS = {
    RiskLevel.LOW:      "Safe to send as-is. No significant PII detected.",
    RiskLevel.MEDIUM:   "Consider masking PERSON and LOCATION before sending to an external AI service.",
    RiskLevel.HIGH:     "Mask before sending. Personal identifiers detected (email, phone, student ID).",
    RiskLevel.CRITICAL: "Do not send. Critical PII detected (SSN, financial account, immigration status). "
                        "Sanitize with mask or pseudonymize mode first.",
}


class PiiGuard:
    """
    Main entry point for PII detection and sanitization.

    Usage:
        guard = PiiGuard()

        # AI preflight check
        check = guard.preflight("John Smith SSN 123-45-6789 asks about CSCI 101")

        # For generative AI calls:
        clean = guard.sanitize(text, mode=SanitizeMode.MASK)

        # For embeddings:
        clean = guard.sanitize(text, mode=SanitizeMode.PSEUDONYMIZE)

        # For strict pipelines:
        clean = guard.sanitize(text, mode=SanitizeMode.EXCLUDE)

        # For structured records (Conductor payloads, Salesforce data):
        clean_record, excluded_fields = guard.sanitize_dict(record, fields=["notes", "bio"])
    """

    def __init__(
        self,
        score_threshold: float = 0.5,
        languages: list[str] = None,
        entities: list[str] = None,
        use_spacy: bool = True,
    ):
        """
        Args:
            score_threshold: Minimum Presidio confidence score (0.0-1.0).
                             0.5 balances precision vs. recall for most ed data.
                             Raise to 0.7+ to reduce false positives on numeric IDs.
            languages:       Language codes. Defaults to ["en"].
            entities:        Entity types to detect. None = all available.
            use_spacy:       Include spaCy NLP for PERSON/LOCATION accuracy.
                             Requires en_core_web_lg (~750MB). Set False for regex-only.
        """
        self.score_threshold = score_threshold
        self.languages = languages or ["en"]
        self.entities = entities
        self._use_spacy = use_spacy
        self._analyzer = None
        self._anonymizer = None
        self._pseudo_cache: dict[str, str] = {}
        self._initialized = False

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            from presidio_anonymizer import AnonymizerEngine
            from .recognizers import build_registry

            model = "en_core_web_lg" if self._use_spacy else "en_core_web_sm"
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": model}],
            })
            nlp_engine = provider.create_engine()
            registry = build_registry()

            self._analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                registry=registry,
                supported_languages=self.languages,
            )
            self._anonymizer = AnonymizerEngine()
            self._initialized = True
            logger.info("PiiGuard initialized (spacy=%s, model=%s)", self._use_spacy, model)

        except ImportError as exc:
            raise RuntimeError(
                "presidio-analyzer and presidio-anonymizer are required. "
                "Run: pip install presidio-analyzer presidio-anonymizer spacy "
                "&& python -m spacy download en_core_web_lg"
            ) from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, text: str) -> ScanResult:
        """
        Detect PII in text. Returns hits without modifying text.
        Use sanitize() if you need cleaned output.
        """
        self._ensure_initialized()
        hits = self._analyze(text)
        return ScanResult(
            original_text=text,
            sanitized_text=text,
            hits=hits,
            excluded=False,
            mode="scan",
        )

    def sanitize(
        self,
        text: str,
        mode: SanitizeMode = SanitizeMode.MASK,
        exclude_entity_types: list[str] = None,
    ) -> ScanResult:
        """
        Scan and sanitize text according to mode.

        Args:
            text:                 Input text (may contain PII).
            mode:                 Sanitization mode (see SanitizeMode).
            exclude_entity_types: Entity types to skip even if detected.
                                  Example: ["DATE_TIME"] to let dates pass through.
        """
        self._ensure_initialized()

        if not text or not text.strip():
            return ScanResult(
                original_text=text,
                sanitized_text=text,
                hits=[],
                excluded=False,
                mode=mode.value,
            )

        hits = self._analyze(text, skip_types=exclude_entity_types)

        if not hits:
            return ScanResult(
                original_text=text,
                sanitized_text=text,
                hits=[],
                excluded=False,
                mode=mode.value,
            )

        if mode == SanitizeMode.EXCLUDE:
            logger.info("chunk excluded — %s", {"entity_types": [h.entity_type for h in hits]})
            return ScanResult(
                original_text=text,
                sanitized_text=None,
                hits=hits,
                excluded=True,
                mode=mode.value,
            )

        if mode == SanitizeMode.PSEUDONYMIZE:
            sanitized = self._pseudonymize(text, hits)
        else:
            sanitized = self._presidio_anonymize(text, hits, mode)

        result = ScanResult(
            original_text=text,
            sanitized_text=sanitized,
            hits=hits,
            excluded=False,
            mode=mode.value,
        )
        logger.info("sanitized — %s", result.summary())
        return result

    def sanitize_batch(
        self,
        texts: list[str],
        mode: SanitizeMode = SanitizeMode.MASK,
        exclude_entity_types: list[str] = None,
    ) -> list[ScanResult]:
        """Sanitize a list of texts. In EXCLUDE mode, excluded items have sanitized_text=None."""
        return [self.sanitize(t, mode, exclude_entity_types) for t in texts]

    def sanitize_dict(
        self,
        record: dict,
        fields: list[str],
        mode: SanitizeMode = SanitizeMode.MASK,
        exclude_entity_types: list[str] = None,
    ) -> tuple[dict, list[str]]:
        """
        Sanitize specific string fields in a dict record.
        Returns (sanitized_record, list_of_excluded_field_names).
        Non-string fields and fields not in `fields` are passed through unchanged.
        Useful for preprocessing Conductor workflow inputs and Salesforce payloads.
        """
        sanitized = dict(record)
        excluded_fields = []

        for f in fields:
            val = record.get(f)
            if not isinstance(val, str):
                continue
            result = self.sanitize(val, mode, exclude_entity_types)
            if result.excluded:
                excluded_fields.append(f)
                sanitized[f] = None
            else:
                sanitized[f] = result.sanitized_text

        return sanitized, excluded_fields

    def preflight(self, text: str) -> PreflightResult:
        """
        AI safety preflight check. Scans text and returns a risk assessment
        with a human-readable recommendation.

        Returns:
            PreflightResult with safe_to_send, risk_level, blocking_entities,
            warning_entities, recommendation, and sanitized_suggestion.
        """
        self._ensure_initialized()
        hits = self._analyze(text)

        if not hits:
            return PreflightResult(
                safe_to_send=True,
                risk_level=RiskLevel.LOW,
                blocking_entities=[],
                warning_entities=[],
                recommendation=_PREFLIGHT_RECOMMENDATIONS[RiskLevel.LOW],
                sanitized_suggestion=None,
                hit_count=0,
            )

        risk = max((entity_risk(h.entity_type) for h in hits), key=lambda r: r._rank())

        blocking = [h.entity_type for h in hits if entity_risk(h.entity_type) >= _PREFLIGHT_BLOCK_RISK]
        warning  = [h.entity_type for h in hits if entity_risk(h.entity_type) == RiskLevel.MEDIUM]

        safe = risk < _PREFLIGHT_BLOCK_RISK

        suggestion = None
        if not safe:
            # Provide a masked suggestion so the caller can send something useful
            masked = self._presidio_anonymize(text, hits, SanitizeMode.MASK)
            suggestion = masked

        return PreflightResult(
            safe_to_send=safe,
            risk_level=risk,
            blocking_entities=list(set(blocking)),
            warning_entities=list(set(warning)),
            recommendation=_PREFLIGHT_RECOMMENDATIONS[risk],
            sanitized_suggestion=suggestion,
            hit_count=len(hits),
        )

    def scan_structured(
        self,
        record: dict,
        fields: list[str] = None,
        exclude_entity_types: list[str] = None,
    ) -> dict:
        """
        Scan all string fields in a dict record (or a specified subset).
        Returns a field-by-field scan report. No text is modified.

        Returns:
            {
              "field_name": {
                "pii_found": bool,
                "hit_count": int,
                "entity_types": [...],
                "risk_level": "LOW|MEDIUM|HIGH|CRITICAL"
              },
              ...
              "_summary": { "total_hits": int, "highest_risk": str, "flagged_fields": [...] }
            }
        """
        self._ensure_initialized()
        report = {}
        total_hits = 0
        highest_risk = RiskLevel.LOW
        flagged = []

        target_fields = fields if fields is not None else [
            k for k, v in record.items() if isinstance(v, str)
        ]

        for field_name in target_fields:
            val = record.get(field_name)
            if not isinstance(val, str):
                report[field_name] = {"skipped": True, "reason": "non-string field"}
                continue

            hits = self._analyze(val, skip_types=exclude_entity_types)
            risk = (
                max((entity_risk(h.entity_type) for h in hits), key=lambda r: r._rank())
                if hits else RiskLevel.LOW
            )
            if hits:
                total_hits += len(hits)
                if risk > highest_risk:
                    highest_risk = risk
                flagged.append(field_name)

            report[field_name] = {
                "pii_found": bool(hits),
                "hit_count": len(hits),
                "entity_types": list({h.entity_type for h in hits}),
                "risk_level": risk.value,
            }

        report["_summary"] = {
            "total_hits": total_hits,
            "highest_risk": highest_risk.value,
            "flagged_fields": flagged,
        }
        return report

    def reset_pseudo_cache(self) -> None:
        """
        Clear the pseudonymization consistency cache.
        Call between unrelated document batches so "John Smith" in doc A
        gets a different fake name than "John Smith" in doc B.
        """
        self._pseudo_cache.clear()

    # ------------------------------------------------------------------
    # Internal analysis
    # ------------------------------------------------------------------

    def _analyze(self, text: str, skip_types: list[str] = None) -> list[EntityHit]:
        results = self._analyzer.analyze(
            text=text,
            entities=self.entities,
            language="en",
            score_threshold=self.score_threshold,
        )
        skip_types = set(skip_types or [])
        hits = []
        for r in results:
            if r.entity_type in skip_types:
                continue
            hits.append(EntityHit(
                entity_type=r.entity_type,
                start=r.start,
                end=r.end,
                score=r.score,
                original=text[r.start:r.end],
            ))
        # Sort descending by start — replace right-to-left to avoid offset drift
        hits.sort(key=lambda h: h.start, reverse=True)
        return hits

    def _presidio_anonymize(self, text: str, hits: list[EntityHit], mode: SanitizeMode) -> str:
        from presidio_anonymizer.entities import OperatorConfig
        from presidio_analyzer import RecognizerResult

        analyzer_results = [
            RecognizerResult(entity_type=h.entity_type, start=h.start, end=h.end, score=h.score)
            for h in hits
        ]

        if mode == SanitizeMode.MASK:
            operator_config = {
                h.entity_type: OperatorConfig("replace", {"new_value": f"[{h.entity_type}]"})
                for h in hits
            }
            result = self._anonymizer.anonymize(
                text=text,
                analyzer_results=analyzer_results,
                operators=operator_config,
            )
        elif mode == SanitizeMode.REDACT:
            result = self._anonymizer.anonymize(
                text=text,
                analyzer_results=analyzer_results,
                operators={"DEFAULT": OperatorConfig("redact", {})},
            )
        else:
            result = self._anonymizer.anonymize(
                text=text,
                analyzer_results=analyzer_results,
            )

        return result.text

    def _pseudonymize(self, text: str, hits: list[EntityHit]) -> str:
        chars = list(text)
        for hit in hits:
            fake = self._get_pseudo_value(hit.entity_type, hit.original)
            chars[hit.start:hit.end] = list(fake)
        return "".join(chars)

    def _get_pseudo_value(self, entity_type: str, original: str) -> str:
        cache_key = f"{entity_type}::{original}"
        if cache_key in self._pseudo_cache:
            return self._pseudo_cache[cache_key]
        seed = int(hashlib.md5(original.encode()).hexdigest()[:8], 16)
        fake = _generate_pseudo(entity_type, seed)
        self._pseudo_cache[cache_key] = fake
        return fake


# ---------------------------------------------------------------------------
# Pseudonym generators — plausible fake values by entity type
# ---------------------------------------------------------------------------

_FAKE_FIRST  = ["Alex", "Jordan", "Casey", "Morgan", "Taylor", "Riley", "Drew", "Quinn", "Avery", "Blake"]
_FAKE_LAST   = ["Rivera", "Chen", "Okafor", "Novak", "Patel", "Santos", "Kim", "Andersen", "Muller", "Diaz"]
_FAKE_CITIES = ["Springfield", "Shelbyville", "Centerville", "Greenfield", "Maplewood", "Riverdale"]
_FAKE_DOMAINS = ["example.com", "test.edu", "placeholder.org", "sample.net"]


def _generate_pseudo(entity_type: str, seed: int) -> str:
    r = seed

    if entity_type == "PERSON":
        return f"{_FAKE_FIRST[r % len(_FAKE_FIRST)]} {_FAKE_LAST[(r >> 4) % len(_FAKE_LAST)]}"

    if entity_type in ("EMAIL_ADDRESS", "DOANE_EMAIL"):
        first  = _FAKE_FIRST[r % len(_FAKE_FIRST)].lower()
        domain = _FAKE_DOMAINS[r % len(_FAKE_DOMAINS)]
        return f"{first}.test@{domain}"

    if entity_type == "PHONE_NUMBER":
        n = (r % 8000000) + 2000000
        return f"(555) {n:07d}"[:14]

    if entity_type in ("US_SSN",):
        a = (r % 899) + 100
        b = (r % 89) + 10
        c = (r % 8999) + 1000
        return f"{a:03d}-{b:02d}-{c:04d}"

    if entity_type in ("CREDIT_CARD",):
        return "4111-1111-1111-1111"  # Luhn-valid Visa test number

    if entity_type in ("DATE_TIME", "DATE_OF_BIRTH"):
        month = (r % 12) + 1
        day   = (r % 28) + 1
        year  = 1970 + (r % 35)
        return f"{month:02d}/{day:02d}/{year}"

    if entity_type == "LOCATION":
        return _FAKE_CITIES[r % len(_FAKE_CITIES)]

    if entity_type in ("STUDENT_ID", "BANNER_ID", "COLLEAGUE_ID"):
        return f"D{(r % 9000000) + 1000000:07d}"

    if entity_type == "FAFSA_ID":
        return f"NE-{(r % 900000) + 100000:06d}"

    if entity_type == "IP_ADDRESS":
        return f"192.0.2.{r % 254 + 1}"  # TEST-NET-1 (RFC 5737)

    if entity_type == "URL":
        return "https://example.com/redacted"

    if entity_type == "IBAN_CODE":
        return "GB00FAKE00000000000000"

    if entity_type in ("MEDICAL_LICENSE",):
        return f"ML{r % 999999:06d}"

    if entity_type in ("FINANCIAL_ACCOUNT", "US_BANK_NUMBER"):
        return "0000000000"  # zeroed placeholder

    if entity_type in ("US_PASSPORT",):
        return "A00000000"

    if entity_type in ("US_DRIVER_LICENSE",):
        return "DL000000"

    if entity_type in ("IMMIGRATION_STATUS",):
        return "[VISA_TYPE]"

    if entity_type in ("DISABILITY_ACCOMMODATION",):
        return "[ACCOMMODATION]"

    if entity_type in ("VETERAN_STATUS",):
        return "[VETERAN_STATUS]"

    if entity_type in ("NRP",):
        return "[SENSITIVE_ATTRIBUTE]"

    # Fallback for unmapped types
    return f"[{entity_type}]"
