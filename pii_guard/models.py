"""
pii_guard.models - Shared data types for the PII detection and sanitization pipeline.

Risk classification drives policy decisions and preflight recommendations.
Nothing in this module touches raw PII text; all types here are safe to log.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class SanitizeMode(str, Enum):
    MASK         = "mask"
    REDACT       = "redact"
    PSEUDONYMIZE = "pseudonymize"
    EXCLUDE      = "exclude"


class RiskLevel(str, Enum):
    """
    Sensitivity tiers aligned to FERPA and Doane data classification policy.
    CRITICAL: release = federal violation or financial fraud exposure.
    HIGH:     release = FERPA violation or targeted identity risk.
    MEDIUM:   release = institutional reputation or privacy concern.
    LOW:      release = minimal harm under most contexts.
    """
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    _ORDER = None  # populated below

    def _rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[self.value]

    def __lt__(self, other: "RiskLevel") -> bool:
        return self._rank() < other._rank()

    def __le__(self, other: "RiskLevel") -> bool:
        return self._rank() <= other._rank()

    def __gt__(self, other: "RiskLevel") -> bool:
        return self._rank() > other._rank()

    def __ge__(self, other: "RiskLevel") -> bool:
        return self._rank() >= other._rank()


# ---------------------------------------------------------------------------
# Entity risk classification — used for policy enforcement and preflight scoring
# ---------------------------------------------------------------------------

ENTITY_RISK_MAP: dict[str, RiskLevel] = {
    # CRITICAL — federal violation exposure or financial fraud
    "US_SSN":                   RiskLevel.CRITICAL,
    "CREDIT_CARD":              RiskLevel.CRITICAL,
    "US_BANK_NUMBER":           RiskLevel.CRITICAL,
    "US_ITIN":                  RiskLevel.CRITICAL,
    "US_PASSPORT":              RiskLevel.CRITICAL,
    "US_DRIVER_LICENSE":        RiskLevel.CRITICAL,
    "IBAN_CODE":                RiskLevel.CRITICAL,
    "FINANCIAL_ACCOUNT":        RiskLevel.CRITICAL,
    "IMMIGRATION_STATUS":       RiskLevel.CRITICAL,  # F-1/DACA exposure = federal risk
    "CRYPTO":                   RiskLevel.CRITICAL,
    # HIGH — FERPA violation or identity targeting
    "EMAIL_ADDRESS":            RiskLevel.HIGH,
    "PHONE_NUMBER":             RiskLevel.HIGH,
    "STUDENT_ID":               RiskLevel.HIGH,
    "DATE_OF_BIRTH":            RiskLevel.HIGH,
    "DOANE_EMAIL":              RiskLevel.HIGH,
    "FAFSA_ID":                 RiskLevel.HIGH,
    "DISABILITY_ACCOMMODATION": RiskLevel.HIGH,
    "VETERAN_STATUS":           RiskLevel.HIGH,
    "MEDICAL_LICENSE":          RiskLevel.HIGH,
    # MEDIUM — institutional or contextual sensitivity
    "PERSON":                   RiskLevel.MEDIUM,
    "LOCATION":                 RiskLevel.MEDIUM,
    "FERPA_MARKER":             RiskLevel.MEDIUM,
    "HIPAA_MARKER":             RiskLevel.MEDIUM,
    "NRP":                      RiskLevel.MEDIUM,
    # LOW — low harm potential in most contexts
    "DATE_TIME":                RiskLevel.LOW,
    "IP_ADDRESS":               RiskLevel.LOW,
    "URL":                      RiskLevel.LOW,
}


def entity_risk(entity_type: str) -> RiskLevel:
    return ENTITY_RISK_MAP.get(entity_type, RiskLevel.MEDIUM)


# ---------------------------------------------------------------------------
# Core result types
# ---------------------------------------------------------------------------

@dataclass
class EntityHit:
    entity_type: str
    start: int
    end: int
    score: float
    original: str  # raw matched text — never log, never serialize to API responses

    @property
    def risk_level(self) -> RiskLevel:
        return entity_risk(self.entity_type)


@dataclass
class ScanResult:
    original_text: str     # never serialize or log
    sanitized_text: Optional[str]
    hits: list[EntityHit]
    excluded: bool
    mode: str

    @property
    def is_clean(self) -> bool:
        return len(self.hits) == 0

    @property
    def risk_level(self) -> RiskLevel:
        if not self.hits:
            return RiskLevel.LOW
        return max((h.risk_level for h in self.hits), key=lambda r: r._rank())

    @property
    def entity_types(self) -> list[str]:
        return list({h.entity_type for h in self.hits})

    def summary(self) -> dict:
        """Safe dict for structured logging — no raw PII."""
        return {
            "mode": self.mode,
            "excluded": self.excluded,
            "pii_found": not self.is_clean,
            "risk_level": self.risk_level.value,
            "entity_types": self.entity_types,
            "hit_count": len(self.hits),
        }


@dataclass
class PreflightResult:
    """Result of an AI-safety preflight check."""
    safe_to_send: bool
    risk_level: RiskLevel
    blocking_entities: list[str]
    warning_entities: list[str]
    recommendation: str
    sanitized_suggestion: Optional[str]  # masked version; None if already safe
    hit_count: int


@dataclass
class PolicyResult:
    """Result of applying a named policy to text."""
    policy_name: str
    passed: bool
    action_taken: str           # "none" | "masked" | "pseudonymized" | "excluded" | "rejected"
    sanitized_text: Optional[str]
    blocked_entities: list[str]
    hit_count: int
    risk_level: str
    original_safe: bool
