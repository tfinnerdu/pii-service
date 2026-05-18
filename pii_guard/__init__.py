"""
pii_guard - PII detection and sanitization for education-sector AI pipelines.

FERPA-aware. Runs fully local via Microsoft Presidio. No data leaves the machine.
"""

from .models import (
    SanitizeMode,
    RiskLevel,
    EntityHit,
    ScanResult,
    PreflightResult,
    PolicyResult,
    ENTITY_RISK_MAP,
    entity_risk,
)
from .guard import PiiGuard
from .recognizers import DOANE_RECOGNIZER_REGISTRY
from .policy import BUILT_IN_POLICIES, PiiPolicy, policy_engine

__all__ = [
    "PiiGuard",
    "SanitizeMode",
    "RiskLevel",
    "EntityHit",
    "ScanResult",
    "PreflightResult",
    "PolicyResult",
    "ENTITY_RISK_MAP",
    "entity_risk",
    "DOANE_RECOGNIZER_REGISTRY",
    "BUILT_IN_POLICIES",
    "PiiPolicy",
    "policy_engine",
]

__version__ = "1.0.0"
