"""
pii_guard.policy - Named policies for context-aware PII handling.

Each policy encodes the right answer for a specific processing context.
Rather than asking every caller to configure modes and exclusions, they
name the context and the engine enforces the appropriate rules.

Built-in policies:
  ai_prompt       - Before sending to an LLM (Claude, GPT, etc.)
  embedding       - Before creating vector embeddings for RAG pipelines
  log_safe        - Before writing to application logs
  export_internal - Before including in internal Doane reports/exports
  export_external - Before sending outside the institution (CRITICAL gating)
  ferpa_strict    - Zero tolerance: exclude any chunk with any PII
  analytics       - Aggregate/dashboard use: pseudonymize, block financial
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import SanitizeMode, RiskLevel, ScanResult, PolicyResult, entity_risk


@dataclass
class PiiPolicy:
    name: str
    description: str
    # Entities in this list trigger immediate rejection (sanitized_text=None).
    # Used for entities that are categorically unacceptable in this context.
    block_entity_types: list[str]
    # Entity types to skip detection for (treated as acceptable).
    pass_through_entity_types: list[str]
    # Default sanitization mode applied to detected (non-blocked, non-passed) entities.
    default_mode: SanitizeMode
    # Requests with any hit at or above this risk level are flagged in the result.
    warn_at_risk: RiskLevel = RiskLevel.HIGH
    # If True, ANY detected PII (after pass-through filter) causes exclusion.
    exclude_any_pii: bool = False
    # Maximum batch size accepted under this policy (0 = use global limit).
    max_batch_size: int = 0


# ---------------------------------------------------------------------------
# Built-in policy definitions
# ---------------------------------------------------------------------------

BUILT_IN_POLICIES: dict[str, PiiPolicy] = {
    "ai_prompt": PiiPolicy(
        name="ai_prompt",
        description=(
            "Safe for generative AI calls. Masks personal identifiers. "
            "Blocks SSN, financial account numbers, and immigration status — "
            "these must never reach an external model. "
            "Dates and URLs pass through (usually needed for context)."
        ),
        block_entity_types=[
            "US_SSN", "CREDIT_CARD", "US_BANK_NUMBER", "US_ITIN",
            "US_PASSPORT", "US_DRIVER_LICENSE", "IBAN_CODE",
            "FINANCIAL_ACCOUNT", "IMMIGRATION_STATUS", "CRYPTO",
        ],
        pass_through_entity_types=["DATE_TIME", "URL", "IP_ADDRESS"],
        default_mode=SanitizeMode.MASK,
        warn_at_risk=RiskLevel.HIGH,
    ),

    "embedding": PiiPolicy(
        name="embedding",
        description=(
            "Safe for vector embeddings (pgvector, Pinecone, etc.). "
            "Pseudonymizes personal data to preserve semantic similarity. "
            "Excludes chunks containing FERPA markers, immigration status, "
            "financial data, or disability accommodations — these create "
            "retrieval risk if stored in an external vector index."
        ),
        block_entity_types=[
            "US_SSN", "CREDIT_CARD", "US_BANK_NUMBER", "US_ITIN",
            "US_PASSPORT", "IBAN_CODE", "FINANCIAL_ACCOUNT",
            "IMMIGRATION_STATUS", "DISABILITY_ACCOMMODATION",
            "FERPA_MARKER", "HIPAA_MARKER", "FAFSA_ID",
        ],
        pass_through_entity_types=["DATE_TIME", "URL"],
        default_mode=SanitizeMode.PSEUDONYMIZE,
        warn_at_risk=RiskLevel.MEDIUM,
    ),

    "log_safe": PiiPolicy(
        name="log_safe",
        description=(
            "Safe for application logs. Redacts all PII. "
            "Nothing personal belongs in log files — "
            "logs are often stored in less-controlled systems."
        ),
        block_entity_types=[],
        pass_through_entity_types=[],
        default_mode=SanitizeMode.REDACT,
        exclude_any_pii=False,
        warn_at_risk=RiskLevel.LOW,
    ),

    "export_internal": PiiPolicy(
        name="export_internal",
        description=(
            "Safe for internal Doane reports and exports. "
            "Masks personal identifiers. Allows institutional email (@doane.edu) "
            "and course dates. Blocks SSN, financial, and immigration data."
        ),
        block_entity_types=[
            "US_SSN", "CREDIT_CARD", "US_BANK_NUMBER", "US_ITIN",
            "US_PASSPORT", "IBAN_CODE", "FINANCIAL_ACCOUNT", "IMMIGRATION_STATUS",
        ],
        pass_through_entity_types=["DOANE_EMAIL", "DATE_TIME", "URL"],
        default_mode=SanitizeMode.MASK,
        warn_at_risk=RiskLevel.HIGH,
    ),

    "export_external": PiiPolicy(
        name="export_external",
        description=(
            "Safe for data leaving the institution. Most restrictive non-strict policy. "
            "Blocks all HIGH and CRITICAL entities. Pseudonymizes MEDIUM entities. "
            "Dates and URLs pass through."
        ),
        block_entity_types=[
            "US_SSN", "CREDIT_CARD", "US_BANK_NUMBER", "US_ITIN",
            "US_PASSPORT", "US_DRIVER_LICENSE", "IBAN_CODE", "FINANCIAL_ACCOUNT",
            "IMMIGRATION_STATUS", "DISABILITY_ACCOMMODATION", "VETERAN_STATUS",
            "EMAIL_ADDRESS", "DOANE_EMAIL", "PHONE_NUMBER", "STUDENT_ID",
            "DATE_OF_BIRTH", "FAFSA_ID",
            "FERPA_MARKER", "HIPAA_MARKER", "MEDICAL_LICENSE",
        ],
        pass_through_entity_types=["DATE_TIME", "URL"],
        default_mode=SanitizeMode.PSEUDONYMIZE,
        warn_at_risk=RiskLevel.MEDIUM,
    ),

    "ferpa_strict": PiiPolicy(
        name="ferpa_strict",
        description=(
            "Zero tolerance: exclude any chunk containing any PII. "
            "Use for highest-sensitivity FERPA contexts — financial aid records, "
            "disciplinary files, disability records. If a chunk contains PII of "
            "any kind, it is dropped entirely from the pipeline."
        ),
        block_entity_types=[],
        pass_through_entity_types=[],
        default_mode=SanitizeMode.EXCLUDE,
        exclude_any_pii=True,
        warn_at_risk=RiskLevel.LOW,
    ),

    "analytics": PiiPolicy(
        name="analytics",
        description=(
            "Safe for aggregate analytics and dashboards. "
            "Pseudonymizes personal data to preserve statistical patterns. "
            "Blocks financial and health data — these are not needed for analytics "
            "and carry disproportionate risk."
        ),
        block_entity_types=[
            "US_SSN", "CREDIT_CARD", "US_BANK_NUMBER", "IBAN_CODE",
            "FINANCIAL_ACCOUNT", "MEDICAL_LICENSE", "HIPAA_MARKER",
            "IMMIGRATION_STATUS", "DISABILITY_ACCOMMODATION",
        ],
        pass_through_entity_types=["DATE_TIME", "URL", "LOCATION"],
        default_mode=SanitizeMode.PSEUDONYMIZE,
        warn_at_risk=RiskLevel.HIGH,
    ),
}


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------

class PolicyEngine:

    def apply(self, policy: PiiPolicy, scan_result: ScanResult, original_text: str) -> PolicyResult:
        """
        Apply a policy to an already-scanned result.
        Returns a PolicyResult describing what happened.

        The scan_result already has hits filtered by the guard's score_threshold.
        We further filter by pass_through_entity_types, then check block_entity_types.
        """
        # Filter out pass-through entities
        relevant_hits = [
            h for h in scan_result.hits
            if h.entity_type not in policy.pass_through_entity_types
        ]

        if not relevant_hits:
            return PolicyResult(
                policy_name=policy.name,
                passed=True,
                action_taken="none",
                sanitized_text=original_text,
                blocked_entities=[],
                hit_count=0,
                risk_level=RiskLevel.LOW.value,
                original_safe=True,
            )

        # Check for blocked entities
        blocked = [h.entity_type for h in relevant_hits if h.entity_type in policy.block_entity_types]

        if blocked or (policy.exclude_any_pii and relevant_hits):
            return PolicyResult(
                policy_name=policy.name,
                passed=False,
                action_taken="excluded",
                sanitized_text=None,
                blocked_entities=list(set(blocked)) if blocked else [h.entity_type for h in relevant_hits],
                hit_count=len(relevant_hits),
                risk_level=max((entity_risk(h.entity_type) for h in relevant_hits),
                               key=lambda r: r._rank()).value,
                original_safe=False,
            )

        # Non-blocked hits: apply the policy's default mode
        action_map = {
            SanitizeMode.MASK:         "masked",
            SanitizeMode.REDACT:       "redacted",
            SanitizeMode.PSEUDONYMIZE: "pseudonymized",
            SanitizeMode.EXCLUDE:      "excluded",
        }
        risk = max((entity_risk(h.entity_type) for h in relevant_hits),
                   key=lambda r: r._rank())

        return PolicyResult(
            policy_name=policy.name,
            passed=True,
            action_taken=action_map.get(policy.default_mode, "masked"),
            sanitized_text=None,  # caller applies the actual sanitization
            blocked_entities=[],
            hit_count=len(relevant_hits),
            risk_level=risk.value,
            original_safe=False,
        )

    def list_policies(self) -> list[dict]:
        return [
            {
                "name": p.name,
                "description": p.description,
                "default_mode": p.default_mode.value,
                "exclude_any_pii": p.exclude_any_pii,
                "block_entity_types": p.block_entity_types,
                "pass_through_entity_types": p.pass_through_entity_types,
            }
            for p in BUILT_IN_POLICIES.values()
        ]


policy_engine = PolicyEngine()
