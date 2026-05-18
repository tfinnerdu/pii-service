"""
examples/usage.py - Practical PiiGuard usage patterns for the Doane AI platform.

Run from project root:
    python examples/usage.py
"""

import sys
sys.path.insert(0, ".")

from pii_guard import PiiGuard, SanitizeMode
from pii_guard.policy import BUILT_IN_POLICIES, policy_engine

guard = PiiGuard(score_threshold=0.5, use_spacy=False)

SAMPLE_TEXTS = [
    "John Smith (D1234567) has an outstanding balance of $3,200. His SSN is 123-45-6789.",
    "Contact advisor at jsmith@doane.edu or 402-826-8221.",
    "Student GPA is 3.45 and enrolled full-time for Fall 2024.",
    "International student on F-1 visa. SEVIS ID must be updated.",
    "Student has a disability accommodation: extended time on exams.",
    "No personal data in this sentence at all.",
]


def example_preflight():
    print("\n=== Preflight Check (AI Safety Gate) ===")
    for text in SAMPLE_TEXTS[:3]:
        result = guard.preflight(text)
        status = "SAFE" if result.safe_to_send else f"NOT SAFE ({result.risk_level.value})"
        print(f"  [{status}] {text[:60]}...")
        if not result.safe_to_send:
            print(f"    Blocking: {result.blocking_entities}")
            print(f"    Suggestion: {result.sanitized_suggestion[:60]}...")


def example_named_policy():
    print("\n=== Named Policy (ai_prompt) ===")
    policy = BUILT_IN_POLICIES["ai_prompt"]
    for text in SAMPLE_TEXTS:
        scan = guard.scan(text)
        result = policy_engine.apply(policy, scan, text)
        if not result.passed:
            print(f"  [BLOCKED] {text[:60]} -> blocked: {result.blocked_entities}")
        elif result.hit_count > 0:
            sanitized = guard.sanitize(text, mode=policy.default_mode,
                                       exclude_entity_types=policy.pass_through_entity_types)
            print(f"  [MASKED]  {sanitized.sanitized_text[:60]}")
        else:
            print(f"  [CLEAN]   {text[:60]}")


def example_embedding_pipeline():
    print("\n=== Embedding Pipeline (pseudonymize) ===")
    for text in SAMPLE_TEXTS:
        result = guard.sanitize(text, mode=SanitizeMode.PSEUDONYMIZE)
        status = "CLEAN" if result.is_clean else f"SANITIZED ({result.risk_level.value})"
        print(f"  [{status}] {result.sanitized_text[:70]}")


def example_batch_with_schema():
    print("\n=== Batch RAG Prep ===")
    results = guard.sanitize_batch(SAMPLE_TEXTS, mode=SanitizeMode.EXCLUDE)
    embedded = [r.sanitized_text for r in results if not r.excluded]
    excluded = [i for i, r in enumerate(results) if r.excluded]
    print(f"  Embedded: {len(embedded)}/{len(results)} chunks")
    print(f"  Excluded indices: {excluded}")


def example_structured_record():
    print("\n=== Structured Record (Conductor/Salesforce payload) ===")
    payload = {
        "personId": "D1234567",
        "operation": "updated",
        "notes": "Student called re: SSN 123-45-6789 and financial aid hold.",
        "advisorEmail": "jadvisor@doane.edu",
        "gpa": 3.45,
        "term": "2024FA",
    }
    clean_payload, excluded = guard.sanitize_dict(
        payload, fields=["notes", "advisorEmail"], mode=SanitizeMode.MASK
    )
    print(f"  Original notes:  {payload['notes']}")
    print(f"  Cleaned notes:   {clean_payload['notes']}")
    print(f"  personId:        {clean_payload['personId']} (unchanged)")
    print(f"  Excluded fields: {excluded}")


if __name__ == "__main__":
    print("PiiGuard Usage Examples (regex-only mode)")
    print("=" * 60)
    example_preflight()
    example_named_policy()
    example_embedding_pipeline()
    example_batch_with_schema()
    example_structured_record()
    print("\nDone.")
