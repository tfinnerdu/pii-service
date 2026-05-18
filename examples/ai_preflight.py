"""
examples/ai_preflight.py - AI preflight gate pattern.

Shows how to use pii-service as a safety gate before any AI API call.
Works with Claude API, OpenAI, or any LLM.

Run from project root:
    python examples/ai_preflight.py
"""

import sys
sys.path.insert(0, ".")

from pii_guard import PiiGuard, SanitizeMode, RiskLevel
from pii_guard.policy import BUILT_IN_POLICIES, policy_engine

guard = PiiGuard(score_threshold=0.5, use_spacy=False)


def safe_ai_call(user_input: str, model_name: str = "claude-sonnet-4-6") -> str:
    """
    Wrapper: run preflight check, sanitize if needed, then call the AI.
    In production, replace the stub with a real API call.
    """
    # Step 1: preflight check
    check = guard.preflight(user_input)
    print(f"  Preflight: safe={check.safe_to_send}, risk={check.risk_level.value}")

    if check.safe_to_send:
        text_for_ai = user_input
        was_sanitized = False
    elif check.sanitized_suggestion:
        text_for_ai = check.sanitized_suggestion
        was_sanitized = True
        print(f"  Sanitized: {text_for_ai[:60]}...")
    else:
        # Policy blocked entirely — don't send at all
        return f"[BLOCKED: text contains {check.blocking_entities} — cannot send to AI]"

    # Step 2: (stub) call the AI model
    # In production:
    #   import anthropic
    #   client = anthropic.Anthropic()
    #   message = client.messages.create(
    #       model=model_name,
    #       max_tokens=1024,
    #       messages=[{"role": "user", "content": text_for_ai}]
    #   )
    #   response = message.content[0].text
    response = f"[AI STUB] Would send to {model_name}: '{text_for_ai[:50]}...'"

    suffix = " (text was sanitized before sending)" if was_sanitized else ""
    return response + suffix


def policy_gate_example():
    """
    Alternative: use the ai_prompt policy for batch processing.
    The policy handles all the blocking/mode decisions.
    """
    print("\n=== Policy Gate (ai_prompt) ===")
    policy = BUILT_IN_POLICIES["ai_prompt"]

    texts = [
        "What courses are available in spring semester?",
        "Help me write a financial aid appeal for student D1234567 whose SSN is 123-45-6789.",
        "Student is on F-1 visa and needs to understand SEVIS reporting requirements.",
        "Summarize the requirements for academic probation review.",
    ]

    for text in texts:
        scan = guard.scan(text)
        result = policy_engine.apply(policy, scan, text)

        if not result.passed:
            print(f"  [BLOCKED]  '{text[:55]}...'")
            print(f"             Blocked entities: {result.blocked_entities}")
        elif result.hit_count > 0:
            sanitized = guard.sanitize(
                text, mode=policy.default_mode,
                exclude_entity_types=policy.pass_through_entity_types
            )
            print(f"  [SANITIZED] '{sanitized.sanitized_text[:55]}...'")
        else:
            print(f"  [SAFE]     '{text[:55]}'")


if __name__ == "__main__":
    print("AI Preflight Gate Examples")
    print("=" * 60)

    test_inputs = [
        "What is the deadline for dropping a course?",
        "Student John Smith, SSN 123-45-6789, needs an advising note.",
        "International student on F-1 visa asking about off-campus work authorization.",
        "The student has a 3.2 GPA and is on the dean's list.",
    ]

    print("\n=== Preflight Gate ===")
    for inp in test_inputs:
        print(f"\nInput: {inp[:60]}")
        result = safe_ai_call(inp)
        print(f"Result: {result}")

    policy_gate_example()
    print("\nDone.")
