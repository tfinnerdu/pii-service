"""
tests/unit/test_policy.py - Unit tests for the policy engine.
"""

import pytest

try:
    import presidio_analyzer  # noqa: F401
    _HAS_PRESIDIO = True
except ImportError:
    _HAS_PRESIDIO = False

from pii_guard import PiiGuard, SanitizeMode, RiskLevel, BUILT_IN_POLICIES
from pii_guard.policy import policy_engine, PiiPolicy


@pytest.fixture(scope="module")
def guard():
    return PiiGuard(score_threshold=0.4, use_spacy=False)


class TestBuiltInPolicies:
    def test_all_required_policies_present(self):
        required = {"ai_prompt", "embedding", "log_safe", "export_internal",
                    "export_external", "ferpa_strict", "analytics"}
        assert required.issubset(set(BUILT_IN_POLICIES.keys())), (
            f"Missing policies: {required - set(BUILT_IN_POLICIES.keys())}"
        )

    def test_all_policies_have_descriptions(self):
        for name, policy in BUILT_IN_POLICIES.items():
            assert policy.description, f"Policy '{name}' has no description"

    def test_all_policies_have_valid_modes(self):
        valid_modes = set(SanitizeMode)
        for name, policy in BUILT_IN_POLICIES.items():
            assert policy.default_mode in valid_modes, (
                f"Policy '{name}' has invalid mode: {policy.default_mode}"
            )

    def test_ferpa_strict_has_exclude_any_pii(self):
        assert BUILT_IN_POLICIES["ferpa_strict"].exclude_any_pii is True, (
            "ferpa_strict must exclude any chunk with any PII — this is a FERPA invariant"
        )

    def test_ai_prompt_blocks_ssn(self):
        assert "US_SSN" in BUILT_IN_POLICIES["ai_prompt"].block_entity_types, (
            "ai_prompt must block SSN — this is a load-bearing safety requirement"
        )

    def test_embedding_blocks_immigration_status(self):
        assert "IMMIGRATION_STATUS" in BUILT_IN_POLICIES["embedding"].block_entity_types, (
            "embedding must block immigration status — CRITICAL risk in vector stores"
        )

    def test_export_external_blocks_email(self):
        policy = BUILT_IN_POLICIES["export_external"]
        assert "EMAIL_ADDRESS" in policy.block_entity_types, (
            "export_external must block personal email addresses"
        )


@pytest.mark.skipif(not _HAS_PRESIDIO, reason="presidio_analyzer not installed — install requirements.txt")
class TestPolicyEngineApply:
    def test_clean_text_passes_all_policies(self, guard):
        text = "CSCI 301 meets MWF at 10am. 24 seats available."
        for name, policy in BUILT_IN_POLICIES.items():
            scan = guard.scan(text)
            result = policy_engine.apply(policy, scan, text)
            assert result.passed, f"Policy '{name}' should pass clean text"
            assert result.action_taken == "none"
            assert result.sanitized_text == text

    def test_ssn_blocked_by_ai_prompt(self, guard):
        scan = guard.scan("SSN: 123-45-6789")
        result = policy_engine.apply(BUILT_IN_POLICIES["ai_prompt"], scan, "SSN: 123-45-6789")
        assert not result.passed
        assert result.action_taken == "excluded"
        assert "US_SSN" in result.blocked_entities

    def test_ssn_blocked_by_ferpa_strict(self, guard):
        scan = guard.scan("SSN: 123-45-6789")
        result = policy_engine.apply(BUILT_IN_POLICIES["ferpa_strict"], scan, "SSN: 123-45-6789")
        assert not result.passed
        assert result.sanitized_text is None

    def test_pass_through_entities_not_flagged(self, guard):
        """ai_prompt passes through DATE_TIME — a date alone should not block the policy."""
        scan = guard.scan("Student enrolled on 08/25/2024")
        result = policy_engine.apply(
            BUILT_IN_POLICIES["ai_prompt"], scan, "Student enrolled on 08/25/2024"
        )
        # DATE_TIME is in pass_through — result should pass
        assert result.passed

    def test_list_policies_returns_all(self):
        policies = policy_engine.list_policies()
        policy_names = {p["name"] for p in policies}
        assert policy_names == set(BUILT_IN_POLICIES.keys())

    def test_list_policies_includes_required_keys(self):
        for p in policy_engine.list_policies():
            for key in ["name", "description", "default_mode", "block_entity_types"]:
                assert key in p, f"Policy listing missing key '{key}'"
