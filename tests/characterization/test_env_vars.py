"""
tests/characterization/test_env_vars.py

Pins every environment variable name that the service reads.
If a var is renamed in code without updating K8s secrets and .env.example,
this test fails. The test does NOT check values — only that the names are
what the code expects.

When an env var is renamed:
  1. Update the code
  2. Update K8s secrets in k8s/
  3. Update .env.example
  4. Update this test (update the comment with the date and reason)
  5. All four changes go in the same commit
"""

import ast
import re
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Known-good list of env var names read by this service — pinned 2025-05
# ---------------------------------------------------------------------------

EXPECTED_ENV_VARS = {
    # Core guard configuration
    "PII_SCORE_THRESHOLD",
    "PII_USE_SPACY",
    # Flask / service
    "PORT",
    "FLASK_ENV",
    "UI_ENABLED",
    # API key authentication (single key backward-compat + named multi-key)
    "API_KEY",
    "API_KEYS",
    # Batch / file limits
    "BATCH_SIZE_LIMIT",
    "FILE_ROW_LIMIT",
    "FILE_SIZE_LIMIT_MB",
    # Dynamic config
    "PII_CONFIG_FILE",
    # Text length limit
    "MAX_TEXT_LENGTH",
    # Pseudonymization security (HMAC seed)
    "PSEUDO_SECRET",
    # Sandbox mode (deterministic fake responses for CI/integration testing)
    "PII_SANDBOX_MODE",
    # Encoded payload preprocessing
    "PII_DECODE_ENCODED",
    # Orkes Conductor integration (optional — standalone worker only)
    "CONDUCTOR_SERVER_URL",
    "CONDUCTOR_AUTH_KEY",
    "CONDUCTOR_AUTH_SECRET",
}


def _extract_getenv_calls(source: str) -> set[str]:
    """Extract literal string args from os.getenv() and os.environ.get() calls."""
    found = set()
    # Match os.getenv("VAR_NAME") and os.environ.get("VAR_NAME")
    for m in re.finditer(r'os\.(?:getenv|environ\.get)\(\s*["\']([A-Z_][A-Z0-9_]*)["\']', source):
        found.add(m.group(1))
    return found


def _source_files() -> list[Path]:
    root = Path(__file__).parent.parent.parent
    sources = list(root.glob("**/*.py"))
    return [
        f for f in sources
        if ".venv" not in str(f) and "__pycache__" not in str(f) and "test_" not in f.name
    ]


class TestEnvVarNames:
    """
    Known-good: the service reads exactly EXPECTED_ENV_VARS.
    If any var name changes in code, this test fails.
    Update EXPECTED_ENV_VARS AND K8s secrets AND .env.example in the same commit.
    """

    def test_env_example_documents_all_expected_vars(self):
        """Every expected env var must appear in .env.example."""
        env_example = (Path(__file__).parent.parent.parent / ".env.example").read_text()
        for var in EXPECTED_ENV_VARS:
            assert var in env_example, (
                f"'{var}' is not documented in .env.example. "
                "Every env var the service reads must be documented there."
            )

    def test_no_undocumented_env_vars_in_source(self):
        """
        Env vars found in source code must all be in EXPECTED_ENV_VARS.
        New vars added to code must also be added to this test, .env.example, and K8s secrets.
        """
        all_found: set[str] = set()
        for path in _source_files():
            try:
                source = path.read_text(encoding="utf-8")
                all_found |= _extract_getenv_calls(source)
            except Exception:
                pass

        undocumented = all_found - EXPECTED_ENV_VARS
        assert not undocumented, (
            f"Env vars found in source but not in EXPECTED_ENV_VARS: {undocumented}. "
            "Add them to EXPECTED_ENV_VARS, .env.example, and K8s secrets."
        )

    def test_k8s_deployment_references_threshold_secret(self):
        """K8s deployment must reference the PII_SCORE_THRESHOLD secret."""
        k8s_path = Path(__file__).parent.parent.parent / "k8s" / "deployment.yaml"
        content = k8s_path.read_text()
        assert "PII_SCORE_THRESHOLD" in content, (
            "K8s deployment.yaml must reference PII_SCORE_THRESHOLD via secretKeyRef. "
            "If this env var is removed from K8s, update this test and the deployment."
        )
