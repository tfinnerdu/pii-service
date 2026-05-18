"""
tests/conftest.py - Shared pytest fixtures for pii-service.

All guards are regex-only (use_spacy=False) for speed.
PERSON/LOCATION detection via spaCy is tested in integration tests when
en_core_web_lg is available.
"""

import pytest
import os

# Disable auth for all tests unless explicitly enabled in the test
os.environ.setdefault("API_KEY", "")

from pii_guard import PiiGuard, SanitizeMode
from app import app as flask_app


@pytest.fixture(scope="session")
def guard():
    """Regex-only guard for fast unit tests. Shared across the session."""
    return PiiGuard(score_threshold=0.4, use_spacy=False)


@pytest.fixture(scope="session")
def strict_guard():
    """Higher threshold guard for false-positive tests."""
    return PiiGuard(score_threshold=0.7, use_spacy=False)


@pytest.fixture(scope="session")
def flask_client():
    """Flask test client with auth disabled."""
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client


@pytest.fixture(scope="session")
def auth_flask_client():
    """Flask test client with a known API key."""
    os.environ["API_KEY"] = "test-key-for-pytest"
    from pii_guard.auth import init_auth
    init_auth()  # re-initialize with the test key

    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client

    os.environ.pop("API_KEY", None)
    init_auth()  # restore disabled state
