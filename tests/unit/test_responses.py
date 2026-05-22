"""
tests/unit/test_responses.py - Unit tests for the shared error envelope helper.

error_response is the single source of the Doane error envelope. Every blueprint
imports it; these tests pin the {error, code, request_id} shape.
"""

from flask import g

from app import app
from utils.responses import error_response


def test_error_response_envelope_shape():
    """error_response returns the standard {error, code, request_id} envelope."""
    with app.test_request_context("/"):
        g.request_id = "req-test-123"
        resp, status = error_response("bad thing", "BAD_THING", 400)
        assert resp.get_json() == {
            "error": "bad thing",
            "code": "BAD_THING",
            "request_id": "req-test-123",
        }
        assert status == 400


def test_error_response_default_status_is_400():
    with app.test_request_context("/"):
        _, status = error_response("msg", "CODE")
        assert status == 400


def test_error_response_passes_through_status():
    with app.test_request_context("/"):
        _, status = error_response("nope", "NOPE", 503)
        assert status == 503


def test_error_response_request_id_falls_back_to_unknown():
    """When the request-id middleware did not run, request_id is 'unknown' — never None."""
    with app.test_request_context("/"):
        resp, _ = error_response("msg", "CODE", 422)
        assert resp.get_json()["request_id"] == "unknown"
