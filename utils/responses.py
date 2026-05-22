"""
utils.responses - Shared HTTP response helpers.

The error envelope is the single Doane-standard shape for every non-2xx API
response: {error, code, request_id}. Every module that returns an error imports
error_response from here — never inline the dict at the call site, so the shape
stays consistent and migrates cleanly when extracted to a shared library.
"""

from flask import g, jsonify, Response


def error_response(message: str, code: str, status: int = 400) -> tuple[Response, int]:
    """
    Build the standard error envelope.

    Args:
        message: Human-readable error message.
        code:    Machine-readable error code (e.g. "INVALID_INPUT"). Never a raw
                 HTTP status number, never None.
        status:  HTTP status code (defaults to 400).

    request_id threads from the per-request middleware via flask.g. If the
    middleware did not run (g.request_id unset), "unknown" is used — never None.
    """
    return jsonify({
        "error": message,
        "code": code,
        "request_id": g.get("request_id", "unknown"),
    }), status
