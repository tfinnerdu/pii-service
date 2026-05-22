"""
pii_service - Flask REST API for PII detection and sanitization.

Designed for Doane University's AI platform. All processing is local via
Microsoft Presidio — no text leaves the machine or the cluster.

Endpoints:
  GET  /ui                           - Browser dev console (disabled when API_KEY is set)
  GET  /api/v1/health                - Liveness (K8s liveness probe, no auth)
  GET  /api/v1/health/deep           - Readiness with dependency checks (K8s readiness probe, no auth)
  GET  /metrics                      - Prometheus-format telemetry scrape target (no auth)
  GET  /api/v1/entities              - All detectable entity types
  GET  /api/v1/policies              - Named policy catalog
  GET  /api/v1/schemas               - Schema profiles (12 built-in ERP/SIS field maps)
  GET  /api/v1/stats                 - In-process telemetry (no raw PII)
  GET  /api/v1/keys                  - List active key names (never values)
  GET  /api/v1/jobs/<id>             - Async job status stub (501 — Redis/RQ deferred)
  POST /api/v1/stats/reset           - Reset in-memory telemetry counters
  POST /api/v1/config/reload         - Hot-reload PII_CONFIG_FILE + API_KEYS without pod restart
  POST /api/v1/scan                  - Detect PII, return hits (no sanitization)
  POST /api/v1/scan/structured       - Scan JSON record field-by-field
  POST /api/v1/scan/ocr              - PII scan of OCR service page output (confidence-aware)
  POST /api/v1/sanitize              - Detect and sanitize a single text
  POST /api/v1/sanitize/batch        - Sanitize a list of texts
  POST /api/v1/sanitize/structured   - Sanitize specific fields of a JSON record
  POST /api/v1/preflight             - AI safety check with recommendation
  POST /api/v1/policy/apply          - Apply a named policy
  POST /api/v1/process               - Generic process: raw text/record in, PII-safe out
  POST /api/v1/file                  - Sanitize uploaded CSV, JSON, PDF, DOCX, XLSX, TXT
  POST /api/v1/explain               - Per-hit detection breakdown (pattern, recognizer, score)
  POST /api/v1/keys/generate         - Generate a secure named API key (shown once)
"""

import base64
import csv
import io
import json
import logging
import os
import re
import time
import urllib.parse
import uuid

from flask import Flask, request, jsonify, g, render_template
from dotenv import load_dotenv

load_dotenv()

from pii_guard import PiiGuard, SanitizeMode, DOANE_RECOGNIZER_REGISTRY
from pii_guard.auth import init_auth, require_api_key, is_auth_enabled, list_key_names, generate_key
from pii_guard import audit
from pii_guard.policy import BUILT_IN_POLICIES, policy_engine
from pii_guard.config import get_config, BUILT_IN_SCHEMA_PROFILES
from utils.responses import error_response

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
_START_TIME = time.time()
VERSION = "1.0.0"
SERVICE = "pii-service"

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","service":"' + SERVICE + '","message":"%(message)s"}',
)
logger = logging.getLogger(SERVICE)

# ---------------------------------------------------------------------------
# Guard initialization (lazy, singleton)
# ---------------------------------------------------------------------------

_guard: PiiGuard = None


def get_guard() -> PiiGuard:
    global _guard
    if _guard is None:
        threshold_str = os.getenv("PII_SCORE_THRESHOLD", "0.5")
        try:
            threshold = float(threshold_str)
        except ValueError:
            logger.error("PII_SCORE_THRESHOLD='%s' is not a valid float — using 0.5", threshold_str)
            threshold = 0.5
        if not 0.0 <= threshold <= 1.0:
            logger.warning("PII_SCORE_THRESHOLD=%.3f outside [0, 1] — clamping to 0.5", threshold)
            threshold = 0.5
        use_spacy = os.getenv("PII_USE_SPACY", "true").lower() == "true"
        _guard = PiiGuard(score_threshold=threshold, use_spacy=use_spacy)
        logger.info("PiiGuard initialized (threshold=%.2f, spacy=%s)", threshold, use_spacy)
    return _guard


def _check_text_length(text: str):
    """Return 400 error_response if text exceeds MAX_TEXT_LENGTH, else None."""
    max_len = int(os.getenv("MAX_TEXT_LENGTH", "100000"))
    if len(text) > max_len:
        return error_response(
            f"Text exceeds maximum length of {max_len:,} characters.",
            "TEXT_TOO_LONG", 400,
        )
    return None


# ---------------------------------------------------------------------------
# Feature flags
# ---------------------------------------------------------------------------

_SANDBOX_MODE = os.getenv("PII_SANDBOX_MODE", "false").lower() == "true"
_DECODE_ENCODED = os.getenv("PII_DECODE_ENCODED", "false").lower() == "true"


def _preprocess_text(text: str) -> str:
    """Optionally decode URL-encoded or base64-encoded payloads before PII scanning."""
    if not _DECODE_ENCODED:
        return text
    # Try URL decode first (idempotent for plain text)
    url_decoded = urllib.parse.unquote(text)
    if url_decoded != text:
        return url_decoded
    # Try base64 decode if the value looks like base64 (4-char aligned, only base64 chars)
    stripped = text.strip()
    if len(stripped) >= 8 and len(stripped) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", stripped):
        try:
            decoded = base64.b64decode(stripped, validate=True).decode("utf-8")
            return decoded
        except Exception:
            pass
    return text


# ---------------------------------------------------------------------------
# GET /ui — browser dev console (only when auth is disabled or UI_ENABLED=true)
# ---------------------------------------------------------------------------

@app.route("/ui")
def ui():
    ui_flag = os.getenv("UI_ENABLED", "").lower()
    if ui_flag == "false":
        return error_response("UI disabled.", "UI_DISABLED", 403)
    if ui_flag != "true" and is_auth_enabled():
        return error_response(
            "Dev console is only available when API_KEY is unset (local development). "
            "Set UI_ENABLED=true to override.",
            "UI_DISABLED", 403,
        )
    return render_template("ui.html", sandbox_mode=_SANDBOX_MODE)


@app.route("/openapi.yaml")
def openapi_yaml():
    """Serve the raw OpenAPI spec (consumed by /swagger UI)."""
    import pathlib
    spec_path = pathlib.Path(__file__).parent / "openapi.yaml"
    if not spec_path.exists():
        return error_response("openapi.yaml not found", "SPEC_NOT_FOUND", 404)
    return spec_path.read_text(encoding="utf-8"), 200, {"Content-Type": "text/yaml; charset=utf-8"}


@app.route("/swagger")
def swagger_ui():
    """Swagger UI — interactive API docs."""
    return render_template("swagger.html"), 200


# Auth initialized at module load so the startup warning appears before first request
with app.app_context():
    init_auth()

# ---------------------------------------------------------------------------
# Request middleware
# ---------------------------------------------------------------------------

@app.before_request
def attach_request_id() -> None:
    g.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    g.api_key_prefix = None
    g.caller_name = None
    g.request_start = time.time()


def _duration_ms() -> float:
    return (time.time() - g.get("request_start", time.time())) * 1000


@app.after_request
def add_mock_mode_header(response):
    """
    Mock/Live signal: tag every response with X-Mock-Mode when sandbox mode is
    active so consumers can detect fabricated data without parsing the body.
    The header is omitted entirely in live mode.
    """
    if _SANDBOX_MODE:
        response.headers["X-Mock-Mode"] = "true"
    return response


def _parse_mode(mode_str: str):
    try:
        return SanitizeMode(mode_str.lower()), None
    except ValueError:
        valid = [m.value for m in SanitizeMode]
        return None, error_response(
            f"Invalid mode '{mode_str}'. Valid values: {valid}",
            "INVALID_MODE", 400,
        )


# ---------------------------------------------------------------------------
# GET /api/v1/health — liveness (polling-safe, no auth)
# ---------------------------------------------------------------------------

@app.route("/api/v1/health")
def health():
    """
    Liveness probe. Returns 200 as long as the process is alive — no dependency
    calls, no audit emission. Safe for K8s liveness and 30s monitoring cadence.
    """
    return jsonify({
        "status": "ok",
        "service": SERVICE,
        "version": VERSION,
        "uptime_seconds": int(time.time() - _START_TIME),
    })


# ---------------------------------------------------------------------------
# GET /api/v1/health/deep — readiness with dependency probes (K8s readiness)
# ---------------------------------------------------------------------------

@app.route("/api/v1/health/deep")
def health_deep():
    """
    Readiness probe. Verifies critical dependencies before the pod receives
    traffic. Intended for K8s readiness and admin diagnostics — not 30s polling.

    Returns 200 when Presidio is ready, 200 with status "degraded" when the
    fallback spaCy model is in use, and 503 when Presidio fails to initialize.
    The "mock" key is the canonical live-vs-fabricated-data signal.
    """
    checks: dict = {}
    status = "ok"
    http_status = 200

    if _SANDBOX_MODE:
        # Sandbox mode is an explicit operator choice — Presidio is never loaded.
        checks["presidio"] = {
            "status": "skipped",
            "detail": "sandbox mode active — responses are fabricated, Presidio not loaded",
        }
    else:
        guard = get_guard()
        probe_start = time.time()
        try:
            guard._ensure_initialized()
            guard.scan("test probe text")  # confirm the analyzer pipeline is live
            latency_ms = int((time.time() - probe_start) * 1000)
            checks["presidio"] = {"status": "ok", "latency_ms": latency_ms}
            if getattr(guard, "_degraded", False):
                checks["spacy_model"] = {
                    "status": "degraded",
                    "detail": "fallback model en_core_web_sm in use — reduced PERSON/LOCATION accuracy",
                }
                status = "degraded"
            else:
                checks["spacy_model"] = {"status": "ok", "detail": "en_core_web_lg"}
        except Exception as exc:
            logger.error("Health deep check failed: %s", exc)
            checks["presidio"] = {
                "status": "down",
                "detail": "Presidio initialization failed — check spaCy model installation",
            }
            status = "failed"
            http_status = 503

    return jsonify({
        "status": status,
        "service": SERVICE,
        "version": VERSION,
        "uptime_seconds": int(time.time() - _START_TIME),
        "mock": _SANDBOX_MODE,
        "checks": checks,
    }), http_status


# ---------------------------------------------------------------------------
# GET /metrics — Prometheus text format (no auth required for scraping)
# ---------------------------------------------------------------------------

@app.route("/metrics")
def metrics():
    """
    Prometheus-compatible scrape endpoint. Returns counters and gauges in the
    Prometheus text exposition format. No external library required.
    """
    stats = audit.get_stats()
    lines = [
        "# HELP pii_requests_total Total PII requests processed",
        "# TYPE pii_requests_total counter",
        f"pii_requests_total {stats['total_requests']}",
        "",
        "# HELP pii_pii_hits_total Total PII entity hits detected across all requests",
        "# TYPE pii_pii_hits_total counter",
        f"pii_pii_hits_total {stats['total_pii_hits']}",
        "",
        "# HELP pii_excluded_total Total text chunks excluded (EXCLUDE mode or blocked by policy)",
        "# TYPE pii_excluded_total counter",
        f"pii_excluded_total {stats['total_excluded']}",
        "",
        "# HELP pii_clean_total Total requests with no PII detected",
        "# TYPE pii_clean_total counter",
        f"pii_clean_total {stats['total_clean']}",
        "",
        "# HELP pii_uptime_seconds Process uptime in seconds",
        "# TYPE pii_uptime_seconds gauge",
        f"pii_uptime_seconds {stats['uptime_seconds']}",
        "",
    ]

    entity_counts = stats.get("entity_type_counts", {})
    if entity_counts:
        lines.append("# HELP pii_entity_type_total Hits per entity type")
        lines.append("# TYPE pii_entity_type_total counter")
        for et, cnt in sorted(entity_counts.items()):
            lines.append(f'pii_entity_type_total{{entity_type="{et}"}} {cnt}')
        lines.append("")

    mode_counts = stats.get("mode_counts", {})
    if mode_counts:
        lines.append("# HELP pii_mode_total Requests per sanitize mode")
        lines.append("# TYPE pii_mode_total counter")
        for mode_val, cnt in sorted(mode_counts.items()):
            lines.append(f'pii_mode_total{{mode="{mode_val}"}} {cnt}')
        lines.append("")

    risk_counts = stats.get("risk_level_counts", {})
    if risk_counts:
        lines.append("# HELP pii_risk_level_total Requests per risk level")
        lines.append("# TYPE pii_risk_level_total counter")
        for risk, cnt in sorted(risk_counts.items()):
            lines.append(f'pii_risk_level_total{{risk_level="{risk}"}} {cnt}')
        lines.append("")

    endpoint_counts = stats.get("endpoint_counts", {})
    if endpoint_counts:
        lines.append("# HELP pii_endpoint_total Requests per endpoint")
        lines.append("# TYPE pii_endpoint_total counter")
        for ep, cnt in sorted(endpoint_counts.items()):
            safe_ep = ep.replace('"', '\\"')
            lines.append(f'pii_endpoint_total{{endpoint="{safe_ep}"}} {cnt}')
        lines.append("")

    return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; version=0.0.4; charset=utf-8"}


# ---------------------------------------------------------------------------
# Entity catalog
# ---------------------------------------------------------------------------

@app.route("/api/v1/recognizers")
@require_api_key
def list_recognizers():
    """
    All recognizer specs: entity type, patterns (name/regex/score), context words.
    Custom recognizers are fully described. Presidio built-ins list entity + context only.
    Used by the dev console Rules tab.
    """
    try:
        from pii_guard.recognizers import _RECOGNIZER_SPECS, _PRESIDIO_CONTEXT
        custom_entities = {spec["entity"] for spec in _RECOGNIZER_SPECS}
        return jsonify({
            "custom": [
                {
                    "entity": spec["entity"],
                    "name": spec["name"],
                    "patterns": [
                        {"name": n, "regex": rx, "score": sc}
                        for n, rx, sc in spec["patterns"]
                    ],
                    "context": spec.get("context", []),
                }
                for spec in _RECOGNIZER_SPECS
            ],
            "presidio_builtins": [
                {"entity": entity, "context": list(ctx)}
                for entity, ctx in _PRESIDIO_CONTEXT.items()
                if entity not in custom_entities
            ],
        })
    except Exception as exc:
        logger.error("list_recognizers failed: %s", exc, exc_info=True)
        return error_response(str(exc), "RECOGNIZERS_ERROR", 500)


@app.route("/api/v1/entities")
@require_api_key
def list_entities():
    """
    All entity types this service can detect.
    Useful for callers building exclude_entity_types allow-lists.
    """
    presidio_defaults = [
        "CREDIT_CARD", "CRYPTO", "DATE_TIME", "EMAIL_ADDRESS", "IBAN_CODE",
        "IP_ADDRESS", "LOCATION", "MEDICAL_LICENSE", "NRP", "PERSON",
        "PHONE_NUMBER", "URL", "US_BANK_NUMBER", "US_DRIVER_LICENSE",
        "US_ITIN", "US_PASSPORT", "US_SSN",
    ]
    return jsonify({
        "presidio_defaults": presidio_defaults,
        "education_custom": DOANE_RECOGNIZER_REGISTRY,
        "total": len(presidio_defaults) + len(DOANE_RECOGNIZER_REGISTRY),
    })


# ---------------------------------------------------------------------------
# Policy catalog
# ---------------------------------------------------------------------------

@app.route("/api/v1/policies")
@require_api_key
def list_policies():
    """
    Named policies available for the /api/v1/policy/apply endpoint.
    Each policy encodes the right default behavior for a specific processing context.
    """
    return jsonify({
        "policies": policy_engine.list_policies(),
        "count": len(BUILT_IN_POLICIES),
    })


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@app.route("/api/v1/stats")
@require_api_key
def get_stats():
    """
    In-process telemetry snapshot. Resets on pod restart.
    Safe to poll — no raw PII, no DB writes, no audit emission.
    """
    stats = audit.get_stats()
    stats["auth_enabled"] = is_auth_enabled()
    stats["version"] = VERSION
    return jsonify(stats)


# ---------------------------------------------------------------------------
# POST /api/v1/stats/reset
# ---------------------------------------------------------------------------

@app.route("/api/v1/stats/reset", methods=["POST"])
@require_api_key
def reset_stats():
    """
    Reset in-memory telemetry counters. Useful after deployments or load tests.
    Does not affect audit log output — only the /api/v1/stats snapshot.
    """
    audit.reset_stats()
    return jsonify({"reset": True})


# ---------------------------------------------------------------------------
# POST /api/v1/config/reload
# ---------------------------------------------------------------------------

@app.route("/api/v1/config/reload", methods=["POST"])
@require_api_key
def config_reload():
    """
    Hot-reload PII_CONFIG_FILE from disk without restarting the pod.
    Use after updating custom patterns, entity thresholds, or schema profiles.
    Note: PiiGuard must be re-created for guard-level settings to take effect
    (threshold, spacy). File-processing and policy settings reload immediately.
    """
    from pii_guard.config import reload_config
    cfg = reload_config()
    init_auth()
    return jsonify({
        "reloaded": True,
        "entity_thresholds": len(cfg.entity_thresholds),
        "custom_patterns": len(cfg.custom_patterns),
        "schema_profiles": len(cfg.schema_profiles),
    })


# ---------------------------------------------------------------------------
# POST /api/v1/scan
# ---------------------------------------------------------------------------

@app.route("/api/v1/scan", methods=["POST"])
@require_api_key
def scan():
    """
    Detect PII in text. Returns hit metadata. Does NOT modify the text.

    Body:
      { "text": "...", "exclude_entity_types": ["DATE_TIME"] }

    Response:
      {
        "pii_found": true,
        "hit_count": 2,
        "risk_level": "HIGH",
        "entity_types": ["PERSON", "US_SSN"],
        "hits": [{ "entity_type": "PERSON", "start": 0, "end": 10, "score": 0.85, "risk_level": "MEDIUM" }],
        "request_id": "..."
      }

    NOTE: hit objects intentionally omit matched_text — never expose raw PII in API responses.
    """
    body = request.get_json(silent=True) or {}
    text = body.get("text", "")
    exclude_types = body.get("exclude_entity_types", [])
    subject_id = body.get("subject_id")
    destination = body.get("destination")
    correlation_id = body.get("correlation_id")

    if not isinstance(text, str):
        return error_response("'text' must be a string", "INVALID_INPUT", 400)
    err = _check_text_length(text)
    if err:
        return err

    if _SANDBOX_MODE:
        resp = {
            "pii_found": True, "hit_count": 1, "risk_level": "MEDIUM",
            "entity_types": ["PERSON"],
            "hits": [{"entity_type": "PERSON", "start": 0, "end": 4, "score": 0.85, "risk_level": "MEDIUM"}],
            "sandbox": True, "request_id": g.request_id,
        }
        if correlation_id is not None:
            resp["correlation_id"] = correlation_id
        return jsonify(resp)

    text = _preprocess_text(text)
    guard = get_guard()
    result = guard.scan(text)

    # Apply exclusion filter post-scan for the response (scan() itself doesn't filter)
    hits = [h for h in result.hits if h.entity_type not in set(exclude_types)]

    audit.log_event(
        endpoint="/api/v1/scan",
        request_id=g.request_id,
        client_ip=request.remote_addr,
        api_key_prefix=g.api_key_prefix,
        mode="scan",
        hit_count=len(hits),
        excluded_count=0,
        entity_types=list({h.entity_type for h in hits}),
        risk_level=result.risk_level.value,
        duration_ms=_duration_ms(),
        action="scan",
        subject_id=subject_id,
        destination=destination,
        caller_name=g.caller_name,
        correlation_id=correlation_id,
    )

    resp = {
        "pii_found": bool(hits),
        "hit_count": len(hits),
        "risk_level": result.risk_level.value,
        "entity_types": list({h.entity_type for h in hits}),
        "hits": [
            {
                "entity_type": h.entity_type,
                "start": h.start,
                "end": h.end,
                "score": round(h.score, 3),
                "risk_level": h.risk_level.value,
            }
            for h in hits
        ],
        "request_id": g.request_id,
    }
    if correlation_id is not None:
        resp["correlation_id"] = correlation_id
    return jsonify(resp)


# ---------------------------------------------------------------------------
# POST /api/v1/scan/structured
# ---------------------------------------------------------------------------

@app.route("/api/v1/scan/structured", methods=["POST"])
@require_api_key
def scan_structured():
    """
    Scan specific string fields in a JSON record without modifying anything.
    Useful for auditing Conductor workflow payloads or Salesforce records.

    Body:
      {
        "record": { "name": "John Smith", "notes": "SSN 123-45-6789", "gpa": 3.5 },
        "fields": ["name", "notes"],           // optional — defaults to all string fields
        "exclude_entity_types": ["DATE_TIME"]   // optional
      }

    Response:
      {
        "name":  { "pii_found": true,  "hit_count": 1, "entity_types": ["PERSON"],  "risk_level": "MEDIUM" },
        "notes": { "pii_found": true,  "hit_count": 1, "entity_types": ["US_SSN"],  "risk_level": "CRITICAL" },
        "_summary": { "total_hits": 2, "highest_risk": "CRITICAL", "flagged_fields": ["name", "notes"] },
        "request_id": "..."
      }
    """
    body = request.get_json(silent=True) or {}
    record = body.get("record")
    fields = body.get("fields")
    exclude_types = body.get("exclude_entity_types", [])

    if not isinstance(record, dict):
        return error_response("'record' must be a JSON object", "INVALID_INPUT", 400)

    guard = get_guard()
    report = guard.scan_structured(record, fields=fields, exclude_entity_types=exclude_types or None)

    summary = report.get("_summary", {})
    audit.log_event(
        endpoint="/api/v1/scan/structured",
        request_id=g.request_id,
        client_ip=request.remote_addr,
        api_key_prefix=g.api_key_prefix,
        mode="scan",
        hit_count=summary.get("total_hits", 0),
        excluded_count=0,
        entity_types=[],
        risk_level=summary.get("highest_risk", "LOW"),
        duration_ms=_duration_ms(),
        action="scan",
    )

    return jsonify({**report, "request_id": g.request_id})


# ---------------------------------------------------------------------------
# POST /api/v1/sanitize
# ---------------------------------------------------------------------------

@app.route("/api/v1/sanitize", methods=["POST"])
@require_api_key
def sanitize():
    """
    Scan and sanitize a single text.

    Body:
      {
        "text": "John Smith SSN 123-45-6789",
        "mode": "mask" | "redact" | "pseudonymize" | "exclude",
        "exclude_entity_types": ["DATE_TIME"]
      }

    Mode guidance:
      mask         - [ENTITY_TYPE] tokens. Use before LLM calls.
      pseudonymize - Fake-but-plausible values. Use before embeddings.
      exclude      - sanitized_text=null if ANY PII found. Drop the chunk.
      redact       - *** stars. Destroys embedding semantics. Use for logs.

    Response:
      {
        "sanitized_text": "...",
        "excluded": false,
        "pii_found": true,
        "risk_level": "HIGH",
        "entity_types": ["PERSON", "US_SSN"],
        "hit_count": 2,
        "mode": "mask",
        "request_id": "..."
      }
    """
    body = request.get_json(silent=True) or {}
    text = body.get("text", "")
    mode_str = body.get("mode", "mask")
    exclude_types = body.get("exclude_entity_types", [])
    subject_id = body.get("subject_id")
    destination = body.get("destination")
    correlation_id = body.get("correlation_id")

    if not isinstance(text, str):
        return error_response("'text' must be a string", "INVALID_INPUT", 400)
    err = _check_text_length(text)
    if err:
        return err

    mode, err = _parse_mode(mode_str)
    if err:
        return err

    if _SANDBOX_MODE:
        resp = {
            "sanitized_text": "[PERSON] placeholder for sandbox mode",
            "excluded": False, "pii_found": True, "risk_level": "MEDIUM",
            "entity_types": ["PERSON"], "hit_count": 1, "mode": mode_str,
            "sandbox": True, "request_id": g.request_id,
        }
        if correlation_id is not None:
            resp["correlation_id"] = correlation_id
        return jsonify(resp)

    text = _preprocess_text(text)
    guard = get_guard()
    result = guard.sanitize(text, mode=mode, exclude_entity_types=exclude_types or None)

    audit.log_event(
        endpoint="/api/v1/sanitize",
        request_id=g.request_id,
        client_ip=request.remote_addr,
        api_key_prefix=g.api_key_prefix,
        mode=mode.value,
        hit_count=len(result.hits),
        excluded_count=1 if result.excluded else 0,
        entity_types=result.entity_types,
        risk_level=result.risk_level.value,
        duration_ms=_duration_ms(),
        action="exclude" if result.excluded else mode.value,
        subject_id=subject_id,
        destination=destination,
        caller_name=g.caller_name,
        correlation_id=correlation_id,
    )

    resp = {
        "sanitized_text": result.sanitized_text,
        "excluded": result.excluded,
        **result.summary(),
        "request_id": g.request_id,
    }
    if correlation_id is not None:
        resp["correlation_id"] = correlation_id
    return jsonify(resp)


# ---------------------------------------------------------------------------
# POST /api/v1/sanitize/batch
# ---------------------------------------------------------------------------

@app.route("/api/v1/sanitize/batch", methods=["POST"])
@require_api_key
def sanitize_batch():
    """
    Sanitize a list of texts. Useful for preprocessing RAG embedding chunks.

    Body:
      {
        "texts": ["chunk 1...", "chunk 2..."],
        "mode": "pseudonymize",
        "exclude_entity_types": [],
        "include_excluded": true
      }

    Response:
      {
        "results": [
          { "index": 0, "sanitized_text": "...", "excluded": false, "pii_found": false, "risk_level": "LOW" },
          { "index": 1, "sanitized_text": null,  "excluded": true,  "pii_found": true,  "risk_level": "CRITICAL" }
        ],
        "total": 2,
        "excluded_count": 1,
        "clean_count": 1,
        "request_id": "..."
      }
    """
    body = request.get_json(silent=True) or {}
    texts = body.get("texts", [])
    mode_str = body.get("mode", "mask")
    exclude_types = body.get("exclude_entity_types", [])
    include_excluded = body.get("include_excluded", True)

    if not isinstance(texts, list):
        return error_response("'texts' must be a list", "INVALID_INPUT", 400)

    max_batch = int(os.getenv("BATCH_SIZE_LIMIT", "500"))
    if len(texts) > max_batch:
        return error_response(f"Batch size limit is {max_batch} texts", "BATCH_TOO_LARGE", 400)

    mode, err = _parse_mode(mode_str)
    if err:
        return err

    guard = get_guard()
    raw_results = guard.sanitize_batch(texts, mode=mode, exclude_entity_types=exclude_types or None)

    results = []
    excluded_count = 0
    clean_count = 0
    all_entity_types: set[str] = set()

    for i, r in enumerate(raw_results):
        if r.excluded:
            excluded_count += 1
            if not include_excluded:
                continue
        elif r.is_clean:
            clean_count += 1
        all_entity_types.update(r.entity_types)
        results.append({
            "index": i,
            "sanitized_text": r.sanitized_text,
            "excluded": r.excluded,
            "pii_found": not r.is_clean,
            "hit_count": len(r.hits),
            "risk_level": r.risk_level.value,
            "entity_types": r.entity_types,
        })

    audit.log_event(
        endpoint="/api/v1/sanitize/batch",
        request_id=g.request_id,
        client_ip=request.remote_addr,
        api_key_prefix=g.api_key_prefix,
        mode=mode.value,
        hit_count=sum(r.hit_count for r in results),
        excluded_count=excluded_count,
        entity_types=list(all_entity_types),
        risk_level="UNKNOWN",
        batch_size=len(texts),
        duration_ms=_duration_ms(),
        action=mode.value,
    )

    return jsonify({
        "results": results,
        "total": len(texts),
        "excluded_count": excluded_count,
        "clean_count": clean_count,
        "request_id": g.request_id,
    })


# ---------------------------------------------------------------------------
# POST /api/v1/sanitize/structured
# ---------------------------------------------------------------------------

@app.route("/api/v1/sanitize/structured", methods=["POST"])
@require_api_key
def sanitize_structured():
    """
    Sanitize specific string fields in a JSON record.
    Non-string fields and unspecified fields pass through unchanged.

    Body:
      {
        "record": { "name": "John Smith", "notes": "SSN 123-45-6789", "gpa": 3.5 },
        "fields": ["name", "notes"],
        "mode": "mask",
        "exclude_entity_types": []
      }

    Response:
      {
        "sanitized_record": { "name": "[PERSON]", "notes": "[US_SSN]", "gpa": 3.5 },
        "excluded_fields": [],
        "hit_count": 2,
        "request_id": "..."
      }
    """
    body = request.get_json(silent=True) or {}
    record = body.get("record")
    fields = body.get("fields")
    mode_str = body.get("mode", "mask")
    exclude_types = body.get("exclude_entity_types", [])

    if not isinstance(record, dict):
        return error_response("'record' must be a JSON object", "INVALID_INPUT", 400)

    mode, err = _parse_mode(mode_str)
    if err:
        return err

    target_fields = fields if isinstance(fields, list) else [
        k for k, v in record.items() if isinstance(v, str)
    ]

    guard = get_guard()
    sanitized_record, excluded_fields = guard.sanitize_dict(
        record,
        fields=target_fields,
        mode=mode,
        exclude_entity_types=exclude_types or None,
    )

    audit.log_event(
        endpoint="/api/v1/sanitize/structured",
        request_id=g.request_id,
        client_ip=request.remote_addr,
        api_key_prefix=g.api_key_prefix,
        mode=mode.value,
        hit_count=0,
        excluded_count=len(excluded_fields),
        entity_types=[],
        risk_level="UNKNOWN",
        duration_ms=_duration_ms(),
        action="exclude" if excluded_fields else mode.value,
    )

    return jsonify({
        "sanitized_record": sanitized_record,
        "excluded_fields": excluded_fields,
        "request_id": g.request_id,
    })


# ---------------------------------------------------------------------------
# POST /api/v1/preflight
# ---------------------------------------------------------------------------

@app.route("/api/v1/preflight", methods=["POST"])
@require_api_key
def preflight():
    """
    AI safety preflight check. Scan text and get a risk assessment with
    an actionable recommendation before sending to an external AI service.

    Body:
      { "text": "..." }

    Response:
      {
        "safe_to_send": false,
        "risk_level": "CRITICAL",
        "hit_count": 2,
        "blocking_entities": ["US_SSN"],
        "warning_entities": ["PERSON"],
        "recommendation": "Do not send. Critical PII detected...",
        "sanitized_suggestion": "...",    // masked version; null if safe
        "request_id": "..."
      }
    """
    body = request.get_json(silent=True) or {}
    text = body.get("text", "")
    subject_id = body.get("subject_id")
    destination = body.get("destination")

    if not isinstance(text, str):
        return error_response("'text' must be a string", "INVALID_INPUT", 400)
    err = _check_text_length(text)
    if err:
        return err

    if _SANDBOX_MODE:
        return jsonify({
            "safe_to_send": False, "risk_level": "MEDIUM", "hit_count": 1,
            "blocking_entities": [], "warning_entities": ["PERSON"],
            "recommendation": "Sandbox mode — no real scanning performed.",
            "sanitized_suggestion": "[PERSON] placeholder for sandbox mode",
            "sandbox": True, "request_id": g.request_id,
        })

    text = _preprocess_text(text)
    guard = get_guard()
    result = guard.preflight(text)

    audit.log_event(
        endpoint="/api/v1/preflight",
        request_id=g.request_id,
        client_ip=request.remote_addr,
        api_key_prefix=g.api_key_prefix,
        mode=None,
        hit_count=result.hit_count,
        excluded_count=0,
        entity_types=result.blocking_entities + result.warning_entities,
        risk_level=result.risk_level.value,
        duration_ms=_duration_ms(),
        action="preflight",
        subject_id=subject_id,
        destination=destination,
        caller_name=g.caller_name,
    )

    return jsonify({
        "safe_to_send": result.safe_to_send,
        "risk_level": result.risk_level.value,
        "hit_count": result.hit_count,
        "blocking_entities": result.blocking_entities,
        "warning_entities": result.warning_entities,
        "recommendation": result.recommendation,
        "sanitized_suggestion": result.sanitized_suggestion,
        "request_id": g.request_id,
    })


# ---------------------------------------------------------------------------
# POST /api/v1/policy/apply
# ---------------------------------------------------------------------------

@app.route("/api/v1/policy/apply", methods=["POST"])
@require_api_key
def apply_policy():
    """
    Apply a named policy to a text (or batch of texts).

    Body:
      {
        "policy": "ai_prompt",
        "text": "...",                           // for single text
        "texts": ["...", "..."],                 // for batch (optional instead of text)
        "exclude_entity_types": []               // additional pass-throughs
      }

    Response (single):
      {
        "policy": "ai_prompt",
        "passed": false,
        "action_taken": "masked",
        "sanitized_text": "...",
        "blocked_entities": ["US_SSN"],
        "hit_count": 1,
        "risk_level": "CRITICAL",
        "request_id": "..."
      }
    """
    body = request.get_json(silent=True) or {}
    policy_name = body.get("policy", "")
    text = body.get("text")
    texts = body.get("texts")
    extra_pass_throughs = body.get("exclude_entity_types", [])

    if policy_name not in BUILT_IN_POLICIES:
        valid = list(BUILT_IN_POLICIES.keys())
        return error_response(
            f"Unknown policy '{policy_name}'. Valid: {valid}",
            "INVALID_POLICY", 400,
        )

    policy = BUILT_IN_POLICIES[policy_name]

    # Merge caller's extra pass-throughs into the policy's list
    effective_pass_throughs = list(set(policy.pass_through_entity_types + extra_pass_throughs))

    guard = get_guard()
    is_batch = texts is not None

    def _apply_one(t: str) -> dict:
        scan_result = guard.scan(t)
        policy_result = policy_engine.apply(policy, scan_result, t)

        if not policy_result.passed:
            # Blocked — return without sanitized text
            return {
                "passed": False,
                "action_taken": "excluded",
                "sanitized_text": None,
                "blocked_entities": policy_result.blocked_entities,
                "hit_count": policy_result.hit_count,
                "risk_level": policy_result.risk_level,
            }

        if policy_result.hit_count == 0:
            return {
                "passed": True,
                "action_taken": "none",
                "sanitized_text": t,
                "blocked_entities": [],
                "hit_count": 0,
                "risk_level": policy_result.risk_level,
            }

        # Apply the policy's mode to the remaining (non-blocked, non-pass-through) hits
        sanitized = guard.sanitize(t, mode=policy.default_mode, exclude_entity_types=effective_pass_throughs)
        return {
            "passed": True,
            "action_taken": policy_result.action_taken,
            "sanitized_text": sanitized.sanitized_text,
            "blocked_entities": [],
            "hit_count": policy_result.hit_count,
            "risk_level": policy_result.risk_level,
        }

    if is_batch:
        if not isinstance(texts, list):
            return error_response("'texts' must be a list", "INVALID_INPUT", 400)
        max_batch = int(os.getenv("BATCH_SIZE_LIMIT", "500"))
        if len(texts) > max_batch:
            return error_response(f"Batch size limit is {max_batch}", "BATCH_TOO_LARGE", 400)

        results = [{"index": i, **_apply_one(t)} for i, t in enumerate(texts)]
        excluded = sum(1 for r in results if r["action_taken"] == "excluded")

        audit.log_event(
            endpoint="/api/v1/policy/apply",
            request_id=g.request_id,
            client_ip=request.remote_addr,
            api_key_prefix=g.api_key_prefix,
            mode=policy.default_mode.value,
            hit_count=sum(r["hit_count"] for r in results),
            excluded_count=excluded,
            entity_types=[],
            risk_level="UNKNOWN",
            batch_size=len(texts),
            duration_ms=_duration_ms(),
            action=policy.default_mode.value,
            policy_name=policy_name,
        )

        return jsonify({
            "policy": policy_name,
            "results": results,
            "total": len(texts),
            "excluded_count": excluded,
            "request_id": g.request_id,
        })

    if text is None:
        return error_response("Provide 'text' (single) or 'texts' (batch)", "INVALID_INPUT", 400)
    if not isinstance(text, str):
        return error_response("'text' must be a string", "INVALID_INPUT", 400)

    result = _apply_one(text)

    audit.log_event(
        endpoint="/api/v1/policy/apply",
        request_id=g.request_id,
        client_ip=request.remote_addr,
        api_key_prefix=g.api_key_prefix,
        mode=policy.default_mode.value,
        hit_count=result["hit_count"],
        excluded_count=1 if result["action_taken"] == "excluded" else 0,
        entity_types=result["blocked_entities"],
        risk_level=result["risk_level"],
        duration_ms=_duration_ms(),
        action=result["action_taken"],
        policy_name=policy_name,
    )

    return jsonify({
        "policy": policy_name,
        **result,
        "request_id": g.request_id,
    })


# ---------------------------------------------------------------------------
# GET /api/v1/schemas
# ---------------------------------------------------------------------------

@app.route("/api/v1/schemas")
@require_api_key
def list_schemas():
    """
    Schema profiles for ERP/SIS data shapes.
    Specifying a profile in /api/v1/process or /api/v1/sanitize/structured gives
    field-name-aware detection so field names like 'SPBPERS_SSN' are recognized as US_SSN.

    Available built-ins (12): banner_student, colleague_person, salesforce_contact,
                         ethos_person, n8n_generic, conductor_ethos, workday_hr,
                         servicenow_itsm, slate_crm, starfish_early_alert,
                         canvas_lms, microsoft_graph.
    Custom profiles are loaded from PII_CONFIG_FILE.
    """
    cfg = get_config()
    all_profiles = cfg.all_schema_profiles()
    return jsonify({
        "schemas": [
            {
                "name": name,
                "description": profile.get("description", ""),
                "field_count": len(profile.get("field_hints", {})),
                "default_mode": profile.get("default_mode", "mask"),
                "fields": profile.get("field_hints", {}),
            }
            for name, profile in all_profiles.items()
        ],
        "count": len(all_profiles),
    })


# ---------------------------------------------------------------------------
# POST /api/v1/process — generic entry point (raw in, PII-safe out)
# ---------------------------------------------------------------------------

@app.route("/api/v1/process", methods=["POST"])
@require_api_key
def process():
    """
    Generic PII processing endpoint. Single entry point for all platforms.
    Accepts text, a structured record, or a batch — plus optional schema and policy.

    Body (all fields optional except providing at least one of text/record/texts):
      {
        "text":                 "raw text string",           // single text mode
        "record":               { "field": "value" },        // structured record mode
        "texts":                ["text1", "text2"],           // batch mode
        "fields":               ["field1", "field2"],         // which fields to process (record/batch)
        "mode":                 "mask",                       // sanitize mode (ignored if policy set)
        "policy":               "ai_prompt",                  // named policy (overrides mode)
        "schema":               "banner_student",             // schema profile for field hints
        "exclude_entity_types": ["DATE_TIME"],                // entity types to skip
        "include_excluded":     true                          // include excluded items in batch output
      }

    Response always includes:
      {
        "input_type": "text" | "record" | "batch",
        "policy_applied": "ai_prompt" | null,
        "schema_applied": "banner_student" | null,
        ... (mode-specific result fields)
      }
    """
    body = request.get_json(silent=True) or {}
    text = body.get("text")
    record = body.get("record")
    texts = body.get("texts")
    fields = body.get("fields")
    mode_str = body.get("mode", "mask")
    policy_name = body.get("policy")
    schema_name = body.get("schema")
    exclude_types = body.get("exclude_entity_types", [])
    include_excluded = body.get("include_excluded", True)
    recursive = body.get("recursive", False)
    subject_id = body.get("subject_id")
    destination = body.get("destination")

    # Validate: need at least one input
    if text is None and record is None and texts is None:
        return error_response(
            "Provide at least one of: 'text' (string), 'record' (object), or 'texts' (array).",
            "INVALID_INPUT", 400,
        )

    # Resolve policy
    policy = None
    if policy_name:
        if policy_name not in BUILT_IN_POLICIES:
            return error_response(
                f"Unknown policy '{policy_name}'. Valid: {list(BUILT_IN_POLICIES.keys())}",
                "INVALID_POLICY", 400,
            )
        policy = BUILT_IN_POLICIES[policy_name]

    # Resolve mode (used when no policy, or as fallback)
    if not policy:
        mode, err = _parse_mode(mode_str)
        if err:
            return err
    else:
        mode = policy.default_mode

    # Apply schema profile to set field hints / adjust exclude types
    schema = None
    schema_pass_throughs = list(exclude_types)
    field_context_hints = None
    if schema_name:
        cfg = get_config()
        schema = cfg.get_schema_profile(schema_name)
        if not schema:
            return error_response(
                f"Unknown schema '{schema_name}'. Use GET /api/v1/schemas for available profiles.",
                "INVALID_SCHEMA", 400,
            )
        # Schema's default mode takes precedence if no explicit mode/policy set
        if not policy and mode_str == "mask" and "default_mode" in schema:
            try:
                mode = SanitizeMode(schema["default_mode"])
            except ValueError:
                pass
        # Wire field hints into context-boosted scanning
        field_context_hints = schema.get("field_hints") or None

    guard = get_guard()

    # Determine effective exclude list (policy pass-throughs + caller's exclusions)
    effective_excludes = list(set(
        (policy.pass_through_entity_types if policy else []) + schema_pass_throughs
    ))

    def _apply_policy_or_mode(t: str) -> dict:
        if policy:
            scan_res = guard.scan(t)
            pr = policy_engine.apply(policy, scan_res, t)
            if not pr.passed:
                return {
                    "sanitized_text": None,
                    "excluded": True,
                    "pii_found": True,
                    "risk_level": pr.risk_level,
                    "entity_types": pr.blocked_entities,
                    "hit_count": pr.hit_count,
                    "action_taken": "excluded_by_policy",
                }
            if pr.hit_count == 0:
                return {
                    "sanitized_text": t,
                    "excluded": False,
                    "pii_found": False,
                    "risk_level": "LOW",
                    "entity_types": [],
                    "hit_count": 0,
                    "action_taken": "none",
                }
            result = guard.sanitize(t, mode=mode, exclude_entity_types=effective_excludes or None)
            return {
                "sanitized_text": result.sanitized_text,
                "excluded": result.excluded,
                **result.summary(),
                "action_taken": mode.value,
            }
        else:
            result = guard.sanitize(t, mode=mode, exclude_entity_types=effective_excludes or None)
            return {
                "sanitized_text": result.sanitized_text,
                "excluded": result.excluded,
                **result.summary(),
                "action_taken": mode.value,
            }

    meta = {
        "policy_applied": policy_name,
        "schema_applied": schema_name,
        "mode": mode.value,
    }

    # TEXT mode
    if text is not None:
        if not isinstance(text, str):
            return error_response("'text' must be a string", "INVALID_INPUT", 400)
        err = _check_text_length(text)
        if err:
            return err
        outcome = _apply_policy_or_mode(text)

        audit.log_event(
            endpoint="/api/v1/process",
            request_id=g.request_id,
            client_ip=request.remote_addr,
            api_key_prefix=g.api_key_prefix,
            mode=mode.value,
            hit_count=outcome.get("hit_count", 0),
            excluded_count=1 if outcome.get("excluded") else 0,
            entity_types=outcome.get("entity_types", []),
            risk_level=outcome.get("risk_level", "LOW"),
            duration_ms=_duration_ms(),
            action=outcome.get("action_taken", mode.value),
            policy_name=policy_name,
        )

        return jsonify({"input_type": "text", **meta, **outcome, "request_id": g.request_id})

    # RECORD mode
    if record is not None:
        if not isinstance(record, dict):
            return error_response("'record' must be a JSON object", "INVALID_INPUT", 400)

        if recursive:
            # Deep traversal — sanitize all string values at any nesting depth
            sanitized_record = guard.sanitize_nested(
                record, mode=mode, exclude_entity_types=effective_excludes or None
            )
            excluded_fields = []
        elif policy:
            target_fields = fields if isinstance(fields, list) else [
                k for k, v in record.items() if isinstance(v, str)
            ]
            sanitized_record = {}
            excluded_fields = []
            for field_name in target_fields:
                val = record.get(field_name)
                if not isinstance(val, str):
                    sanitized_record[field_name] = val
                    continue
                outcome = _apply_policy_or_mode(val)
                if outcome.get("excluded"):
                    excluded_fields.append(field_name)
                    sanitized_record[field_name] = None
                else:
                    sanitized_record[field_name] = outcome["sanitized_text"]
            # Pass non-targeted fields through unchanged
            for k, v in record.items():
                if k not in sanitized_record:
                    sanitized_record[k] = v
        else:
            target_fields = fields if isinstance(fields, list) else [
                k for k, v in record.items() if isinstance(v, str)
            ]
            sanitized_record, excluded_fields = guard.sanitize_dict(
                record,
                fields=target_fields,
                mode=mode,
                exclude_entity_types=effective_excludes or None,
                field_context_hints=field_context_hints,
            )

        audit.log_event(
            endpoint="/api/v1/process",
            request_id=g.request_id,
            client_ip=request.remote_addr,
            api_key_prefix=g.api_key_prefix,
            mode=mode.value,
            hit_count=0,
            excluded_count=len(excluded_fields),
            entity_types=[],
            risk_level="UNKNOWN",
            duration_ms=_duration_ms(),
            action=mode.value,
            policy_name=policy_name,
            subject_id=subject_id,
            destination=destination,
        )

        return jsonify({
            "input_type": "record",
            **meta,
            "sanitized_record": sanitized_record,
            "excluded_fields": excluded_fields,
            "request_id": g.request_id,
        })

    # BATCH mode
    if texts is not None:
        if not isinstance(texts, list):
            return error_response("'texts' must be an array", "INVALID_INPUT", 400)
        max_batch = int(os.getenv("BATCH_SIZE_LIMIT", "500"))
        if len(texts) > max_batch:
            return error_response(f"Batch size limit is {max_batch}", "BATCH_TOO_LARGE", 400)

        results = []
        excluded_count = 0
        all_entity_types: set[str] = set()

        for i, t in enumerate(texts):
            if not isinstance(t, str):
                results.append({"index": i, "error": "non-string item skipped"})
                continue
            outcome = _apply_policy_or_mode(t)
            if outcome.get("excluded"):
                excluded_count += 1
                if not include_excluded:
                    continue
            all_entity_types.update(outcome.get("entity_types", []))
            results.append({"index": i, **outcome})

        audit.log_event(
            endpoint="/api/v1/process",
            request_id=g.request_id,
            client_ip=request.remote_addr,
            api_key_prefix=g.api_key_prefix,
            mode=mode.value,
            hit_count=sum(r.get("hit_count", 0) for r in results),
            excluded_count=excluded_count,
            entity_types=list(all_entity_types),
            risk_level="UNKNOWN",
            batch_size=len(texts),
            duration_ms=_duration_ms(),
            action=mode.value,
            policy_name=policy_name,
        )

        return jsonify({
            "input_type": "batch",
            **meta,
            "results": results,
            "total": len(texts),
            "excluded_count": excluded_count,
            "request_id": g.request_id,
        })


# ---------------------------------------------------------------------------
# POST /api/v1/file
# ---------------------------------------------------------------------------

@app.route("/api/v1/file", methods=["POST"])
@require_api_key
def process_file():
    """
    Sanitize an uploaded CSV or JSON file.
    CSV: processes all string columns (or specified columns).
    JSON: processes as an array of objects — same as sanitize/structured per record.

    Form fields:
      file                 - multipart file upload (.csv or .json)
      mode                 - sanitize mode (default: mask)
      columns              - JSON array of column/field names to process (optional)
      exclude_entity_types - JSON array of entity types to skip (optional)
      include_excluded     - "true"/"false" — whether to include excluded rows (default: true)

    Response:
      {
        "file_type": "csv",
        "total_rows": 100,
        "rows_with_pii": 23,
        "excluded_rows": 5,
        "results": [ ...per-row result objects... ],
        "request_id": "..."
      }
    """
    if "file" not in request.files:
        return error_response("No file uploaded. Include 'file' in multipart form.", "NO_FILE", 400)

    uploaded = request.files["file"]
    filename = uploaded.filename or ""
    mode_str = request.form.get("mode", "mask")
    columns_raw = request.form.get("columns", "")
    exclude_raw = request.form.get("exclude_entity_types", "")
    include_excluded = request.form.get("include_excluded", "true").lower() == "true"

    try:
        columns: list[str] = json.loads(columns_raw) if columns_raw else []
    except json.JSONDecodeError:
        columns = []
    try:
        exclude_types: list[str] = json.loads(exclude_raw) if exclude_raw else []
    except json.JSONDecodeError:
        exclude_types = []

    mode, err = _parse_mode(mode_str)
    if err:
        return err

    max_rows = int(os.getenv("FILE_ROW_LIMIT", "10000"))
    max_bytes = int(os.getenv("FILE_SIZE_LIMIT_MB", "10")) * 1024 * 1024

    content = uploaded.read()
    if len(content) > max_bytes:
        return error_response(
            f"File too large. Max {os.getenv('FILE_SIZE_LIMIT_MB', '10')}MB.",
            "FILE_TOO_LARGE", 400,
        )

    guard = get_guard()

    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    handlers = {
        ".csv":   _process_csv,
        ".tsv":   _process_tsv,
        ".json":  _process_json,
        ".jsonl": _process_jsonl,
        ".txt":   _process_txt,
        ".pdf":   _process_pdf,
        ".docx":  _process_docx,
        ".xlsx":  _process_xlsx,
    }

    handler = handlers.get(ext)
    if not handler:
        return error_response(
            f"Unsupported file type '{ext}'. Supported: {list(handlers.keys())}",
            "INVALID_FILE_TYPE", 400,
        )

    return handler(guard, content, columns, mode, exclude_types, include_excluded, max_rows)


# ---------------------------------------------------------------------------
# POST /api/v1/explain — per-hit detection breakdown
# ---------------------------------------------------------------------------

@app.route("/api/v1/explain", methods=["POST"])
@require_api_key
def explain():
    """
    Explain why each PII hit was flagged: pattern name, recognizer, context words, score.
    Requires Presidio. Returns 503 if unavailable.

    Body:
      { "text": "Student D1234567 has SSN 123-45-6789" }

    Response:
      {
        "text_length": 38,
        "hit_count": 2,
        "hits": [
          {
            "entity_type": "STUDENT_ID",
            "start": 8, "end": 16, "score": 0.9, "risk_level": "MEDIUM",
            "recognizer": "StudentIdRecognizer",
            "pattern_name": "doane_d_prefix",
            "pattern": "\\\\bD\\\\d{7}\\\\b",
            "context_words": ["student", "id", ...]
          }
        ],
        "request_id": "..."
      }
    """
    body = request.get_json(silent=True) or {}
    text = body.get("text", "")

    if not isinstance(text, str):
        return error_response("'text' must be a string", "INVALID_INPUT", 400)
    err = _check_text_length(text)
    if err:
        return err

    guard = get_guard()
    try:
        guard._ensure_initialized()
    except RuntimeError as exc:
        return error_response(str(exc), "DEPENDENCY_MISSING", 503)

    text = _preprocess_text(text)

    results = guard._analyzer.analyze(
        text=text,
        entities=guard.entities,
        language="en",
        score_threshold=guard.score_threshold,
    )

    from pii_guard.recognizers import _RECOGNIZER_SPECS
    from pii_guard.models import entity_risk

    explained = []
    for r in results:
        recognizer_name = None
        pattern_name = None
        pattern_regex = None
        context_words = []

        for spec in _RECOGNIZER_SPECS:
            if spec["entity"] == r.entity_type:
                recognizer_name = spec["name"]
                context_words = spec.get("context", [])
                matched_text = text[r.start:r.end]
                for pname, patt, _ in spec["patterns"]:
                    if re.search(patt, matched_text, re.IGNORECASE):
                        pattern_name = pname
                        pattern_regex = patt
                        break
                break

        if recognizer_name is None:
            # Presidio built-in recognizer — extract name from metadata if available
            meta = getattr(r, "recognition_metadata", {}) or {}
            recognizer_name = meta.get("recognizer_name", f"Presidio:{r.entity_type}")

        explained.append({
            "entity_type": r.entity_type,
            "start": r.start,
            "end": r.end,
            "score": round(r.score, 3),
            "risk_level": entity_risk(r.entity_type).value,
            "recognizer": recognizer_name,
            "pattern_name": pattern_name,
            "pattern": pattern_regex,
            "context_words": context_words,
        })

    explained.sort(key=lambda h: h["start"])

    audit.log_event(
        endpoint="/api/v1/explain",
        request_id=g.request_id,
        client_ip=request.remote_addr,
        api_key_prefix=g.api_key_prefix,
        mode="scan",
        hit_count=len(explained),
        excluded_count=0,
        entity_types=list({h["entity_type"] for h in explained}),
        risk_level="UNKNOWN",
        duration_ms=_duration_ms(),
        action="explain",
    )

    return jsonify({
        "text_length": len(text),
        "hit_count": len(explained),
        "hits": explained,
        "request_id": g.request_id,
    })


# ---------------------------------------------------------------------------
# GET /api/v1/keys — list active key names (never exposes key values)
# ---------------------------------------------------------------------------

@app.route("/api/v1/keys")
@require_api_key
def list_keys():
    names = list_key_names()
    return jsonify({
        "keys": names,
        "count": len(names),
        "auth_enabled": is_auth_enabled(),
    })


# ---------------------------------------------------------------------------
# POST /api/v1/keys/generate — generate a cryptographically secure API key
# ---------------------------------------------------------------------------

@app.route("/api/v1/keys/generate", methods=["POST"])
@require_api_key
def generate_api_key():
    """
    Generate a secure API key for a named caller. The key is shown once — it is
    never stored by pii-service. Add it to API_KEYS env var, then POST /api/v1/config/reload.

    Body: { "name": "n8n-prod", "prefix": "sk_n8n" }
    """
    body = request.get_json(silent=True) or {}
    name = body.get("name", "").strip()
    prefix = body.get("prefix", "sk").strip()

    if not name:
        return error_response("'name' is required — a label for audit logs (e.g. 'n8n-prod').", "INVALID_INPUT", 400)
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return error_response(
            "'name' must contain only letters, digits, hyphens, and underscores.",
            "INVALID_INPUT", 400,
        )

    key = generate_key(prefix=prefix)
    add_to = f"{name}:{key}"
    return jsonify({
        "name": name,
        "key": key,
        "add_to_api_keys": add_to,
        "instructions": (
            f"Add '{add_to}' to your API_KEYS env var (comma-separated), "
            "then POST /api/v1/config/reload to activate without restart. "
            "This key is shown once — store it securely."
        ),
    })


# ---------------------------------------------------------------------------
# POST /api/v1/scan/ocr — PII scan of OCR service output (per-page, with confidence)
# ---------------------------------------------------------------------------

@app.route("/api/v1/scan/ocr", methods=["POST"])
@require_api_key
def scan_ocr():
    """
    Accept OCR service output (pages with extracted text + confidence scores) and
    scan each page for PII. Designed to be called by the OCR service after text
    extraction from scanned PDFs, images, or faxes.

    Body:
      {
        "pages": [{ "page_number": 1, "text": "...", "confidence": 94.1 }],
        "mode": "mask",
        "low_confidence_threshold": 70.0,
        "exclude_entity_types": [],
        "correlation_id": "banner-pidm-123456"
      }

    Pages with confidence below low_confidence_threshold get low_confidence_warning=true,
    flagging that OCR errors may have caused PII to be missed or misread.
    """
    body = request.get_json(silent=True) or {}
    pages = body.get("pages")
    mode_str = body.get("mode", "mask")
    low_conf_threshold = float(body.get("low_confidence_threshold", 70.0))
    exclude_types = body.get("exclude_entity_types", [])
    correlation_id = body.get("correlation_id")

    if not isinstance(pages, list) or not pages:
        return error_response(
            "'pages' must be a non-empty array of {page_number, text, confidence} objects.",
            "INVALID_INPUT", 400,
        )

    mode, err = _parse_mode(mode_str)
    if err:
        return err

    if _SANDBOX_MODE:
        fake_pages = [
            {
                "page_number": p.get("page_number", i + 1),
                "ocr_confidence": float(p.get("confidence", 100.0)),
                "low_confidence_warning": float(p.get("confidence", 100.0)) < low_conf_threshold,
                "sanitized_text": "[PERSON] placeholder for sandbox mode",
                "pii_found": True,
                "hit_count": 1,
                "entity_types": ["PERSON"],
                "risk_level": "MEDIUM",
            }
            for i, p in enumerate(pages) if isinstance(p, dict)
        ]
        resp = {
            "page_count": len(fake_pages),
            "pages_with_pii": len(fake_pages),
            "highest_risk": "MEDIUM",
            "pages": fake_pages,
            "sandbox": True,
            "request_id": g.request_id,
        }
        if correlation_id is not None:
            resp["correlation_id"] = correlation_id
        return jsonify(resp)

    guard = get_guard()
    page_results = []
    pages_with_pii = 0
    _risk_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    highest_risk = "LOW"

    for page in pages:
        if not isinstance(page, dict):
            continue
        page_num = page.get("page_number", 0)
        text = page.get("text", "")
        confidence = float(page.get("confidence", 100.0))
        low_confidence_warning = confidence < low_conf_threshold

        if not isinstance(text, str) or not text.strip():
            page_results.append({
                "page_number": page_num,
                "ocr_confidence": confidence,
                "low_confidence_warning": low_confidence_warning,
                "sanitized_text": "",
                "pii_found": False,
                "hit_count": 0,
                "entity_types": [],
                "risk_level": "LOW",
            })
            continue

        result = guard.sanitize(text, mode=mode, exclude_entity_types=exclude_types or None)
        if not result.is_clean:
            pages_with_pii += 1
        risk = result.risk_level.value
        if _risk_order.index(risk) > _risk_order.index(highest_risk):
            highest_risk = risk

        page_results.append({
            "page_number": page_num,
            "ocr_confidence": confidence,
            "low_confidence_warning": low_confidence_warning,
            "sanitized_text": result.sanitized_text,
            "pii_found": not result.is_clean,
            "hit_count": len(result.hits),
            "entity_types": result.entity_types,
            "risk_level": risk,
        })

    all_entity_types = list({et for p in page_results for et in p.get("entity_types", [])})
    audit.log_event(
        endpoint="/api/v1/scan/ocr",
        request_id=g.request_id,
        client_ip=request.remote_addr,
        api_key_prefix=g.api_key_prefix,
        mode=mode.value,
        hit_count=sum(p["hit_count"] for p in page_results),
        excluded_count=0,
        entity_types=all_entity_types,
        risk_level=highest_risk,
        batch_size=len(page_results),
        duration_ms=_duration_ms(),
        action="scan_ocr",
        caller_name=g.caller_name,
        correlation_id=correlation_id,
    )

    resp = {
        "page_count": len(page_results),
        "pages_with_pii": pages_with_pii,
        "highest_risk": highest_risk,
        "pages": page_results,
        "request_id": g.request_id,
    }
    if correlation_id is not None:
        resp["correlation_id"] = correlation_id
    return jsonify(resp)


# ---------------------------------------------------------------------------
# GET /api/v1/jobs/<job_id> — async job status stub (Redis/RQ deferred)
# ---------------------------------------------------------------------------

@app.route("/api/v1/jobs/<job_id>")
@require_api_key
def job_status(job_id):
    return jsonify({
        "error": "Async job queue not yet implemented. Use synchronous endpoints for now.",
        "code": "NOT_IMPLEMENTED",
        "job_id": job_id,
        "pending_item": "Redis/RQ queue — deferred until file workloads hit timeout ceiling.",
        "request_id": g.request_id,
    }), 501


def _process_csv(guard, content: bytes, columns: list, mode, exclude_types, include_excluded, max_rows) -> tuple:
    try:
        text = content.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
    except Exception as exc:
        logger.warning("CSV parse error: %s", exc)
        return error_response("CSV file is invalid or unreadable.", "PARSE_ERROR", 400)

    if len(rows) > max_rows:
        return error_response(f"CSV exceeds {max_rows} row limit.", "TOO_MANY_ROWS", 400)

    target_cols = columns if columns else [k for k in (rows[0].keys() if rows else [])]
    results = []
    rows_with_pii = 0
    excluded_rows = 0

    for i, row in enumerate(rows):
        sanitized_row, excluded_fields = guard.sanitize_dict(
            row, fields=target_cols, mode=mode, exclude_entity_types=exclude_types or None
        )
        has_pii = any(
            row[f] != sanitized_row.get(f) for f in target_cols if f in row
        )
        if has_pii:
            rows_with_pii += 1
        if excluded_fields:
            excluded_rows += 1
            if not include_excluded:
                continue

        results.append({
            "index": i,
            "row": sanitized_row,
            "excluded_fields": excluded_fields,
            "has_pii": has_pii,
        })

    audit.log_event(
        endpoint="/api/v1/file",
        request_id=g.request_id,
        client_ip=request.remote_addr,
        api_key_prefix=g.api_key_prefix,
        mode=mode.value,
        hit_count=rows_with_pii,
        excluded_count=excluded_rows,
        entity_types=[],
        risk_level="UNKNOWN",
        batch_size=len(rows),
        duration_ms=_duration_ms(),
        action=mode.value,
    )

    return jsonify({
        "file_type": "csv",
        "total_rows": len(rows),
        "rows_with_pii": rows_with_pii,
        "excluded_rows": excluded_rows,
        "results": results,
        "request_id": g.request_id,
    })


def _process_json(guard, content: bytes, columns: list, mode, exclude_types, include_excluded, max_rows) -> tuple:
    try:
        data = json.loads(content.decode("utf-8"))
    except Exception as exc:
        logger.warning("JSON parse error: %s", exc)
        return error_response("JSON file is invalid or unreadable.", "PARSE_ERROR", 400)

    if not isinstance(data, list):
        return error_response("JSON file must contain a top-level array of objects.", "INVALID_JSON_SHAPE", 400)

    if len(data) > max_rows:
        return error_response(f"JSON array exceeds {max_rows} record limit.", "TOO_MANY_ROWS", 400)

    results = []
    rows_with_pii = 0
    excluded_rows = 0

    for i, record in enumerate(data):
        if not isinstance(record, dict):
            continue
        target_fields = columns if columns else [k for k, v in record.items() if isinstance(v, str)]
        sanitized_record, excluded_fields = guard.sanitize_dict(
            record, fields=target_fields, mode=mode, exclude_entity_types=exclude_types or None
        )
        has_pii = any(
            record.get(f) != sanitized_record.get(f) for f in target_fields
        )
        if has_pii:
            rows_with_pii += 1
        if excluded_fields:
            excluded_rows += 1
            if not include_excluded:
                continue

        results.append({
            "index": i,
            "record": sanitized_record,
            "excluded_fields": excluded_fields,
            "has_pii": has_pii,
        })

    audit.log_event(
        endpoint="/api/v1/file",
        request_id=g.request_id,
        client_ip=request.remote_addr,
        api_key_prefix=g.api_key_prefix,
        mode=mode.value,
        hit_count=rows_with_pii,
        excluded_count=excluded_rows,
        entity_types=[],
        risk_level="UNKNOWN",
        batch_size=len(data),
        duration_ms=_duration_ms(),
        action=mode.value,
    )

    return jsonify({
        "file_type": "json",
        "total_rows": len(data),
        "rows_with_pii": rows_with_pii,
        "excluded_rows": excluded_rows,
        "results": results,
        "request_id": g.request_id,
    })


def _process_tsv(guard, content: bytes, columns: list, mode, exclude_types, include_excluded, max_rows) -> tuple:
    try:
        text = content.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text), delimiter="\t")
        rows = list(reader)
    except Exception as exc:
        logger.warning("TSV parse error: %s", exc)
        return error_response("TSV file is invalid or unreadable.", "PARSE_ERROR", 400)

    if len(rows) > max_rows:
        return error_response(f"TSV exceeds {max_rows} row limit.", "TOO_MANY_ROWS", 400)

    target_cols = columns if columns else list(rows[0].keys() if rows else [])
    results, rows_with_pii, excluded_rows = [], 0, 0

    for i, row in enumerate(rows):
        sanitized_row, excluded_fields = guard.sanitize_dict(
            row, fields=target_cols, mode=mode, exclude_entity_types=exclude_types or None
        )
        has_pii = any(row[f] != sanitized_row.get(f) for f in target_cols if f in row)
        if has_pii:
            rows_with_pii += 1
        if excluded_fields:
            excluded_rows += 1
            if not include_excluded:
                continue
        results.append({
            "index": i,
            "row": sanitized_row,
            "excluded_fields": excluded_fields,
            "has_pii": has_pii,
        })

    audit.log_event(
        endpoint="/api/v1/file",
        request_id=g.request_id,
        client_ip=request.remote_addr,
        api_key_prefix=g.api_key_prefix,
        mode=mode.value,
        hit_count=rows_with_pii,
        excluded_count=excluded_rows,
        entity_types=[],
        risk_level="UNKNOWN",
        batch_size=len(rows),
        duration_ms=_duration_ms(),
        action=mode.value,
    )

    return jsonify({
        "file_type": "tsv",
        "total_rows": len(rows),
        "rows_with_pii": rows_with_pii,
        "excluded_rows": excluded_rows,
        "results": results,
        "request_id": g.request_id,
    })


def _process_jsonl(guard, content: bytes, columns: list, mode, exclude_types, include_excluded, max_rows) -> tuple:
    try:
        lines = [json.loads(line) for line in content.decode("utf-8").splitlines() if line.strip()]
    except Exception as exc:
        logger.warning("JSONL parse error: %s", exc)
        return error_response("JSONL file contains invalid JSON on one or more lines.", "PARSE_ERROR", 400)

    if len(lines) > max_rows:
        return error_response(f"JSONL exceeds {max_rows} record limit.", "TOO_MANY_ROWS", 400)

    results, rows_with_pii, excluded_rows = [], 0, 0
    for i, record in enumerate(lines):
        if not isinstance(record, dict):
            continue
        target_fields = columns if columns else [k for k, v in record.items() if isinstance(v, str)]
        sanitized_record, excluded_fields = guard.sanitize_dict(record, fields=target_fields, mode=mode, exclude_entity_types=exclude_types or None)
        has_pii = any(record.get(f) != sanitized_record.get(f) for f in target_fields)
        if has_pii:
            rows_with_pii += 1
        if excluded_fields:
            excluded_rows += 1
            if not include_excluded:
                continue
        results.append({"index": i, "record": sanitized_record, "excluded_fields": excluded_fields, "has_pii": has_pii})

    return jsonify({"file_type": "jsonl", "total_rows": len(lines), "rows_with_pii": rows_with_pii, "excluded_rows": excluded_rows, "results": results, "request_id": g.request_id})


def _process_txt(guard, content: bytes, columns: list, mode, exclude_types, include_excluded, max_rows) -> tuple:
    try:
        text = content.decode("utf-8")
    except Exception as exc:
        logger.warning("TXT decode error: %s", exc)
        return error_response("Text file must be UTF-8 encoded.", "PARSE_ERROR", 400)

    result = guard.sanitize(text, mode=mode, exclude_entity_types=exclude_types or None)
    return jsonify({
        "file_type": "txt",
        "total_rows": 1,
        "rows_with_pii": 0 if result.is_clean else 1,
        "excluded_rows": 1 if result.excluded else 0,
        "results": [{"index": 0, "sanitized_text": result.sanitized_text, "excluded": result.excluded, "has_pii": not result.is_clean}],
        "request_id": g.request_id,
    })


def _process_pdf(guard, content: bytes, columns: list, mode, exclude_types, include_excluded, max_rows) -> tuple:
    try:
        import pdfplumber
    except ImportError:
        return error_response("PDF support requires pdfplumber. Run: pip install pdfplumber", "DEPENDENCY_MISSING", 501)

    try:
        with pdfplumber.open(io.BytesIO(content)) as pdf:
            pages = [page.extract_text() or "" for page in pdf.pages]
    except Exception as exc:
        logger.warning("PDF parse error: %s", exc)
        return error_response("PDF file is corrupted or unreadable.", "PARSE_ERROR", 400)

    if len(pages) > max_rows:
        return error_response(f"PDF has {len(pages)} pages, limit is {max_rows}.", "TOO_MANY_ROWS", 400)

    results, rows_with_pii, excluded_rows = [], 0, 0
    for i, text in enumerate(pages):
        if not text.strip():
            continue
        result = guard.sanitize(text, mode=mode, exclude_entity_types=exclude_types or None)
        if not result.is_clean:
            rows_with_pii += 1
        if result.excluded:
            excluded_rows += 1
            if not include_excluded:
                continue
        results.append({"index": i, "page": i + 1, "sanitized_text": result.sanitized_text, "excluded": result.excluded, "has_pii": not result.is_clean})

    return jsonify({"file_type": "pdf", "total_rows": len(pages), "rows_with_pii": rows_with_pii, "excluded_rows": excluded_rows, "results": results, "request_id": g.request_id})


def _process_docx(guard, content: bytes, columns: list, mode, exclude_types, include_excluded, max_rows) -> tuple:
    try:
        from docx import Document
    except ImportError:
        return error_response("DOCX support requires python-docx. Run: pip install python-docx", "DEPENDENCY_MISSING", 501)

    try:
        doc = Document(io.BytesIO(content))
        paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
    except Exception as exc:
        logger.warning("DOCX parse error: %s", exc)
        return error_response("DOCX file is corrupted or unreadable.", "PARSE_ERROR", 400)

    if len(paragraphs) > max_rows:
        return error_response(f"DOCX has {len(paragraphs)} paragraphs, limit is {max_rows}.", "TOO_MANY_ROWS", 400)

    results, rows_with_pii, excluded_rows = [], 0, 0
    for i, text in enumerate(paragraphs):
        result = guard.sanitize(text, mode=mode, exclude_entity_types=exclude_types or None)
        if not result.is_clean:
            rows_with_pii += 1
        if result.excluded:
            excluded_rows += 1
            if not include_excluded:
                continue
        results.append({"index": i, "sanitized_text": result.sanitized_text, "excluded": result.excluded, "has_pii": not result.is_clean})

    return jsonify({"file_type": "docx", "total_rows": len(paragraphs), "rows_with_pii": rows_with_pii, "excluded_rows": excluded_rows, "results": results, "request_id": g.request_id})


def _process_xlsx(guard, content: bytes, columns: list, mode, exclude_types, include_excluded, max_rows) -> tuple:
    try:
        import openpyxl
    except ImportError:
        return error_response("XLSX support requires openpyxl. Run: pip install openpyxl", "DEPENDENCY_MISSING", 501)

    try:
        wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
        ws = wb.active
        all_rows = list(ws.iter_rows(values_only=True))
    except Exception as exc:
        logger.warning("XLSX parse error: %s", exc)
        return error_response("XLSX file is corrupted or unreadable.", "PARSE_ERROR", 400)

    if not all_rows:
        return jsonify({"file_type": "xlsx", "total_rows": 0, "rows_with_pii": 0, "excluded_rows": 0, "results": [], "request_id": g.request_id})

    # Use Excel column letters (A, B, C...) for unnamed headers
    _col_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    def _col_name(i: int) -> str:
        return _col_letters[i] if i < 26 else f"col_{i + 1}"
    headers = [str(h) if h is not None else _col_name(i) for i, h in enumerate(all_rows[0])]
    data_rows = all_rows[1:]

    if len(data_rows) > max_rows:
        return error_response(f"XLSX has {len(data_rows)} rows, limit is {max_rows}.", "TOO_MANY_ROWS", 400)

    target_cols = columns if columns else headers
    results, rows_with_pii, excluded_rows = [], 0, 0

    for i, row in enumerate(data_rows):
        record = {headers[j]: (str(v) if v is not None else "") for j, v in enumerate(row)}
        sanitized_record, excluded_fields = guard.sanitize_dict(record, fields=target_cols, mode=mode, exclude_entity_types=exclude_types or None)
        has_pii = any(record.get(f) != sanitized_record.get(f) for f in target_cols if f in record)
        if has_pii:
            rows_with_pii += 1
        if excluded_fields:
            excluded_rows += 1
            if not include_excluded:
                continue
        results.append({"index": i, "row": sanitized_record, "excluded_fields": excluded_fields, "has_pii": has_pii})

    return jsonify({"file_type": "xlsx", "total_rows": len(data_rows), "rows_with_pii": rows_with_pii, "excluded_rows": excluded_rows, "results": results, "request_id": g.request_id})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5900))
    debug = os.getenv("FLASK_ENV", "production") == "development"
    logger.info("Starting %s v%s on port %d", SERVICE, VERSION, port)
    app.run(host="0.0.0.0", port=port, use_reloader=False, debug=debug)
