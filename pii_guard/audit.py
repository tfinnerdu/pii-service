"""
pii_guard.audit - FERPA-compliant structured audit logging for PII processing events.

All audit events are written to stdout as structured JSON alongside the regular app log.
No raw PII text ever appears in audit records. The audit log records:
  - what was asked (endpoint, mode, batch size)
  - what was found (entity types, hit counts, risk level)
  - what was done (action taken)
  - who asked (api_key_prefix, client_ip, request_id)
  - how long it took (duration_ms)

In-memory stats accumulate for the lifetime of the process and are exposed via
/api/v1/stats. They reset on pod restart — they are operational telemetry, not
a durable audit archive. A durable archive requires piping stdout to a log aggregator.
"""

import json
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("pii_guard.audit")

_lock = threading.Lock()

# ---------------------------------------------------------------------------
# In-memory stats (reset on restart)
# ---------------------------------------------------------------------------

_stats: dict = {
    "total_requests": 0,
    "total_pii_hits": 0,
    "total_excluded": 0,
    "total_clean": 0,
    "entity_type_counts": defaultdict(int),
    "mode_counts": defaultdict(int),
    "risk_level_counts": defaultdict(int),
    "endpoint_counts": defaultdict(int),
    "process_start": time.time(),
}


def get_stats() -> dict:
    """Return a safe snapshot of in-memory stats for the /api/v1/stats endpoint."""
    with _lock:
        return {
            "total_requests": _stats["total_requests"],
            "total_pii_hits": _stats["total_pii_hits"],
            "total_excluded": _stats["total_excluded"],
            "total_clean": _stats["total_clean"],
            "entity_type_counts": dict(_stats["entity_type_counts"]),
            "mode_counts": dict(_stats["mode_counts"]),
            "risk_level_counts": dict(_stats["risk_level_counts"]),
            "endpoint_counts": dict(_stats["endpoint_counts"]),
            "uptime_seconds": round(time.time() - _stats["process_start"], 1),
        }


# ---------------------------------------------------------------------------
# Audit event emission
# ---------------------------------------------------------------------------

def reset_stats() -> None:
    """Reset in-memory counters. Call between test runs or after deployment."""
    with _lock:
        _stats["total_requests"] = 0
        _stats["total_pii_hits"] = 0
        _stats["total_excluded"] = 0
        _stats["total_clean"] = 0
        _stats["entity_type_counts"].clear()
        _stats["mode_counts"].clear()
        _stats["risk_level_counts"].clear()
        _stats["endpoint_counts"].clear()
        _stats["process_start"] = time.time()


def log_event(
    *,
    endpoint: str,
    request_id: str,
    client_ip: str,
    api_key_prefix: Optional[str],  # first 4 chars of key, or None if no auth
    mode: Optional[str],
    hit_count: int,
    excluded_count: int,
    entity_types: list[str],
    risk_level: str,
    batch_size: int = 1,
    duration_ms: float,
    action: str,                    # "scan" | "sanitize" | "exclude" | "reject" | "preflight"
    policy_name: Optional[str] = None,
) -> None:
    """
    Emit one structured audit event per request (never one per fan-out item).
    Accumulates into in-memory stats.
    """
    event = {
        "audit": True,
        "endpoint": endpoint,
        "request_id": request_id,
        "client_ip": client_ip,
        "api_key_prefix": api_key_prefix,
        "mode": mode,
        "action": action,
        "batch_size": batch_size,
        "hit_count": hit_count,
        "excluded_count": excluded_count,
        "entity_types": entity_types,
        "risk_level": risk_level,
        "duration_ms": round(duration_ms, 2),
        "policy": policy_name,
    }
    logger.info(json.dumps(event))

    with _lock:
        _stats["total_requests"] += 1
        _stats["total_pii_hits"] += hit_count
        _stats["total_excluded"] += excluded_count
        if hit_count == 0:
            _stats["total_clean"] += batch_size
        for et in entity_types:
            _stats["entity_type_counts"][et] += 1
        if mode:
            _stats["mode_counts"][mode] += 1
        _stats["risk_level_counts"][risk_level] += 1
        _stats["endpoint_counts"][endpoint] += 1
