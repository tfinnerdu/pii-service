"""
workers/conductor_pii_worker.py - Orkes Conductor SIMPLE task workers for pii-service.

Registers two task types that can be used in any Conductor workflow:

  pii_scan_text
    Input:  text (str), exclude_entity_types (list, optional)
    Output: pii_found (bool), risk_level (str), entity_types (list), hit_count (int)

  pii_sanitize_text
    Input:  text (str), mode (str), exclude_entity_types (list, optional)
            policy (str, optional — uses named policy instead of mode)
    Output: sanitized_text (str|null), excluded (bool), pii_found (bool),
            risk_level (str), entity_types (list), hit_count (int)

  pii_sanitize_dict
    Input:  record (dict), fields (list), mode (str), exclude_entity_types (list, optional)
    Output: sanitized_record (dict), excluded_fields (list)

  pii_preflight
    Input:  text (str)
    Output: safe_to_send (bool), risk_level (str), blocking_entities (list),
            recommendation (str), sanitized_suggestion (str|null)

Usage in Conductor workflow:
  {
    "name": "pii_scan_text",
    "taskReferenceName": "scan_student_notes",
    "type": "SIMPLE",
    "inputParameters": {
      "text": "${workflow.input.notes}",
      "exclude_entity_types": ["DATE_TIME"]
    }
  }

Run this worker standalone:
  python workers/conductor_pii_worker.py

Or register it in start-local.ps1 by launching it alongside the Flask app.

Conductor Python SDK: pip install conductor-python
"""

import logging
import os
import sys
import time
from typing import Optional

logger = logging.getLogger("pii_conductor_worker")
logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# Guard singleton (shared across tasks in this worker process)
# ---------------------------------------------------------------------------

_guard = None

def _get_guard():
    global _guard
    if _guard is None:
        from pii_guard import PiiGuard
        threshold = float(os.getenv("PII_SCORE_THRESHOLD", "0.5"))
        use_spacy = os.getenv("PII_USE_SPACY", "true").lower() == "true"
        _guard = PiiGuard(score_threshold=threshold, use_spacy=use_spacy)
    return _guard


# ---------------------------------------------------------------------------
# Task implementations
# ---------------------------------------------------------------------------

def task_pii_scan_text(task: dict) -> dict:
    """
    pii_scan_text: Detect PII without modifying the text.
    Returns hit metadata — callers use this to decide whether to proceed.
    """
    inp = task.get("inputData", {})
    text = inp.get("text", "")
    exclude_types = inp.get("exclude_entity_types", [])

    guard = _get_guard()
    result = guard.scan(text)

    filtered_hits = [h for h in result.hits if h.entity_type not in set(exclude_types)]

    return {
        "status": "COMPLETED",
        "outputData": {
            "pii_found": bool(filtered_hits),
            "hit_count": len(filtered_hits),
            "risk_level": result.risk_level.value,
            "entity_types": list({h.entity_type for h in filtered_hits}),
            "is_clean": not bool(filtered_hits),
        },
        "logs": [],
    }


def task_pii_sanitize_text(task: dict) -> dict:
    """
    pii_sanitize_text: Scan and sanitize a single text field.

    If 'policy' is specified, the named policy is applied (takes precedence over 'mode').
    If mode=exclude and PII is found, sanitized_text will be null.
    """
    from pii_guard import SanitizeMode
    from pii_guard.policy import BUILT_IN_POLICIES, policy_engine

    inp = task.get("inputData", {})
    text = inp.get("text", "")
    mode_str = inp.get("mode", "mask")
    exclude_types = inp.get("exclude_entity_types", [])
    policy_name = inp.get("policy")

    guard = _get_guard()

    if policy_name:
        if policy_name not in BUILT_IN_POLICIES:
            return {
                "status": "FAILED",
                "reasonForIncompletion": f"Unknown policy '{policy_name}'. Valid: {list(BUILT_IN_POLICIES.keys())}",
                "outputData": {},
            }
        policy = BUILT_IN_POLICIES[policy_name]
        scan_result = guard.scan(text)
        policy_result = policy_engine.apply(policy, scan_result, text)

        if not policy_result.passed:
            return {
                "status": "COMPLETED",
                "outputData": {
                    "sanitized_text": None,
                    "excluded": True,
                    "pii_found": True,
                    "risk_level": policy_result.risk_level,
                    "entity_types": policy_result.blocked_entities,
                    "hit_count": policy_result.hit_count,
                    "policy_applied": policy_name,
                    "action_taken": "excluded_by_policy",
                },
            }

        # Apply the policy's default mode for non-blocked hits
        result = guard.sanitize(text, mode=policy.default_mode, exclude_entity_types=policy.pass_through_entity_types)
        return {
            "status": "COMPLETED",
            "outputData": {
                **result.summary(),
                "sanitized_text": result.sanitized_text,
                "policy_applied": policy_name,
                "action_taken": policy.default_mode.value,
            },
        }

    # Mode-based path
    try:
        mode = SanitizeMode(mode_str.lower())
    except ValueError:
        return {
            "status": "FAILED",
            "reasonForIncompletion": f"Invalid mode '{mode_str}'. Valid: {[m.value for m in SanitizeMode]}",
            "outputData": {},
        }

    result = guard.sanitize(text, mode=mode, exclude_entity_types=exclude_types or None)

    return {
        "status": "COMPLETED",
        "outputData": {
            "sanitized_text": result.sanitized_text,
            "excluded": result.excluded,
            **result.summary(),
        },
    }


def task_pii_sanitize_dict(task: dict) -> dict:
    """
    pii_sanitize_dict: Sanitize specific string fields in a dict record.
    Returns the sanitized record and any fields that were excluded.

    Useful in Conductor for sanitizing Ethos change event payloads before
    passing them to an LLM or an external service.
    """
    from pii_guard import SanitizeMode

    inp = task.get("inputData", {})
    record = inp.get("record", {})
    fields = inp.get("fields", [])
    mode_str = inp.get("mode", "mask")
    exclude_types = inp.get("exclude_entity_types", [])

    if not isinstance(record, dict):
        return {
            "status": "FAILED",
            "reasonForIncompletion": "'record' must be a dict",
            "outputData": {},
        }

    try:
        mode = SanitizeMode(mode_str.lower())
    except ValueError:
        return {
            "status": "FAILED",
            "reasonForIncompletion": f"Invalid mode '{mode_str}'",
            "outputData": {},
        }

    guard = _get_guard()
    sanitized, excluded_fields = guard.sanitize_dict(
        record,
        fields=fields if fields else [k for k, v in record.items() if isinstance(v, str)],
        mode=mode,
        exclude_entity_types=exclude_types or None,
    )

    return {
        "status": "COMPLETED",
        "outputData": {
            "sanitized_record": sanitized,
            "excluded_fields": excluded_fields,
            "has_excluded_fields": bool(excluded_fields),
        },
    }


def task_pii_preflight(task: dict) -> dict:
    """
    pii_preflight: AI safety check. Returns whether the text is safe to send
    to an LLM, with a risk level and recommendation.

    Use this as a gate before any Conductor task that calls an external AI API.
    """
    inp = task.get("inputData", {})
    text = inp.get("text", "")

    guard = _get_guard()
    result = guard.preflight(text)

    return {
        "status": "COMPLETED",
        "outputData": {
            "safe_to_send": result.safe_to_send,
            "risk_level": result.risk_level.value,
            "hit_count": result.hit_count,
            "blocking_entities": result.blocking_entities,
            "warning_entities": result.warning_entities,
            "recommendation": result.recommendation,
            "sanitized_suggestion": result.sanitized_suggestion,
        },
    }


# ---------------------------------------------------------------------------
# Worker registration
# ---------------------------------------------------------------------------

TASK_HANDLERS = {
    "pii_scan_text":      task_pii_scan_text,
    "pii_sanitize_text":  task_pii_sanitize_text,
    "pii_sanitize_dict":  task_pii_sanitize_dict,
    "pii_preflight":      task_pii_preflight,
}


def start_workers():
    """
    Register all PII task handlers with the Conductor Python SDK and start polling.
    Requires: pip install conductor-python
    """
    try:
        from conductor.client.configuration.configuration import Configuration
        from conductor.client.configuration.settings.authentication_settings import AuthenticationSettings
        from conductor.client.worker.worker_task import WorkerTask
        from conductor.client.automator.task_handler import TaskHandler
    except ImportError:
        logger.error(
            "conductor-python not installed. Run: pip install conductor-python\n"
            "See: https://github.com/conductor-sdk/conductor-python"
        )
        sys.exit(1)

    conductor_url = os.getenv("CONDUCTOR_SERVER_URL", "http://localhost:8080/api")
    conductor_key = os.getenv("CONDUCTOR_AUTH_KEY", "")
    conductor_secret = os.getenv("CONDUCTOR_AUTH_SECRET", "")

    auth = AuthenticationSettings(key_id=conductor_key, key_secret=conductor_secret) if conductor_key else None
    config = Configuration(server_api_url=conductor_url, authentication_settings=auth)

    workers = [
        WorkerTask(task_definition_name=name, execute_function=handler, poll_interval=0.5)
        for name, handler in TASK_HANDLERS.items()
    ]

    logger.info("Starting Conductor workers: %s", list(TASK_HANDLERS.keys()))
    with TaskHandler(workers, config) as handler:
        handler.start_processes()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Worker shutdown requested")


if __name__ == "__main__":
    # Standalone mode — can also be imported by the main app
    start_workers()
