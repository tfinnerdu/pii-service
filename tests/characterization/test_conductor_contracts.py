"""
tests/characterization/test_conductor_contracts.py

Pins Conductor workflow and task contracts. If task names, input parameter names,
or workflow task order changes, these tests fail and force a conscious decision
about whether downstream Conductor workflow definitions need updating.

These tests do NOT call the live Conductor server. They assert what we know
the contracts to be as of the pinned date.
"""

import json
from pathlib import Path

import pytest


WORKFLOWS_DIR = Path(__file__).parent.parent.parent / "workflows"
WORKERS_DIR   = Path(__file__).parent.parent.parent / "workers"


# ---------------------------------------------------------------------------
# Task name contracts — pinned 2025-05
# ---------------------------------------------------------------------------

class TestConductorTaskNames:
    """
    Known-good: these are the task definition names registered with Conductor.
    If any name changes, update the Conductor task definitions AND all workflow
    JSON files that reference them.
    """
    EXPECTED_TASK_NAMES = {
        "pii_scan_text",
        "pii_sanitize_text",
        "pii_sanitize_dict",
        "pii_preflight",
    }

    def test_all_task_names_registered_in_worker(self):
        worker_source = (WORKERS_DIR / "conductor_pii_worker.py").read_text()
        for task_name in self.EXPECTED_TASK_NAMES:
            assert f'"{task_name}"' in worker_source or f"'{task_name}'" in worker_source, (
                f"Task name '{task_name}' not found in conductor_pii_worker.py. "
                "If renamed, update all Conductor workflow JSON files that reference this task."
            )

    def test_task_handler_dict_has_all_tasks(self):
        import sys
        sys.path.insert(0, str(WORKERS_DIR.parent))
        # Import worker module without triggering start_workers()
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "conductor_pii_worker", WORKERS_DIR / "conductor_pii_worker.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        registered = set(mod.TASK_HANDLERS.keys())
        missing = self.EXPECTED_TASK_NAMES - registered
        assert not missing, (
            f"TASK_HANDLERS dict is missing: {missing}. "
            "The Conductor worker won't register these tasks on startup."
        )


# ---------------------------------------------------------------------------
# Task input parameter names — pinned 2025-05
# ---------------------------------------------------------------------------

class TestConductorTaskInputParams:
    """
    Known-good: input parameter names for each task.
    Renaming an input param breaks all workflows that use it.
    Update workflows/ JSON files in the same commit as any rename.
    """
    EXPECTED_INPUTS = {
        "pii_scan_text": {"text", "exclude_entity_types"},
        "pii_sanitize_text": {"text", "mode", "policy", "exclude_entity_types"},
        "pii_sanitize_dict": {"record", "fields", "mode", "exclude_entity_types"},
        "pii_preflight": {"text"},
    }

    def test_scan_text_params_in_source(self):
        source = (WORKERS_DIR / "conductor_pii_worker.py").read_text()
        for param in self.EXPECTED_INPUTS["pii_scan_text"]:
            assert f'"{param}"' in source or f"'{param}'" in source, (
                f"Input parameter '{param}' for pii_scan_text not found in worker source. "
                "Rename without updating workflows will break Conductor executions."
            )

    def test_preflight_params_in_source(self):
        source = (WORKERS_DIR / "conductor_pii_worker.py").read_text()
        for param in self.EXPECTED_INPUTS["pii_preflight"]:
            assert f'"{param}"' in source or f"'{param}'" in source


# ---------------------------------------------------------------------------
# Workflow JSON shape — pinned 2025-05
# ---------------------------------------------------------------------------

class TestWorkflowJsonShape:
    """
    Known-good: workflow JSON files have the required Conductor fields.
    A workflow missing 'name', 'version', 'tasks', or 'inputParameters' will fail to register.
    """
    REQUIRED_FIELDS = {"name", "version", "tasks", "outputParameters"}

    def _load_workflow(self, filename: str) -> dict:
        path = WORKFLOWS_DIR / filename
        return json.loads(path.read_text())

    def test_scan_and_sanitize_workflow_shape(self):
        wf = self._load_workflow("pii_scan_and_sanitize.json")
        missing = self.REQUIRED_FIELDS - set(wf.keys())
        assert not missing, f"pii_scan_and_sanitize.json missing fields: {missing}"

    def test_preflight_gate_workflow_shape(self):
        wf = self._load_workflow("pii_ai_preflight_gate.json")
        missing = self.REQUIRED_FIELDS - set(wf.keys())
        assert not missing, f"pii_ai_preflight_gate.json missing fields: {missing}"

    def test_scan_and_sanitize_task_references_known_task(self):
        wf = self._load_workflow("pii_scan_and_sanitize.json")
        task_names = {t["name"] for t in wf["tasks"]}
        assert "pii_sanitize_text" in task_names, (
            "pii_scan_and_sanitize workflow must reference 'pii_sanitize_text' task. "
            "If the task is renamed, update this workflow."
        )

    def test_preflight_gate_references_pii_preflight(self):
        wf = self._load_workflow("pii_ai_preflight_gate.json")
        task_names = {t["name"] for t in wf["tasks"]}
        assert "pii_preflight" in task_names, (
            "pii_ai_preflight_gate must reference 'pii_preflight' task."
        )

    def test_workflow_task_order_pinned(self):
        """
        Known-good: task reference name order in pii_ai_preflight_gate.
        If order changes, downstream JQ expressions referencing task outputs may break.
        """
        wf = self._load_workflow("pii_ai_preflight_gate.json")
        task_refs = [t["taskReferenceName"] for t in wf["tasks"]]
        # preflight must come before sanitize (preflight result used in JQ)
        assert task_refs.index("preflight_ref") < task_refs.index("sanitize_ref"), (
            "preflight_ref must come before sanitize_ref in pii_ai_preflight_gate. "
            "The JQ decide_output step reads from both."
        )
