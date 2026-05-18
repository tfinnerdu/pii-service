# Coverage Accountability Table — pii-service

Every production file is assigned exactly one (or more) of:
- **Unit-tested** — behavior asserted by pytest
- **Contract-pinned** — characterization test pins an invariant or shape
- **Compile-verified** — no runtime behavior; Python import check is the test
- **Manual-procedure** — UI or host-specific flow; see TESTING.md

Update this table in the same commit that adds or removes a file.
No file ships without a bucket.

| File | Bucket | Test / Reference |
|---|---|---|
| `app.py` | Unit-tested + Contract-pinned | `tests/integration/test_api_endpoints.py` (requires presidio), `tests/characterization/test_api_contract.py` (all endpoints including `/stats/reset`, `/config/reload`, `/schemas`, file error contracts) |
| `pii_guard/__init__.py` | Compile-verified | (no runtime behavior — re-exports) |
| `pii_guard/models.py` | Unit-tested | indirectly via `tests/unit/test_guard.py` and `tests/unit/test_policy.py` (all tests use ScanResult, EntityHit, RiskLevel) |
| `pii_guard/guard.py` | Unit-tested + Contract-pinned | `tests/unit/test_guard.py` (requires presidio), `tests/characterization/test_recognizer_patterns.py` |
| `pii_guard/recognizers.py` | Unit-tested + Contract-pinned | `tests/unit/test_recognizers.py` (requires presidio), `tests/characterization/test_recognizer_patterns.py` |
| `pii_guard/policy.py` | Unit-tested + Contract-pinned | `tests/unit/test_policy.py`, `tests/characterization/test_api_contract.py` (policy catalog shape) |
| `pii_guard/audit.py` | Unit-tested | `tests/unit/test_audit.py` (log_event, get_stats, reset_stats) |
| `pii_guard/auth.py` | Unit-tested + Contract-pinned | `tests/unit/test_auth.py` (including edge cases: empty key, header precedence), `tests/characterization/test_api_contract.py` |
| `pii_guard/config.py` | Contract-pinned | `tests/characterization/test_env_vars.py` (all env var names), `tests/characterization/test_api_contract.py` (schemas endpoint, config/reload endpoint) |
| `workers/conductor_pii_worker.py` | Contract-pinned | `tests/characterization/test_conductor_contracts.py` (task names, TASK_HANDLERS dict, input param names) |
| `k8s/deployment.yaml` | Contract-pinned | `tests/characterization/test_k8s_manifest.py` (namespace, port, TLS, middleware, imagePullSecret) |
| `workflows/pii_scan_and_sanitize.json` | Contract-pinned | `tests/characterization/test_conductor_contracts.py` (required fields, task reference name, task order) |
| `workflows/pii_ai_preflight_gate.json` | Contract-pinned | `tests/characterization/test_conductor_contracts.py` (required fields, preflight-before-sanitize order, JQ transform task) |
| `n8n/pii_service_workflow.json` | Manual-procedure | TESTING.md §4 |
| `examples/usage.py` | Manual-procedure | TESTING.md §5.1 |
| `examples/ai_preflight.py` | Manual-procedure | TESTING.md §5.2 |
| `README.md` | Manual-procedure | Review during any feature addition or endpoint change |

## CI enforcement

Add to CI pipeline to catch unregistered files:

```bash
# Find Python source files not mentioned in coverage-accountability.md
python -c "
import os, sys
src = [f for f in (
    list(__import__('pathlib').Path('.').rglob('*.py'))
) if '.venv' not in str(f) and '__pycache__' not in str(f) and 'test_' not in str(f)]
table = open('docs/coverage-accountability.md').read()
missing = [f for f in src if str(f) not in table]
if missing:
    print('FILES NOT IN COVERAGE TABLE:', missing)
    sys.exit(1)
"
```
