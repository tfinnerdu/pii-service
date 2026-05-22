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
| `app.py` | Unit-tested + Contract-pinned | `tests/integration/test_api_endpoints.py` (requires presidio), `tests/characterization/test_api_contract.py` (all endpoints including `/api/v1/health`, `/api/v1/health/deep` checks+mock shape, `/metrics`, `/api/v1/explain`, sandbox mode, mock/live signal, swagger, new schema profiles, `/stats/reset`, `/config/reload`, file error contracts) |
| `pii_guard/__init__.py` | Compile-verified | (no runtime behavior — re-exports) |
| `pii_guard/models.py` | Unit-tested | indirectly via `tests/unit/test_guard.py` and `tests/unit/test_policy.py` (all tests use ScanResult, EntityHit, RiskLevel) |
| `pii_guard/guard.py` | Unit-tested + Contract-pinned | `tests/unit/test_guard.py` (requires presidio), `tests/characterization/test_recognizer_patterns.py` (HMAC seed, new pseudo format fidelity) |
| `pii_guard/recognizers.py` | Unit-tested + Contract-pinned | `tests/unit/test_recognizers.py` (requires presidio), `tests/characterization/test_recognizer_patterns.py` (all custom entities including TITLE_IX_CASE_ID, IRB_PROTOCOL, FINANCIAL_AID_AWARD, STUDENT_ACCOUNT_ID, LICENSE_PLATE; `get_context_for_entity()`) |
| `pii_guard/policy.py` | Unit-tested + Contract-pinned | `tests/unit/test_policy.py`, `tests/characterization/test_api_contract.py` (policy catalog shape) |
| `pii_guard/audit.py` | Unit-tested | `tests/unit/test_audit.py` (log_event, get_stats, reset_stats; `AuditEvent` frozen dataclass shape + field mapping; subject_id, destination, caller_name, correlation_id fields) |
| `pii_guard/auth.py` | Unit-tested + Contract-pinned | `tests/unit/test_auth.py` (single key backward-compat, named multi-key API_KEYS, get_caller_name timing-safe, list_key_names, generate_key, header precedence, edge cases), `tests/characterization/test_api_contract.py` |
| `pii_guard/config.py` | Contract-pinned | `tests/characterization/test_env_vars.py` (all env var names including API_KEYS, PSEUDO_SECRET, PII_SANDBOX_MODE, PII_DECODE_ENCODED), `tests/characterization/test_api_contract.py` (schemas endpoint, 12 profiles, config/reload endpoint) |
| `utils/__init__.py` | Compile-verified | (no runtime behavior — package marker) |
| `utils/responses.py` | Unit-tested | `tests/unit/test_responses.py` (error envelope shape, default status, request_id fallback) |
| `workers/conductor_pii_worker.py` | Contract-pinned | `tests/characterization/test_conductor_contracts.py` (task names, TASK_HANDLERS dict, input param names) |
| `workers/__init__.py` | Compile-verified | (no runtime behavior — empty package marker) |
| `k8s/deployment.yaml` | Contract-pinned | `tests/characterization/test_k8s_manifest.py` (namespace, port, TLS, imagePullSecret; probe paths `/api/v1/health` + `/api/v1/health/deep`; middleware name + ingress annotation cross-check) |
| `workflows/pii_scan_and_sanitize.json` | Contract-pinned | `tests/characterization/test_conductor_contracts.py` (required fields, task reference name, task order) |
| `workflows/pii_ai_preflight_gate.json` | Contract-pinned | `tests/characterization/test_conductor_contracts.py` (required fields, preflight-before-sanitize order, JQ transform task) |
| `templates/ui.html` | Contract-pinned + Manual-procedure | `tests/characterization/test_api_contract.py` (TestUiContract: 200 when auth disabled, HTML present, all tabs, LIVE/MOCK badge); full demo walkthrough in TESTING.md §10 |
| `templates/swagger.html` | Contract-pinned | `tests/characterization/test_api_contract.py` (TestSwaggerContract: `/swagger` 200 HTML, `/openapi.yaml` served) |
| `openapi.yaml` | Manual-procedure | Review during any endpoint addition, removal, or schema change |
| `Dockerfile` | Manual-procedure | `docker build` during deployment; TESTING.md §7 |
| `start-local.ps1` | Manual-procedure | Local launcher; TESTING.md §1 |
| `n8n/pii_service_workflow.json` | Manual-procedure | TESTING.md §4 |
| `examples/usage.py` | Manual-procedure | TESTING.md §5.1 |
| `examples/ai_preflight.py` | Manual-procedure | TESTING.md §5.2 |
| `README.md` | Manual-procedure | Review during any feature addition or endpoint change |

## CI enforcement

Add to CI pipeline to catch unregistered files:

```bash
# Find production files not mentioned in coverage-accountability.md.
# Scans Python AND the non-Python production files (Dockerfile, *.ps1, *.html)
# that a Python-only scan would silently miss.
python -c "
import sys
from pathlib import Path
src = []
for pat in ('*.py', '*.ps1', '*.html'):
    src += Path('.').rglob(pat)
src += Path('.').rglob('Dockerfile')
src = [f for f in src
       if '.venv' not in str(f)
       and '__pycache__' not in str(f)
       and 'tests' not in str(f).split('/')]   # exclude all test infrastructure
table = open('docs/coverage-accountability.md').read()
missing = sorted(str(f) for f in src if str(f) not in table)
if missing:
    print('FILES NOT IN COVERAGE TABLE:', missing)
    sys.exit(1)
print('All production files accounted for.')
"
```
