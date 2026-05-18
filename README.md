# pii-service

FERPA-compliant PII detection and sanitization service for Doane University's AI platform.
Built on [Microsoft Presidio](https://microsoft.github.io/presidio/) — all processing is local; no text leaves your machine or cluster.

---

## What it does

- Detects 35+ PII entity types including education-sector types (Banner student IDs, FAFSA IDs, FERPA markers, Title IX case IDs, IRB protocol numbers, financial aid awards, student account IDs, immigration status, disability accommodations, veteran status)
- Sanitizes text via mask, redact, pseudonymize, or exclude modes
- Provides AI preflight checks before sending data to external LLMs
- Ingests CSV, TSV, JSON, JSONL, TXT, PDF, DOCX, and XLSX files
- Integrates with Orkes Conductor workflows and n8n automation
- Ships named policies (ai_prompt, ferpa_strict, analytics, etc.) for one-call compliance

---

## Quick start (local)

```powershell
# 1. Copy and configure environment
cp .env.example .env
# Edit .env — set API_KEY to a strong random value for anything non-local

# 2. Install dependencies (requires Python 3.11+)
pip install -r requirements.txt
python -m spacy download en_core_web_lg

# 3. Run
.\start-local.ps1
# or: python app.py
```

Service starts on **port 5900** by default. Visit `http://localhost:5900/health` to verify.

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness — no auth required (K8s liveness probe) |
| GET | `/health/deep` | Readiness with Presidio verification — no auth (K8s readiness probe) |
| GET | `/metrics` | Prometheus text format telemetry — no auth |
| GET | `/api/v1/entities` | All detectable entity types |
| GET | `/api/v1/policies` | Named policy catalog |
| GET | `/api/v1/schemas` | ERP schema profiles (Banner, Colleague, Salesforce, Ethos, Workday, ServiceNow, Slate, Starfish, Canvas, Microsoft Graph, n8n) |
| GET | `/api/v1/stats` | In-process telemetry snapshot |
| POST | `/api/v1/stats/reset` | Reset telemetry counters |
| POST | `/api/v1/config/reload` | Hot-reload PII_CONFIG_FILE without pod restart |
| POST | `/api/v1/scan` | Detect PII in text (no modification) |
| POST | `/api/v1/scan/structured` | Scan specific fields of a JSON record |
| POST | `/api/v1/sanitize` | Detect and sanitize a single text |
| POST | `/api/v1/sanitize/batch` | Sanitize a list of texts |
| POST | `/api/v1/sanitize/structured` | Sanitize specific fields of a JSON record |
| POST | `/api/v1/preflight` | AI safety check with recommendation |
| POST | `/api/v1/policy/apply` | Apply a named policy to text or batch |
| POST | `/api/v1/process` | Generic entry point — text, record, or batch + optional policy + schema + `recursive` |
| POST | `/api/v1/file` | Upload and sanitize a file (CSV/TSV/JSON/JSONL/TXT/PDF/DOCX/XLSX) |
| POST | `/api/v1/explain` | Per-hit detection breakdown (pattern, recognizer, context, score) |

All endpoints except `/health` require `Authorization: Bearer <key>` or `X-API-Key: <key>` when `API_KEY` is set.

---

## Authentication

```bash
# Bearer token
curl -H "Authorization: Bearer $API_KEY" http://localhost:5900/api/v1/entities

# X-API-Key header
curl -H "X-API-Key: $API_KEY" http://localhost:5900/api/v1/entities
```

Set `API_KEY=` (empty) to disable auth for local development. **Never deploy without auth.**

---

## Sanitization modes

| Mode | Output | Use for |
|------|--------|---------|
| `mask` | `[ENTITY_TYPE]` tokens | LLM prompts, general API calls |
| `pseudonymize` | Consistent fake values | RAG embeddings, analytics |
| `redact` | `***` stars | Logs, audit trails |
| `exclude` | `null` if any PII found | Strict pipelines, drop-the-chunk |

---

## Named policies

| Policy | Default mode | Behavior |
|--------|-------------|---------|
| `ai_prompt` | mask | Blocks SSN, financial, immigration; passes dates |
| `embedding` | pseudonymize | Blocks CRITICAL; pseudonymizes HIGH/MEDIUM |
| `log_safe` | redact | Blocks all but low-risk date/location |
| `export_internal` | mask | Blocks SSN/financial; allows names/email for staff |
| `export_external` | mask | Blocks SSN/financial/email; strict for external |
| `ferpa_strict` | exclude | Rejects any record with PII — FERPA compliance |
| `analytics` | pseudonymize | Pseudonymizes everything; no hard blocks |

```bash
curl -X POST http://localhost:5900/api/v1/policy/apply \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"policy": "ai_prompt", "text": "Student D1234567 SSN 123-45-6789 needs help with CSCI 301"}'
```

---

## File upload

```bash
curl -X POST http://localhost:5900/api/v1/file \
  -H "X-API-Key: $API_KEY" \
  -F "file=@students.csv" \
  -F "mode=mask" \
  -F 'columns=["name","email","notes"]'
```

Optional form fields: `mode`, `columns` (JSON array), `exclude_entity_types` (JSON array), `include_excluded` (true/false).

File size limit: `FILE_SIZE_LIMIT_MB` (default 10 MB). Row limit: `FILE_ROW_LIMIT` (default 10,000).

PDF, DOCX, and XLSX require optional dependencies:
```bash
pip install pdfplumber python-docx openpyxl
```

---

## Conductor integration

Import `workflows/pii_scan_and_sanitize.json` and `workflows/pii_ai_preflight_gate.json` into your Orkes Conductor instance.

Run the standalone worker (requires `conductor-python`):
```bash
pip install conductor-python
CONDUCTOR_SERVER_URL=http://localhost:8080/api python workers/conductor_pii_worker.py
```

---

## n8n integration

Import `n8n/pii_service_workflow.json` into your n8n instance. Set the `PII_SERVICE_API_KEY` environment variable in n8n, and update the service URL to match your deployment.

---

## Schema profiles

Schema profiles map ERP field names to entity types so detection is field-name-aware:

```bash
curl -X POST http://localhost:5900/api/v1/process \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "schema": "banner_student",
    "record": {
      "SPRIDEN_LAST_NAME": "Smith",
      "SPBPERS_SSN": "123-45-6789",
      "GPA": 3.5
    },
    "mode": "mask"
  }'
```

Built-in profiles: `banner_student`, `colleague_person`, `salesforce_contact`, `ethos_person`, `n8n_generic`, `conductor_ethos`, `workday_hr`, `servicenow_itsm`, `slate_crm`, `starfish_early_alert`, `canvas_lms`, `microsoft_graph`.

Custom profiles can be added via `PII_CONFIG_FILE`.

---

## Dynamic configuration

Create a JSON config file and point `PII_CONFIG_FILE` at it:

```json
{
  "entity_thresholds": { "STUDENT_ID": 0.8, "FERPA_MARKER": 0.6 },
  "custom_patterns": [
    {
      "entity_type": "EMPLOYEE_ID",
      "patterns": [{"name": "emp_id", "regex": "\\bEMP-\\d{5}\\b", "score": 0.9}],
      "context": ["employee", "staff", "faculty"]
    }
  ],
  "pseudo_pools": {
    "first_names": ["Alex", "Morgan", "Jordan"],
    "last_names": ["Rivera", "Chen", "Patel"],
    "cities": ["Lincoln", "Omaha", "Kearney"]
  }
}
```

Hot-reload without restart:
```bash
curl -X POST http://localhost:5900/api/v1/config/reload -H "X-API-Key: $API_KEY"
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PII_SCORE_THRESHOLD` | `0.5` | Presidio confidence threshold (0.0–1.0) |
| `PII_USE_SPACY` | `true` | Use spaCy NLP for PERSON/LOCATION (requires en_core_web_lg) |
| `PORT` | `5900` | Flask listen port |
| `FLASK_ENV` | `production` | `development` enables debug mode |
| `API_KEY` | *(empty)* | Auth key — leave empty to disable auth locally |
| `BATCH_SIZE_LIMIT` | `500` | Max texts in a batch request |
| `FILE_ROW_LIMIT` | `10000` | Max rows in uploaded files |
| `FILE_SIZE_LIMIT_MB` | `10` | Max file upload size |
| `MAX_TEXT_LENGTH` | `100000` | Max characters per text input |
| `PII_CONFIG_FILE` | *(empty)* | Path to JSON config for custom patterns/thresholds |
| `PSEUDO_SECRET` | *(empty)* | HMAC-SHA256 seed for pseudonymization — prevents reversal attacks. Generate: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `PII_SANDBOX_MODE` | `false` | Return deterministic fake responses without Presidio — for CI/integration testing |
| `PII_DECODE_ENCODED` | `false` | Decode URL-encoded or base64-encoded text before scanning |

---

## Kubernetes deployment

```bash
kubectl apply -f k8s/deployment.yaml
```

The manifest targets `namespace: prod`, exposes the service at `/prod/pii-service` via Traefik stripPrefix middleware, and uses `wildcard-doane-tls` for TLS.

---

## Testing

```bash
# All tests (some skip without presidio installed)
pytest

# Only tests that run without the ML stack
pytest -k "not presidio"

# With full ML stack
pip install presidio-analyzer presidio-anonymizer spacy
python -m spacy download en_core_web_lg
pytest
```

See [TESTING.md](TESTING.md) for the full test strategy and four-bucket accountability table.

---

## License

MIT — see [LICENSE](LICENSE).
