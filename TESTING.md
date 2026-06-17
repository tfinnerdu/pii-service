# TESTING.md — pii-service End-to-End Test Walkthrough

This document covers the QA layer that pytest cannot reach: file uploads, browser flows,
Conductor task registration, and n8n workflow imports.

All automated tests run via:
```
.venv\Scripts\pytest tests/ -v
```

---

## §1 Local Startup Verification

**Preconditions:** `.env` exists, `.venv` is active, `requirements.txt` installed.

1. Run: `.\start-local.ps1`
2. Expected: console shows port 5900 and endpoint list. No errors.
3. Open browser: `http://localhost:5900/api/v1/health`
4. Expected response: `{"status":"ok","service":"pii-service","version":"1.0.0","uptime_seconds":N}`
   where `uptime_seconds` is an integer.
5. Key: `service` must be `"pii-service"` — not `"pii-guard"`.
6. The bare `/health` path is retired — it returns 404. Only `/api/v1/health` resolves.

**Last verified:** 2025-05 (initial release); health path versioned 2026-05-21

---

## §2 Core API Smoke Tests (curl or Postman)

### §2.1 Scan endpoint

```
POST http://localhost:5900/api/v1/scan
Body: { "text": "Student D1234567, SSN 123-45-6789, jsmith@doane.edu" }
```

Expected: `pii_found: true`, `risk_level: "CRITICAL"`, hits include `US_SSN` and `STUDENT_ID`.
Verify: no `original` or `matched_text` field in any hit object.

### §2.2 Preflight check

```
POST http://localhost:5900/api/v1/preflight
Body: { "text": "SSN 123-45-6789" }
```

Expected: `safe_to_send: false`, `sanitized_suggestion` contains `[US_SSN]`, not the raw SSN.

### §2.3 Named policy

```
POST http://localhost:5900/api/v1/policy/apply
Body: { "policy": "ferpa_strict", "text": "Student GPA is 3.45" }
```

Expected: `action_taken: "excluded"`, `sanitized_text: null`.
Reason: ferpa_strict excludes any chunk with FERPA_MARKER.

### §2.4 All policies respond without error

Hit `/api/v1/policies` — verify all 7 policies appear: `ai_prompt`, `embedding`,
`log_safe`, `export_internal`, `export_external`, `ferpa_strict`, `analytics`.

### §2.5 Schema profiles catalog

```
GET http://localhost:5900/api/v1/schemas
```

Expected: 12 built-in profiles appear — `colleague_person`, `ethos_person`, `salesforce_contact`,
`conductor_ethos`, `n8n_generic`, `workday_hr`, `servicenow_itsm`, `slate_crm`,
`starfish_early_alert`, `canvas_lms`, `microsoft_graph`, `banner_student`. Each has `name`,
`description`, `field_count`, `default_mode`, and `fields` map.

### §2.6 Generic process endpoint

```
POST http://localhost:5900/api/v1/process
Body: { "schema": "colleague_person", "record": { "lastName": "Smith", "socialSecurityNumber": "123-45-6789", "gpa": 3.5 }, "mode": "mask" }
```

Expected: `input_type: "record"`, `schema_applied: "colleague_person"`, `sanitized_record.socialSecurityNumber` contains `[US_SSN]`.
`gpa` (non-string) should pass through unchanged.

### §2.7 Deep health check

```
GET http://localhost:5900/api/v1/health/deep
```

Expected after warm-up: 200 with
`{"status":"ok","service":"pii-service","version":"1.0.0","uptime_seconds":N,"mock":false,"checks":{...}}`.
The `checks` object carries per-dependency status — `checks.presidio.status` is `"ok"` with a
`latency_ms`, and `checks.spacy_model.status` is `"ok"` for `en_core_web_lg`.
If `en_core_web_sm` loaded instead: top-level `"status":"degraded"` and
`checks.spacy_model.status":"degraded"`.
If Presidio fails entirely: 503 with `checks.presidio.status":"down"`.
In sandbox mode: `"mock":true` and `checks.presidio.status":"skipped"`.

### §2.8b Prometheus metrics

```
GET http://localhost:5900/metrics
```

Expected: Prometheus text format (plain text, not JSON). Required metrics: `pii_requests_total`, `pii_pii_hits_total`, `pii_excluded_total`, `pii_clean_total`, `pii_uptime_seconds`.
After making a few scan requests, verify the counters increment.

### §2.8c Explain endpoint

```
POST http://localhost:5900/api/v1/explain
Body: { "text": "Student D1234567 has SSN 123-45-6789" }
```

Expected: `hit_count: 2`, each hit has `entity_type`, `recognizer`, `pattern_name`, `pattern`, `context_words`.
Verify: `STUDENT_ID` hit shows `recognizer: "StudentIdRecognizer"`, `pattern_name: "doane_d_prefix"`.

### §2.7 Stats and telemetry

```
GET http://localhost:5900/api/v1/stats
```

Expected: keys include `total_requests`, `total_pii_hits`, `entity_type_counts`, `uptime_seconds`.

```
POST http://localhost:5900/api/v1/stats/reset
```

Expected: `{ "reset": true }`. Subsequent GET /stats shows zeroed counters.

### §2.8 Config hot-reload

1. Set `PII_CONFIG_FILE=/path/to/custom.json` in `.env` before starting
2. Modify the custom config file on disk
3. `POST http://localhost:5900/api/v1/config/reload`
4. Expected: `{ "reloaded": true, "entity_thresholds": N, "custom_patterns": N, "schema_profiles": N }`
5. Subsequent requests use the updated config (custom thresholds, new patterns)

### §2.9 Text length guard

```
POST http://localhost:5900/api/v1/scan
Body: { "text": "<string longer than MAX_TEXT_LENGTH>" }
```

Expected: 400 with `code: "TEXT_TOO_LONG"`. Default limit is 100,000 characters.
Override with `MAX_TEXT_LENGTH` in `.env`.

---

## §3 File Upload Testing

### §3.1 CSV file

1. Create `test.csv`:
   ```
   name,ssn,gpa
   John Smith,123-45-6789,3.5
   Jane Doe,987-65-4321,3.8
   ```
2. POST to `/api/v1/file` with `file=@test.csv`, `mode=mask`, `columns=["ssn"]`
3. Expected: `file_type: "csv"`, `total_rows: 2`, `rows_with_pii: 2`
4. Verify: SSN column in results contains `[US_SSN]`, name column unchanged (not in columns list)

### §3.2 JSON file

1. Create `test.json`:
   ```json
   [{"email": "jsmith@doane.edu", "note": "SSN 123-45-6789"}, {"email": "clean", "note": "no pii"}]
   ```
2. POST to `/api/v1/file` with `file=@test.json`, `mode=pseudonymize`
3. Expected: `file_type: "json"`, `total_rows: 2`, first row has PII sanitized

### §3.3 Supported file types

`.csv`, `.tsv`, `.json`, `.jsonl`, `.txt` — always supported (no extra deps).
`.pdf` — requires `pdfplumber` (`pip install pdfplumber`).
`.docx` — requires `python-docx` (`pip install python-docx`).
`.xlsx` — requires `openpyxl` (`pip install openpyxl`).

Upload a file with an unsupported extension (e.g., `.xml`, `.rtf`).
Expected: 400 with `code: "INVALID_FILE_TYPE"`, message lists supported types.

### §3.4 Oversized file rejection

Attempt to upload a file larger than `FILE_SIZE_LIMIT_MB`. Expected: 400 with `code: "FILE_TOO_LARGE"`.
Tip: temporarily set `FILE_SIZE_LIMIT_MB=0` in `.env` and upload any non-empty file to trigger this.

### §3.5 PDF / DOCX / XLSX ingestion (requires optional deps)

```bash
pip install pdfplumber python-docx openpyxl
```

1. Upload a PDF with student names or SSNs in the body text.
   Expected: per-page results array, PII replaced per chosen mode.
2. Upload a DOCX with a paragraph containing `jsmith@doane.edu`.
   Expected: per-paragraph results, email masked as `[EMAIL_ADDRESS]` or `[DOANE_EMAIL]`.
3. Upload an XLSX with column headers in row 1 and data in rows 2+.
   Expected: header names used as field names in results. Blank headers get Excel column letters (A, B, C…).
4. Upload a missing-dep file type without the library installed.
   Expected: 501 with `code: "DEPENDENCY_MISSING"` and install instructions.

---

## §4 n8n Workflow Integration

**Preconditions:** n8n running locally, pii-service running on port 5900.

1. In n8n: Settings > Import Workflow > select `n8n/pii_service_workflow.json`
2. In n8n: Settings > Environment Variables > add `PII_SERVICE_API_KEY` (blank for local dev)
3. Activate the workflow
4. POST to the webhook URL with body `{ "text": "SSN: 123-45-6789" }`
5. Expected response: `{ "safe_text": "SSN: [US_SSN]", "was_sanitized": true, "risk_level": "CRITICAL" }`
6. POST with clean text: `{ "text": "CSCI 101 meets Monday" }`
7. Expected: `{ "safe_text": "CSCI 101 meets Monday", "was_sanitized": false }`

**Last verified:** TBD (verify after n8n integration is live)

---

## §5 Example Scripts

### §5.1 usage.py

```
cd C:\doane\code\pii-service
.venv\Scripts\python examples\usage.py
```

Expected: all 6 examples run without error, output shows sanitized text in each mode.

### §5.2 ai_preflight.py

```
.venv\Scripts\python examples\ai_preflight.py
```

Expected: preflight examples run, showing safe/unsafe results and recommendations.

---

## §6 Conductor Task Registration

**Preconditions:** Conductor server running, `CONDUCTOR_SERVER_URL` set in `.env`.

1. Start the worker: `.venv\Scripts\python workers\conductor_pii_worker.py`
2. In Orkes UI: Task Definitions — verify `pii_scan_text`, `pii_sanitize_text`, `pii_sanitize_dict`, `pii_preflight` appear
3. Import `workflows/pii_scan_and_sanitize.json` via the Workflow Definitions UI
4. Trigger a test run with input `{ "text": "SSN 123-45-6789", "mode": "mask", "exclude_entity_types": [] }`
5. Expected: workflow completes, output contains `sanitized_text` with `[US_SSN]`
6. Import `workflows/pii_ai_preflight_gate.json` and trigger with the same input
7. Expected: `safe_text` contains masked text, `was_sanitized: true`

**Last verified:** TBD (verify after Conductor integration is live)

---

## §7 K8s Deployment

1. Apply manifests: `kubectl apply -f k8s/deployment.yaml`
2. Check pods: `kubectl get pods -n prod -l app=pii-service`
3. Wait for Running state (allow 60s for spaCy model load)
4. Probe: `curl https://du-int.doane.edu/prod/pii-service/api/v1/health`
5. Expected: same health JSON as local
6. Verify the Traefik middleware resolved: the Ingress annotation
   `router.middlewares` must read `prod-pii-service-prefix@kubernetescrd` (single
   `prod-`). A doubled `prod-prod-` means the middleware did not resolve and
   stripPrefix is not applied — routes will 404.

---

## §8 Authentication (Production)

### §8.1 Single key (backward-compatible)

1. Call `/api/v1/scan` without a key: expect 401
2. Call with wrong key: expect 403
3. Call with correct key in `Authorization: Bearer <key>`: expect 200
4. Verify `/api/v1/health`, `/api/v1/health/deep`, `/metrics` return 200 without any key (K8s probes must work without auth)

### §8.2 Named multi-key (API_KEYS)

1. Set `API_KEYS="n8n-prod:key1,conductor:key2"` in `.env`
2. Start service — log should show: `API key authentication enabled (2 key(s): conductor, n8n-prod)`
3. Call `/api/v1/scan` with `X-API-Key: key1` — expect 200
4. Call `/api/v1/scan` with `X-API-Key: key2` — expect 200
5. Verify audit log shows `"caller_name": "n8n-prod"` for key1 and `"caller_name": "conductor"` for key2
6. Call with either key and check `GET /api/v1/keys` — expect `{ "keys": ["conductor", "n8n-prod"], "count": 2 }`
7. Note: key VALUES are never returned by any endpoint

### §8.3 Key generator

```
POST http://localhost:5900/api/v1/keys/generate
X-API-Key: <existing-key>
Body: { "name": "ocr-service", "prefix": "sk_ocr" }
```

Expected: `{ "name": "ocr-service", "key": "sk_ocr_...", "add_to_api_keys": "ocr-service:sk_ocr_...", "instructions": "..." }`

Verify: copy `add_to_api_keys` value into `API_KEYS` in `.env`, then `POST /api/v1/config/reload`. New key should now be accepted.

---

## §9 OCR Service Integration

**Preconditions:** OCR service running on port 8089, pii-service running on port 5900.

### §9.1 Direct endpoint smoke test

```
POST http://localhost:5900/api/v1/scan/ocr
X-API-Key: <key>
Body: {
  "pages": [
    { "page_number": 1, "text": "Student D1234567, SSN 123-45-6789", "confidence": 94.1 },
    { "page_number": 2, "text": "GPA 3.45, enrolled CSCI 301", "confidence": 88.0 }
  ],
  "mode": "mask",
  "low_confidence_threshold": 70.0,
  "correlation_id": "test-job-001"
}
```

Expected:
- `page_count: 2`, `pages_with_pii: 1`, `highest_risk: "CRITICAL"`
- Page 1: `pii_found: true`, `low_confidence_warning: false`, `sanitized_text` contains `[STUDENT_ID]` and `[US_SSN]`
- Page 2: `pii_found: false`, `low_confidence_warning: false`
- `correlation_id: "test-job-001"` echoed in response

### §9.2 Low-confidence warning

Upload a page with `"confidence": 45.0` and `"low_confidence_threshold": 70.0`.
Expected: `low_confidence_warning: true` on that page. PII may be unreliable due to OCR errors.

### §9.3 Correlation ID absent when not provided

Call without `correlation_id` in body.
Expected: `correlation_id` key is absent from response (not null — completely absent).

### §9.4 Through OCR service (end-to-end)

1. Upload a scanned PDF with student SSN to OCR service (`POST http://localhost:8089/api/v1/ocr`)
2. Verify OCR service calls pii-service internally (check pii-service logs for `/api/v1/scan/ocr` hit)
3. Verify OCR service response includes `pii_scan.pages_with_pii` and per-page sanitized text
4. Verify `caller_name: "ocr-service"` in pii-service audit log

**Last verified:** TBD (verify after OCR service wiring is complete)

---

## §10 Dev Console (/ui) Walkthrough

**Preconditions:** service running locally with `API_KEY` unset (auth disabled).

1. Open `http://localhost:5900/ui`.
2. Expected: the dark-themed dev console loads with six tabs — Scan & Sanitize,
   Explain, Policy, File Upload, Record / Schema, Rules.
3. Header check: a green **LIVE** badge appears next to "API Docs". The health
   dot turns green ("Presidio ready") within ~30s of warm-up.
4. **Scan & Sanitize:** paste `Student D1234567, SSN 123-45-6789, jsmith@doane.edu`,
   click *Scan & Sanitize*. Expected: original text with highlighted hits, a
   sanitized panel, and a hit-details table.
5. **Explain:** paste the same text. Expected: per-hit recognizer + pattern breakdown.
6. **Policy:** pick `ferpa_strict`, run on any text with PII. Expected: EXCLUDED panel.
7. **File Upload:** drag a small CSV. Expected: per-row results table.
8. **Record / Schema:** paste a JSON record, pick `colleague_person`. Expected:
   original vs sanitized diff.
9. **Rules:** switch to the tab. Expected: policies, custom recognizers, and
   Presidio built-ins render.

**Last verified:** 2026-05-21 (contract-pinned by `TestUiContract` / `TestSwaggerContract`)

---

## §11 Mock/Live Signal Verification

Mock mode must never be silent. With `PII_SANDBOX_MODE=true` in `.env`, verify all
three signals:

1. **UI badge:** open `/ui`. The header badge reads **MOCK** in amber (not LIVE).
2. **Response header:** `curl -i http://localhost:5900/api/v1/health` — the
   response carries `X-Mock-Mode: true`. Hit any `/api/v1/*` endpoint and confirm
   the same header is present.
3. **Health body:** `GET /api/v1/health/deep` returns `"mock": true` and
   `checks.presidio.status: "skipped"`.

Set `PII_SANDBOX_MODE=false` and confirm: badge flips to green **LIVE**, the
`X-Mock-Mode` header is absent, and `/api/v1/health/deep` reports `"mock": false`.

**Last verified:** 2026-05-21 (contract-pinned by `TestMockSignalContract`)
