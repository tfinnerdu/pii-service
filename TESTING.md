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
3. Open browser: `http://localhost:5900/health`
4. Expected response: `{"status":"ok","service":"pii-service","version":"1.0.0","uptime_seconds":...}`
5. Key: `service` must be `"pii-service"` — not `"pii-guard"`.

**Last verified:** 2025-05 (initial release)

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

### §3.3 Unsupported file type rejection

Upload a `.txt` file. Expected: 400 with `code: "INVALID_FILE_TYPE"`.

### §3.4 Oversized file rejection

Attempt to upload a file larger than `FILE_SIZE_LIMIT_MB`. Expected: 400 with `code: "FILE_TOO_LARGE"`.

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
4. Trigger a test run with input `{ "text": "SSN 123-45-6789", "mode": "mask" }`
5. Expected: workflow completes, output contains `sanitized_text` with `[US_SSN]`

**Last verified:** TBD (verify after Conductor integration is live)

---

## §7 K8s Deployment

1. Apply manifests: `kubectl apply -f k8s/deployment.yaml`
2. Check pods: `kubectl get pods -n prod -l app=pii-service`
3. Wait for Running state (allow 60s for spaCy model load)
4. Probe: `curl https://du-int.doane.edu/prod/pii-service/health`
5. Expected: same health JSON as local

---

## §8 Authentication (Production)

1. Call `/api/v1/scan` without a key: expect 401
2. Call with wrong key: expect 403
3. Call with correct key in `Authorization: Bearer <key>`: expect 200
4. Verify `/health` returns 200 without any key (K8s probe must work without auth)
