# PII Service — User Guide

pii-service is Doane University's AI safety layer. Before any text goes to an AI model,
an embedding index, a log file, or an external export, pii-service removes or replaces
personal information so the right data stays inside the institution.

All processing happens locally inside Doane's infrastructure. Text never leaves the cluster.

---

## Who should use this

- **Developers** building AI-powered Doane tools: run text through pii-service before sending it to Claude, GPT, or any embedding API.
- **Data analysts**: sanitize student record exports before loading them into analytics tools or sharing with vendors.
- **Integration engineers**: add the pii_scan_text or pii_sanitize_text tasks to any Conductor workflow that touches student data.
- **n8n workflow builders**: use the provided workflow template to add a PII safety gate to any webhook flow.

---

## What it detects

### Standard PII
Name, email address, phone number, date of birth, mailing address, IP address,
credit card number, SSN, ITIN, passport number, driver's license, bank account/routing numbers.

### Education-specific (higher ed focus)
| Type | Examples |
|---|---|
| Student ID | D1234567 (Banner), @01234567 (Colleague) |
| FERPA markers | "GPA", "transcript", "financial aid hold", "academic probation" |
| Financial aid | FAFSA application numbers, ISIR references, EFC amounts |
| Immigration status | F-1, J-1, DACA, SEVIS ID, I-20, I-94 |
| Disability accommodations | "extended time", ADA accommodation letters, IEP references |
| Veteran status | GI Bill, Chapter 33, VA benefit amounts, DD-214 |
| Campus health | Mental health records, counseling notes, HIPAA markers |
| Institutional email | @doane.edu addresses (tagged separately from personal email) |

---

## How to use it

### Option 1: AI preflight check (recommended starting point)

Before sending anything to an AI model, run a preflight check:

```http
POST /api/v1/preflight
{ "text": "your text here" }
```

Response:
```json
{
  "safe_to_send": false,
  "risk_level": "CRITICAL",
  "blocking_entities": ["US_SSN"],
  "recommendation": "Do not send. Critical PII detected. Sanitize first.",
  "sanitized_suggestion": "The student's SSN is [US_SSN].",
  "hit_count": 1
}
```

If `safe_to_send` is false, use `sanitized_suggestion` as your input to the AI instead.

---

### Option 2: Apply a named policy

Named policies encode the right defaults for common contexts:

| Policy | Use when |
|---|---|
| `ai_prompt` | Before sending to Claude, GPT, or any LLM |
| `embedding` | Before creating embeddings for RAG pipelines |
| `log_safe` | Before writing to application logs |
| `export_internal` | Before including in internal Doane reports |
| `export_external` | Before sharing data outside the institution |
| `ferpa_strict` | Zero tolerance — FERPA financial aid or disciplinary records |
| `analytics` | Aggregate dashboards where personal data is not needed |

```http
POST /api/v1/policy/apply
{ "policy": "ai_prompt", "text": "Student D1234567 has a GPA of 3.5 and SSN 123-45-6789" }
```

The policy handles all the decisions for you — which types to block, which to allow, what mode to use.

---

### Option 3: Explicit sanitize

For full control over mode:

```http
POST /api/v1/sanitize
{
  "text": "John Smith, SSN 123-45-6789, enrolled at Doane",
  "mode": "mask",
  "exclude_entity_types": ["DATE_TIME"]
}
```

Modes:
- **mask** — `[US_SSN]` tokens. Best for LLM prompts.
- **pseudonymize** — Fake-but-plausible values (consistent within a session). Best for embeddings.
- **exclude** — Returns `sanitized_text: null` if any PII found. Drop the chunk entirely.
- **redact** — `***` stars. Destroys context. Use only for logs.

---

### Option 4: Batch processing for RAG pipelines

Sanitize many chunks at once before embedding:

```http
POST /api/v1/sanitize/batch
{
  "texts": ["chunk 1...", "chunk 2...", "chunk 3..."],
  "mode": "pseudonymize",
  "include_excluded": true
}
```

Each result includes `index`, `sanitized_text`, `excluded`, `pii_found`, and `risk_level`.
Filter on `excluded: true` to drop chunks that couldn't be safely sanitized.

---

### Option 5: Upload a CSV or JSON file

```http
POST /api/v1/file
Content-Type: multipart/form-data

file=<your file>
mode=mask
columns=["ssn","name","email"]
```

Returns each row with the specified columns sanitized. Useful for preprocessing
Banner or Colleague data exports before analysis.

---

### Option 6: Conductor workflow task

Add to any workflow:

```json
{
  "name": "pii_sanitize_text",
  "taskReferenceName": "sanitize_notes",
  "type": "SIMPLE",
  "inputParameters": {
    "text": "${workflow.input.advisor_notes}",
    "policy": "ai_prompt"
  }
}
```

Output: `sanitize_notes.output.sanitized_text`, `sanitize_notes.output.excluded`, `sanitize_notes.output.risk_level`

See `workflows/pii_ai_preflight_gate.json` for a complete preflight gate sub-workflow.

---

### Option 7: n8n workflow

Import `n8n/pii_service_workflow.json` into n8n. Set the `PII_SERVICE_API_KEY` environment variable.
The workflow runs a preflight check and returns either the original text (if safe)
or a masked version (if PII was found).

---

## Risk levels

| Level | Examples | Default recommendation |
|---|---|---|
| LOW | Dates, URLs, IP addresses | Safe to send |
| MEDIUM | Names, locations, FERPA markers | Consider masking |
| HIGH | Email, phone, student ID, disability info | Mask before sending |
| CRITICAL | SSN, credit card, bank account, immigration status | Do not send without sanitizing |

---

## Schema profiles

When processing records from Banner, Colleague, Salesforce, or Ethos, use a schema profile
to get field-name-aware detection. Pass the profile name in your request and the service
will treat specific field names as higher-confidence signals for the corresponding entity type.

Available profiles: `banner_student`, `colleague_person`, `salesforce_contact`, `ethos_person`, `n8n_generic`, `conductor_ethos`

---

## Service URL

- Production: `https://du-int.doane.edu/prod/pii-service`
- Local dev: `http://localhost:5900`

---

## Authentication

Production requires an API key:
```
Authorization: Bearer <key>
```
or:
```
X-API-Key: <key>
```

Contact the AI platform team for a key. Local development runs without auth by default.
