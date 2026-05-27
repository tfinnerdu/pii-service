# pii-service User Guide

pii-service is Doane University's AI safety layer. Before any text goes to an AI model,
an embedding index, a log file, or an external export, pii-service detects and removes
or replaces personal information so the right data stays inside the institution.

All processing happens locally inside Doane's infrastructure. Text never leaves the
machine or the cluster.

---

## Table of Contents

1. [Accessing the Service](#accessing-the-service)
2. [The Header Bar](#the-header-bar)
3. [Tab: Scan & Sanitize](#tab-scan--sanitize)
4. [Tab: Explain](#tab-explain)
5. [Tab: Policy](#tab-policy)
6. [Tab: File Upload](#tab-file-upload)
7. [Tab: Record / Schema](#tab-record--schema)
8. [Tab: Rules](#tab-rules)
9. [Sanitization Modes](#sanitization-modes)
10. [Named Policies](#named-policies)
11. [Risk Levels](#risk-levels)
12. [Entity Types Reference](#entity-types-reference)
13. [Schema Profiles](#schema-profiles)
14. [Direct API Use](#direct-api-use)
15. [Authentication](#authentication)

---

## Accessing the Service

| Environment | URL |
|---|---|
| Local development | `http://localhost:5900/ui` |
| Network (same LAN) | `http://<your-ip>:5900/ui` |
| API docs (Swagger) | `http://localhost:5900/swagger` |
| Health check | `http://localhost:5900/api/v1/health` |

The dev console (`/ui`) is automatically available when no API key is configured
(local development). In production, set `UI_ENABLED=true` in your `.env` to force-enable
it alongside auth.

---

## The Header Bar

The header is always visible at the top of the console.

### Health Indicator (top right)

**How to use:** No action needed — it updates automatically every 30 seconds.

**What it shows:**
- **Green dot — "Presidio ready"**: The full detection engine (spaCy + Presidio) is loaded
  and operational. All entity types are available.
- **Yellow dot — "degraded (fallback spaCy)"**: Presidio loaded but is using a lighter spaCy
  model. Detection accuracy on names and locations may be reduced.
- **Red dot — "Presidio failed"**: The ML stack did not initialize. Regex-based patterns
  still work but NLP-based detection (PERSON, LOCATION) is unavailable.
- **Red dot — "unreachable"**: The service itself is not responding. Check that Python
  is running.

### API Docs link (top right)

**How to use:** Click "API Docs ↗" to open the Swagger UI in a new tab.

**What it does:** Opens the interactive OpenAPI documentation at `/swagger`. From there
you can read endpoint specifications, see request/response schemas, and execute live API
calls directly in the browser without writing any code.

---

## Tab: Scan & Sanitize

**Purpose:** The main workhorse tab. Paste any text, detect all PII in it, and get a
sanitized version back — all in one operation.

### Text to scan (input area)

**How to use:** Paste or type any text you want to check. There is no length limit shown
in the UI, but the service enforces a configurable maximum (default 100,000 characters).

**What it does:** This is the raw input that gets scanned. The original is preserved
for side-by-side comparison in the results — it is never modified in place.

### Mode (dropdown)

**How to use:** Select the sanitization behavior you want before clicking the button.
Default is `mask`.

**What it does:** Controls how detected PII is replaced in the sanitized output.

| Mode | What replaces PII | Best used for |
|---|---|---|
| `mask` | `[ENTITY_TYPE]` token (e.g., `[US_SSN]`) | LLM prompts — preserves readable structure |
| `pseudonymize` | Fake but plausible value (e.g., a different name, a fake SSN) | Embeddings — preserves semantic similarity |
| `redact` | `***` asterisks | Application logs — maximum obscurity |
| `exclude` | Returns `null` if any PII is found; the whole chunk is dropped | RAG pipelines — prevents PII from entering vector stores |

See [Sanitization Modes](#sanitization-modes) for full detail.

### Policy (optional dropdown)

**How to use:** Leave blank to use only the Mode you selected. Select a named policy to
let the policy override the mode and apply pre-configured blocking rules.

**What it does:** When a policy is selected, the scan runs the policy's rules first:
- **Blocked entities** (e.g., SSN under `ai_prompt`) cause the entire text to be excluded
  regardless of mode.
- **Pass-through entities** (e.g., DATE_TIME) are ignored by the policy.
- **Remaining entities** are sanitized using the policy's default mode.

The policy takes precedence over the Mode dropdown when both are set.

See [Named Policies](#named-policies) for details on each policy.

### Correlation ID (optional text field)

**How to use:** Enter any string you use to identify this request in your own system
(e.g., a Banner PIDM, a workflow run ID, a ticket number). Leave blank if not needed.

**What it does:** The correlation ID is echoed back in the API response and recorded in
the audit log. Use it to link pii-service events to records in your own system without
exposing PII in the log.

### Scan & Sanitize button

**How to use:** Click after filling in the text and selecting a mode. The button shows
a spinner while the service is working and is disabled to prevent double-submission.

**What it does:** Fires two simultaneous API calls:
1. `POST /api/v1/scan` — detects all PII and returns hit positions and scores.
2. `POST /api/v1/sanitize` (or `/api/v1/policy/apply` if a policy is selected) — returns
   the sanitized text.

### Results panel

After the button completes, the right side of the screen shows:

**Stats bar** — A summary row showing:
- `Risk:` — The highest risk level among all detected entities (LOW / MEDIUM / HIGH / CRITICAL).
- `Hits:` — Total number of PII detections.
- `Mode:` — The mode that was applied.
- `Corr ID:` — The correlation ID you entered (if any).
- `sandbox` badge — Appears if the service is running in sandbox mode (no real scanning).

**Original panel** — The input text with each detected PII span highlighted in a color
matching its risk level. Hover over any highlight to see the entity type and confidence
score. Entity type tags are listed below the text.

**Sanitized panel** — The output text after sanitization. If the text was excluded
(mode=exclude or a policy blocked it), a red "EXCLUDED" badge appears instead of text.

**Hit details table** — Lists every detection with:
- Entity type
- Character positions (start–end)
- Risk level badge
- Confidence score (0.0–1.0)

---

## Tab: Explain

**Purpose:** Understand exactly why each piece of text was flagged — which pattern
matched, which recognizer caught it, and what context words boosted the score.
Useful for tuning, debugging false positives, and verifying detection accuracy.

### Text to explain (input area)

**How to use:** Paste the text you want to analyze. Works best with text you suspect
contains PII or that produced unexpected results on the Scan tab.

### Explain Detections button

**How to use:** Click to run the analysis. The button shows a spinner while working.

**What it does:** Calls `POST /api/v1/explain`, which runs Presidio at full verbosity
and returns the internal metadata for every detection — the specific regex pattern that
matched, the recognizer class that produced the hit, and the context words that were
present to boost confidence.

### Results panel

**Stats bar** — Shows total hit count and text character length.

**Highlighted text panel** — Same color-coded highlighting as the Scan tab, so you can
see exactly which spans were flagged.

**Detection breakdown table** — One row per hit with:
- **Entity Type** — What kind of PII was detected.
- **Risk** — Risk level badge.
- **Score** — Presidio confidence score (0.0–1.0). Hits must exceed the service's
  configured threshold (default 0.5) to be returned.
- **Recognizer** — The class name of the recognizer that produced the hit
  (e.g., `UsSsnCustomRecognizer`, `Presidio:PERSON`).
- **Pattern** — The specific regex pattern name that matched
  (e.g., `ssn_dashed`, `doane_d_prefix`). Blank for Presidio NLP-based detections.
- **Context Words** — Context keywords that were present near the hit. Presidio uses
  these to boost the confidence score above the base pattern score.

---

## Tab: Policy

**Purpose:** Apply a named policy to text without manually configuring modes and
exclusions. Policies encode the correct defaults for a specific data-handling context
(AI calls, embeddings, logs, exports, etc.).

### Text (input area)

**How to use:** Paste the text you want to process under the chosen policy.

### Policy (dropdown)

**How to use:** Select the policy that matches your processing context. The dropdown
shows the policy name and a short description. It defaults to the first real policy
(skipping the blank option).

**Available policies:**

| Policy | Use when |
|---|---|
| `ai_prompt` | Before sending text to Claude, GPT, or any external LLM |
| `embedding` | Before creating vector embeddings for RAG pipelines |
| `log_safe` | Before writing text to application logs |
| `export_internal` | Before including data in internal Doane reports |
| `export_external` | Before sending any data outside the institution |
| `ferpa_strict` | Zero tolerance — highest-sensitivity FERPA records |
| `analytics` | Aggregate dashboards where individual identifiers are not needed |

See [Named Policies](#named-policies) for full per-policy detail.

### Apply Policy button

**How to use:** Click after selecting text and a policy.

**What it does:** Calls `POST /api/v1/policy/apply`. The service scans the text, applies
the policy's blocking rules, and then sanitizes the remainder using the policy's default
mode. Returns the result in a single operation.

### Results panel

**Stats bar** — Shows:
- `Policy:` — The policy that was applied.
- `Risk:` — Highest risk level found.
- `Action:` — What the policy did: `none` (no PII), `masked`, `redacted`,
  `pseudonymized`, or `excluded_by_policy`.
- `Passed:` — Whether the text is safe to use in this context. `✓ yes` means it went
  through (possibly sanitized). `✗ no` means it was blocked entirely.

**Blocked entities panel** — If the policy blocked the text, shows which entity types
triggered the block (e.g., `US_SSN`, `IMMIGRATION_STATUS`).

**Output panel** — The sanitized text if the policy passed, or a red "EXCLUDED — dropped
by policy" badge if it was blocked.

---

## Tab: File Upload

**Purpose:** Sanitize an entire file — CSV, TSV, JSON, JSONL, TXT, PDF, DOCX, or XLSX
— row by row or page by page. Useful for preprocessing Banner/Colleague exports before
analysis, or scrubbing uploaded documents before storage.

### File drop zone

**How to use:** Click the drop zone to open a file browser, or drag a file directly
onto the zone. The zone highlights when a file is dragged over it. After selecting a
file, the zone shows the file name and size.

**Accepted formats:** `.csv`, `.tsv`, `.json`, `.jsonl`, `.txt`, `.pdf`, `.docx`, `.xlsx`

**Size limits:** Configurable via `FILE_SIZE_LIMIT_MB` (default 10 MB) and
`FILE_ROW_LIMIT` (default 10,000 rows/pages).

**What each format does:**
- **CSV / TSV** — Sanitizes specified columns (or all string columns) row by row.
- **JSON** — Expects a top-level array of objects. Sanitizes specified fields per record.
- **JSONL** — Same as JSON, one record per line.
- **TXT** — Treats the entire file as a single text block and sanitizes it.
- **PDF** — Extracts text page by page and sanitizes each page.
- **DOCX** — Extracts paragraphs and sanitizes each one.
- **XLSX** — Reads the active sheet, uses the first row as headers, sanitizes each data row.

### Mode (dropdown)

**How to use:** Select the sanitization mode. Same options as the Scan tab (`mask`,
`pseudonymize`, `redact`). `exclude` is not shown here — use the API directly if you
need per-row exclusion.

### Columns (optional text field)

**How to use:** Enter column names separated by commas (e.g., `name,ssn,email`).
Leave blank to process all string-valued columns.

**What it does:** Restricts sanitization to only the named columns. Non-string columns
(numbers, dates) always pass through unchanged. Useful when you know exactly which
fields contain PII and want to avoid false positives on fields like ID numbers that
should be preserved.

### Process File button

**How to use:** Enabled only after a file is selected. Click to upload and process.
Large files may take several seconds.

**What it does:** Sends the file via `POST /api/v1/file` (multipart form). The service
reads, parses, sanitizes, and returns all rows in a single response.

### Results panel

**Stats bar** — Shows:
- `Type:` — Detected file format (csv, json, pdf, etc.).
- `Total rows:` — Number of rows, records, or pages processed.
- `With PII:` — How many rows contained at least one PII hit (highlighted in red).
- `Excluded:` — How many rows were dropped (only nonzero in exclude mode).

**Results table** — Shows the first 50 rows (up to the limit). Each row includes:
- Row index
- PII badge (HIGH = PII found, LOW = clean)
- Sanitized content (pretty-printed JSON for structured files, raw text for TXT/PDF/DOCX)

---

## Tab: Record / Schema

**Purpose:** Sanitize a single structured JSON record field by field, with optional
schema-aware detection. Use this when your data comes from Banner, Colleague, Salesforce,
or another ERP and you want the service to understand field names as context clues.

### JSON record (input area)

**How to use:** Paste a JSON object (not an array). Example:
```json
{
  "SPRIDEN_LAST_NAME": "Smith",
  "SPBPERS_SSN": "123-45-6789",
  "GPA": 3.5
}
```

**What it does:** Each string field in the object is scanned independently. Non-string
fields (numbers, booleans, nulls) pass through unchanged.

### Schema profile (dropdown)

**How to use:** Select the profile matching your data source, or leave blank for
schema-agnostic detection.

**What it does:** When a schema is selected, the service uses field name hints to boost
detection confidence. For example, under the `banner_student` schema, a field named
`SPBPERS_SSN` is treated as a strong signal for `US_SSN` even if the value alone would
score below the confidence threshold.

**Available profiles:**

| Profile | Use for |
|---|---|
| `banner_student` | Ellucian Banner student/person records |
| `colleague_person` | Ellucian Colleague person records |
| `salesforce_contact` | Salesforce Contact and Lead objects |
| `ethos_person` | Ethos Integration person payloads |
| `n8n_generic` | n8n workflow generic person payloads |
| `conductor_ethos` | Conductor + Ethos person records |

### Mode (dropdown)

**How to use:** Select the sanitization mode (`mask`, `pseudonymize`, `redact`, `exclude`).

### Process Record button

**How to use:** Click after entering a valid JSON record.

**What it does:** Calls `POST /api/v1/process` with `input_type: record`. The service
sanitizes each string field and returns the sanitized record alongside a list of any
excluded fields.

### Results panel

**Stats bar** — Shows:
- `Schema:` — The schema profile applied (or `none`).
- `Mode:` — The sanitization mode used.
- `Changed fields:` — Count of fields whose value was modified (highlighted in orange).
- `Excluded:` — Fields that were dropped (only shown when exclude mode blocked a field).

**Side-by-side diff** — The original record and sanitized record displayed as formatted
JSON, with changed field names highlighted in orange and changed values in red/dim.
Fields that were not changed appear normally in both panels.

---

## Tab: Rules

**Purpose:** Inspect the full set of detection rules in place — every regex pattern,
policy configuration, and Presidio built-in. Also provides a quick-test tool to verify
that a specific pattern is working as expected without leaving the console.

This tab loads its data on first click (lazy-loaded). If the service was just restarted,
allow a few seconds for Presidio to initialize before opening the tab.

---

### Quick Test section (left card)

#### Text to test (input area)

**How to use:** Paste any text you want to run through the full detection engine.
Good for testing edge cases: `111-11-1111`, `D1234567`, `jsmith@doane.edu`.

#### Filter by entity (dropdown)

**How to use:** Leave blank to see all detections. Select a specific entity type
(e.g., `US_SSN`, `STUDENT_ID`) to filter the results to only that type.

**What it does:** The filter is applied client-side to the results from
`POST /api/v1/explain`. It does not change what the service scans — it only changes
what is displayed. This lets you verify a specific recognizer without noise from other
types.

#### Test Detection button

**How to use:** Click after entering text. Results appear on the right.

**What it does:** Calls `POST /api/v1/explain` and displays a highlighted view of the
text plus a breakdown table showing entity type, confidence score, recognizer name,
pattern name, and context words for every hit.

#### Quick test results panel

- **Stats bar** — Hit count and active filter (if any).
- **Highlighted panel** — Text with PII spans color-coded by risk.
- **Detection breakdown table** — Same format as the Explain tab: entity type, score,
  recognizer, pattern name, context words.

---

### Rules content section (below Quick Test)

Loaded automatically when you open the Rules tab. Three sections:

#### Policies

Displays a card for each named policy showing:
- **Policy name** and **default mode** badge.
- **Description** — The full plain-English description of when to use this policy.
- **Blocks** (red tags) — Entity types that trigger outright rejection. If any of these
  are detected, the text is excluded entirely regardless of mode.
- **Passes** (green tags) — Entity types the policy ignores (allows through without
  scanning or sanitizing).
- **exclude any PII** badge — Shown for `ferpa_strict`: any PII at all causes exclusion.

#### Custom Recognizers

Expandable cards for every custom regex-based recognizer. Click any recognizer to
expand it and see its full pattern table.

Each card header shows:
- Entity type tag
- Recognizer class name
- Pattern count

Expanded view shows a table with one row per pattern:
- **Pattern name** — The internal identifier (e.g., `ssn_dashed`, `doane_d_prefix`).
- **Score** — Base confidence score assigned when this pattern matches. Green = high
  (0.75+), orange = medium (0.40–0.74), purple = low (<0.40). A low base score
  requires context words nearby to reach the detection threshold.
- **Regex** — The actual regular expression. Monospaced, word-wrapped.

Below the table, **Context words** — keywords that boost this recognizer's score when
found near a match. For example, the SSN recognizer's score increases if the word
"social" or "ssn#" appears nearby.

#### Presidio Built-ins

A table listing every Presidio built-in entity type that is active but not overridden
by a custom recognizer. Shows the entity name and the context words configured to
boost its detection in field-hint scenarios.

---

## Sanitization Modes

| Mode | Output format | Effect on meaning | Best use |
|---|---|---|---|
| `mask` | `[ENTITY_TYPE]` | Structured token — readable, clearly marked | LLM prompts, most API calls |
| `pseudonymize` | Plausible fake value | Preserves semantic similarity | Vector embeddings, analytics |
| `redact` | `***` | Completely destroys the value | Application logs |
| `exclude` | `null` / chunk dropped | Removes the entire text if any PII found | RAG chunk filtering |

**mask** is the default and the safest choice when you are unsure. It keeps the text
readable and clearly signals where PII was removed.

**pseudonymize** generates deterministic fakes (same input always produces the same
fake, within a process lifetime). Names become different plausible names, SSNs become
different valid-format SSNs. Useful when downstream systems need realistic-looking data.

**redact** replaces with stars. It is the most destructive mode — the resulting text
loses all structural meaning around the redacted value. Use only for logs where
readability does not matter.

**exclude** is binary: any PII found means the entire chunk is dropped
(`sanitized_text: null`, `excluded: true`). Use at the entry point of a RAG pipeline
to prevent any PII from entering a vector store.

---

## Named Policies

Policies are pre-configured bundles of mode + block list + pass-through list designed
for a specific processing context. Use a policy instead of a mode when you want
consistent, auditable behavior that does not require each caller to configure rules.

### `ai_prompt`
**Use:** Before sending text to Claude, GPT, or any external generative AI model.

Masks personal identifiers. Blocks SSN, financial accounts, ITIN, passport, driver's
license, immigration status, and crypto — these must never reach an external model.
Dates, URLs, and IP addresses pass through (usually needed for context in prompts).

### `embedding`
**Use:** Before creating vector embeddings for pgvector, Pinecone, or any RAG pipeline.

Pseudonymizes personal data to preserve semantic similarity in the embedding space.
Excludes chunks containing FERPA markers, immigration status, financial data, or
disability accommodations — these create a retrieval risk if stored in a vector index
that may be queried by an AI model.

### `log_safe`
**Use:** Before writing any text to application logs.

Redacts all PII with `***`. Nothing personal belongs in log files, which are often
stored in less-controlled systems (Splunk, CloudWatch, disk). Applies to all entity
types with no exceptions.

### `export_internal`
**Use:** Before including data in internal Doane reports, dashboards, or data files
shared within the institution.

Masks personal identifiers. Allows institutional email (`@doane.edu`) and dates to pass
through. Blocks SSN, financial accounts, ITIN, passport, and immigration status.

### `export_external`
**Use:** Before any data leaves the institution (vendor reports, shared datasets,
external partners).

The most restrictive non-zero-tolerance policy. Blocks a broad set of HIGH and CRITICAL
entity types including email, phone, student ID, DOB, and all financial and health data.
Pseudonymizes anything that passes through.

### `ferpa_strict`
**Use:** Highest-sensitivity FERPA contexts — financial aid records, disciplinary files,
disability records, counseling notes.

Zero tolerance: if any PII of any kind is detected, the entire chunk is dropped.
There is no sanitization — the chunk is simply excluded from the pipeline. Use when
the cost of inadvertent disclosure is unacceptable and partial data is preferable to
no data.

### `analytics`
**Use:** Aggregate analytics, dashboards, and statistical reporting where individual
identifiers are not needed.

Pseudonymizes personal data to preserve statistical patterns. Blocks financial and
health data. Allows dates, URLs, and location names through (needed for aggregate
trends and geographic reporting).

---

## Risk Levels

Every detected entity is assigned a risk level based on the sensitivity of that entity
type, regardless of context.

| Level | Color | Examples | Default guidance |
|---|---|---|---|
| LOW | Green | Dates, URLs, IP addresses | Generally safe; context-dependent |
| MEDIUM | Orange | Names, locations, FERPA markers, email | Consider masking before sharing |
| HIGH | Red | Phone, student ID, DOB, disability, veteran status | Mask before sending outside the institution |
| CRITICAL | Purple | SSN, credit card, bank account, immigration status | Never send without sanitizing |

The risk level shown in the stats bar is always the **highest** level among all hits.
A single CRITICAL hit makes the whole text CRITICAL even if all other hits are LOW.

---

## Entity Types Reference

### Standard PII (Presidio built-ins)

| Entity | Description | Risk |
|---|---|---|
| `PERSON` | Full names detected by NLP | MEDIUM |
| `EMAIL_ADDRESS` | Any email address | HIGH |
| `PHONE_NUMBER` | US and international phone numbers | HIGH |
| `US_SSN` | Social Security Numbers (dashed, spaced, dotted, or bare 9 digits) | CRITICAL |
| `US_ITIN` | Individual Taxpayer Identification Numbers | CRITICAL |
| `US_PASSPORT` | US passport numbers | CRITICAL |
| `US_DRIVER_LICENSE` | US driver's license numbers | HIGH |
| `US_BANK_NUMBER` | Bank account numbers | CRITICAL |
| `CREDIT_CARD` | Credit and debit card numbers | CRITICAL |
| `IBAN_CODE` | International bank account numbers | CRITICAL |
| `DATE_TIME` | Dates and times | LOW |
| `LOCATION` | Addresses, cities, places detected by NLP | MEDIUM |
| `IP_ADDRESS` | IPv4 and IPv6 addresses | LOW |
| `URL` | Web addresses | LOW |
| `CRYPTO` | Cryptocurrency wallet addresses | CRITICAL |
| `NRP` | Nationalities, religious, and political groups | MEDIUM |
| `MEDICAL_LICENSE` | NPI numbers, DEA registration numbers | HIGH |

### Education-specific (custom recognizers)

| Entity | Description | Risk |
|---|---|---|
| `STUDENT_ID` | 5–9 digit numeric institutional IDs (Doane's canonical 7-digit form with leading zeros, plus peer-institution variations) and single-letter-prefixed external-system IDs (`S1234567`, `A1234567`). Low base score; context words like "id", "student", "banner", "colleague" boost detection. | HIGH |
| `DOANE_EMAIL` | `@doane.edu` addresses (tagged separately from generic email) | HIGH |
| `DATE_OF_BIRTH` | Dates in DOB context (MM/DD/YYYY, YYYY-MM-DD, written month) | HIGH |
| `FERPA_MARKER` | FERPA-protected record types: "GPA", "transcript", "financial aid", "academic probation", etc. | MEDIUM |
| `FAFSA_ID` | FAFSA application numbers, FSA IDs, ISIR references, EFC amounts | HIGH |
| `FINANCIAL_AID_AWARD` | Named federal aid awards with dollar amounts (Pell Grant, Direct Loan, etc.) | HIGH |
| `STUDENT_ACCOUNT_ID` | TouchNet, CashNet, and SAR payment/transaction IDs | HIGH |
| `FINANCIAL_ACCOUNT` | ACH routing numbers, bank account numbers in financial context | CRITICAL |
| `IMMIGRATION_STATUS` | Visa types (F-1, J-1, DACA), SEVIS IDs, I-20, I-94, DS-2019 | CRITICAL |
| `DISABILITY_ACCOMMODATION` | ADA/504 accommodation letters, IEP references, specific disability mentions | HIGH |
| `VETERAN_STATUS` | GI Bill chapters, VA benefit amounts, DD-214, deployment references | HIGH |
| `HIPAA_MARKER` | Health and mental health record types, PHI references, medication, diagnosis | HIGH |
| `IRB_PROTOCOL` | Institutional Review Board protocol numbers | HIGH |
| `TITLE_IX_CASE_ID` | Title IX case and complaint identifiers | CRITICAL |
| `LICENSE_PLATE` | Vehicle license plate numbers (low base score, requires context) | MEDIUM |
| `MEDICAL_LICENSE` | NPI/DEA numbers in medical context (supplements Presidio built-in) | HIGH |

---

## Schema Profiles

Schema profiles make detection field-name-aware. When a profile is applied, field names
like `SPBPERS_SSN` are used as a strong context signal for `US_SSN` — even if the value
alone would score below the detection threshold.

Use profiles via the Record / Schema tab in the UI or via `schema` in
`POST /api/v1/process`.

| Profile | Source system |
|---|---|
| `banner_student` | Ellucian Banner — SPRIDEN, SPBPERS, SGBSTDN tables |
| `colleague_person` | Ellucian Colleague — person and student entity |
| `salesforce_contact` | Salesforce Contact and Lead standard fields |
| `ethos_person` | Ethos Integration person API payload |
| `n8n_generic` | n8n workflow generic person data shape |
| `conductor_ethos` | Conductor + Ethos combined person payload |

Custom profiles can be added via a `PII_CONFIG_FILE` JSON file without restarting.
See `POST /api/v1/schemas` for the current profile list.

---

## Direct API Use

The dev console covers the most common operations, but the full API surface is available
for direct integration.

### Key endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/health` | Liveness check (no auth, safe for K8s probes) |
| GET | `/api/v1/health/deep` | Readiness check — verifies Presidio + dependency status |
| GET | `/metrics` | Prometheus scrape endpoint |
| GET | `/api/v1/entities` | All detectable entity types |
| GET | `/api/v1/policies` | Named policy catalog |
| GET | `/api/v1/recognizers` | Pattern specs for all custom recognizers |
| GET | `/api/v1/schemas` | Available schema profiles |
| GET | `/api/v1/stats` | In-process telemetry (request counts, entity counts, etc.) |
| GET | `/api/v1/keys` | List active API key names (never values) |
| POST | `/api/v1/scan` | Detect PII, return hits (no sanitization) |
| POST | `/api/v1/scan/structured` | Scan specific fields in a JSON record |
| POST | `/api/v1/scan/ocr` | Scan OCR output (per-page with confidence scores) |
| POST | `/api/v1/sanitize` | Detect and sanitize a single text |
| POST | `/api/v1/sanitize/batch` | Sanitize a list of texts |
| POST | `/api/v1/sanitize/structured` | Sanitize specific fields of a JSON record |
| POST | `/api/v1/preflight` | AI safety check with recommendation |
| POST | `/api/v1/policy/apply` | Apply a named policy (single text or batch) |
| POST | `/api/v1/process` | Generic entry point — text, record, or batch with optional policy and schema |
| POST | `/api/v1/file` | Upload CSV/TSV/JSON/JSONL/TXT/PDF/DOCX/XLSX for sanitization |
| POST | `/api/v1/explain` | Per-hit detection breakdown (recognizer, pattern, context) |
| POST | `/api/v1/stats/reset` | Reset in-memory telemetry counters |
| POST | `/api/v1/config/reload` | Hot-reload config + API keys without restart |
| POST | `/api/v1/keys/generate` | Generate a secure named API key |

### Quick examples

**Scan only (no sanitization):**
```http
POST /api/v1/scan
Content-Type: application/json

{ "text": "Student D1234567, SSN 111-11-1111" }
```

**Sanitize with mask:**
```http
POST /api/v1/sanitize
Content-Type: application/json

{ "text": "Student D1234567, SSN 111-11-1111", "mode": "mask" }
```

**Apply a policy:**
```http
POST /api/v1/policy/apply
Content-Type: application/json

{ "policy": "ai_prompt", "text": "Advising notes for student D1234567..." }
```

**Process a Banner record:**
```http
POST /api/v1/process
Content-Type: application/json

{
  "record": { "SPRIDEN_LAST_NAME": "Smith", "SPBPERS_SSN": "123-45-6789" },
  "schema": "banner_student",
  "mode": "mask"
}
```

**Batch sanitize for RAG:**
```http
POST /api/v1/sanitize/batch
Content-Type: application/json

{
  "texts": ["chunk one...", "chunk two..."],
  "mode": "pseudonymize",
  "include_excluded": false
}
```

Full request/response schemas are in the Swagger UI at `/swagger`.

---

## Authentication

**Local development:** Authentication is disabled by default when `API_KEY` is not set
in `.env`. The dev console and all API endpoints are open.

**Production:** All API endpoints (except `/api/v1/health`, `/api/v1/health/deep`, and `/metrics`)
require an API key sent as:
```
Authorization: Bearer <key>
```
or:
```
X-API-Key: <key>
```

**Generating a key:**
```http
POST /api/v1/keys/generate
Content-Type: application/json

{ "name": "n8n-prod", "prefix": "sk_n8n" }
```

The response includes the key (shown once — store it securely). Add it to `API_KEYS`
in `.env` and call `POST /api/v1/config/reload` to activate without restarting.

**Multiple keys:** Set `API_KEYS=name1:key1,name2:key2,...` to give each integration
its own named key. The name appears in audit logs so you know which system made each
request.

Contact the AI platform team to request a production key.
