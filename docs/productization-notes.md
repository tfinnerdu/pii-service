# Productization Notes — pii-service

Tracks **productization taxes**: Doane/Nebraska-specific values baked into
executable code rather than config. The "Path B" goal (Doane standards,
*University / Higher-Ed Agnostic Design*) is that a peer institution can deploy
this service by changing **config, not code**.

Each open item below is an **accepted, documented** tax — not a silent one.
Resolving them is a deliberate design decision, deferred pending sign-off.

---

## Open: institution-specific values in detection and pseudonymization

### 1. Detection recognizers — `pii_guard/recognizers.py`

`_RECOGNIZER_SPECS` hardcodes Doane-shaped detection patterns:

| Location | Hardcoded value | Institution assumption |
|---|---|---|
| `recognizers.py:81` | `doane_d_prefix` → `\bD\d{7}\b` (`STUDENT_ID`) | Doane's Banner student-ID format (D + 7 digits) |
| `recognizers.py:99` | `DOANE_EMAIL` → `@doane\.edu` | Doane's email domain |
| `recognizers.py:61-63` | `STUDENT_ACCOUNT_ID` → `TN-` / `CN-` / `SAR-` | TouchNet / CashNet vendor choice |

`PII_CONFIG_FILE` lets a peer institution **add** custom patterns, but the
built-in specs cannot be **disabled or overridden** — a peer with a different
ID format still pays for the Doane patterns firing.

### 2. Pseudonymization output — `pii_guard/guard.py`

`_generate_pseudo()` hardcodes output formats in executable logic — these are
not reachable through `PII_CONFIG_FILE` at all:

| Location | Hardcoded value | Institution assumption |
|---|---|---|
| `guard.py:626` | `STUDENT_ID` → 7-digit zero-padded numeric | Doane's actual ID shape (7 digits, leading zeros). Peer institutions with different digit lengths would need to override. |
| `recognizers.py:STUDENT_ID` | digit range `\d{5,9}` and context vocabulary | Range fits Doane + common peer-institution forms; vocabulary skews to higher-ed terms. Both belong in a tenant config eventually. |
| `guard.py:629` | `FAFSA_ID` → `NE-{6}` | **Nebraska** state prefix |
| `guard.py:682` | `STUDENT_ACCOUNT_ID` → `TN-{9}` | TouchNet prefix |

The pseudonym name/city pools *are* already config-overridable via
`PII_CONFIG_FILE` → `pseudo_pools`; only the format strings are stuck in code.

### 3. Baked-in identifiers

The `DOANE_EMAIL` entity type, `DOANE_RECOGNIZER_REGISTRY`, and the
`doane_d_prefix` pattern name are Doane-named API surface. Renaming them is a
breaking change for callers — note it, don't churn it. Lower priority.

---

## Proposed direction (not yet decided)

A config mechanism already exists (`PII_CONFIG_FILE` → `pii_guard/config.py`).
The standard warns against a second parallel tenant-config system, so the
recommendation is to **extend the existing one** rather than add a separate
`tenant_config.py`:

1. Make `_RECOGNIZER_SPECS` a default *seed* that `PII_CONFIG_FILE` can override
   and disable per-entity — not only append to.
2. Lift the `_generate_pseudo()` format strings (`D{7}`, `NE-`, `TN-`) into
   config keys, with the Doane values as defaults.
3. Treat the institution email domain (`doane.edu`) as a config value.

Doane defaults stay byte-for-byte identical — a peer institution swaps config,
not code. Rough effort estimate: ~1 week (config-schema design, recognizer
override semantics, and characterization tests covering both the Doane-default
config and a sample peer-tenant config).
