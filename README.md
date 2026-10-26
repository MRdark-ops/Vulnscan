# Lightweight Web Vulnerability Scanner (SQLi + XSS)

A course-safe, evidence-first **DAST** (Dynamic Application Security Testing)
scanner. Given one **explicitly authorized** target it crawls the same-host
attack surface, tests every parameter for **error- and boolean-based SQL
injection** (CWE-89) and **reflected, context-aware XSS** (CWE-79), persists
every finding with verifiable evidence to SQLite, and reports through a CLI, a
Flask dashboard, and self-contained HTML reports.

> **Ethics by construction.** No scan runs without explicit consent
> (`--i-am-authorized`) **and** a host-scope check (localhost / target host /
> allowlist). The gate fails closed. This tool is for systems you own or are
> authorized to test — the bundled lab app, DVWA, bWAPP — never third parties.
> Unauthorized scanning may be illegal.

---

## Install

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
python -m scanner version        # -> 1.2.0
```

## Quick start (against the bundled lab app)

```bash
# 1. start the intentionally-vulnerable benchmark app (localhost only)
python tests/vuln_app.py                 # serves http://127.0.0.1:5000/

# 2. scan it and generate a report
python -m scanner scan \
    --target http://127.0.0.1:5000/ \
    --i-am-authorized \
    --report reports/scan.html \
    --json   reports/scan.json

# 3. open the dashboard
python -m scanner serve                  # http://127.0.0.1:5050/

# 4. reproduce the evaluation metrics
python -m scanner evaluate
```

## Commands

| Command | Purpose |
|---|---|
| `scan`     | Scan an authorized target; optional `--report` / `--json`. |
| `report`   | (Re)generate the HTML report for a stored scan. |
| `serve`    | Run the Flask dashboard (binds `127.0.0.1`). |
| `evaluate` | Run a full scan on the lab app and print precision/recall/F1. |
| `version`  | Print the version. |

**Exit codes:** `0` ok · `1` runtime error · `2` scope/consent refused · `3` config error.

## Dashboard UI

`python -m scanner serve` starts a localhost-bound interactive dashboard at
`http://127.0.0.1:5050/`. It is a small single-page frontend (vanilla JS, no
build step, no framework) backed by a JSON API that calls the **same**
`ScanEngine` as the CLI:

- **Scan history** — list of past scans with status, findings, endpoints,
  requests, duration, and timestamp.
- **New scan** — enter a target, set crawl/rate/deadline options, and tick the
  mandatory authorization box. Consent is enforced server-side (unchecked ⇒ 400,
  no scan row). The scan runs through the shared engine and the result appears
  immediately.
- **Scan detail** — summary stat cards, severity/type breakdown, and a
  filterable/searchable findings table with expandable evidence (payload,
  reflection context, CWE, remediation), plus the discovered attack surface.
- **Download** — links to the self-contained HTML report and the JSON findings.

Evidence is rendered with `textContent` (never `innerHTML`), so a reflected-XSS
payload captured as evidence cannot execute in the dashboard. The dashboard
cannot bypass the CLI's consent, scope, or request-budget controls.

## Architecture (strict one-directional layers)

```
Interfaces     : CLI (cli.py) · Flask dashboard (webapp/)        — thin callers
Orchestration  : ScanEngine — budget, events, dedupe-before-write
Discovery      : Crawler (same-host BFS) → Endpoint/Parameter surface
Detection      : Detector registry — SQLiDetector · XSSDetector
Infrastructure : HttpClient (rate limit, retries, truncation, budget hook)
                 Storage (SQLite WAL) · Evidence helpers · Scope/ethics gate
```

The dashboard and the CLI call the **same** `ScanEngine`. Detectors receive one
`(endpoint, parameter)` at a time and never crawl, so they are unit-testable in
isolation. All response comparison goes through `evidence.py`, which normalizes
away volatile tokens (CSRF, session IDs, timestamps) **before** any similarity
math — a detector cannot skip it.

## Detection methods

- **SQLi — error-based:** inject minimal quote/syntax breakers; match the
  response against DB error signatures across 6 families (MySQL, PostgreSQL,
  SQLite, MSSQL, Oracle, generic) → `HIGH`, confidence `0.90`, with the error
  snippet as evidence.
- **SQLi — boolean-based (Δ-rule):** send TRUE/FALSE condition pairs; fire iff
  `ratio(baseline, true) ≥ θ` **and** `ratio(true, false) ≤ θ − Δ`
  (θ = 0.85, Δ = 0.10) on normalized bodies → `HIGH`, confidence `0.75`, with
  the three similarity ratios stored as evidence.
- **Reflected XSS — canary → context → proof:** inject a unique canary with
  metacharacters; classify the worst reflection context (script > attribute >
  text); if output is encoded, **no finding**; otherwise send one *inert*
  context-specific proof marker and confirm it reflects unencoded →
  confidence `0.85` (`HIGH` in script/attribute, `MEDIUM` in text). Raw
  metacharacters without a clean proof → `LOW` `0.60`, flagged manual review.

Detection probes are deliberately minimal — no stacked queries, UNION
extraction, DB-takeover payloads, or executing XSS payloads. The scanner
*detects and reports for remediation*; it does not exploit.

## Measured results (on the bundled lab app)

| Metric | Target | Measured |
|---|---|---|
| Precision | ≥ 0.90 | **1.00** |
| Recall | ≥ 0.80 | **1.00** |
| F1 | ≥ 0.85 | **1.00** |
| True-negative rate (`/safe-*`) | 100% | **100%** (0 findings) |
| Wall-clock | ≤ 60 s | **~5 s** |
| Unit + e2e tests | 100% green | **76 passed** |

Reproduce with `python -m scanner evaluate`.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

The suite covers config validation, budget/termination, the fail-closed scope
gate, the HTTP gateway (**including off-scope redirect blocking** and body
truncation), evidence math (normalization, Δ-rule edges, signature families),
crawler extraction/dedupe, storage CRUD under WAL, both detectors (mocked
responses), engine (event order, dedupe, partial-on-deadline), report escaping,
CLI exit codes, dashboard consent enforcement, and the end-to-end accuracy
targets.

> Sample reports are in `reports/`.

## Responsible use

This project exists to help developers *find and fix* injection bugs in systems
they control. The fail-closed consent and scope gate are intentional. Do not
point it at systems you are not authorized to test.
