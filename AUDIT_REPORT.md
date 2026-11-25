# WhoisFreaks ↔ Swimlane Turbine Connector — Enterprise Production & Publication Audit

**Audited build:** `connector.yaml` version `1.0.0`, schema `connector/1`, template `python_311_definition_fips`
**Target platform:** Swimlane Turbine (SOAR)
**Endpoint family implemented:** Stream / bulk feeds only (`files.whoisfreaks.com`)
**Audit date:** 2026-11-24
**Auditor scope:** Source inspection + library test execution + behavioural reproduction. Platform tooling (`tsdk`, Docker, live API) was **not** available in this environment — those checks are marked *Blocked/Not Verified*, not passed.

---

## A. Executive Summary

The repository contains a Swimlane Turbine connector that ingests WhoisFreaks **stream/files** products: newly‑registered domains (gTLD/ccTLD) and threat feeds (phishing/malware/spam), plus a feed‑status action and an all‑in‑one `ingest_stream_feeds` orchestration action. The declarative Turbine manifests are clean and well‑structured, the status‑first date‑resolution contract is implemented, and a tidy, fully‑tested Python client library exists (16/16 unit tests pass).

However, the audit surfaced a **structural problem that invalidates most of the project's quality signals**, plus several confirmed functional defects and a platform‑fit/scope gap:

- **The tested code is not the shipped code.** The Docker image copies only `connector/` (`Dockerfile:67 COPY connector /app`). The entire `whoisfreaks_client/` + `pipeline/` + `destination/` library — the thing the 16 tests exercise — is **excluded from the runtime image and never imported** by the runner. The code Turbine actually executes (`connector/src/runner_override.py`) has **zero test coverage** and lacks the retry/backoff/timeout logic the README and design docs attribute to the connector.
- **`HTTP 401 "Api record not found"` (the documented *end‑of‑feed* signal) is misclassified as a subscription/plan error** in both the shipped runner and the library. During normal bulk pagination this produces a misleading "Please upgrade your plans" error and causes `ingest_stream_feeds` to mark a feed `subscription_skipped` *after* it has actually ingested data.
- **Platform fit / scope:** Swimlane Turbine's core strength is real‑time, on‑demand enrichment inside playbooks. WhoisFreaks' **22 real‑time lookup operations** (whois, reverse/history, DNS, SSL, subdomains, IP geolocation, IP WHOIS, IP/domain security, ASN, availability, reputation, typosquatting) — the operations a SOC playbook actually calls — are **entirely absent**. Meanwhile the implemented bulk‑stream path does **not** scale cleanly inside Turbine's single‑output action model (`ingest_stream_feeds` accumulates every page in memory into one output).

**Enterprise readiness:** Not ready. **Publication readiness:** Not ready (and several marketplace gates could not be run here).

## B. Final Release Verdict

### ❌ NOT READY TO PUBLISH

Supported by concrete, reproduced evidence:

1. The shipped runtime (`runner_override.py`) is **untested** and is **missing the resilience** (retry, backoff, explicit timeouts) that the documentation claims the connector has. The 16 passing tests cover a library that is not packaged into the image. *(ARCH‑001)*
2. `HTTP 401` end‑of‑feed is treated as a subscription failure — breaking the normal pagination completion path and misreporting ingestion status. Reproduced. *(FUNC‑001)*
3. Checkpoint offset advances by *parsed* rows rather than rows the server returned, so any filtered row drifts the offset → duplicate or skipped records on resume, contradicting the "lossless" claim. Reproduced. *(FUNC‑002)*
4. Platform/scope: the real‑time lookup family (Swimlane's primary use case) is not implemented, and the bulk‑stream path has an unbounded in‑memory aggregation. *(FUNC‑005 / PERF‑001)*

These are release blockers independent of the numerical scores below. Marketplace certification gates (`tsdk connector validate/lint/build`, AppInspect‑equivalent, live‑API behaviour) **could not be executed in this environment** and remain unverified, which on its own precludes an unconditional "ready" verdict.

## C. Repository File Coverage

| Metric | Value |
|---|---|
| Relevant source/config/doc files | 24 (excluding `__pycache__`) |
| Fully inspected | 24 (100%) |
| Executed | Library test suite (16 tests) + 3 behavioural repros |
| Could not execute | `tsdk` validate/lint/build (not installed), Docker build (no daemon/`tsdk`), live API (no key — and out of scope), `runner_override.py` runtime (requires `connector_definition_runner` SDK, absent) |

**Inventory (inspected):**
`connector/connector.yaml`; `connector/config/assets/apikey.yaml`; `connector/config/actions/{get_feed_status, stream_nrd_gtld, stream_nrd_cctld, stream_threat_feed_phishing, stream_threat_feed_malware, stream_threat_feed_spam, ingest_stream_feeds}.yaml`; `connector/src/runner_override.py`; `whoisfreaks_client/{__init__,constants,errors,models,status,stream}.py`; `pipeline/orchestrator.py`; `destination/{__init__,adapter}.py`; `tests/{test_stream_client,test_status_client,test_orchestrator}.py`; `scripts/validate.sh`; `Dockerfile`; `requirements.txt`; `.gitignore`; `image/logo.png`; `README.md` + `docs/{README,MANUAL_TESTING_GUIDE,ARCHITECTURE_AND_CODE_FLOW,CODE_EXPLANATION,CHANGELOG.md.t}`.

**Coverage limitation:** behaviour of the Swimlane base `Runner` (auth‑header injection, `verify_ssl`/proxy wiring, default request timeout) cannot be confirmed without the `connector_definition_runner` SDK; items that depend on it are marked *Needs verification*.

---

## D. Architecture & Workflow Findings

### The two‑codebase split (root cause of most quality gaps)

There are two independent implementations of the same logic:

| | **Shipped at runtime** | **Tested, but not shipped** |
|---|---|---|
| Files | `connector/` (runner + YAMLs) | `whoisfreaks_client/`, `pipeline/`, `destination/` |
| Entry point | `RunnerOverride(Runner)` in `runner_override.py` | `WhoisFreaksStreamClient` / `IngestionOrchestrator` |
| In image? | **Yes** (`Dockerfile:67 COPY connector /app`) | **No** — not copied, not imported |
| Retry/backoff | **None** | Exponential backoff + jitter |
| Explicit timeouts | **None** (relies on base session) | 30 s |
| Unit tests | **0** | 16 (all pass) |

`grep` confirms `runner_override.py` imports only stdlib + `connector_definition_runner` (no `whoisfreaks_client`), and nothing under `connector/` references the root packages. So every claim grounded in the library ("retry with exponential backoff and jitter", "30 s timeout", "16 tests covering retry/checkpoints") does **not** describe the shipped connector.

### End‑to‑end workflow (as actually shipped — `runner_override.py`)

```
Playbook → Turbine → RunnerOverride.run(inputs, action_schema)
  ├─ get_feed_status            → super().run()  (base runner hits /v3.4/status)
  ├─ stream_* (single feed)     → _fetch_feed_status → _resolve_feed_date
  │                              → _execute_stream_request (SINGLE GET, no retry/timeout)
  │                              → _parse_records → {response_text, records_count, has_more}
  └─ ingest_stream_feeds        → _fetch_feed_status
                                 → for feed in enabled_feeds:
                                     loop pages (max_pages): _execute_stream_request → _parse_records
                                     accumulate ALL rows into all_records (in memory)
                                 → one JSON output {records:[...everything...], checkpoint}
```

**Workflow defects:** single‑GET with no retry/timeout; 401 end‑of‑feed misrouted to the subscription branch; non‑subscription HTTP errors ignored by the single‑feed path; unbounded in‑memory record accumulation in `ingest_stream_feeds`.

---

## E. Working Features

| Feature | Implementation | Verified status |
|---|---|---|
| `get_feed_status` action (manifest + routing to base runner) | `get_feed_status.yaml`, `runner_override.py:229` | Partial — routing correct; live call not run |
| Status‑first date resolution (window check + fallback to `last_update`) | `runner_override.py:58`, `status.py:73` | **Verified** (library tests + logic review) |
| Per‑feed enable/disable (separate actions + `enabled_feeds`) | all action YAMLs, `runner_override.py:163` | Verified (design) |
| 413 "upgrade your plans" handled gracefully, other feeds continue | `runner_override.py:116`, `orchestrator.py:173` | **Verified** (test `test_subscription_413_plan_error`, `test_orchestrator_multi_feed_run`) |
| Header‑only page → clean pagination stop | `runner_override.py:201`, `stream.py:273` | **Verified** (test `test_pagination_termination_header_only_page`) |
| Lossless CSV / plain‑text parsing (whois true/false) | `runner_override.py:87`, `stream.py:154/211` | Partial — see FUNC‑002/FUNC‑003 |
| Checkpoint `(date, offset)` emit + resume | `runner_override.py:217`, `orchestrator.py:130/165` | Partial — see FUNC‑002 |
| Library retry/backoff/jitter + typed errors | `stream.py:51` | **Verified in library** — but **not shipped** (ARCH‑001) |
| 16‑test unit suite | `tests/` | **Verified 16/16 pass** — but covers unshipped library |
| No hardcoded secrets; FIPS base; minimal deps | repo‑wide | Verified |

---

## F. Missing or Incomplete Features

### Essential (platform‑fit gap — tied to the stated scoping rule)

**FUNC‑005 — Entire real‑time lookup family absent.** Swimlane Turbine is a SOAR platform whose primary, well‑scaling workload is *on‑demand enrichment and response inside playbooks* (given an IP/domain/hash in a case, enrich it now). WhoisFreaks exposes 22 lookup operations on `api.whoisfreaks.com` that map 1:1 onto that workload, none of which are implemented:

`/v2.0/whois/live`, `/v2.0/whois/reverse`, `/v2.0/whois/history`, `/v2.0/bulkwhois/live`, `/v2.0/dns/live`, `/v2.0/dns/bulk/live`, `/v2.0/dns/historical`, `/v2.1/dns/reverse`, `/v1.0/ssl/live`, `/v1.0/subdomains`, `/v1.0/geolocation`, `/v1.0/ip-whois`, `/v2.0/security` (IP/domain reputation & abuse), `/v2.0/asn-whois`, `/v2.0/domain/availability`, `/v3.0/domain/typos`, domain reputation/discovery, `/v1.0/whoisapi/usage`.

Per the project's own scoping rule — *if the platform sustains the lookup family, implement it* — and because Turbine clearly sustains real‑time lookups at scale, these are **required**, not optional. A WhoisFreaks SOAR connector that cannot enrich an indicator in a playbook is missing its central use case. **Recommend P1 (feature build‑out).**

### Incomplete within the implemented (stream) family

- No actions for `expired`, `cleaned_expired`, `dropped`, `dropped_with_backlinks`, `cleaned_gtld/cctld`, or `database_updates/*` — the status schema advertises these windows (`get_feed_status.yaml`) but no stream action consumes them. Scope decision; document it. *(P2)*
- `ingest_stream_feeds` returns all records in a single output rather than emitting per‑page records consumable by a looping playbook — see PERF‑001.

### Stream‑at‑scale fit (the second half of the scoping rule)

Threat feeds (bounded, high‑value) are a reasonable Turbine fit. **Wholesale bulk NRD (millions of domains/day)** is a questionable fit for pushing as Swimlane records and, as implemented, does not scale (PERF‑001). If retained, it should be page‑oriented, volume‑documented, and filter‑first.

---

## G. Security Findings

| ID | Severity | Finding | Evidence |
|---|---|---|---|
| SEC‑001 | Low | `verify_ssl` / `http_proxy` honoring unverified in shipped path. Custom `_execute_stream_request`/`_fetch_feed_status` never pass `verify=`/proxies; they rely on the base `Runner` session. The library sets `verify=self.verify_ssl` explicitly, but the library isn't shipped. If the base session doesn't apply the asset `verify_ssl`, TLS verification could be silently on/ignored contrary to the asset setting. | `runner_override.py:48,115`; `apikey.yaml:18` vs `stream.py:66` |
| SEC‑002 | Low | Unpinned dependencies / no lockfile. `requirements.txt` uses `>=` ranges (`requests>=2.28.0`, `urllib3>=1.26.0`); no hashes/lockfile → non‑reproducible builds, supply‑chain drift. (Also: the runner uses neither directly — stdlib + SDK only — so the file is largely vestigial but is installed into the image.) | `requirements.txt`; `Dockerfile:43` |
| SEC‑003 | Low | Secret scan is a silent no‑op here. `validate.sh` guards the scan behind `git status`; this checkout is not a git repo, so Gate 4 is skipped while still printing "Secret scan passed." Pattern also excludes `tests/`, `scripts/`. | `validate.sh:56‑64` |
| SEC‑004 | Info | Downstream CSV‑injection consideration. Feed values (`domain`, `matched_pivots`) are attacker‑influenced strings stored verbatim into records; if later exported to spreadsheets they could carry formula‑injection payloads. Connector does not sanitize (reasonable — it shouldn't mutate data), but downstream export should neutralize leading `= + - @`. | `runner_override.py:104`; feed sample in memory |
| SEC‑005 (positive) | — | No hardcoded secrets found. API key is an asset `password` field delivered via `X‑API‑KEY` header; not logged. SSRF surface low: destination URL is operator‑set, endpoints fixed. Error logging truncates to `resp.text[:200]` and does not echo the key. | `apikey.yaml`; `runner_override.py:144` |
| SEC‑006 (privacy) | Info | NRD‑with‑WHOIS ingests registrant PII fields wholesale into Swimlane records. Redaction tokens ("REDACTED FOR PRIVACY") are preserved verbatim (not expanded) — good — but operators should be warned about PII/data‑retention when `nrd_whois=true`. | `stream.py:241`; memory WHOIS sample |

No command/shell/SQL/SPL/template injection paths exist (data flows only into CSV parsing and record fields). No unsafe deserialization, no `yaml.load`, no subprocess.

---

## H. Functional Bugs

**FUNC‑001 — `HTTP 401 "Api record not found"` (end‑of‑feed) misclassified as subscription error.**
*Severity: High · Priority: P1 · Confidence: Confirmed (reproduced).*
Affected: `runner_override.py:116` (shipped) and `stream.py:70` (library); documented as intended behaviour in `README.md:39`, `docs/README.md:39`, `docs/ARCHITECTURE_AND_CODE_FLOW.md:13`.
Per WhoisFreaks (status/stream contract + error sample in `memory/stream endpoints template.txt:65`), `401 "Api record not found"` means *offset beyond available data* = the normal pagination stop; `413` (not 401) means plan‑not‑covered. The connector lumps `401/403/413` together as subscription failures.
Reproduced:
```
fetch_page("malware", "2026-09-30", offset=4490557) →
  SubscriptionError(401): "Subscription plan limit (401): Api record not found..."
```
Impact: normal bulk pagination ends with a false "upgrade your plans" error; in `ingest_stream_feeds` the feed is marked `subscription_skipped` with an error message *after records were already ingested*, misreporting completion as a plan failure. Directly violates the explicit contract "handle `401 'record not found'` (offset beyond data)."
Fix: treat `401` + message `~ "record not found"` as clean end‑of‑feed (stop pagination, `is_end=True`, status `success`); reserve the subscription branch for `413` (and optionally `403`). Distinguish by message/body, not status alone.

**FUNC‑002 — Checkpoint offset advances by parsed rows, not rows returned; `len<limit` end‑detection.**
*Severity: Medium‑High · P1 · Confirmed (reproduced).*
Affected: `runner_override.py:201,209` (shipped) and `stream.py:273,297` (library). Offset advances `+= len(page_records)` after parse‑time filtering drops blank lines, `#` comments, and rows without a domain; and end‑of‑feed is inferred from `len(records) < limit`. A full server page containing any filtered row therefore (a) trips the "short page" early stop and (b) advances the resume offset short of the true cursor → **skipped or duplicated records** on the next run. Contradicts the "lossless, resumable" claim.
Reproduced: a 5‑line NRD page (blank + `#comment` among 3 domains, `limit=5`) parsed to 3 records and reported `is_end=True`.
Fix: track the number of rows the server returned (raw line/row count) for offset math and end detection, independent of post‑filter record count.

**FUNC‑003 — Unhandled `ValueError` on malformed `confidence` (library path).**
*Severity: Medium · P2 · Confirmed (reproduced).*
Affected: `stream.py:189` `float(conf_val)`; `orchestrator.py:173‑183` catches only `SubscriptionError`/`TransientError`. One non‑numeric `confidence` cell crashes the whole feed run with an uncaught `ValueError`, contradicting "lossless" / "controlled error on malformed data." (The shipped runner keeps values as strings, so it is not affected — but this is live code in the repo, tests, and docs.)
Reproduced: `confidence=HIGH` → `ValueError: could not convert string to float: 'HIGH'`.
Fix: guard the cast (`try/except`, keep raw string in `extra_fields`), or broaden the orchestrator handler and emit a parse warning per row.

**FUNC‑004 — Single‑feed actions ignore non‑subscription HTTP errors.**
*Severity: Medium‑High · P1 · Strong evidence (code trace).*
Affected: `runner_override.py:244‑257`. `run()` checks only `result.get('subscription_error')`, not `result.get('error')`. A `400` (invalid apikey/date) or `5xx` returns a dict with `error:True` + `error_message`, but `run()` falls through to parse `response_text` (`''` for JSON errors) → returns `records_count:0, has_more:false`. A playbook keying on `records_count`/`has_more` sees "empty feed," not a failure. Fix: surface `error` prominently (non‑200 `status_code`, explicit `error_message`) so playbooks can branch.

**FUNC‑006 — `max_pages` semantics contradictory / dead branch.**
*Severity: Medium · P2.*
`ingest_stream_feeds.yaml:41` documents "0 or null for single page," but `runner_override.py:158` coerces `max_pages = inputs.get('max_pages') or 1` (so `0→1`, single page — accidentally matching the doc), while the loop guard `runner_override.py:180 max_pages == 0 or pages_fetched < max_pages` would mean **unlimited** for 0 — an unreachable, contradictory branch. Fix: remove the dead `== 0` branch; use `None` for "all pages" if an unlimited mode is desired, and document it as such with the memory risks.

**FUNC‑007 — Status‑endpoint failure masked as "feed not available."**
*Severity: Medium · P2.* `_fetch_feed_status` swallows all errors to `{}` (`runner_override.py:49‑56`); a single‑feed action with no caller date then resolves to `(None, …)` and returns a benign `status_code:200` "Feed is not currently available." A status outage is indistinguishable from "no data." Fix: propagate a distinct, visible status‑fetch error.

---

## I. API & Data‑Quality Issues

- **Field pointers are correct.** `FEED_POINTERS`/`FEED_CONFIG` (`constants.py:14`, `runner_override.py:21`) match the live status document shape (`newly.gtld`, `newly.cctld`, `threat_feed.{phishing,malware,spam}`) in `memory/`. Verified.
- **Threat‑feed columns match** the documented schema (`domain, threat_type, confidence, first_seen, last_seen, is_seed, is_extrapolated, is_dropped, is_parked, parked_reason, matched_pivots`); unknown columns are preserved into `extra_fields`/record dicts — genuinely lossless there. Verified.
- **Boolean/flag fields kept as raw `t`/`f` strings** (`is_seed` etc.). Acceptable but downstream playbooks must not treat the empty string as `false` (missing vs false ambiguity). Document the encoding.
- **`confidence` typing is inconsistent across the two code paths:** library coerces to `float` (and can crash — FUNC‑003); the shipped runner leaves it a string. Downstream schema will see a string. Pick one and document it.
- **No ECS/CIM/observable normalization.** Output is a flat record (`domain, feed_name, feed_date, feed_type, confidence, observed_at, raw_attributes`). Fine for raw ingestion; for SOAR usability, map `domain`→observable, `threat_type`/`confidence`→indicator metadata so playbooks can pivot. *(Enhancement.)*

---

## J. Performance & Enterprise Scalability

**PERF‑001 — `ingest_stream_feeds` accumulates all records in memory into one action output.**
*Severity: Medium‑High · P1.* `runner_override.py:160,207,212,219‑221` builds `all_records` across every page of every feed and returns it in a single JSON blob. Turbine actions return one bounded output per run; with large `max_pages` (or a future "all pages" mode) over million‑row feeds this is an OOM/timeout and a pathological single record. The scalable primitive is the per‑page `stream_*` action (fetch one page + return a checkpoint; let a looping playbook drive pagination). Recommend: have `ingest_stream_feeds` emit per‑page batches (or cap hard and document), and position the single‑page actions as the scale path.

**Platform scale assessment (per the scoping rule):**
- *Real‑time lookups:* Turbine scales these well (bounded request/response per playbook step). **Right fit — currently missing.**
- *Threat‑feed streams:* bounded daily volume, high value → **reasonable fit.**
- *Bulk NRD streams:* millions of rows/day as Swimlane records is at the edge of what a case‑management SOAR should store; feasible only as paginated, filtered, scheduled ingestion — and not via the current in‑memory aggregation.

No live benchmarks were run (no API key / not authorized). Figures above are design‑level, labelled as such.

---

## K. Platform‑Specific Compatibility (Swimlane Turbine)

- Manifest set is coherent: `connector.yaml` (vendor/product/name/schema/version/build template), `apikey.yaml` asset with `meta.security {type: apiKey, name: X-API-KEY, in: header}` and `asset_url_key: url`, seven `action/1` manifests, `runConfig.inputs.type: stdin`, FIPS Python 3.11 build template, Apache‑2.0, `image/logo.png` present. Looks publish‑shaped.
- **Not verified here (no `tsdk`/Docker):** `tsdk connector validate`, `tsdk connector lint`, `tsdk connector build`, image signing/save. The Dockerfile `COPY compile.* /scripts/` and `COPY runner.* /scripts/` expect build‑time helper files not present in the source tree (normally generated by `tsdk`) — a raw `docker build` from this tree would fail; a `tsdk` build is required. **These gates must pass before any publication claim.**
- `verify_ssl`/`http_proxy`/auth‑header injection depend on the base `Runner`; confirm the custom request methods inherit them (SEC‑001).

---

## L. Testing & Execution Report

| Test | Command / Environment | Result | Evidence |
|---|---|---|---|
| Dependency import (`requests`) | `python3 -c import requests` | **PASS** | requests 2.31.0, Py 3.12.3 |
| Library unit suite (16) | custom harness (pytest absent), `PYTHONPATH=.` | **PASS 16/16** | all `test_*` green |
| Shipped runner tests | — | **NONE EXIST** | `runner_override.py` has no tests (ARCH‑001) |
| Repro: 401 end‑of‑feed | scripted mock | **BUG CONFIRMED** | raises `SubscriptionError(401)` |
| Repro: malformed `confidence` | scripted mock | **BUG CONFIRMED** | uncaught `ValueError` |
| Repro: offset/parsed‑row drift | scripted mock | **BUG CONFIRMED** | 5‑line page → 3 records, early `is_end` |
| `tsdk connector validate` | — | **BLOCKED** | `tsdk` not installed |
| `tsdk connector lint` | — | **BLOCKED** | `tsdk` not installed |
| `tsdk connector build` / Docker | — | **BLOCKED** | no `tsdk`/daemon; needs generated `compile.*`/`runner.*` |
| Live connectivity / enrichment / load | — | **NOT RUN** | no API key; not authorized |

*(No test is reported as passed that was not actually executed.)*

---

## M. README & Documentation Findings

- **DOC‑001 (High):** README/docs attribute library‑only behaviour to the connector — "exponential backoff and jitter," "30 s timeout," "16 test cases covering … retry, checkpoints" (`README.md:124`, `docs/CODE_EXPLANATION.md:431/493/516`, `docs/ARCHITECTURE_AND_CODE_FLOW.md:378`). The shipped runner has none of this. Rewrite to describe `runner_override.py`, or wire the runner to the library so the claims become true.
- **DOC‑002 (High):** Docs codify the 401 bug as intended ("HTTP **401**, 403, or 413 … marks the feed as skipped" — `README.md:39`). Correct to: 401 "record not found" = end‑of‑feed; 413 = plan limit.
- **DOC‑003 (Medium):** `MANUAL_TESTING_GUIDE.md:133` hardcodes a personal absolute venv path (`/home/px/.../opencti/.../open-venv/bin/pytest`); `validate.sh:32‑34` hardcodes other connectors' venv paths. Non‑portable; fails on any other machine/CI. Replace with `python -m pytest` / project venv.
- **DOC‑004 (Low):** Fabricated "Expected Output" status dates (`MANUAL_TESTING_GUIDE.md:72‑77`) and a malformed sample pytest line (`:156`). `MANUAL_TESTING_GUIDE` asks users to import `whoisfreaks_client.*` to "test the connector," but that package isn't in the image — clarify it tests the (dev‑only) library.
- **DOC‑005 (Low):** `README.md` and `docs/README.md` are near‑duplicates — single‑source them. `CHANGELOG` is only a template (`docs/CHANGELOG.md.t`); ship a real `CHANGELOG.md`.

---

## N. Prioritized Remediation Plan

| Priority | Finding | Files to change | Recommended fix | Verification |
|---|---|---|---|---|
| **P0** | ARCH‑001 shipped≠tested | `runner_override.py` or `Dockerfile` + tests | Either make the runner import the tested library (and package it), or add a real test suite for `RunnerOverride`; align docs. | New runner tests pass in CI; image contains the code that tests cover |
| **P0/P1** | FUNC‑001 401 end‑of‑feed | `runner_override.py:116`, `stream.py:70` | Treat 401 "record not found" as clean end‑of‑feed; keep 413(/403) as subscription. | Repro returns `is_end=True, status=success`; add regression test |
| **P1** | FUNC‑005 missing lookups | new `connector/config/actions/*`, runner routing | Implement real‑time lookup actions (whois/reverse/history, DNS/reverse/history, SSL, subdomains, IP geo/whois/security, ASN, availability, reputation, typosquatting) against `api.whoisfreaks.com`. | Each action enriches a sample indicator; schema/examples per op |
| **P1** | FUNC‑002 offset drift | `runner_override.py:201,209`; `stream.py:273,297` | Base offset/end‑of‑feed on server row count, not post‑filter count. | Resume test with filtered rows shows no gap/dupe |
| **P1** | FUNC‑004 errors ignored | `runner_override.py:244‑257` | Surface non‑subscription HTTP errors in single‑feed output. | 400/5xx yields explicit error output |
| **P1** | PERF‑001 in‑memory aggregation | `runner_override.py:_run_ingest_action` | Emit per‑page batches / hard cap; document scale model. | Large `max_pages` stays bounded |
| **P1** | SEC‑001 TLS/proxy wiring | `runner_override.py` | Pass `verify`/proxies explicitly (or confirm base session applies asset `verify_ssl`). | TLS‑fail test respects `verify_ssl=false/true` |
| **P2** | FUNC‑003 confidence cast | `stream.py:189`, `orchestrator.py` | Guard cast; keep raw on failure. | Malformed row → warning, no crash |
| **P2** | FUNC‑006/007 max_pages & status masking | `runner_override.py` | Remove dead branch; surface status‑fetch failures. | Unit tests |
| **P2** | DOC‑001..003 | `README*`, `docs/*`, `validate.sh` | Describe shipped behaviour; fix 401 docs; remove hardcoded paths. | Fresh‑machine doc walkthrough |
| **P2/P3** | SEC‑002/003, stream coverage, changelog | `requirements.txt`, `validate.sh`, new actions, `CHANGELOG.md` | Pin deps; make secret scan real; add remaining feeds if in scope; ship changelog. | CI |

---

## O. Enterprise Readiness Scorecard

| Category | Score /10 | Basis |
|---|---|---|
| Architecture & design | 4 | Clean manifests + tidy library, but shipped runner is a separate, untested reimplementation (ARCH‑001); in‑memory aggregation. |
| Code correctness | 4 | Confirmed FUNC‑001/002/004; 401 contract violation. |
| Feature completeness | 3 | Entire real‑time lookup family (Swimlane's core use case) missing; partial stream coverage. |
| Security | 6 | No secrets, low SSRF/injection, FIPS base; TLS‑wiring unverified, unpinned deps, no‑op secret gate. |
| API reliability | 3 | Shipped path: no retry/backoff/timeout; errors mishandled. |
| Data accuracy & mapping | 6 | Pointers/columns correct & lossless‑ish; offset drift + confidence typing issues. |
| Error handling & resilience | 3 | Single‑GET, masked status failures, uncaught `ValueError` (lib), 401 misroute. |
| Performance & scalability | 4 | Per‑page primitive OK; `ingest` aggregation unscalable; wrong family for bulk‑at‑scale. |
| Platform compatibility | 5 (Not Verified) | Manifests look right; `tsdk validate/lint/build` **not run**. |
| Installation & configuration | 6 | Asset model clear; docs have portability defects. |
| Automated testing | 3 | 16 green but cover unshipped code; shipped runner untested. |
| Documentation & README | 4 | Thorough but describes the wrong (unshipped) code and the 401 bug as intended. |
| Enterprise operations | 4 | Checkpointing present; no health check in shipped path, limited observability. |
| Marketplace compliance | Not Verified | Gates not runnable here. |
| Maintainability | 5 | Two sources of truth invite drift; otherwise readable. |

A critical blocker (ARCH‑001) and confirmed workflow failures (FUNC‑001/002) cap the outcome regardless of averages.

## P. Publication Checklist

| Item | Status |
|---|---|
| Manifests present & structured | PASS (static) |
| `tsdk connector validate` | **BLOCKED** (not run) |
| `tsdk connector lint` | **BLOCKED** |
| `tsdk connector build` / signed image | **BLOCKED** |
| No hardcoded secrets | PASS |
| License / icon / keywords / homepage | PASS |
| Real CHANGELOG | FAIL (template only) |
| Docs match shipped behaviour | FAIL (DOC‑001/002) |
| Shipped code is tested | FAIL (ARCH‑001) |
| Core functional paths correct | FAIL (FUNC‑001/002/004) |
| Platform‑appropriate feature set | FAIL (FUNC‑005) |
| Marketplace submission readiness | **NOT MET** |
| Platform certification | **NOT ASSESSED** (separate from submission) |

## Q. Final Recommendation

1. **Can it be published today?** No.
2. **Can enterprises safely deploy it today?** No — the shipped path is untested and mishandles normal end‑of‑feed and transient errors.
3. **What exactly prevents publication?** ARCH‑001 (untested shipped code / docs describe unshipped code), FUNC‑001 (401 end‑of‑feed misclassified), FUNC‑002 (offset drift vs "lossless"), FUNC‑004 (errors ignored), PERF‑001 (unscalable aggregation), FUNC‑005 (missing lookup family), plus unrun marketplace gates.
4. **Mandatory before release:** reconcile shipped vs tested code with real coverage; fix 401 handling, offset math, error surfacing; add retry/backoff/explicit timeouts to the runner; bound `ingest_stream_feeds`; correct the docs; pass `tsdk validate/lint/build`.
5. **Can wait:** remaining stream families, ECS/observable normalization, caching/dedup, dependency pinning, changelog polish.
6. **Workflows actually executed:** library status/stream/orchestrator logic (16 tests) + three behavioural repros.
7. **Could not test:** live API, `tsdk`/Docker build & platform validation, the `runner_override.py` runtime (SDK absent), load.
8. **Remaining evidence required:** `tsdk validate/lint/build` output; a live single‑page fetch per feed (incl. a real end‑of‑feed 401); a resume run proving no gap/dupe; a 429/5xx retry demonstration on the shipped path.
9. **Tests that must pass after remediation:** runner‑level unit tests for 401 end‑of‑feed, offset/resume integrity, error surfacing, retry/timeout; schema validation; a bounded `ingest` run.
10. **Recommended decision:** **NOT READY TO PUBLISH.** Fix the P0/P1 items (resolve the two‑codebase split, the 401 contract, offset integrity, runner resilience) and decide the endpoint‑family scope: for Swimlane, prioritize the real‑time **lookup** actions (the platform's strength) and keep **threat‑feed** streaming; treat bulk NRD streaming as a page‑oriented, volume‑bounded, optional path rather than wholesale record ingestion.

---

### Platform‑fit summary (direct answer to the scoping question)

> *"If the platform supports lookups, implement them; include streams only if the platform handles them at scale."*

- **Swimlane Turbine sustains real‑time lookups at scale → the lookup family is in scope and must be implemented. It is currently 100% absent — the connector's biggest gap.**
- **Streams:** threat feeds are a good fit; **bulk NRD at full volume is not a natural Turbine workload** and, as built, does not scale (in‑memory aggregation). Keep streaming as paginated per‑page actions (threat feeds first), document volume, and don't funnel entire feeds into one action output.
