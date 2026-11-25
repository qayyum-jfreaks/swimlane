# Audit Remediation Record

This records how each finding in [`../AUDIT_REPORT.md`](../AUDIT_REPORT.md) was
resolved. Verified locally against the real Swimlane tooling: `tsdk connector
validate` (valid), `tsdk connector lint` (passed), 39/39 unit tests,
`tsdk connector build` (image built), secret scan (clean).

## Structural

| ID | Finding | Resolution |
|---|---|---|
| ARCH-001 | Shipped code ≠ tested code; tested library excluded from the image | Consolidated to a single shipped source of truth: `connector/src/whoisfreaks_core.py` (logic) + `runner_override.py` (adapter), both under `connector/` (the only dir the Dockerfile packages). Removed the parallel `whoisfreaks_client/`, `pipeline/`, `destination/` packages. New tests exercise the **core and the runner** (via a stubbed SDK base). |

## Functional

| ID | Finding | Resolution |
|---|---|---|
| FUNC-001 | `HTTP 401` end-of-feed misclassified as a subscription error | Host-aware classification: on the stream host, `401 "Api record not found"` → `end_of_feed`; only `403`/`413` → subscription. On the lookup host `401` → `auth`. Tests: `test_401_record_not_found_is_end_of_feed`, `test_lookup_401_is_auth_not_end_of_feed`, `test_stream_action_401_end_of_feed_not_subscription`. |
| FUNC-002 | Offset advanced by filtered rows → resume skips/dupes | `parse_stream_text` returns `raw_count` (server rows); offsets advance by `raw_count`. Test: `test_offset_counts_server_rows_not_filtered`. |
| FUNC-003 | Uncaught `ValueError` on non-numeric `confidence` | No numeric coercion in parsing; values preserved as-is. Test: `test_parse_threat_csv_lossless_no_crash_on_bad_confidence`. |
| FUNC-004 | Single-feed actions ignored non-subscription HTTP errors | `_run_stream` surfaces every error kind (`config`/`auth`/`transient`/`error`) with `error: true` + `error_kind`. Test: `test_stream_action_413_subscription_surfaced`. |
| FUNC-005 | Entire real-time lookup family missing (platform-fit gap) | Added all 22 lookup actions (WHOIS/DNS/SSL/IP/ASN/reputation/availability/typosquatting/subdomains/account) against `api.whoisfreaks.com`, routed through `execute_lookup`. |
| FUNC-006 | `max_pages` contradictory / dead branch | `0`/null → 1; removed the dead "unlimited" branch; hard cap of 50 pages, documented in the manifest. Test: `test_ingest_max_pages_zero_coerced_to_one`. |
| FUNC-007 | Status-endpoint failure masked | `fetch_status` returns `{ok:false, status_code, message}`; `get_feed_status` surfaces it; stream actions still honour an explicit date during a status outage. Tests: `test_fetch_status_http_error_surfaced`, `test_resolve_status_down_but_date_given`. |

## Reliability / performance / security

| ID | Finding | Resolution |
|---|---|---|
| (runner) | Shipped runner had no retry/backoff/timeout | `_request` retries 408/429/5xx + transport errors with backoff + jitter and `Retry-After`; explicit timeout on every call. Tests: `test_retry_429_then_200`, `test_retry_500_exhausted_is_transient`, `test_lookup_retry_on_408_then_success`. |
| PERF-001 | `ingest_stream_feeds` unbounded in-memory aggregation | Bounded to `MAX_INGEST_PAGES=50` / `MAX_INGEST_RECORDS=100000` with a `truncated` flag + `checkpoint` for continuation. |
| SEC-001 | `verify_ssl`/proxy honoring unverified | TLS `verify` passed explicitly on every request from the asset `verify_ssl`; proxy from the base runner. |
| SEC-002 | Unpinned dependencies | `requirements.txt` pinned (`requests==2.31.0`, `urllib3==1.26.20`). |
| SEC-003 | Secret scan was a no-op outside git; hardcoded paths | `validate.sh` scans the filesystem directly; no machine-specific paths; `scripts/run_tests.py` replaces the hardcoded venv. |
| SEC-006 | API-key exposure via `account_usage` | `account_usage` redacts the echoed `apiKey`; `rotate_api_key` output is never logged; error messages use provider `message` fields only. |

## Documentation

| ID | Finding | Resolution |
|---|---|---|
| DOC-001 | Docs described unshipped library behaviour | README, `ARCHITECTURE_AND_CODE_FLOW.md` and `CODE_EXPLANATION.md` rewritten to the shipped design. |
| DOC-002 | Docs codified the 401 bug | Error semantics corrected (host-aware table) in README and architecture docs. |
| DOC-003 | Hardcoded personal venv paths | Removed from `validate.sh` and the manual-testing guide. |
| DOC-004 | Fabricated outputs / malformed samples | Manual guide rewritten with portable commands and realistic expectations. |
| DOC-005 | Duplicate READMEs; template-only changelog | `docs/README.md` is now a docs index; `docs/CHANGELOG.md.t` carries a real 1.0.0 entry. |

## Notes

* The two parallel `whoisfreaks_client/` / `pipeline/` / `destination/` packages
  and the three old test files were deleted during consolidation.
* `tsdk`-based gates require the Swimlane SDK + Docker; `./scripts/validate.sh`
  ran all five green in the remediation environment.
