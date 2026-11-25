# Code Explanation (file by file)

## `connector/connector.yaml`
Connector manifest: vendor/product/name, `schema: connector/1`, version `1.0.0`,
Apache-2.0, FIPS Python 3.11 build template, icon, and keywords. `description`
must stay ≤ 255 characters (a Turbine schema limit).

## `connector/config/assets/apikey.yaml`
One asset for both product families:
* `url` — stream/feeds host (default `https://files.whoisfreaks.com`).
* `api_url` — lookup host (default `https://api.whoisfreaks.com`).
* `X-API-KEY` — password-type API key; `meta.security` declares it as an
  `apiKey` header named `X-API-KEY`.
* `verify_ssl` (default `true`) and `http_proxy`.

## `connector/config/actions/*.yaml`
29 action manifests:
* **5 stream** (`stream_nrd_gtld`, `stream_nrd_cctld`,
  `stream_threat_feed_{phishing,malware,spam}`) — nested `parameters`
  (`date`, `limit`, `offset`, and `whois` for NRD).
* **`get_feed_status`** — no inputs; `json_body` of availability windows.
* **`ingest_stream_feeds`** — `enabled_feeds`, `date`, `limit`, `offset`,
  `max_pages` (0/null → 1, capped at 50), `nrd_whois`.
* **22 lookup** — flat top-level inputs mapped to query string or JSON body by
  the core. Outputs: `status_code`, `reason`, `success`, `json_body` (or
  `response_text` for `rotate_api_key`), `error_message`.

## `connector/src/whoisfreaks_core.py`
The single source of truth. Key elements:
* **Constants / registries** — `STREAM_ENDPOINTS`, `FEED_POINTERS`,
  `STREAM_ACTIONS`, `LOOKUP_CONFIG` (action → method/endpoint/body-keys), caps
  (`MAX_INGEST_PAGES=50`, `MAX_INGEST_RECORDS=100000`).
* **`_request`** — the one HTTP path: explicit timeout + TLS `verify`, retry on
  408/429/5xx and transport errors with backoff + jitter and `Retry-After`.
  Returns `(response, error)`; never raises across the boundary.
* **`fetch_status`** — GETs `/v3.4/status`; returns `{ok, status_code, json,
  message}`, surfacing failures instead of masking them.
* **`resolve_feed_date`** — status-first date rule; honours an explicit caller
  date even when status is unavailable.
* **`parse_stream_text`** — lossless CSV / plain-text parsing; returns
  `(records, raw_row_count, is_header_only)`. `raw_row_count` is the server's row
  count (for offset integrity); values are preserved as-is (no numeric coercion,
  so a non-numeric `confidence` never raises).
* **`fetch_stream_page`** — stream-host classification: `data`, `end_of_feed`
  (401 "record not found"), `subscription` (403/413), `config` (400), `auth`,
  `transient`, `error`.
* **`execute_lookup`** — splits inputs into query/body per `LOOKUP_CONFIG`,
  calls the api host, and classifies with lookup-host semantics
  (`auth`, `not_found`, `reserved_ip`, `plan_limit`, `quota`, …).

## `connector/src/runner_override.py`
Thin `RunnerOverride(Runner)` adapter. `__init__` stashes the asset dict;
`_core()` builds a `WhoisFreaksCore` from it and the Turbine session; `run()`
dispatches by action name (see ARCHITECTURE_AND_CODE_FLOW.md). The `_run_*`
helpers translate core result dicts into Turbine outputs, surface non-subscription
errors explicitly, bound `ingest_stream_feeds`, and redact `account_usage`'s
`apiKey`. It adds its own directory to `sys.path` so the sibling core imports at
runtime.

## `tests/`
* `helpers.py` / `conftest.py` — path wiring + mock-response factory.
* `test_core_status.py` — status fetch + date resolution (8 tests).
* `test_core_stream.py` — parsing, 401 end-of-feed, 413 subscription, 400
  config, retry, offset integrity (11 tests).
* `test_core_lookup.py` — request shaping, body/query split, lookup-host error
  classification, text responses (10 tests).
* `test_runner.py` — the shipped `RunnerOverride` end-to-end with a stubbed SDK
  base: dispatch, stream data, 401 end-of-feed, 413 surfaced, ingest multi-feed,
  lookups, secret redaction, fall-through (10 tests).

## `scripts/`
* `validate.sh` — portable 5-gate runner (validate, lint, tests, secret scan,
  build); tsdk/Docker gates are SKIPPED, not passed, when absent.
* `run_tests.py` — dependency-free runner for the `test_*` functions.

## `requirements.txt`
Pinned `requests==2.31.0`, `urllib3==1.26.20` (urllib3 on 1.26.x for FIPS base
compatibility). The Swimlane base image provides `requests` at runtime; the pins
make standalone builds and the local harness deterministic.
