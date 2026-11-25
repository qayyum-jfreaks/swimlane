# Architecture & Code Flow

## Overview

The connector has one runtime implementation, shipped under `connector/` (the
only directory packaged into the image by the Dockerfile) and exercised by the
test suite:

```
connector/
  connector.yaml                 # connector manifest
  config/
    assets/apikey.yaml           # asset: url, api_url, X-API-KEY, verify_ssl, http_proxy
    actions/*.yaml               # 29 action manifests (22 lookups + 5 streams + status + ingest)
  src/
    whoisfreaks_core.py          # all logic (SDK-independent, unit-tested)
    runner_override.py           # thin Turbine adapter -> core
tests/                           # 39 tests over core + runner
scripts/                         # validate.sh, run_tests.py
```

There is no second "library" implementation. `runner_override.py` imports its
sibling `whoisfreaks_core.py`; the core imports only the standard library and
`requests`.

## Dispatch

`RunnerOverride.run(inputs, action_schema)` builds a `WhoisFreaksCore` from the
asset (`url`, `api_url`, `X-API-KEY`, `verify_ssl`) and the Turbine session, then
dispatches by action name:

```
get_feed_status      -> _run_status  -> core.fetch_status
ingest_stream_feeds  -> _run_ingest  -> core.fetch_status + core.fetch_stream_page (loop)
stream_* (5 feeds)   -> _run_stream  -> core.fetch_status + core.resolve_feed_date + core.fetch_stream_page
<lookup action>      -> _run_lookup  -> core.execute_lookup
<anything else>      -> super().run()   # base Turbine declarative HTTP
```

## Two hosts, one key

`X-API-KEY` authenticates both hosts. Stream actions use `files_url`
(`files.whoisfreaks.com`); lookup actions use `api_url`
(`api.whoisfreaks.com`). The core keeps both base URLs and selects per call.

## Request flow (`WhoisFreaksCore._request`)

Every HTTP call goes through one method that:
1. sets the `X-API-KEY` header,
2. passes an explicit `timeout` and `verify` (TLS) — never relying on session
   defaults,
3. retries `408`/`429`/`5xx` and transport errors with bounded exponential
   backoff + jitter, honouring `Retry-After` on `429`,
4. returns `(response, None)` or `(None, error_message)` after exhausting
   retries.

Callers (`fetch_status`, `fetch_stream_page`, `execute_lookup`) then classify the
response into a plain result dict — no exceptions cross the boundary, so the
adapter maps results straight into action outputs.

## Host-aware error model

```
                       files host (stream)        api host (lookup)
HTTP 400               config                     config
HTTP 401               END OF FEED (record        auth (invalid key)
                       not found) / else auth
HTTP 403               subscription               forbidden
HTTP 404               -                          not_found
HTTP 408/429/5xx       transient (retried)        transient (retried)
HTTP 412               -                          plan_limit
HTTP 413               subscription               quota
HTTP 423               -                          reserved_ip
```

The `401` split is the key correctness point: offset-beyond-data on the stream
host returns `401 "Api record not found"`, which is a normal end-of-feed stop,
whereas `401` on the lookup host is a real authentication failure.

## Stream pagination

`fetch_stream_page` returns `records`, `raw_count` (rows the **server** returned,
before any filtering) and `is_end` (`raw_count < limit` or header-only). Offsets
advance by `raw_count`, so a checkpoint resume (`{date, next_offset}`) never
skips or duplicates rows. `ingest_stream_feeds` loops pages per feed up to
`max_pages` (capped at `MAX_INGEST_PAGES = 50`) and `MAX_INGEST_RECORDS =
100_000`, setting `truncated: true` and a `checkpoint` when a cap is hit.

## Stream ingest sequence

```
Playbook -> ingest_stream_feeds
  core.fetch_status
  for feed in enabled_feeds:
      date, warn = core.resolve_feed_date(status, feed, requested_date)
      if not date: summary[feed] = not_ready; continue
      while has_more and pages < max_pages:
          res = core.fetch_stream_page(feed, date, offset, limit, whois)
          match res.kind:
              subscription -> summary[feed]=subscription_skipped; break
              config/auth/transient/error -> summary[feed]=error; break
              end_of_feed -> break
              data -> collect; offset += raw_count; stop if is_end or caps hit
      checkpoint[feed] = {date, next_offset: offset}
  return {status, total_records, truncated, feeds_summary, records, checkpoint}
```

## Secret handling

The API key is only ever sent in the `X-API-KEY` header and is never logged.
`account_usage` redacts the echoed `apiKey` field before returning. `rotate_api_key`
returns the new secondary key as `response_text` and is never logged. Error
messages are extracted from the provider's `message`/`error` fields only (never
raw bodies), so secrets cannot leak through logs.
