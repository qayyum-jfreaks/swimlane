# WhoisFreaks Swimlane Connector — Manual Testing Guide

Step-by-step manual verification before production use. Commands are portable
(no machine-specific paths). Replace `cd <connector-dir>` with the path where you
checked out the connector.

## 1. Prerequisites

```bash
node -v            # for tsdk
tsdk version       # Swimlane Turbine SDK (e.g. @swimlane/turbine-sdk 3.31.0+)
docker version     # Docker daemon running
python3 --version  # 3.11+ for the local test harness
```

A WhoisFreaks API key is needed only for the live steps (7–9). The key is used
for **both** hosts (`files.whoisfreaks.com` and `api.whoisfreaks.com`) via the
`X-API-KEY` header.

## 2. Status endpoint (no key required)

```bash
curl -s https://files.whoisfreaks.com/v3.4/status | python3 -m json.tool | head -n 40
```

Confirm each feed shows `last_update` and `available_from`. `"Not Available"`
means that feed has no data to stream.

## 3. Schema validation

```bash
cd <connector-dir>
tsdk connector validate
```

Expect: `✔ connector "whoisfreaks" ... is valid` (all 29 actions + asset).

## 4. Lint

```bash
tsdk connector lint
```

Expect: `Linting passed`. (Without tsdk, `./scripts/validate.sh` falls back to
`flake8 --max-line-length=120`.)

## 5. Unit tests (39)

```bash
python3 scripts/run_tests.py       # no pytest required
# or, if you have pytest:
pytest -q tests/
```

Expect: `39 passed`. These cover the shipped core **and** the runner (status,
date resolution, stream parsing, host-aware error classification, retry,
pagination-offset integrity, lookups, ingest, secret redaction).

## 6. Build the container image

```bash
tsdk connector build
```

Expect: `✓ Successfully built image: whoisfreaks:1.0.0`.

## 7. Live lookup (with API key)

Configure a Turbine asset (URL `https://files.whoisfreaks.com`, Lookup API URL
`https://api.whoisfreaks.com`, your API Key). Then, for example:

* `live_whois` — input `{"domainName": "whoisfreaks.com"}` → `json_body` with the
  parsed WHOIS record; `success: true`.
* `ip_security` — input `{"ip": "8.8.8.8"}` → threat score + risk signals.
* `ip_security` — input `{"ip": "10.0.0.1"}` → `success: false`,
  `error_kind: "reserved_ip"` (private IP is rejected with 423, by design).
* `account_usage` — no inputs → credit/usage `json_body`; the `apiKey` field
  reads `***redacted***`.

## 8. Live stream feed

* `stream_threat_feed_phishing` — input
  `{"parameters": {"date": "", "limit": 10, "offset": 0}}`. With no date the
  connector resolves the latest available date. Expect `records_count` up to 10,
  `has_more`, `is_end_of_feed`, `next_offset`, and `date_used`.
* Supply an out-of-window date (e.g. `2010-01-01`) and confirm `date_warning`
  reports the fallback to `last_update`.

## 9. Pagination, resume, and end-of-feed

1. Run `ingest_stream_feeds` with
   `{"enabled_feeds": ["phishing"], "limit": 1000, "max_pages": 1}`.
2. Note `checkpoint.phishing.next_offset` and re-run with
   `{"enabled_feeds": ["phishing"], "offset": <next_offset>, "limit": 1000}`.
   Records continue without gaps or duplicates.
3. Set `offset` far beyond the feed size (e.g. `99999999`). The feed ends
   cleanly: the single-feed action returns `is_end_of_feed: true` with
   `records_count: 0` — it does **not** report a subscription error (the stream
   host signals end-of-data with `HTTP 401 "Api record not found"`).

## 10. Error cases to verify

| Scenario | Action | Expected |
|---|---|---|
| Missing/invalid API key | any stream action | `error: true`, config error (stream host returns 400 for a bad key) |
| Unsubscribed feed | e.g. `stream_threat_feed_malware` | `subscription_error: true` (413), run continues for other feeds in `ingest_stream_feeds` |
| Offset beyond data | any stream action | clean end-of-feed, no error |
| Invalid key on a lookup | e.g. `live_whois` | `error_kind: "auth"` (lookup host returns 401 for a bad key) |
| No record found | `live_whois` on a free domain | `error_kind: "not_found"` (404) |
| Private IP | `ip_geolocation` / `ip_security` | `error_kind: "reserved_ip"` (423) |

## 11. Full gate

```bash
./scripts/validate.sh
```

Runs all five gates and exits non-zero if any fails. tsdk/Docker gates report
**SKIPPED** (not passed) when that tooling is not installed.

## FAQ

* **How do I know a feed finished for the day?** `is_end_of_feed: true`, or
  `records_count: 0` / a header-only `response_text`.
* **NRD with full WHOIS?** Set `whois: true` on the NRD stream actions (or
  `nrd_whois: true` on `ingest_stream_feeds`). PII fields arrive as CSV with
  `REDACTED FOR PRIVACY` preserved.
