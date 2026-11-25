# WhoisFreaks Connector for Swimlane Turbine

The **WhoisFreaks** connector integrates [WhoisFreaks](https://whoisfreaks.com)
domain, DNS, SSL, IP and threat intelligence with Swimlane Turbine SOAR. It
provides two complementary families:

1. **Real-time enrichment lookups** (`api.whoisfreaks.com`) — the on-demand
   actions a SOC playbook calls against an observable in a case: WHOIS, DNS, SSL,
   IP geolocation, IP security/reputation, ASN, domain reputation, availability,
   typosquatting and subdomains, including bulk variants.
2. **Bulk stream feeds** (`files.whoisfreaks.com`) — daily Newly Registered
   Domains (gTLD/ccTLD) and phishing/malware/spam threat feeds, paginated with
   resumable checkpoints, for scheduled ingestion and threat hunting.

Both families authenticate with the **same WhoisFreaks API key**, sent in the
**`X-API-KEY`** header.

---

## Architecture (single source of truth)

All runtime logic lives in [`connector/src/whoisfreaks_core.py`](connector/src/whoisfreaks_core.py),
a self-contained, unit-tested module (standard library + `requests`, no SDK
dependency). [`connector/src/runner_override.py`](connector/src/runner_override.py)
is a thin Turbine adapter that wires the platform session/asset into the core.
**The shipped code and the tested code are the same code** — the 39-test suite
in [`tests/`](tests) exercises the core *and* the runner, not a parallel library.

---

## Asset Setup

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| **URL** | String | Yes | `https://files.whoisfreaks.com` | Stream/feeds host (files API). |
| **Lookup API URL** | String | No | `https://api.whoisfreaks.com` | Real-time lookup host. |
| **API Key** | Password | Yes | — | Your WhoisFreaks API key (sent as `X-API-KEY`). |
| **Verify SSL Certificates** | Boolean | No | `true` | TLS certificate verification (passed explicitly on every request). |
| **HTTP(s) Proxy** | String | No | — | Optional proxy. |

---

## Real-time lookup actions

Each returns `status_code`, `reason`, `success`, and `json_body` (the full
provider response), or `error_message` + `error_kind` on failure.

| Action | Endpoint | Key inputs |
|---|---|---|
| `live_whois` | `/v2.0/whois/live` | `domainName` |
| `whois_history` | `/v2.0/whois/history` | `domainName` |
| `reverse_whois` | `/v2.0/whois/reverse` | one of `keyword`/`email`/`owner`/`company`, `mode`, `exact`, `page` |
| `bulk_whois` | `/v2.0/bulkwhois/live` | `domainNames` (≤100) |
| `live_dns` | `/v2.0/dns/live` | `domainName` or `ipAddress`, `type` |
| `dns_history` | `/v2.0/dns/historical` | `domainName`, `type`, `page` |
| `reverse_dns` | `/v2.1/dns/reverse` | `value`, `type`, `exact`, `sort`, `page` |
| `bulk_dns` | `/v2.0/dns/bulk/live` | `domainNames`/`ipAddresses` (≤100), `type` |
| `domain_availability` | `/v2.0/domain/availability` | `domain`, `sug`, `count` |
| `bulk_domain_availability` | `/v2.0/domain/availability` | `domainNames`, or `domain`+`tld` |
| `typosquatting` | `/v3.0/domain/typos` | one of `keyword`/`pattern`, `pageToken` |
| `domain_reputation` | `/v1/domain/security` | `domainName` |
| `ssl_lookup` | `/v1.0/ssl/live` | `domainName`, `chain`, `sslRaw` |
| `subdomains` | `/v1.0/subdomains` | `domain`, `after`, `before`, `status`, `page` |
| `ip_geolocation` | `/v1.0/geolocation` | `ip` |
| `bulk_ip_geolocation` | `/v1.0/geolocation` | `ips` (≤100) |
| `ip_security` | `/v2.0/security` | `ip` |
| `bulk_ip_security` | `/v1.0/security` | `ips` (≤100) |
| `ip_whois` | `/v1.0/ip-whois` | `ip` |
| `asn_whois` | `/v2.0/asn-whois` | `asn` |
| `account_usage` | `/v1.0/whoisapi/usage` | — (the echoed `apiKey` is redacted by the connector) |
| `rotate_api_key` | `/v1.0/api-key/rotate` | — (returns the new secondary key as `response_text`; treated as a secret, never logged) |

> **Analyst note on interpretation:** WhoisFreaks geolocation is an estimate, not
> a verified physical location; VPN/proxy/Tor flags are signals, not proof of
> malicious activity; a threat/trust score is a probability, not certainty; and
> an "unknown" classification is not a negative one. Use these as enrichment
> context, not as a verdict.

---

## Stream feed actions

Each page returns `response_text` (raw CSV/plain text), `records_count`,
`has_more`, `is_end_of_feed`, `date_used` and `next_offset`.

| Action | Endpoint | Notes |
|---|---|---|
| `get_feed_status` | `/v3.4/status` | Availability windows for every product (`last_update`, `available_from`). |
| `stream_nrd_gtld` | `/v3.3/stream/domainer/gtld` | `whois=false` → one domain per line; `whois=true` → full CSV WHOIS. |
| `stream_nrd_cctld` | `/v3.3/stream/domainer/cctld` | Same as gTLD. |
| `stream_threat_feed_phishing` | `/v3.4/stream/threat-feed/phishing` | Daily phishing indicators (CSV). |
| `stream_threat_feed_malware` | `/v3.4/stream/threat-feed/malware` | Daily malware indicators (CSV). |
| `stream_threat_feed_spam` | `/v3.4/stream/threat-feed/spam` | Daily spam indicators (CSV). |
| `ingest_stream_feeds` | — | Status-first multi-feed orchestration with checkpoints (see below). |

### Status-first contract
Every stream endpoint requires a `date` (`YYYY-MM-DD`). Before fetching, the
connector reads `/v3.4/status`:
* A supplied date inside `[available_from, last_update]` is used as-is; outside
  the window it falls back to `last_update` (with a `date_warning`).
* No date supplied → the latest available date (`last_update`) is used.
* If `/v3.4/status` is unreachable but you supplied an explicit date, that date
  is still used (status outages do not block an explicit-date fetch).

### Pagination & end-of-feed
Feeds return millions of rows via zero-based `offset`/`limit`. The connector
recognises **two** end-of-feed signals and stops cleanly on either:
* a header-only page (CSV) or empty body (plain text), and
* **`HTTP 401 "Api record not found"`** — on the stream host this means *offset
  beyond available data*, i.e. end of feed. It is **not** an auth or plan error.

Offsets advance by the number of rows the server actually returned (not the
post-filter count), so resuming from a `checkpoint` never skips or duplicates
rows.

### Subscription handling
A single plan may not cover every feed. **`HTTP 413` (and `403`)** → the feed is
marked `subscription_skipped` and the run continues with other enabled feeds.
`HTTP 400` surfaces as a configuration error (bad/missing API key or date).

### `ingest_stream_feeds`
Status-first multi-feed action. Inputs: `enabled_feeds`
(`phishing`/`malware`/`spam`/`gtld`/`cctld`), `date`, `limit` (default 1000),
`offset`, `max_pages` (default 1; `0`/null → 1; **hard-capped at 50 pages/run**),
`nrd_whois`. Outputs: `status`, `total_records`, `truncated`, `feeds_summary`,
`records`, `checkpoint`. For large backfills, loop the per-feed stream actions
or re-run with the returned `checkpoint` rather than inflating `max_pages`.

### Recommended schedule
Feeds refresh once per day. Schedule ingestion **once daily** or every **6–12
hours** — never minute-level polling.

---

## Error semantics (host-aware)

The same HTTP status means different things per host; the connector classifies
them separately:

| Status | Stream host (`files.`) | Lookup host (`api.`) |
|---|---|---|
| 400 | Config (bad/missing key or date) | Config (invalid parameter) |
| 401 | **End of feed** ("record not found") | **Invalid API key** (auth) |
| 403 | Subscription | Forbidden (unsupported/inactive TLD) |
| 404 | — | No record found |
| 408/429/5xx | Transient (retried with backoff + jitter) | Transient (retried) |
| 412 | — | Plan limit |
| 413 | Subscription | Quota exceeded |
| 423 | — | Reserved/private IP |

Transient errors (408/429/5xx, timeouts, connection errors) are retried with
bounded exponential backoff and jitter, honouring `Retry-After` on 429.

---

## Privacy & security
* The API key is a password-type asset field, sent only in the `X-API-KEY`
  header, and is never logged. `account_usage` redacts the echoed `apiKey`;
  `rotate_api_key` output is never logged.
* NRD WHOIS data carries PII; `REDACTED FOR PRIVACY` markers are preserved
  verbatim. Enable `nrd_whois=true` only when you need registrant fields, and
  mind your Swimlane data-retention policy.
* TLS verification is controlled by **Verify SSL Certificates** and passed
  explicitly on every request.

---

## Validation

```bash
./scripts/validate.sh
```

Runs, in order: Turbine schema validation (`tsdk connector validate`), lint
(`tsdk connector lint`, or `flake8` fallback), the 39-test suite
(`pytest`, or the bundled `scripts/run_tests.py` fallback), a secret scan, and
the container image build (`tsdk connector build`). tsdk/Docker gates report
**SKIPPED** (not passed) when that tooling is absent. See
[docs/MANUAL_TESTING_GUIDE.md](docs/MANUAL_TESTING_GUIDE.md) for step-by-step
manual testing and [docs/REMEDIATION.md](docs/REMEDIATION.md) for the audit
remediation record.
