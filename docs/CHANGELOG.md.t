# Change Log

All notable changes to this project are documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## 1.0.0 - {{{timestamp}}}

Initial release.

### Real-time lookup actions (api.whoisfreaks.com)
 * WHOIS: `live_whois`, `whois_history`, `reverse_whois`, `bulk_whois`
 * DNS: `live_dns`, `dns_history`, `reverse_dns`, `bulk_dns`
 * Domain intelligence: `domain_availability`, `bulk_domain_availability`,
   `typosquatting`, `domain_reputation`, `ssl_lookup`, `subdomains`
 * IP / ASN: `ip_geolocation`, `bulk_ip_geolocation`, `ip_security`,
   `bulk_ip_security`, `ip_whois`, `asn_whois`
 * Account: `account_usage` (echoed API key redacted), `rotate_api_key`
   (secondary key returned as text, never logged)

### Stream feed actions (files.whoisfreaks.com)
 * `get_feed_status`, `stream_nrd_gtld`, `stream_nrd_cctld`,
   `stream_threat_feed_phishing`, `stream_threat_feed_malware`,
   `stream_threat_feed_spam`, and the status-first `ingest_stream_feeds`
   orchestration with resumable checkpoints.

### Behaviour
 * Host-aware error classification: on the stream host `HTTP 401
   "Api record not found"` is treated as end-of-feed; on the lookup host `HTTP
   401` is an invalid-key error. `413`/`403` on the stream host are plan limits.
 * Bounded exponential backoff with jitter on 408/429/5xx and transport errors,
   honouring `Retry-After`; explicit timeouts and TLS verification on every call.
 * Pagination offsets advance by rows returned by the server, so checkpoint
   resume never skips or duplicates rows.
 * `ingest_stream_feeds` is bounded (max 50 pages / 100k records per run) to keep
   a single action output safe.
