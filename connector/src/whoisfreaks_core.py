"""WhoisFreaks core logic for the Swimlane Turbine connector.

This module is the single source of truth for the connector's runtime behaviour.
It is self-contained (standard library + ``requests`` only), has no dependency on
the Swimlane SDK, and is therefore fully unit-testable with a mock session. The
Turbine entry point (``runner_override.RunnerOverride``) is a thin adapter that
wires the platform's session/asset into this core.

It covers both WhoisFreaks product families:

* **Stream / files API** (``files.whoisfreaks.com``) - daily bulk feeds (NRD
  gTLD/ccTLD, threat feeds) returned as CSV / plain text with offset pagination.
  On this host ``HTTP 401 "Api record not found"`` is the *end-of-feed* signal
  (offset beyond available data), **not** an auth or subscription failure, and
  ``HTTP 413`` ("upgrade your plans") is the plan/subscription signal.

* **Lookup / real-time API** (``api.whoisfreaks.com``) - point queries returning
  JSON. On this host ``HTTP 401`` means an **invalid API key**, ``404`` means no
  record was found, and ``423`` means a reserved/private IP was supplied. Error
  codes therefore carry different meaning per host and are classified separately.
"""

import csv
import io
import logging
import random
import time
from typing import Any, Dict, List, Optional, Tuple
import requests

DEFAULT_FILES_URL = "https://files.whoisfreaks.com"
DEFAULT_API_URL = "https://api.whoisfreaks.com"
STATUS_ENDPOINT = "/v3.4/status"
HEADER_API_KEY = "X-API-KEY"
STREAM_ENDPOINTS = {
    "gtld": "/v3.3/stream/domainer/gtld",
    "cctld": "/v3.3/stream/domainer/cctld",
    "phishing": "/v3.4/stream/threat-feed/phishing",
    "malware": "/v3.4/stream/threat-feed/malware",
    "spam": "/v3.4/stream/threat-feed/spam",
}
FEED_POINTERS = {
    "gtld": ("newly", "gtld"),
    "cctld": ("newly", "cctld"),
    "phishing": ("threat_feed", "phishing"),
    "malware": ("threat_feed", "malware"),
    "spam": ("threat_feed", "spam"),
}
THREAT_FEEDS = "phishing", "malware", "spam"
NRD_FEEDS = "gtld", "cctld"
STREAM_FEEDS = THREAT_FEEDS + NRD_FEEDS
FEED_ALIASES = {
    "gtld": "gtld",
    "cctld": "cctld",
    "phishing": "phishing",
    "malware": "malware",
    "spam": "spam",
}
STREAM_ACTIONS = {
    "stream_nrd_gtld": ("gtld", "nrd"),
    "stream_nrd_cctld": ("cctld", "nrd"),
    "stream_threat_feed_phishing": ("phishing", "threat"),
    "stream_threat_feed_malware": ("malware", "threat"),
    "stream_threat_feed_spam": ("spam", "threat"),
}
FEED_TYPE = {f: ("threat" if f in THREAT_FEEDS else "nrd") for f in STREAM_FEEDS}
LOOKUP_CONFIG: Dict[str, Dict[str, Any]] = {
    "live_whois": {"method": "GET", "endpoint": "/v2.0/whois/live", "body": set()},
    "whois_history": {
        "method": "GET",
        "endpoint": "/v2.0/whois/history",
        "body": set(),
    },
    "reverse_whois": {
        "method": "GET",
        "endpoint": "/v2.0/whois/reverse",
        "body": set(),
    },
    "bulk_whois": {
        "method": "POST",
        "endpoint": "/v2.0/bulkwhois/live",
        "body": {"domainNames"},
    },
    "live_dns": {"method": "GET", "endpoint": "/v2.0/dns/live", "body": set()},
    "dns_history": {"method": "GET", "endpoint": "/v2.0/dns/historical", "body": set()},
    "reverse_dns": {"method": "GET", "endpoint": "/v2.1/dns/reverse", "body": set()},
    "bulk_dns": {
        "method": "POST",
        "endpoint": "/v2.0/dns/bulk/live",
        "body": {"domainNames", "ipAddresses"},
    },
    "domain_availability": {
        "method": "GET",
        "endpoint": "/v2.0/domain/availability",
        "body": set(),
    },
    "bulk_domain_availability": {
        "method": "POST",
        "endpoint": "/v2.0/domain/availability",
        "body": {"domainNames", "tld"},
    },
    "typosquatting": {"method": "GET", "endpoint": "/v3.0/domain/typos", "body": set()},
    "domain_reputation": {
        "method": "GET",
        "endpoint": "/v1/domain/security",
        "body": set(),
    },
    "ssl_lookup": {"method": "GET", "endpoint": "/v1.0/ssl/live", "body": set()},
    "subdomains": {"method": "GET", "endpoint": "/v1.0/subdomains", "body": set()},
    "ip_geolocation": {"method": "GET", "endpoint": "/v1.0/geolocation", "body": set()},
    "bulk_ip_geolocation": {
        "method": "POST",
        "endpoint": "/v1.0/geolocation",
        "body": {"ips"},
    },
    "ip_security": {"method": "GET", "endpoint": "/v2.0/security", "body": set()},
    "bulk_ip_security": {
        "method": "POST",
        "endpoint": "/v1.0/security",
        "body": {"ips"},
    },
    "ip_whois": {"method": "GET", "endpoint": "/v1.0/ip-whois", "body": set()},
    "asn_whois": {"method": "GET", "endpoint": "/v2.0/asn-whois", "body": set()},
    "account_usage": {
        "method": "GET",
        "endpoint": "/v1.0/whoisapi/usage",
        "body": set(),
    },
    "rotate_api_key": {
        "method": "GET",
        "endpoint": "/v1.0/api-key/rotate",
        "body": set(),
    },
}
SECRET_LOOKUPS = {"rotate_api_key", "account_usage"}
DEFAULT_PAGE_LIMIT = 1000
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_BASE_SECONDS = 1.0
MAX_INGEST_PAGES = 50
MAX_INGEST_RECORDS = 100000
_DEFAULT_LOGGER = logging.getLogger("whoisfreaks.core")


class WhoisFreaksCore:
    """Host-aware WhoisFreaks client: stream feeds + real-time lookups.

    All methods return plain dictionaries (never raise across the boundary) so
    the Turbine adapter can serialise results directly into action outputs.
    """

    def __init__(
        self,
        session: requests.Session,
        files_url: str = DEFAULT_FILES_URL,
        api_url: str = DEFAULT_API_URL,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_base: float = DEFAULT_BACKOFF_BASE_SECONDS,
        logger: Optional[logging.Logger] = None,
    ):
        self.session = session
        self.files_url = (files_url or DEFAULT_FILES_URL).rstrip("/")
        self.api_url = (api_url or DEFAULT_API_URL).rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.log = logger or _DEFAULT_LOGGER

    def _sleep_for(self, attempt: int, retry_after: Optional[str]) -> float:
        if retry_after:
            try:
                return max(0.0, float(retry_after))
            except (TypeError, ValueError):
                pass
        return self.backoff_base * 2**attempt + random.uniform(0.05, 0.2)

    def _request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> Tuple[Optional[requests.Response], Optional[str]]:
        """Perform an HTTP request with bounded exponential backoff + jitter.

        Retries 408/429/5xx and transport errors up to ``max_retries``; honours
        ``Retry-After`` on 429. TLS verification and timeout are always passed
        explicitly (never left to session defaults). Returns ``(response, None)``
        or ``(None, error_message)`` when the transport failed after all retries.
        """
        headers = {}
        if self.api_key:
            headers[HEADER_API_KEY] = self.api_key
        req_timeout = timeout or self.timeout
        last_net: Optional[str] = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = self.session.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=headers,
                    timeout=req_timeout,
                    verify=self.verify_ssl,
                )
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_net = str(exc)
                if attempt < self.max_retries:
                    time.sleep(self._sleep_for(attempt, None))
                    continue
                return (
                    None,
                    f"Connection failed after {self.max_retries} retries: {exc}",
                )
            except requests.RequestException as exc:
                return None, f"Request error: {exc}"
            if resp.status_code in (408, 429) or resp.status_code >= 500:
                if attempt < self.max_retries:
                    wait = self._sleep_for(attempt, resp.headers.get("Retry-After"))
                    self.log.warning(
                        "Transient HTTP %s on %s; retry %d/%d in %.2fs",
                        resp.status_code,
                        url,
                        attempt + 1,
                        self.max_retries,
                        wait,
                    )
                    time.sleep(wait)
                    continue
            return resp, None
        return None, last_net or "Request failed after retries."

    @staticmethod
    def _message(resp: Optional[requests.Response], body: Any = None) -> str:
        """Extract a short human-readable message, never leaking secrets/bodies."""
        if isinstance(body, dict):
            msg = body.get("message") or body.get("error")
            if msg:
                return str(msg)
        if resp is None:
            return ""
        try:
            data = resp.json()
            if isinstance(data, dict):
                return str(
                    data.get("message") or data.get("error") or resp.reason or ""
                )
        except Exception:
            pass
        return resp.reason or f"HTTP {resp.status_code}"

    def fetch_status(self) -> Dict[str, Any]:
        """Fetch /v3.4/status. Returns {ok, status_code, json, message}."""
        url = f"{self.files_url}{STATUS_ENDPOINT}"
        resp, neterr = self._request("GET", url)
        if neterr:
            return {"ok": False, "status_code": 0, "json": {}, "message": neterr}
        if resp.status_code != 200:
            return {
                "ok": False,
                "status_code": resp.status_code,
                "json": {},
                "message": self._message(resp),
            }
        try:
            data = resp.json()
        except Exception as exc:
            return {
                "ok": False,
                "status_code": resp.status_code,
                "json": {},
                "message": f"Status endpoint returned non-JSON: {exc}",
            }
        return {"ok": True, "status_code": 200, "json": data, "message": ""}

    @staticmethod
    def resolve_feed_date(
        status_json: Dict[str, Any], feed_key: str, requested_date: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        """Status-first date resolution.

        * No status available -> use the caller's date if given, else (None, reason).
        * Caller date inside [available_from, last_update] -> use it.
        * Caller date outside the window -> fall back to last_update (with warning).
        * No caller date -> latest available (last_update).
        """
        pointer = FEED_POINTERS.get(feed_key)
        window = {}
        if status_json and pointer:
            p1, p2 = pointer
            window = (status_json.get(p1, {}) or {}).get(p2, {}) or {}
        last_update = window.get("last_update")
        available_from = window.get("available_from")
        if not last_update or last_update == "Not Available":
            if requested_date:
                return (
                    requested_date,
                    f"Feed '{feed_key}' availability window is unknown (status unavailable); using requested date '{requested_date}'.",
                )
            return (None, f"Feed '{feed_key}' has no available data on the server.")
        if requested_date:
            if available_from and available_from != "Not Available":
                if available_from <= requested_date <= last_update:
                    return requested_date, None
                return (
                    last_update,
                    f"Requested date '{requested_date}' for feed '{feed_key}' is outside the available window ({available_from} to {last_update}); falling back to '{last_update}'.",
                )
            return requested_date, None
        return last_update, None

    @staticmethod
    def parse_stream_text(
        text: str, feed_type: str, whois: bool
    ) -> Tuple[List[Dict[str, Any]], int, bool]:
        """Losslessly parse a stream page.

        Returns ``(records, raw_row_count, is_header_only)`` where ``raw_row_count``
        is the number of data rows the server actually returned (NOT the filtered
        count) so pagination offsets never drift (FUNC-002). Every data row is
        preserved as-is; no numeric coercion is performed (FUNC-003).
        """
        if not text or not text.strip():
            return [], 0, True
        if feed_type == "nrd" and not whois:
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            records = [{"domain_name": ln} for ln in lines if not ln.startswith("#")]
            return records, len(lines), len(lines) == 0
        reader = csv.DictReader(io.StringIO(text))
        records: List[Dict[str, Any]] = []
        raw = 0
        for row in reader:
            if row is None:
                continue
            if not any(v is not None and str(v).strip() != "" for v in row.values()):
                continue
            raw += 1
            cleaned = {
                (k.strip() if isinstance(k, str) else k): (
                    v.strip() if isinstance(v, str) else v
                )
                for k, v in row.items()
                if k is not None and v is not None
            }
            records.append(cleaned)
        return records, raw, raw == 0

    def fetch_stream_page(
        self,
        feed_key: str,
        date: str,
        offset: int = 0,
        limit: int = DEFAULT_PAGE_LIMIT,
        whois: bool = False,
    ) -> Dict[str, Any]:
        """Fetch one stream page and classify the result (stream-host semantics).

        kinds: ``data`` | ``end_of_feed`` | ``subscription`` | ``config`` |
        ``auth`` | ``transient`` | ``error``.
        """
        endpoint = STREAM_ENDPOINTS.get(feed_key)
        if not endpoint:
            return {
                "kind": "config",
                "status_code": 0,
                "message": f"Unknown feed '{feed_key}'.",
            }
        feed_type = FEED_TYPE[feed_key]
        params: Dict[str, Any] = {"date": date, "limit": limit, "offset": offset}
        if feed_key in NRD_FEEDS:
            params["whois"] = "true" if whois else "false"
        resp, neterr = self._request(
            "GET", f"{self.files_url}{endpoint}", params=params
        )
        if neterr:
            return {"kind": "transient", "status_code": 0, "message": neterr}
        sc = resp.status_code
        ctype = resp.headers.get("content-type", "")
        if sc == 400:
            return {"kind": "config", "status_code": sc, "message": self._message(resp)}
        if sc == 401:
            msg = self._message(resp)
            if "not found" in msg.lower():
                return {
                    "kind": "end_of_feed",
                    "status_code": sc,
                    "records": [],
                    "raw_count": 0,
                    "is_end": True,
                    "message": "End of feed.",
                }
            return {"kind": "auth", "status_code": sc, "message": msg}
        if sc in (403, 413):
            return {
                "kind": "subscription",
                "status_code": sc,
                "message": self._message(resp),
            }
        if "application/json" in ctype:
            return {"kind": "error", "status_code": sc, "message": self._message(resp)}
        if sc == 429 or sc >= 500:
            return {
                "kind": "transient",
                "status_code": sc,
                "message": self._message(resp),
            }
        if sc != 200:
            return {"kind": "error", "status_code": sc, "message": self._message(resp)}
        records, raw_count, is_header_only = self.parse_stream_text(
            resp.text, feed_type, whois
        )
        is_end = is_header_only or raw_count < limit
        return {
            "kind": "data",
            "status_code": sc,
            "records": records,
            "raw_count": raw_count,
            "is_end": is_end,
            "response_text": resp.text,
        }

    def execute_lookup(
        self, action_name: str, inputs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a real-time lookup and classify the result (lookup-host semantics)."""
        cfg = LOOKUP_CONFIG.get(action_name)
        if not cfg:
            return {
                "kind": "config",
                "status_code": 0,
                "message": f"Unknown lookup action '{action_name}'.",
            }
        params: Dict[str, Any] = {}
        body: Dict[str, Any] = {}
        for key, value in (inputs or {}).items():
            if value is None or value == "" or value == []:
                continue
            if key in cfg["body"]:
                body[key] = value
            else:
                params[key] = value
        resp, neterr = self._request(
            cfg["method"],
            f"{self.api_url}{cfg['endpoint']}",
            params=params or None,
            json_body=body or None,
        )
        if neterr:
            return {"kind": "transient", "status_code": 0, "message": neterr}
        return self._classify_lookup(resp)

    def _classify_lookup(self, resp: requests.Response) -> Dict[str, Any]:
        sc = resp.status_code
        ctype = resp.headers.get("content-type", "")
        json_body: Any = None
        text: Optional[str] = None
        if "application/json" in ctype:
            try:
                json_body = resp.json()
            except Exception:
                text = resp.text
        else:
            text = resp.text
        kind_map = {
            (400): "config",
            (401): "auth",
            (403): "forbidden",
            (404): "not_found",
            (408): "transient",
            (412): "plan_limit",
            (413): "quota",
            (423): "reserved_ip",
            (429): "rate_limited",
        }
        if sc in (200, 206, 210):
            kind = "data"
        elif sc in kind_map:
            kind = kind_map[sc]
        elif sc >= 500:
            kind = "server_error"
        else:
            kind = "error"
        return {
            "kind": kind,
            "status_code": sc,
            "message": self._message(resp, json_body),
            "json_body": json_body,
            "response_text": text,
        }
