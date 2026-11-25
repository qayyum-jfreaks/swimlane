"""Exercise the SHIPPED RunnerOverride end-to-end with a stubbed Turbine SDK.

This closes ARCH-001: the connector's real runtime entry point is tested, not a
parallel library.
"""
import os
import sys
import types

from helpers import make_resp, session_returning

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "connector", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)

# Stub the Swimlane SDK base class before importing the runner.
_stub = types.ModuleType("connector_definition_runner")


class _BaseRunner:
    def __init__(self, asset, asset_schema, http_proxy=None):
        self.asset = asset
        self.asset_schema = asset_schema
        self.http_proxy = http_proxy
        self.session = None
        self.url = (asset or {}).get("url")

    def _join_url(self, base, path):
        return base.rstrip("/") + path

    def run(self, inputs, action_schema):
        return {"_base_run": True, "name": action_schema.get("name")}


_stub.Runner = _BaseRunner
sys.modules["connector_definition_runner"] = _stub

import runner_override  # noqa: E402

ASSET = {
    "url": "https://files.whoisfreaks.com",
    "api_url": "https://api.whoisfreaks.com",
    "X-API-KEY": "test-key",
    "verify_ssl": True,
}
STATUS_JSON = {
    "newly": {"gtld": {"last_update": "2026-10-29", "available_from": "2026-07-29"}},
    "threat_feed": {
        "phishing": {"last_update": "2026-10-30", "available_from": "2026-07-29"},
        "malware": {"last_update": "2026-10-30", "available_from": "2026-07-29"},
    },
}
PHISH_CSV = (
    "domain,threat_type,confidence,first_seen,last_seen,is_seed,"  # noqa: E501
    "is_extrapolated,is_dropped,is_parked,parked_reason,matched_pivots\n"
    "phish1.com,phishing,1.0,2026-10-11,2026-10-12,t,f,f,,,\n"
    "phish2.com,phishing,0.9,2026-10-11,2026-10-12,t,t,f,f,,\n"
)


def _runner(session):
    r = runner_override.RunnerOverride(ASSET, {}, None)
    r.session = session
    # keep retries/backoff fast for any transient paths
    orig = r._core

    def fast_core():
        c = orig()
        c.max_retries = 1
        c.backoff_base = 0
        return c
    r._core = fast_core
    return r


def test_status_action():
    r = _runner(session_returning(make_resp(200, json_data=STATUS_JSON)))
    out = r.run({}, {"name": "get_feed_status"})
    assert out["status_code"] == 200
    assert out["json_body"]["threat_feed"]["phishing"]["last_update"] == "2026-10-30"


def test_stream_action_data():
    status = make_resp(200, json_data=STATUS_JSON)
    page = make_resp(200, text=PHISH_CSV, content_type="text/csv")
    r = _runner(session_returning(status, page))
    out = r.run({"parameters": {"date": "2026-10-12", "limit": 2}}, {"name": "stream_threat_feed_phishing"})
    assert out["records_count"] == 2 and out["is_end_of_feed"] is False
    assert out["has_more"] is True and out["next_offset"] == 2


def test_stream_action_401_end_of_feed_not_subscription():
    status = make_resp(200, json_data=STATUS_JSON)
    end = make_resp(401, json_data={"status": 401, "message": "Api record not found."})
    r = _runner(session_returning(status, end))
    out = r.run({"parameters": {"date": "2026-10-12", "offset": 999999}}, {"name": "stream_threat_feed_malware"})
    assert out["is_end_of_feed"] is True
    assert out.get("subscription_error") in (None, False)
    assert "error" not in out


def test_stream_action_413_subscription_surfaced():
    status = make_resp(200, json_data=STATUS_JSON)
    sub = make_resp(413, json_data={"message": "Please upgrade your plans."})
    r = _runner(session_returning(status, sub))
    out = r.run({"parameters": {"date": "2026-10-12"}}, {"name": "stream_threat_feed_malware"})
    assert out["error"] is True and out["subscription_error"] is True


def test_ingest_multi_feed_subscription_skip_and_continue():
    status = make_resp(200, json_data=STATUS_JSON)
    phish = make_resp(200, text=PHISH_CSV, content_type="text/csv")
    sub = make_resp(413, json_data={"message": "Please upgrade your plans."})

    def route(method, url, **kw):
        if "phishing" in url:
            return phish
        if "status" in url:
            return status
        return sub
    s = session_returning(make_resp(200))  # placeholder
    s.request.side_effect = route
    r = _runner(s)
    out = r.run({"enabled_feeds": ["phishing", "malware"], "date": "2026-10-12", "limit": 2, "max_pages": 1},
                {"name": "ingest_stream_feeds"})
    assert out["status"] == "success"
    assert out["feeds_summary"]["phishing"]["status"] == "success"
    assert out["feeds_summary"]["phishing"]["records_fetched"] == 2
    assert out["feeds_summary"]["malware"]["status"] == "subscription_skipped"
    assert out["total_records"] == 2
    assert out["checkpoint"]["phishing"]["next_offset"] == 2


def test_ingest_max_pages_zero_coerced_to_one():
    status = make_resp(200, json_data=STATUS_JSON)
    # full page of 2 with limit 2 would normally continue; max_pages must cap to 1
    page = make_resp(200, text=PHISH_CSV, content_type="text/csv")
    s = session_returning(status, page, page, page)
    r = _runner(s)
    out = r.run({"enabled_feeds": ["phishing"], "date": "2026-10-12", "limit": 2, "max_pages": 0},
                {"name": "ingest_stream_feeds"})
    assert out["feeds_summary"]["phishing"]["pages_fetched"] == 1


def test_lookup_live_whois():
    s = session_returning(make_resp(200, json_data={"domain_name": "whoisfreaks.com", "domain_registered": "yes"}))
    r = _runner(s)
    out = r.run({"domainName": "whoisfreaks.com"}, {"name": "live_whois"})
    assert out["success"] is True
    assert out["json_body"]["domain_registered"] == "yes"
    _, url = s.request.call_args.args
    assert url == "https://api.whoisfreaks.com/v2.0/whois/live"


def test_lookup_ip_security_reserved_ip_error():
    s = session_returning(make_resp(423, json_data={"status": 423, "message": "Reserved/Private IP"}))
    r = _runner(s)
    out = r.run({"ip": "10.0.0.1"}, {"name": "ip_security"})
    assert out["success"] is False and out["error_kind"] == "reserved_ip"


def test_account_usage_redacts_apikey():
    s = session_returning(make_resp(200, json_data={"apiKey": "SECRET123", "credits": 100}))
    r = _runner(s)
    out = r.run({}, {"name": "account_usage"})
    assert out["json_body"]["apiKey"] == "***redacted***"
    assert out["json_body"]["credits"] == 100


def test_unknown_action_falls_through_to_base():
    r = _runner(session_returning(make_resp(200, json_data={})))
    out = r.run({}, {"name": "something_else"})
    assert out == {"_base_run": True, "name": "something_else"}
