"""Status fetch + status-first date resolution."""
from helpers import core, make_resp, session_returning

STATUS_JSON = {
    "newly": {
        "gtld": {"last_update": "2026-10-29", "available_from": "2026-07-29"},
        "cctld": {"last_update": "2026-10-29", "available_from": "2026-07-28"},
    },
    "threat_feed": {
        "phishing": {"last_update": "2026-10-30", "available_from": "2026-07-29"},
        "malware": {"last_update": "2026-10-30", "available_from": "2026-07-29"},
        "spam": {"last_update": "Not Available", "available_from": "Not Available"},
    },
}


def test_fetch_status_ok():
    c = core(session_returning(make_resp(200, json_data=STATUS_JSON)))
    res = c.fetch_status()
    assert res["ok"] is True
    assert res["json"]["threat_feed"]["phishing"]["last_update"] == "2026-10-30"


def test_fetch_status_http_error_surfaced():
    c = core(session_returning(make_resp(403, text="Forbidden")))
    res = c.fetch_status()
    assert res["ok"] is False
    assert res["status_code"] == 403


def test_resolve_within_window():
    date, warn = core(None).resolve_feed_date(STATUS_JSON, "phishing", "2026-08-15")
    assert date == "2026-08-15"
    assert warn is None


def test_resolve_outside_window_falls_back():
    date, warn = core(None).resolve_feed_date(STATUS_JSON, "phishing", "2025-01-01")
    assert date == "2026-10-30"
    assert warn and "outside" in warn


def test_resolve_no_date_uses_last_update():
    date, warn = core(None).resolve_feed_date(STATUS_JSON, "gtld", None)
    assert date == "2026-10-29"
    assert warn is None


def test_resolve_unavailable_feed():
    date, reason = core(None).resolve_feed_date(STATUS_JSON, "spam", None)
    assert date is None
    assert "no available data" in reason


def test_resolve_status_down_but_date_given():
    # status unavailable -> still honour an explicit caller date (do not block)
    date, warn = core(None).resolve_feed_date({}, "phishing", "2026-10-01")
    assert date == "2026-10-01"
    assert warn and "status unavailable" in warn


def test_resolve_status_down_no_date():
    date, reason = core(None).resolve_feed_date({}, "phishing", None)
    assert date is None
