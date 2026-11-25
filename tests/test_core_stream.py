"""Stream parsing, host-aware error classification, retry, offset integrity."""
from helpers import core, make_resp, session_returning

_COLS = (  # noqa: E501
    "domain,threat_type,confidence,first_seen,last_seen,is_seed,"
    "is_extrapolated,is_dropped,is_parked,parked_reason,matched_pivots"
)
PHISHING_CSV = (
    _COLS + ",custom_asn\n"
    "phish1.com,phishing,1.0,2026-10-11,2026-10-12,t,f,f,,,email:a@b.com,AS12345\n"
    "phish2.com,phishing,HIGH,2026-10-11,2026-10-12,t,t,f,f,,mx:mail.phish2.com,AS67890\n"
)
NRD_DOMAINS = "domain1.com.cn\ndomain2.ca\ndomain3.co.in\n"
HEADER_ONLY = _COLS + "\n"


def test_parse_threat_csv_lossless_no_crash_on_bad_confidence():
    # 'HIGH' is not numeric; must NOT raise (FUNC-003) and must be preserved.
    records, raw, header_only = core(None).parse_stream_text(PHISHING_CSV, "threat", False)
    assert raw == 2 and len(records) == 2 and header_only is False
    assert records[1]["confidence"] == "HIGH"
    assert records[0]["custom_asn"] == "AS12345"  # unknown column preserved (lossless)


def test_parse_nrd_plaintext():
    records, raw, header_only = core(None).parse_stream_text(NRD_DOMAINS, "nrd", False)
    assert raw == 3 and len(records) == 3
    assert records[0]["domain_name"] == "domain1.com.cn"


def test_parse_header_only_is_end():
    records, raw, header_only = core(None).parse_stream_text(HEADER_ONLY, "threat", False)
    assert records == [] and raw == 0 and header_only is True


def test_offset_counts_server_rows_not_filtered():
    """FUNC-002: raw_count reflects rows the server returned, not post-filter rows.
    A blank line and a '#' comment among 3 domains => 5 physical lines returned."""
    text = "aaa.com\n\nbbb.com\n# comment\nccc.com\n"
    records, raw, header_only = core(None).parse_stream_text(text, "nrd", False)
    assert len(records) == 3          # domains kept
    assert raw == 4                    # non-empty physical lines (incl '# comment')
    # page of 4 server rows with limit 5 => short page => end of feed
    c = core(session_returning(make_resp(200, text=text, content_type="text/plain")))
    res = c.fetch_stream_page("gtld", "2026-09-14", offset=0, limit=5)
    assert res["kind"] == "data" and res["raw_count"] == 4 and res["is_end"] is True


def test_fetch_page_data_full_page_not_end():
    c = core(session_returning(make_resp(200, text=PHISHING_CSV, content_type="text/csv")))
    res = c.fetch_stream_page("phishing", "2026-10-12", offset=0, limit=2)
    assert res["kind"] == "data"
    assert len(res["records"]) == 2 and res["raw_count"] == 2
    assert res["is_end"] is False  # raw_count == limit


def test_401_record_not_found_is_end_of_feed():
    """FUNC-001: on the stream host, 401 'Api record not found' = end of feed."""
    err = {"status": 401, "error": "Api Access Exception",
           "message": "Api record not found. [For Technical Support: support@whoisfreaks.com]"}
    c = core(session_returning(make_resp(401, json_data=err)))
    res = c.fetch_stream_page("malware", "2026-09-30", offset=4490557, limit=10)
    assert res["kind"] == "end_of_feed"
    assert res["is_end"] is True and res["records"] == []


def test_401_without_not_found_is_auth():
    err = {"status": 401, "message": "Provided API key is invalid."}
    c = core(session_returning(make_resp(401, json_data=err)))
    res = c.fetch_stream_page("malware", "2026-09-30", offset=0, limit=10)
    assert res["kind"] == "auth"


def test_413_is_subscription():
    err = {"status": 413, "message": "Please upgrade your plans.This Plan does not have the access to download file."}
    c = core(session_returning(make_resp(413, json_data=err)))
    res = c.fetch_stream_page("malware", "2026-10-10", offset=0, limit=10)
    assert res["kind"] == "subscription"
    assert "upgrade your plans" in res["message"]


def test_400_is_config():
    err = {"status": 400, "message": "Please provide the date parameter (YYYY-MM-DD)"}
    c = core(session_returning(make_resp(400, json_data=err)))
    res = c.fetch_stream_page("phishing", "", offset=0, limit=10)
    assert res["kind"] == "config"


def test_retry_429_then_200():
    r429 = make_resp(429, text="Rate Limited", content_type="text/plain")
    r200 = make_resp(200, text=PHISHING_CSV, content_type="text/csv")
    c = core(session_returning(r429, r200))
    res = c.fetch_stream_page("spam", "2026-10-12", offset=0, limit=2)
    assert res["kind"] == "data" and len(res["records"]) == 2


def test_retry_500_exhausted_is_transient():
    r500 = make_resp(500, text="Server Error", content_type="text/plain")
    c = core(session_returning(r500, r500, r500), max_retries=2)
    res = c.fetch_stream_page("malware", "2026-10-12", offset=0, limit=2)
    assert res["kind"] == "transient" and res["status_code"] == 500
