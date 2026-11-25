"""Real-time lookups: request shaping + lookup-host error classification."""
from helpers import core, make_resp, session_returning


def test_live_whois_get_query_params_on_api_host():
    s = session_returning(make_resp(200, json_data={"domain_name": "whoisfreaks.com"}))
    res = core(s, api_url="https://api.whoisfreaks.com").execute_lookup(
        "live_whois", {"domainName": "whoisfreaks.com", "format": "json"}
    )
    method, url = s.request.call_args.args
    kwargs = s.request.call_args.kwargs
    assert method == "GET"
    assert url == "https://api.whoisfreaks.com/v2.0/whois/live"
    assert kwargs["params"] == {"domainName": "whoisfreaks.com", "format": "json"}
    assert kwargs["json"] is None
    assert kwargs["headers"]["X-API-KEY"] == "test-key"
    assert res["kind"] == "data"
    assert res["json_body"]["domain_name"] == "whoisfreaks.com"


def test_bulk_whois_sends_json_body():
    s = session_returning(make_resp(200, json_data=[{"domain_name": "a.com"}]))
    core(s).execute_lookup("bulk_whois", {"domainNames": ["a.com", "b.com"], "format": "json"})
    method, url = s.request.call_args.args
    kwargs = s.request.call_args.kwargs
    assert method == "POST"
    assert url.endswith("/v2.0/bulkwhois/live")
    assert kwargs["json"] == {"domainNames": ["a.com", "b.com"]}
    assert kwargs["params"] == {"format": "json"}  # format stays a query param


def test_bulk_dns_splits_body_and_query():
    s = session_returning(make_resp(200, json_data={}))
    core(s).execute_lookup("bulk_dns", {"domainNames": ["a.com"], "type": "all", "cname_depth": 1})
    kwargs = s.request.call_args.kwargs
    assert kwargs["json"] == {"domainNames": ["a.com"]}
    assert kwargs["params"] == {"type": "all", "cname_depth": 1}


def test_empty_inputs_filtered():
    s = session_returning(make_resp(200, json_data={}))
    core(s).execute_lookup("reverse_whois", {"keyword": "acme", "email": "", "owner": None, "company": []})
    assert s.request.call_args.kwargs["params"] == {"keyword": "acme"}


def test_lookup_401_is_auth_not_end_of_feed():
    """Host-aware: on the lookup host 401 means invalid key (NOT end of feed)."""
    s = session_returning(make_resp(401, json_data={"status": 401, "message": "Provided API key is invalid."}))
    res = core(s).execute_lookup("live_whois", {"domainName": "x.com"})
    assert res["kind"] == "auth" and res["status_code"] == 401


def test_lookup_404_not_found():
    s = session_returning(make_resp(404, json_data={"status": 404, "message": "No record found"}))
    res = core(s).execute_lookup("live_whois", {"domainName": "x.com"})
    assert res["kind"] == "not_found"


def test_lookup_423_reserved_ip():
    s = session_returning(make_resp(423, json_data={"status": 423, "message": "Reserved IP"}))
    res = core(s).execute_lookup("ip_geolocation", {"ip": "10.0.0.1"})
    assert res["kind"] == "reserved_ip"


def test_lookup_412_plan_and_413_quota():
    s1 = session_returning(make_resp(412, json_data={"message": "plan"}))
    assert core(s1).execute_lookup("asn_whois", {"asn": "as1"})["kind"] == "plan_limit"
    s2 = session_returning(make_resp(413, json_data={"message": "quota"}))
    assert core(s2).execute_lookup("asn_whois", {"asn": "as1"})["kind"] == "quota"


def test_lookup_rotate_returns_text():
    s = session_returning(make_resp(200, text="API Key Rotated Successfully! New API Key: abc",
                                    content_type="text/plain"))
    res = core(s).execute_lookup("rotate_api_key", {})
    assert res["kind"] == "data"
    assert res["json_body"] is None
    assert "New API Key" in res["response_text"]


def test_lookup_retry_on_408_then_success():
    r408 = make_resp(408, json_data={"message": "upstream timeout"})
    r200 = make_resp(200, json_data={"ok": True})
    res = core(session_returning(r408, r200)).execute_lookup("ip_security", {"ip": "8.8.8.8"})
    assert res["kind"] == "data"
