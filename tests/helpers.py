"""Shared test helpers: path wiring + mock HTTP responses."""
import os
import sys
from unittest.mock import MagicMock

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "connector", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import whoisfreaks_core as wf  # noqa: E402


def make_resp(status=200, *, json_data=None, text="", content_type="application/json",
              reason="OK", retry_after=None):
    r = MagicMock()
    r.status_code = status
    headers = {"content-type": content_type}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    r.headers = headers
    r.reason = reason
    r.text = text
    if json_data is _NO_JSON:
        r.json.side_effect = ValueError("no json")
    else:
        r.json.return_value = json_data if json_data is not None else {}
    return r


class _NoJson:
    pass


_NO_JSON = _NoJson()


def session_returning(*responses):
    """A mock session whose .request returns the given responses in order
    (or repeats the single response)."""
    s = MagicMock()
    if len(responses) == 1:
        s.request.return_value = responses[0]
    else:
        s.request.side_effect = list(responses)
    return s


def core(session, **kw):
    kw.setdefault("api_key", "test-key")
    kw.setdefault("backoff_base", 0)
    kw.setdefault("max_retries", 2)
    return wf.WhoisFreaksCore(session=session, **kw)
