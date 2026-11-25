"""WhoisFreaks Swimlane Turbine connector runner.

Thin adapter over :mod:`whoisfreaks_core`. It wires the Turbine-provided session
and asset configuration into the (SDK-independent, unit-tested) core and maps the
core's structured results onto Turbine action outputs. All real logic lives in the
core so that the shipped runtime and the tested code are the same code.
"""
import logging
import os
import sys
from typing import Any, Dict
from connector_definition_runner import Runner
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from whoisfreaks_core import DEFAULT_API_URL, DEFAULT_FILES_URL, DEFAULT_PAGE_LIMIT, FEED_ALIASES, LOOKUP_CONFIG, MAX_INGEST_PAGES, MAX_INGEST_RECORDS, STREAM_ACTIONS, STREAM_FEEDS, WhoisFreaksCore
logger = logging.getLogger('whoisfreaks')
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [whoisfreaks] %(message)s'))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)


class RunnerOverride(Runner):
    """Custom Turbine definition runner for WhoisFreaks feeds and lookups."""

    def __init__(self, asset: Dict[str, Any], asset_schema: Dict[str, Any],
        http_proxy=None):
        super().__init__(asset, asset_schema, http_proxy)
        self._asset = asset or {}

    def _core(self) ->WhoisFreaksCore:
        asset = self._asset
        files_url = asset.get('url') or getattr(self, 'url', None
            ) or DEFAULT_FILES_URL
        api_url = asset.get('api_url') or DEFAULT_API_URL
        verify_ssl = asset.get('verify_ssl', True)
        if verify_ssl is None:
            verify_ssl = True
        return WhoisFreaksCore(session=self.session, files_url=files_url,
            api_url=api_url, api_key=asset.get('X-API-KEY'), verify_ssl=
            bool(verify_ssl), logger=logger)

    def run(self, inputs: Dict[str, Any], action_schema: Dict[str, Any]
        ) ->Dict[str, Any]:
        """Main action handler called by Turbine."""
        action_name = action_schema.get('name', '')
        core = self._core()
        if action_name == 'get_feed_status':
            return self._run_status(core)
        if action_name == 'ingest_stream_feeds':
            return self._run_ingest(core, inputs or {})
        if action_name in STREAM_ACTIONS:
            return self._run_stream(core, action_name, inputs or {})
        if action_name in LOOKUP_CONFIG:
            return self._run_lookup(core, action_name, inputs or {})
        return super().run(inputs, action_schema)

    def _run_status(self, core: WhoisFreaksCore) ->Dict[str, Any]:
        res = core.fetch_status()
        if not res['ok']:
            return {'status_code': res['status_code'], 'reason':
                'Failed to fetch feed status.', 'error': True,
                'error_message': res['message'], 'json_body': {}}
        return {'status_code': 200, 'reason':
            'Availability windows for every data product.', 'json_body':
            res['json']}

    def _run_stream(self, core: WhoisFreaksCore, action_name: str, inputs:
        Dict[str, Any]) ->Dict[str, Any]:
        feed_key, _feed_type = STREAM_ACTIONS[action_name]
        params = inputs.get('parameters') or {}
        requested_date = params.get('date')
        status = core.fetch_status()
        resolved_date, warn = core.resolve_feed_date(status.get('json', {}),
            feed_key, requested_date)
        if not resolved_date:
            return {'status_code': 200, 'reason': warn or
                'Feed is not currently available.', 'response_text': '',
                'records_count': 0, 'has_more': False, 'is_end_of_feed': True}
        offset = params.get('offset') or 0
        limit = params.get('limit') or DEFAULT_PAGE_LIMIT
        whois = bool(params.get('whois', False))
        res = core.fetch_stream_page(feed_key, resolved_date, offset, limit,
            whois)
        kind = res['kind']
        if kind == 'data':
            out = {'status_code': res['status_code'], 'reason':
                'One page of feed records.', 'response_text': res[
                'response_text'], 'records_count': len(res['records']),
                'has_more': not res['is_end'], 'is_end_of_feed': res[
                'is_end'], 'date_used': resolved_date, 'next_offset': 
                offset + res['raw_count']}
            if warn:
                out['date_warning'] = warn
            return out
        if kind == 'end_of_feed':
            return {'status_code': res['status_code'], 'reason':
                'End of feed reached (no more records for this date).',
                'response_text': '', 'records_count': 0, 'has_more': False,
                'is_end_of_feed': True, 'date_used': resolved_date}
        subscription = kind == 'subscription'
        return {'status_code': res['status_code'], 'reason': res['message'],
            'error': True, 'error_kind': kind, 'subscription_error':
            subscription, 'error_message': 
            f"Subscription plan limit ({res['status_code']}): {res['message']}. Please verify your WhoisFreaks subscription covers this feed."
             if subscription else res['message'], 'response_text': '',
            'records_count': 0, 'has_more': False, 'is_end_of_feed': False}

    def _run_ingest(self, core: WhoisFreaksCore, inputs: Dict[str, Any]
        ) ->Dict[str, Any]:
        enabled = inputs.get('enabled_feeds') or ['phishing', 'malware', 'spam'
            ]
        requested_date = inputs.get('date')
        limit = inputs.get('limit') or DEFAULT_PAGE_LIMIT
        base_offset = inputs.get('offset') or 0
        whois = bool(inputs.get('nrd_whois', False))
        max_pages = inputs.get('max_pages')
        if not max_pages:
            max_pages = 1
        max_pages = min(int(max_pages), MAX_INGEST_PAGES)
        status = core.fetch_status()
        status_json = status.get('json', {})
        all_records = []
        feeds_summary: Dict[str, Any] = {}
        checkpoint: Dict[str, Any] = {}
        truncated = False
        for feed_name in enabled:
            feed_key = FEED_ALIASES.get(feed_name)
            if feed_key not in STREAM_FEEDS:
                feeds_summary[feed_name] = {'status': 'skipped', 'reason':
                    f"Unknown feed name '{feed_name}'."}
                continue
            resolved_date, warn = core.resolve_feed_date(status_json,
                feed_key, requested_date)
            if not resolved_date:
                feeds_summary[feed_name] = {'status': 'not_ready', 'reason':
                    warn or 'No date available.'}
                continue
            offset = base_offset
            feed_records = []
            pages = 0
            feed_status = 'success'
            error_message = None
            has_more = True
            while has_more and pages < max_pages:
                res = core.fetch_stream_page(feed_key, resolved_date,
                    offset, limit, whois)
                kind = res['kind']
                if kind == 'subscription':
                    feed_status = 'subscription_skipped'
                    error_message = res['message']
                    has_more = False
                    break
                if kind in ('config', 'auth', 'transient', 'error'):
                    feed_status = 'error'
                    error_message = res['message']
                    has_more = False
                    break
                if kind == 'end_of_feed':
                    has_more = False
                    break
                for rec in res['records']:
                    rec['_feed'] = feed_name
                    rec['_feed_date'] = resolved_date
                feed_records.extend(res['records'])
                pages += 1
                offset += res['raw_count']
                if res['is_end']:
                    has_more = False
                if len(all_records) + len(feed_records) >= MAX_INGEST_RECORDS:
                    truncated = True
                    has_more = False
            all_records.extend(feed_records)
            if feed_status == 'success':
                feeds_summary[feed_name] = {'status': 'success', 'date':
                    resolved_date, 'pages_fetched': pages,
                    'records_fetched': len(feed_records), 'has_more': 
                    has_more or truncated, 'next_offset': offset, 'warning':
                    warn}
            else:
                feeds_summary[feed_name] = {'status': feed_status,
                    'error_message': error_message, 'date': resolved_date}
            checkpoint[feed_name] = {'date': resolved_date, 'next_offset':
                offset}
        return {'status_code': 200, 'status': 'success', 'total_records':
            len(all_records), 'truncated': truncated, 'feeds_summary':
            feeds_summary, 'records': all_records, 'checkpoint': checkpoint}

    def _run_lookup(self, core: WhoisFreaksCore, action_name: str, inputs:
        Dict[str, Any]) ->Dict[str, Any]:
        res = core.execute_lookup(action_name, inputs)
        kind = res['kind']
        out: Dict[str, Any] = {'status_code': res['status_code'], 'reason':
            res.get('message') or kind}
        if kind == 'data':
            out['success'] = True
            json_body = res.get('json_body')
            if action_name == 'account_usage' and isinstance(json_body, dict
                ) and 'apiKey' in json_body:
                json_body = dict(json_body)
                json_body['apiKey'] = '***redacted***'
            if res.get('response_text') is not None:
                out['response_text'] = res['response_text']
            else:
                out['json_body'] = json_body
            return out
        out['success'] = False
        out['error'] = True
        out['error_kind'] = kind
        out['error_message'] = res.get('message')
        if res.get('json_body') is not None:
            out['json_body'] = res['json_body']
        return out
