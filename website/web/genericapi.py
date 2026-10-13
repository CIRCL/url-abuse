#!/usr/bin/env python3

'''API v2 of URL Abuse, mounted at /api/v2 (doc/api/v2.md).'''

from __future__ import annotations

from importlib.metadata import version
from typing import Any

from flask import request
from flask_restx import Namespace, Resource, fields  # type: ignore[import-untyped]
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from urlabuse.analysis import InvalidURL, normalise_url
from urlabuse.default import get_socket_path
from urlabuse.report import ReportsDisabled

from urlabuse.queries import UnknownProvider

from .helpers import client_ip, get_analyses, get_legacy, get_queries, get_reports

api = Namespace('API v2', path='/api/v2',
                description='The URL broker: analyse a URL with every provider, list the providers, report to CIRCL.')


@api.route('/health')
@api.doc(description='Is the instance up, and is its database reachable?')
class Health(Resource):  # type: ignore[misc]

    def get(self) -> tuple[dict[str, Any], int]:
        try:
            db_up = bool(Redis(unix_socket_path=get_socket_path('cache')).ping())
        except RedisConnectionError:
            db_up = False
        return {'status': 'ok' if db_up else 'degraded', 'database': db_up,
                'version': version('urlabuse')}, 200 if db_up else 503


analyse_input = api.model('AnalyseInput', {
    'url': fields.String(required=True, description='URL to check. hxxp is accepted, http:// is added when there is no scheme.',
                         example='https://example.com/login'),
})
analyse_created = api.model('AnalyseCreated', {
    'uuid': fields.String(description='UUID of the analysis, to poll with GET /api/v2/analyse/{uuid}'),
    'url': fields.String(description='The URL as it is checked (normalised)'),
})


@api.route('/analyse')
class Analyse(Resource):  # type: ignore[misc]

    @api.doc(description='Start the analysis of a URL: capture in Lookyloo (redirect chain), then every '
                         'configured provider on each URL of the chain and on each IP of their hosts.')
    @api.expect(analyse_input, validate=True)
    @api.response(201, 'Analysis queued', analyse_created)
    @api.response(400, 'Invalid URL')
    def post(self) -> tuple[dict[str, Any], int]:
        try:
            url = normalise_url(str((request.get_json(silent=True) or {}).get('url', '')))
        except InvalidURL as e:
            return {'status': 400, 'error': 'Invalid URL', 'message': str(e)}, 400
        return {'uuid': get_analyses().create(url), 'url': url}, 201


@api.route('/analyse/<string:analysis_uuid>')
@api.doc(params={'analysis_uuid': 'UUID returned by POST /api/v2/analyse'})
class AnalyseResult(Resource):  # type: ignore[misc]

    @api.doc(description='State of an analysis: status (queued, running, done, failed), progress, the '
                         'Lookyloo capture, the redirect chain with the answer of every provider on each '
                         'URL and IP, and the overall verdict of the reputation providers. Poll it until '
                         'status is done or failed.')
    @api.response(200, 'The analysis')
    @api.response(404, 'Unknown (or expired) analysis')
    def get(self, analysis_uuid: str) -> tuple[dict[str, Any], int]:
        result = get_analyses().get(analysis_uuid)
        if result is None:
            return {'status': 404, 'error': 'Not Found', 'message': 'Unknown or expired analysis.'}, 404
        return result, 200


@api.route('/providers')
class ProvidersList(Resource):  # type: ignore[misc]

    @api.doc(description='Providers known by this instance, the kinds of values they take '
                         '(url, hostname, ip) and whether they are configured.')
    def get(self) -> list[dict[str, Any]]:
        return [{'name': p.name, 'label': p.label or p.name, 'description': p.description,
                 'accepts': sorted(k.value for k in p.accepts), 'reputation': p.reputation,
                 'configured': p.configured}
                for p in get_analyses().providers.all()]


report_result = api.model('ReportResult', {
    'sent': fields.Boolean(description='false when this host was already reported today'),
    'message': fields.String(),
})


@api.route('/report')
class Report(Resource):  # type: ignore[misc]

    @api.doc(description='Send the results of a URL to CIRCL analysts by e-mail (at most once a day per host). '
                         'Check the URL first: the report is built from the cached answers.')
    @api.expect(analyse_input, validate=True)
    @api.response(200, 'Sent, or already reported today', report_result)
    @api.response(400, 'Invalid URL')
    @api.response(503, 'Reports are not enabled on this instance')
    def post(self) -> tuple[dict[str, Any], int]:
        try:
            url = normalise_url(str((request.get_json(silent=True) or {}).get('url', '')))
        except InvalidURL as e:
            return {'status': 400, 'error': 'Invalid URL', 'message': str(e)}, 400
        try:
            sent = get_reports().send(url, client_ip(request))
        except ReportsDisabled as e:
            return {'status': 503, 'error': 'Service Unavailable', 'message': str(e)}, 503
        return {'sent': sent, 'message': 'Report sent to CIRCL.' if sent
                else 'This host was already reported to CIRCL today.'}, 200


validate_result = api.model('ValidateResult', {
    'valid': fields.Boolean(),
    'url': fields.String(description='The URL as it would be checked (normalised)'),
    'reason': fields.String(description='Why it can\'t be checked (when valid is false)'),
})


@api.route('/validate')
class Validate(Resource):  # type: ignore[misc]

    @api.doc(description='Can this URL be checked, and how is it normalised (trimmed, hxxp fixed, http:// added '
                         'when there is no scheme)? Answers at once, nothing is queued. v1: /start.')
    @api.expect(analyse_input, validate=True)
    @api.response(200, 'Validity', validate_result)
    def post(self) -> tuple[dict[str, Any], int]:
        raw = str((request.get_json(silent=True) or {}).get('url', ''))
        try:
            return {'valid': True, 'url': normalise_url(raw), 'reason': None}, 200
        except InvalidURL as e:
            return {'valid': False, 'url': raw, 'reason': str(e)}, 200


query_input = api.model('QueryInput', {
    'value': fields.String(required=True, description='URL, hostname or IP, depending on the provider',
                           example='https://example.com/'),
})
query_created = api.model('QueryCreated', {
    'uuid': fields.String(description='UUID of the query, to poll with GET /api/v2/queries/{uuid}'),
})


@api.route('/providers/<string:name>/query')
@api.doc(params={'name': 'Provider name (GET /api/v2/providers)'})
class ProviderQuery(Resource):  # type: ignore[misc]

    @api.doc(description='Ask one provider about one value (URL, hostname or IP). The answer is a ProviderResult '
                         '(doc/providers.md): status ok, not_configured, not_applicable or error, data, verdict, '
                         'links. v1: /urls and /lookyloo (lookyloo: data.redirects, data.permalink), /resolve (dns), '
                         '/bgpranking, /whois, /phishtank, /virustotal_report, /googlesafebrowsing, /eupi, '
                         '/pdnscircl, /psslcircl.')
    @api.expect(query_input, validate=True)
    @api.response(201, 'Query queued', query_created)
    @api.response(404, 'Unknown provider')
    def post(self, name: str) -> tuple[dict[str, Any], int]:
        value = str((request.get_json(silent=True) or {}).get('value', '')).strip()
        if not value:
            return {'status': 400, 'error': 'Bad Request', 'message': 'value is empty.'}, 400
        try:
            return {'uuid': get_queries().create(name, value)}, 201
        except UnknownProvider:
            return {'status': 404, 'error': 'Not Found', 'message': f'Unknown provider {name}.'}, 404


@api.route('/queries/<string:query_uuid>')
@api.doc(params={'query_uuid': 'UUID returned by POST /api/v2/providers/{name}/query'})
class QueryResult(Resource):  # type: ignore[misc]

    @api.doc(description='State of a provider query: status queued or done, and the result once done '
                         '(kept for a day, it can be read many times). v1: /_result/{job_id}.')
    @api.response(200, 'The query')
    @api.response(404, 'Unknown (or expired) query')
    def get(self, query_uuid: str) -> tuple[dict[str, Any], int]:
        result = get_queries().get(query_uuid)
        if result is None:
            return {'status': 404, 'error': 'Not Found', 'message': 'Unknown or expired query.'}, 404
        return result, 200


cached_input = api.model('CachedInput', {
    'url': fields.String(required=True, example='https://example.com/'),
    'digest': fields.Boolean(default=False, description='Add the text sent to CIRCL, the abuse contacts and the ASNs'),
})


@api.route('/cached')
class Cached(Resource):  # type: ignore[misc]

    @api.doc(description='Everything already known about a URL, from the cache, without querying anything: the '
                         'chain with the answers of every provider on each URL and IP (same shape as an analysis). '
                         'v1: /get_cache.')
    @api.expect(cached_input, validate=True)
    @api.response(400, 'Invalid URL')
    def post(self) -> tuple[dict[str, Any], int]:
        body = request.get_json(silent=True) or {}
        try:
            url = normalise_url(str(body.get('url', '')))
        except InvalidURL as e:
            return {'status': 400, 'error': 'Invalid URL', 'message': str(e)}, 400
        result = get_queries().cached(url)
        if body.get('digest'):
            text, contacts, asns = get_legacy().cached(url, digest=True)['digest']
            result['digest'] = {'text': text, 'abuse_contacts': contacts, 'asns': asns}
        return result, 200
