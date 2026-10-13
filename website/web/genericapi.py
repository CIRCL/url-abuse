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

from .helpers import client_ip, get_analyses, get_reports

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
