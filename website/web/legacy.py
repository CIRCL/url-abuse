#!/usr/bin/env python3

'''API v1 routes, same requests and answers as before the rebuild
(doc/api/v1.md, checked by tests/contract). Documented in the Swagger
description as "API v1 (legacy)"; new clients: API v2.'''

from __future__ import annotations

import json

from typing import Any

from flask import Response, current_app, redirect, render_template, request, url_for
from flask_restx import Namespace, Resource, fields  # type: ignore[import-untyped]

from urlabuse.report import ReportsDisabled

from .helpers import client_ip, get_legacy, get_reports

api = Namespace('API v1 (legacy)', path='/',
                description='The endpoints of URL Abuse before the rebuild, kept unchanged for existing '
                            'clients (pyurlabuse, scripts). Every check returns a job id as plain text, '
                            'to poll with GET /_result/{job_id}. New clients: use API v2.')

url_input = api.model('V1Url', {'url': fields.String(required=True, example='http://example.com/')})
query_input = api.model('V1Query', {'query': fields.String(required=True, example='http://example.com/')})
cache_input = api.model('V1Cache', {
    'query': fields.String(required=True, example='http://example.com/'),
    'digest': fields.Boolean(default=False, description='Add the text digest, abuse e-mails and ASNs'),
})

JOB_DOC = 'Returns a job id (text/plain); poll GET /_result/{job_id} for the result.'
NOT_CONFIGURED_DOC = ('Returns an empty body: this source is not set up on this instance '
                      '(not ported yet, or no credentials). v2: POST /api/v2/providers/{name}/query.')


def _body() -> dict[str, Any]:
    # Like before: the Content-Type is not checked
    return request.get_json(force=True, silent=True) or {}


def _text(value: str) -> Response:
    return Response(value, mimetype='text/html')


def _json(data: Any, status: int=200) -> Response:
    return Response(json.dumps(data), status=status, mimetype='application/json')


def _job_route(path: str, method: str, model: Any, field: str, param: str, doc: str, v2: str) -> None:
    @api.route(f'/{path}', endpoint=f'v1_{path}')
    class Job(Resource):  # type: ignore[misc]
        @api.doc(description=f'{doc} {JOB_DOC} v2: {v2}.')
        @api.expect(model)
        @api.response(200, 'Job id (text)')
        def post(self) -> Response:
            return _text(get_legacy().create(method, **{param: str(_body().get(field, ''))}))


_job_route('urls', 'url_list', url_input, 'url', 'url',
           'Redirect chain of the URL (from the Lookyloo capture). Result: list of URLs.', 'POST /api/v2/providers/lookyloo/query (data.redirects)')
_job_route('resolve', 'dns_resolve', url_input, 'url', 'url',
           'Addresses of the host of the URL. Result: [IPv4 list or null, IPv6 list or null].', 'POST /api/v2/providers/dns/query')
_job_route('lookyloo', 'lookyloo', url_input, 'url', 'url',
           'Captures the URL in Lookyloo. Result: permalink of the capture, or null.', 'POST /api/v2/providers/lookyloo/query (data.permalink)')
_job_route('bgpranking', 'bgpranking', query_input, 'query', 'ip',
           'Network of an IP. Result: [asn, prefix, asn_description, rank, position, total_known_asns].', 'POST /api/v2/providers/bgpranking/query')
_job_route('whois', 'whois', query_input, 'query', 'query',
           'Abuse contacts of a URL or IP. Result: list of e-mails, or null.', 'POST /api/v2/providers/whois/query (when ported)')


@api.route('/start', endpoint='v1_start')
class Start(Resource):  # type: ignore[misc]
    @api.doc(description='Checks that the URL can be analysed and counts the submission (a URL submitted '
                         'many times in a day is reported to CIRCL automatically). Result: '
                         '[true, normalised URL, null] or [false, URL, reason]. ' + JOB_DOC + ' v2: POST /api/v2/validate.')
    @api.expect(url_input)
    @api.response(200, 'Job id (text)')
    def post(self) -> Response:
        url = str(_body().get('url', ''))
        reports = get_reports()
        if reports.should_autosend(reports.count_submission(url)):
            try:
                reports.send(url, auto=True)
            except Exception:
                # A mail server outage must not prevent the check itself
                current_app.logger.exception('Automatic report failed')
        return _text(get_legacy().create('is_valid_url', url=url))


# v1 checks of sources that are not ported (yet): "not configured" (empty body)
NOT_CONFIGURED = ('phishtank', 'virustotal_report', 'googlesafebrowsing', 'eupi',
                  'pdnscircl', 'psslcircl', 'urlquery', 'ticket')


def _not_configured_route(path: str) -> None:
    @api.route(f'/{path}', endpoint=f'v1_{path}')
    class NotConfigured(Resource):  # type: ignore[misc]
        @api.doc(description=NOT_CONFIGURED_DOC)
        @api.expect(query_input)
        @api.response(200, 'Empty body')
        def post(self) -> Response:
            return _text('')


for _path in NOT_CONFIGURED:
    _not_configured_route(_path)


@api.route('/_result/<string:job_id>', endpoint='v1_result')
@api.doc(params={'job_id': 'Job id returned by a check'})
class Result(Resource):  # type: ignore[misc]
    @api.doc(description='Result of a job: 202 "Nay!" while it runs, 200 with the JSON result when it is '
                         'done (the job is then deleted), 200 null for an unknown job. v2: GET /api/v2/queries/{uuid}.')
    @api.response(200, 'The result, or null')
    @api.response(202, '"Nay!": not done yet')
    def get(self, job_id: str) -> Response:
        status, data = get_legacy().result(job_id)
        return _json(data, status)


@api.route('/get_cache', endpoint='v1_get_cache')
class GetCache(Resource):  # type: ignore[misc]
    @api.doc(description='Everything known about the URL and each URL of its chain (from the cached answers), '
                         'and with digest the text sent to CIRCL. v2: POST /api/v2/cached.')
    @api.expect(cache_input)
    def post(self) -> Response:
        body = _body()
        return _json(get_legacy().cached(str(body.get('query', '')), bool(body.get('digest', False))))


@api.route('/submit', endpoint='v1_submit')
class Submit(Resource):  # type: ignore[misc]
    @api.doc(description='Sends the report of the URL to CIRCL (at most once a day per host). '
                         'Answers the home page; 503 when reports are not enabled on this instance. v2: POST /api/v2/report.')
    @api.expect(url_input)
    @api.response(503, 'Reports are not enabled')
    def post(self) -> Response:
        try:
            get_reports().send(str(_body().get('url', '')), client_ip(request))
        except ReportsDisabled as e:
            return _json({'status': 503, 'error': 'Service Unavailable', 'message': str(e)}, 503)
        return _text(render_template('index.html'))


@api.route('/urlreport', endpoint='v1_urlreport')
@api.doc(params={'url': {'description': 'URL to show', 'in': 'query'}})
class URLReport(Resource):  # type: ignore[misc]
    @api.doc(description='Report page of a URL: redirects to the home page, which checks it. v2: POST /api/v2/analyse.')
    @api.response(302, 'Redirect to /?url=…')
    def get(self) -> Any:
        url = request.args.get('url')
        return redirect(url_for('index', url=url) if url else url_for('index'))
