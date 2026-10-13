#!/usr/bin/env python3

'''API v1 routes, same requests and answers as before the rebuild
(doc/api/v1.md, checked by tests/contract). New clients: API v2.'''

from __future__ import annotations

import json

from typing import Any

from flask import Blueprint, Response, current_app, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue

from urlabuse.report import ReportsDisabled

from .helpers import client_ip, get_legacy, get_reports

v1 = Blueprint('v1', __name__)

# v1 checks of sources that are not ported (yet): "not configured" (empty body)
NOT_CONFIGURED = ('phishtank', 'virustotal_report', 'googlesafebrowsing', 'eupi',
                  'pdnscircl', 'psslcircl', 'urlquery', 'ticket')


def _body() -> dict[str, Any]:
    # Like before: the Content-Type is not checked
    return request.get_json(force=True, silent=True) or {}


def _json(data: Any, status: int=200) -> Response:
    return Response(json.dumps(data), status=status, mimetype='application/json')


@v1.route('/start', methods=['POST'])
def start() -> str:
    url = str(_body().get('url', ''))
    reports = get_reports()
    if reports.should_autosend(reports.count_submission(url)):
        try:
            reports.send(url, auto=True)
        except Exception:
            # A mail server outage must not prevent the check itself
            current_app.logger.exception('Automatic report failed')
    return get_legacy().create('is_valid_url', url=url)


@v1.route('/urls', methods=['POST'])
def urls() -> str:
    return get_legacy().create('url_list', url=str(_body().get('url', '')))


@v1.route('/resolve', methods=['POST'])
def resolve() -> str:
    return get_legacy().create('dns_resolve', url=str(_body().get('url', '')))


@v1.route('/lookyloo', methods=['POST'])
def lookyloo() -> str:
    return get_legacy().create('lookyloo', url=str(_body().get('url', '')))


@v1.route('/bgpranking', methods=['POST'])
def bgpranking() -> str:
    return get_legacy().create('bgpranking', ip=str(_body().get('query', '')))


@v1.route('/whois', methods=['POST'])
def whois() -> str:
    return get_legacy().create('whois', query=str(_body().get('query', '')))


def _not_configured() -> str:
    return ''


for _name in NOT_CONFIGURED:
    v1.add_url_rule(f'/{_name}', f'not_configured_{_name}', _not_configured, methods=['POST'])


@v1.route('/_result/<job_id>', methods=['GET'])
def result(job_id: str) -> Response:
    status, data = get_legacy().result(job_id)
    return _json(data, status)


@v1.route('/get_cache', methods=['POST'])
def get_cache() -> Response:
    body = _body()
    return _json(get_legacy().cached(str(body.get('query', '')), bool(body.get('digest', False))))


@v1.route('/submit', methods=['POST'])
def submit() -> ResponseReturnValue:
    try:
        get_reports().send(str(_body().get('url', '')), client_ip(request))
    except ReportsDisabled as e:
        return _json({'status': 503, 'error': 'Service Unavailable', 'message': str(e)}, 503)
    return render_template('index.html')


@v1.route('/urlreport', methods=['GET'])
def urlreport() -> ResponseReturnValue:
    # The report is the home page now: it checks ?url= when it loads
    url = request.args.get('url')
    return redirect(url_for('index', url=url) if url else url_for('index'))
