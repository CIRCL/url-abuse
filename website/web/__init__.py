#!/usr/bin/env python3

'''URL Abuse website: the web page and the API (Swagger at /doc).

The v2 API (the broker) lives in genericapi.py; the v1 endpoints come back in
roadmap step 7 (doc/ROADMAP.md).'''

from __future__ import annotations

from importlib.metadata import version

from flask import Flask, jsonify, render_template, request
from flask.typing import ResponseReturnValue
from werkzeug.exceptions import HTTPException, InternalServerError
from flask_restx import Api  # type: ignore[import-untyped]

from .credits_data import CREDITS
from .genericapi import api as generic_api
from .helpers import get_reports
from .legacy import api as legacy_api
from .proxied import ReverseProxied

app: Flask = Flask(__name__)
app.wsgi_app = ReverseProxied(app.wsgi_app)  # type: ignore[method-assign]
app.config['RESTX_MASK_SWAGGER'] = False

pkg_version = version('urlabuse')


@app.context_processor
def inject_layout() -> dict[str, object]:
    return {'urlabuse_version': pkg_version, 'report_enabled': get_reports().enabled}


@app.route('/', methods=['GET', 'HEAD'])
def index() -> str:
    return render_template('index.html')


@app.route('/api', methods=['GET'])
def api_page() -> str:
    return render_template('api.html')


@app.route('/credits', methods=['GET'])
def credits() -> str:
    return render_template('credits.html', credits=CREDITS)


# Error pages: JSON under /api/ (and for clients that only accept JSON), the
# error page otherwise. Doc: doc/api/v2.md (errors)
ERROR_MESSAGES = {
    404: ('This page doesn\'t exist.', 'The address may be mistyped, or the page was removed.'),
    405: ('This method is not allowed here.', 'This address exists, but not for this kind of request.'),
    500: ('Something went wrong on our side.', 'The error was logged. Try again in a moment.'),
}


def _wants_json() -> bool:
    if request.path.startswith('/api/'):
        return True
    best = request.accept_mimetypes.best_match(['text/html', 'application/json'])
    return best == 'application/json'


@app.errorhandler(HTTPException)
def http_error(error: HTTPException) -> ResponseReturnValue:
    code = error.code or 500
    title, message = ERROR_MESSAGES.get(code, (error.name, error.description or ''))
    if _wants_json():
        return jsonify({'status': code, 'error': error.name, 'message': error.description}), code
    return render_template('error.html', code=code, title=title, message=message), code


@app.errorhandler(Exception)
def unhandled_error(error: Exception) -> ResponseReturnValue:
    app.logger.exception('Unhandled error')
    return http_error(InternalServerError())


api = Api(app, title='URL Abuse API',
          description='API broker for URLs: send a URL, get the answers of every provider.',
          doc='/doc/', version=pkg_version)
api.add_namespace(generic_api)
api.add_namespace(legacy_api)
