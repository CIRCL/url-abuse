#!/usr/bin/env python3

'''URL Abuse website: the web page and the API (Swagger at /doc).

The v2 API (the broker) lives in genericapi.py; the v1 endpoints come back in
roadmap step 7 (doc/ROADMAP.md).'''

from __future__ import annotations

from importlib.metadata import version

from flask import Flask, render_template
from flask_restx import Api  # type: ignore[import-untyped]

from .genericapi import api as generic_api
from .proxied import ReverseProxied

app: Flask = Flask(__name__)
app.wsgi_app = ReverseProxied(app.wsgi_app)  # type: ignore[method-assign]
app.config['RESTX_MASK_SWAGGER'] = False

pkg_version = version('urlabuse')


@app.route('/', methods=['GET', 'HEAD'])
def index() -> str:
    return render_template('index.html')


api = Api(app, title='URL Abuse API',
          description='API broker for URLs: send a URL, get the answers of every provider.',
          doc='/doc/', version=pkg_version)
api.add_namespace(generic_api)
