#!/usr/bin/env python3

'''What URL Abuse is built with, shown on /credits (templates/credits.html).
Add a line here when a library, font, service or provider is added.
Doc: doc/web.md'''

from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

VENDOR = Path(__file__).parent / 'static' / 'vendor'


@dataclass(frozen=True)
class Credit:
    name: str
    url: str
    license: str
    role: str
    package: str | None = None   # Python package: its installed version is shown
    vendor: str | None = None    # static/vendor/<name>/COMMIT (tools/3rdparty.py): pinned commit shown

    @property
    def version(self) -> str:
        if self.vendor:
            commit = VENDOR / self.vendor / 'COMMIT'
            return commit.read_text().strip()[:7] if commit.exists() else ''
        if not self.package:
            return ''
        try:
            return version(self.package)
        except PackageNotFoundError:
            return ''


CREDITS: dict[str, list[Credit]] = {
    'Backend': [
        Credit('Flask', 'https://flask.palletsprojects.com/', 'BSD-3-Clause', 'Web framework', 'flask'),
        Credit('Werkzeug', 'https://werkzeug.palletsprojects.com/', 'BSD-3-Clause', 'WSGI toolkit used by Flask', 'werkzeug'),
        Credit('Jinja', 'https://jinja.palletsprojects.com/', 'BSD-3-Clause', 'HTML templates', 'jinja2'),
        Credit('Flask-RESTX', 'https://github.com/python-restx/flask-restx', 'BSD-3-Clause', 'API and its Swagger description', 'flask-restx'),
        Credit('Gunicorn', 'https://gunicorn.org/', 'MIT', 'HTTP server', 'gunicorn'),
        Credit('redis-py', 'https://github.com/redis/redis-py', 'MIT', 'Database client', 'redis'),
        Credit('Requests', 'https://requests.readthedocs.io/', 'Apache-2.0', 'HTTP client', 'requests'),
        Credit('Valkey', 'https://valkey.io/', 'BSD-3-Clause', 'Database: jobs and cache'),
    ],
    'Interface': [
        Credit('Vitrine', 'https://github.com/ecrou-exact/vitrine', 'MIT', 'Web components of the API page (<vt-openapi>, <vt-http>, <vt-markdown>)',
               vendor='vitrine'),
        Credit('Swagger UI', 'https://swagger.io/tools/swagger-ui/', 'Apache-2.0', 'Interactive API documentation at /doc/ (shipped with Flask-RESTX)'),
        Credit('Schibsted Grotesk', 'https://github.com/schibsted/schibsted-grotesk', 'OFL-1.1', 'Interface font'),
        Credit('IBM Plex Mono', 'https://github.com/IBM/plex', 'OFL-1.1', 'Font of the data: URLs, IPs, hashes'),
    ],
    'Sources': [
        Credit('Lookyloo', 'https://www.lookyloo.eu/', 'BSD-3-Clause', 'Capture of the URL in a real browser: redirect chain'),
        Credit('PyLookyloo', 'https://github.com/Lookyloo/PyLookyloo', 'GPL-2.0-or-later', 'Lookyloo client', 'pylookyloo'),
        Credit('BGP Ranking', 'https://bgpranking-ng.circl.lu/', 'AGPL-3.0', 'Rank of the network (AS) of an IP, by CIRCL'),
        Credit('IP ASN History', 'https://ipasnhistory.circl.lu/', 'AGPL-3.0', 'ASN and prefix of an IP, by CIRCL'),
        Credit('pybgpranking2', 'https://github.com/D4-project/pybgpranking', 'BSD-3-Clause', 'BGP Ranking client', 'pybgpranking2'),
        Credit('pyipasnhistory', 'https://github.com/D4-project/pyipasnhistory', 'AGPL-3.0', 'IP ASN History client', 'pyipasnhistory'),
        Credit('dnspython', 'https://www.dnspython.org/', 'ISC', 'DNS resolution of the hosts', 'dnspython'),
    ],
}
