#!/usr/bin/env python3

'''Lookyloo (PyLookyloo): captures the URL in a real browser. Gives the
capture permalink and the redirect chain (AGENTS.md decision 3).'''

from __future__ import annotations

import time

from pylookyloo import Lookyloo as PyLookyloo

from . import register
from .base import Kind, Provider, ProviderResult, Status

STATUS_UNKNOWN, STATUS_READY = -1, 1


@register
class Lookyloo(Provider):
    name = 'lookyloo'
    label = 'Lookyloo capture'
    description = 'Capture of the page in a real browser: redirect chain and permalink'
    accepts = frozenset({Kind.url})
    required_config = ('url',)
    cache_ttl = 6 * 3600

    def _query(self, value: str, kind: Kind) -> ProviderResult:
        lookyloo = PyLookyloo(self.config['url'])
        capture_uuid = lookyloo.submit(url=value, quiet=True, listing=bool(self.config.get('listing', False)))
        if not isinstance(capture_uuid, str):
            return ProviderResult(Status.error, error=f'Unexpected answer: {capture_uuid}')
        permalink = f'{lookyloo.root_url}tree/{capture_uuid}'
        deadline = time.monotonic() + int(self.config.get('timeout', 180))
        while True:
            status = lookyloo.get_status(capture_uuid).get('status_code')
            if status == STATUS_READY:
                break
            if status == STATUS_UNKNOWN:
                return ProviderResult(Status.error, error='Lookyloo lost the capture', links=[permalink])
            if time.monotonic() > deadline:
                return ProviderResult(Status.error, error='The capture took too long', links=[permalink])
            time.sleep(2)
        redirects = lookyloo.get_redirects(capture_uuid).get('response', {}).get('redirects') or []
        return ProviderResult(Status.ok, links=[permalink],
                              data={'capture_uuid': capture_uuid, 'permalink': permalink, 'redirects': redirects})
