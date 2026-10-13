#!/usr/bin/env python3

'''API v1 on top of the providers (AGENTS.md decision 4, doc/api/v1.md).

A v1 check is one provider call answered in the old shape: POST /<check>
returns a job id, the analysis_worker runs it, GET /_result/<id> returns
the result once. get_cache rebuilds the old report from the provider cache.'''

from __future__ import annotations

import json
import logging
import uuid

from collections.abc import Callable
from typing import Any

from redis import Redis

from .analysis import InvalidURL, chain_from_capture, normalise_url
from .cache import Cache
from .default import get_socket_path
from .providers import Provider, Providers, ProviderResult, Status

QUEUE = 'v1|queue'
JOB_TTL = 3600
NOT_VALID = 'Not a valid http/https URL/URI'


class LegacyJobs:

    def __init__(self, providers: Providers, cache: Cache, redis: Redis | None=None) -> None:  # type: ignore[type-arg]
        self.redis = redis or Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        self.providers = providers
        self.cache = cache
        self.logger = logging.getLogger('LegacyJobs')
        self.methods: dict[str, Callable[..., Any]] = {
            'is_valid_url': self.is_valid_url, 'url_list': self.url_list,
            'dns_resolve': self.dns_resolve, 'lookyloo': self.lookyloo,
            'bgpranking': self.bgpranking, 'whois': self.whois,
        }

    # ---- Jobs

    def create(self, method: str, **params: Any) -> str:
        if method not in self.methods:
            raise ValueError(f'Unknown v1 method {method}')
        job_id = str(uuid.uuid4())
        p = self.redis.pipeline()
        p.hset(f'v1|job|{job_id}', mapping={'method': method, 'data': json.dumps(params)})
        p.expire(f'v1|job|{job_id}', JOB_TTL)
        p.rpush(QUEUE, job_id)
        p.execute()
        return job_id

    def result(self, job_id: str) -> tuple[int, Any]:
        '''(200, None) unknown, (202, 'Nay!') pending, (200, result) done (then deleted).'''
        key = f'v1|job|{job_id}'
        if not self.redis.exists(key):
            return 200, None
        raw = self.redis.hget(key, 'result')
        if raw is None:
            return 202, 'Nay!'
        self.redis.delete(key)
        return 200, json.loads(raw)

    def next_queued(self) -> str | None:
        return self.redis.lpop(QUEUE)

    def run(self, job_id: str) -> None:
        key = f'v1|job|{job_id}'
        job = self.redis.hgetall(key)
        if not job:
            return
        try:
            result = self.methods[job['method']](**json.loads(job['data']))
        except Exception:
            # Like the old workers: a failed job never gets a result
            self.logger.exception(f'v1 job {job_id} failed')
            return
        self.redis.hset(key, 'result', json.dumps(result))

    # ---- Checks, in the v1 shapes

    def _query(self, name: str, value: str) -> ProviderResult | None:
        if name not in self.providers:
            return None
        provider: Provider = self.providers[name]
        result = provider.query(value)
        return result if result.status == Status.ok else None

    def is_valid_url(self, url: str) -> list[Any]:
        try:
            return [True, normalise_url(url), None]
        except InvalidURL:
            fixed = url.strip()
            if fixed.lower().startswith('hxxp'):
                fixed = 'http' + fixed[4:]
            elif not fixed.startswith('http'):
                fixed = 'http://' + fixed
            return [False, fixed, NOT_VALID]

    def url_list(self, url: str) -> list[str]:
        return chain_from_capture(url, self._query('lookyloo', url))

    def dns_resolve(self, url: str) -> list[list[str] | None]:
        result = self._query('dns', url)
        data = result.data if result and result.data else {}
        return [data.get('ipv4') or None, data.get('ipv6') or None]

    def lookyloo(self, url: str) -> str | None:
        result = self._query('lookyloo', url)
        return result.data['permalink'] if result and result.data else None

    def bgpranking(self, ip: str) -> list[Any]:
        result = self._query('bgpranking', ip)
        d = result.data if result and result.data else {}
        return [d.get(k) for k in ('asn', 'prefix', 'asn_description', 'rank', 'position', 'total_known_asns')]

    def whois(self, query: str) -> list[str] | None:
        # Not ported yet (doc/ROADMAP.md step 4): "no abuse contact found"
        return None

    # ---- get_cache: the old report, from the provider cache

    def _cached(self, name: str, value: str) -> ProviderResult | None:
        raw = self.cache.get(name, value)
        if raw is None:
            return None
        result = ProviderResult.from_dict(raw)
        return result if result.status == Status.ok else None

    def cached(self, url: str, digest: bool=False) -> dict[str, Any]:
        capture = self._cached('lookyloo', url)
        entries: list[dict[str, Any]] = []
        for hop in chain_from_capture(url, capture):
            data: dict[str, Any] = {}
            if hop == url and capture and capture.data:
                data['lookyloo'] = capture.data['permalink']
            dns = self._cached('dns', hop)
            if dns and dns.data:
                ipv4, ipv6 = dns.data.get('ipv4') or None, dns.data.get('ipv6') or None
                data['dns'] = [ipv4, ipv6]
                for ip in (ipv4 or []) + (ipv6 or []):
                    bgp = self._cached('bgpranking', ip)
                    if bgp and bgp.data:
                        d = bgp.data
                        data[ip] = {'bgpranking': [d.get(k) for k in ('asn', 'prefix', 'asn_description', 'rank',
                                                                      'position', 'total_known_asns')]}
            entries.append({hop: data})
        if digest:
            return {'result': entries, 'digest': self.digest(entries)}
        return {'result': entries}

    @staticmethod
    def digest(entries: list[dict[str, Any]]) -> list[Any]:
        '''[text, abuse e-mails, ["AS description (asn)"]], as the old digest.'''
        text = ''
        mails: set[str] = set()
        asns: set[str] = set()
        for entry in entries:
            for url, info in entry.items():
                text += f'\n{url}\n'
                mails.update(info.get('whois') or [])
                if info.get('lookyloo'):
                    text += f'\tLookyloo permanent URL: {info["lookyloo"]}\n'
                ipv4, ipv6 = info.get('dns') or [None, None]
                for ip in (ipv4 or []) + (ipv6 or []):
                    text += f'\t{ip}\n'
                    bgp = (info.get(ip) or {}).get('bgpranking')
                    if bgp and bgp[0]:
                        text += f'\t\tis announced by {bgp[2]} ({bgp[0]}). Position {bgp[4]}/{bgp[5]}.\n'
                        asns.add(f'{bgp[2]} ({bgp[0]})')
                    mails.update((info.get(ip) or {}).get('whois') or [])
        return [text, sorted(mails), sorted(asns)]
