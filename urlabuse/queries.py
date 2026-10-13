#!/usr/bin/env python3

'''API v2 building blocks that the v1 checks map onto (doc/api/v2.md):

- one provider on one value, as a job (POST /api/v2/providers/<name>/query,
  GET /api/v2/queries/<uuid>), run by the analysis_worker;
- everything cached about a URL and its chain (POST /api/v2/cached).'''

from __future__ import annotations

import json
import logging
import time
import uuid

from typing import Any

from redis import Redis

from .analysis import chain_from_capture
from .cache import Cache
from .default import get_socket_path
from .providers import Kind, Providers, ProviderResult, Status, detect_kind

QUEUE = 'query|queue'
TTL = 24 * 3600


class UnknownProvider(KeyError):
    pass


class Queries:
    '''Keys: query|<uuid> hash: provider, value, kind, status (queued, done),
    created, finished, result (JSON ProviderResult). Expire after a day.'''

    def __init__(self, providers: Providers, cache: Cache, redis: Redis | None=None) -> None:  # type: ignore[type-arg]
        self.redis = redis or Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        self.providers = providers
        self.cache = cache
        self.logger = logging.getLogger('Queries')

    # ---- One provider, one value

    def create(self, provider: str, value: str) -> str:
        if provider not in self.providers:
            raise UnknownProvider(provider)
        query_uuid = str(uuid.uuid4())
        key = f'query|{query_uuid}'
        p = self.redis.pipeline()
        p.hset(key, mapping={'provider': provider, 'value': value, 'kind': detect_kind(value).value,
                             'status': 'queued', 'created': time.time()})
        p.expire(key, TTL)
        p.rpush(QUEUE, query_uuid)
        p.execute()
        return query_uuid

    def get(self, query_uuid: str) -> dict[str, Any] | None:
        job = self.redis.hgetall(f'query|{query_uuid}')
        if not job:
            return None
        return {'uuid': query_uuid, 'provider': job['provider'], 'value': job['value'], 'kind': job['kind'],
                'status': job['status'], 'created': float(job['created']),
                'finished': float(job['finished']) if job.get('finished') else None,
                'result': json.loads(job['result']) if job.get('result') else None}

    def next_queued(self) -> str | None:
        return self.redis.lpop(QUEUE)

    def run(self, query_uuid: str) -> None:
        key = f'query|{query_uuid}'
        job = self.redis.hgetall(key)
        if not job:
            return
        try:
            result = self.providers[job['provider']].query(job['value'], Kind(job['kind']))
        except Exception as e:
            self.logger.exception(f'Query {query_uuid} failed')
            result = ProviderResult(Status.error, error=f'{type(e).__name__}: {e}')
        self.redis.hset(key, mapping={'status': 'done', 'finished': time.time(),
                                      'result': json.dumps(result.to_dict())})

    # ---- Everything cached about a URL

    def cached(self, url: str) -> dict[str, Any]:
        '''The chain of the URL with every cached answer, in the shape of an
        analysis (GET /api/v2/analyse/<uuid>); nothing is queried.'''
        def answers(target: str, kind: Kind) -> dict[str, Any]:
            found = {}
            for provider in self.providers.all():
                if kind in provider.accepts and provider.name != 'lookyloo':
                    if (raw := self.cache.get(provider.name, target)) is not None:
                        found[provider.name] = raw
            return found

        raw_capture = self.cache.get('lookyloo', url)
        capture = ProviderResult.from_dict(raw_capture) if raw_capture else None
        hops = []
        for hop in chain_from_capture(url, capture):
            results = answers(hop, Kind.url)
            hosts = []
            dns = results.get('dns')
            if dns and dns.get('data'):
                for family, ips in (('IPv4', dns['data'].get('ipv4', [])), ('IPv6', dns['data'].get('ipv6', []))):
                    hosts += [{'ip': ip, 'family': family, 'results': answers(ip, Kind.ip)} for ip in ips]
            hops.append({'url': hop, 'results': results, 'hosts': hosts})
        return {'url': url, 'lookyloo': raw_capture, 'chain': hops}
