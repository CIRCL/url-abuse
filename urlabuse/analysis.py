#!/usr/bin/env python3

'''Analysis of a URL: the job behind POST /api/v2/analyse.

    URL ──> lookyloo (capture: redirect chain)          ┐
     └───> URL providers on the URL, dns ──> IPs ──> IP providers per IP
    each new URL of the chain ──> the same URL stage

Everything is stored in Valkey as it arrives, so GET /api/v2/analyse/<uuid>
shows the progress. Doc: doc/architecture/jobs.md'''

from __future__ import annotations

import ipaddress
import json
import logging
import time
import uuid

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from threading import Condition
from typing import Any
from urllib.parse import urlsplit

from redis import Redis

from .default import get_socket_path
from .providers import Kind, Provider, Providers, ProviderResult, Status, Verdict

QUEUE = 'analysis|queue'
TTL = 7 * 24 * 3600
MAX_URL_LENGTH = 2048
# Providers with a stage of their own (not run as plain URL providers)
CHAIN_PROVIDER = 'lookyloo'
RESOLVER = 'dns'


class InvalidURL(ValueError):
    pass


def normalise_url(raw: str) -> str:
    '''What a person pastes -> an http(s) URL: trimmed, hxxp(s) fixed, http://
    added when there is no scheme. Raises InvalidURL.'''
    url = raw.strip()
    if not url:
        raise InvalidURL('The URL is empty.')
    if len(url) > MAX_URL_LENGTH:
        raise InvalidURL(f'The URL is longer than {MAX_URL_LENGTH} characters.')
    if url.lower().startswith('hxxp'):
        url = 'http' + url[4:]
    if '://' not in url:
        url = 'http://' + url
    parts = urlsplit(url)
    if parts.scheme.lower() not in ('http', 'https'):
        raise InvalidURL('Only http and https URLs can be checked.')
    if not parts.hostname:
        raise InvalidURL('The URL has no host.')
    return url


def same_url(a: str, b: str) -> bool:
    '''https://example.com and https://example.com/ are the same page.'''
    def norm(u: str) -> str:
        parts = urlsplit(u)
        return u if parts.path else u + '/'
    return norm(a) == norm(b)


def chain_from_capture(url: str, capture: ProviderResult | None) -> list[str]:
    '''The checked URL, then the URLs of the Lookyloo capture it redirects to.'''
    chain = [url]
    if capture and capture.status == Status.ok and capture.data:
        for hop in capture.data.get('redirects', []):
            if not any(same_url(hop, known) for known in chain):
                chain.append(hop)
    return chain


class Analyses:
    '''Create, read and run analyses. Keys (all expire after TTL):
        analysis|<uuid>           hash: url, status, created, finished, error
        analysis|<uuid>|chain     JSON list of the URLs of the redirect chain
        analysis|<uuid>|hosts     hash: url -> JSON list of [ip, family]
        analysis|<uuid>|results   hash: "<target>|<provider>" -> JSON ProviderResult
    '''

    def __init__(self, providers: Providers | None=None, redis: Redis | None=None) -> None:  # type: ignore[type-arg]
        self.redis = redis or Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        self.providers = providers or Providers()
        self.logger = logging.getLogger('Analyses')

    # ---- API side

    def create(self, url: str) -> str:
        analysis_uuid = str(uuid.uuid4())
        key = f'analysis|{analysis_uuid}'
        p = self.redis.pipeline()
        p.hset(key, mapping={'url': url, 'status': 'queued', 'created': time.time()})
        p.expire(key, TTL)
        p.set(f'{key}|chain', json.dumps([url]), ex=TTL)
        p.rpush(QUEUE, analysis_uuid)
        p.execute()
        return analysis_uuid

    def get(self, analysis_uuid: str) -> dict[str, Any] | None:
        key = f'analysis|{analysis_uuid}'
        meta = self.redis.hgetall(key)
        if not meta:
            return None
        chain: list[str] = json.loads(self.redis.get(f'{key}|chain') or '[]')
        hosts = {u: json.loads(v) for u, v in self.redis.hgetall(f'{key}|hosts').items()}
        results = {k: json.loads(v) for k, v in self.redis.hgetall(f'{key}|results').items()}

        def results_for(target: str) -> dict[str, Any]:
            prefix = f'{target}|'
            return {k[len(prefix):]: v for k, v in results.items()
                    if k.startswith(prefix) and k[len(prefix):] != CHAIN_PROVIDER}

        hops = [{'url': u,
                 'results': results_for(u),
                 'hosts': [{'ip': ip, 'family': family, 'results': results_for(ip)}
                           for ip, family in hosts.get(u, [])]}
                for u in chain]
        done = sum(1 for r in results.values() if r['status'] != Status.pending.value)
        return {
            'uuid': analysis_uuid,
            'url': meta['url'],
            'status': meta['status'],
            'error': meta.get('error'),
            'created': float(meta['created']),
            'finished': float(meta['finished']) if meta.get('finished') else None,
            'progress': {'done': done, 'total': len(results)},
            'lookyloo': results.get(f'{meta["url"]}|{CHAIN_PROVIDER}'),
            'chain': hops,
            'verdict': self._verdict(results),
            'providers': {p.name: {'label': p.label or p.name, 'reputation': p.reputation}
                          for p in self.providers.all()},
        }

    def _verdict(self, results: dict[str, Any]) -> dict[str, Any]:
        '''Overall verdict from the reputation providers, by distinct provider.'''
        reputation = {p.name for p in self.providers.all() if p.reputation}
        by_verdict: dict[str, set[str]] = {v.value: set() for v in Verdict}
        checked: set[str] = set()
        for key, result in results.items():
            provider = key.rsplit('|', 1)[1]
            if provider not in reputation or result['status'] != Status.ok.value:
                continue
            checked.add(provider)
            by_verdict[result.get('verdict', 'unknown')].add(provider)
        for verdict in (Verdict.malicious, Verdict.suspicious):
            if by_verdict[verdict.value]:
                return {'verdict': verdict.value, 'flagged_by': sorted(by_verdict[verdict.value]),
                        'checked_by': sorted(checked)}
        return {'verdict': Verdict.clean.value if by_verdict['clean'] else Verdict.unknown.value,
                'flagged_by': [], 'checked_by': sorted(checked)}

    def next_queued(self) -> str | None:
        return self.redis.lpop(QUEUE)

    # ---- Worker side

    def run(self, analysis_uuid: str, pool: ThreadPoolExecutor) -> None:
        key = f'analysis|{analysis_uuid}'
        url = self.redis.hget(key, 'url')
        if not url:
            return
        self.redis.hset(key, 'status', 'running')
        # Tasks still running, follow-up stages included: the analysis is done at 0
        running = 0
        idle = Condition()

        def schedule(target: str, provider: Provider,
                     then: Callable[[ProviderResult], None] | None=None) -> None:
            nonlocal running
            self._store(analysis_uuid, target, provider.name, ProviderResult(Status.pending))
            with idle:
                running += 1

            def task() -> None:
                nonlocal running
                try:
                    result = provider.query(target)
                    self._store(analysis_uuid, target, provider.name, result)
                    if then:
                        then(result)
                except Exception:
                    self.logger.exception(f'{provider.name} on {target} failed')
                finally:
                    with idle:
                        running -= 1
                        idle.notify_all()
            pool.submit(task)

        def url_stage(target: str) -> None:
            for provider in self.providers.for_kind(Kind.url):
                if provider.name not in (CHAIN_PROVIDER, RESOLVER):
                    schedule(target, provider)
            if RESOLVER in self.providers and self.providers[RESOLVER].configured:
                schedule(target, self.providers[RESOLVER], lambda r: ip_stage(target, r))

        def ip_stage(target: str, resolved: ProviderResult) -> None:
            if resolved.status != Status.ok or not resolved.data:
                return
            hosts = [[ip, 'IPv4'] for ip in resolved.data.get('ipv4', [])]
            hosts += [[ip, 'IPv6'] for ip in resolved.data.get('ipv6', [])]
            self.redis.hset(f'{key}|hosts', target, json.dumps(hosts))
            self.redis.expire(f'{key}|hosts', TTL)
            for ip, _ in hosts:
                if not ipaddress.ip_address(ip).is_global:
                    continue
                for provider in self.providers.for_kind(Kind.ip):
                    schedule(ip, provider)

        def chain_stage(capture: ProviderResult) -> None:
            chain = chain_from_capture(url, capture)
            if len(chain) == 1:
                return
            self.redis.set(f'{key}|chain', json.dumps(chain), ex=TTL)
            for hop in chain[1:]:
                url_stage(hop)

        try:
            if CHAIN_PROVIDER in self.providers and self.providers[CHAIN_PROVIDER].configured:
                schedule(url, self.providers[CHAIN_PROVIDER], chain_stage)
            url_stage(url)
            with idle:
                idle.wait_for(lambda: running == 0)
            self.redis.hset(key, mapping={'status': 'done', 'finished': time.time()})
        except Exception as e:
            self.logger.exception(f'Analysis {analysis_uuid} failed')
            self.redis.hset(key, mapping={'status': 'failed', 'error': f'{type(e).__name__}: {e}',
                                          'finished': time.time()})

    def _store(self, analysis_uuid: str, target: str, provider: str, result: ProviderResult) -> None:
        key = f'analysis|{analysis_uuid}|results'
        self.redis.hset(key, f'{target}|{provider}', json.dumps(result.to_dict()))
        self.redis.expire(key, TTL)
