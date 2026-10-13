#!/usr/bin/env python3

'''What every provider implements, and what every provider answers.
Doc: doc/providers.md'''

from __future__ import annotations

import ipaddress
import logging

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, ClassVar
from urllib.parse import urlsplit

from ..cache import Cache


class Status(str, Enum):
    ok = 'ok'
    pending = 'pending'                 # scheduled in an analysis, no answer yet
    not_configured = 'not_configured'   # disabled, or credentials missing
    not_applicable = 'not_applicable'   # the provider does not take this kind of value
    error = 'error'


class Verdict(str, Enum):
    '''Only for reputation providers; the others leave it to unknown.'''
    malicious = 'malicious'
    suspicious = 'suspicious'
    clean = 'clean'
    unknown = 'unknown'


class Kind(str, Enum):
    url = 'url'
    hostname = 'hostname'
    ip = 'ip'


def detect_kind(value: str) -> Kind:
    '''url when there is a scheme, ip for an IPv4/IPv6 literal, else hostname.'''
    try:
        ipaddress.ip_address(value)
        return Kind.ip
    except ValueError:
        pass
    parts = urlsplit(value)
    if parts.scheme and parts.netloc:
        return Kind.url
    return Kind.hostname


@dataclass
class ProviderResult:
    status: Status
    data: Any = None                      # the provider's answer, as JSON-able data
    verdict: Verdict = Verdict.unknown
    links: list[str] = field(default_factory=list)   # permalinks on the provider
    error: str | None = None
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d['status'] = self.status.value
        d['verdict'] = self.verdict.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ProviderResult:
        return cls(status=Status(d['status']), data=d.get('data'),
                   verdict=Verdict(d.get('verdict', 'unknown')), links=d.get('links', []),
                   error=d.get('error'), cached=d.get('cached', False))


class Provider(ABC):
    '''A source URL Abuse forwards values to.

    Subclasses set name / accepts / required_config and implement _query();
    query() handles configuration, kinds, cache and errors for them.'''

    name: ClassVar[str]
    label: ClassVar[str] = ''                          # shown in the interface ('Network')
    description: ClassVar[str] = ''
    reputation: ClassVar[bool] = False                 # gives a verdict on the value
    accepts: ClassVar[frozenset[Kind]]
    required_config: ClassVar[tuple[str, ...]] = ()   # config keys that must be non-empty
    cache_ttl: ClassVar[int] = 24 * 3600               # seconds, 0 = no cache

    def __init__(self, config: dict[str, Any], cache: Cache | None=None) -> None:
        self.config = config
        self.cache = cache
        self.logger = logging.getLogger(f'provider.{self.name}')

    @property
    def configured(self) -> bool:
        return bool(self.config.get('enabled')) and all(self.config.get(k) for k in self.required_config)

    def query(self, value: str, kind: Kind | None=None) -> ProviderResult:
        kind = kind or detect_kind(value)
        if not self.configured:
            return ProviderResult(Status.not_configured)
        if kind not in self.accepts:
            return ProviderResult(Status.not_applicable)
        if self.cache and self.cache_ttl:
            if (cached := self.cache.get(self.name, value)) is not None:
                result = ProviderResult.from_dict(cached)
                result.cached = True
                return result
        try:
            result = self._query(value, kind)
        except Exception as e:
            self.logger.exception(f'Query failed for {value}')
            return ProviderResult(Status.error, error=f'{type(e).__name__}: {e}')
        if self.cache and self.cache_ttl and result.status == Status.ok:
            self.cache.set(self.name, value, result.to_dict(), self.cache_ttl)
        return result

    @abstractmethod
    def _query(self, value: str, kind: Kind) -> ProviderResult:
        ...
