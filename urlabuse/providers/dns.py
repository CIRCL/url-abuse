#!/usr/bin/env python3

'''DNS: IPv4 and IPv6 addresses of the host of a URL (or of a hostname).'''

from __future__ import annotations

import ipaddress

from urllib.parse import urlsplit

import dns.exception
import dns.resolver

from . import register
from .base import Kind, Provider, ProviderResult, Status


def host_of(value: str, kind: Kind) -> str:
    return (urlsplit(value).hostname or '') if kind == Kind.url else value


@register
class DNS(Provider):
    name = 'dns'
    label = 'Addresses'
    description = 'IPv4 and IPv6 addresses of the host'
    accepts = frozenset({Kind.url, Kind.hostname})
    cache_ttl = 3600

    def _query(self, value: str, kind: Kind) -> ProviderResult:
        host = host_of(value, kind).lower()
        try:
            ip = ipaddress.ip_address(host)
            key = 'ipv6' if ip.version == 6 else 'ipv4'
            return ProviderResult(Status.ok, data={'host': host, 'ipv4': [], 'ipv6': [], key: [host]})
        except ValueError:
            pass
        resolver = dns.resolver.Resolver()
        resolver.lifetime = float(self.config.get('timeout', 5))
        data: dict[str, object] = {'host': host}
        for family, rtype in (('ipv4', 'A'), ('ipv6', 'AAAA')):
            try:
                data[family] = sorted({str(r) for r in resolver.resolve(host, rtype)})
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                data[family] = []
            except dns.exception.Timeout:
                data[family] = []
        return ProviderResult(Status.ok, data=data)
