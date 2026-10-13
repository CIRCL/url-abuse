#!/usr/bin/env python3

'''Network of an IP: ASN and prefix (IP ASN History), then the rank of the AS
in BGP Ranking (CIRCL).'''

from __future__ import annotations

from datetime import date, timedelta

from pybgpranking2.api import PyBGPRanking
from pyipasnhistory.api import IPASNHistory

from . import register
from .base import Kind, Provider, ProviderResult, Status


@register
class BGPRanking(Provider):
    name = 'bgpranking'
    label = 'Network'
    description = 'ASN and prefix of the IP (IP ASN History) and rank of the AS (BGP Ranking)'
    accepts = frozenset({Kind.ip})
    required_config = ('url', 'ipasn_url')
    cache_ttl = 12 * 3600

    def _query(self, value: str, kind: Kind) -> ProviderResult:
        ipasn = IPASNHistory(self.config['ipasn_url']).query(value)
        entries = [e for e in (ipasn.get('response') or {}).values() if e]
        if not entries:
            return ProviderResult(Status.ok)
        asn, prefix = entries[0]['asn'], entries[0]['prefix']
        data: dict[str, object] = {'asn': asn, 'prefix': prefix, 'asn_description': None,
                                   'rank': None, 'position': None, 'total_known_asns': None}
        family = 'v6' if ':' in value else 'v4'
        ranking = PyBGPRanking(self.config['url']).query(
            asn, address_family=family, date=(date.today() - timedelta(1)).isoformat())
        response = ranking.get('response') or {}
        if response:
            data['asn_description'] = response.get('asn_description')
            data.update({k: response.get('ranking', {}).get(k) for k in ('rank', 'position', 'total_known_asns')})
        return ProviderResult(Status.ok, data=data,
                              links=[f'{self.config["url"].rstrip("/")}/asn?asn={asn}'])
