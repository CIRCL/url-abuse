"""The real providers, with their network calls mocked."""

from __future__ import annotations

from typing import Any

import pytest

from urlabuse.providers import PROVIDER_CLASSES, Kind, Status
from urlabuse.providers import bgpranking as bgp_mod
from urlabuse.providers import lookyloo as lk_mod


def test_registered() -> None:
    assert {'dns', 'bgpranking', 'lookyloo'} <= set(PROVIDER_CLASSES)


def test_dns_ip_literal() -> None:
    r = PROVIDER_CLASSES['dns']({'enabled': True}).query('http://1.2.3.4/x')
    assert r.status == Status.ok and r.data['ipv4'] == ['1.2.3.4'] and r.data['ipv6'] == []


def test_bgpranking(monkeypatch: pytest.MonkeyPatch) -> None:
    class IPASN:
        def __init__(self, url: str) -> None: ...
        def query(self, ip: str) -> dict[str, Any]:
            return {'response': {'2026-10-11': {'asn': '13335', 'prefix': '1.1.1.0/24'}}}

    class BGP:
        def __init__(self, url: str) -> None: ...
        def query(self, asn: str, **kwargs: Any) -> dict[str, Any]:
            return {'response': {'asn_description': 'CLOUDFLARENET',
                                 'ranking': {'rank': 0.1, 'position': 2599, 'total_known_asns': 3529}}}
    monkeypatch.setattr(bgp_mod, 'IPASNHistory', IPASN)
    monkeypatch.setattr(bgp_mod, 'PyBGPRanking', BGP)
    p = PROVIDER_CLASSES['bgpranking']({'enabled': True, 'url': 'https://bgp.test/', 'ipasn_url': 'https://ipasn.test/'})
    r = p.query('1.1.1.1')
    assert r.status == Status.ok
    assert r.data == {'asn': '13335', 'prefix': '1.1.1.0/24', 'asn_description': 'CLOUDFLARENET',
                      'rank': 0.1, 'position': 2599, 'total_known_asns': 3529}
    assert r.links == ['https://bgp.test/asn?asn=13335']
    assert p.query('http://a.test/').status == Status.not_applicable


def test_lookyloo(monkeypatch: pytest.MonkeyPatch) -> None:
    statuses = iter([0, 2, 1])

    class Fake:
        root_url = 'https://lookyloo.test/'

        def __init__(self, url: str) -> None: ...
        def submit(self, **kwargs: Any) -> str:
            return 'abc'
        def get_status(self, uuid: str) -> dict[str, int]:
            return {'status_code': next(statuses)}
        def get_redirects(self, uuid: str) -> dict[str, Any]:
            return {'response': {'redirects': ['http://a.test/', 'https://a.test/']}}
    monkeypatch.setattr(lk_mod, 'PyLookyloo', Fake)
    monkeypatch.setattr('urlabuse.providers.lookyloo.time.sleep', lambda s: None)
    r = PROVIDER_CLASSES['lookyloo']({'enabled': True, 'url': 'https://lookyloo.test/'}).query('http://a.test')
    assert r.status == Status.ok
    assert r.data == {'capture_uuid': 'abc', 'permalink': 'https://lookyloo.test/tree/abc',
                      'redirects': ['http://a.test/', 'https://a.test/']}


def test_lookyloo_lost_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    class Fake:
        root_url = 'https://lookyloo.test/'

        def __init__(self, url: str) -> None: ...
        def submit(self, **kwargs: Any) -> str:
            return 'abc'
        def get_status(self, uuid: str) -> dict[str, int]:
            return {'status_code': -1}
    monkeypatch.setattr(lk_mod, 'PyLookyloo', Fake)
    r = PROVIDER_CLASSES['lookyloo']({'enabled': True, 'url': 'https://lookyloo.test/'}).query('http://a.test')
    assert r.status == Status.error and r.error == 'Lookyloo lost the capture'


def test_kinds() -> None:
    assert Kind.ip in PROVIDER_CLASSES['bgpranking'].accepts
