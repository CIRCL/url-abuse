"""Analysis job and API v2 (fake providers, fake Valkey: no network)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

import fakeredis
import pytest

from flask.testing import FlaskClient

from urlabuse.analysis import Analyses, InvalidURL, normalise_url, same_url
from urlabuse.providers import Kind, Provider, ProviderResult, Status, Verdict


class FakeLookyloo(Provider):
    name = 'lookyloo'
    accepts = frozenset({Kind.url})

    def _query(self, value: str, kind: Kind) -> ProviderResult:
        return ProviderResult(Status.ok, links=['https://lookyloo.test/tree/x'],
                              data={'redirects': [value + '/', 'https://final.test/']})


class FakeDNS(Provider):
    name = 'dns'
    accepts = frozenset({Kind.url, Kind.hostname})

    def _query(self, value: str, kind: Kind) -> ProviderResult:
        return ProviderResult(Status.ok, data={'ipv4': ['8.8.8.8', '10.0.0.1'], 'ipv6': []})


class FakeReputation(Provider):
    name = 'rep'
    accepts = frozenset({Kind.url})
    reputation = True

    def _query(self, value: str, kind: Kind) -> ProviderResult:
        bad = 'final' in value
        return ProviderResult(Status.ok, verdict=Verdict.malicious if bad else Verdict.clean)


class FakeNetwork(Provider):
    name = 'net'
    accepts = frozenset({Kind.ip})

    def _query(self, value: str, kind: Kind) -> ProviderResult:
        return ProviderResult(Status.ok, data={'asn': '15169'})


class FakeProviders:
    def __init__(self, providers: list[Provider]) -> None:
        self.providers = {p.name: p for p in providers}

    def __getitem__(self, name: str) -> Provider:
        return self.providers[name]

    def __contains__(self, name: str) -> bool:
        return name in self.providers

    def all(self) -> list[Provider]:
        return list(self.providers.values())

    def enabled(self) -> list[Provider]:
        return [p for p in self.all() if p.configured]

    def for_kind(self, kind: Kind) -> list[Provider]:
        return [p for p in self.enabled() if kind in p.accepts]


def make(*classes: type[Provider], **config: Any) -> Analyses:
    providers = FakeProviders([cls({'enabled': True, **config}) for cls in classes])
    return Analyses(providers, fakeredis.FakeRedis(decode_responses=True))  # type: ignore[arg-type]


def run(analyses: Analyses, url: str) -> dict[str, Any]:
    uuid = analyses.create(url)
    assert analyses.next_queued() == uuid
    with ThreadPoolExecutor(4) as pool:
        analyses.run(uuid, pool)
    result = analyses.get(uuid)
    assert result is not None
    return result


@pytest.mark.parametrize('raw,url', [
    ('example.com', 'http://example.com'),
    ('  hxxps://example.com/a ', 'https://example.com/a'),
    ('HTTP://Example.com', 'HTTP://Example.com'),
])
def test_normalise(raw: str, url: str) -> None:
    assert normalise_url(raw) == url


@pytest.mark.parametrize('raw', ['', 'ftp://example.com', 'http://', 'http://' + 'a' * 2050])
def test_normalise_refuses(raw: str) -> None:
    with pytest.raises(InvalidURL):
        normalise_url(raw)


def test_same_url() -> None:
    assert same_url('https://a.test', 'https://a.test/')
    assert not same_url('https://a.test/x', 'https://a.test/')


def test_full_analysis() -> None:
    a = run(make(FakeLookyloo, FakeDNS, FakeReputation, FakeNetwork), 'http://start.test')
    assert a['status'] == 'done' and a['finished']
    # Chain from the capture, "http://start.test/" being the same page as the URL
    assert [hop['url'] for hop in a['chain']] == ['http://start.test', 'https://final.test/']
    assert a['lookyloo']['links'] == ['https://lookyloo.test/tree/x']
    first = a['chain'][0]
    assert set(first['results']) == {'dns', 'rep'}          # lookyloo is not a row
    # Only global IPs are sent to the IP providers
    hosts = {h['ip']: h for h in first['hosts']}
    assert set(hosts) == {'8.8.8.8', '10.0.0.1'}
    assert hosts['8.8.8.8']['results']['net']['data'] == {'asn': '15169'}
    assert hosts['10.0.0.1']['results'] == {}
    assert a['progress']['done'] == a['progress']['total'] > 0
    assert a['verdict'] == {'verdict': 'malicious', 'flagged_by': ['rep'], 'checked_by': ['rep']}


def test_no_reputation_source() -> None:
    a = run(make(FakeDNS, FakeNetwork), 'http://start.test')
    assert a['verdict']['verdict'] == 'unknown' and a['verdict']['checked_by'] == []
    assert a['lookyloo'] is None and len(a['chain']) == 1


def test_unknown_analysis() -> None:
    assert make(FakeDNS).get('nope') is None


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    from website.web import app, genericapi
    analyses = make(FakeDNS, FakeNetwork)
    monkeypatch.setattr(genericapi, '_analyses', analyses)
    return app.test_client()


def test_api_analyse(client: FlaskClient) -> None:
    r = client.post('/api/v2/analyse', json={'url': 'hxxp://example.com'})
    assert r.status_code == 201
    created = r.get_json()
    assert created['url'] == 'http://example.com'
    r = client.get(f'/api/v2/analyse/{created["uuid"]}')
    assert r.status_code == 200 and r.get_json()['status'] == 'queued'


def test_api_analyse_invalid(client: FlaskClient) -> None:
    r = client.post('/api/v2/analyse', json={'url': 'ftp://example.com'})
    assert r.status_code == 400 and r.get_json()['error'] == 'Invalid URL'
    assert client.post('/api/v2/analyse', json={}).status_code == 400


def test_api_analyse_unknown(client: FlaskClient) -> None:
    r = client.get('/api/v2/analyse/nope')
    assert r.status_code == 404 and r.is_json


def test_api_providers(client: FlaskClient) -> None:
    names = {p['name']: p for p in client.get('/api/v2/providers').get_json()}
    assert names['dns']['accepts'] == ['hostname', 'url'] and names['dns']['configured']
