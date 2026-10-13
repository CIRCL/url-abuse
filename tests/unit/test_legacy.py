"""API v1 layer and reports (fake providers, fake Valkey, fake SMTP)."""

from __future__ import annotations

from typing import Any

import fakeredis
import pytest

from flask.testing import FlaskClient

from urlabuse.cache import Cache
from urlabuse.legacy import NOT_VALID, LegacyJobs
from urlabuse.providers import Kind, Provider, ProviderResult, Status
from urlabuse.report import Reports, ReportsDisabled

from .test_analysis import FakeProviders


class Lk(Provider):
    name = 'lookyloo'
    accepts = frozenset({Kind.url})

    def _query(self, value: str, kind: Kind) -> ProviderResult:
        return ProviderResult(Status.ok, data={'permalink': 'https://lk.test/tree/1',
                                               'redirects': [value + '/', 'https://end.test/']})


class Dns(Provider):
    name = 'dns'
    accepts = frozenset({Kind.url})

    def _query(self, value: str, kind: Kind) -> ProviderResult:
        return ProviderResult(Status.ok, data={'ipv4': ['8.8.8.8'], 'ipv6': []})


class Bgp(Provider):
    name = 'bgpranking'
    accepts = frozenset({Kind.ip})

    def _query(self, value: str, kind: Kind) -> ProviderResult:
        return ProviderResult(Status.ok, data={'asn': '15169', 'prefix': '8.8.8.0/24', 'asn_description': 'GOOGLE',
                                               'rank': 0.0, 'position': 10, 'total_known_asns': 100})


@pytest.fixture
def legacy() -> LegacyJobs:
    redis = fakeredis.FakeRedis(decode_responses=True)
    cache = Cache(redis)
    providers = FakeProviders([cls({'enabled': True}, cache) for cls in (Lk, Dns, Bgp)])
    return LegacyJobs(providers, cache, redis)  # type: ignore[arg-type]


def done(legacy: LegacyJobs, method: str, **params: Any) -> Any:
    job = legacy.create(method, **params)
    assert legacy.result(job) == (202, 'Nay!')
    assert legacy.next_queued() == job
    legacy.run(job)
    status, result = legacy.result(job)
    assert status == 200
    assert legacy.result(job) == (200, None)      # deleted once read
    return result


def test_shapes(legacy: LegacyJobs) -> None:
    assert done(legacy, 'is_valid_url', url='hxxp://a.test') == [True, 'http://a.test', None]
    assert done(legacy, 'is_valid_url', url='ftp://a.test') == [False, 'http://ftp://a.test', NOT_VALID]
    assert done(legacy, 'url_list', url='http://a.test') == ['http://a.test', 'https://end.test/']
    assert done(legacy, 'dns_resolve', url='http://a.test') == [['8.8.8.8'], None]
    assert done(legacy, 'lookyloo', url='http://a.test') == 'https://lk.test/tree/1'
    assert done(legacy, 'bgpranking', ip='8.8.8.8') == ['15169', '8.8.8.0/24', 'GOOGLE', 0.0, 10, 100]
    assert done(legacy, 'whois', query='http://a.test') is None


def test_unknown_job(legacy: LegacyJobs) -> None:
    assert legacy.result('nope') == (200, None)


def test_cached_and_digest(legacy: LegacyJobs) -> None:
    for method, params in (('url_list', {'url': 'http://a.test'}), ('dns_resolve', {'url': 'http://a.test'}),
                           ('bgpranking', {'ip': '8.8.8.8'})):
        done(legacy, method, **params)
    cached = legacy.cached('http://a.test', digest=True)
    first = cached['result'][0]['http://a.test']
    assert first['lookyloo'] == 'https://lk.test/tree/1'
    assert first['dns'] == [['8.8.8.8'], None]
    assert first['8.8.8.8']['bgpranking'][0] == '15169'
    assert list(cached['result'][1]) == ['https://end.test/']
    text, mails, asns = cached['digest']
    assert 'Lookyloo permanent URL: https://lk.test/tree/1' in text and asns == ['GOOGLE (15169)']


class FakeSMTP:
    sent: list[Any] = []

    def __init__(self, host: str, port: int, timeout: int) -> None: ...
    def __enter__(self) -> FakeSMTP:
        return self
    def __exit__(self, *args: Any) -> None: ...
    def send_message(self, message: Any) -> None:
        FakeSMTP.sent.append(message)


def test_reports(legacy: LegacyJobs, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr('urlabuse.report.smtplib.SMTP', FakeSMTP)
    FakeSMTP.sent = []
    config = {'enabled': True, 'sender': 's@test', 'recipients': ['r@test'], 'autosend_threshold': 2}
    reports = Reports(legacy, legacy.redis, config)
    assert reports.send('http://a.test/x', '1.2.3.4') is True
    assert reports.send('http://a.test/other', '1.2.3.4') is False      # same host, same day
    assert len(FakeSMTP.sent) == 1 and FakeSMTP.sent[0]['To'] == 'r@test'
    assert 'from 1.2.3.4' in FakeSMTP.sent[0]['Subject']
    assert not reports.should_autosend(reports.count_submission('http://b.test'))
    assert reports.should_autosend(reports.count_submission('http://b.test'))


def test_reports_disabled(legacy: LegacyJobs) -> None:
    with pytest.raises(ReportsDisabled):
        Reports(legacy, legacy.redis, {'enabled': False}).send('http://a.test')


@pytest.fixture
def client(legacy: LegacyJobs, monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    from website.web import app, genericapi
    from website.web import legacy as routes
    reports = Reports(legacy, legacy.redis, {'enabled': False})
    monkeypatch.setattr(routes, 'get_legacy', lambda: legacy)
    monkeypatch.setattr(routes, 'get_reports', lambda: reports)
    monkeypatch.setattr(genericapi, 'get_reports', lambda: reports)
    return app.test_client()


def test_v1_routes(client: FlaskClient, legacy: LegacyJobs) -> None:
    job = client.post('/resolve', data='{"url": "http://a.test"}').get_data(as_text=True)
    r = client.get(f'/_result/{job}')
    assert r.status_code == 202 and r.get_json() == 'Nay!'
    legacy.run(legacy.next_queued() or '')
    assert client.get(f'/_result/{job}').get_json() == [['8.8.8.8'], None]
    for path in ('phishtank', 'virustotal_report', 'urlquery', 'ticket'):
        r = client.post(f'/{path}', json={'query': 'http://a.test'})
        assert r.status_code == 200 and r.data == b''
    assert client.post('/get_cache', json={'query': 'http://a.test'}).get_json()['result']
    assert client.post('/submit', json={'url': 'http://a.test'}).status_code == 503
    assert client.post('/api/v2/report', json={'url': 'http://a.test'}).status_code == 503
    r = client.get('/urlreport?url=http://a.test')
    assert r.status_code == 302 and r.headers['Location'].startswith('/?url=')
