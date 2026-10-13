"""Provider interface, registry and cache (no instance needed)."""

from __future__ import annotations

from typing import Any

import fakeredis
import pytest

from urlabuse.cache import Cache
from urlabuse.providers import (PROVIDER_CLASSES, Kind, Provider, ProviderResult,
                                Providers, Status, Verdict, detect_kind, register)


class Fake(Provider):
    name = 'fake'
    accepts = frozenset({Kind.url, Kind.hostname})
    required_config = ('apikey',)

    def __init__(self, config: dict[str, Any], cache: Cache | None=None) -> None:
        super().__init__(config, cache)
        self.calls = 0

    def _query(self, value: str, kind: Kind) -> ProviderResult:
        self.calls += 1
        if value == 'http://boom/':
            raise RuntimeError('provider down')
        return ProviderResult(Status.ok, data={'value': value}, verdict=Verdict.clean,
                              links=[f'https://fake/{value}'])


@pytest.fixture
def cache() -> Cache:
    return Cache(fakeredis.FakeRedis(decode_responses=True))


def fake(cache: Cache | None=None, **config: Any) -> Fake:
    return Fake({'enabled': True, 'apikey': 'k', **config}, cache)


@pytest.mark.parametrize('value,kind', [
    ('http://example.com/a', Kind.url), ('https://x.lu', Kind.url),
    ('1.1.1.1', Kind.ip), ('2001:db8::1', Kind.ip),
    ('example.com', Kind.hostname)])
def test_detect_kind(value: str, kind: Kind) -> None:
    assert detect_kind(value) == kind


def test_ok() -> None:
    r = fake().query('http://example.com/')
    assert r.status == Status.ok and r.verdict == Verdict.clean and not r.cached


def test_not_configured() -> None:
    assert Fake({'enabled': False, 'apikey': 'k'}).query('http://a/').status == Status.not_configured
    assert Fake({'enabled': True, 'apikey': ''}).query('http://a/').status == Status.not_configured
    assert Fake({}).query('http://a/').status == Status.not_configured


def test_not_applicable() -> None:
    p = fake()
    assert p.query('1.1.1.1').status == Status.not_applicable
    assert p.calls == 0


def test_error_is_caught() -> None:
    r = fake().query('http://boom/')
    assert r.status == Status.error and r.error == 'RuntimeError: provider down'


def test_cache(cache: Cache) -> None:
    p = fake(cache)
    first = p.query('http://example.com/')
    second = p.query('http://example.com/')
    assert p.calls == 1 and second.cached and second.data == first.data
    assert second.links == first.links and second.verdict == Verdict.clean


def test_errors_are_not_cached(cache: Cache) -> None:
    p = fake(cache)
    p.query('http://boom/')
    p.query('http://boom/')
    assert p.calls == 2


def test_result_roundtrip() -> None:
    r = ProviderResult(Status.ok, data=[1, 2], verdict=Verdict.malicious, links=['l'])
    assert ProviderResult.from_dict(r.to_dict()) == r
    assert r.to_dict()['status'] == 'ok'


def test_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr('urlabuse.providers.PROVIDER_CLASSES', {})
    from urlabuse import providers as mod
    register(Fake)
    assert mod.PROVIDER_CLASSES == {'fake': Fake}
    with pytest.raises(ValueError):
        register(Fake)
    monkeypatch.setattr(mod, 'get_config', lambda _: {'fake': {'enabled': True, 'apikey': 'k'}})
    ps = Providers()
    assert 'fake' in ps and ps.enabled() == [ps['fake']]
    assert ps.for_kind(Kind.url) == [ps['fake']] and ps.for_kind(Kind.ip) == []


def test_unconfigured_provider_missing_from_config(monkeypatch: pytest.MonkeyPatch) -> None:
    from urlabuse import providers as mod
    monkeypatch.setattr(mod, 'PROVIDER_CLASSES', {'fake': Fake})
    monkeypatch.setattr(mod, 'get_config', lambda _: {})
    assert Providers().enabled() == []


def test_registry_is_a_dict() -> None:
    assert isinstance(PROVIDER_CLASSES, dict)
