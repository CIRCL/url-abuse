"""Unit tests of the skeleton (no running instance needed)."""

from __future__ import annotations

import json

from pathlib import Path

import pytest

from flask.testing import FlaskClient

from urlabuse.default import get_config, get_homedir

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def client() -> FlaskClient:
    from website.web import app
    return app.test_client()


def test_homedir() -> None:
    assert get_homedir().resolve() == ROOT


@pytest.mark.parametrize('name', ['generic', 'providers', 'logging'])
def test_samples_documented(name: str) -> None:
    sample = json.loads((ROOT / 'config' / f'{name}.json.sample').read_text())
    if '_notes' in sample:
        assert set(sample) - {'_notes'} <= set(sample['_notes'])


def test_get_config_falls_back_on_sample() -> None:
    assert isinstance(get_config('generic', 'website_listen_port'), int)


def test_home_page(client: FlaskClient) -> None:
    r = client.get('/')
    assert r.status_code == 200 and b'<html' in r.data


def test_swagger(client: FlaskClient) -> None:
    assert client.get('/doc/').status_code == 200
    spec = client.get('/swagger.json').get_json()
    assert '/api/v2/health' in spec['paths']


def test_health_answers(client: FlaskClient) -> None:
    r = client.get('/api/v2/health')
    data = r.get_json()
    assert r.status_code in (200, 503)
    assert data['status'] in ('ok', 'degraded') and 'version' in data


def test_404_page(client: FlaskClient) -> None:
    r = client.get('/does-not-exist', headers={'Accept': 'text/html'})
    assert r.status_code == 404 and b'Error 404' in r.data and b"doesn&#39;t exist" in r.data


def test_404_json_under_api(client: FlaskClient) -> None:
    r = client.get('/api/v2/nope')
    assert r.status_code == 404 and r.get_json()['status'] == 404


def test_404_json_when_asked(client: FlaskClient) -> None:
    r = client.get('/nope', headers={'Accept': 'application/json'})
    assert r.status_code == 404 and r.is_json


def test_405_page(client: FlaskClient) -> None:
    r = client.delete('/', headers={'Accept': 'text/html'})
    assert r.status_code == 405 and b'Error 405' in r.data


def test_api_link_in_pages(client: FlaskClient) -> None:
    assert b'href="/doc/"' in client.get('/').data
    assert b'href="/doc/"' in client.get('/nope', headers={'Accept': 'text/html'}).data
