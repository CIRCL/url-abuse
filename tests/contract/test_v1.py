"""Contract of the v1 API (doc/api/v1.md), run against a live instance.

    URLABUSE_URL=http://127.0.0.1:5200/ pytest tests/contract

It must pass on the old code and on the rebuild (doc/ROADMAP.md step 1 and 7).
Sources that need credentials are accepted either unconfigured (empty body)
or configured (job id + result of the documented shape).
"""

from __future__ import annotations

import os
import time
import uuid

from typing import Any
from urllib.parse import urljoin

import pytest
import requests

BASE = os.environ.get('URLABUSE_URL', 'http://127.0.0.1:5200/')
TEST_URL = 'http://example.com/'
TIMEOUT = 90


def post(path: str, body: dict[str, Any]) -> requests.Response:
    return requests.post(urljoin(BASE, path), json=body, timeout=30)


def wait_result(job_id: str) -> Any:
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        r = requests.get(urljoin(BASE, f'_result/{job_id}'), timeout=30)
        if r.status_code == 200:
            return r.json()
        assert r.status_code == 202
        assert r.json() == 'Nay!'
        time.sleep(.5)
    pytest.fail(f'job {job_id} not done after {TIMEOUT}s')


def run(path: str, body: dict[str, Any]) -> Any:
    r = post(path, body)
    assert r.status_code == 200
    uuid.UUID(r.text)
    return wait_result(r.text)


def run_optional(path: str, body: dict[str, Any]) -> tuple[bool, Any]:
    '''Source that may not be configured: (configured, result).'''
    r = post(path, body)
    assert r.status_code == 200
    if not r.text:
        return False, None
    uuid.UUID(r.text)
    return True, wait_result(r.text)


@pytest.fixture(scope='session', autouse=True)
def instance_up() -> None:
    try:
        r = requests.head(BASE, timeout=10)
    except requests.ConnectionError:
        pytest.exit(f'No URL Abuse instance at {BASE} (set URLABUSE_URL).')
    assert r.status_code == 200


def test_unknown_job() -> None:
    r = requests.get(urljoin(BASE, f'_result/{uuid.uuid4()}'), timeout=30)
    assert r.status_code == 200
    assert r.json() is None


def test_result_deleted_once_read() -> None:
    r = post('resolve', {'url': TEST_URL})
    wait_result(r.text)
    again = requests.get(urljoin(BASE, f'_result/{r.text}'), timeout=30)
    assert again.status_code == 200 and again.json() is None


def test_start_valid() -> None:
    assert run('start', {'url': TEST_URL}) == [True, TEST_URL, None]


def test_start_normalises() -> None:
    valid, url, reason = run('start', {'url': 'hxxp://example.com/'})
    assert (valid, url, reason) == (True, 'http://example.com/', None)
    valid, url, _ = run('start', {'url': 'example.com'})
    assert valid is True and url == 'http://example.com'


def test_urls() -> None:
    result = run('urls', {'url': TEST_URL})
    assert isinstance(result, list) and result
    assert all(isinstance(u, str) for u in result)
    assert len(result) == len(set(result))


def test_resolve() -> None:
    ipv4, ipv6 = run('resolve', {'url': TEST_URL})
    assert ipv4 is None or all(isinstance(ip, str) for ip in ipv4)
    assert ipv6 is None or all(isinstance(ip, str) for ip in ipv6)
    assert ipv4 or ipv6


def test_resolve_ip_literal() -> None:
    assert run('resolve', {'url': 'http://1.1.1.1/'}) == [['1.1.1.1'], None]


def test_bgpranking_shape() -> None:
    result = run('bgpranking', {'query': '1.1.1.1'})
    assert isinstance(result, list) and len(result) == 6


def test_whois_shape() -> None:
    result = run('whois', {'query': TEST_URL})
    assert result is None or all(isinstance(m, str) for m in result)


def test_lookyloo_shape() -> None:
    result = run('lookyloo', {'url': TEST_URL})
    assert result is None or (isinstance(result, str) and result.startswith('http'))


@pytest.mark.parametrize('path,check', [
    ('phishtank', lambda r: r is None or isinstance(r, str)),
    ('virustotal_report', lambda r: r is None or (isinstance(r, list) and len(r) == 4)),
    ('googlesafebrowsing', lambda r: r is None or isinstance(r, str)),
    ('eupi', lambda r: r is None or isinstance(r, str)),
    ('pdnscircl', lambda r: isinstance(r, list) and len(r) == 2),
    ('psslcircl', lambda r: r is None or isinstance(r, dict)),
])
def test_optional_sources(path: str, check: Any) -> None:
    configured, result = run_optional(path, {'query': TEST_URL if path != 'psslcircl' else '1.1.1.1'})
    if configured:
        assert check(result)


@pytest.mark.parametrize('path', ['urlquery', 'ticket'])
def test_disabled_sources(path: str) -> None:
    # Old code: 404. Rebuild: empty body ("not configured", AGENTS.md decision 12).
    r = post(path, {'query': TEST_URL})
    assert r.status_code == 404 or (r.status_code == 200 and r.text == '')


def test_get_cache() -> None:
    run('urls', {'url': TEST_URL})
    run('resolve', {'url': TEST_URL})
    data = post('get_cache', {'query': TEST_URL, 'digest': False}).json()
    assert set(data) == {'result'}
    assert isinstance(data['result'], list) and data['result']
    first = data['result'][0]
    assert list(first) == [TEST_URL]
    assert 'dns' in first[TEST_URL]


def test_get_cache_digest() -> None:
    data = post('get_cache', {'query': TEST_URL, 'digest': True}).json()
    assert set(data) == {'result', 'digest'}
    text, mails, asns = data['digest']
    assert isinstance(text, str) and TEST_URL in text
    assert isinstance(mails, list) and isinstance(asns, list)


def test_urlreport_page() -> None:
    r = requests.get(urljoin(BASE, 'urlreport'), timeout=30)
    assert r.status_code == 200 and 'html' in r.headers['content-type']
