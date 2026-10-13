# Providers

A provider is a source URL Abuse forwards a value to (Lookyloo, VirusTotal,
BGP Ranking…). URL Abuse has no analysis logic of its own: everything comes
from providers (`AGENTS.md`, decisions 1–3).

Code: `urlabuse/providers/` (`base.py` = the interface, `__init__.py` = the
registry), cache in `urlabuse/cache.py`.

## Values

Every value has a kind (`Kind`), guessed by `detect_kind()` when the caller
does not give it:

| Kind | Example | Rule |
|---|---|---|
| `url` | `http://example.com/a` | has a scheme and a host |
| `ip` | `1.1.1.1`, `2001:db8::1` | IPv4/IPv6 literal |
| `hostname` | `example.com` | anything else |

## What a provider answers: `ProviderResult`

| Field | Meaning |
|---|---|
| `status` | `ok`, `not_configured` (disabled or credentials missing), `not_applicable` (does not take this kind), `error` |
| `data` | the provider's answer, JSON-able (`null` when nothing is known) |
| `verdict` | reputation providers only: `malicious`, `suspicious`, `clean`, `unknown` (default) |
| `links` | permalinks on the provider (report page, capture…) |
| `error` | `"ExceptionName: message"` when `status` is `error` |
| `cached` | the answer comes from the cache |

`not_configured` is not an error: the web page shows it as "not set up".

## Writing a provider

```python
from urlabuse.providers import Kind, Provider, ProviderResult, Status, Verdict, register


@register
class PhishTank(Provider):
    name = 'phishtank'                       # key in config/providers.json
    description = 'Known phishing URLs'
    accepts = frozenset({Kind.url})
    required_config = ('apikey',)            # must be non-empty, with "enabled": true
    cache_ttl = 6 * 3600                     # seconds, 0 = never cached

    def _query(self, value: str, kind: Kind) -> ProviderResult:
        answer = ...                         # call the provider's library with self.config['apikey']
        if not answer:
            return ProviderResult(Status.ok)
        return ProviderResult(Status.ok, data=answer, verdict=Verdict.malicious,
                              links=[answer['detail_page']])
```

Call it with `provider.query(value)`; `query()` does the rest:

1. not enabled or a `required_config` key is empty → `not_configured`;
2. kind not in `accepts` → `not_applicable` (`_query` is not called);
3. cached answer → returned with `cached: true`;
4. `_query()`; any exception → `error` (logged, never raised);
5. an `ok` answer is cached for `cache_ttl` seconds (errors are never cached).

Then:

- add its entry, with a line in `_notes`, to `config/providers.json.sample`;
- unit tests with the HTTP calls mocked (`tests/unit/`);
- a row in the table below.

## Registry

`@register` adds the class to `PROVIDER_CLASSES`. `Providers()` instantiates
every registered provider with its entry of `config/providers.json` (a
provider missing from the file is disabled):

```python
providers = Providers(Cache())
providers['phishtank'].query('http://example.com/')
providers.enabled()               # configured providers
providers.for_kind(Kind.ip)       # configured providers that take IPs
```

## Cache

Valkey (`cache` database), key `cache|<provider>|<sha256 of the value>`, JSON
of the `ProviderResult`, expiring after the provider's `cache_ttl`.

## Providers

| Name | Kinds | Config | Status |
|---|---|---|---|
| — | | | ported in roadmap step 4 |
