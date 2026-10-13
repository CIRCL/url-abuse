# Analyses (jobs)

An analysis is what `POST /api/v2/analyse` starts: every configured provider
on a URL, on each URL of its redirect chain, and on each IP of their hosts.
Code: `urlabuse/analysis.py`, run by the `analysis_worker` daemon
(`bin/analysis_worker.py`, started by `poetry run start`).

## Flow

```
POST /api/v2/analyse {"url"}      normalise_url(): trim, hxxp -> http, http:// added,
        │                         http/https only, a host, max 2048 characters
        ▼
Valkey: analysis|<uuid> (queued) + uuid pushed on analysis|queue
        │
        ▼  analysis_worker pops it (analysis_workers analyses at a time)
   ┌──────────────────────────────┬──────────────────────────────────────┐
   │ lookyloo(url)                │ URL stage on url:                    │
   │  (capture, slow)             │   every URL provider                 │
   │   └─ redirects -> chain      │   dns ─> IPs ─> every IP provider    │
   │      URL stage on each new   │          (global IPs only)           │
   │      URL of the chain        │                                      │
   └──────────────────────────────┴──────────────────────────────────────┘
        │  done when no task is left (follow-up stages included)
        ▼
analysis|<uuid> status = done (or failed)
```

- Provider calls run in a thread pool shared by the running analyses (8
  threads per analysis); each answer is stored as soon as it arrives, and a
  task is first stored as `pending`, so the progress is `done / total` of the
  tasks known so far (the total grows when the chain and the IPs are known).
- `lookyloo` and `dns` have a stage of their own; any other provider that
  accepts URLs runs on every URL of the chain, any provider that accepts IPs
  on every global IP of their hosts. A new provider is picked up without
  changing the analysis.
- `https://a.test` and `https://a.test/` are the same URL in the chain.
- Provider answers are cached per provider (doc/providers.md): checking the
  same URL again is fast, and the Lookyloo capture is reused for 6 hours.

## Storage (Valkey, `cache` database, everything expires after 7 days)

| Key | Content |
|---|---|
| `analysis\|queue` | list of uuids waiting for a worker |
| `analysis\|<uuid>` | hash: `url`, `status` (queued, running, done, failed), `created`, `finished`, `error` |
| `analysis\|<uuid>\|chain` | JSON list of the URLs of the chain (first = the checked URL) |
| `analysis\|<uuid>\|hosts` | hash: URL -> JSON list of `[ip, "IPv4" or "IPv6"]` |
| `analysis\|<uuid>\|results` | hash: `<url or ip>\|<provider>` -> JSON `ProviderResult` |

## Verdict

From the reputation providers only (`reputation = True`), counted by
distinct provider: `malicious` when one says so, else `suspicious`, else
`clean` when one checked it and found nothing, else `unknown` (no reputation
provider answered). The web page never says a link is safe.

## Configuration

`config/generic.json`: `analysis_workers` (analyses at the same time).
Providers: `config/providers.json` (doc/providers.md).
