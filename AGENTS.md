# AGENTS.md — URL Abuse

Guide for AI agents and contributors. The `ui-redesign` branch holds the new
interface and the decisions for the rebuild of URL Abuse. **Nothing is pushed
without the owner's review.**

## What URL Abuse is (and will be)

URL Abuse (CIRCL) lets anyone check a suspicious link: paste a URL, see what
it redirects to and what reputation sources say about it, and report it to
CIRCL. Online: <https://www.circl.lu/urlabuse/>.

It is being rebuilt as an **API broker for URLs** (decided with the Lookyloo
maintainer, October 2026):

![Planned architecture](./doc/architecture/urlabuse-lookyloo.png)

Interactive diagram: <https://ecrou-exact.github.io/project-graph/?example=urlabuse>,
source in `doc/architecture/urlabuse-lookyloo.json` (Pivograph format, edit it
there and re-export the PNG when the architecture changes).

## Decisions

1. **URL Abuse is only an API broker for URLs.** It receives a URL, forwards
   it to the providers, and returns their answers. It has no analysis logic of
   its own.
2. **One implementation.** The analysis lives in the providers. Nothing is
   duplicated between URL Abuse and Lookyloo (no shared library copied in both).
3. **Lookyloo is a provider like any other.** URL Abuse calls it through
   **PyLookyloo**, which exposes all the Lookyloo calls (capture, redirects,
   tree, indexes). **No URL Abuse view, endpoint or logic is added to
   Lookyloo**: the maintainer does not want Lookyloo to become a "gas factory";
   a URL is a pivot towards many services.
4. **Compatibility.** The URL Abuse public API and the incoming data stream
   keep their format, so existing integrations (scripts, feeds, partners) keep
   working.
5. **The backend is rewritten.** Almost nothing in the current backend is kept;
   everything needed already exists in Lookyloo and the other providers.
6. **More providers later**, plugged into the broker the same way: MISP modules,
   then other pivot services (passive DNS, WHOIS, reputation…).
7. **New web interface** (in progress on this branch, see below).
8. **Full rebuild** (October 2026): new code from scratch, the old code only
   stays in the git history. Plan: [`doc/ROADMAP.md`](./doc/ROADMAP.md).
9. **A real API**: Flask 3 + flask-restx, self-documented with Swagger at
   `/doc`. v2 = the broker (`/api/v2/analyse`, `/api/v2/providers`…); the v1
   endpoints are reimplemented on top of it with the same payloads.
10. **Stack like Lookyloo**: poetry + `pyproject.toml`, Python >= 3.10,
    Valkey 8, `urlabuse/default/` (homedir, config, AbstractManager daemons),
    `config/*.json` with committed `.sample` files.
11. **Provider credentials** in `config/providers.json` (git-ignored,
    `config/providers.json.sample` committed).
12. **Broken v1 sources** (`/urlquery`, `/ticket`) are kept in the contract
    and answer "not configured" (empty body), like any unconfigured source.
13. **No third-party front-end file committed, no CDN** (Lookyloo rule):
    fonts and libraries are fetched at install time by `tools/3rdparty.py`.

## Repository layout (rebuild in progress, see `doc/ROADMAP.md`)

```
bin/                 Entry points (pyproject [project.scripts]): start, stop,
                     shutdown, run_backend (Valkey), start_website (gunicorn),
                     analysis_worker (runs the queued analyses)
urlabuse/default/    Plumbing shared with Lookyloo: get_homedir() (+ .env),
                     get_config() (config/*.json, fallback on the .sample),
                     get_socket_path(), AbstractManager (daemon base class)
urlabuse/providers/  Provider interface + registry + one module per provider
                     (lookyloo, dns, bgpranking; doc/providers.md)
urlabuse/cache.py    Provider answers cache in Valkey
urlabuse/analysis.py Analysis job: chain, URL and IP stages, verdict
                     (doc/architecture/jobs.md)
urlabuse/legacy.py   API v1 checks on the providers, get_cache + digest (doc/api/v1.md)
urlabuse/report.py   Reports to CIRCL by e-mail (doc/api/v2.md)
urlabuse/queries.py  v2 provider queries (one provider, one value) and cached results
website/web/         Flask app (doc/web.md): __init__.py (pages, errors, flask-restx
                     Api), genericapi.py (API v2 at /api/v2), legacy.py (API v1
                     routes), helpers.py (shared objects), credits_data.py
                     (/credits list), proxied.py
  templates/         layouts/base.html (head, header, footer), partials/ (header,
                     footer), index.html, api.html (vitrine <vt-openapi>),
                     credits.html, error.html
  static/            app.css (tokens, light/dark), app.js, theme.js, api.js, logos
    vendor/          git-ignored, installed by tools/3rdparty.py (vitrine)
config/              *.json.sample (committed) -> *.json (git-ignored):
                     generic, providers (credentials), logging
cache/               Valkey config + run_redis.sh
tools/               validate_config_files.py, 3rdparty.py (front-end libraries)
tests/unit/          No instance needed (Flask test client)
tests/contract/      v1 contract, against a running instance (doc/api/v1.md)
client/pyurlabuse/   Python client of the URL Abuse API (must keep working)
doc/                 install.md, ROADMAP.md, api/, architecture/
```

The code before the rebuild is tagged `legacy-v1` (`git worktree add
../url-abuse-legacy legacy-v1` to run it).

## Running and checking

```bash
poetry install --with dev
poetry run start / poetry run stop
poetry run ruff check . && poetry run mypy . && poetry run python -m pytest tests/unit
```

## Web interface (redesign)

- Layout, footer, credits page, light/dark themes and the URL field
  animation: `doc/web.md`. Add a line to `credits_data.py` for every new
  library, font, service or provider.
- One column: big intake ("Check a link before you trust it."), the checked
  URL typeset large in monospace (scheme faint, host bold, path muted), a
  **segmented progress bar where each segment is a real check**, then the
  verdict, the actions (send report to CIRCL, open the capture in Lookyloo,
  check another URL) and the redirect chain with per-hop and per-IP results.
- Verdict: a red block when any source flags the URL (count distinct sources),
  an ochre block when in doubt, a green block of the same weight when no
  source flags it (worded "No source flags this link", with the sources that
  checked it and a reminder that this is not proof), and a slate block "We
  can't tell if this link is dangerous" when no reputation source could check
  it; never claim a URL is safe. A source without an API key is shown as "not set up", never as an error.
- Light and dark themes from CSS tokens; Schibsted Grotesk for the UI,
  IBM Plex Mono only for data (URLs, IPs, hashes).
- Security: every value from a checked site or a provider is attacker
  controlled — insert it with `textContent`, links only http/https.
- The page uses API v2: `POST /api/v2/analyse`, then polls
  `GET /api/v2/analyse/<uuid>` and updates the rows that changed (doc/api/v2.md).
  Each provider has a reader in `static/app.js` (`readers`).

## Where we left off (2026-10-13)

- Done: new skeleton, providers `lookyloo`, `dns`, `bgpranking`, analysis jobs
  + worker, API v2 (`/analyse`, `/providers`, `/validate`,
  `/providers/<name>/query`, `/queries/<uuid>`, `/cached`, `/report`), API v1
  rebuilt on top, web page on API v2 with the four verdict blocks. 80 unit
  tests pass.
- Next (see `doc/ROADMAP.md`, unchecked boxes): providers with API keys
  (`phishtank`, `virustotal`, `googlesafebrowsing`, `eupi`), then `pdns_circl`,
  `pssl_circl`, `whois`/RDAP; retries and rate limiting; `pyurlabuse`
  `analyse()`; list the incoming feeds with the owner; remove the old code.
- To see the red and green verdicts locally, add at least one reputation key
  (Google Safe Browsing is free) in `config/providers.json`; without keys the
  page shows the slate "We can't tell" block, which is expected. Test URLs:
  `https://testsafebrowsing.appspot.com/s/phishing.html` (flagged),
  `https://www.circl.lu/` (not flagged).

## Open points

- Who sends data to URL Abuse today (feeds, partners, scripts) and in which
  format: to confirm with the owner (roadmap step 8).

## Conventions

- Code, comments, docs and commit messages in English.
- Commit messages: `<type>: [<section>] <description>` with `<type>` one of
  `add`, `chg`, `fix` (never `feat:`), no AI / Co-Authored-By attribution.
- Every feature ships with its documentation in the same change.
- Work on `ui-redesign`; do not push without the owner's review.
