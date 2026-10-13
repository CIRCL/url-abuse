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
                     shutdown, run_backend (Valkey), start_website (gunicorn)
urlabuse/default/    Plumbing shared with Lookyloo: get_homedir() (+ .env),
                     get_config() (config/*.json, fallback on the .sample),
                     get_socket_path(), AbstractManager (daemon base class)
urlabuse/providers/  Provider interface + registry (doc/providers.md)
urlabuse/cache.py    Provider answers cache in Valkey
urlabuse/            Core (jobs: roadmap step 5)
website/web/         Flask app: __init__.py (pages + flask-restx Api, Swagger
                     at /doc/), genericapi.py (API v2 at /api/v2), proxied.py
  templates/         index.html (new interface), api.html (API reference with
                     vitrine <vt-openapi>), error.html (404/405/500, doc/api/v2.md)
  static/            app.css, app.js, api.js, logos (new interface)
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

- URL field: example links are "typed" letter by letter in its placeholder
  (`app.js`, end of file); only the placeholder changes, it stops for good on
  focus or input, and is off with `prefers-reduced-motion`.
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
- Contract with the backend (to keep or to evolve together with the broker):
  `POST <check>` with `{"url": …}` or `{"query": …}` returns a job id as text
  (empty body = source not configured); `GET _result/<id>` answers 202 while
  pending, 200 with the JSON result when done; `POST submit` sends the report.

## Open points

- Who sends data to URL Abuse today (feeds, partners, scripts) and in which
  format: to confirm with the owner (roadmap step 8).

## Conventions

- Code, comments, docs and commit messages in English.
- Commit messages: `<type>: [<section>] <description>` with `<type>` one of
  `add`, `chg`, `fix` (never `feat:`), no AI / Co-Authored-By attribution.
- Every feature ships with its documentation in the same change.
- Work on `ui-redesign`; do not push without the owner's review.
