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

## Repository layout (current code, before the rebuild)

```
bin/                 start.py, run_backend.py (Redis), run_workers.py (RQ workers),
                     start_website.py, stats.py
urlabuse/urlabuse.py Current checks (redirects, resolve, PhishTank, VirusTotal, Google
                     Safe Browsing, URLquery, passive DNS/SSL, BGP ranking, WHOIS,
                     EUPI, Lookyloo, RT tickets) — to be replaced by provider calls
website/web/         Flask app: one POST route per check returning a job id,
                     GET /_result/<job_id>, POST /submit (report to CIRCL)
  templates/         index.html (new interface), url-report.html, 404.html
  static/            app.css, app.js, logos (new interface)
client/pyurlabuse/   Python client of the URL Abuse API (must keep working)
doc/architecture/    Architecture diagram (PNG + Pivograph JSON)
```

## Web interface (redesign)

- One column: big intake ("Check a link before you trust it."), the checked
  URL typeset large in monospace (scheme faint, host bold, path muted), a
  **segmented progress bar where each segment is a real check**, then the
  verdict, the actions (send report to CIRCL, open the capture in Lookyloo,
  check another URL) and the redirect chain with per-hop and per-IP results.
- Verdict: a red block when any source flags the URL (count distinct sources),
  an ochre block when in doubt, a quiet note otherwise; never claim a URL is
  safe. A source without an API key is shown as "not set up", never as an error.
- Light and dark themes from CSS tokens; Schibsted Grotesk for the UI,
  IBM Plex Mono only for data (URLs, IPs, hashes).
- Security: every value from a checked site or a provider is attacker
  controlled — insert it with `textContent`, links only http/https.
- Contract with the backend (to keep or to evolve together with the broker):
  `POST <check>` with `{"url": …}` or `{"query": …}` returns a job id as text
  (empty body = source not configured); `GET _result/<id>` answers 202 while
  pending, 200 with the JSON result when done; `POST submit` sends the report.

## Open points

- **Fonts from Google Fonts**: `templates/index.html` loads Schibsted Grotesk and
  IBM Plex Mono from `fonts.googleapis.com`. Lookyloo serves everything locally
  (no CDN, CSP `default-src 'self'`) and does not commit third-party files (they
  are downloaded by a `tools/3rdparty.py` script). Decide whether URL Abuse
  follows the same rule; if so, download the fonts at install time.
- Shape of the broker API (one aggregated call, or one call per provider as
  today) and how the existing endpoints map onto it.
- Where provider credentials live (today: API key files at the repository root).

## Conventions

- Code, comments, docs and commit messages in English.
- Commit messages: `<type>: [<section>] <description>` with `<type>` one of
  `add`, `chg`, `fix` (never `feat:`), no AI / Co-Authored-By attribution.
- Every feature ships with its documentation in the same change.
- Work on `ui-redesign`; do not push without the owner's review.
