# Roadmap — full rebuild of URL Abuse as an API broker for URLs

URL Abuse is **rebuilt from scratch** (decision 5 in `AGENTS.md`): new
package, new backend, new install. Nothing of `urlabuse/urlabuse.py`,
`bin/` or `website/web/__init__.py` is ported; the old code only serves as a
reference for the behaviour to reproduce. The only thing kept on purpose is
the **public contract** (decision 4): v1 endpoints, their payloads and the
incoming data stream.

Each step is one or a few commits, ships with its docs, and is checked before
the next one starts. Tick the boxes as the work lands.

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done

---

## The contract to keep (v1)

Used today by the web page, `client/pyurlabuse` and external integrations.
The rebuild must answer them identically (checked by the step 1 suite).

| Endpoint | Body | Answer |
|---|---|---|
| `POST /start` | `{"url": u}` | job id (text) → URL validity |
| `POST /urls` | `{"url": u}` | job id → list of URLs of the redirect chain |
| `POST /resolve` | `{"url": u}` | job id → `[ipv4 list, ipv6 list]` |
| `POST /lookyloo` | `{"url": u}` | job id → Lookyloo permalink |
| `POST /phishtank`, `/virustotal_report`, `/googlesafebrowsing`, `/eupi` | `{"query": u}` | job id (empty body = source not configured) |
| `POST /urlquery`, `/ticket` | `{"query": u}` | job id (**broken today**: old RQ code) |
| `POST /whois`, `/pdnscircl`, `/psslcircl`, `/bgpranking` | `{"query": u_or_ip}` | job id |
| `GET /_result/<id>` | — | `202 "Nay!"` pending · `200` JSON result (job deleted) · `200 null` unknown id |
| `POST /get_cache` | `{"query": u, "digest": bool}` | `{"result": [...], "digest": [text, ...]}` |
| `POST /submit` | `{"url": u}` | sends the report to CIRCL (max once a day per URL) |
| `GET /urlreport` | `?url=` | HTML report |

---

## Step 0 — Decisions before writing code

- [x] Decided, see `AGENTS.md` (decisions 8–13): real API with flask-restx,
      poetry, Lookyloo-like layout, credentials in `config/providers.json`,
      `urlquery`/`ticket` answer "not configured", no CDN, old code only in git
      history.

## Step 1 — Contract suite on the current code

The safety net that lets us throw the old code away.

- [x] `tests/contract/`: pytest suite calling every v1 endpoint against a
      running instance (`URLABUSE_URL`), checking status codes and JSON shapes.
- [x] Fixtures recorded from the current instance for a few URLs (simple,
      with redirects, IP literal, invalid URL, unconfigured source).
- [ ] `client/pyurlabuse` tests (`run_query`, `get_cache`) in the same suite (moved to step 8, with the client update).
- [x] Doc: `doc/api/v1.md` (the table above + example payloads).

**Done when** the suite passes against the current code. ✔ 21 tests
(`tests/contract/test_v1.py`, doc `doc/api/v1.md`). Providers are checked
configured or not, so no fixture files are needed.

## Step 2 — New skeleton

- [x] `pyproject.toml` (poetry), scripts `start`, `stop`, `shutdown`, `run_backend`, `start_website` (`update` comes with step 10).
- [x] `urlabuse/default/`: `get_homedir()` (+ `.env`), `get_config()`,
      `get_socket_path()`, `AbstractManager`.
- [x] `cache/run_redis.sh`: valkey next to the repo, then redis, then `/usr/bin`.
- [x] `config/generic.json.sample`, `config/providers.json.sample`,
      `tools/validate_config_files.py`.
- [x] Empty Flask app with flask-restx, `/doc`, health route.
- [x] CI: mypy, ruff, unit tests.
- [x] Doc: `doc/install.md`, README "Install", `AGENTS.md` layout.

**Done when** `poetry install && poetry run start` starts Valkey + an empty website. ✔
The old code was removed in place (paths collide with the new layout) and
tagged `legacy-v1`. Until step 7, the web page loads but its checks fail (no
v1 endpoints); the Google Fonts link of `index.html` is handled in step 8.

## Step 3 — Provider interface and cache

- [x] `urlabuse/providers/base.py`:
  ```python
  class Provider(ABC):
      name: str                       # 'virustotal', 'lookyloo', ...
      accepts: set[str]               # {'url'}, {'ip'}, {'domain'}...
      def available(self) -> bool     # configured and reachable
      def query(self, value: str) -> ProviderResult
  ```
  `ProviderResult`: `status` (`ok` | `not_configured` | `error` | `pending`),
  `data` (raw answer), `verdict` (`malicious` | `suspicious` | `clean` |
  `unknown`, reputation sources only), `links` (permalinks).
- [x] Registry built from `config/providers.json`.
- [x] Cache per (provider, value) with TTL in Valkey.
- [x] Doc: `doc/providers.md` (how to write a provider).

**Done** ✔ `urlabuse/providers/`, `urlabuse/cache.py`, 15 unit tests
(`tests/unit/test_providers.py`). Statuses also have `not_applicable`
(kind not taken), and kinds are `url` / `hostname` / `ip`.

## Step 4 — Providers

One commit per provider, each with unit tests (mocked HTTP) and a line in
`doc/providers.md`. No analysis logic of our own: use the provider's library.

- [ ] `lookyloo` (PyLookyloo): capture, **redirect chain, IPs and hostnames
      from the capture** — replaces the old crawler and most of the DNS work
- [ ] `resolve` (dnspython), only for what Lookyloo does not give
- [ ] `phishtank`, `virustotal`, `googlesafebrowsing`, `eupi` (pyeupi)
- [ ] `pdns_circl` (pypdns), `pssl_circl` (pypssl)
- [ ] `ipasn` + `bgpranking` (pyipasnhistory, pybgpranking2)
- [ ] `whois` / RDAP (abuse contacts, ignore/replace lists)
- [ ] URL parsing: check if Faup is still needed (Lookyloo / `publicsuffix2`
      / `urllib` may be enough → no C library to build)

## Step 5 — Analysis jobs

- [ ] `Analysis`: URL → `lookyloo` (chain, IPs) → URL providers per URL →
      IP providers per IP; results stored per node, progress counted.
- [ ] Worker daemon (`bin/analysis_worker.py`, `AbstractManager`), timeouts and
      retries per provider, job TTL.
- [ ] Report: digest text + JSON, sent to CIRCL at most once a day per URL.
- [ ] Doc: `doc/architecture/jobs.md`.

## Step 6 — API v2 (the broker)

- [ ] `POST /api/v2/analyse` `{"url": …}` → `{"uuid": …}`
- [ ] `GET /api/v2/analyse/<uuid>` → URLs, IPs, per-provider status/result,
      overall verdict, progress
- [ ] `GET /api/v2/providers` → providers, accepted types, configured or not
- [ ] `POST /api/v2/providers/<name>` `{"value": …}` → one provider call
- [ ] `POST /api/v2/report` → report to CIRCL
- [ ] Input validation (http/https only, size limits), rate limiting.
- [ ] Doc: Swagger + `doc/api/v2.md`.

## Step 7 — v1 compatibility layer

- [ ] `website/web/legacy.py`: every v1 route reimplemented on top of the
      providers/jobs (`/start`, `/urls`, …, `/_result/<id>`, `/get_cache`,
      `/submit`, `/urlreport`), same payloads.
- [ ] Step 1 contract suite passes against the **new** code.

**Done when** the contract suite is green on the rebuild: the old code can go.

## Step 8 — Clients and entry points

- [ ] Web page (`static/app.js`): `POST /api/v2/analyse` + polling
      `GET /api/v2/analyse/<uuid>`; the segmented bar maps to the job's providers.
- [ ] `pyurlabuse`: new `analyse()` on v2, old methods kept.
- [ ] Incoming data stream: list the current feeds/integrations (who sends
      what, format — to confirm with the owner), keep their input, route to `analyse`.
- [ ] **Lookyloo browser plugin**: the existing extension already sends a URL
      to Lookyloo. Check what it calls; either let it target URL Abuse
      (`analyse` gives Lookyloo + every other provider) or add a "check with
      URL Abuse" action. Must not add URL-Abuse-specific code to Lookyloo (decision 3).

## Step 9 — Remove the old code

- [ ] Delete `urlabuse/urlabuse.py`, the old `bin/`, the old Flask app,
      AngularJS files in `static/`, pipenv/setup.py files.
- [ ] Deprecation notice for v1 in `doc/api/v1.md` (kept working, v2 recommended).

## Step 10 — More providers and release

- [ ] MISP modules (misp-modules HTTP API) as a provider family.
- [ ] Other pivot services (RDAP, reputation, …).
- [ ] Docker / systemd samples, release notes, architecture diagram updated.
