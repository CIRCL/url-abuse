# Install and run

URL Abuse needs Python 3.10+, [poetry](https://python-poetry.org/) and
**Valkey 8** (or Redis 8).

## Valkey

`cache/run_redis.sh` looks for `../../valkey/src/valkey-server` (a valkey clone
*next to* the url-abuse directory), then `../../redis/src/redis-server`, then
`/usr/bin/redis-server`, and refuses v7.

```bash
cd ..   # the directory that contains url-abuse
git clone https://github.com/valkey-io/valkey.git
cd valkey && git checkout 8.1 && make && cd ..
```

## URL Abuse

```bash
git clone https://github.com/CIRCL/url-abuse.git
cd url-abuse
poetry install
echo URLABUSE_HOME="'`pwd`'" > .env
poetry run tools/validate_config_files.py   # creates config/*.json from the samples
```

Review `config/generic.json` (port, reports to CIRCL) and fill the provider
credentials in `config/providers.json` (doc: the `_notes` of each sample).

## Run

```bash
poetry run start   # Valkey + website on http://0.0.0.0:5200
poetry run stop    # graceful stop
```

- Web page: `/`, API documentation (Swagger): `/doc/`, health: `/api/v2/health`.
- Logs: `logs/` (daemons), `website/logs/`, `cache/cache.log`.

## Checks

```bash
poetry run ruff check .
poetry run mypy .
poetry run python -m pytest tests/unit
URLABUSE_URL=http://127.0.0.1:5200/ poetry run python -m pytest tests/contract   # v1 contract, running instance
```

## Old version

The code before the rebuild is tagged `legacy-v1`. To run it next to the new
one: `git worktree add ../url-abuse-legacy legacy-v1` and follow its README
(pipenv, Faup, `config.ini`).
