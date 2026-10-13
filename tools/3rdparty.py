#!/usr/bin/env python3

"""Install the third-party front-end resources in website/web/static/vendor/
(git-ignored: no third-party file is committed, AGENTS.md decision 13).

- Vitrine (https://github.com/ecrou-exact/vitrine, web components, used by the
  API page): source tarball of a pinned commit, SHA-256 checked, built with
  Node >= 20 (`npm ci --ignore-scripts` + `node scripts/build.js`), only the ES
  modules, languages, syntax themes and vendor files are kept.

Without Node or network on the server, build it elsewhere and install the
`dist/` folder of a vitrine checkout at the same commit:

    poetry run tools/3rdparty.py --vitrine-dist /path/to/vitrine/dist
"""

from __future__ import annotations

import argparse
import hashlib
import io
import shutil
import subprocess
import sys
import tarfile
import tempfile

from pathlib import Path

import requests

from urlabuse.default import get_homedir

VITRINE_COMMIT = '7c379edba7ffb89abcae01b0806f20ed43dbc627'
VITRINE_TARBALL = f'https://codeload.github.com/ecrou-exact/vitrine/tar.gz/{VITRINE_COMMIT}'
VITRINE_SHA256 = 'baad470e885837d27e8f820b3df9f936047003ac864be4542c4d48ed90ba550a'
# What the website needs from vitrine's dist/
VITRINE_KEEP = ('esm', 'languages', 'syntax-themes', 'vendor', 'vitrine.css')


def build_vitrine(workdir: Path) -> Path:
    if not shutil.which('node') or not shutil.which('npm'):
        raise SystemExit('Vitrine is built with Node >= 20 (node and npm not found). '
                         'Install Node, or use --vitrine-dist (see the doc of this script).')
    response = requests.get(VITRINE_TARBALL, timeout=120)
    response.raise_for_status()
    if hashlib.sha256(response.content).hexdigest() != VITRINE_SHA256:
        raise SystemExit(f'Vitrine {VITRINE_COMMIT[:10]}: SHA-256 mismatch, refusing to build it.')
    with tarfile.open(fileobj=io.BytesIO(response.content), mode='r:gz') as tar:
        tar.extractall(workdir, filter='data')
    source = workdir / f'vitrine-{VITRINE_COMMIT}'
    subprocess.run(['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'], cwd=source, check=True)
    subprocess.run(['node', 'scripts/build.js'], cwd=source, check=True)
    return source / 'dist'


def install_vitrine(dist: Path, dest: Path) -> None:
    if not (dist / 'esm' / 'vt-openapi.js').exists():
        raise SystemExit(f'{dist} is not a vitrine dist/ folder (esm/vt-openapi.js missing).')
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for name in VITRINE_KEEP:
        source = dist / name
        if source.is_dir():
            shutil.copytree(source, dest / name, ignore=shutil.ignore_patterns('*.map'))
        elif source.exists():
            shutil.copy2(source, dest / name)
    (dest / 'COMMIT').write_text(VITRINE_COMMIT + '\n')
    print(f'Installed vitrine {VITRINE_COMMIT[:10]} in {dest}.')


def main() -> None:
    parser = argparse.ArgumentParser(description='Install the third-party front-end resources.')
    parser.add_argument('--vitrine-dist', type=Path, help='Install vitrine from an already built dist/ folder.')
    args = parser.parse_args()

    vendor = get_homedir() / 'website' / 'web' / 'static' / 'vendor'
    if args.vitrine_dist:
        install_vitrine(args.vitrine_dist, vendor / 'vitrine')
    else:
        with tempfile.TemporaryDirectory() as tmp:
            install_vitrine(build_vitrine(Path(tmp)), vendor / 'vitrine')
    sys.exit(0)


if __name__ == '__main__':
    main()
