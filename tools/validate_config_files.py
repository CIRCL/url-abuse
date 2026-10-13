#!/usr/bin/env python3

'''Check the config files against their samples: every sample key is
documented in _notes, the user files exist (copied from the samples when
missing) and their entries have the type of the sample.'''

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys

from typing import Any

from urlabuse.default import get_homedir

logger = logging.getLogger('Config validator')

CONFIG_FILES = ('generic', 'providers', 'logging')


def _check_types(sample: dict[str, Any], user: dict[str, Any], where: str) -> bool:
    ok = True
    for key, value in sample.items():
        if key == '_notes':
            continue
        if key not in user:
            logger.warning(f'{where}: {key} missing, the sample value is used.')
            continue
        if not isinstance(user[key], type(value)):
            logger.error(f'{where}: invalid type for {key}, got {type(user[key]).__name__}, expected {type(value).__name__}.')
            ok = False
        elif isinstance(value, dict) and key != 'replace':
            ok = _check_types(value, user[key], f'{where}.{key}') and ok
    for key in user:
        if key not in sample:
            logger.warning(f'{where}: {key} is not in the sample, it was probably removed.')
    return ok


def validate(name: str) -> bool:
    config_dir = get_homedir() / 'config'
    sample_path = config_dir / f'{name}.json.sample'
    user_path = config_dir / f'{name}.json'
    sample = json.loads(sample_path.read_text())
    ok = True
    if '_notes' in sample:
        for key in sample:
            if key != '_notes' and key not in sample['_notes']:
                logger.error(f'{name}: documentation missing in _notes for {key}.')
                ok = False
    if not user_path.exists():
        shutil.copy(sample_path, user_path)
        logger.info(f'{user_path} created from the sample, review it.')
    return _check_types(sample, json.loads(user_path.read_text()), name) and ok


def main() -> None:
    parser = argparse.ArgumentParser(description='Validate the config files.')
    parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    if not all([validate(name) for name in CONFIG_FILES]):
        sys.exit(1)
    print('Config files are valid.')


if __name__ == '__main__':
    main()
