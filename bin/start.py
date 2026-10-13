#!/usr/bin/env python3

from subprocess import Popen, run

from urlabuse.default import get_homedir


def main() -> None:
    # Just fail if the env isn't set.
    get_homedir()
    print('Start backend (valkey)...')
    p = run(['run_backend', '--start'])
    try:
        p.check_returncode()
    except Exception:
        print('Failed to start the backend, exiting.')
        return
    print('done.')
    print('Start website...')
    Popen(['start_website'])
    print('done.')


if __name__ == '__main__':
    main()
