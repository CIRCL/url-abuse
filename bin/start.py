#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import Popen
from urlabuse.helpers import get_homedir

import redis
import sys

if redis.VERSION < (3, ):
    print('redis-py >= 3 is required.')
    sys.exit()

if __name__ == '__main__':
    # Just fail if the env isn't set.
    get_homedir()
    p = Popen(['run_backend.py', '--start'])
    p.wait()
    Popen(['run_workers.py'])
