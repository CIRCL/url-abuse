#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import Popen
from urlabuse.helpers import get_homedir

if __name__ == '__main__':
    website_dir = get_homedir() / 'website'
    Popen([f'{website_dir}/3drparty.sh'], cwd=website_dir)
    try:
        Popen(['gunicorn', '--worker-class', 'gevent', '-w', '10', '-b', '0.0.0.0:5100', 'web:app'],
              cwd=website_dir).communicate()
    except KeyboardInterrupt:
        print('Stopping gunicorn.')
