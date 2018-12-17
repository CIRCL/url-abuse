#!/usr/bin/env python3

from datetime import date, timedelta
import redis
from urlabuse.helpers import get_socket_path
import argparse


def perdelta(start, end, delta):
    curr = start
    while curr < end:
        yield curr
        curr += delta


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Show on last 30 days.')
    args = parser.parse_args()

    r = redis.Redis(get_socket_path('cache'))

    for result in perdelta(date.today() - timedelta(days=30), date.today(), timedelta(days=1)):
        val = r.zcard('{}_submissions'.format(result))
        print('{},{}'.format(result, val))
