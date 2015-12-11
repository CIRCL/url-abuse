#!/usr/bin/env python

from datetime import date, timedelta
import redis


def perdelta(start, end, delta):
    curr = start
    while curr < end:
        yield curr
        curr += delta

r = redis.Redis('localhost', 6334, db=1)

for result in perdelta(date(2015, 03, 01), date(2015, 12, 12), timedelta(days=1)):
    val = r.zcard('{}_submissions'.format(result))
    print('{},{}'.format(result, val))
