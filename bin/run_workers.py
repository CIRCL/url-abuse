#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
from multiprocessing import Pool
from redis import Redis
from urlabuse.helpers import get_socket_path
from urlabuse.urlabuse import Query
import json
import time


def worker(process_id: int):
    urlabuse_query = Query()
    queue = Redis(unix_socket_path=get_socket_path('cache'), db=0,
                  decode_responses=True)
    print(f'Start Worker {process_id}')
    while True:
        jobid = queue.spop('to_process')
        if not jobid:
            time.sleep(.1)
            continue
        to_process = queue.hgetall(jobid)
        parameters = json.loads(to_process['data'])
        try:
            result = getattr(urlabuse_query, to_process['method'])(**parameters)
            queue.hset(jobid, 'result', json.dumps(result))
        except Exception as e:
            print(e, to_process)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Launch a certain amount of workers.')
    parser.add_argument('-n', '--number', default=10, type=int, help='Amount of workers to launch.')
    args = parser.parse_args()

    with Pool(args.number) as p:
        p.map(worker, list(range(args.number)))
