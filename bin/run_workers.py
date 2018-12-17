#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
from multiprocessing import Pool
from rq import Worker, Queue, Connection
from redis import Redis
from urlabuse.helpers import get_socket_path


def worker(process_id: int):
    listen = ['default']
    cache_socket = get_socket_path('cache')
    with Connection(Redis(unix_socket_path=cache_socket)):
        worker = Worker(list(map(Queue, listen)))
        worker.work()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Launch a certain amount of workers.')
    parser.add_argument('-n', '--number', default=10, type=int, help='Amount of workers to launch.')
    args = parser.parse_args()

    with Pool(args.number) as p:
        p.map(worker, list(range(args.number)))
