#!/usr/bin/env python3

'''Objects shared by the routes, created on first use (one per gunicorn worker).'''

from __future__ import annotations

from functools import lru_cache

from flask import Request

from urlabuse.analysis import Analyses
from urlabuse.cache import Cache
from urlabuse.legacy import LegacyJobs
from urlabuse.providers import Providers
from urlabuse.queries import Queries
from urlabuse.report import Reports


@lru_cache(1)
def get_providers() -> Providers:
    return Providers(Cache())


@lru_cache(1)
def get_analyses() -> Analyses:
    return Analyses(get_providers())


@lru_cache(1)
def get_legacy() -> LegacyJobs:
    return LegacyJobs(get_providers(), Cache())


@lru_cache(1)
def get_queries() -> Queries:
    return Queries(get_providers(), Cache())


@lru_cache(1)
def get_reports() -> Reports:
    return Reports(get_legacy())


def client_ip(request: Request) -> str:
    return request.headers.get('X-Forwarded-For') or request.remote_addr or ''
