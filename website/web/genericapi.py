#!/usr/bin/env python3

'''API v2 of URL Abuse, mounted at /api/v2 (doc/api/v2.md).'''

from __future__ import annotations

from importlib.metadata import version
from typing import Any

from flask_restx import Namespace, Resource  # type: ignore[import-untyped]
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from urlabuse.default import get_socket_path

api = Namespace('GenericAPI', description='URL Abuse API v2', path='/api/v2')


@api.route('/health')
@api.doc(description='Is the instance up, and is its database reachable?')
class Health(Resource):  # type: ignore[misc]

    def get(self) -> tuple[dict[str, Any], int]:
        try:
            db_up = bool(Redis(unix_socket_path=get_socket_path('cache')).ping())
        except RedisConnectionError:
            db_up = False
        return {'status': 'ok' if db_up else 'degraded', 'database': db_up,
                'version': version('urlabuse')}, 200 if db_up else 503
