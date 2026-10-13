#!/usr/bin/env python3

'''Cache of the provider answers in Valkey, one key per (provider, value),
with a TTL. Doc: doc/providers.md'''

from __future__ import annotations

import hashlib
import json

from typing import Any

from redis import Redis

from .default import get_socket_path


class Cache:

    def __init__(self, redis: Redis | None=None) -> None:  # type: ignore[type-arg]
        self.redis = redis or Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

    @staticmethod
    def _key(provider: str, value: str) -> str:
        return f'cache|{provider}|{hashlib.sha256(value.encode()).hexdigest()}'

    def get(self, provider: str, value: str) -> Any:
        raw = self.redis.get(self._key(provider, value))
        return json.loads(raw) if raw is not None else None

    def set(self, provider: str, value: str, data: Any, ttl: int) -> None:
        self.redis.set(self._key(provider, value), json.dumps(data), ex=ttl)

    def delete(self, provider: str, value: str) -> None:
        self.redis.delete(self._key(provider, value))
