#!/usr/bin/env python3

'''Providers registry: every provider class registers itself with @register,
and Providers instantiates them from config/providers.json.
Doc: doc/providers.md'''

from __future__ import annotations

from typing import TypeVar

from ..cache import Cache
from ..default import get_config
from .base import Kind, Provider, ProviderResult, Status, Verdict, detect_kind

PROVIDER_CLASSES: dict[str, type[Provider]] = {}

P = TypeVar('P', bound=type[Provider])


def register(cls: P) -> P:
    if cls.name in PROVIDER_CLASSES:
        raise ValueError(f'Provider {cls.name} registered twice.')
    PROVIDER_CLASSES[cls.name] = cls
    return cls


class Providers:
    '''All the known providers, configured or not (a provider missing from
    the config file is instantiated disabled).'''

    def __init__(self, cache: Cache | None=None) -> None:
        config = get_config('providers')
        self.providers: dict[str, Provider] = {
            name: cls(config.get(name, {}), cache) for name, cls in PROVIDER_CLASSES.items()}

    def __getitem__(self, name: str) -> Provider:
        return self.providers[name]

    def __contains__(self, name: str) -> bool:
        return name in self.providers

    def all(self) -> list[Provider]:
        return list(self.providers.values())

    def enabled(self) -> list[Provider]:
        return [p for p in self.providers.values() if p.configured]

    def for_kind(self, kind: Kind) -> list[Provider]:
        return [p for p in self.enabled() if kind in p.accepts]


# Providers register themselves when imported (one module per provider)
from . import bgpranking, dns, lookyloo  # noqa: E402,F401

__all__ = ['Kind', 'PROVIDER_CLASSES', 'Provider', 'ProviderResult', 'Providers',
           'Status', 'Verdict', 'detect_kind', 'register']
