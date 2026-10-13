#!/usr/bin/env python3

'''Reports to CIRCL (POST /api/v2/report, v1 POST /submit): the digest and the
cached results of a URL, by e-mail, at most once a day per host. A URL
submitted many times in a day is reported automatically.
Configuration: "report" in config/generic.json. Doc: doc/api/v2.md'''

from __future__ import annotations

import json
import smtplib

from datetime import date
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlsplit

from redis import Redis

from .default import get_config, get_socket_path
from .legacy import LegacyJobs

DAY_TTL = 2 * 24 * 3600


class ReportsDisabled(Exception):
    pass


class Reports:

    def __init__(self, legacy: LegacyJobs, redis: Redis | None=None,  # type: ignore[type-arg]
                 config: dict[str, Any] | None=None) -> None:
        self.redis = redis or Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        self.legacy = legacy
        self.config = config if config is not None else get_config('generic', 'report')

    @property
    def enabled(self) -> bool:
        return bool(self.config.get('enabled'))

    @staticmethod
    def _day() -> str:
        return date.today().isoformat()

    def count_submission(self, url: str) -> int:
        key = f'{self._day()}_submissions'
        count = self.redis.zincrby(key, 1, url)
        self.redis.expire(key, DAY_TTL)
        return int(count)

    def should_autosend(self, submissions: int) -> bool:
        return self.enabled and submissions >= int(self.config.get('autosend_threshold', 5))

    def already_sent(self, url: str) -> bool:
        return bool(self.redis.sismember(f'{self._day()}_mails', urlsplit(url).hostname or url))

    def send(self, url: str, source_ip: str='', auto: bool=False) -> bool:
        '''True when sent, False when this host was already reported today.'''
        if not self.enabled:
            raise ReportsDisabled('Reports to CIRCL are not enabled on this instance.')
        if self.already_sent(url):
            return False
        cached = self.legacy.cached(url, digest=True)
        message = EmailMessage()
        message['Subject'] = ('URL Abuse report sent automatically' if auto
                              else f'URL Abuse report from {source_ip}')
        message['From'] = self.config['sender']
        message['To'] = ', '.join(self.config['recipients'])
        message.set_content(cached['digest'][0] + '\n\n' + json.dumps(cached['result'], sort_keys=True, indent=2))
        with smtplib.SMTP(self.config.get('smtp_host', 'localhost'), int(self.config.get('smtp_port', 25)), timeout=30) as smtp:
            smtp.send_message(message)
        key = f'{self._day()}_mails'
        self.redis.sadd(key, urlsplit(url).hostname or url)
        self.redis.expire(key, DAY_TTL)
        return True
