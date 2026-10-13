#!/usr/bin/env python3


class URLAbuseException(Exception):
    pass


class MissingEnv(URLAbuseException):
    pass


class CreateDirectoryException(URLAbuseException):
    pass


class ConfigError(URLAbuseException):
    pass
