#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class URLAbuseException(Exception):
    pass


class CreateDirectoryException(URLAbuseException):
    pass


class MissingEnv(URLAbuseException):
    pass
