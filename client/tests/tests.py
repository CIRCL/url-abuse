#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from pyurlabuse import PyURLAbuse

import json


class TestPyUrlAbuse(unittest.TestCase):

    def test_digest(self):
        urlabuse = PyURLAbuse('http://0.0.0.0:5200')
        response = urlabuse.run_query('https://circl.lu/url-abuse')
        print(json.dumps(response, indent=2))
        self.assertTrue(response['result'])

if __name__ == '__main__':
    unittest.main()
