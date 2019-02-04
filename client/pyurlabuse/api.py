#!/bin/python
# -*- coding: utf-8 -*-

import json
import requests
import time
from urllib.parse import urljoin


class PyURLAbuse(object):

    def __init__(self, url='https://www.circl.lu/urlabuse/'):
        self.url = url

        self.session = requests.Session()
        self.session.headers.update({'content-type': 'application/json'})

    @property
    def is_up(self):
        r = self.session.head(self.root_url)
        return r.status_code == 200

    def get_result(self, job_id):
        response = self.session.get(urljoin(self.url, '_result/{}'.format(job_id)))
        if response.status_code == 202:
            return None
        else:
            return response.json()

    def _async(self, path, query):
        response = self.session.post(urljoin(self.url, path), data=json.dumps(query))
        return response.text

    def start(self, q):
        query = {'url': q}
        return self._async('start', query)

    def urls(self, q):
        query = {'url': q}
        return self._async('urls', query)

    def resolve(self, q):
        query = {'url': q}
        return self._async('resolve', query)

    def phishtank(self, q):
        query = {'query': q}
        return self._async('phishtank', query)

    def virustotal(self, q):
        query = {'query': q}
        return self._async('virustotal_report', query)

    def googlesafebrowsing(self, q):
        query = {'query': q}
        return self._async('googlesafebrowsing', query)

    def urlquery(self, q):
        query = {'query': q}
        return self._async('urlquery', query)

    def ticket(self, q):
        query = {'query': q}
        return self._async('ticket', query)

    def whoismail(self, q):
        query = {'query': q}
        return self._async('whois', query)

    def pdnscircl(self, q):
        query = {'query': q}
        return self._async('pdnscircl', query)

    def bgpr(self, q):
        query = {'query': q}
        return self._async('bgpranking', query)

    def sslcircl(self, q):
        query = {'query': q}
        return self._async('psslcircl', query)

    def lookyloo(self, q):
        query = {'url': q}
        return self._async('lookyloo', query)

    def _update_cache(self, cached):
        for result in cached['result']:
            for url, items in result.items():
                self.resolve(url)
                self.phishtank(url)
                self.virustotal(url)
                self.googlesafebrowsing(url)
                self.urlquery(url)
                self.ticket(url)
                self.whoismail(url)
                if 'dns' not in items:
                    continue
                for entry in items['dns']:
                    if entry is None:
                        continue
                    for ip in entry:
                        self.phishtank(ip)
                        self.bgpr(ip)
                        self.urlquery(ip)
                        self.pdnscircl(ip)
                        self.sslcircl(ip)
                        self.whoismail(ip)

    def run_query(self, q, with_digest=False):
        cached = self.get_cache(q, with_digest)
        if len(cached['result']) > 0:
            has_cached_content = True
            self._update_cache(cached)
            for r in cached['result']:
                for url, content in r.items():
                    if not content:
                        has_cached_content = False
            if has_cached_content:
                cached['info'] = 'Used cached content'
                return cached
        self.lookyloo(q)
        job_id = self.urls(q)
        all_urls = None
        while True:
            all_urls = self.get_result(job_id)
            if all_urls is None:
                time.sleep(.5)
            else:
                break

        res = {}
        for u in all_urls:
            res[u] = self.resolve(u)
            self.phishtank(u)
            self.virustotal(u)
            self.googlesafebrowsing(u)
            self.urlquery(u)
            self.ticket(u)
            self.whoismail(u)

        waiting = True
        done = []
        while waiting:
            waiting = False
            for u, job_id in res.items():
                if job_id in done:
                    continue
                ips = self.get_result(job_id)
                if ips is not None:
                    done.append(job_id)
                    v4, v6 = ips
                    if v4 is not None:
                        for ip in v4:
                            self.phishtank(ip)
                            self.bgpr(ip)
                            self.urlquery(ip)
                            self.pdnscircl(ip)
                            self.sslcircl(ip)
                            self.whoismail(ip)
                    if v6 is not None:
                        for ip in v6:
                            self.phishtank(ip)
                            self.bgpr(ip)
                            self.urlquery(ip)
                            self.pdnscircl(ip)
                            self.whoismail(ip)
                waiting = True
                time.sleep(.5)
        time.sleep(1)
        cached = self.get_cache(q, with_digest)
        cached['info'] = 'New query, all the details may not be available.'
        return cached

    def get_cache(self, q, digest=False):
        query = {'query': q, 'digest': digest}
        response = self.session.post(urljoin(self.url, 'get_cache'), data=json.dumps(query))
        return response.json()
