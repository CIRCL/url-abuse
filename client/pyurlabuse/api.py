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
        response = self.session.get(urljoin(self.url, f'_result/{job_id}'))
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

    def run_query(self, q):
        cached = self.get_cache(q)
        if len(cached[0][q]) > 0:
            return {'info': 'Used cached content'}, cached
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
                            self.ticket(ip)
                            self.whoismail(ip)
                    if v6 is not None:
                        for ip in v6:
                            self.phishtank(ip)
                            self.urlquery(ip)
                            self.pdnscircl(ip)
                            self.ticket(ip)
                            self.whoismail(ip)
                waiting = True
                time.sleep(.5)
        time.sleep(1)
        return {'info': 'New query, all the details may not be available.'}, self.get_cache(q)

    def get_cache(self, q):
        query = {'query': q}
        response = self.session.post(urljoin(self.url, 'get_cache'), data=json.dumps(query))
        return response.json()
