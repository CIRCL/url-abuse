#!/usr/bin/env python3
#
#
# Copyright (C) 2014 Sascha Rommelfangen, Raphael Vinot
# Copyright (C) 2014 CIRCL Computer Incident Response Center Luxembourg (SMILE gie)
#

from datetime import date, timedelta
import json
from redis import Redis
from urllib.parse import quote
from .helpers import get_socket_path
import ipaddress


from pyfaup.faup import Faup
import socket
import dns.resolver
import re
import logging
from pypdns import PyPDNS
from pyipasnhistory import IPASNHistory
from pybgpranking import BGPRanking


from pypssl import PyPSSL
from pyeupi import PyEUPI
import requests
from bs4 import BeautifulSoup

try:
    # import sphinxapi
    sphinx = True
except Exception:
    sphinx = False


class Query():

    def __init__(self, loglevel: int=logging.DEBUG):
        self.__init_logger(loglevel)
        self.fex = Faup()
        self.cache = Redis(unix_socket_path=get_socket_path('cache'), db=1,
                           decode_responses=True)

    def __init_logger(self, loglevel) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(loglevel)

    def _cache_set(self, key, value, field=None):
        if field is None:
            self.cache.setex(key, json.dumps(value), 3600)
        else:
            self.cache.hset(key, field, json.dumps(value))
            self.cache.expire(key, 3600)

    def _cache_get(self, key, field=None):
        if field is None:
            value_json = self.cache.get(key)
        else:
            value_json = self.cache.hget(key, field)
        if value_json is not None:
            return json.loads(value_json)
        return None

    def to_bool(self, s):
        """
        Converts the given string to a boolean.
        """
        return s.lower() in ('1', 'true', 'yes', 'on')

    def get_submissions(self, url, day=None):
        if day is None:
            day = date.today().isoformat()
        else:
            day = day.isoformat()
        return self.cache.zscore(f'{day}_submissions', url)

    def get_mail_sent(self, url, day=None):
        if day is None:
            day = date.today().isoformat()
        else:
            day = day.isoformat()
        return self.cache.sismember(f'{day}_mails', url)

    def set_mail_sent(self, url, day=None):
        if day is None:
            day = date.today().isoformat()
        else:
            day = day.isoformat()
        return self.cache.sadd(f'{day}_mails', url)

    def is_valid_url(self, url):
        cached = self._cache_get(url, 'valid')
        key = f'{date.today().isoformat()}_submissions'
        self.cache.zincrby(key, 1, url)
        if cached is not None:
            return cached
        if url.startswith('hxxp'):
            url = 'http' + url[4:]
        elif not url.startswith('http'):
            url = 'http://' + url
        logging.debug("Checking validity of URL: " + url)
        self.fex.decode(url)
        scheme = self.fex.get_scheme()
        host = self.fex.get_host()
        if scheme is None or host is None:
            reason = "Not a valid http/https URL/URI"
            return False, url, reason
        self._cache_set(url, (True, url, None), 'valid')
        return True, url, None

    def is_ip(self, host):
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def try_resolve(self, url):
        self.fex.decode(url)
        host = self.fex.get_host().lower()
        if self.is_ip(host):
            return True, None
        try:
            ipaddr = dns.resolver.query(host, 'A')
        except Exception:
            reason = "DNS server problem. Check resolver settings."
            return False, reason
        if not ipaddr:
            reason = "Host " + host + " does not exist."
            return False, reason
        return True, None

    def get_urls(self, url, depth=1):
        if depth > 5:
            print('Too many redirects.')
            return

        def meta_redirect(content):
            c = content.lower()
            soup = BeautifulSoup(c, "html.parser")
            for result in soup.find_all(attrs={'http-equiv': 'refresh'}):
                if result:
                    out = result["content"].split(";")
                    if len(out) == 2:
                        wait, text = out
                        try:
                            a, url = text.split('=', 1)
                            return url.strip()
                        except Exception:
                            print(text)
            return None

        resolve, reason = self.try_resolve(url)
        if not resolve:
            # FIXME: inform that the domain does not resolve
            yield url
            return

        logging.debug(f"Making HTTP connection to {url}")

        headers = {'User-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:8.0) Gecko/20100101 Firefox/8.0'}
        try:
            response = requests.get(url, allow_redirects=True, headers=headers,
                                    timeout=15, verify=False)
        except Exception:
            # That one can fail (DNS for example)
            # FIXME: inform that the get failed
            yield url
            return
        if response.history is not None:
            for h in response.history:
                # Yeld the urls in the order we find them
                yield h.url

        yield response.url

        meta_redir_url = meta_redirect(response.content)
        if meta_redir_url is not None:
            depth += 1
            if not meta_redir_url.startswith('http'):
                self.fex.decode(url)
                base = '{}://{}'.format(self.fex.get_scheme(), self.fex.get_host())
                port = self.fex.get_port()
                if port is not None:
                    base += f':{port}'
                if not meta_redir_url.startswith('/'):
                    # relative redirect. resource_path has the initial '/'
                    if self.fex.get_resource_path() is not None:
                        base += self.fex.get_resource_path()
                if not base.endswith('/'):
                    base += '/'
                meta_redir_url = base + meta_redir_url
            for url in self.get_urls(meta_redir_url, depth):
                yield url

    def url_list(self, url):
        cached = self._cache_get(url, 'list')
        if cached is not None:
            return cached
        list_urls = []
        for u in self.get_urls(url):
            if u is None or u in list_urls:
                continue
            list_urls.append(u)
        self._cache_set(url, list_urls, 'list')
        return list_urls

    def dns_resolve(self, url):
        cached = self._cache_get(url, 'dns')
        if cached is not None:
            return cached
        self.fex.decode(url)
        host = self.fex.get_host().lower()
        ipv4 = None
        ipv6 = None
        if self.is_ip(host):
            if ':' in host:
                try:
                    socket.inet_pton(socket.AF_INET6, host)
                    ipv6 = [host]
                except Exception:
                    pass
            else:
                try:
                    socket.inet_aton(host)
                    ipv4 = [host]
                except Exception:
                    pass
        else:
            try:
                ipv4 = [str(ip) for ip in dns.resolver.query(host, 'A')]
            except Exception:
                logging.debug("No IPv4 address assigned to: " + host)
            try:
                ipv6 = [str(ip) for ip in dns.resolver.query(host, 'AAAA')]
            except Exception:
                logging.debug("No IPv6 address assigned to: " + host)
        self._cache_set(url, (ipv4, ipv6), 'dns')
        return ipv4, ipv6

    def phish_query(self, url, key, query):
        cached = self._cache_get(query, 'phishtank')
        if cached is not None:
            return cached
        postfields = {'url': quote(query), 'format': 'json', 'app_key': key}
        response = requests.post(url, data=postfields)
        res = response.json()
        if res["meta"]["status"] == "success":
            if res["results"]["in_database"]:
                self._cache_set(query, res["results"]["phish_detail_page"], 'phishtank')
                return res["results"]["phish_detail_page"]
            else:
                # no information
                pass
        elif res["meta"]["status"] == 'error':
            # Inform the user?
            # errormsg = res["errortext"]
            pass
        return None

    def sphinxsearch(server, port, url, query):
        # WARNING: too dangerous to have on the public interface
        return ''
        """
        if not sphinx:
            return None
        cached = _cache_get(query, 'sphinx')
        if cached is not None:
            return cached
        client = sphinxapi.SphinxClient()
        client.SetServer(server, port)
        client.SetMatchMode(2)
        client.SetConnectTimeout(5.0)
        result = []
        res = client.Query(query)
        if res.get("matches") is not None:
            for ticket in res["matches"]:
                ticket_id = ticket["id"]
                ticket_link = url + str(ticket_id)
                result.append(ticket_link)
        _cache_set(query, result, 'sphinx')
        return result

        """

    def vt_query_url(self, url, url_up, key, query, upload=True):
        cached = self._cache_get(query, 'vt')
        if cached is not None:
            return cached
        parameters = {"resource": query, "apikey": key}
        if upload:
            parameters['scan'] = 1
        response = requests.post(url, data=parameters)
        if response.text is None or len(response.text) == 0:
            return None
        res = response.json()
        msg = res["verbose_msg"]
        link = res.get("permalink")
        positives = res.get("positives")
        total = res.get("total")
        if positives is not None:
            self._cache_set(query, (msg, link, positives, total), 'vt')
        return msg, link, positives, total

    def gsb_query(self, url, query):
        cached = self._cache_get(query, 'gsb')
        if cached is not None:
            return cached
        param = '1\n' + query
        response = requests.post(url, data=param)
        status = response.status_code
        if status == 200:
            self._cache_set(query, response.text, 'gsb')
            return response.text

    '''
    def urlquery_query(url, key, query):
        return None
        cached = _cache_get(query, 'urlquery')
        if cached is not None:
            return cached
        try:
            urlquery.url = url
            urlquery.key = key
            response = urlquery.search(query)
        except Exception:
            return None
        if response['_response_']['status'] == 'ok':
            if response.get('reports') is not None:
                total_alert_count = 0
                for r in response['reports']:
                    total_alert_count += r['urlquery_alert_count']
                    total_alert_count += r['ids_alert_count']
                    total_alert_count += r['blacklist_alert_count']
                    _cache_set(query, total_alert_count, 'urlquery')
                    return total_alert_count
            else:
                return None
    '''

    def process_emails(self, emails, ignorelist, replacelist):
        to_return = list(set(emails))
        for mail in reversed(to_return):
            for ignorelist_entry in ignorelist:
                if re.search(ignorelist_entry, mail, re.I):
                    if mail in to_return:
                        to_return.remove(mail)
            for k, v in list(replacelist.items()):
                if re.search(k, mail, re.I):
                    if k in to_return:
                        to_return.remove(k)
                        to_return += v
        return to_return

    def whois(self, server, port, domain, ignorelist, replacelist):
        cached = self._cache_get(domain, 'whois')
        if cached is not None:
            return cached
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(15)
        try:
            s.connect((server, port))
        except Exception:
            print("Connection problems - check WHOIS server")
            print(("WHOIS request while problem occurred: ", domain))
            print(("WHOIS server: {}:{}".format(server, port)))
            return None
        if domain.startswith('http'):
            self.fex.decode(domain)
            d = self.fex.get_domain().lower()
        else:
            d = domain
        s.send(("{}\r\n".format(d)).encode())
        response = b''
        while True:
            d = s.recv(4096)
            response += d
            if d == b'':
                break
        s.close()
        match = re.findall(r'[\w\.-]+@[\w\.-]+', response.decode())
        emails = self.process_emails(match, ignorelist, replacelist)
        if len(emails) == 0:
            return None
        list_mail = list(set(emails))
        self._cache_set(domain, list_mail, 'whois')
        return list_mail

    def pdnscircl(self, url, user, passwd, q):
        cached = self._cache_get(q, 'pdns')
        if cached is not None:
            return cached
        pdns = PyPDNS(url, basic_auth=(user, passwd))
        response = pdns.query(q)
        all_uniq = []
        for e in reversed(response):
            host = e['rrname'].lower()
            if host in all_uniq:
                continue
            else:
                all_uniq.append(host)
        response = (len(all_uniq), all_uniq[:5])
        self._cache_set(q, response, 'pdns')
        return response

    def psslcircl(self, url, user, passwd, q):
        cached = self._cache_get(q, 'pssl')
        if cached is not None:
            return cached
        pssl = PyPSSL(url, basic_auth=(user, passwd))
        response = pssl.query(q)
        if response.get(q) is not None:
            certinfo = response.get(q)
            entries = {}
            for sha1 in certinfo['certificates']:
                entries[sha1] = []
                if certinfo['subjects'].get(sha1):
                    for value in certinfo['subjects'][sha1]['values']:
                        entries[sha1].append(value)
            self._cache_set(q, entries, 'pssl')
            return entries
        return None

    def eupi(self, url, key, q):
        cached = self._cache_get(q, 'eupi')
        if cached is not None:
            return cached
        eu = PyEUPI(key, url)
        response = eu.search_url(url=q)
        if response.get('results'):
            r = response.get('results')[0]['tag_label']
            self._cache_set(q, r, 'eupi')
            return r
        eu.post_submission(q)
        return None

    def bgpranking(self, ip):
        cached = self._cache_get(ip, 'ipasn')
        if cached is not None:
            asn = cached['asn']
            prefix = cached['prefix']
        else:
            ipasn = IPASNHistory()
            response = ipasn.query(ip)
            if 'response' not in response:
                asn = None
                prefix = None
            entry = response['response'][list(response['response'].keys())[0]]
            if entry:
                self._cache_set(ip, entry, 'ipasn')
                asn = entry['asn']
                prefix = entry['prefix']
            else:
                asn = None
                prefix = None

        if not asn or not prefix:
            # asn, prefix, asn_descr, rank, position, known_asns
            return None, None, None, None, None, None

        cached = self._cache_get(ip, 'bgpranking')
        if cached is not None:
            return cached
        bgpranking = BGPRanking()
        response = bgpranking.query(asn, date=(date.today() - timedelta(1)).isoformat())
        if 'response' not in response or not response['response']:
            return None, None, None, None, None, None
        to_return = (asn, prefix, response['response']['asn_description'], response['response']['ranking']['rank'],
                     response['response']['ranking']['position'], response['response']['ranking']['total_known_asns'])
        self._cache_set(ip, to_return, 'bgpranking')
        return to_return

    def _deserialize_cached(self, entry):
        to_return = {}
        redirects = []
        h = self.cache.hgetall(entry)
        for key, value in h.items():
            v = json.loads(value)
            if key == 'list':
                redirects = v
                continue
            to_return[key] = v
        return to_return, redirects

    def get_url_data(self, url):
        data, redirects = self._deserialize_cached(url)
        if data.get('dns') is not None:
            ipv4, ipv6 = data['dns']
            ip_data = {}
            if ipv4 is not None:
                for ip in ipv4:
                    info, _ = self._deserialize_cached(ip)
                    ip_data[ip] = info
            if ipv6 is not None:
                for ip in ipv6:
                    info, _ = self._deserialize_cached(ip)
                    ip_data[ip] = info
            if len(ip_data) > 0:
                data.update(ip_data)
        return {url: data}, redirects

    def cached(self, url, digest=False):
        url_data, redirects = self.get_url_data(url)
        to_return = [url_data]
        for u in redirects:
            if u == url:
                continue
            data, redir = self.get_url_data(u)
            to_return.append(data)
        if digest:
            return {'result': to_return, 'digest': self.digest(to_return)}
        return {'result': to_return}

    def ip_details_digest(self, ips, all_info, all_asns, all_mails):
        to_return = ''
        for ip in ips:
            to_return += '\t' + ip + '\n'
            data = all_info[ip]
            if data.get('bgpranking'):
                to_return += '\t\tis announced by {} ({}). Position {}/{}.'.format(
                    data['bgpranking'][2], data['bgpranking'][0],
                    data['bgpranking'][4], data['bgpranking'][5])
                all_asns.add('{} ({})'.format(data['bgpranking'][2], data['bgpranking'][0]))
            if data.get('whois'):
                all_mails.update(data.get('whois'))
        return to_return

    def digest(self, data):
        to_return = ''
        all_mails = set()
        all_asns = set()
        for entry in data:
            # Each URL we're redirected to
            for url, info in entry.items():
                # info contains the information we got for the URL.
                to_return += '\n{}\n'.format(url)
                if 'whois' in info:
                    all_mails.update(info['whois'])
                if 'vt' in info and len(info['vt']) == 4:
                    to_return += '\t{} out of {} positive detections in VT - {}\n'.format(
                        info['vt'][2], info['vt'][3], info['vt'][1])
                if 'gsb' in info:
                    to_return += '\tKnown as malicious on Google Safe Browsing: {}\n'.format(info['gsb'])
                if 'phishtank' in info:
                    to_return += '\tKnown on PhishTank: {}\n'.format(info['phishtank'])

                if 'dns'in info:
                    ipv4, ipv6 = info['dns']
                    if ipv4 is not None:
                        to_return += self.ip_details_digest(ipv4, info, all_asns, all_mails)
                    if ipv6 is not None:
                        to_return += self.ip_details_digest(ipv6, info, all_asns, all_mails)
        return to_return, list(all_mails), list(all_asns)
