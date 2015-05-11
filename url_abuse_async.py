#!/usr/bin/env python
#
#
# Copyright (C) 2014 Sascha Rommelfangen, Raphael Vinot
# Copyright (C) 2014 CIRCL Computer Incident Response Center Luxembourg (SMILE gie)
#

from datetime import date
import json
import redis
try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote

from pyfaup.faup import Faup
import socket
import dns.resolver
import re
import sys
import logging
from pypdns import PyPDNS
import bgpranking_web
import urlquery
from pypssl import PyPSSL
import requests
from bs4 import BeautifulSoup

try:
    import sphinxapi
    sphinx = True
except:
    sphinx = False

enable_cache = True
r_cache = None


def _cache_init(host='localhost', port=6334, db=1):
    global r_cache
    if enable_cache and r_cache is None:
        r_cache = redis.Redis(host, port, db=db)


def _cache_set(key, value, field=None):
    _cache_init()
    if enable_cache:
        if field is None:
            r_cache.setex(key, json.dumps(value), 3600)
        else:
            r_cache.hset(key, field, json.dumps(value))
            r_cache.expire(key, 3600)


def _cache_get(key, field=None):
    _cache_init()
    if enable_cache:
        if field is None:
            value_json = r_cache.get(key)
        else:
            value_json = r_cache.hget(key, field)
        if value_json is not None:
            return json.loads(value_json)
    return None


def to_bool(s):
    """
    Converts the given string to a boolean.
    """
    return s.lower() in ('1', 'true', 'yes', 'on')


def get_submissions(url, day=None):
    _cache_init()
    if enable_cache:
        if day is None:
            day = date.today().isoformat()
        else:
            day = day.isoformat()
        key = date.today().isoformat() + '_submissions'
        return r_cache.zscore(key, url)


def get_mail_sent(url, day=None):
    _cache_init()
    if enable_cache:
        if day is None:
            day = date.today().isoformat()
        else:
            day = day.isoformat()
        key = date.today().isoformat() + '_mails'
        return r_cache.sismember(key, url)


def set_mail_sent(url, day=None):
    _cache_init()
    if enable_cache:
        if day is None:
            day = date.today().isoformat()
        else:
            day = day.isoformat()
        key = date.today().isoformat() + '_mails'
        return r_cache.sadd(key, url)


def is_valid_url(url):
    cached = _cache_get(url, 'valid')
    key = date.today().isoformat() + '_submissions'
    r_cache.zincrby(key, url)
    if cached is not None:
        return cached
    fex = Faup()
    if url.startswith('hxxp'):
        url = 'http' + url[4:]
    elif not url.startswith('http'):
        url = 'http://' + url
    logging.debug("Checking validity of URL: " + url)
    fex.decode(url)
    scheme = fex.get_scheme()
    host = fex.get_host()
    if scheme is None or host is None:
        reason = "Not a valid http/https URL/URI"
        return False, url, reason
    _cache_set(url, (True, url, None), 'valid')
    return True, url, None


def is_ip(host):
    if ':' in host:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except:
            pass
    else:
        try:
            socket.inet_aton(host)
            return True
        except:
            pass
    return False


def try_resolve(fex, url):
    fex.decode(url)
    host = fex.get_host().lower()
    if is_ip(host):
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


def get_urls(url, depth=1):
    if depth > 5:
        print('Too many redirects.')
        return
    fex = Faup()

    def meta_redirect(content):
        c = content.lower()
        soup = BeautifulSoup(c)
        for result in soup.find_all(attrs={'http-equiv': 'refresh'}):
            if result:
                out = result["content"].split(";")
                if len(out) == 2:
                    wait, text = out
                    a, url = text.split('=', 1)
                    return url.strip()
        return None

    resolve, reason = try_resolve(fex, url)
    if not resolve:
        # FIXME: inform that the domain does not resolve
        yield url
        return

    logging.debug("Making HTTP connection to " + url)

    headers = {'User-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:8.0) Gecko/20100101 Firefox/8.0'}
    try:
        response = requests.get(url, allow_redirects=True, headers=headers,
                                timeout=15, verify=False)
    except:
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
            fex.decode(url)
            base = '{}://{}'.format(fex.get_scheme(), fex.get_host())
            port = fex.get_port()
            if port is not None:
                base += ':{}'.format(port)
            if not meta_redir_url.startswith('/'):
                # relative redirect. resource_path has the initial '/'
                if fex.get_resource_path() is not None:
                    base += fex.get_resource_path()
            if not base.endswith('/'):
                base += '/'
            meta_redir_url = base + meta_redir_url
        for url in get_urls(meta_redir_url, depth):
            yield url


def url_list(url):
    cached = _cache_get(url, 'list')
    if cached is not None:
        return cached
    list_urls = []
    for u in get_urls(url):
        if u is None or u in list_urls:
            continue
        list_urls.append(u)
    _cache_set(url, list_urls, 'list')
    return list_urls


def dns_resolve(url):
    cached = _cache_get(url, 'dns')
    if cached is not None:
        return cached
    fex = Faup()
    fex.decode(url)
    host = fex.get_host().lower()
    ipv4 = None
    ipv6 = None
    if not is_ip(host):
        try:
            ipv4 = [str(ip) for ip in dns.resolver.query(host, 'A')]
        except:
            logging.debug("No IPv4 address assigned to: " + host)
        try:
            ipv6 = [str(ip) for ip in dns.resolver.query(host, 'AAAA')]
        except:
            logging.debug("No IPv6 address assigned to: " + host)
    _cache_set(url, (ipv4, ipv6), 'dns')
    return ipv4, ipv6


def phish_query(url, key, query):
    cached = _cache_get(query, 'phishtank')
    if cached is not None:
        return cached
    postfields = {'url': quote(query), 'format': 'json', 'app_key': key}
    response = requests.post(url, data=postfields)
    res = response.json()
    if res["meta"]["status"] == "success":
        if res["results"]["in_database"]:
            _cache_set(query, res["results"]["phish_detail_page"], 'phishtank')
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


def vt_query_url(url, url_up, key, query, upload=True):
    cached = _cache_get(query, 'vt')
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
        _cache_set(query, (msg, link, positives, total), 'vt')
    return msg, link, positives, total


def gsb_query(url, query):
    cached = _cache_get(query, 'gsb')
    if cached is not None:
        return cached
    param = '1\n' + query
    response = requests.post(url, data=param)
    status = response.status_code
    if status == 200:
        _cache_set(query, response.text, 'gsb')
        return response.text


def urlquery_query(url, key, query):
    cached = _cache_get(query, 'urlquery')
    if cached is not None:
        return cached
    try:
        urlquery.url = url
        urlquery.key = key
        response = urlquery.search(query)
    except:
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


def process_emails(emails, ignorelist, replacelist):
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


def whois(server, port, domain, ignorelist, replacelist):
    cached = _cache_get(domain, 'whois')
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
        sys.exit(0)
    if domain.startswith('http'):
        fex = Faup()
        fex.decode(domain)
        d = fex.get_domain().lower()
    else:
        d = domain
    s.send(d + "\r\n")
    response = ''
    while True:
        d = s.recv(4096)
        response += d
        if d == '':
            break
    s.close()
    match = re.findall(r'[\w\.-]+@[\w\.-]+', response)
    emails = process_emails(match, ignorelist, replacelist)
    if len(emails) == 0:
        return None
    list_mail = list(set(emails))
    _cache_set(domain, list_mail, 'whois')
    return list_mail


def pdnscircl(url, user, passwd, q):
    cached = _cache_get(q, 'pdns')
    if cached is not None:
        return cached
    pdnscircl = PyPDNS(url, basic_auth=(user, passwd))
    response = pdnscircl.query(q)
    all_uniq = []
    for e in reversed(response):
        host = e['rrname'].lower()
        if host in all_uniq:
            continue
        else:
            all_uniq.append(host)
    response = (len(all_uniq), all_uniq[:5])
    _cache_set(q, response, 'pdns')
    return response


def psslcircl(url, user, passwd, q):
    cached = _cache_get(q, 'pssl')
    if cached is not None:
        return cached
    psslcircl = PyPSSL(url, basic_auth=(user, passwd))
    response = psslcircl.query(q)
    if response.get(q) is not None:
        entries = response[q]
        _cache_set(q, entries, 'pssl')
        return entries
    return None


def bgpranking(ip):
    cached = _cache_get(ip, 'bgp')
    if cached is not None:
        return cached
    details = bgpranking_web.ip_lookup(ip, 7)
    ptrr = details.get('ptrrecord')
    if details.get('history') is None or len(details.get('history')) == 0:
        return ptrr, None, None, None, None, None
    asn = details['history'][0].get('asn')
    rank_info = bgpranking_web.cached_daily_rank(asn)
    position, total = bgpranking_web.cached_position(asn)
    asn_descr = rank_info[1]
    rank = rank_info[-1]
    response = (ptrr, asn_descr, asn, int(position), int(total), float(rank))
    _cache_set(ip, response, 'bgp')
    return response


def _deserialize_cached(entry):
    to_return = {}
    h = r_cache.hgetall(entry)
    for key, value in list(h.items()):
        to_return[key] = json.loads(value)
    return to_return


def get_url_data(url):
    data = _deserialize_cached(url)
    if data.get('dns') is not None:
        ipv4, ipv6 = data['dns']
        ip_data = {}
        if ipv4 is not None:
            for ip in ipv4:
                ip_data[ip] = _deserialize_cached(ip)
        if ipv6 is not None:
            for ip in ipv6:
                ip_data[ip] = _deserialize_cached(ip)
        if len(ip_data) > 0:
            data.update(ip_data)
    return {url: data}


def cached(url):
    _cache_init()
    if not enable_cache:
        return [url]
    url_data = get_url_data(url)
    to_return = [url_data]
    if url_data[url].get('list') is not None:
        url_redirs = url_data[url]['list']
        for u in url_redirs:
            if u == url:
                continue
            to_return.append(get_url_data(u))
    return to_return
