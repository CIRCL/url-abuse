import json
import os
from pathlib import Path

from flask import Flask, render_template, request, Response, redirect, url_for
from flask_mail import Mail, Message
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.widgets import TextInput
from wtforms.validators import Required

import logging
from logging.handlers import RotatingFileHandler
from logging import Formatter

from rq import Queue
from rq.job import Job
from redis import Redis

from urlabuse.helpers import get_socket_path

import configparser
from .proxied import ReverseProxied
from urlabuse.urlabuse import is_valid_url, url_list, dns_resolve, phish_query, psslcircl, \
    vt_query_url, gsb_query, urlquery_query, sphinxsearch, whois, pdnscircl, bgpranking, \
    cached, get_mail_sent, set_mail_sent, get_submissions, eupi


config_dir = Path('config')


class AngularTextInput(TextInput):

    def __call__(self, field, **kwargs):
        kwargs['ng-model'] = 'input_url'
        return super(AngularTextInput, self).__call__(field, **kwargs)


class URLForm(FlaskForm):
    url = StringField('URL Field',
                      description='Enter the URL you want to lookup here.',
                      validators=[Required()], widget=AngularTextInput())

    submit_button = SubmitField('Run lookup')


def make_dict(parser, section):
    to_return = {}
    entries = parser.items(section)
    for k, v in entries:
        to_return[k] = v.split(',')
    return to_return


def prepare_auth():
    if not os.path.exists('users.key'):
        return None
    to_return = {}
    with open('users.key', 'r') as f:
        for line in f:
            line = line.strip()
            user, password = line.split('=')
            to_return[user] = password
    return to_return


def create_app(configfile=None):
    app = Flask(__name__)
    handler = RotatingFileHandler('urlabuse.log', maxBytes=10000, backupCount=5)
    handler.setFormatter(Formatter('%(asctime)s %(message)s'))
    app.wsgi_app = ReverseProxied(app.wsgi_app)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    Bootstrap(app)
    q = Queue(connection=Redis(unix_socket_path=get_socket_path('cache')))

    # Mail Config
    app.config['MAIL_SERVER'] = 'localhost'
    app.config['MAIL_PORT'] = 25
    mail = Mail(app)

    app.config['SECRET_KEY'] = 'devkey'
    app.config['BOOTSTRAP_SERVE_LOCAL'] = True
    app.config['configfile'] = config_dir / 'config.ini'

    parser = configparser.SafeConfigParser()
    parser.read(app.config['configfile'])

    replacelist = make_dict(parser, 'replacelist')
    auth_users = prepare_auth()
    ignorelist = [i.strip()
                  for i in parser.get('abuse', 'ignore').split('\n')
                  if len(i.strip()) > 0]
    autosend_threshold = 5

    def _get_user_ip(request):
        ip = request.headers.get('X-Forwarded-For')
        if ip is None:
            ip = request.remote_addr
        return ip

    @app.route('/', methods=['GET', 'POST'])
    def index():
        form = URLForm()
        return render_template('index.html', form=form)

    @app.route('/urlreport', methods=['GET'])
    def url_report():
        return render_template('url-report.html')

    @app.errorhandler(404)
    def page_not_found(e):
        ip = request.headers.get('X-Forwarded-For')
        if ip is None:
            ip = request.remote_addr
        if request.path != '/_result/':
            app.logger.info('404 of {} on {}'.format(ip, request.path))
        return render_template('404.html'), 404

    def authenticate():
        """Sends a 401 response that enables basic auth"""
        return Response('Could not verify your access level for that URL.\n'
                        'You have to login with proper credentials', 401,
                        {'WWW-Authenticate': 'Basic realm="Login Required"'})

    def check_auth(username, password):
        """This function is called to check if a username /
        password combination is valid.
        """
        if auth_users is None:
            return False
        else:
            db_pass = auth_users.get(username)
            return db_pass == password

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return redirect(url_for('index'))

    @app.route("/_result/<job_key>", methods=['GET'])
    def check_valid(job_key):
        if job_key is None:
            return json.dumps(None), 200
        job = Job.fetch(job_key, connection=Redis(unix_socket_path=get_socket_path('cache')))
        if job.is_finished:
            return json.dumps(job.result), 200
        else:
            return json.dumps("Nay!"), 202

    @app.route('/start', methods=['POST'])
    def run_query():
        data = json.loads(request.data.decode())
        url = data["url"]
        ip = _get_user_ip(request)
        app.logger.info('{} {}'.format(ip, url))
        if get_submissions(url) and get_submissions(url) >= autosend_threshold:
            send(url, '', True)
        is_valid = q.enqueue_call(func=is_valid_url, args=(url,), result_ttl=500)
        return is_valid.get_id()

    @app.route('/urls', methods=['POST'])
    def urls():
        data = json.loads(request.data.decode())
        url = data["url"]
        u = q.enqueue_call(func=url_list, args=(url,), result_ttl=500)
        return u.get_id()

    @app.route('/resolve', methods=['POST'])
    def resolve():
        data = json.loads(request.data.decode())
        url = data["url"]
        u = q.enqueue_call(func=dns_resolve, args=(url,), result_ttl=500)
        return u.get_id()

    def read_auth(name):
        key = config_dir / f'{name}.key'
        if not key.exists():
            return None
        with open(key) as f:
            to_return = []
            for line in f.readlines():
                to_return.append(line.strip())
            return to_return

    @app.route('/phishtank', methods=['POST'])
    def phishtank():
        auth = read_auth('phishtank')
        if not auth:
            return None
        key = auth[0]
        data = json.loads(request.data.decode())
        url = parser.get("PHISHTANK", "url")
        query = data["query"]
        u = q.enqueue_call(func=phish_query, args=(url, key, query,), result_ttl=500)
        return u.get_id()

    @app.route('/virustotal_report', methods=['POST'])
    def vt():
        auth = read_auth('virustotal')
        if not auth:
            return None
        key = auth[0]
        data = json.loads(request.data.decode())
        url = parser.get("VIRUSTOTAL", "url_report")
        url_up = parser.get("VIRUSTOTAL", "url_upload")
        query = data["query"]
        u = q.enqueue_call(func=vt_query_url, args=(url, url_up, key, query,), result_ttl=500)
        return u.get_id()

    @app.route('/googlesafebrowsing', methods=['POST'])
    def gsb():
        auth = read_auth('googlesafebrowsing')
        if not auth:
            return None
        key = auth[0]
        data = json.loads(request.data.decode())
        url = parser.get("GOOGLESAFEBROWSING", "url")
        url = url.format(key)
        query = data["query"]
        u = q.enqueue_call(func=gsb_query, args=(url, query,), result_ttl=500)
        return u.get_id()

    @app.route('/urlquery', methods=['POST'])
    def urlquery():
        auth = read_auth('urlquery')
        if not auth:
            return None
        key = auth[0]
        data = json.loads(request.data.decode())
        url = parser.get("URLQUERY", "url")
        query = data["query"]
        u = q.enqueue_call(func=urlquery_query, args=(url, key, query,), result_ttl=500)
        return u.get_id()

    @app.route('/ticket', methods=['POST'])
    def ticket():
        if not request.authorization:
            return ''
        data = json.loads(request.data.decode())
        server = parser.get("SPHINX", "server")
        port = int(parser.get("SPHINX", "port"))
        url = parser.get("ITS", "url")
        query = data["query"]
        u = q.enqueue_call(func=sphinxsearch, args=(server, port, url, query,),
                           result_ttl=500)
        return u.get_id()

    @app.route('/whois', methods=['POST'])
    def whoismail():
        # if not request.authorization:
        #    return ''
        server = parser.get("WHOIS", "server")
        port = parser.getint("WHOIS", "port")
        data = json.loads(request.data.decode())
        query = data["query"]
        u = q.enqueue_call(func=whois, args=(server, port, query, ignorelist, replacelist),
                           result_ttl=500)
        return u.get_id()

    @app.route('/eupi', methods=['POST'])
    def eu():
        auth = read_auth('eupi')
        if not auth:
            return None
        key = auth[0]
        data = json.loads(request.data.decode())
        url = parser.get("EUPI", "url")
        query = data["query"]
        u = q.enqueue_call(func=eupi, args=(url, key, query,), result_ttl=500)
        return u.get_id()

    @app.route('/pdnscircl', methods=['POST'])
    def dnscircl():
        auth = read_auth('pdnscircl')
        if not auth:
            return None
        user, password = auth
        url = parser.get("PDNS_CIRCL", "url")
        data = json.loads(request.data.decode())
        query = data["query"]
        u = q.enqueue_call(func=pdnscircl, args=(url, user.strip(), password.strip(),
                                                 query,), result_ttl=500)
        return u.get_id()

    @app.route('/bgpranking', methods=['POST'])
    def bgpr():
        data = json.loads(request.data.decode())
        query = data["query"]
        u = q.enqueue_call(func=bgpranking, args=(query,), result_ttl=500)
        return u.get_id()

    @app.route('/psslcircl', methods=['POST'])
    def sslcircl():
        auth = read_auth('psslcircl')
        if not auth:
            return None
        user, password = auth
        url = parser.get("PDNS_CIRCL", "url")
        url = parser.get("PSSL_CIRCL", "url")
        data = json.loads(request.data.decode())
        query = data["query"]
        u = q.enqueue_call(func=psslcircl, args=(url, user.strip(), password.strip(),
                                                 query,), result_ttl=500)
        return u.get_id()

    @app.route('/get_cache', methods=['POST'])
    def get_cache():
        data = json.loads(request.data.decode())
        url = data["query"]
        data = cached(url)
        dumped = json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))
        return dumped

    def digest(data):
        to_return = ''
        all_mails = set()
        for entry in data:
            for url, info in list(entry.items()):
                to_return += '\n{}\n'.format(url)
                if info.get('whois'):
                    all_mails.update(info.get('whois'))
                    to_return += '\tContacts: {}\n'.format(', '.join(info.get('whois')))
                if info.get('vt') and len(info.get('vt')) == 4:
                    vtstuff = info.get('vt')
                    to_return += '\t{} out of {} positive detections in VT - {}\n'.format(
                        vtstuff[2], vtstuff[3], vtstuff[1])
                if info.get('gsb'):
                    to_return += '\tKnown as malicious on Google Safe Browsing: {}\n'.format(info.get('gsb'))
                if info.get('phishtank'):
                    to_return += '\tKnown as malicious on PhishTank\n'
                if info.get('dns'):
                    ipv4, ipv6 = info.get('dns')
                    if ipv4 is not None:
                        for ip in ipv4:
                            to_return += '\t' + ip + '\n'
                            data = info[ip]
                            if data.get('bgp'):
                                to_return += '\t\t(PTR: {}) is announced by {} ({}).\n'.format(*(data.get('bgp')[:3]))
                            if data.get('whois'):
                                all_mails.update(data.get('whois'))
                                to_return += '\t\tContacts: {}\n'.format(', '.join(data.get('whois')))
                    if ipv6 is not None:
                        for ip in ipv6:
                            to_return += '\t' + ip + '\n'
                            data = info[ip]
                            if data.get('whois'):
                                all_mails.update(data.get('whois'))
                                to_return += '\t\tContacts: {}\n'.format(', '.join(data.get('whois')))
            to_return += '\tAll contacts: {}\n'.format(', '.join(all_mails))
        return to_return

    def send(url, ip='', autosend=False):
        if not get_mail_sent(url):
            set_mail_sent(url)
            data = cached(url)
            if not autosend:
                subject = 'URL Abuse report from ' + ip
            else:
                subject = 'URL Abuse report sent automatically'
            msg = Message(subject, sender='urlabuse@circl.lu', recipients=["info@circl.lu"])
            msg.body = digest(data)
            msg.body += '\n\n'
            msg.body += json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))
            mail.send(msg)

    @app.route('/submit', methods=['POST'])
    def send_mail():
        data = json.loads(request.data.decode())
        url = data["url"]
        if not get_mail_sent(url):
            ip = _get_user_ip(request)
            send(url, ip)
        return redirect(url_for('index'))

    return app
