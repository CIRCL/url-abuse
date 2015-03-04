import json
import os

from flask import Flask, render_template, request, Response, redirect, url_for, flash
from flask_mail import Mail, Message
from flask_bootstrap import Bootstrap
from flask_wtf import Form
from wtforms import StringField, SubmitField
from wtforms.widgets import TextInput
from wtforms.validators import Required

import logging
from logging.handlers import RotatingFileHandler
from logging import Formatter

from rq import Queue
from rq.job import Job
from worker import conn

import ConfigParser
# from pyfaup.faup import Faup
from proxied import ReverseProxied
from url_abuse_async import is_valid_url, url_list, dns_resolve, phish_query, psslcircl, \
    vt_query_url, gsb_query, urlquery_query, sphinxsearch, whois, pdnscircl, bgpranking, \
    get_cached

config_path = 'config.ini'


class AngularTextInput(TextInput):

    def __call__(self, field, **kwargs):
        kwargs['ng-model'] = 'input_url'
        return super(AngularTextInput, self).__call__(field, **kwargs)


class URLForm(Form):
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
        for l in f:
            l = l.strip()
            user, password = l.split('=')
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
    q = Queue(connection=conn)

    # Mail Config
    app.config['MAIL_SERVER'] = 'localhost'
    app.config['MAIL_PORT'] = 25
    mail = Mail(app)

    app.config['SECRET_KEY'] = 'devkey'
    app.config['BOOTSTRAP_SERVE_LOCAL'] = True
    app.config['configfile'] = config_path

    parser = ConfigParser.SafeConfigParser()
    parser.read(app.config['configfile'])

    replacelist = make_dict(parser, 'replacelist')
    auth_users = prepare_auth()
    ignorelist = [i.strip()
                  for i in parser.get('abuse', 'ignore').split('\n')
                  if len(i.strip()) > 0]

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
        job = Job.fetch(job_key, connection=conn)
        if job.is_finished:
            return json.dumps(job.result), 200
        else:
            return json.dumps("Nay!"), 202

    @app.route('/start', methods=['POST'])
    def run_query():
        data = json.loads(request.data)
        url = data["url"]
        ip = _get_user_ip(request)
        app.logger.info('{} {}'.format(ip, url))
        is_valid = q.enqueue_call(func=is_valid_url, args=(url,), result_ttl=500)
        return is_valid.get_id()

    @app.route('/urls', methods=['POST'])
    def urls():
        data = json.loads(request.data)
        url = data["url"]
        u = q.enqueue_call(func=url_list, args=(url,), result_ttl=500)
        return u.get_id()

    @app.route('/resolve', methods=['POST'])
    def resolve():
        data = json.loads(request.data)
        url = data["url"]
        u = q.enqueue_call(func=dns_resolve, args=(url,), result_ttl=500)
        return u.get_id()

    @app.route('/phishtank', methods=['POST'])
    def phishtank():
        data = json.loads(request.data)
        if not os.path.exists('phishtank.key'):
            return None
        url = parser.get("PHISHTANK", "url")
        key = open('phishtank.key', 'r').readline().strip()
        query = data["query"]
        u = q.enqueue_call(func=phish_query, args=(url, key, query,), result_ttl=500)
        return u.get_id()

    @app.route('/virustotal_report', methods=['POST'])
    def vt():
        data = json.loads(request.data)
        if not os.path.exists('virustotal.key'):
            return None
        url = parser.get("VIRUSTOTAL", "url_report")
        url_up = parser.get("VIRUSTOTAL", "url_upload")
        key = open('virustotal.key', 'r').readline().strip()
        query = data["query"]
        u = q.enqueue_call(func=vt_query_url, args=(url, url_up, key, query,), result_ttl=500)
        return u.get_id()

    @app.route('/googlesafebrowsing', methods=['POST'])
    def gsb():
        data = json.loads(request.data)
        if not os.path.exists('googlesafebrowsing.key'):
            return None
        url = parser.get("GOOGLESAFEBROWSING", "url")
        key = open('googlesafebrowsing.key', 'r').readline().strip()
        url = url.format(key)
        query = data["query"]
        u = q.enqueue_call(func=gsb_query, args=(url, query,), result_ttl=500)
        return u.get_id()

    @app.route('/urlquery', methods=['POST'])
    def urlquery():
        data = json.loads(request.data)
        if not os.path.exists('urlquery.key'):
            return None
        url = parser.get("URLQUERY", "url")
        key = open('urlquery.key', 'r').readline().strip()
        query = data["query"]
        u = q.enqueue_call(func=urlquery_query, args=(url, key, query,), result_ttl=500)
        return u.get_id()

    @app.route('/ticket', methods=['POST'])
    def ticket():
        if not request.authorization:
            return ''
        data = json.loads(request.data)
        server = parser.get("SPHINX", "server")
        port = int(parser.get("SPHINX", "port"))
        url = parser.get("ITS", "url")
        query = data["query"]
        u = q.enqueue_call(func=sphinxsearch, args=(server, port, url, query,),
                           result_ttl=500)
        return u.get_id()

    @app.route('/whois', methods=['POST'])
    def whoismail():
        if not request.authorization:
            return ''
        server = parser.get("WHOIS", "server")
        port = parser.getint("WHOIS", "port")
        data = json.loads(request.data)
        query = data["query"]
        u = q.enqueue_call(func=whois, args=(server, port, query, ignorelist, replacelist),
                           result_ttl=500)
        return u.get_id()

    @app.route('/pdnscircl', methods=['POST'])
    def dnscircl():
        url = parser.get("PDNS_CIRCL", "url")
        user, password = open('pdnscircl.key', 'r').readlines()
        data = json.loads(request.data)
        query = data["query"]
        u = q.enqueue_call(func=pdnscircl, args=(url, user.strip(), password.strip(),
                                                 query,), result_ttl=500)
        return u.get_id()

    @app.route('/bgpranking', methods=['POST'])
    def bgpr():
        data = json.loads(request.data)
        query = data["query"]
        u = q.enqueue_call(func=bgpranking, args=(query,), result_ttl=500)
        return u.get_id()

    @app.route('/psslcircl', methods=['POST'])
    def sslcircl():
        url = parser.get("PSSL_CIRCL", "url")
        user, password = open('psslcircl.key', 'r').readlines()
        data = json.loads(request.data)
        query = data["query"]
        u = q.enqueue_call(func=psslcircl, args=(url, user.strip(), password.strip(),
                                                 query,), result_ttl=500)
        return u.get_id()

    @app.route('/get_cache/<path:url>')
    def get_cache(url):
        data = get_cached(url)
        dumped = json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))
        return dumped

    @app.route('/submit/<path:url>')
    def send_mail(url):
        ip = _get_user_ip(request)
        data = get_cached(url)
        dumped = json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))
        msg = Message('URL Abuse report from ' + ip, sender='urlabuse@circl.lu',
                      recipients=["info@circl.lu"])
        msg.body = dumped
        mail.send(msg)
        flash('Mail successfully sent to CIRCL.')
        return redirect(url_for('index'))

    return app
