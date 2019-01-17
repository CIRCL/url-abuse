import json
import os
from pathlib import Path
import uuid

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

from redis import Redis

from urlabuse.helpers import get_socket_path, get_homedir
from urlabuse.urlabuse import Query

import configparser
from .proxied import ReverseProxied


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


app = Flask(__name__)
handler = RotatingFileHandler('urlabuse.log', maxBytes=10000, backupCount=5)
handler.setFormatter(Formatter('%(asctime)s %(message)s'))
app.wsgi_app = ReverseProxied(app.wsgi_app)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)
Bootstrap(app)
queue = Redis(unix_socket_path=get_socket_path('cache'), db=0,
              decode_responses=True)
urlabuse_query = Query()

# Mail Config
app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 25
mail = Mail(app)

secret_file_path = get_homedir() / 'website' / 'secret_key'

if not secret_file_path.exists() or secret_file_path.stat().st_size < 64:
    with open(secret_file_path, 'wb') as f:
        f.write(os.urandom(64))

with open(secret_file_path, 'rb') as f:
    app.config['SECRET_KEY'] = f.read()

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
    if request.method == 'HEAD':
        # Just returns ack if the webserver is running
        return 'Ack'
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
    if not job_key or not queue.exists(job_key):
        return Response(json.dumps(None), mimetype='application/json'), 200
    if not queue.hexists(job_key, 'result'):
        return Response(json.dumps('Nay!'), mimetype='application/json'), 202
    result = queue.hget(job_key, 'result')
    queue.delete(job_key)
    return Response(result, mimetype='application/json'), 200


def enqueue(method, data):
    job_id = str(uuid.uuid4())
    p = queue.pipeline()
    p.hmset(job_id, {'method': method, 'data': json.dumps(data)})
    p.sadd('to_process', job_id)
    p.execute()
    return job_id


@app.route('/start', methods=['POST'])
def run_query():
    data = request.get_json(force=True)
    url = data["url"]
    ip = _get_user_ip(request)
    app.logger.info(f'{ip} {url}')
    if urlabuse_query.get_submissions(url) and urlabuse_query.get_submissions(url) >= autosend_threshold:
        send(url, '', True)
    return enqueue('is_valid_url', {'url': url})


@app.route('/urls', methods=['POST'])
def urls():
    data = request.get_json(force=True)
    return enqueue('url_list', {'url': data["url"]})


@app.route('/resolve', methods=['POST'])
def resolve():
    data = request.get_json(force=True)
    return enqueue('dns_resolve', {'url': data["url"]})


def read_auth(name):
    key = config_dir / f'{name}.key'
    if not key.exists():
        return ''
    with open(key) as f:
        to_return = []
        for line in f.readlines():
            to_return.append(line.strip())
        return to_return


@app.route('/phishtank', methods=['POST'])
def phishtank():
    auth = read_auth('phishtank')
    if not auth:
        return ''
    data = request.get_json(force=True)
    return enqueue('phish_query', {'url': parser.get("PHISHTANK", "url"),
                                   'key': auth[0], 'query': data["query"]})


@app.route('/virustotal_report', methods=['POST'])
def vt():
    auth = read_auth('virustotal')
    if not auth:
        return ''
    data = request.get_json(force=True)
    return enqueue('vt_query_url', {'url': parser.get("VIRUSTOTAL", "url_report"),
                                    'url_up': parser.get("VIRUSTOTAL", "url_upload"),
                                    'key': auth[0], 'query': data["query"]})


@app.route('/googlesafebrowsing', methods=['POST'])
def gsb():
    auth = read_auth('googlesafebrowsing')
    if not auth:
        return ''
    key = auth[0]
    data = request.get_json(force=True)
    url = parser.get("GOOGLESAFEBROWSING", "url").format(key)
    return enqueue('gsb_query', {'url': url,
                                 'query': data["query"]})


'''
@app.route('/urlquery', methods=['POST'])
def urlquery():
    auth = read_auth('urlquery')
    if not auth:
        return ''
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
'''


@app.route('/whois', methods=['POST'])
def whoismail():
    data = request.get_json(force=True)
    return enqueue('whois', {'server': parser.get("WHOIS", "server"),
                             'port': parser.getint("WHOIS", "port"),
                             'domain': data["query"],
                             'ignorelist': ignorelist, 'replacelist': replacelist})


@app.route('/eupi', methods=['POST'])
def eu():
    auth = read_auth('eupi')
    if not auth:
        return ''
    data = request.get_json(force=True)
    return enqueue('eupi', {'url': parser.get("EUPI", "url"),
                            'key': auth[0], 'q': data["query"]})


@app.route('/pdnscircl', methods=['POST'])
def dnscircl():
    auth = read_auth('pdnscircl')
    if not auth:
        return ''
    user, password = auth
    url = parser.get("PDNS_CIRCL", "url")
    data = request.get_json(force=True)
    return enqueue('pdnscircl', {'url': url, 'user': user.strip(),
                                 'passwd': password.strip(), 'q': data["query"]})


@app.route('/bgpranking', methods=['POST'])
def bgpr():
    data = request.get_json(force=True)
    return enqueue('bgpranking', {'ip': data["query"]})


@app.route('/psslcircl', methods=['POST'])
def sslcircl():
    auth = read_auth('psslcircl')
    if not auth:
        return ''
    user, password = auth
    url = parser.get("PSSL_CIRCL", "url")
    data = request.get_json(force=True)
    return enqueue('psslcircl', {'url': url, 'user': user.strip(),
                                 'passwd': password.strip(), 'q': data["query"]})


@app.route('/get_cache', methods=['POST'])
def get_cache():
    data = request.get_json(force=True)
    url = data["query"]
    if 'digest' in data:
        digest = data["digest"]
    else:
        digest = False
    data = urlabuse_query.cached(url, digest)
    return Response(json.dumps(data), mimetype='application/json')


def send(url, ip='', autosend=False):
    if not urlabuse_query.get_mail_sent(url):
        data = urlabuse_query.cached(url, digest=True)
        if not autosend:
            subject = 'URL Abuse report from ' + ip
        else:
            subject = 'URL Abuse report sent automatically'
        msg = Message(subject, sender='urlabuse@circl.lu', recipients=["info@circl.lu"])
        msg.body = data['digest'][0]
        msg.body += '\n\n'
        msg.body += json.dumps(data['result'], sort_keys=True, indent=2)
        mail.send(msg)
        urlabuse_query.set_mail_sent(url)


@app.route('/submit', methods=['POST'])
def send_mail():
    data = request.get_json(force=True)
    url = data["url"]
    if not urlabuse_query.get_mail_sent(url):
        ip = _get_user_ip(request)
        send(url, ip)
    return redirect(url_for('index'))
