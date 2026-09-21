"""Real Chromium + HTTP fixtures. Only the external model is substituted."""

import json
import re
import threading
import uuid
from contextlib import contextmanager
from urllib.parse import urlsplit
from urllib.parse import quote

import pytest
from flask import Flask, request, redirect, jsonify, make_response
from werkzeug.serving import make_server, WSGIRequestHandler

import app as mod
import sources
import source_browser
from source_auth import decrypt
from test_app import env, post
from test_sources import configure


class QuietHandler(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass


@contextmanager
def platform(kind='ctfd'):
    app = Flask('fixture')
    state = {'sessions': set(), 'logins': 0, 'posts': [], 'csrf': {}, 'captcha': False}

    def allowed():
        return request.cookies.get('session') in state['sessions']

    @app.get('/')
    def root():
        return redirect('/challenges' if kind == 'ctfd' else '/tasks')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if state['captcha']:
            return '<main>Two-factor authentication <input autocomplete="one-time-code"></main>'
        error = ''
        if request.method == 'POST':
            state['posts'].append(dict(request.form))
            if request.form.get('nonce') != state['csrf'].get(request.cookies.get('csrf')):
                return 'CSRF rejected', 400
            if request.form.get('name') == 'fixture-user' and request.form.get('password') == 'fixture-password-PRIVATE':
                state['logins'] += 1
                session = uuid.uuid4().hex
                state['sessions'].add(session)
                response = make_response(redirect('/challenges' if kind == 'ctfd' else '/tasks'))
                response.set_cookie('session', session, httponly=True)
                return response
            error = 'Incorrect password'
        csrf, nonce = uuid.uuid4().hex, uuid.uuid4().hex
        state['csrf'][csrf] = nonce
        response = make_response(f'<main>{error}<form method="post" action="/login"><input type="hidden" name="nonce" value="{nonce}"><label>Username<input name="name"></label><label>Password<input name="password" type="password"></label><button type="submit">Log in</button></form></main>')
        response.set_cookie('csrf', csrf, httponly=True)
        return response

    @app.get('/challenges')
    def challenges():
        if not allowed():
            return redirect('/login')
        return '<main>CTFd task list</main>'

    @app.get('/api/v1/challenges')
    def api():
        if kind != 'ctfd':
            return 'Not found', 404
        if not allowed():
            return jsonify(error='Login required'), 401
        return jsonify(success=True, data=[dict(id=7, name='Private task', category='OSINT', value=250, solves=12, tags=[{'value': 'Hard'}])])

    @app.get('/tasks')
    def tasks():
        if not allowed():
            return redirect('/login')
        return '''<header>fixture-user</header><main id="board" aria-busy="true">Loading…</main>
        <script>window.privateToken='SCRIPT-PRIVATE';
        fetch('/task-data'+location.search).then(r=>r.json()).then(d=>{
          document.querySelector('#board').innerHTML=d.html;
          document.querySelector('#board').removeAttribute('aria-busy');
        });</script>'''

    @app.get('/task-data')
    def data():
        if not allowed():
            return jsonify(error='Unauthorized'), 401
        page = request.args.get('page', '1')
        if page == '1':
            return jsonify(html='<article>Task Alpha OSINT Hard 250 points 12 solves <a href="/challenge/alpha">Open task</a></article><button onclick="location.href=\'/tasks?page=2\'">Next</button>')
        return jsonify(html='<article>Task Beta Web 100 points 3 solves <a href="/challenge/beta">Open task</a></article><button disabled>Next</button>')

    server = make_server('127.0.0.1', 0, app, threaded=True, request_handler=QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def keycloak_platform():
    identity = Flask('identity')
    platform_app = Flask('platform')
    state = {'logins': 0, 'forms': [], 'sessions': set()}
    platform_url = {'value': ''}

    @identity.route('/realms/fsp/protocol/openid-connect/auth')
    def authorize():
        target = request.args['redirect_uri']
        return f'''<main><form id="kc-form-login" action="/realms/fsp/login-actions/authenticate" method="post">
        <input type="hidden" name="redirect_uri" value="{target}">
        <input name="username" type="text" autocomplete="username" required>
        <input name="password" type="password" autocomplete="current-password" required>
        <button id="kc-login" name="login" type="submit">Войти</button></form></main>'''

    @identity.post('/realms/fsp/login-actions/authenticate')
    def authenticate():
        state['forms'].append(dict(request.form))
        if request.form.get('username') != 'fixture-user' or request.form.get('password') != 'fixture-password-PRIVATE':
            return 'Incorrect password', 401
        state['logins'] += 1
        return redirect(request.form['redirect_uri'] + '?code=test-code')

    @platform_app.get('/')
    @platform_app.get('/challenges')
    def challenges():
        if request.cookies.get('session') not in state['sessions']:
            return '<main><a href="/sso/login/fsp">Войти по ФСП ID</a></main>'
        return '<main>Challenge list</main>'

    @platform_app.get('/sso/login/fsp')
    def start_sso():
        callback = quote(platform_url['value'] + '/callback', safe=':/')
        return redirect(identity_url['value'] + '/realms/fsp/protocol/openid-connect/auth?redirect_uri=' + callback)

    @platform_app.get('/callback')
    def callback():
        if request.args.get('code') != 'test-code':
            return 'Invalid code', 400
        session = uuid.uuid4().hex
        state['sessions'].add(session)
        response = make_response(redirect('/challenges'))
        response.set_cookie('session', session, httponly=True)
        return response

    @platform_app.get('/api/v1/challenges')
    def api():
        if request.cookies.get('session') not in state['sessions']:
            return jsonify(error='Login required'), 401
        return jsonify(success=True, data=[dict(id=9, name='SSO task', category='Web', value=200, solves=4)])

    identity_server = make_server('127.0.0.1', 0, identity, threaded=True, request_handler=QuietHandler)
    identity_url = {'value': f'http://localhost:{identity_server.server_port}'}
    platform_server = make_server('127.0.0.1', 0, platform_app, threaded=True, request_handler=QuietHandler)
    platform_url['value'] = f'http://127.0.0.1:{platform_server.server_port}'
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (identity_server, platform_server)]
    for thread in threads:
        thread.start()
    try:
        yield platform_url['value'], state
    finally:
        for server in (identity_server, platform_server):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


def connect(client, url, **auth_changes):
    mod.app.config['SOURCE_ALLOW_PRIVATE_TESTS'] = True
    auth = dict(method='password', username='fixture-user', password='fixture-password-PRIVATE')
    auth.update(auth_changes)
    configure(client, url=url, auth=auth)


def test_ctfd_browser_login_csrf_session_reuse_and_expiration(env):
    with platform() as (url, state):
        connect(env, url)
        assert sources.sync_once(mod.app, mod.db, 1), env.get('/api/admin/source/1').json
        tasks = env.get('/api/board/1').json['tasks']
        assert tasks[0]['title'] == 'Private task' and tasks[0]['difficulty'] == 'Hard'
        assert state['logins'] == 1
        assert state['posts'][0]['nonce']
        with mod.app.app_context():
            row = mod.db().execute('SELECT session FROM source_credentials').fetchone()
            stored = row[0]
            assert stored and 'fixture-user' not in stored
            assert decrypt(stored)['cookies']
        # New sync/context reads persistent encrypted state, just as after restart.
        assert sources.sync_once(mod.app, mod.db, 1)
        assert state['logins'] == 1
        state['sessions'].clear()
        assert sources.sync_once(mod.app, mod.db, 1), env.get('/api/admin/source/1').json
        assert state['logins'] == 2
        assert len(env.get('/api/board/1').json['tasks']) == 1


def test_keycloak_cross_origin_username_password_login(env):
    with keycloak_platform() as (url, state):
        connect(env, url)
        assert sources.sync_once(mod.app, mod.db, 1), env.get('/api/admin/source/1').json
        assert env.get('/api/board/1').json['tasks'][0]['title'] == 'SSO task'
        assert state['logins'] == 1
        assert state['forms'][0]['username'] == 'fixture-user'
        assert state['forms'][0]['redirect_uri'].startswith(url)
        with mod.app.app_context():
            storage = decrypt(mod.db().execute('SELECT session FROM source_credentials').fetchone()[0])
            domains = {cookie['domain'] for cookie in storage['cookies']}
            assert '127.0.0.1' in domains


@pytest.mark.parametrize('blocked', ['password', 'captcha'])
def test_browser_login_blockers_pause_without_retry(env, blocked):
    with platform() as (url, state):
        state['captcha'] = blocked == 'captcha'
        connect(env, url, password='incorrect' if blocked == 'password' else 'fixture-password-PRIVATE')
        assert not sources.sync_once(mod.app, mod.db, 1)
        result = env.get('/api/admin/source/1').json
        assert result['status'] == 'needs_action', result
        count = len(state['posts'])
        assert not sources.sync_once(mod.app, mod.db, 1)
        assert len(state['posts']) == count and state['logins'] == 0


def browser_model(captured, *, incomplete=False, malicious=False):
    def model(system, content, timeout=45):
        captured.append(content)
        assert 'fixture-password-PRIVATE' not in content and 'fixture-user' not in content and 'SCRIPT-PRIVATE' not in content
        data = json.loads(content)
        alpha = 'Task Alpha' in data['text']
        excerpt = 'Task Alpha OSINT Hard 250 points 12 solves' if alpha else 'Task Beta Web 100 points 3 solves'
        control = next((c for c in data['controls'] if c['kind'] == 'next' and not c['disabled']), None)
        return {'kind': 'tasks', 'tasks': [{'title': 'Task Alpha' if alpha else 'Task Beta', 'category': 'OSINT' if alpha else 'Web', 'difficulty': 'Hard' if alpha else None, 'points': 250 if alpha else 100, 'solves': 12 if alpha else 3, 'external_id': '/challenge/alpha' if alpha else '/challenge/beta', 'evidence': excerpt}], 'next_control': 'arbitrary-selector' if malicious else control['id'] if control else None, 'complete': not control and not incomplete}
    return model


def test_js_pagination_metadata_and_no_credentials_in_model(env, monkeypatch):
    with platform('browser') as (url, state):
        captured = []
        monkeypatch.setattr(source_browser, 'model_json', browser_model(captured))
        connect(env, url)
        assert sources.sync_once(mod.app, mod.db, 1), env.get('/api/admin/source/1').json
        tasks = env.get('/api/board/1').json['tasks']
        assert len(tasks) == 2 and len(captured) == 2
        assert tasks[0]['category'] == 'OSINT' and tasks[0]['difficulty'] == 'Hard'
        assert tasks[1]['difficulty'] is None
        assert env.get('/api/admin/source/1').json['parser'] == 'browser'
        assert state['logins'] == 1
        with mod.app.app_context():
            strategy = json.loads(mod.db().execute('SELECT strategy FROM sources').fetchone()[0])
            assert urlsplit(strategy['list_url']).path == '/tasks'
        assert sources.sync_once(mod.app, mod.db, 1)
        assert state['logins'] == 1 and len(env.get('/api/board/1').json['tasks']) == 2


@pytest.mark.parametrize('failure', ['incomplete', 'malicious'])
def test_unknown_site_requires_complete_list_and_vetted_actions(env, monkeypatch, failure):
    with platform('browser') as (url, state):
        monkeypatch.setattr(source_browser, 'model_json', browser_model([], incomplete=failure == 'incomplete', malicious=failure == 'malicious'))
        connect(env, url)
        assert not sources.sync_once(mod.app, mod.db, 1)
        assert env.get('/api/admin/source/1').json['status'] == 'incomplete'
        assert env.get('/api/board/1').json['tasks'] == []
        assert len(state['posts']) == 1  # Only the form login, never arbitrary model actions.
