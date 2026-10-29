"""Loopback-only UI. This process has no target-fetching implementation."""
import argparse
import hmac
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time
from urllib.parse import unquote, urlsplit
import uuid
import webbrowser
from . import backend, policy
from .report import sanitize, CSP
from .storage import Store, atomic, default_home

HERE = Path(__file__).resolve().parent
ACTIVE = {'starting','running','stopping'}

class Application:
    def __init__(self, root):
        self.store = Store(root)
        self.bootstrap = secrets.token_urlsafe(32)
        self.session = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(32)
        self.mutex = threading.RLock()
        self.origin = ''
    def info(self):
        try:
            cfg = backend.settings(self.store.root)
            ready, error = True, ''
        except Exception as e:
            ready, error = False, 'Backend is unavailable or its source pin failed. Check installation settings.'
        return dict(ready=ready, error=error, data_directory=str(self.store.root), model='Current qualified model',
                    privacy='Local uploads and report mirrors are plaintext in your private app-data folder. The backend case vault is encrypted. Use an encrypted local disk.',
                    workflow='Whonix collection → offline tools → analysis → detractor → adjudication')

class Handler(BaseHTTPRequestHandler):
    server_version = 'OSINTHarness'
    sys_version = ''
    def log_message(self, *_): pass
    @property
    def app(self): return self.server.app
    def setup(self):
        super().setup()
        self.connection.settimeout(20)
    def send(self, code, body=b'', content_type='application/json; charset=utf-8', extra=None, report=False):
        if isinstance(body, (dict,list)): body = json.dumps(body).encode()
        if isinstance(body, str): body = body.encode('utf-8')
        self.send_response(code)
        headers = {'Content-Type':content_type, 'Content-Length':str(len(body)), 'Cache-Control':'no-store',
                   'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'no-referrer', 'X-Frame-Options':'SAMEORIGIN',
                   'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
                   'Content-Security-Policy':CSP if report else "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"}
        headers.update(extra or {})
        for k,v in headers.items(): self.send_header(k,v)
        self.end_headers()
        try: self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError): pass
    def authorized(self):
        try:
            cookie = SimpleCookie(self.headers.get('Cookie',''))
            value = cookie['osint_session'].value
            return hmac.compare_digest(value, self.app.session)
        except Exception: return False
    def body(self, maximum=100000):
        if self.headers.get('Transfer-Encoding'): raise ValueError('Chunked requests are not accepted.')
        raw = self.headers.get('Content-Length', '')
        if not raw.isdigit(): raise ValueError('Content-Length is required.')
        size = int(raw)
        if size > maximum: raise ValueError('Request exceeds its size limit.')
        data = self.rfile.read(size)
        if len(data) != size: raise ValueError('Incomplete request body.')
        return data
    def json_body(self):
        if self.headers.get('Content-Type','').split(';')[0] != 'application/json': raise ValueError('Expected application/json.')
        data = json.loads(self.body())
        if not isinstance(data, dict): raise ValueError('Expected an object.')
        return data
    def do_OPTIONS(self): self.send(405, {'error':'Cross-origin requests are disabled.'})
    def do_GET(self): self.dispatch('GET')
    def do_POST(self): self.dispatch('POST')
    def dispatch(self, method):
        try:
            expected = urlsplit(self.app.origin).netloc
            if self.headers.get('Host') != expected:
                return self.send(421, {'error':'Invalid local host.'})
            if self.headers.get('Sec-Fetch-Site') == 'cross-site':
                return self.send(403, {'error':'Cross-site requests are blocked.'})
            path = urlsplit(self.path).path
            if self.path != path: return self.send(400, {'error':'Query parameters are not accepted.'})
            if method == 'POST' and self.headers.get('Origin') != self.app.origin:
                return self.send(403, {'error':'Invalid request origin.'})
            if path == '/api/session' and method == 'POST':
                data = self.json_body()
                if not self.app.bootstrap or not hmac.compare_digest(str(data.get('token','')), self.app.bootstrap):
                    return self.send(403, {'error':'Open the app using its local launcher.'})
                self.app.bootstrap = secrets.token_urlsafe(32)
                atomic(self.app.store.root/'ui-address.json', {'url':self.app.origin+'/#'+self.app.bootstrap,'pid':os.getpid()})
                return self.send(200, {'csrf':self.app.csrf}, extra={'Set-Cookie':f'osint_session={self.app.session}; HttpOnly; SameSite=Strict; Path=/'})
            public = {'/':'index.html','/app.js':'app.js','/style.css':'style.css'}
            if method == 'GET' and path in public:
                filename = public[path]
                typ = {'html':'text/html','js':'text/javascript','css':'text/css'}[filename.rsplit('.',1)[1]]
                return self.send(200, (HERE/'static'/filename).read_bytes(), typ+'; charset=utf-8')
            if not self.authorized(): return self.send(401, {'error':'Open the app using its local launcher.'})
            if method == 'POST' and not hmac.compare_digest(self.headers.get('X-CSRF-Token',''), self.app.csrf):
                return self.send(403, {'error':'Invalid session token.'})
            with self.app.mutex:
                self.route(method, path)
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            self.send(400, {'error':str(e)[:400]})
        except Exception:
            self.send(500, {'error':'The operation failed. Existing case data was preserved; check the local application/backend logs.'})
    def route(self, method, path):
        store = self.app.store
        if path == '/api/session' and method == 'GET': return self.send(200, {'csrf':self.app.csrf})
        if path == '/api/info' and method == 'GET': return self.send(200, self.app.info())
        if path == '/api/catalog' and method == 'GET': return self.send(200, json.loads((HERE/'catalog.json').read_text()))
        if path == '/api/shutdown' and method == 'POST':
            self.json_body()
            if any(x['state'] in ACTIVE for x in store.list()): raise ValueError('Wait for the active case to finish cleanup before closing the UI server.')
            self.send(200, {'closed':True})
            threading.Thread(target=self.server.shutdown,daemon=True).start()
            return
        if path == '/api/cases' and method == 'GET':
            rows = store.list()
            for row in rows:
                row['title'] = json.loads(row.pop('form'))['title']
            return self.send(200, rows)
        if path == '/api/cases' and method == 'POST':
            return self.send(201, store.create(policy.normalize(self.json_body())))
        if path == '/api/settings' and method == 'POST':
            data = self.json_body()
            if any(x['state'] in ACTIVE for x in store.list()): raise ValueError('Finish the active case before changing installation settings.')
            folder = Path(data['operator_dir']).resolve()
            source = json.loads((folder/'SOURCE-MANIFEST.json').read_text(encoding='utf-8'))
            if 'ui_entry.py' not in source.get('files', {}): raise ValueError('This backend does not include a qualified UI adapter.')
            cfg = dict(contract='qualified-pilot-v1', operator_dir=str(folder), source_files=source['files'],
                       python=sys.executable, runtime_hash=data['runtime_hash'])
            # Check the proposed installation in a temporary private folder before replacing configuration.
            import tempfile
            with tempfile.TemporaryDirectory(dir=store.root) as test:
                atomic(Path(test)/'settings.json', cfg)
                backend.settings(test)
            atomic(store.root/'settings.json', cfg)
            return self.send(200, self.app.info())
        parts = path.strip('/').split('/')
        if len(parts) not in (3,4) or parts[:2] != ['api','cases']: return self.send(404, {'error':'Not found.'})
        cid, action = parts[2], parts[3] if len(parts)==4 else ''
        case, folder = store.get(cid), store.path(cid)
        if method == 'GET' and action == '':
            status_path = folder/'report'/'osint-pilot-status.json'
            case['status'] = json.loads(status_path.read_text(encoding='utf-8')) if status_path.exists() else {}
            case['stale'] = case['state'] in ACTIVE and time.time()-case['heartbeat'] > 45
            case['report_available'] = (folder/'report'/'osint-pilot-live-report.html').exists()
            return self.send(200, case)
        if method == 'GET' and action == 'report':
            report = folder/'report'/'osint-pilot-live-report.html'
            if not report.exists(): return self.send(200, '<p>The working report will appear after the first backend checkpoint.</p>', 'text/html; charset=utf-8', report=True)
            if report.is_symlink(): raise ValueError('Invalid report file.')
            with report.open(encoding='utf-8',errors='replace') as handle: raw = handle.read(4*1024*1024)
            return self.send(200, sanitize(raw), 'text/html; charset=utf-8', report=True)
        if method == 'GET' and action == 'log':
            p = folder/'runner.log'
            text = ''
            if p.exists():
                with p.open('rb') as handle:
                    handle.seek(max(0,p.stat().st_size-12000)); text=handle.read(12000).decode('utf-8','replace')
            return self.send(200, {'text':text})
        if method != 'POST': return self.send(405, {'error':'Method not allowed.'})
        if action in ('','upload','remove-file') and case['state'] != 'draft': raise ValueError('Started cases are immutable. Create a new case to change scope.')
        if action == '':
            form = policy.normalize(self.json_body())
            for f in case['files']:
                if f.get('url'): policy.url(f['url'], policy.lines(form['hosts']))
            store.update(cid, form=form)
            return self.send(200, store.get(cid))
        if action == 'upload':
            if len(case['files']) >= 20: raise ValueError('At most 20 uploaded files are allowed.')
            if self.headers.get('Content-Type') != 'application/octet-stream': raise ValueError('Use a raw file upload.')
            name = unquote(self.headers.get('X-File-Name',''))
            if not name or len(name)>200 or any(x in name for x in ('/','\\',':','\0')) or any(ord(x)<32 for x in name): raise ValueError('Invalid filename.')
            ext = Path(name).suffix.lower()
            if ext not in policy.FORMATS: raise ValueError('Supported uploads: PDF, HTML, TXT and JSON.')
            source_url = unquote(self.headers.get('X-Source-URL',''))
            if source_url: policy.url(source_url, policy.lines(case['form']['hosts']))
            body = self.body(policy.MAX_FILE)
            if not body: raise ValueError('Empty files are not accepted.')
            if ext == '.pdf' and not body.startswith(b'%PDF-'): raise ValueError('The file does not have a PDF header.')
            if ext != '.pdf': body.decode('utf-8-sig')
            if ext == '.json': json.loads(body)
            sid = 'source-' + uuid.uuid4().hex[:16]
            source = dict(id=sid, filename=sid+ext, display_name=name, sha256=policy.sha256(body),
                          size=len(body), content_type=policy.FORMATS[ext], origin='operator_supplied', description='Operator supplied: '+name)
            if source_url: source['url']=source_url
            # A user upload is not an observed HTTP response; never fabricate a successful status.
            if source_url: source.update(http_status=0, curl_exit=0)
            target = folder/'uploads'/source['filename']
            with target.open('xb') as handle: handle.write(body)
            store.update(cid, files=case['files']+[source])
            return self.send(201, store.get(cid))
        if action == 'remove-file':
            sid = self.json_body()['id']
            source = next((f for f in case['files'] if f['id']==sid), None)
            if not source: raise ValueError('Unknown file.')
            store.update(cid, files=[f for f in case['files'] if f['id']!=sid])
            (folder/'uploads'/source['filename']).unlink()
            return self.send(200, store.get(cid))
        if action == 'preview':
            self.json_body()
            cfg = backend.settings(store.root)
            manifest, reasons = policy.manifest(cid, case['form'], case['files'], cfg['runtime_hash'])
            catalog = json.loads((HERE/'catalog.json').read_text())
            modes = {r['mode'] for r in manifest['tool_recipes']}
            references = [e for e in catalog['entries'] if e['adapter'] in modes or
                          (e['adapter'] is None and case['form']['profile'] in e['profiles'])]
            return self.send(200, dict(plan=reasons, scope=manifest['allowed_hosts'], urls=manifest['seed_urls'],
                                      mode=manifest['workflow_mode'], model_rounds=0 if manifest['workflow_mode']=='tools_only' else 3,
                                      references=references, catalog_revision=catalog['revision'],
                                      limits=['Exact host scope; redirects cannot expand it.', 'Only qualified fixed recipes execute.', 'Sources and reports are untrusted; findings require human review.']))
        if action in ('start','resume'):
            self.json_body()
            cfg = backend.settings(store.root)
            resume = action == 'resume'
            if not resume:
                if case['state'] != 'draft': raise ValueError('Use Resume for an existing case.')
                manifest, _ = policy.manifest(cid, case['form'], case['files'], cfg['runtime_hash'])
                atomic(folder/'manifest.json', manifest)
                (folder/'manifest.sha256').write_text(policy.sha256((folder/'manifest.json').read_bytes()))
            from .worker import verify_inputs
            verify_inputs(store,cid)
            store.reserve(cid,resume)
            (folder/'stop.request').unlink(missing_ok=True)
            try: backend.spawn_worker(store.root,cid,resume)
            except Exception:
                store.update(cid,state='needs_attention',message='Worker could not start. No success was recorded.')
                raise
            return self.send(202, store.get(cid))
        if action == 'stop':
            self.json_body()
            if case['state'] != 'running': raise ValueError('Stop is available after the worker starts.')
            # The pinned launcher checks this flag between bounded operations and
            # enters its normal cleanup path. Never kill a process or VM from HTTP.
            (folder/'stop.request').touch(exist_ok=True)
            store.update(cid,state='stopping',message='Stop requested. Waiting for the current bounded operation and owned-session cleanup.')
            return self.send(202, store.get(cid))
        return self.send(404, {'error':'Not found.'})

def create_server(root, port=0):
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.daemon_threads = True
    server.app = Application(root)
    server.app.origin = f'http://127.0.0.1:{server.server_port}'
    return server

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir', type=Path, default=default_home())
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    # Prevent two UI instances from racing over the same case store.
    from .storage import run_lock
    ui_lock = args.data_dir/'ui'
    ui_lock.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        with run_lock(ui_lock):
            server = create_server(args.data_dir, args.port)
            url = server.app.origin+'/#'+server.app.bootstrap
            atomic(args.data_dir/'ui-address.json', {'url':url, 'pid':os.getpid()})
            if not args.no_browser: webbrowser.open(url)
            server.serve_forever()
    except (OSError, BlockingIOError):
        # Existing instance: its authenticated browser session is reused.
        address = args.data_dir/'ui-address.json'
        if address.exists() and not args.no_browser:
            webbrowser.open(json.loads(address.read_text())['url'])
        else: raise

if __name__ == '__main__': main()
