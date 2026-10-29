import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from osint_harness import backend, policy
from osint_harness.report import sanitize, CSP
from osint_harness.server import create_server
from osint_harness.storage import Store, atomic, run_lock

FORM = dict(title='Public documentation review', question='What does this source establish and what remains unknown?',
            hosts='example.org', urls='https://example.org/', profile='mixed', max_urls=4, workflow_mode='tool_first', domain='example.org')

class PolicyTests(unittest.TestCase):
    def test_scope_rejects_escape_and_ambiguous_urls(self):
        bad = ['http://example.org/','https://example.org.evil.com/','https://example.org@evil.com/',
               'https://example.org:444/','https://127.0.0.1/','https://example.org/#fragment',
               'https://example.org\\@evil.com/','https://example.org/\nnext','https://example.org./']
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError): policy.normalize(dict(FORM,urls=value))
    def test_scope_budget_and_private_hosts(self):
        for value in ['localhost','a.local','a.onion','*.example.org','127.0.0.1']:
            with self.assertRaises(ValueError): policy.host(value)
        with self.assertRaises(ValueError): policy.normalize(dict(FORM,max_urls=0))
        with self.assertRaises(ValueError): policy.normalize(dict(FORM,domain='outside.org'))
    def test_deterministic_plan_and_fixed_model(self):
        manifest,reasons=policy.manifest('case-test',FORM,[],'a'*64)
        self.assertEqual([r['mode'] for r in manifest['tool_recipes']],['browser','fingerprint','harvest','permutations'])
        self.assertEqual(manifest['model_socket'],'/ipc/current.sock')
        self.assertEqual(manifest['workflow_mode'],'tool_first')
        self.assertEqual(len(reasons),4)
        self.assertTrue(all(set(r)=={'id','mode','run_at','inputs','params'} for r in manifest['tool_recipes']))
    def test_username_requires_binding_and_absence_marker(self):
        with self.assertRaises(ValueError): policy.normalize(dict(FORM,username='subject',positive_markers='Welcome',absence_markers='Missing'))
        with self.assertRaises(ValueError): policy.normalize(dict(FORM,username='subject',positive_markers='Profile subject'))
    def test_pdf_routes_to_native_and_ocr(self):
        files=[dict(id='doc',filename='doc.pdf',sha256='b'*64,content_type='application/pdf',origin='operator_supplied',description='Document')]
        m,_=policy.manifest('case-test',dict(FORM,profile='documents'),files,'a'*64)
        self.assertEqual([r['mode'] for r in m['tool_recipes']],['pdf-text','pdf-ocr'])
        self.assertEqual(m['tool_recipes'][1]['run_at'],'review')
    def test_untrusted_report_has_no_executable_or_network_surface(self):
        result=sanitize('<head><meta http-equiv="refresh" content="0;url=https://evil.org"><style>body{background:url(https://evil.org)}</style></head><script>alert(1)</script><svg onload="alert(2)"></svg><iframe src="https://evil.org"></iframe><img src="https://evil.org"><a href="https://evil.org">Evidence</a><p onclick="x()">Safe &amp; quoted</p>')
        for value in ['evil.org','<script','<svg','<iframe','<img','onclick','href=','alert(']: self.assertNotIn(value,result)
        self.assertIn('Evidence',result)
        self.assertIn('Safe &amp; quoted',result)

class StorageTests(unittest.TestCase):
    def test_success_requires_current_cleanup_receipt(self):
        from osint_harness.worker import outcome
        self.assertEqual(outcome(0,'report_ready_unreviewed',True,False)[0],'complete')
        self.assertEqual(outcome(0,'report_ready_unreviewed',False,False)[0],'needs_attention')
        self.assertEqual(outcome(1,'report_ready_unreviewed',False,True)[0],'needs_attention')
        self.assertEqual(outcome(1,'running',True,True)[0],'stopped')
        self.assertEqual(outcome(1,'report_ready_unreviewed',True,False)[0],'needs_attention')
    def test_immutable_run_reservation_and_concurrency(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(tmp);a=store.create(FORM);b=store.create(FORM)
            store.reserve(a['id'],False)
            with self.assertRaises(ValueError): store.reserve(b['id'],False)
            with self.assertRaises(ValueError): store.path('../outside')
    def test_kernel_lock_releases_on_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            with run_lock(tmp):
                with self.assertRaises(OSError):
                    with run_lock(tmp): pass
            with run_lock(tmp): pass
    def test_backend_pin_rejects_new_or_changed_modules(self):
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/'operator';folder.mkdir()
            for n in ['start_case.py','ui_entry.py']: (folder/n).write_text('# fixture')
            cfg=dict(contract='qualified-pilot-v1',operator_dir=str(folder),source_files={p.name:policy.sha256(p.read_bytes()) for p in folder.iterdir()},runtime_hash='a'*64,ssh_alias='fixture-backend',python=sys.executable)
            atomic(Path(tmp)/'settings.json',cfg)
            backend.settings(tmp)
            (folder/'new_module.py').write_text('raise RuntimeError')
            with self.assertRaises(ValueError): backend.settings(tmp)
            (folder/'new_module.py').unlink();(folder/'start_case.py').write_text('changed')
            with self.assertRaises(ValueError): backend.settings(tmp)
            (folder/'start_case.py').write_text('# fixture');(folder/'shadow.pyd').write_bytes(b'untrusted')
            with self.assertRaises(ValueError): backend.settings(tmp)

class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.server=create_server(self.tmp.name)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.cookie='';self.csrf=''
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.tmp.cleanup()
    def request(self,path,method='GET',data=None,headers=None,raw=None):
        h={'Origin':self.server.app.origin}
        if self.cookie:h['Cookie']=self.cookie
        if self.csrf:h['X-CSRF-Token']=self.csrf
        body=raw
        if data is not None:body=json.dumps(data);h['Content-Type']='application/json'
        h.update(headers or {})
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=5)
        connection.request(method,path,body=body,headers=h);res=connection.getresponse();content=res.read();result=(res.status,dict(res.getheaders()),content);connection.close();return result
    def login(self):
        status,h,b=self.request('/api/session','POST',{'token':self.server.app.bootstrap})
        self.assertEqual(status,200);self.cookie=h['Set-Cookie'].split(';')[0];self.csrf=json.loads(b)['csrf']
    def test_auth_origin_host_csrf_and_bootstrap(self):
        self.assertEqual(self.request('/api/cases')[0],401)
        self.assertEqual(self.request('/',headers={'Host':'evil.org'})[0],421)
        self.assertEqual(self.request('/api/session','POST',{},headers={'Origin':'https://evil.org'})[0],403)
        token=self.server.app.bootstrap;self.login()
        self.assertEqual(self.request('/api/session','POST',{'token':token})[0],403)
        self.assertEqual(self.request('/api/cases','POST',FORM,headers={'X-CSRF-Token':'bad'})[0],403)
        self.assertEqual(self.request('/api/cases',headers={'Sec-Fetch-Site':'cross-site'})[0],403)
        self.assertEqual(self.request('/api/cases')[0],200)
        # A fresh launcher can authenticate another browser; the previous capability stays invalid.
        self.cookie='';self.csrf='';self.login()
    def test_draft_upload_hash_and_run_failure_closed(self):
        self.login();code,_,body=self.request('/api/cases','POST',FORM);self.assertEqual(code,201);cid=json.loads(body)['id']
        prefix='/api/cases/'+cid
        h={'Content-Type':'application/octet-stream','X-File-Name':'../escape.txt'}
        self.assertEqual(self.request(prefix+'/upload','POST',raw=b'evidence',headers=h)[0],400)
        h['X-File-Name']='record.txt'
        code,_,body=self.request(prefix+'/upload','POST',raw=b'evidence',headers=h);self.assertEqual(code,201)
        f=json.loads(body)['files'][0];self.assertEqual(f['sha256'],policy.sha256(b'evidence'))
        h['X-File-Name']='fake.pdf';self.assertEqual(self.request(prefix+'/upload','POST',raw=b'not pdf',headers=h)[0],400)
        self.assertEqual(self.request(prefix+'/start','POST',{})[0],400)
        self.assertEqual(self.server.app.store.get(cid)['state'],'draft')
    def test_report_has_separate_sandbox_policy(self):
        self.login();_,_,body=self.request('/api/cases','POST',FORM);cid=json.loads(body)['id']
        p=self.server.app.store.path(cid)/'report'/'osint-pilot-live-report.html';p.write_text('<img src="https://evil.org"><p>Evidence</p>')
        code,headers,body=self.request('/api/cases/'+cid+'/report');self.assertEqual(code,200)
        self.assertEqual(headers['Content-Security-Policy'],CSP)
        self.assertNotIn(b'evil.org',body)
    def test_started_cases_reject_edits_and_uploads(self):
        self.login();_,_,body=self.request('/api/cases','POST',FORM);cid=json.loads(body)['id'];self.server.app.store.reserve(cid,False)
        self.assertEqual(self.request('/api/cases/'+cid,'POST',FORM)[0],400)
        self.assertEqual(self.request('/api/cases/'+cid+'/upload','POST',raw=b'xx',headers={'Content-Type':'application/octet-stream','X-File-Name':'x.txt'})[0],400)

if __name__=='__main__':unittest.main()
