import contextlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid

def default_home():
    base = os.environ.get('LOCALAPPDATA') if os.name == 'nt' else os.environ.get('XDG_DATA_HOME', str(Path.home()/'.local/share'))
    return Path(base or Path.home()) / 'OSINTHarness'

def atomic(path, value):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, indent=2), encoding='utf-8')
    tmp.replace(path)

class Store:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.root/'cases').mkdir(exist_ok=True, mode=0o700)
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, created REAL, updated REAL, state TEXT, form TEXT, files TEXT, message TEXT, pid INTEGER, heartbeat REAL)')
    @contextlib.contextmanager
    def db(self):
        db = sqlite3.connect(self.root/'cases.sqlite', timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db: yield db
        finally: db.close()
    def path(self, cid):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', cid): raise ValueError('Invalid case ID.')
        folder = self.root/'cases'/cid
        if folder.is_symlink() or not folder.resolve().is_relative_to(self.root/'cases'):
            raise ValueError('Invalid case directory.')
        return folder
    def create(self, form):
        cid = 'case-' + uuid.uuid4().hex[:20]
        folder = self.path(cid)
        folder.mkdir(mode=0o700)
        (folder/'uploads').mkdir(mode=0o700)
        (folder/'report').mkdir(mode=0o700)
        now = time.time()
        with self.db() as db:
            db.execute('INSERT INTO cases VALUES(?,?,?,?,?,?,?,?,?)', (cid,now,now,'draft',json.dumps(form),'[]','',0,0))
        return self.get(cid)
    def get(self, cid):
        self.path(cid)
        with self.db() as db:
            row = db.execute('SELECT * FROM cases WHERE id=?',(cid,)).fetchone()
        if not row: raise KeyError('Case not found.')
        data = dict(row)
        data['form'], data['files'] = json.loads(data['form']), json.loads(data['files'])
        return data
    def list(self):
        with self.db() as db:
            return [dict(row) for row in db.execute('SELECT id,created,updated,state,form,message,heartbeat FROM cases ORDER BY created DESC LIMIT 200')]
    def update(self, cid, **fields):
        allowed = {'form','files','state','message','pid','heartbeat'}
        if not fields or set(fields)-allowed: raise ValueError('Invalid update.')
        fields = {k:json.dumps(v) if k in {'form','files'} else v for k,v in fields.items()}
        fields['updated'] = time.time()
        with self.db() as db:
            db.execute('UPDATE cases SET '+','.join(k+'=?' for k in fields)+' WHERE id=?', (*fields.values(), cid))
    def reserve(self, cid, resume):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT 1 FROM cases WHERE state IN ('starting','running','stopping')").fetchone():
                raise ValueError('Another case is active. Wait for its cleanup to finish.')
            current = db.execute('SELECT state FROM cases WHERE id=?',(cid,)).fetchone()
            if not current or (not resume and current[0] != 'draft') or (resume and current[0] == 'draft'):
                raise ValueError('Invalid case transition.')
            db.execute("UPDATE cases SET state='starting',message='',updated=?,heartbeat=? WHERE id=?", (time.time(),time.time(),cid))

@contextlib.contextmanager
def run_lock(root):
    """A kernel-owned lock survives UI restarts and is released on worker exit."""
    path = Path(root)/'active.lock'
    with path.open('a+b') as handle:
        handle.seek(0)
        if os.name == 'nt':
            import msvcrt
            if not path.stat().st_size: handle.write(b'0'); handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try: yield
        finally:
            if os.name == 'nt':
                handle.seek(0); msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else: fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
