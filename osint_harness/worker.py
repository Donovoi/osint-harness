import json
from pathlib import Path
import subprocess
import sys
import threading
import time
from . import backend
from .storage import Store, run_lock
from .policy import sha256

def outcome(code, state, cleaned, stop_requested):
    if code == 0 and state == 'report_ready_unreviewed' and cleaned:
        return 'complete', 'Report ready for human review; owned-session cleanup completed.'
    if stop_requested and cleaned:
        return 'stopped', 'Stopped at a checkpoint; owned-session cleanup completed. Resume keeps the frozen scope.'
    return 'needs_attention', 'Run did not complete successfully. Review status and the private runner log before resuming; cleanup may need attention.'

def verify_inputs(store, cid):
    case, folder = store.get(cid), store.path(cid)
    for f in case['files']:
        path = folder/'uploads'/f['filename']
        if path.is_symlink() or path.resolve().parent != (folder/'uploads').resolve() or sha256(path.read_bytes()) != f['sha256']:
            raise ValueError('An uploaded source changed. Execution is blocked.')
    path = folder/'manifest.json'
    if sha256(path.read_bytes()) != (folder/'manifest.sha256').read_text():
        raise ValueError('The frozen case manifest changed. Execution is blocked.')

def main():
    root, cid, *flags = sys.argv[1:]
    store, finished = Store(root), threading.Event()
    try:
        with run_lock(root):
            cfg = backend.settings(root)
            verify_inputs(store, cid)
            folder = store.path(cid)
            (folder/'report'/'ui-session.json').unlink(missing_ok=True)
            args = backend.launch_args(cfg, folder, cid, '--resume' in flags)
            def heartbeat():
                while not finished.wait(5): store.update(cid, heartbeat=time.time())
            threading.Thread(target=heartbeat, daemon=True).start()
            with (folder/'runner.log').open('ab') as log:
                process = subprocess.Popen(args, cwd=cfg['operator_dir'], stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                           creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                store.update(cid, state='running', pid=process.pid, heartbeat=time.time())
                code = process.wait()
            # A successful launcher includes its owned-resource cleanup. Reports alone never signal success.
            status_path = folder/'report'/'osint-pilot-status.json'
            status = json.loads(status_path.read_text(encoding='utf-8')) if status_path.exists() else {}
            state = (status.get('supervisor') or {}).get('state')
            receipt_path = folder/'report'/'ui-session.json'
            receipt = json.loads(receipt_path.read_text(encoding='utf-8')) if receipt_path.exists() else {}
            cleaned = receipt.get('cleanup_complete') is True
            state_name, message = outcome(code, state, cleaned, (folder/'stop.request').exists())
            store.update(cid, state=state_name, message=message, pid=0, heartbeat=time.time())
    except Exception as error:
        store.update(cid, state='needs_attention', message=f'Execution blocked or interrupted ({type(error).__name__}). Check backend integrity, private logs and cleanup.', heartbeat=time.time())
        # Diagnostic stays local; never put raw paths/host details in HTTP errors.
        with (store.path(cid)/'runner.log').open('a', encoding='utf-8') as log: log.write('\n'+repr(error)+'\n')
    finally: finished.set()
