"""Fixed CLI adapter. All infrastructure values belong in private settings."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from .policy import sha256, ID

def settings(root):
    path = Path(root)/'settings.json'
    if not path.is_file(): raise ValueError('Backend is not configured. Open installation settings.')
    cfg = json.loads(path.read_text(encoding='utf-8'))
    if cfg.get('contract') != 'qualified-pilot-v1': raise ValueError('Unsupported backend contract.')
    folder = Path(cfg['operator_dir']).resolve()
    hashes = cfg.get('source_files', {})
    if not {'start_case.py','ui_entry.py'} <= hashes.keys():
        raise ValueError('Missing backend source pin.')
    # Reject unpinned modules: imports must not silently acquire new executable code.
    actual = {p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name != 'SOURCE-MANIFEST.json'}
    pinned = set(hashes)
    if actual != pinned: raise ValueError('Backend executable closure changed. Requalification is required.')
    for name, digest in hashes.items():
        path = folder/name
        if path.is_symlink() or not path.resolve().is_relative_to(folder) or not path.is_file() or sha256(path.read_bytes()) != digest:
            raise ValueError('Backend source integrity check failed. Requalification is required.')
    if not re.fullmatch(r'[0-9a-f]{64}', cfg.get('runtime_hash','')): raise ValueError('Missing tool-runtime pin.')
    if not Path(cfg['python']).is_file(): raise ValueError('Backend Python executable is unavailable.')
    return cfg

def launch_args(cfg, folder, cid, resume=False):
    if not ID.fullmatch(cid): raise ValueError('Invalid case ID.')
    args = [cfg['python'], '-I', str(Path(cfg['operator_dir'])/'ui_entry.py')]
    # ui_entry is part of the pinned closure; it adds ONLY its own trusted directory.
    args += ['--resume', cid] if resume else ['--manifest', str(folder/'manifest.json'), '--evidence-dir', str(folder/'uploads')]
    return args + ['--output', str(folder/'report'), '--stop-file', str(folder/'stop.request')]

def spawn_worker(root, cid, resume):
    # Start this installed source, without trusting cwd or PYTHONPATH.
    args = [sys.executable, '-I', str(Path(__file__).resolve().parent/'worker_entry.py'), str(root), cid]
    if resume: args += ['--resume']
    options = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    if os.name == 'nt': options['creationflags'] = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    else: options['start_new_session'] = True
    return subprocess.Popen(args, **options)
