"""Deterministic routing. Source data and model text cannot create commands."""
import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

MAX_FILE = 20 * 1024 * 1024
FORMATS = {'.pdf': 'application/pdf', '.html': 'text/html', '.htm': 'text/html',
           '.txt': 'text/plain', '.json': 'application/json'}
MODES = {'browser', 'pdf-text', 'pdf-ocr', 'username', 'harvest', 'fingerprint', 'permutations'}
PROFILES = {'mixed', 'documents', 'websites', 'accounts', 'domains'}
ID = re.compile(r'[A-Za-z0-9_-]{1,80}')

def host(value):
    if not isinstance(value, str):
        raise ValueError('Hosts must be text.')
    value = value.strip().lower()
    if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}', value):
        raise ValueError('Use exact public DNS hostnames, without wildcards or ports.')
    if value.endswith(('.local', '.localhost', '.internal', '.lan', '.onion', '.home', '.test', '.invalid')):
        raise ValueError('Private, special-use and onion hosts are outside this adapter scope.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('IP literals are not allowed.')

def url(value, hosts):
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) <= 32 or ord(c) == 127 for c in value) or '\\' in value:
        raise ValueError('Invalid URL.')
    u = urlsplit(value)
    if u.scheme != 'https' or u.username is not None or u.password is not None or u.fragment or u.port not in (None, 443):
        raise ValueError('URLs must use HTTPS on port 443, with no credentials or fragments.')
    if host(u.hostname or '') not in hosts:
        raise ValueError('Every URL must match an allowed host exactly.')
    return value

def lines(value):
    if not isinstance(value, str):
        raise ValueError('Expected one value per line.')
    return list(dict.fromkeys(x.strip() for x in value.splitlines() if x.strip()))

def normalize(data):
    if not isinstance(data, dict):
        raise ValueError('Expected a case form.')
    title = str(data.get('title', '')).strip()
    question = str(data.get('question', '')).strip()
    if not 1 <= len(title) <= 160 or not 10 <= len(question) <= 12000:
        raise ValueError('Give the case a title and an objective of 10–12,000 characters.')
    hosts = [host(x) for x in lines(data.get('hosts', ''))]
    seeds = lines(data.get('urls', ''))
    if not 1 <= len(hosts) <= 40 or not 1 <= len(seeds) <= 20:
        raise ValueError('This backend requires 1–40 allowed hosts and 1–20 seed URLs.')
    for seed in seeds:
        url(seed, hosts)
    budget = data.get('max_urls', 12)
    if type(budget) is not int or not max(1, len(seeds)) <= budget <= 40:
        raise ValueError('Page budget must cover all seeds and be at most 40.')
    profile = data.get('profile', 'mixed')
    if profile not in PROFILES:
        raise ValueError('Unknown job profile.')
    workflow = data.get('workflow_mode', 'tool_first')
    if workflow not in ('tool_first', 'tools_only'):
        raise ValueError('Unknown workflow mode.')
    domain = data.get('domain', '').strip().lower()
    if domain:
        domain = host(domain)
        if domain not in hosts:
            raise ValueError('The extraction domain must be an allowed host.')
    username = data.get('username', '').strip()
    if username and not re.fullmatch(r'[\w.-]{1,80}', username):
        raise ValueError('Invalid username.')
    positive = lines(data.get('positive_markers', ''))
    absence = lines(data.get('absence_markers', ''))
    if username and (not positive or not absence or not any(username.lower() in x.lower() for x in positive)):
        raise ValueError('Username checks need presence markers containing that username and absence markers.')
    if len(positive) > 8 or len(absence) > 8 or any(len(x) > 300 for x in positive + absence):
        raise ValueError('Use at most eight markers of 300 characters each.')
    clicks = lines(data.get('clicks', ''))
    if len(clicks) > 8 or any(len(x) > 300 for x in clicks):
        raise ValueError('Use at most eight browser selectors of 300 characters each.')
    return dict(title=title, question=question, hosts='\n'.join(hosts), urls='\n'.join(seeds),
                max_urls=budget, profile=profile, workflow_mode=workflow, domain=domain,
                username=username, positive_markers='\n'.join(positive), absence_markers='\n'.join(absence), clicks='\n'.join(clicks))

def manifest(case_id, data, files, runtime_hash):
    data = normalize(data)
    if not ID.fullmatch(case_id) or not re.fullmatch('[0-9a-f]{64}', runtime_hash):
        raise ValueError('A qualified tool-runtime pin is required.')
    hosts, seeds = lines(data['hosts']), lines(data['urls'])
    sources = [{k: v for k, v in f.items() if k in {'id','filename','sha256','content_type','origin','description','url','http_status','curl_exit'}} for f in files]
    captures = ['url:' + u for u in seeds if not urlsplit(u).path.lower().endswith('.pdf')]
    captures += ['local:' + f['id'] for f in sources if f['content_type'] == 'text/html' and f.get('url')]
    pdfs = ['local:' + f['id'] for f in sources if f['content_type'] == 'application/pdf']
    pdfs += ['url:' + u for u in seeds if urlsplit(u).path.lower().endswith('.pdf')]
    recipes, reasons = [], []
    def add(ident, mode, refs, params, reason, phase='initial'):
        recipes.append(dict(id=ident, mode=mode, inputs=refs, params=params, run_at=phase))
        reasons.append(dict(id=ident, mode=mode, reason=reason, phase=phase))
    for offset in range(0, len(pdfs), 10):
        refs = pdfs[offset:offset+10]
        add('text-' + str(offset//10+1), 'pdf-text', refs, {}, 'Native text extraction preserves source wording.')
        add('ocr-' + str(offset//10+1), 'pdf-ocr', refs, {}, 'OCR provides a second extraction pass; compare disagreements.', 'review')
    profile = data['profile']
    # Only bounded captured inputs are passed; tools never receive a live network URL to fetch.
    if len(captures) > 20 and profile != 'documents':
        raise ValueError('Capture recipes accept at most 20 inputs. Reduce the combined URL/HTML source set; no inputs are silently skipped.')
    if captures and profile in {'mixed','websites','accounts'}:
        add('page-replay', 'browser', captures, {'start': captures[0], 'clicks': lines(data['clicks'])}, 'Replay the first page against approved captures in an offline browser.')
    if captures and profile in {'mixed','websites','domains'}:
        add('technology-hints', 'fingerprint', captures, {}, 'Extract technology indicators from captures; treat them as hints.')
    if data['domain'] and profile in {'mixed','domains'}:
        if captures:
            add('scoped-contacts', 'harvest', captures, {'domain': data['domain']}, 'Extract only contacts matching the selected domain.')
        add('domain-candidates', 'permutations', [], {'domain': data['domain']}, 'Generate candidates offline; availability is not checked.')
    if data['username'] and captures and profile in {'mixed','accounts'}:
        checks = [dict(source=r, username=data['username'], positive_markers=lines(data['positive_markers']), absence_markers=lines(data['absence_markers'])) for r in captures]
        add('account-markers', 'username', captures, {'checks': checks}, 'Compare explicit presence and absence markers; identity remains unresolved.')
    if len(recipes) > 12:
        raise ValueError('The proposed plan exceeds 12 tool jobs. Reduce the source set.')
    result = dict(case_id=case_id, title=data['title'], question=data['question'], allowed_hosts=hosts,
                  seed_urls=seeds, max_urls=data['max_urls'], model_socket='/ipc/current.sock',
                  workflow_mode=data['workflow_mode'], data_classification='private', local_evidence=sources,
                  tool_recipes=recipes, tool_runtime_sha256=runtime_hash, max_tool_jobs=12)
    return result, reasons

def sha256(raw):
    return hashlib.sha256(raw).hexdigest()
