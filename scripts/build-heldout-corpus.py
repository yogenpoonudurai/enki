#!/usr/bin/env python3
"""Build the held-out public-source corpus.

Populate HELDOUT_SEARCH_DIR with JSON results from:
  gh search code 'mcpServers filename:.mcp.json' --limit 100 --json repository,path,url > mcp.json
  gh search code 'bypassPermissions filename:settings.json' --limit 100 --json repository,path,url > agt.json
  gh search code 'defaultMode filename:.claude/settings.json' --limit 100 --json repository,path,url > agt_default.json
  gh search code 'trust_remote_code=True language:Python' --limit 100 --json repository,path,url > mdl_trust.json
  gh search code 'torch.load language:Python' --limit 100 --json repository,path,url > mdl_torch.json
  gh search code 'OPENAI_API_KEY filename:.env.example' --limit 100 --json repository,path,url > sec.json

Labels are produced by independent parsers in this script (MCP/agent/model/env)
and by live OSV (SBOM). Files containing high-confidence live secrets are skipped.
Requires network access, npm, and the public GitHub raw content endpoints.
"""
import concurrent.futures, hashlib, json, os, re, sys, time, subprocess, shutil
import urllib.request, urllib.error, urllib.parse
from pathlib import Path

SEARCH = Path(os.environ.get('HELDOUT_SEARCH_DIR', '/tmp/heldout-search'))
OUT = Path(__file__).resolve().parent.parent / 'internal/bench/testdata'
CACHE = Path('/tmp/heldout-src'); CACHE.mkdir(exist_ok=True)
UA = 'enki-heldout-builder/1'

SECRET_RE = re.compile(r'''(?x)
  (sk-[A-Za-z0-9_-]{20,})
| (hf_[A-Za-z0-9]{20,})
| (gh[pousr]_[A-Za-z0-9]{20,})
| (github_pat_[A-Za-z0-9_]{20,})
| (AKIA[0-9A-Z]{16})
| (AIza[0-9A-Za-z_-]{35})
| (xox[baprs]-[A-Za-z0-9-]{10,})
| (-----BEGIN [A-Z ]*PRIVATE KEY-----)
''')

def has_secret(s):
    return SECRET_RE.search(s) is not None

def fetch(url):
    key = hashlib.sha256(url.encode()).hexdigest()
    p = CACHE / (key + '.src')
    if p.exists():
        return p.read_bytes()
    last = None
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': UA})
            with urllib.request.urlopen(req, timeout=25) as r:
                if r.status != 200:
                    raise RuntimeError('HTTP %d' % r.status)
                data = r.read(2 * 1024 * 1024 + 1)
                if len(data) > 2 * 1024 * 1024:
                    raise RuntimeError('file too large')
            p.write_bytes(data)
            return data
        except Exception as e:
            last = e; time.sleep(1.5 * (attempt + 1))
    raise RuntimeError('fetch %s: %s' % (url, last))

def parse_search(path, filter_path=None):
    rows = json.load(open(path))
    out = []
    for r in rows:
        u = r.get('url', '')
        m = re.match(r'https://github\.com/([^/]+/[^/]+)/blob/([0-9a-f]{40})/(.+)$', u)
        if not m:
            continue
        repo, sha, p = m.groups(); p = urllib.parse.unquote(p)
        if filter_path and not filter_path(p):
            continue
        out.append((repo, sha, p, u))
    return out

def hyphen_commit(sha):
    return '-'.join(sha[i:i+8] for i in range(0, len(sha), 8))

def raw_url(repo, sha, path):
    return 'https://raw.githubusercontent.com/%s/%s/%s' % (repo, sha, urllib.parse.quote(path))

def strip_jsonc(text):
    out=[]; i=0; in_str=False; esc=False
    while i < len(text):
        c=text[i]
        if in_str:
            out.append(c)
            if esc: esc=False
            elif c=='\\': esc=True
            elif c=='"': in_str=False
            i+=1; continue
        if c=='"': in_str=True; out.append(c); i+=1; continue
        if c=='/' and i+1<len(text) and text[i+1]=='/':
            while i<len(text) and text[i] not in '\r\n': i+=1
            continue
        if c=='/' and i+1<len(text) and text[i+1]=='*':
            i+=2
            while i+1<len(text) and not (text[i]=='*' and text[i+1]=='/'): i+=1
            i+=2; continue
        out.append(c); i+=1
    return ''.join(out)

def load_jsonc(data):
    s = data.decode('utf-8', 'replace')
    return json.loads(strip_jsonc(s))

def pinned_npm(spec):
    if not spec: return False
    if spec.startswith('@'):
        rest = spec.split('/',1)[1] if '/' in spec else ''
        if '@' not in rest: return False
        ver = rest.rsplit('@',1)[1]
    else:
        if '@' not in spec: return False
        ver = spec.rsplit('@',1)[1]
    return bool(re.match(r'^\d+\.\d+', ver)) and ver.lower() not in ('latest','next','beta','canary')

def npx_pkg(args):
    i=0
    while i < len(args):
        a=args[i]
        if a.startswith('--package='): return a.split('=',1)[1]
        if a=='--package' and i+1<len(args): return args[i+1]
        if a in ('--registry','--cache','-w','--workspace','--prefix','--userconfig'):
            i+=2; continue
        if a=='--': i+=1; continue
        if a.startswith('-'): i+=1; continue
        return a
    return None

def uvx_pkg(args):
    i=0; from_spec=None
    while i < len(args):
        a=args[i]
        if a.startswith('--from='): from_spec=a.split('=',1)[1]; i+=1; continue
        if a=='--from' and i+1<len(args): from_spec=args[i+1]; i+=2; continue
        if a in ('--index-url','--index','--python','--with','--with-editable'):
            i+=2; continue
        if a.startswith('-'): i+=1; continue
        return from_spec or a, bool(from_spec)
    return from_spec, bool(from_spec)

def labels_mcp(data):
    servers = data.get('mcpServers') if isinstance(data, dict) else None
    if not isinstance(servers, dict) or not servers: return None
    counts={}
    def add(rule,n=1): counts[rule]=counts.get(rule,0)+n
    for name, srv in servers.items():
        if not isinstance(srv, dict): continue
        cmd = os.path.basename(str(srv.get('command',''))).lower().replace('.exe','').replace('.cmd','')
        args = [str(x) for x in (srv.get('args') or []) if isinstance(x,(str,int,float))]
        if cmd in ('npx','pnpx','bunx'):
            pkg=npx_pkg(args)
            if pkg and not pinned_npm(pkg): add('MCP-001')
        elif cmd in ('uvx',):
            pkg,is_from=uvx_pkg(args)
            if pkg:
                pinned = ('==' in pkg and bool(re.search(r'==\d', pkg))) or ('@' in pkg and pinned_npm(pkg))
                if not pinned: add('MCP-001')
        url = srv.get('url')
        if isinstance(url,str) and url:
            u=urllib.parse.urlparse(url)
            host=(u.hostname or '').lower()
            if u.scheme=='http' and host not in ('localhost','127.0.0.1','::1'):
                add('MCP-002')
        for k,v in list((srv.get('env') or {}).items())+list((srv.get('headers') or {}).items()):
            if isinstance(v,str) and has_secret(v): add('MCP-003')
        for a in args:
            if a in ('/','~','C:\\\\','C:/','C:\\'): add('MCP-004'); break
        lname=str(name).lower()
        if any(m in lname for m in ('shell','exec','terminal','bash','powershell','cmd','command')):
            add('MCP-005')
    return counts

def walk_obj(v, cb):
    if isinstance(v, dict):
        for k,val in v.items(): cb(k,val); walk_obj(val,cb)
    elif isinstance(v,list):
        for x in v: walk_obj(x,cb)

def labels_agt(data):
    counts={}
    def add(r): counts[r]=counts.get(r,0)+1
    def cb(key,val):
        lk=str(key).lower()
        if lk=='defaultmode' and isinstance(val,str) and val.lower()=='bypasspermissions': add('AGT-001')
        if lk in ('dangerouslyskipperpermissions','dangerously-skip-permissions','dangerouslyskip') and val is True: add('AGT-001')
        if lk in ('allow','allowedtools','allowed_tools','alwaysallow'):
            entries = val if isinstance(val,list) else []
            for e in entries:
                es=str(e).strip().lower()
                if es in ('bash','bash(*)','bash(:*)','shell','shell(*)','zsh','zsh(*)','sh','sh(*)','powershell','powershell(*)','pwsh','pwsh(*)','cmd','cmd(*)'): add('AGT-002')
                if any(m in es for m in ('.ssh','.aws','.gnupg','.config/gcloud','id_rsa','id_ed25519')): add('AGT-004')
        if 'autorun' in lk or 'auto_run' in lk or 'autoapprove' in lk:
            if val is True: add('AGT-003')
    walk_obj(data, cb)
    # enki emits at most one finding per rule per config file.
    return {k: 1 for k in counts}

def labels_mdl(text):
    counts={}
    if re.search(r'trust_remote_code\s*=\s*True', text, re.I): counts['MDL-002']=1
    n=0
    for m in re.finditer(r'torch\.load\s*\(', text):
        tail=text[m.end():m.end()+240]
        if not re.search(r'weights_only\s*=\s*True', tail): n+=1
    if n: counts['MDL-003']=1
    n=len(re.findall(r'http://[^\s"\'<>)]+?\.(?:pt|pth|pkl|ckpt|bin|safetensors)\b', text, re.I))
    if n: counts['MDL-004']=n
    return counts

def dev_sources():
    d=json.load(open(OUT/'realworld.json'))
    out=set()
    for c in d.get('cases',[]):
        s=c.get('source') or {}
        if s.get('repo') and s.get('commit') and s.get('path'):
            out.add((s['repo'],s['commit'],s['path']))
    return out

def add_case(cases, name, module, source, evaluate, labels, notes):
    c={'name':name,'category':'heldout','module':module,'evaluate':evaluate,'source':source,'notes':notes}
    if labels: c['labels']=labels
    cases.append(c)

def build_sbom(cases, start_index):
    outdir = OUT / 'realworld' / 'heldout' / 'ecosystem'
    outdir.mkdir(parents=True, exist_ok=True)
    candidates = [
        ('axios','0.21.1'), ('minimist','1.2.5'), ('json5','2.2.1'), ('node-fetch','2.6.6'),
        ('tar','6.1.0'), ('glob-parent','5.1.1'), ('follow-redirects','1.14.7'), ('cross-fetch','3.1.4'),
        ('semver','7.3.5'), ('word-wrap','1.2.3'), ('tough-cookie','4.1.2'), ('loader-utils','2.0.2'),
        ('jsonwebtoken','8.5.1'), ('qs','6.10.2'), ('braces','3.0.2'), ('minimatch','3.0.4'),
        ('nanoid','3.1.30'), ('debug','2.6.8'), ('serialize-javascript','2.1.1'), ('xmldom','0.5.0'),
        ('ejs','3.1.6'), ('got','11.8.3'), ('minimist','1.2.8'), ('json5','2.2.3'),
        ('node-fetch','3.3.2'), ('axios','1.7.7'), ('tough-cookie','4.1.4'),
    ]
    results=[]
    tmpbase = Path('/tmp/heldout-npm'); tmpbase.mkdir(exist_ok=True)
    for pkg, ver in candidates:
        d = tmpbase / ('%s-%s' % (pkg.replace('/','_'), ver)); shutil.rmtree(d, ignore_errors=True); d.mkdir(parents=True)
        try:
            subprocess.run(['npm','init','-y'], cwd=d, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
            subprocess.run(['npm','install','%s@%s' % (pkg, ver), '--package-lock-only','--ignore-scripts','--no-audit','--no-fund'], cwd=d, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
            lockdata = (d/'package-lock.json').read_bytes()
        except Exception as e:
            print('npm skip', pkg, ver, e, file=sys.stderr); continue
        try: lock = json.loads(lockdata)
        except Exception: continue
        queries=[]
        for key, entry in (lock.get('packages') or {}).items():
            if not key or not isinstance(entry, dict): continue
            ver2 = entry.get('version'); name = key.rsplit('node_modules/',1)[-1]
            if name and ver2 and re.match(r'^\d', str(ver2)):
                queries.append({'package':{'name':name,'ecosystem':'npm'},'version':ver2})
        if not queries: continue
        try:
            body=json.dumps({'queries':queries}).encode()
            req=urllib.request.Request('https://api.osv.dev/v1/querybatch', data=body, headers={'User-Agent':UA,'Content-Type':'application/json'})
            with urllib.request.urlopen(req, timeout=60) as r:
                osv=json.loads(r.read().decode()).get('results', [])
            vuln=any(x.get('vulns') for x in osv)
        except Exception as e:
            print('osv skip', pkg, ver, e, file=sys.stderr); continue
        results.append((pkg, ver, lockdata, vuln))
    positives=[r for r in results if r[3]]
    negatives=[r for r in results if not r[3]]
    selected = positives[:15] + negatives[:5]
    if len(selected) < 20:
        selected += [r for r in results if r not in selected][:20-len(selected)]
    created=0
    for pkg, ver, lockdata, vuln in selected:
        rel = Path('heldout')/'ecosystem'/(pkg.replace('/','_')+'-'+ver)/'package-lock.json'
        (outdir/rel.parent.name).mkdir(parents=True, exist_ok=True)
        (OUT/'realworld'/rel).write_bytes(lockdata)
        src={'local_path':str(rel),'work_path':'package-lock.json','mode':'0644','notes':'npm registry lockfile %s@%s' % (pkg,ver)}
        labels=[{'rule_id':'SBOM-001','presence':True}] if vuln else []
        add_case(cases, 'heldout-sbom-%03d' % (start_index+created), 'sbom', src, ['SBOM-001'], labels, 'Public npm lockfile %s@%s' % (pkg,ver))
        created += 1
    return created

def main():
    dev=dev_sources()
    cases=[]; seen=set()

    # MCP: keep valid configs (mix of labeled and clean)
    mcp=parse_search(SEARCH/'mcp.json'); mcp_ok=0
    for repo,sha,path,blob in mcp:
        if not (path.endswith('.mcp.json') or path in ('.mcp.json','mcp.json')): continue
        raw=raw_url(repo,sha,path)
        if (repo,sha,path) in dev or raw in seen: continue
        try: data=load_jsonc(fetch(raw))
        except Exception: continue
        if has_secret(json.dumps(data)): continue
        labels=labels_mcp(data)
        if labels is None: continue
        seen.add(raw)
        src={'repo':repo,'commit':hyphen_commit(sha),'path':path,'work_path':'.mcp.json','mode':'0600','notes':'Public MCP config'}
        add_case(cases, 'heldout-mcp-%03d'%len(cases), 'mcp', src, ['MCP-001','MCP-002','MCP-003','MCP-004','MCP-005'], [{'rule_id':k,'count':v} for k,v in sorted(labels.items())], 'Public MCP config: %s'%repo)
        mcp_ok+=1

    # Agent settings: 10 labeled + 10 unlabeled (or best effort)
    agt=parse_search(SEARCH/'agt.json')+parse_search(SEARCH/'agt_default.json')
    labeled=[]; clean=[]
    for repo,sha,path,blob in agt:
        if not path.endswith('.claude/settings.json'): continue
        raw=raw_url(repo,sha,path)
        if (repo,sha,path) in dev or raw in seen: continue
        try: data=load_jsonc(fetch(raw))
        except Exception: continue
        if has_secret(json.dumps(data)): continue
        labels=labels_agt(data); seen.add(raw)
        src={'repo':repo,'commit':hyphen_commit(sha),'path':path,'work_path':'.claude/settings.json','mode':'0600','notes':'Public Claude settings'}
        c={'name':'heldout-agt','category':'heldout','module':'agent-permissions','evaluate':['AGT-001','AGT-002','AGT-003','AGT-004'],'source':src,'labels':[{'rule_id':k,'count':v} for k,v in sorted(labels.items())],'notes':'Public Claude settings: %s'%repo}
        (labeled if labels else clean).append(c)
    selected = labeled[:10] + clean[:10]
    if len(selected) < 20: selected += (labeled[10:]+clean[10:])[:20-len(selected)]
    for i,c in enumerate(selected):
        c['name']='heldout-agt-%03d'%len(cases); cases.append(c)

    # Model: 20 trust-remote positives + 20 torch cases with both outcomes
    trust=parse_search(SEARCH/'mdl_trust.json', lambda p: p.endswith('.py'))
    torch=parse_search(SEARCH/'mdl_torch.json', lambda p: p.endswith('.py'))
    def model_cases(rows, limit):
        out=[]
        for repo,sha,path,blob in rows:
            raw=raw_url(repo,sha,path)
            if (repo,sha,path) in dev or raw in seen: continue
            try: data=fetch(raw)
            except Exception: continue
            text=data.decode('utf-8','replace')
            if has_secret(text): continue
            labels=labels_mdl(text); seen.add(raw)
            src={'repo':repo,'commit':hyphen_commit(sha),'path':path,'work_path':'app.py','mode':'0644','notes':'Public Python model code'}
            out.append({'name':'heldout-mdl','category':'heldout','module':'model-artifacts','evaluate':['MDL-002','MDL-003','MDL-004'],'source':src,'labels':[{'rule_id':k,'count':v} for k,v in sorted(labels.items())],'notes':'Public model code: %s'%repo})
            if len(out)>=limit: break
        return out
    trust_cases=model_cases(trust,20)
    torch_cases=model_cases(torch,20)
    torch_pos=[c for c in torch_cases if c['labels']]
    torch_neg=[c for c in torch_cases if not c['labels']]
    torch_selected=torch_pos[:10]+torch_neg[:10]
    if len(torch_selected)<20: torch_selected += (torch_pos[10:]+torch_neg[10:])[:20-len(torch_selected)]
    for c in trust_cases+torch_selected:
        c['name']='heldout-mdl-%03d'%len(cases); cases.append(c)

    # Env examples: negatives only, no live secrets
    sec=parse_search(SEARCH/'sec.json'); sec_ok=0
    for repo,sha,path,blob in sec:
        if repo == 'gusye1234/nano-graphrag': continue
        raw=raw_url(repo,sha,path)
        if (repo,sha,path) in dev or raw in seen: continue
        try: data=fetch(raw)
        except Exception: continue
        text=data.decode('utf-8','replace')
        if has_secret(text): continue
        seen.add(raw)
        src={'repo':repo,'commit':hyphen_commit(sha),'path':path,'work_path':'.env','mode':'0600','notes':'Public env example with placeholders'}
        add_case(cases, 'heldout-sec-%03d'%len(cases), 'secrets', src, ['SEC-001','SEC-003'], [], 'Public env example (no live secrets): %s'%repo)
        sec_ok+=1
        if sec_ok>=14: break

    sbom_ok=build_sbom(cases, len(cases))
    print('mcp',mcp_ok,'agt',len(selected),'mdl',len(trust_cases)+len(torch_selected),'sec',sec_ok,'sbom',sbom_ok,'total',len(cases))
    json.dump({'cases':cases}, open(OUT/'heldout.json','w'), indent=2)
    open(OUT/'heldout.json','a').write('\n')

if __name__=='__main__': main()
