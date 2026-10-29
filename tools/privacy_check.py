"""Conservative offline checks for this publication's declared content boundary."""
from pathlib import Path
import ipaddress
import json
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
FORBIDDEN={'.exe','.iso','.vmx','.vmdk','.vmem','.vmss','.nvram','.pem','.key','.log','.bak'}
TEXT={'.py','.cs','.md','.json','.yaml','.yml','.svg','.sh','.in','.init','.hotplug'}
PUBLIC_TEST_IPS={'1.1.1.1','1.0.0.1'}

def files(root):
    return sorted(p for p in root.rglob('*') if p.is_file() and not any(x in {'.git','__pycache__'} for x in p.relative_to(root).parts))

def check(root=ROOT):
    failures=[]
    for path in files(root):
        relative=path.relative_to(root).as_posix()
        if any(x in {'.local','.secrets','VMs','openwrt'} for x in path.relative_to(root).parts) or path.suffix.lower() in FORBIDDEN:
            failures.append((relative,'forbidden-file'));continue
        try: text=path.read_text(encoding='utf-8')
        except UnicodeError:
            failures.append((relative,'non-text'));continue
        patterns={
            'private-key':r'-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----',
            'token':r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b',
            'personal-path':r'(?i)[A-Z]:[\\/]Users[\\/][^\s/\\]+',
            'uuid':r'\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b',
            'chat-link':r'https://(?:chatgpt\.com|claude\.ai)/(?:c|share|chat)/',
        }
        for label,pattern in patterns.items():
            if re.search(pattern,text):failures.append((relative,label))
        for raw in re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])',text):
            try: address=ipaddress.IPv4Address(raw)
            except ValueError: continue
            if address.is_global and raw not in PUBLIC_TEST_IPS:failures.append((relative,'unexpected-public-ip'))
        if path.suffix=='.json':
            try: value=json.loads(text)
            except ValueError: failures.append((relative,'invalid-json'));continue
            def walk(item):
                if isinstance(item,dict):
                    for key,value in item.items():
                        if key.lower() in ('username','password','token','secret') and value not in ('EXAMPLE_USERNAME','EXAMPLE_PASSWORD',''):
                            failures.append((relative,'non-placeholder-credential'))
                        walk(value)
                elif isinstance(item,list):
                    for value in item:walk(value)
            walk(value)
    return failures

if __name__=='__main__':
    failures=check()
    print(json.dumps({'checked_files':len(files(ROOT)),'findings':failures},ensure_ascii=False))
    sys.exit(bool(failures))
