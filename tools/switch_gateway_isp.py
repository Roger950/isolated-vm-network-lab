"""Replace only the gateway SOCKS endpoint, with backup and timed rollback.

Private replacement credentials arrive on stdin. Existing private configuration
is parsed in memory and never printed or saved on the host.
"""
from pathlib import Path
import argparse
import hashlib
import ipaddress
import json
import socket
import subprocess
import sys
import time
import uuid

BASE=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description='Operator-authorized gateway endpoint replacement')
parser.add_argument('--host',required=True,help='SSH destination, e.g. root@gateway.example.invalid')
parser.add_argument('--key',required=True,type=Path)
parser.add_argument('--known-hosts',required=True,type=Path)
options=parser.parse_args()
SSH=['ssh','-i',str(options.key),'-o','BatchMode=yes',
     '-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',
     '-o','UserKnownHostsFile='+str(options.known_hosts),'-o','ConnectTimeout=8']
HOST=options.host

def remote(command, data=None, timeout=35):
    r=subprocess.run(SSH+[HOST,command],input=data,capture_output=True,timeout=timeout)
    if r.returncode: raise RuntimeError('remote_operation_failed')
    return r.stdout

def main():
    replacement=json.load(sys.stdin)
    ipaddress.IPv4Address(replacement['server'])
    if not 1<=int(replacement['port'])<=65535: raise ValueError('invalid_port')
    current=remote('cat /etc/mihomo/config.yaml')
    config=json.loads(current)
    proxy=config['proxies'][0]
    if proxy['name']!='Static-ISP' or proxy['type']!='socks5':
        raise RuntimeError('unexpected_proxy_shape')
    for field in ('server','port','username','password'): proxy[field]=replacement[field]
    proxy['udp']=False
    proxy['ip-version']='ipv4'
    candidate=json.dumps(config,ensure_ascii=False).encode('utf-8')
    before=hashlib.sha256(current).hexdigest()
    after=hashlib.sha256(candidate).hexdigest()
    backup='/root/guardian-endpoint-backup-'+uuid.uuid4().hex[:12]
    script=r'''set -eu
umask 077
test "$(sha256sum /etc/mihomo/config.yaml | cut -d ' ' -f 1)" = BEFORE
mkdir -m 700 BACKUP
cp -p /etc/mihomo/config.yaml BACKUP/config.before.json
cp -p /usr/share/guardian-gateway/guardian-gateway.nft.in BACKUP/firewall.before.nft.in
sed 's/^flush table inet guardian_gateway$/delete table inet guardian_gateway/' BACKUP/firewall.before.nft.in > BACKUP/firewall.candidate.nft.in
cat > BACKUP/candidate.json
test "$(sha256sum BACKUP/candidate.json | cut -d ' ' -f 1)" = AFTER
if ! /usr/bin/mihomo -t -d /etc/mihomo -f BACKUP/candidate.json > BACKUP/validation.log 2>&1; then
    echo CONFIG_VALIDATION_FAILED; exit 1
fi
cat > BACKUP/rollback.sh <<'ROLLBACK'
#!/bin/sh
set -eu
test -e BACKUP/pending || exit 0
cp -p BACKUP/config.before.json /etc/mihomo/config.yaml
cp -p BACKUP/firewall.before.nft.in /usr/share/guardian-gateway/guardian-gateway.nft.in
/usr/share/guardian-gateway/guardian-render-firewall.sh | sed 's/^flush table inet guardian_gateway$/delete table inet guardian_gateway/' > BACKUP/rollback-rules.nft
nft -c -f BACKUP/rollback-rules.nft
nft -f BACKUP/rollback-rules.nft
/etc/init.d/guardian-mihomo restart
rm -f BACKUP/pending
echo ROLLED_BACK
ROLLBACK
chmod 700 BACKUP/rollback.sh
touch BACKUP/pending
setsid sh -c 'sleep 300; sh BACKUP/rollback.sh' </dev/null >BACKUP/timer.log 2>&1 &
trap 'sh BACKUP/rollback.sh' HUP INT TERM
if ! ( /etc/init.d/guardian-mihomo stop &&
       cp -p BACKUP/candidate.json /etc/mihomo/config.yaml &&
       cp -p BACKUP/firewall.candidate.nft.in /usr/share/guardian-gateway/guardian-gateway.nft.in &&
       /etc/init.d/guardian-gateway start &&
       /etc/init.d/guardian-mihomo start ); then
    sh BACKUP/rollback.sh
    exit 1
fi
echo APPLIED_WITH_PENDING_ROLLBACK
'''.replace('BACKUP',backup).replace('BEFORE',before).replace('AFTER',after)
    tunnel=None
    armed=True
    try:
        print(remote(script,candidate).decode().strip(),flush=True)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port=listener.getsockname()[1]
        tunnel=subprocess.Popen(SSH+['-N','-T','-o','ExitOnForwardFailure=yes','-L',
            f'127.0.0.1:{port}:127.0.0.1:7890',HOST],stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        time.sleep(2)
        if tunnel.poll() is not None: raise RuntimeError('test_tunnel_failed')
        checks={}
        for hostname in ('example.com','api.ipify.org'):
            r=subprocess.run(['curl','--noproxy','','--proxy',f'http://127.0.0.1:{port}',
                '--connect-timeout','8','--max-time','18','--silent','--show-error',
                '--write-out','\n%{http_code}',f'https://{hostname}/'],capture_output=True,timeout=22)
            body,_,status=r.stdout.rpartition(b'\n')
            checks[hostname]=r.returncode==0 and status.strip()==b'200'
            if hostname=='api.ipify.org' and checks[hostname]:
                address=ipaddress.ip_address(body.decode().strip())
                checks['exit_is_ipv4']=address.version==4
                checks['exit_equals_configured_endpoint']=str(address)==replacement['server']
        state=remote("/etc/init.d/guardian-mihomo status; nslookup -type=a example.com 127.0.0.1; nft -j list table inet guardian_gateway",timeout=25).decode()
        checks['core_running']=state.startswith('running\n')
        checks['dns_a_answer']='Name:' in state and 'Address:' in state
        table=json.loads(state[state.index('{'):])
        chains={item['chain']['name']:item['chain'] for item in table['nftables'] if 'chain' in item}
        checks['forward_policy_drop']=chains['forward_guard']['policy']=='drop'
        checks['output_policy_drop']=chains['output_guard']['policy']=='drop'
        sets=[item['set'] for item in table['nftables'] if 'set' in item]
        endpoint=next(s for s in sets if s['name']=='isp_endpoint')
        checks['only_configured_endpoint_allowed']=endpoint.get('elem')==[{'concat':[replacement['server'],replacement['port']]}]
        print(json.dumps(checks),flush=True)
        required=[v for k,v in checks.items() if k!='exit_equals_configured_endpoint']
        if not all(required): raise RuntimeError('post_switch_verification_failed')
        remote(f"test -e {backup}/pending; test \"$(sha256sum /etc/mihomo/config.yaml | cut -d ' ' -f 1)\" = {after}; rm {backup}/pending; echo COMMITTED")
        armed=False
        result={'provider':'operator-configured','backup':backup,'checks':checks,'rollback_pending':False,
                'guest_application_verified':False}
        (BASE/'endpoint-switch-result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print('SWITCH_VERIFIED_AND_COMMITTED; BACKUP='+backup,flush=True)
    except Exception:
        if armed:
            try: print(remote(f'sh {backup}/rollback.sh').decode().strip(),flush=True)
            except Exception: print('AUTOMATIC_ROLLBACK_TIMER_REMAINS',flush=True)
        raise
    finally:
        if tunnel is not None:
            tunnel.terminate()
            try: tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired: tunnel.kill();tunnel.wait()

if __name__=='__main__':
    try: main()
    except Exception as error:
        print('SWITCH_FAILED: '+type(error).__name__+': '+str(error) if isinstance(error,RuntimeError) else 'SWITCH_FAILED: '+type(error).__name__)
        sys.exit(1)
