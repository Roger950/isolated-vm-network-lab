"""Probe supplied SOCKS credentials through the host HTTP proxy; never print them."""
import json
import socket
import ssl
import sys
import time

def read_exact(sock, count):
    result = b''
    while len(result) < count:
        chunk = sock.recv(count-len(result))
        if not chunk:
            raise ConnectionError('peer closed connection')
        result += chunk
    return result

def main():
    args=json.load(sys.stdin)
    hostname=args.get('test_host','example.com')
    if hostname not in ('example.com','api.ipify.org'):
        print('INVALID_TEST_HOST'); return 1
    if any(not 1 <= len(args[field].encode()) <= 255 for field in ('username','password')):
        print('INVALID_CREDENTIAL_LENGTH'); return 1
    stage='HOST_PROXY_CONNECT'
    start=time.monotonic()
    try:
        with socket.create_connection(('127.0.0.1',args['local_port']),timeout=10) as sock:
            sock.settimeout(12)
            target=f"{args['server']}:{args['port']}"
            sock.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode())
            response=b''
            while not response.endswith(b'\r\n\r\n'):
                response+=read_exact(sock,1)
                if len(response)>8192: raise ValueError('oversized HTTP response')
            code=response.split(b' ',2)[1].decode()
            print('HOST_CONNECT_HTTP='+code,flush=True)
            if code!='200': return 1
            stage='SOCKS_GREETING'
            sock.sendall(b'\x05\x01\x02')
            greeting=read_exact(sock,2)
            print('SOCKS_METHOD='+greeting.hex(),flush=True)
            if greeting!=b'\x05\x02': return 1
            stage='SOCKS_AUTH'
            user=args['username'].encode(); password=args['password'].encode()
            sock.sendall(b'\x01'+bytes([len(user)])+user+bytes([len(password)])+password)
            auth=read_exact(sock,2)
            print('SOCKS_AUTH_OK='+str(auth==b'\x01\x00'),flush=True)
            if auth!=b'\x01\x00': return 1
            stage='SOCKS_DESTINATION'
            domain=hostname.encode('ascii')
            sock.sendall(b'\x05\x01\x00\x03'+bytes([len(domain)])+domain+b'\x01\xbb')
            reply=read_exact(sock,4)
            print('SOCKS_CONNECT_CODE='+str(reply[1]),flush=True)
            if reply[1]!=0: return 1
            count={1:4,4:16}.get(reply[3])
            if reply[3]==3: count=read_exact(sock,1)[0]
            if count is None: raise ValueError('invalid address type')
            read_exact(sock,count+2)
            stage='TLS_AND_HTTP'
            with ssl.create_default_context().wrap_socket(sock,server_hostname=hostname) as tls:
                tls.sendall(f'GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'.encode('ascii'))
                response=tls.recv(1024)
                print('WEBSITE_HTTP='+response.split(b'\r\n',1)[0].decode('ascii',errors='replace'),flush=True)
                print('TEST_HOST='+hostname+' TOTAL_SECONDS='+str(round(time.monotonic()-start,2)),flush=True)
                if args.get('hold_seconds'):
                    time.sleep(min(10,max(0,float(args['hold_seconds']))))
            return 0 if response.split(b' ',2)[1:2]==[b'200'] else 1
    except (OSError,ValueError) as error:
        print(json.dumps({'failed_stage':stage,'error_type':type(error).__name__,'seconds':round(time.monotonic()-start,2)}),flush=True)
        return 1

if __name__=='__main__': sys.exit(main())
