"""Offline protocol fixtures: no real proxy credentials and no network requests."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('probe',ROOT/'tools/diagnose_socks_chain.py')
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)

class FakeSocket:
    def __init__(self,data):self.data=data;self.sent=[]
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def recv(self,count):
        if isinstance(self.data,Exception):raise self.data
        result=self.data[:count];self.data=self.data[count:];return result
    def sendall(self,data):self.sent.append(data)
    def settimeout(self,value):pass

class ProtocolTests(unittest.TestCase):
    def run_probe(self,payload,status=200,host='example.com'):
        sock=FakeSocket(b'HTTP/1.1 200 Connection established\r\n\r\n'+payload)
        tls=FakeSocket(f'HTTP/1.1 {status} Test\r\n\r\n'.encode())
        context=type('Context',(),{'wrap_socket':lambda self,*args,**kwargs:tls})()
        args={'local_port':7897,'server':'192.0.2.10','port':1080,
              'username':'fixture-user','password':'fixture-password','test_host':host}
        out=io.StringIO()
        with patch('sys.stdin',io.StringIO(json.dumps(args))),patch.object(probe.socket,'create_connection',return_value=sock),patch.object(probe.ssl,'create_default_context',return_value=context),contextlib.redirect_stdout(out):
            code=probe.main()
        self.assertNotIn('fixture-password',out.getvalue())
        return code,out.getvalue(),sock
    def test_success(self):
        code,out,sock=self.run_probe(b'\x05\x02\x01\x00\x05\x00\x00\x01'+bytes(6))
        self.assertEqual(code,0);self.assertIn('SOCKS_AUTH_OK=True',out)
    def test_auth_rejection(self):
        code,out,sock=self.run_probe(b'\x05\x02\x01\x01')
        self.assertEqual(code,1);self.assertIn('SOCKS_AUTH_OK=False',out)
    def test_destination_rejection(self):
        code,out,sock=self.run_probe(b'\x05\x02\x01\x00\x05\x05\x00\x01')
        self.assertEqual(code,1);self.assertIn('SOCKS_CONNECT_CODE=5',out)
    def test_unexpected_auth_method(self):
        self.assertEqual(self.run_probe(b'\x05\xff')[0],1)
    def test_http_failure_not_success(self):
        self.assertEqual(self.run_probe(b'\x05\x02\x01\x00\x05\x00\x00\x01'+bytes(6),503)[0],1)
    def test_destination_allowlist(self):
        self.assertEqual(self.run_probe(b'',host='other.example.invalid')[0],1)
    def test_premature_eof(self):
        with self.assertRaises(ConnectionError):probe.read_exact(FakeSocket(b'a'),2)
    def test_read_timeout(self):
        with self.assertRaises(TimeoutError):probe.read_exact(FakeSocket(TimeoutError()),2)

if __name__=='__main__':unittest.main()
