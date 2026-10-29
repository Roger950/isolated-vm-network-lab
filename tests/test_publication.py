import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('privacy',ROOT/'tools/privacy_check.py')
privacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(privacy)

class PublicationTests(unittest.TestCase):
    def test_public_snapshot(self):self.assertEqual(privacy.check(ROOT),[])
    def test_private_key_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);(p/'sample.txt').write_text('-----BEGIN '+'PRIVATE KEY-----')
            self.assertTrue(privacy.check(p))
    def test_credential_file_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);(p/'input.json').write_text('{"password":"synthetic-secret"}')
            self.assertTrue(privacy.check(p))
    def test_firewall_rebuilds_table(self):
        source=(ROOT/'gateway/guardian-gateway.nft.in').read_text()
        self.assertIn('delete table inet guardian_gateway',source)
        self.assertNotIn('flush table inet guardian_gateway',source)

if __name__=='__main__':unittest.main()
