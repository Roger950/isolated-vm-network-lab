"""Verify the public file set and SHA-256 values without reading runtime data."""
from pathlib import Path
import hashlib
import sys

ROOT=Path(__file__).resolve().parents[1]
manifest=ROOT/'MANIFEST.sha256'
expected=dict(line.split('  ',1)[::-1] for line in manifest.read_text().splitlines() if line)
actual={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
        for p in ROOT.rglob('*') if p.is_file() and p!=manifest
        and not any(x in {'.git','__pycache__'} for x in p.relative_to(ROOT).parts)}
ok=expected==actual
print('MANIFEST='+('PASS' if ok else 'FAIL')+' FILES='+str(len(actual)))
sys.exit(not ok)
