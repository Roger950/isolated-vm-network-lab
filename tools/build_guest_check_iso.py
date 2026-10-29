"""Build a minimal non-bootable ISO9660 data disk using only Python stdlib."""
from pathlib import Path
from datetime import datetime, timezone
import struct
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--executable', default='CHECK.EXE')
parser.add_argument('--output', default='guest-check.iso')
args = parser.parse_args()

BASE = Path(__file__).resolve().parent
SECTOR = 2048
now = datetime.now(timezone.utc)
date7 = bytes([now.year - 1900, now.month, now.day, now.hour, now.minute, now.second, 0])

def dual32(n): return struct.pack('<I', n) + struct.pack('>I', n)
def dual16(n): return struct.pack('<H', n) + struct.pack('>H', n)
def record(name, extent, size, directory=False):
    length = 33 + len(name) + (1 if len(name) % 2 == 0 else 0)
    data = bytearray(length)
    data[0] = length
    data[2:10] = dual32(extent)
    data[10:18] = dual32(size)
    data[18:25] = date7
    data[25] = 2 if directory else 0
    data[28:32] = dual16(1)
    data[32] = len(name)
    data[33:33+len(name)] = name
    return data

readme = ('Guardian Guest Check\r\n\r\nOpen CHECK.EXE manually inside the Windows guest.\r\n'
          'Choose 1 for offline checks. Choose 2 for network checks, 3 for direct-IP HTTPS.\r\n'
          'Do not choose 2 or 3 until the isolated LAN is connected. Both require manual T.\r\n'
          'No installation, settings changes, account/password reads, or report files.\r\n'
          'CHECK.CS contains the complete source for review.\r\n').encode('ascii')
files = [(b'CHECK.EXE;1', (BASE / args.executable).read_bytes()),
         (b'README.TXT;1', readme), (b'CHECK.CS;1', (BASE / 'GuestCheck.cs').read_bytes())]
position = 21
entries = []
for name, data in files:
    entries.append((name, data, position))
    position += (len(data) + SECTOR - 1) // SECTOR
image = bytearray(position * SECTOR)
pvd = bytearray(SECTOR)
pvd[0:7] = b'\x01CD001\x01'
pvd[8:40] = b'WINDOWS'.ljust(32, b' ')
pvd[40:72] = b'GUARDIAN_CHECK'.ljust(32, b' ')
pvd[80:88] = dual32(position)
pvd[120:124] = dual16(1)
pvd[124:128] = dual16(1)
pvd[128:132] = dual16(SECTOR)
pvd[132:140] = dual32(10)
pvd[140:144] = struct.pack('<I', 18)
pvd[148:152] = struct.pack('>I', 19)
pvd[156:190] = record(b'\0', 20, SECTOR, True)
pvd[190:813] = b' ' * (813 - 190)
stamp = now.strftime('%Y%m%d%H%M%S').encode('ascii') + b'00\0'
for offset in (813, 830, 864): pvd[offset:offset+17] = stamp
pvd[847:864] = b'0' * 16 + b'\0'
pvd[881] = 1
image[16*SECTOR:17*SECTOR] = pvd
image[17*SECTOR:17*SECTOR+7] = b'\xffCD001\x01'
image[18*SECTOR:18*SECTOR+10] = b'\x01\0' + struct.pack('<I',20) + struct.pack('<H',1) + b'\0\0'
image[19*SECTOR:19*SECTOR+10] = b'\x01\0' + struct.pack('>I',20) + struct.pack('>H',1) + b'\0\0'
directory = record(b'\0',20,SECTOR,True) + record(b'\1',20,SECTOR,True)
for name, data, extent in entries:
    directory += record(name, extent, len(data))
    image[extent*SECTOR:extent*SECTOR+len(data)] = data
assert len(directory) <= SECTOR
image[20*SECTOR:20*SECTOR+len(directory)] = directory
output = BASE / args.output
output.write_bytes(image)
print('Read-only data ISO created:', output.name, 'bytes=',len(image))
