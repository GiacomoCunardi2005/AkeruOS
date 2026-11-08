#!/usr/bin/env python3
"""Check GUI JPEG getter, payload mapping, and use of its return in V1.1."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, disasm, locate, raw, u32

sha = lambda x: hashlib.sha256(x).hexdigest()
tbm = (ROOT / 'S33-sections/02_TBM_SK501_payload.bin').read_bytes()
dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
for address, length in [(0x302634, 8), (0x7c9e38, 0xa0), (0x981734, 160)]:
    block, delta = locate(address, length)
    assert raw(address, length) == dump[block['offset'] + delta:block['offset'] + delta + length]
block = BS[1]
assert (block['offset'], block['load_address_candidate'], block['size']) == (0x2ae600, 0x360800, 0xc7e00)
assert PS[1] == tbm[block['offset']:block['offset'] + block['size']]
assert PS[1] == dump[block['offset']:block['offset'] + block['size']]
base_file, base_memory = 0x35c918, u32(0x302638)
assert base_memory == 0x40eb18 == block['load_address_candidate'] + base_file - block['offset']
getter = disasm(0x302634, 0x302638)
gui = disasm(0x7c9e38, 0x7c9ec6)
for token in ('j_s.d\t[blink]', 'ld_s\tr0,[pcl,0x4]'):
    assert token in getter
for token in (';0x302634', ';0x7c9ecc', 'ld_s\tr0,[pcl,0x60]', 'ld\tr0,[r16]', ';0x159558'):
    assert token in gui
assert 'bne_s\t6\t;0x7c9e62' in gui and 'b_s\t102\t;0x7c9ec6' in gui
between = gui.split('  7c9e62:', 1)[1].split('  7c9e6c:', 1)[0]
assert 'r0' not in between
assert ';0x159550' not in gui
records = []
for i in range(1, 19):
    offset, size = u32(0x981734 + i * 8), u32(0x981738 + i * 8)
    memory, source = base_memory + offset, base_file + offset
    assert size > 0 and source + size <= block['offset'] + block['size']
    payload = raw(memory, size)
    assert payload == tbm[source:source + size] == dump[source:source + size]
    assert payload[:2] == b'\xff\xd8' and payload[-2:] == b'\xff\xd9'
    records.append({'index': i, 'offset': offset, 'length': size, 'file_offset': source,
                    'candidate_load_address': memory, 'sha256': sha(payload)})
assert u32(0x981734) == u32(0x981738) == u32(0x9817cc) == u32(0x9817d0) == 0
out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('jpeg_resident_getter_%Y%m%dT%H%M%SZ')
out.mkdir(parents=True, exist_ok=False)
(out / 'gnu_windows.txt').write_text(getter + '\n' + gui)
(out / 'evidence.json').write_text(json.dumps({
    'status': 'PASS_STATIC_MAPPED_BYTES', 'tbm_sha256': sha(tbm), 'dump_sha256': sha(dump),
    'payload1_sha256': sha(PS[1]), 'getter': '0x302634', 'getter_value': hex(base_memory),
    'file_base': hex(base_file), 'table': '0x981734', 'records': records,
    'limits': ['Candidate loader mapping only, no runtime RAM observation.',
               'Getter return overwritten before read; no GUI memory read demonstrated.',
               'Indirect writes, real synchronization, backend, scheduling and display not tested.']}, indent=2) + '\n')
(out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
print('PASS: getter maps to all 18 JPEGs, GUI overwrites return before reader;', out)
