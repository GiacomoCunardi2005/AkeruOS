#!/usr/bin/env python3
"""Verify the illustrated JPEG offset/length index and original reader."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import disasm, locate, raw, u32

src = ROOT / 'Risultati/GUI_S33/embedded_jpeg_20261027T113806Z/inventory.json'
records = [r for r in json.loads(src.read_text())['records'] if r['size'] == [160, 96]]
assert len(records) == 18
table = 0x981734
dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
block, offset = locate(table, 20 * 8)
assert raw(table, 20 * 8) == dump[block['offset'] + offset:block['offset'] + offset + 20 * 8]
assert (u32(table), u32(table + 4)) == (0, 0)
base = int(records[0]['offset'], 16)
rows = []
for i, rec in enumerate(records, 1):
    entry = table + i * 8
    off, length = u32(entry), u32(entry + 4)
    assert off == int(rec['offset'], 16) - base and length == rec['bytes']
    rows.append({'index': i, 'entry': hex(entry), 'relative_offset': hex(off),
                 'length': length, 'container_offset': rec['offset']})
assert (u32(table + 19 * 8), u32(table + 19 * 8 + 4)) == (0, 0)
assert u32(0x7c9ecc) == table
start, end = 0x7c9e38, 0x7c9ed8
b, off = locate(start, end-start)
assert raw(start, end-start) == dump[b['offset']+off:b['offset']+off+end-start]
window = disasm(start, end)
for term in ('add3_s', 'ld_s\tr0,[r0,0x4]', ';0x1593ac', ';0x159558', ';0x1594a4'):
    assert term in window, term
out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('jpeg_index_%Y%m%dT%H%M%SZ')
out.mkdir(parents=True, exist_ok=False)
(out / 'gnu_window.txt').write_text(window)
(out / 'evidence.json').write_text(json.dumps({'status':'PASS_STATIC', 'table':hex(table),
    'rows':rows, 'source_inventory_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),
    'limits':['Byte agreement establishes table contents, not actual runtime mapping of reader base.',
              'No caller, selected menu, storage backend, rendering or hardware execution established.']}, indent=2)+'\n')
(out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
print('PASS: 18 offset/length entries and reader;',out)
