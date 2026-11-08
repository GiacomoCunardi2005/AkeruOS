#!/usr/bin/env python3
"""Check boundaries and literal-address references for the illustrated JPEG run."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS

src = ROOT / 'Risultati/GUI_S33/embedded_jpeg_20261027T113806Z/inventory.json'
inventory = json.loads(src.read_text())
records = [r for r in inventory['records'] if r['size'] == [160, 96]]
assert len(records) == 18
firmware = (ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()
assert hashlib.sha256(firmware).hexdigest() == inventory['firmware_sha256']
rows = []
for i, rec in enumerate(records):
    offset, size = int(rec['offset'], 16), rec['bytes']
    blob = firmware[offset:offset + size]
    assert blob.startswith(b'\xff\xd8\xff') and blob.endswith(b'\xff\xd9')
    assert hashlib.sha256(blob).hexdigest() == rec['sha256']
    if i:
        prev = records[i - 1]
        assert offset == int(prev['offset'], 16) + prev['bytes']
    block = next(b for b in BS if b['offset'] <= offset and offset + size <= b['offset'] + b['size'])
    assert block['index'] == 2
    runtime = block['load_address_candidate'] + offset - block['offset']
    hits = {}
    for name, needle in [('le32', struct.pack('<I', runtime)),
                         ('arc_limm', struct.pack('<HH', runtime >> 16, runtime & 0xffff))]:
        found = []
        for b in BS:
            data, start = PS[b['index']], 0
            while (where := data.find(needle, start)) >= 0:
                found.append({'payload': b['index'], 'address_candidate': hex(b['load_address_candidate'] + where)})
                start = where + 1
        hits[name] = found
    rows.append({'index': i, 'offset': hex(offset), 'bytes': size,
                 'address_candidate': hex(runtime), 'references': hits})
out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('jpeg_sequence_%Y%m%dT%H%M%SZ')
out.mkdir(parents=True, exist_ok=False)
(out / 'evidence.json').write_text(json.dumps({'status': 'PASS_STATIC', 'records': rows,
    'source_inventory_sha256': hashlib.sha256(src.read_bytes()).hexdigest(),
    'limits': ['Literal matches can be data or code and do not prove references.',
               'Relative offsets, transforms, computed addresses and runtime copies are not searched.',
               'Payload load address is a candidate; no menu or hardware path is established.']}, indent=2) + '\n')
(out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
print('PASS:', len(rows), 'contiguous JPEGs;', sum(bool(r['references']['le32'] or r['references']['arc_limm']) for r in rows), 'with literal hits;', out)
