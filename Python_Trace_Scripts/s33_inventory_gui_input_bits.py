#!/usr/bin/env python3
"""Check the original input-state records associated with GUI events."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import locate, raw

address, count, stride = 0x392f04, 16, 20
data = raw(address, count * stride)
block, offset = locate(address, len(data))
dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
assert data == dump[block['offset'] + offset:block['offset'] + offset + len(data)]
rows = []
for index in range(count):
    record = data[index * stride:(index + 1) * stride]
    mask = int.from_bytes(record[:8], 'little')
    bit, key = record[8:10]
    assert mask == 1 << bit
    rows.append({'index': index, 'address': hex(address + index * stride),
                 'raw': record.hex(), 'mask': hex(mask), 'bit': bit,
                 'logical_key': key, 'event_nonzero': hex(key << 7) if key < 0x61 else None,
                 'event_zero': hex((key << 7) | 1) if key < 0x61 else None})
assert [(r['bit'], r['logical_key']) for r in rows if r['logical_key'] == 14] == [(7, 14)]
assert [(r['bit'], r['logical_key']) for r in rows if r['logical_key'] in (9, 10, 11)] == [(21, 9), (15, 10), (12, 11)]
out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('input_bits_%Y%m%dT%H%M%SZ')
out.mkdir(parents=True, exist_ok=False)
result = {'status': 'PASS_STATIC_RECORDS', 'table': hex(address), 'records': rows,
          'dump_sha256': hashlib.sha256(dump).hexdigest(),
          'limits': ['Static initial records, not observed runtime state.',
                     'The source and physical identity of the state bits are unverified.',
                     'Event codes apply only when the event-emission path is enabled.']}
(out / 'records.json').write_text(json.dumps(result, indent=2) + '\n')
(out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
print('PASS: 16 original input records;', out)
