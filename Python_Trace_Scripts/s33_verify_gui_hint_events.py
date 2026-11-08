#!/usr/bin/env python3
"""Check the V1.1 HintMessage event routes against the recorded dump."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import disasm, locate, raw, u32

dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()

def check(addr, length):
    block, offset = locate(addr, length)
    assert raw(addr, length) == dump[block['offset'] + offset:block['offset'] + offset + length]

events = [(0x4405, 0x7c97a4), (0x4406, 0x7c9a9c),
          (0x440e, 0x7c9adc), (0x300, 0x7c9b04),
          (0x600, 0x7c9b44), (0x4005, 0x7c9b6c),
          (0x5000, 0x7c9af0), (0, 0x20e814)]
check(0x9819c8, 8 * len(events))
assert [(u32(0x9819c8 + 8*i), u32(0x9819cc + 8*i))
        for i in range(len(events))] == events
segments = [(0x7c97a4, 0x7c97f8), (0x7c999a, 0x7c9a68),
            (0x7c9a9c, 0x7c9b04), (0x7c9b04, 0x7c9bbc),
            (0x7c9bbc, 0x7c9bec)]
windows = []
for start, end in segments:
    check(start, end-start)
    windows.append(disasm(start, end))
for n, needle in [(0, ';0x12845c'), (0, ';0x7c9a5a'),
                  (1, 'cmp_s\tr0,0x7'), (1, ';0x7c9bbc'),
                  (1, 'cmp_s\tr0,0x58'), (2, ';0x15b044'),
                  (3, ';0x1453e4'), (3, ';0x169f40'),
                  (4, 'mov\tr4,0xe'), (4, ';0x7c9bf0')]:
    assert needle in windows[n], needle

out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('hint_events_%Y%m%dT%H%M%SZ')
out.mkdir(parents=True, exist_ok=False)
(out / 'gnu_windows.txt').write_text('\n'.join(windows))
(out / 'evidence.json').write_text(json.dumps({
    'status': 'PASS_STATIC_BOUNDED',
    'dump_sha256': hashlib.sha256(dump).hexdigest(),
    'events': [{'event': hex(event), 'handler': hex(handler)} for event, handler in events],
    'limits': ['Static routes only; indirect calls, event delivery and service results untested.',
               'Index 14 does not establish the runtime source base or a displayed image.']
}, indent=2) + '\n')
(out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
print('PASS: event table and bounded HintMessage routes;', out)
