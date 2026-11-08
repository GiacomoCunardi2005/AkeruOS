#!/usr/bin/env python3
"""Verify the bounded static route from HintMessage to indexed JPEG reading."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import cstring, disasm, locate, raw, u16, u32

dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
def checked(addr, length):
    b, off = locate(addr, length)
    value = raw(addr, length)
    assert value == dump[b['offset'] + off:b['offset'] + off + length]
    return value

descriptor, wrapper, event_table = 0x981990, 0x7c976c, 0x9819c8
checked(0x3f5900 + 4*0x9e, 4)
assert u32(0x3f5900 + 4*0x9e) == descriptor
checked(descriptor, 24)
assert u16(descriptor + 4) == 0x9e and u32(descriptor + 12) == wrapper
assert cstring(u32(descriptor + 20)) == 'HintMessage'
checked(0x7c979c, 8)
assert u32(0x7c97a0) == event_table
checked(event_table, 8)
assert u32(event_table) == 0x4405 and u32(event_table+4) == 0x7c97a4
segments = [(0x7c976c,0x7c97c2), (0x7c999a,0x7c99c6),
            (0x7c9bbc,0x7c9bec), (0x7c9bf0,0x7c9c80),
            (0x7c9cfc,0x7c9d5e)]
windows = []
for start,end in segments:
    checked(start,end-start)
    windows.append(disasm(start,end))
for i,needle in [(0,';0x169f60'),(1,'cmp_s\tr0,0x7'),(1,';0x7c9bbc'),
                 (2,'mov\tr4,0xe'),(2,';0x7c9bf0'),(3,';0x7c9c54'),
                 (3,';0x7c9cfc'),(4,';0x7c9e38'),(4,';0x7c9c80')]:
    assert needle in windows[i], needle
out = ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('jpeg_hint_path_%Y%m%dT%H%M%SZ')
out.mkdir(parents=True, exist_ok=False)
(out/'gnu_windows.txt').write_text('\n'.join(windows))
(out/'evidence.json').write_text(json.dumps({'status':'PASS_STATIC_BOUNDED',
    'object':'HintMessage', 'object_id':'0x9e', 'event':'0x4405',
    'event_handler':'0x7c97a4', 'selected_index':14,
    'dump_sha256':hashlib.sha256(dump).hexdigest(),
    'limits':['Conditional static path; object state, runtime resource base and services not executed.',
              'JPEG identification assumes matching source base; no physical display observed.']},indent=2)+'\n')
(out/'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
print('PASS: HintMessage event 0x4405, conditional indexed JPEG path;',out)
