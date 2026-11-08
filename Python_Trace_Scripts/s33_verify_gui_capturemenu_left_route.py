#!/usr/bin/env python3
"""Verify the bounded V1.1 CaptureMenu Left route against MainCode."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import cstring, disasm, locate, raw, u16, u32

dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()

def check(addr, length):
    block, offset = locate(addr, length)
    assert raw(addr, length) == dump[block['offset'] + offset:block['offset'] + offset + length]

check(0x3f5900, (0x87 + 1) * 4)
for ident, desc, name, callback in [(2, 0x9802ac, 'CaptureMenu', 0x7cafe8),
                                     (0x87, 0x783ae8, 'AutoSceneLiveView', 0x6593a0)]:
    assert u32(0x3f5900 + ident*4) == desc
    check(desc, 24)
    assert u16(desc+4) == ident and u32(desc+12) == callback
    nameaddr = u32(desc+20)
    check(nameaddr, len(name)+1)
    assert cstring(nameaddr) == name

capture = [(0x4401, 0x7cb020), (0x4405, 0x7cb03c),
           (0x4406, 0x7cb0a4), (0x180, 0x7cb0d8),
           (0x480, 0x7cb0f8), (0, 0x20e814)]
check(0x982384, len(capture)*8)
assert [(u32(0x982384+8*i), u32(0x982388+8*i)) for i in range(len(capture))] == capture
check(0x3e8bb4, 0xa8)
assert (u32(0x3e8c4c), u32(0x3e8c50)) == (0x2180, 0x20e940)
check(0x7cb018, 8)
assert (u32(0x7cb018), u32(0x7cb01c)) == (0x899858, 0x982384)
check(0x20e844, 4)
assert u32(0x20e844) == 0x3e8bb4
check(0x20ea50, 12)
assert [u32(0x20ea50+i) for i in (0,4,8)] == [0x3101, 0x1453fc, 0x17c074]

segments = [(0x7cafe8, 0x7cb018), (0x7cb0f8, 0x7cb118),
            (0x20e814, 0x20e844), (0x169f60, 0x169fb4),
            (0x20e940, 0x20ea50), (0x16e41c, 0x16e440)]
windows = []
for start, end in segments:
    check(start, end-start)
    windows.append(disasm(start, end))
for n, needle in [(0, ';0x169f60'), (1, 'mov_s\tr1,0x43'),
                  (1, 'asl_s\tr1,r1,0x7'), (1, ';0x20e814'),
                  (2, ';0x169f60'), (3, 'jl_s.d\t[r3]'),
                  (4, ';0xcb4a8'), (4, ';0xcad5c'),
                  (4, ';0x17be18'), (4, ';0x16f920'),
                  (4, ';0x16e41c'), (4, ';0x1564c0'),
                  (4, 'mov_s\tr0,0x87'), (4, ';0x1453e4'),
                  (5, 'mov_s\tr0,0x2a'), (5, 'mov_s\tr1,0')]:
    assert needle in windows[n], needle
out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('capturemenu_left_route_%Y%m%dT%H%M%SZ')
out.mkdir(parents=True, exist_ok=False)
(out / 'gnu_windows.txt').write_text('\n'.join(windows))
(out / 'evidence.json').write_text(json.dumps({
    'status': 'PASS_STATIC_BOUNDED',
    'dump_sha256': hashlib.sha256(dump).hexdigest(),
    'path': ['CaptureMenu descriptor 0x9802ac', 'wrapper 0x7cafe8',
             'event 0x480: table 0x982384 -> 0x7cb0f8',
             'event 0x2180: dispatcher 0x20e814, table 0x3e8bb4 -> 0x20e940',
             'conditional request 0x1453e4(0x87,0), AutoSceneLiveView'],
    'limits': ['Static route only, not event delivery, task order or physical key.',
               'Runtime filter and service returns unknown; call 0x1453e4 is a request, not proof of display.',
               'Other table entries and 0x20e940 service side effects not exhaustively analyzed.']
}, indent=2)+'\n')
(out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
print('PASS: CaptureMenu Left -> generic 0x2180 conditional request;', out)
