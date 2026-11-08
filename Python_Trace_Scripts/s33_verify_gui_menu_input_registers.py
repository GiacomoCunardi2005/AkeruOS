#!/usr/bin/env python3
"""Verify register sources on the bounded Menu input path, statically."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import disasm, locate, raw, u32

dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
ranges = [(0x2d62b0, 0x2d62d8), (0x2d62d8, 0x2d6300),
          (0x2b7190, 0x2b71ac), (0x242104, 0x2421fc),
          (0x1406d0, 0x140700)]
windows = []
for start, end in ranges:
    block, offset = locate(start, end - start)
    assert raw(start, end - start) == dump[block['offset'] + offset:block['offset'] + offset + end - start]
    windows.append(disasm(start, end))
for text in windows[:2]:
    assert text.count('ldh.di') == 2 and 'asl_s\tr13,r13,0xa' in text and 'or_s\tr0,r0,r13' in text
assert ';0x2d62d8' in windows[2] and 'st_s\tr0,[r2,0x30]' in windows[2]
assert ';0x2d62b0' in windows[3] and ';0x2b7190' in windows[3]
assert 'not_s' in windows[4] and 'jl_s' in windows[4]
pools = {hex(a): hex(u32(a)) for a in (0x2d62b8, 0x2d62c8, 0x2d62e0, 0x2d62f0, 0x2b7234)}
assert list(pools.values()) == ['0xfe7021c', '0xfe70220', '0xfe70224', '0xfe70228', '0x5545f8']
assert 0xfe31b188 & 0x80
out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('input_registers_%Y%m%dT%H%M%SZ')
out.mkdir(parents=True, exist_ok=False)
(out / 'gnu_windows.txt').write_text('\n'.join(windows))
(out / 'evidence.json').write_text(json.dumps({'status': 'PASS_STATIC_BOUNDED', 'pools': pools,
    'dump_sha256': hashlib.sha256(dump).hexdigest(),
    'limits': ['Static branch and callback registration conditions must hold.',
               'No MMIO values or physical button identity are observed.',
               'MMIO bit behavior and runtime sampling are not verified.']}, indent=2) + '\n')
(out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
print('PASS: monitored and snapshot registers;', out)
