#!/usr/bin/env python3
"""Check bounded S33 V1.1 graphic lookup and descriptor preparation offline."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import disasm, locate, raw, u32


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    windows = [(0x23b19c, 0x23b1a8), (0x23b20c, 0x23b234),
               (0x23b234, 0x23b31e), (0x23b4ec, 0x23b514),
               (0x23b530, 0x23b59c)]
    text = {}
    for start, end in windows:
        block, offset = locate(start, end - start)
        assert raw(start, end - start) == dump[block['offset'] + offset:block['offset'] + offset + end - start]
        text[start] = disasm(start, end)
    needles = {
        0x23b19c: ['0x23b4d0', 'st_s\tr0,[r2,0]', 'stw_s\tr1,[r2,0x4]'],
        0x23b20c: ['add2_s\tr2,r2,r0', 'ld_s\tr3,[r2,0]', 'ldw_s.x\tr2,[r13,0x4]', 'blt_s'],
        0x23b234: ['ldb_s\tr3,[r0,0x8]', 'cmp_s\tr3,0x1', 'ld_s\tr1,[r3,0x14]',
                   'ld_s\tr1,[r3,0x18]', 'muldw', 'ldb.ab\tr3,[r13,1]',
                   'lsr_s\tr1,r3', 'btst_s\tr3,0', 'stb.ab\tr3,[r2,1]',
                   'st\tr4,[r0,16]', 'stb_s\tr1,[r0,0x8]', 'cmp\tr3,128'],
        0x23b4ec: ['mov_s\tr2,0x14', '0xad920', 'ldb_s\tr0,[sp,0xc]', '0x23b234'],
        0x23b530: ['ldw_s.x\tr1,[r14,0]', 'ldw_s.x\tr1,[r14,0x2]', 'jl_s.d\t[r15]'],
    }
    for start, values in needles.items():
        for value in values:
            assert value in text[start], (hex(start), value)
    assert text[0x23b20c].index('ld_s\tr3,[r2,0]') < text[0x23b20c].index('ldw_s.x\tr2,[r13,0x4]')
    for address, length in ((0x23b4d0, 4), (0x36a5e0, 28)):
        block, offset = locate(address, length)
        assert raw(address, length) == dump[block['offset'] + offset:block['offset'] + offset + length]
    assert u32(0x23b4d0) == 0x36a5e0
    initial = [u32(0x36a5e0 + i) for i in range(0, 28, 4)]
    assert initial == [0, 0, 0x2c8380, 0, 0, 0, 0]
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('graphic_descriptor_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'disassembly.txt').write_text('\n'.join(text.values()))
    (out / 'evidence.json').write_text(json.dumps({
        'status': 'PASS_STATIC_BOUNDED', 'dump_sha256': hashlib.sha256(dump).hexdigest(),
        'context': '0x36a5e0', 'initial_words': [hex(x) for x in initial],
        'limits': ['Static code and initial payload only, not initialized RAM or hardware.',
                   'Table and input descriptors unknown; decoder loop and actual pixels not executed.']
    }, indent=2) + '\n')
    (out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    print('PASS: bounded lookup, initializer, descriptor preparation and initial context;', out)


if __name__ == '__main__':
    main()
