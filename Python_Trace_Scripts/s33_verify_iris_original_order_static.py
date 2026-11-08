#!/usr/bin/env python3
"""Check one original V1.1 exposure call order; no camera or firmware writes."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import disasm, locate, raw, u32


def main():
    dump = ROOT / 'DUMPS/MainCode.dmp'
    data = dump.read_bytes()
    spans = [(0xd6aa0, 0xd6abe), (0xd6ef2, 0xd6f02), (0xd6f68, 0xd6f84),
             (0xf72fe, 0xf7306), (0xf7568, 0xf7580), (0xf7844, 0xf7876), (0xf78a4, 0xf78e6)]
    listings = {}
    for start, end in spans:
        block, off = locate(start, end-start)
        assert raw(start, end-start) == data[block['offset']+off:block['offset']+off+end-start]
        listings[hex(start)] = disasm(start, end)
    checks = {
        '0xd6aa0': ['mov_s\tr0,0', 'mov_s\tr13,r0'],
        '0xd6ef2': [';0xf7238', 'mov_s\tr1,0x1', ';0xf7844'],
        '0xd6f68': [';0xf7568', ';0xd4df4', ';0xd755c', 'mov_s\tr1,r13', ';0xf7844'],
        '0xf72fe': [';0xf7540', 'mov_s\tr2,r14', ';0xfda28'],
        '0xf7568': [';0xf7598', ';0xf7540', 'mov_s\tr2,0xf0', 'add3\tr0,r14,0x1e', ';0x128c20'],
        '0xf7844': ['mov_s\tr19,r1', 'cmp\tr19,0', ';0xf7952'],
        '0xf78a4': [';0x11d074', ';0xf78be', 'ldb\tr18,[r1,-225]', ';0x149548', ';0x149598'],
    }
    for key, needles in checks.items():
        pos = -1
        for needle in needles:
            pos = listings[key].find(needle, pos+1)
            assert pos >= 0, (key, needle)
    assert u32(0xf7540) == 0x380754 and u32(0xf7544) == 0x380770 and u32(0xf7598) == 0x380574
    for address, size in [(0xf7540, 8), (0xf7598, 4)]:
        block, off = locate(address, size)
        assert raw(address, size) == data[block['offset']+off:block['offset']+off+size]
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('iris_original_order_static_%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    (out / 'disassembly.txt').write_text('\n'.join(listings.values()))
    (out / 'result.json').write_text(json.dumps({'status': 'PASS', 'sha256_dump': hashlib.sha256(data).hexdigest(), 'spans': [[hex(a), hex(b)] for a,b in spans], 'limits': 'Static path and branch constraints only; no scheduling, intervening service side effects, hardware, or Auto semantics established.'}, indent=2)+'\n')
    print('PASS:', out)


if __name__ == '__main__':
    main()
