#!/usr/bin/env python3
"""Verify bounded V1.1 CaptureMenu resource resolution against MainCode."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import disasm, locate, raw, u16, u32


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()

    def check(addr, length):
        block, offset = locate(addr, length)
        data = raw(addr, length)
        assert data == dump[block['offset'] + offset:block['offset'] + offset + length], hex(addr)
        return data

    windows = [(0x6316bc, 0x63176e), (0x631f44, 0x631fac),
               (0x6322fa, 0x632368), (0x632370, 0x63241e),
               (0x632518, 0x63255a), (0x6337c4, 0x6337f0),
               (0x1286c4, 0x1286fc), (0x26e3c0, 0x26e3e8),
               (0x23b20c, 0x23b234), (0x26e338, 0x26e3c0)]
    texts = {}
    for start, end in windows:
        check(start, end - start)
        texts[start] = disasm(start, end)
    needles = {
        0x6316bc: ['btst_s\tr0,0x2', 'btst_s\tr0,0', '0x631f44'],
        0x631f44: ['ldh.aw.x\tr16,[r13,r0]', 'ldw_s.x\tr14,[r13,0x6]'],
        0x6322fa: ['btst_s\tr0,0x1', '0xd0a84', 'cmp\tr0,606',
                   'mov\tr16,607', 'ldh.x\tr16,[r13,2]', 'ldh.x\tr16,[r13,4]'],
        0x632370: ['cmp\tr2,606', 'mov\tr16,607', 'ldh.x\tr16,[r13,2]',
                   'mov.f\tr2,r16', '0x26e3c0'],
        0x632518: ['ld\tr4,[fp,-40]', '0x186d08'],
        0x6337c4: ['cmp\tr1,381', '0x1286c4'],
        0x1286c4: ['cmp\tr2,381', 'ld.as\tr1,[r0,r2]', 'add_s\tr0,r1,r12'],
        0x26e3c0: ['0x23b230', '0x26e338'],
        0x23b20c: ['add2_s\tr2,r2,r0', 'ld_s\tr3,[r2,0]', 'ldw_s.x\tr2,[r13,0x4]'],
        0x26e338: ['0x23b5c8'],
    }
    for start, phrases in needles.items():
        for phrase in phrases:
            assert phrase in texts[start], (hex(start), phrase)
    assert [u32(a) for a in (0x1286fc, 0x128700, 0x23b4d0)] == [0x43e174, 0x43e768, 0x36a5e0]
    for a in (0x1286fc, 0x128700, 0x23b4d0):
        check(a, 4)
    check(0x77f66c, 8)
    assert (u32(0x77f66c), u32(0x77f670)) == (0x4409, 0x6316bc)
    # +12 is resolved into the value saved at fp-40 before the call to 0x186d08.
    check(0x63200a, 12)
    extra = disasm(0x63200a, 0x632016)
    assert all(s in extra for s in ('ld_s\tr0,[r13,0xc]', '0x6337c4', 'st\tr0,[fp,-40]'))
    rows = []
    for table, count in ((0x98016c, 3), (0x9801f8, 4)):
        check(table, count * 28)
        for i in range(count):
            address = table + 28 * i
            triple = [u16(address + j) for j in (0, 2, 4)]
            text_id = u32(address + 12)
            assert 0 < text_id < 381
            rows.append({'record': hex(address), 'graphic_fields': triple,
                         'lookup_id_at_12': text_id, 'initial_flags': hex(u32(address + 24))})
    assert [r['graphic_fields'] for r in rows] == [[606,606,606], [284,285,284],
        [806,807,806], [606,606,606], [633,634,633], [413,414,413], [222,223,222]]
    assert [r['lookup_id_at_12'] for r in rows] == [59,91,92,60,61,1,26]
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('capture_resource_resolution_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'disassembly.txt').write_text('\n'.join(texts.values()) + '\n' + extra)
    (out / 'evidence.json').write_text(json.dumps({
        'status': 'PASS_STATIC_BOUNDED', 'dump_sha256': hashlib.sha256(dump).hexdigest(),
        'items': rows, 'lookup_table_runtime': '0x43e174', 'lookup_base_runtime': '0x43e768',
        'graphic_context_runtime': '0x36a5e0',
        'limits': ['Static code and original table only; runtime activation and initialisation unverified.',
                   'Resource table contents, actual labels, graphic output, and physical display not observed.']
    }, indent=2) + '\n')
    (out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    print('PASS: 7 records and bounded static graphic/resource lookup paths;', out)


if __name__ == '__main__':
    main()
