#!/usr/bin/env python3
"""Check bounded static V1.1 EVMenu event and setter paths against original bytes."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import disasm, locate, raw, u16, u32
from catalog_hiddenmenu import parse_lines


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    spans = []
    def check(address, size):
        block, offset = locate(address, size)
        data = raw(address, size)
        assert data == dump[block['offset'] + offset:block['offset'] + offset + size], hex(address)
        spans.append({'address': hex(address), 'size': size, 'sha256': hashlib.sha256(data).hexdigest()})
    for a, n in ((0x980598, 72), (0x7c7bb0, 4), (0x7c7bcc, 4), (0x7c7e24, 4), (0xcc74c, 4),
                 (0x3788b0, 10), (0xce208, 4), (0x131718, 5), (0x17e368, 4),
                 (0x1fce60, 4), (0xd1150, 4), (0x191b7c, 4)):
        check(a, n)
    events = [(u32(0x980598 + i * 8), u32(0x98059c + i * 8)) for i in range(9)]
    assert events == [(0x4401, 0x7c7bb4), (0x4405, 0x7c7bd0), (0x4406, 0x7c7e50),
                      (0x480, 0x7c7ef8), (0x500, 0x7c7f70), (0x580, 0x7c7fec),
                      (0x2180, 0x7c800c), (0x2700, 0x7c8090), (0, 0x20e814)]
    assert u32(0x7c7bb0) == 0x980598
    assert u32(0x7c7bcc) == u32(0x7c7e24) == 0x8997c4
    assert u32(0xcc74c) == 0x3788b0
    exposure = list(struct.unpack('<5h', raw(0x3788b0, 10)))
    assert exposure == [2000, 1000, 0, -1000, -2000]
    assert [u32(a) for a in (0xce208, 0x17e368, 0x1fce60, 0xd1150, 0x191b7c)] == [0xc8ec52, 0x367c06, 0x3695ce, 0xc8eb5a, 0x3681dc]
    assert raw(0x131718, 5) == bytes([3, 7, 9, 11, 13])
    windows = [(0x7c7b7c, 0x7c7baa), (0x7c7bb4, 0x7c7bcc), (0x7c7ef8, 0x7c7f70), (0x7c7f70, 0x7c7fec),
               (0x7c8104, 0x7c8150), (0x7c8150, 0x7c8190), (0x7c8190, 0x7c81fe),
               (0xcc730, 0xcc74c), (0xcc7dc, 0xcc80a), (0xce1ec, 0xce208),
               (0x1316f8, 0x131718), (0x13171e, 0x13173a), (0x17e36c, 0x17e388),
               (0x1fce58, 0x1fce60), (0xd1138, 0xd1148), (0xd1154, 0xd115a),
               (0x191b58, 0x191b70)]
    rows = {}; listings = []
    for a, b in windows:
        check(a, b-a)
        text = disasm(a, b); listings.append(text)
        rows.update({r['address']: r for r in parse_lines(text)})
    assertions = [
        (0x7c7b9a, 'bl', ';0x169f60'),
        (0x7c7bbe, 'st_s', 'r2,[r3,0]'),
        (0x7c7f24, 'stw_s', 'r1,[r13,0x8]'), (0x7c7f28, 'bl', ';0x7c8104'),
        (0x7c7f40, 'stw_s', 'r1,[r13,0xc]'), (0x7c7f44, 'bl', ';0x7c8150'),
        (0x7c7f50, 'mov_s', 'r1,0xd'), (0x7c7f54, 'bl', ';0x3341e4'),
        (0x7c7f5a, 'stw_s', 'r1,[r13,0x10]'), (0x7c7f60, 'bl', ';0x7c8190'),
        (0x7c7f9a, 'mov_s', 'r1,0x4'), (0x7c7fb6, 'mov_s', 'r1,0x4'),
        (0x7c7fcc, 'mov_s', 'r1,0xc'), (0x7c7fd4, 'stw_s', 'r1,[r0,0x10]'),
        (0x7c8118, 'bl', ';0xcc7dc'), (0x7c811c, 'bl', ';0xce1ec'),
        (0xcc73a, 'mov_s', 'r0,0x5'), (0xcc7f0, 'cmp_s', 'r2,0'),
        (0xcc800, 'ldh.as.x', 'r1,[r0,r2]'), (0xce1fc, 'stw_s', 'r13,[r0,0]'),
        (0x7c8166, 'bl', ';0x1316f8'), (0x13170a, 'add', 'r12,pcl,0x10'),
        (0x13170e, 'ldb.x', 'r11,[r12,r13]'), (0x131712, 'add1', 'r12,r12,r11'),
        (0x13171e, 'mov_s', 'r0,0xa'), (0x131726, 'mov_s', 'r0,0x6'),
        (0x13172a, 'mov_s', 'r0,0'), (0x13172e, 'mov_s', 'r0,0x5'),
        (0x131732, 'mov_s', 'r0,0x9'), (0x131720, 'bl', ';0x17e36c'),
        (0x131736, 'bl', ';0x1fce58'), (0x17e384, 'stb_s', 'r14,[r0,0]'),
        (0x1fce5a, 'mov_s', 'r1,0x1'), (0x1fce5c, 'stb_s', 'r1,[r0,0]'),
        (0x7c81d2, 'extb_s', 'r0,r14'), (0x7c81d4, 'bl', ';0xd1138'),
        (0x7c81dc, 'bl', ';0x1421ac'), (0x7c81e0, 'bl', ';0xd1154'),
        (0xd1142, 'stb_s', 'r0,[r1,0]'), (0xd1158, 'ldb_s', 'r0,[r0,0]'),
        (0x7c81e4, 'cmp_s', 'r0,0'), (0x7c81ec, 'add_s', 'r0,r0,0x1'),
        (0x7c81ee, 'bl', ';0x191b58'), (0x7c81f8, 'mov_s', 'r0,0'),
        (0x7c81fa, 'bl', ';0x191b58'), (0x191b68, 'st_s', 'r13,[r0,0]')]
    for pc, op, arg in assertions:
        assert rows[pc]['op'] == op and arg in rows[pc]['args'], (hex(pc), rows.get(pc))
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('evmenu_values_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'disassembly.txt').write_text('\n'.join(listings))
    (out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    (out / 'evidence.json').write_text(json.dumps({
        'status': 'PASS_STATIC_BOUNDED', 'dump_sha256': hashlib.sha256(dump).hexdigest(),
        'spans': spans, 'events': [[hex(a), hex(b)] for a, b in events],
        'mode_0_table_signed': exposure, 'mode_1_indices_0_to_4': [10, 6, 0, 5, 9],
        'state_base': '0x8997c4', 'checked_instructions': len(assertions),
        'limits': ['Mode is conditional on event delivery and argument preservation.',
                   'Helper 0x3341e4 is not semantically verified; no claim about mode 2 increment wrap.',
                   'No runtime, ISP pixel effects, storage persistence or physical key events established.']
    }, indent=2) + '\n')
    print('PASS static EVMenu values:', out)


if __name__ == '__main__':
    main()
