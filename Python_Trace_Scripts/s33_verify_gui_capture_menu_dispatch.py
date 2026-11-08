#!/usr/bin/env python3
"""Verify bounded V1.1 CaptureMenu/ImageMode dispatch against original dump."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import raw, u16, u32, cstring, locate, disasm
from catalog_hiddenmenu import parse_lines


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    checks = []
    def check(a, size):
        block, offset = locate(a, size)
        data = raw(a, size)
        assert dump[block['offset'] + offset:block['offset'] + offset + size] == data, hex(a)
        checks.append({'address': hex(a), 'length': size, 'sha256': hashlib.sha256(data).hexdigest()})
        return data
    descriptors = [(2, 0x9802ac, 'CaptureMenu', 0x7cafe8, 0x899858, 0x982384,
                    [(0x4401, 0x7cb020), (0x4405, 0x7cb03c), (0x4406, 0x7cb0a4),
                     (0x180, 0x7cb0d8), (0x480, 0x7cb0f8), (0, 0x20e814)]),
                   (0x9b, 0x9814b8, 'ImageMode', 0x7c8c6c, 0x8997f0, 0x9814d8,
                    [(0x4405, 0x7c8ca4), (0x4406, 0x7c8e5c), (0x580, 0x7c8e90),
                     (0x700, 0x7c8f04), (0x2180, 0x7c90c4), (0x2700, 0x7c92dc),
                     (0x80, 0x7c936c), (0, 0x20e814)])]
    records = []
    for ident, obj, name, entry, filt, table, events in descriptors:
        check(0x3f5900 + ident * 4, 4); assert u32(0x3f5900 + ident * 4) == obj
        check(obj, 24); assert u16(obj + 4) == ident and u32(obj + 12) == entry
        nameptr = u32(obj + 20); check(nameptr, len(name) + 1); assert cstring(nameptr) == name
        pool = entry + 0x30
        check(pool, 8); assert (u32(pool), u32(pool + 4)) == (filt, table)
        check(filt, 4); check(table, len(events) * 8)
        assert [(u32(table + i*8), u32(table + i*8 + 4)) for i in range(len(events))] == events
        records.append(dict(id=hex(ident), name=name, descriptor=hex(obj), main=hex(entry),
                            filter=hex(filt), initial_filter=raw(filt, 4).hex(),
                            table=hex(table), events=[{'event': hex(e), 'handler': hex(h)} for e,h in events]))
    check(0x20e844, 4); assert u32(0x20e844) == 0x3e8bb4
    default = 0x3e8bb4
    check(default, 20 * 8)
    assert (u32(default + 19*8), u32(default + 19*8 + 4)) == (0x2180, 0x20e940)
    check(0x7cb038, 4); assert u32(0x7cb038) == 0x899860
    check(0x7cb1ac, 8); assert u32(0x7cb1ac) == 0x899858 and u32(0x7cb1b0) == 0x4801
    check(0x7c92c0, 4); check(0x7c9368, 4)
    assert (u32(0x7c92c0), u32(0x7c9368)) == (0x4801, 0x4802)
    check(0x3f5900 + 0xb7 * 4, 4); assert u32(0x3f5900 + 0xb7 * 4) == 0x99242c
    check(0x99242c, 24); nameptr = u32(0x99242c + 20)
    check(nameptr, len('GeneralSetupMenu') + 1); assert cstring(nameptr) == 'GeneralSetupMenu'
    for table, values in [(0x98016c, [0x87, 0x9d, 0x9d]), (0x9801f8, [0x87, 7, 10, 0xbb])]:
        check(table, 28*len(values))
        assert [struct.unpack_from('<h', raw(table + 28*i + 20, 2))[0] for i in range(len(values))] == values
    windows = [(0x14507c,0x145098),(0x1453e4,0x1453f4),(0x169f60,0x169fb4),
               (0x20e814,0x20e844),(0x20e940,0x20ea50),
               (0x7cafe8,0x7cb018),(0x7cb020,0x7cb038),(0x7cb03c,0x7cb0f8),
               (0x7cb0f8,0x7cb118),(0x7cb118,0x7cb1ac),(0x7cb1b4,0x7cb250),
               (0x7cb256,0x7cb2de),(0x7c8c6c,0x7c8c9c),(0x7c8e90,0x7c8f00),
               (0x7c92dc,0x7c9368)]
    text = []; rows = {}
    for a,b in windows:
        check(a,b-a); listing=disasm(a,b); text.append(listing)
        rows.update({row['address']: row for row in parse_lines(listing)})
    for pc, op, arg in [(0x1453e8,'bl_s',';0x14507c'),(0x1453ec,'bl_s',';0x145180'),
                        (0x7cb006,'bl',';0x169f60'),(0x7c8c8a,'bl',';0x169f60'),
                        (0x7cb02a,'st_s','r2,[r3,0]'),(0x7cb076,'bl',';0x7cb1b4'),
                        (0x7cb0f2,'bl',';0x20e814'),(0x7cb112,'bl',';0x20e814'),
                        (0x7cb20e,'ldh.x','r0,[r0,r1]'),(0x7cb212,'cmp','r0,187'),
                        (0x7cb22a,'cmp_s','r0,0xa'),(0x7cb24c,'bl',';0x631e98'),
                        (0x7c8eae,'asl_s','r1,r1,0xb'),(0x7c8eb4,'mov_s','r0,0xb7'),
                        (0x7c8eb6,'mov_s','r1,0x1'),(0x7c8eb8,'bl',';0x1453e4'),(0x7c9324,'bl',';0x1453e4'),
                        (0x7c935e,'bl',';0x1453e4')]:
        assert rows[pc]['op'] == op and arg in rows[pc]['args'], (hex(pc), rows[pc])
    out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('capture_menu_dispatch_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False)
    evidence=dict(status='PASS_STATIC_CAPTURE_MENU_DISPATCH', date='2026-10-27',
                  maincode_sha256=hashlib.sha256(dump).hexdigest(), descriptors=records,
                  checked_spans=checks,
                  limitations=['Static original V1.1 bytes and initial RAM image only; no lifecycle, CPU or real execution.',
                               'Filter lists are writable runtime data; initial image is not runtime state.',
                               'Conditional calls and labels do not prove selection, display, physical input or camera behavior.'])
    (out/'verified_evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
    (out/'gnu_verified.txt').write_text('\n'.join(text))
    (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
    print('PASS static menu dispatch:',out)


if __name__ == '__main__': main()
