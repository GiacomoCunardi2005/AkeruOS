#!/usr/bin/env python3
"""Check the origin of the type-1 video diagnostic buffer in V1.1."""
from datetime import datetime, timezone
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import EXPECTED, ORIGINAL, disasm, locate, raw, sha
from catalog_hiddenmenu import parse_lines


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    assert sha(ORIGINAL.read_bytes()) == EXPECTED
    spans = [(0x163836, 0x16388a), (0x12a71c, 0x12a736),
             (0x1ef8a4, 0x1ef8b6), (0x127b60, 0x127b88),
             (0x127c62, 0x127c72), (0x127d2a, 0x127d42),
             (0x127d82, 0x127de6), (0x13b64c, 0x13b652),
             (0x1e6a96, 0x1e6aba)]
    rows, listings, hashes = {}, [], []
    for start, end in spans:
        data = raw(start, end - start)
        block, offset = locate(start, len(data))
        assert data == dump[block['offset'] + offset:block['offset'] + offset + len(data)]
        listing = disasm(start, end)
        listings.append(listing)
        rows.update({row['address']: row for row in parse_lines(listing)})
        hashes.append({'start': hex(start), 'end_exclusive': hex(end), 'sha256': sha(data)})
    checks = [
        (0x163836, 'mov_s', 'r0,0x6d'), (0x163838, 'sub', 'r1,fp,0x18'),
        (0x16383c, 'sub', 'r2,fp,0x14'), (0x163840, 'bl', ';0x12a71c'),
        (0x163848, 'bne_s', ';0x1638bc'), (0x163878, 'ld', 'r1,[fp,-24]'),
        (0x163886, 'bl', ';0x127b60'), (0x12a72c, 'bl.d', ';0x1ef7f8'),
        (0x1ef8a8, 'ld_s', 'r2,[r0,0xc]'), (0x1ef8aa, 'st', 'r2,[r19]'),
        (0x1ef8ae, 'ld_s', 'r1,[r0,0x10]'), (0x1ef8b2, 'st', 'r1,[r18]'),
        (0x127b74, 'st.as', 'r1,[fp,-172]'), (0x127c64, 'add', 'r0,r0,508'),
        (0x127c68, 'st.as', 'r0,[fp,-167]'), (0x127d2a, 'ld.as', 'r0,[fp,-172]'),
        (0x127d2e, 'add_s', 'r1,r0,0x7'), (0x127d30, 'lsr_s', 'r1,r1,0x3'),
        (0x127d32, 'asl_s', 'r1,r1,0x3'), (0x127d34, 'mov_s', 'r17,r1'),
        (0x127d36, 'add_s', 'r1,r1,0x100007'), (0x127d3c, 'lsr_s', 'r1,r1,0x3'),
        (0x127d3e, 'asl', 'r18,r1,0x3'), (0x127d96, 'ld.as', 'r0,[fp,-167]'),
        (0x127d9e, 'st', 'r18,[fp,-204]'), (0x127da2, 'st', 'r17,[fp,-200]'),
        (0x127da6, 'sub', 'r0,r0,684'), (0x127dd6, 'bl', ';0x13b64c'),
        (0x13b650, 'st_s', 'r0,[r1,0]'), (0x127dda, 'ld.as', 'r0,[fp,-167]'),
        (0x127dde, 'sub', 'r0,r0,728'), (0x127de2, 'bl', ';0x126dd8'),
        (0x1e6a98, 'ld', 'r16,[r14,16]'), (0x1e6ab0, 'mov_s', 'r3,r16'),
        (0x1e6ab4, 'bl.d', ';0x28d66c')]
    for pc, op, arg in checks:
        assert rows[pc]['op'] == op and arg in rows[pc]['args'], rows.get(pc)
    for base in [0, 1, 7, 8, 0x12345678, 0xffeffff0]:
        aligned = (base + 7) & ~7
        assert ((aligned + 0x100007) & ~7) == aligned + 0x100000
    out = ROOT / 'Risultati/HiddenMenu_RAW' / ('cfa_video_source_static_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    out.mkdir(parents=True)
    (out / 'disassembly.txt').write_text('\n'.join(listings))
    (out / 'evidence.json').write_text(json.dumps({'status': 'PASS_STATIC_CONDITIONAL',
        'source_sha256': EXPECTED, 'dump_sha256': sha(dump), 'spans': hashes,
        'checked_instructions': len(checks),
        'limits': ['Selected static instructions only; no CPU, hardware, pixel data or storage.',
                   'Formula assumes no 32-bit overflow and preserved inputs/registers.',
                   'Intervening services and concurrent writers can affect payload; region geometry and runtime contents unknown.']}, indent=2) + '\n')
    print(out)


if __name__ == '__main__':
    main()
