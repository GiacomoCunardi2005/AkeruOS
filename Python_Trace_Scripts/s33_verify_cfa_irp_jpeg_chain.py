#!/usr/bin/env python3
"""Check original V1.1 conditional CFA diagnostic and JPEG work chain."""
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
    spans = [(0x126dd8, 0x126e20), (0x15a4ca, 0x15a4f0),
             (0x1e63c0, 0x1e641e), (0x1e6a54, 0x1e6acc),
             (0x1e77c8, 0x1e789c), (0x1e7320, 0x1e7394),
             (0x1e7670, 0x1e7688)]
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
        (0x126de8, 'mov_s', 'r0,0x1'), (0x126dea, 'st', 'r0,[fp,-16]'),
        (0x126dee, 'ld_s', ';0x126e20'), (0x126df0, 'st', 'r13,[fp,-12]'),
        (0x126df4, 'st', 'r0,[fp,-8]'), (0x126e06, 'bl', ';0x15a570'),
        (0x15a4ce, 'ld_s', 'r1,[r0,0x10]'), (0x15a4d6, 'jl_s.d', '[r1]'),
        (0x15a4d8, 'add', 'r0,r13,0x8'), (0x1e77da, 'ld_s', 'r0,[r14,0]'),
        (0x1e77dc, 'cmp_s', 'r0,0x1'), (0x1e77f4, 'ld_s', 'r0,[r14,0x4]'),
        (0x1e77fa, 'st.as', 'r0,[r13,123]'), (0x1e7804, 'bl.d', ';0x1e63c0'),
        (0x1e63d6, 'ld.as', 'r3,[r13,123]'), (0x1e63da, 'ld_s', 'r0,[r3,0x10]'),
        (0x1e63de, 'beq_s', ';0x1e6416'), (0x1e63e0, 'ld_s', 'r0,[r3,0x14]'),
        (0x1e63e4, 'beq_s', ';0x1e6416'), (0x1e781e, 'bne_s', ';0x1e7836'),
        (0x1e7822, 'bl_s', ';0x1e6a54'), (0x1e6a5a, 'bl.d', ';0x13af18'),
        (0x1e6a62, 'beq_s', ';0x1e6acc'), (0x1e6a98, 'ld', 'r16,[r14,16]'),
        (0x1e6ab4, 'bl.d', ';0x28d66c'), (0x1e6ac6, 'bl.d', ';0x28d66c'),
        (0x1e7838, 'bne_s', ';0x1e7850'), (0x1e783c, 'bl_s', ';0x1e6c00'),
        (0x1e7852, 'bne_s', ';0x1e786a'), (0x1e7856, 'bl_s', ';0x1e6ed4'),
        (0x1e786c, 'bne_s', ';0x1e7880'), (0x1e7870, 'bl_s', ';0x1e72e4'),
        (0x1e7320, 'ld.as', 'r2,[r15,123]'), (0x1e738c, 'ld_s', 'r0,[r14,0x10]'),
        (0x1e7390, 'add', 'r20,r0,r1'), (0x1e7678, 'bl.d', ';0x15a7a8'),
        (0x1e767c, 'ld_s', ';0x1e78a0'), (0x1e7882, 'bl_s', ';0x1e7704')]
    for pc, op, arg in checks:
        assert rows[pc]['op'] == op and arg in rows[pc]['args'], rows.get(pc)
    for address, expected in [(0x126e20, 0x1e77c8), (0x1e78a0, 0x22ae2c)]:
        data = raw(address, 4)
        block, offset = locate(address, len(data))
        assert data == dump[block['offset'] + offset:block['offset'] + offset + len(data)]
        assert int.from_bytes(data, 'little') == expected
    out = ROOT / 'Risultati/HiddenMenu_RAW' / ('cfa_irp_jpeg_static_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    out.mkdir(parents=True)
    (out / 'disassembly.txt').write_text('\n'.join(listings))
    (out / 'evidence.json').write_text(json.dumps({'status': 'PASS_STATIC_CONDITIONAL',
        'source_sha256': EXPECTED, 'dump_sha256': sha(dump), 'spans': hashes,
        'checked_instructions': len(checks), 'callback_literals': ['0x1e77c8', '0x22ae2c'],
        'limits': ['Selected instructions and conditional branches, no CPU execution.',
                   'No hardware, actual frame, buffer capacity, CFA purity, successful JPEG or persistence.',
                   'Image processing between CFA dump and JPEG, asynchronous services and indirect calls are not fully analyzed.']}, indent=2) + '\n')
    print(out)


if __name__ == '__main__':
    main()
