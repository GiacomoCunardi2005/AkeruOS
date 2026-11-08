#!/usr/bin/env python3
"""Offline V1.1 checks of the conditional RAW-to-image-buffer connection."""
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
    spans = [(0x65f23c, 0x65f266), (0x1b8f24, 0x1b8f76),
             (0x1b8fc0, 0x1b9024), (0x1b91ec, 0x1b92ce),
             (0x1b9310, 0x1b93c0), (0x18ed60, 0x18ee18),
             (0x18ee50, 0x18ee74), (0x18efc2, 0x18f012),
             (0x1e2924, 0x1e2952), (0x660316, 0x660340)]
    rows, listings, hashes = {}, [], []
    for start, end in spans:
        data = raw(start, end - start)
        block, offset = locate(start, end - start)
        assert data == dump[block['offset'] + offset:block['offset'] + offset + len(data)]
        listing = disasm(start, end)
        listings.append(listing)
        rows.update({row['address']: row for row in parse_lines(listing)})
        hashes.append({'start': hex(start), 'end_exclusive': hex(end), 'sha256': sha(data)})
    checks = [
        (0x65f262, 'bl', ';0x1b9ea8'),
        (0x1b8f38, 'st', 'r1,[fp,-204]'), (0x1b8f56, 'mov', 'r4,0'),
        (0x1b8f72, 'mov', 'r16,r4'), (0x1b8fc4, 'cmp_s', 'r1,0x10'),
        (0x1b8fc6, 'bne_s', ';0x1b8ffc'), (0x1b9002, 'mov_s', 'r2,0'),
        (0x1b9004, 'bl', ';0x18ed60'),
        (0x1b91ec, 'bl', ';0x28d48c'), (0x1b91f0, 'cmp_s', 'r0,0x1'),
        (0x1b9214, 'ld_s', 'r0,[r0,0x4]'), (0x1b9236, 'bl', ';0x28d5bc'),
        (0x1b9252, 'cmp_s', 'r1,0x4'), (0x1b9254, 'bne_s', ';0x1b9292'),
        (0x1b9298, 'beq_s', ';0x1b933a'), (0x1b92a0, 'beq_s', ';0x1b933a'),
        (0x1b932e, 'ld_s', 'r2,[r0,0x4]'), (0x1b9330, 'mov_s', 'r0,r16'),
        (0x1b9336, 'bl', ';0x28d4d4'), (0x1b933a, 'bl', ';0x28d48c'),
        (0x1b93a4, 'cmp_s', 'r1,0x10'), (0x1b93a8, 'cmp_s', 'r1,0x12'),
        (0x1b93ac, 'cmp_s', 'r1,0x11'), (0x1b93b0, 'bl', ';0x18ee50'),
        (0x18ed76, 'mov_s', 'r13,0'), (0x18ed86, 'mov_s', 'r20,r13'),
        (0x18edd2, 'ld', 'r18,[r13,8]'), (0x18ee0e, 'add', 'r1,r18,r20'),
        (0x18ee12, 'st', 'r0,[r17]'), (0x18ee16, 'st_s', 'r1,[r0,0x4]'),
        (0x18ee58, 'ld_s', 'r0,[r13,0x24]'), (0x18ee5e, 'ld_s', 'r1,[r13,0x1c]'),
        (0x18ee64, 'ld_s', 'r0,[r13,0x4]'), (0x18ee66, 'bl_s', ';0x18e9d0'),
        (0x18efd8, 'bl_s', ';0x18e8b4'), (0x18efe6, 'ld_s', 'r0,[r15,0x8]'),
        (0x18efea, 'bl_s', ';0x18e354'), (0x18eff8, 'bl_s', ';0x18e310'),
        (0x18f002, 'st_s', 'r15,[r14,0]'), (0x18f006, 'ld_s', 'r0,[r15,0x4]'),
        (0x18f00c, 'st_s', 'r0,[r14,0x8]'), (0x1e2944, 'cmp_s', 'r1,r0'),
        (0x660336, 'bl', ';0x126d48'),
    ]
    for pc, op, arg in checks:
        assert rows[pc]['op'] == op and arg in rows[pc]['args'], rows[pc]
    out = ROOT / 'Risultati/HiddenMenu_RAW' / ('raw_jpeg_link_static_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    out.mkdir(parents=True)
    (out / 'disassembly.txt').write_text('\n'.join(listings))
    (out / 'evidence.json').write_text(json.dumps({
        'status': 'PASS_STATIC_CONDITIONAL', 'source_sha256': EXPECTED,
        'dump_sha256': sha(dump), 'spans': hashes, 'checked_instructions': len(checks),
        'scope': 'Original V1.1 bytes and selected control/data flow only; no CPU execution.',
        'limits': ['Capture state 0x0a and successful prior services assumed.',
                   'Internal pool, zero offset, unchanged descriptor/queue, and successful later gates assumed.',
                   'Selected instruction checks do not prove exclusive writers, scheduling, same real sensor frame, JPEG output or persistence.',
                   'The marker conditional precedes the writer; its effect on image output is unknown.'],
    }, indent=2) + '\n')
    print(out)


if __name__ == '__main__':
    main()
