#!/usr/bin/env python3
"""Verify selected V1.1 CFA diagnostic path instructions offline."""
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
    spans = [(0x1e6a54, 0x1e6ad2), (0x1e77c8, 0x1e7850),
             (0x28d66c, 0x28d6d8), (0x28d6e6, 0x28d742), (0x28d7f2, 0x28d818)]
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
        (0x1e6a5a, 'bl.d', ';0x13af18'), (0x1e6a62, 'beq_s', ';0x1e6acc'),
        (0x1e6a68, 'ldw_s', 'r0,[r14,0x1c]'), (0x1e6a76, 'ldw_s', 'r0,[r14,0x1e]'),
        (0x1e6a8a, 'cmp_s', 'r15,0x2'), (0x1e6a8e, 'add_s', 'r15,r0,r0'),
        (0x1e6a92, 'add1_s', 'r0,r0,r0'), (0x1e6a94, 'lsr_s', 'r15,r0'),
        (0x1e6a96, 'ld_s', 'r2,[r14,0x4]'), (0x1e6a98, 'ld', 'r16,[r14,16]'),
        (0x1e6aa2, 'bl.d', ';0x28d66c'), (0x1e6aac, 'mov_s', 'r0,0'),
        (0x1e6aae, 'mov_s', 'r1,0x1'), (0x1e6ab0, 'mov_s', 'r3,r16'),
        (0x1e6ab4, 'bl.d', ';0x28d66c'), (0x1e6ab8, 'mov_s', 'r4,r15'),
        (0x1e6abe, 'mov_s', 'r0,0'), (0x1e6ac0, 'mov_s', 'r1,0x2'),
        (0x1e6ac6, 'bl.d', ';0x28d66c'), (0x1e6acc, 'bl', ';0x13b554'),
        (0x1e7804, 'bl.d', ';0x1e63c0'), (0x1e781e, 'bne_s', ';0x1e7836'),
        (0x1e7822, 'bl_s', ';0x1e6a54'), (0x1e783c, 'bl_s', ';0x1e6c00'),
        (0x28d6d0, 'ldh.as.x', 'r15,[r12,r15]'), (0x28d6d4, 'add1_s', 'r12,r12,r15'),
        (0x28d6e6, 'cmp_s', 'r13,0'), (0x28d6fc, 'bl.d', ';0x1378b4'),
        (0x28d7f8, 'bl.d', ';0x12bcc4'), (0x28d802, 'ld', 'r0,[sp,156]'),
        (0x28d806, 'cmp_s', 'r14,r0'), (0x28d80e, 'bl', ';0x12bce4')]
    for pc, op, arg in checks:
        assert rows[pc]['op'] == op and arg in rows[pc]['args'], rows.get(pc)
    table = raw(0x28d6d8, 2)
    assert 0x28d6d8 + 2 * int.from_bytes(table, 'little', signed=True) == 0x28d6e6
    out = ROOT / 'Risultati/HiddenMenu_RAW' / ('cfa_irp_static_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    out.mkdir(parents=True)
    (out / 'disassembly.txt').write_text('\n'.join(listings))
    (out / 'evidence.json').write_text(json.dumps({'status': 'PASS_STATIC_CONDITIONAL',
        'source_sha256': EXPECTED, 'dump_sha256': sha(dump), 'spans': hashes,
        'checked_instructions': len(checks), 'selector0_destination': '0x28d6e6',
        'limits': ['Selected instructions only; no CPU execution or hardware.',
                   'No proof of actual frame, buffer capacity, CFA purity, JPEG or file persistence.',
                   'Dispatcher and downstream behavior conditional on gates and services.']}, indent=2) + '\n')
    print(out)


if __name__ == '__main__':
    main()
