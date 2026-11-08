#!/usr/bin/env python3
"""Bounded V1.1 RAW marker analysis, compared with the historical MainCode dump."""
from datetime import datetime, timezone
from pathlib import Path
import json, sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import EXPECTED, ORIGINAL, disasm, locate, raw, sha, u32
from catalog_hiddenmenu import parse_lines


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    assert sha(ORIGINAL.read_bytes()) == EXPECTED
    spans = [(0x1b91ec, 0x1b923a), (0xbc698, 0xbc6a0),
             (0x12be64, 0x12be74), (0x28d5bc, 0x28d666),
             (0x28d668, 0x28d66c), (0x35231c, 0x35233c)]
    rows, listings, hashes = {}, [], []
    for start, end in spans:
        data = raw(start, end-start)
        block, off = locate(start, end-start)
        assert data == dump[block['offset'] + off:block['offset'] + off + len(data)]
        hashes.append({'start': hex(start), 'end_exclusive': hex(end), 'sha256': sha(data)})
        if start not in (0x28d668, 0x35231c):
            listing = disasm(start, end)
            listings.append(listing)
            rows.update({r['address']: r for r in parse_lines(listing)})
    checks = [(0x1b91ec,'bl',';0x28d48c'), (0x1b91f0,'cmp_s','r0,0x1'),
      (0x1b91fa,'beq_s',';0x1b9218'), (0x1b91fc,'bl',';0xbc698'),
      (0x1b9204,'bl',';0xbc69c'), (0x1b9210,'mov_s','r1,r16'),
      (0x1b9214,'ld_s','r0,[r0,0x4]'), (0x1b9232,'mov','r4,0x2'),
      (0x1b9236,'bl',';0x28d5bc'), (0xbc698,'b',';0x12be64'),
      (0xbc69c,'b',';0x12be6c'), (0x12be64,'mov_s','r0,0x70'),
      (0x12be66,'bset_s','r0,r0,0xc'), (0x12be6c,'mov_s','r0,0xc5'),
      (0x12be6e,'asl_s','r0,r0,0x4'), (0x28d5c4,'mov_s','r18,r1'),
      (0x28d5ca,'mov_s','r17,r2'), (0x28d5cc,'mov_s','r14,r3'),
      (0x28d5d2,'bl.d',';0x128c20'), (0x28d5d6,'mov_s','r2,0x20'),
      (0x28d5da,'add','r15,r16,r18'), (0x28d620,'cmp_s','r13,0x2'),
      (0x28d62c,'muludw','0,r14,r17'), (0x28d630,'mov','lp_count,0x20'),
      (0x28d63a,'mov','r2,r57'), (0x28d63e,'add_s','r0,r15,r2'),
      (0x28d640,'ldb_s','r3,[r0,0]'), (0x28d642,'ldb_s','r13,[r1,0]'),
      (0x28d644,'bmsk','r14,r3,0'), (0x28d64c,'beq_s',';0x28d656'),
      (0x28d64e,'and','r3,r3,254'), (0x28d652,'add_s','r3,r3,r13'),
      (0x28d654,'stb_s','r3,[r0,0]'), (0x28d656,'add1','r57,r2,r17')]
    for pc, op, arg in checks:
        assert rows[pc]['op'] == op and arg in rows[pc]['args'], rows[pc]
    assert u32(0x28d668) == 0x35231c
    bits = list(raw(0x35231c, 32))
    assert all(b in (0, 1) for b in bits) and len(bits) == 32
    width, height = 4208, 3152
    offsets = [width * height + i * 2 * width for i in range(32)]
    assert offsets[0] == 13263616 and offsets[-1] == 13524512
    assert all(width*height <= x < 2*width*height for x in offsets)
    out = ROOT / 'Risultati/HiddenMenu_RAW' / ('marker_positions_static_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    out.mkdir(parents=True)
    (out/'disassembly.txt').write_text('\n'.join(listings))
    (out/'evidence.json').write_text(json.dumps({
      'status':'PASS_STATIC_CONDITIONAL', 'source_sha256':EXPECTED,
      'dump_sha256':sha(dump), 'spans':hashes, 'checked_instructions':len(checks),
      'conditional_path':'flag getter == 1, context byte +12 != 0x0b, 32-byte copy service succeeds and normal arithmetic/loop semantics',
      'base':'descriptor+4 plus caller r16, assumed no 32-bit wrap',
      'width':width, 'height':height, 'offsets_relative_to_base':offsets,
      'target_lsb_values':bits,
      'ordinary_export_bytes':width*height, 'mode3_export_bytes':2*width*height,
      'limits':['Static analysis, not a CPU or hardware execution.', 'r16, pointer, capacity and concurrent mutation are runtime unknowns.', 'The other +12 == 0x0b branch uses different getters and is not covered.', 'A non-null buffer for writer, real data layout, and reachability are not established.'],
    }, indent=2)+'\n')
    print(out)

if __name__ == '__main__': main()
