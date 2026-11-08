#!/usr/bin/env python3
"""Verify bounded original V1.1 RAW marker/export flag predicates offline."""
from datetime import datetime, timezone
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import EXPECTED, ORIGINAL, disasm, locate, raw, sha, u32
from catalog_hiddenmenu import parse_lines


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    assert sha(ORIGINAL.read_bytes()) == EXPECTED
    windows = [(0x1b91ec, 0x1b923a), (0x1b923a, 0x1b92aa),
               (0x1b9310, 0x1b933a), (0x28d48c, 0x28d4b0),
               (0x7cf7f0, 0x7cf822), (0x14a2d8, 0x14a2e0)]
    rows, listings, spans = {}, [], []
    for start, end in windows:
        data = raw(start, end-start)
        block, offset = locate(start, end-start)
        assert data == dump[block['offset']+offset:block['offset']+offset+len(data)]
        listing = disasm(start, end)
        listings.append(listing)
        rows.update({r['address']:r for r in parse_lines(listing)})
        spans.append(dict(start=hex(start), end_exclusive=hex(end), sha256=sha(data)))
    checks = [(0x1b91ec,'bl',';0x28d48c'), (0x1b91f0,'cmp_s','r0,0x1'),
        (0x1b91f2,'bne_s',';0x1b923a'), (0x1b9236,'bl',';0x28d5bc'),
        (0x1b9292,'bl',';0x28d48c'), (0x1b9296,'cmp_s','r0,0'),
        (0x1b9298,'beq_s',';0x1b933a'), (0x1b929c,'ld_s','r0,[r0,0x4]'),
        (0x1b92a0,'beq_s',';0x1b933a'), (0x1b92a2,'bl',';0x14a2d8'),
        (0x1b92a6,'cmp_s','r0,0x3'), (0x1b92a8,'beq_s',';0x1b9310'),
        (0x1b9328,'add','r3,r57,r57'), (0x1b9336,'bl',';0x28d4d4'),
        (0x28d48e,'ldb_s','r0,[r0,0]'), (0x28d4a4,'stb_s','r0,[r1,0]'),
        (0x7cf7f4,'cmp_s','r0,0'), (0x7cf7f6,'mov_s','r0,0x1'),
        (0x7cf7f8,'sub_s.ne','r0,r0,r0'), (0x7cf7fa,'bl',';0x28d498')]
    for pc, op, operand in checks:
        assert rows[pc]['op'] == op and operand in rows[pc]['args'], rows[pc]
    assert u32(0x28d494) == 0x36c26e
    cases = [dict(flag=f, marker_flag_gate=f == 1, writer_flag_gate=f != 0)
             for f in (0, 1, 2, 255)]
    assert [(x['marker_flag_gate'],x['writer_flag_gate']) for x in cases] == [
        (False,False),(True,True),(False,True),(False,True)]
    out = ROOT / 'Risultati/HiddenMenu_RAW' / datetime.now(timezone.utc).strftime('flag_gate_static_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True)
    (out/'gnu_windows.txt').write_text('\n'.join(listings))
    (out/'evidence.json').write_text(json.dumps(dict(
        status='PASS_STATIC_CONDITIONAL', source_sha256=EXPECTED, dump_sha256=sha(dump),
        source_spans=spans, checked_instructions=len(checks), cases=cases,
        assumptions=['Same unchanged getter value for the two predicates; nonnull descriptor buffer and selector 3 for the 2N writer branch.'],
        limits=['Static only, conditions do not demonstrate reachability or actual execution.',
                'Calls and an indirect callback between the reads may alter state; no concurrency or lifetime analysis.',
                'Flag 2/255 is not produced by the observed menu toggle and may affect other consumers.',
                'Skipping this marker does not prove buffer purity, format, capacity, file persistence, JPEG or hardware safety.']), indent=2)+'\n')
    print(out)


if __name__ == '__main__':
    main()
