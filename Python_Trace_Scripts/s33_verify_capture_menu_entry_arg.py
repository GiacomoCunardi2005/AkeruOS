#!/usr/bin/env python3
"""Verify bounded V1.1 CaptureMenu entry-argument flow in original bytes."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import raw, u32, locate, disasm
from catalog_hiddenmenu import parse_lines


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    spans = []
    def check(addr, size):
        block, off = locate(addr, size)
        data = raw(addr, size)
        assert data == dump[block['offset'] + off:block['offset'] + off + size], hex(addr)
        spans.append({'address': hex(addr), 'length': size, 'sha256': hashlib.sha256(data).hexdigest()})
    for addr, size in [(0x3f5900, 12), (0x9802ac, 24), (0x899858, 12),
                       (0x982384, 48), (0x3e8bb4, 67*8), (0x7cb018, 8),
                       (0x7cb038, 4), (0x7cb1ac, 8), (0x14535c, 4),
                       (0x145370, 4), (0x145378, 4), (0x169ddc, 9),
                       (0x16a138, 4), (0x654328, 8)]: check(addr, size)
    assert [u32(0x3f5900+i*4) for i in range(3)] == [0, 0x7833cc, 0x9802ac]
    assert u32(0x9802ac) == 0x402 and u32(0x9802b8) == 0x7cafe8
    assert [u32(0x899858+i*4) for i in range(3)] == [0x500, 0, 0]
    assert (u32(0x7cb018),u32(0x7cb01c),u32(0x7cb038),u32(0x7cb1ac),u32(0x7cb1b0)) == (0x899858,0x982384,0x899860,0x899858,0x4801)
    assert [u32(a) for a in (0x14535c,0x145370,0x145378)] == [0x4403,0x4401,0x4405]
    events = [(u32(0x982384+i*8),u32(0x982388+i*8)) for i in range(6)]
    assert events == [(0x4401,0x7cb020),(0x4405,0x7cb03c),(0x4406,0x7cb0a4),(0x180,0x7cb0d8),(0x480,0x7cb0f8),(0,0x20e814)]
    common = [(u32(0x3e8bb4+i*8),u32(0x3e8bb8+i*8)) for i in range(67)]
    assert common[-1] == (0,0) and all(e not in (0,0x4403) for e,_ in common[:-1])
    assert raw(0x169ddc,1) == b'\x05' and u32(0x16a138) == 0x16a05c
    windows = [(0x14510c,0x145150),(0x145180,0x1451b8),(0x1451ba,0x14520e),
               (0x1452e0,0x1452ea),(0x145310,0x145316),(0x1453e4,0x1453f4),
               (0x169d78,0x169ddc),(0x169de6,0x169e1c),(0x16a028,0x16a0bc),
               (0x16a6e4,0x16a7a4),(0x169f60,0x169fb4),(0x20e814,0x20e844),
               (0x6542ea,0x654302),(0x7cafe8,0x7cb018),(0x7cb020,0x7cb038),
               (0x7cb03c,0x7cb05c),(0x7cb118,0x7cb1ac)]
    listings=[]; rows={}
    for a,b in windows:
        check(a,b-a); listing=disasm(a,b); listings.append(listing)
        rows.update({row['address']:row for row in parse_lines(listing)})
    assertions=[(0x145190,'mov_s','r16,r1'),(0x1451f0,'bl.d',';0x169d78'),
        (0x1451f4,'mov_s','r2,r14'),(0x1451fc,'bl_s',';0x14510c'),
        (0x1451b4,'ld','r16,[sp,4]'),(0x14513c,'asr_s','r15,r15,0x10'),
        (0x1452e4,'bl.d',';0x169d78'),(0x1452e8,'mov_s','r2,r16'),
        (0x145310,'bl.d',';0x169d78'),(0x145314,'mov_s','r2,r15'),
        (0x169d84,'mov_s','r16,r2'),(0x169dd4,'ldb.x','r0,[r12,r0]'),
        (0x169dd8,'add1_s','r12,r12,r0'),(0x169e14,'jl_s.d','[r3]'),
        (0x169e16,'mov_s','r2,r16'),(0x16a066,'mov_s','r13,r2'),
        (0x16a0b2,'mov_s','r2,r13'),(0x16a0b4,'bl_s',';0x16a028'),
        (0x16a054,'jl_s.d','[r3]'),(0x16a056,'mov_s','r2,r16'),
        (0x6542f6,'mov_s','r0,0x2'),(0x6542fc,'mov_s','r1,0'),
        (0x6542fe,'bl',';0x1453e4'),(0x7cb02a,'st_s','r2,[r3,0]'),
        (0x7cb058,'bl',';0x7cb118'),(0x7cb12a,'ld_s','r0,[r14,0x8]'),
        (0x7cb12c,'cmp_s','r0,0x4'),(0x7cb16c,'cmp_s','r0,0x5'),
        (0x7cb15a,'st_s','r0,[r14,0x4]'),(0x7cb196,'st_s','r0,[r14,0x4]')]
    for pc,op,arg in assertions:
        assert rows[pc]['op'] == op and arg in rows[pc]['args'], (hex(pc),rows.get(pc))
    out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('capture_menu_entry_arg_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False)
    (out/'disassembly.txt').write_text('\n'.join(listings))
    (out/'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    (out/'evidence.json').write_text(json.dumps({'status':'PASS_STATIC_ENTRY_ARGUMENT','date':'2026-10-27','maincode_sha256':hashlib.sha256(dump).hexdigest(),'spans':spans,'assertions':len(assertions),'common_table_records_before_terminator':66,'limits':['Original static V1.1 image; initial writable state is not runtime state.','Redirect, hook, event filtering, dynamic modifications and real display are not executed.']},indent=2)+'\n')
    print('PASS static CaptureMenu entry argument:',out)

if __name__ == '__main__': main()
