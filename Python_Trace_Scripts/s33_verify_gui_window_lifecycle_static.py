#!/usr/bin/env python3
"""Verify bounded WindowManager lifecycle flow against V1.1 MainCode bytes."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import raw, u32, locate, disasm
from catalog_hiddenmenu import parse_lines

def main():
    dump=(ROOT/'DUMPS/MainCode.dmp').read_bytes(); spans=[]; listings=[]; rows={}
    windows=[(0x14503c,0x14504a),(0x14507c,0x145098),(0x14510c,0x145150),
             (0x145180,0x1451b8),(0x1451b8,0x14520e),(0x14520e,0x14525a),
             (0x14525a,0x1452b4),(0x1452b4,0x145310),(0x145310,0x145350),
             (0x14537c,0x1453e4),(0x1453e4,0x1453f2)]
    def check(a,n):
        block,off=locate(a,n); b=raw(a,n)
        assert b==dump[block['offset']+off:block['offset']+off+n],hex(a)
        spans.append({'address':hex(a),'length':n,'sha256':hashlib.sha256(b).hexdigest()})
    for a,b in windows:
        check(a,b-a); listing=disasm(a,b); listings.append(listing)
        rows.update({r['address']:r for r in parse_lines(listing)})
    check(0x145350,0x2c)
    events=[u32(a) for a in range(0x145350,0x14537c,4)]
    assert events==[0x366e94,0x4409,0x366eb0,0x4403,0x4414,0x4404,0x4406,0x4402,0x4401,0x4415,0x4405]
    checks=[(0x1453e8,'bl_s',';0x14507c'),(0x1453ec,'bl_s',';0x145180'),
            (0x14518c,'beq.d',';0x14539a'),(0x145194,'bl_s',';0x14503c'),
            (0x145196,'btst_s','r0,0'),(0x14519e,'ldb','[r0,39]'),
            (0x1451b0,'ld_s','r14,[r0,0x10]'),(0x1451de,'ld_s','r0,[r0,0x14]'),
            (0x1451f0,'bl.d',';0x169d78'),(0x1451f4,'mov_s','r2,r14'),
            (0x1451fc,'bl_s',';0x14510c'),(0x145202,'ld_s','r1,[sp,0]'),
            (0x1451b4,'ld','r16,[sp,4]'),(0x1451b8,'mov_s','r13,r1'),
            (0x14511a,'cmp','r0,-1'),(0x14512c,'btst_s','r0,0x9'),
            (0x145130,'st_s','r13,[r14,0]'),(0x145132,'st_s','r2,[r3,0]'),
            (0x145138,'bl_s',';0x14507c'),(0x14513c,'asr_s','r15,r15,0x10'),
            (0x145254,'bl.d',';0x169d78'),(0x14525a,'cmp','r0,-1'),
            (0x145264,'bl.d',';0x169d78'),(0x145284,'bl.d',';0x169d78'),
            (0x1452e4,'bl.d',';0x169d78'),(0x1452e8,'mov_s','r2,r16'),
            (0x1452ee,'st_s','r13,[r0,0x10]'),(0x145310,'bl.d',';0x169d78'),
            (0x145314,'mov_s','r2,r15'),(0x14531c,'bl_s',';0x14510c'),
            (0x145326,'bl.d',';0x169d78'),(0x145330,'bl.d',';0x169d78'),
            (0x145338,'st_s','r15,[r0,0x10]'),(0x14534c,'st_s','r14,[r0,0x14]'),
            (0x14538a,'st_s','r13,[r0,0x14]')]
    for pc,op,arg in checks:
        assert rows[pc]['op']==op and arg in rows[pc]['args'],(hex(pc),rows.get(pc))
    out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('window_lifecycle_static_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False)
    (out/'gnu_windows.txt').write_text('\n'.join(listings)); (out/'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    (out/'evidence.json').write_text(json.dumps({'status':'PASS_STATIC','date':'2026-10-28','maincode_sha256':hashlib.sha256(dump).hexdigest(),'spans':spans,'assertions':len(checks),'literal_words':[hex(e) for e in events], 'limits':['Static original V1.1 instructions, not execution or proof of runtime ordering.','No universal menu stack, actual display, current state, callbacks, concurrency or hardware established.']},indent=2)+'\n')
    print('PASS',out)
if __name__=='__main__': main()
