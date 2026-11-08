#!/usr/bin/env python3
"""Verify bounded original V1.1 GeneralSetup and sound-menu paths."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import raw, u16, u32, cstring, locate, disasm
from catalog_hiddenmenu import parse_lines


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    spans = []
    def check(addr, length):
        block, off = locate(addr, length)
        data = raw(addr, length)
        assert dump[block['offset'] + off:block['offset'] + off + length] == data, hex(addr)
        spans.append({'address': hex(addr), 'length': length, 'sha256': hashlib.sha256(data).hexdigest()})
    objects = [(0xb7, 0x99242c, 'GeneralSetupMenu', 0x7ea958, 0x7ea988,
                [(0x4401,0x7ea990),(0x4405,0x7ea9ac),(0x4406,0x7eaa6c),(0x600,0x7eaa80),(0x480,0x7eaab0),(0x580,0x7eaad8),(0x700,0x7eab18),(0x2180,0x7eab48),(0x2700,0x7eab70),(0,0x20e814)]),
               (0xbd, 0x9a0a44, 'SoundSettingMenu', 0x808fec, 0x80901c,
                [(0x4405,0x809024),(0x4406,0x8090b0),(0x580,0x8090c4),(0x700,0x8090e4),(0x2180,0x809110),(0x2700,0x80913c),(0,0x20e814)]),
               (0xc3, 0x9a0b3c, 'SoundOnOffMenu', 0x80915c, 0x80918c,
                [(0x4401,0x809194),(0x4405,0x8091b0),(0x4406,0x80925c),(0x580,0x809270),(0x700,0x809290),(0x2180,0x8092e0),(0x2700,0x809334),(0,0x20e814)])]
    for ident, obj, name, entry, pool, events in objects:
        ptr = 0x3f5900 + ident * 4
        check(ptr, 4); assert u32(ptr) == obj
        check(obj, 24); assert u16(obj + 4) == ident and u32(obj + 12) == entry
        s = u32(obj + 20); check(s, len(name)+1); assert cstring(s) == name
        check(pool, 8); table = u32(pool+4); check(table, 8*len(events))
        assert [(u32(table+i*8), u32(table+i*8+4)) for i in range(len(events))] == events
    for ident, expected in [(0x78,'SetupMenu'),(0x93,'SoundSetting')]:
        ptr=0x3f5900+ident*4; check(ptr,4); obj=u32(ptr); check(obj,24)
        s=u32(obj+20); check(s,len(expected)+1); assert cstring(s)==expected
    for ptr,value in [(0x7ea9a8,0x89a04c),(0x8091ac,0x89a70c),
                      (0xd2448,0xc8ec6b),(0xcbcdc,0xc8eab7),
                      (0xcbd50,0xc8eab5),(0xce4d0,0xc8eaf0)]:
        check(ptr,4); assert u32(ptr)==value
    windows=[(0x7c8e90,0x7c8f00),(0x7eab18,0x7eab48),
             (0x7eab70,0x7eaba0),(0x8090c4,0x8090e4),
             (0x8090e4,0x809110),(0x809110,0x80913c),
             (0x809270,0x809290),(0x809290,0x8092e0),
             (0x8092e0,0x809334),(0xd2468,0xd2470),
             (0xcbcc4,0xcbcdc),(0xcbd38,0xcbd50),
             (0xcbdf8,0xcbe00),(0xce4d4,0xce4ec),(0x176d64,0x176da0)]
    rows = {}; listings=[]
    for a,b in windows:
        check(a,b-a); listing=disasm(a,b); listings.append(listing)
        rows.update({r['address']:r for r in parse_lines(listing)})
    for pc,op,arg in [(0x7c8eb4,'mov_s','0xb7'),(0x7c8eb8,'bl',';0x1453e4'),
                      (0x7eab36,'mov_s','0x5f'),(0x7eab3c,'mov_s','0xbd'),
                      (0x7eab8e,'mov_s','0x78'),(0x7eab98,'bl',';0x1453e4'),
                      (0x8090f8,'bl',';0xd2468'),(0x809100,'mov_s','0xc3'),
                      (0x809104,'mov_s','0x93'),(0x809108,'bl',';0x1453e4'),
                      (0x80912c,'mov_s','0xc3'),(0x809130,'mov_s','0x93'),
                      (0x8092b8,'bl',';0xcbcc4'),(0x8092c4,'bl',';0xcbd38'),
                      (0x8092ca,'bl',';0xce4d4'),(0x8092ce,'bl',';0xcbdf8'),
                      (0x8092d2,'bl',';0x176d64'),(0x8092da,'bl',';0x1453e4'),
                      (0x809308,'bl',';0xcbcc4'),(0x809314,'bl',';0xcbd38'),
                      (0x80931c,'bl',';0xce4d4'),(0x809320,'bl',';0xcbdf8'),
                      (0x809324,'bl',';0x176d64'),(0xcbcce,'stb_s','r0,[r1,0]'),
                      (0xcbd42,'stb_s','r0,[r1,0]'),(0xce4e0,'stb_s','r0,[r1,0]')]:
        assert rows[pc]['op']==op and arg in rows[pc]['args'], (hex(pc),rows[pc])
    out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('settings_sound_static_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False)
    (out/'gnu_verified.txt').write_text('\n'.join(listings))
    (out/'verified_evidence.json').write_text(json.dumps({'status':'PASS_STATIC', 'date':'2026-10-27',
        'maincode_sha256':hashlib.sha256(dump).hexdigest(),'spans':spans,
        'limitations':['Static V1.1 bytes and conditional calls only.',
        'No event delivery, runtime ordering, rendering, hardware or persistence demonstrated.']},indent=2)+'\n')
    (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
    print('PASS static settings and sound:',out)

if __name__ == '__main__': main()
