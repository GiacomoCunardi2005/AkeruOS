#!/usr/bin/env python3
"""Verify the bounded ChangeColorMenu resource route to CaptureMenu(2, 5)."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import raw, u16, u32, locate, disasm, cstring
from catalog_hiddenmenu import parse_lines


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    spans = []
    def check(address, size):
        block, offset = locate(address, size)
        data = raw(address, size)
        assert data == dump[block['offset'] + offset:block['offset'] + offset + size], hex(address)
        spans.append({'address': hex(address), 'size': size, 'sha256': hashlib.sha256(data).hexdigest()})

    for addr, size in [(0x3f5908,4),(0x3f5bec,4),(0x9802ac,24),(0x982064,24),
                       (0x9820ac,16),(0x89983c,8),(0x98202c,56),(0x981fbc,112),
                       (0x7cad38,8),(0x982084,16),(0x982094,24),
                       (0x6337b8,4),(0x77f728,88),(0x631670,4),(0x77f664,96)]:
        check(addr, size)
    assert u32(0x3f5908) == 0x9802ac and u16(0x9802b0) == 2
    assert cstring(u32(0x9802c0)) == 'CaptureMenu'
    check(u32(0x9802c0), len('CaptureMenu') + 1)
    assert u32(0x3f5bec) == 0x982064 and u16(0x982068) == 0xbb
    assert u16(0x98206a) == 2 and u32(0x98206c) == 0x89983c
    assert u32(0x982070) == 0x7cad08 and cstring(u32(0x982078)) == 'ChangeColorMenu'
    check(u32(0x982078), len('ChangeColorMenu') + 1)
    assert [u32(0x89983c+i*4) for i in range(2)] == [0x98202c,0x3aba38]
    assert (u16(0x982030), u16(0x982032), u32(0x98205c), raw(0x982060,1)[0]) == (0x4800,0x15,0x981fbc,4)
    assert [u16(0x981fbc+i) for i in (0,2,4)] == [606,606,606]
    assert (u32(0x981fcc),u16(0x981fd0),u32(0x981fd4)) == (5,2,8)
    assert u32(0x7cad38) == 0x982084 and u32(0x7cad3c) == 0x982094
    assert [(u32(0x982094+i*8),u32(0x982098+i*8)) for i in range(3)] == [(0x4405,0x7cad40),(0x4406,0x7cad78),(0,0x20e814)]
    assert u32(0x6337b8) == 0x77f728 and u32(0x77f728+0x15*4) == 0x631610
    assert u32(0x631670) == 0x77f664
    assert (0x580,0x631878) in [(u32(0x77f664+i*8),u32(0x77f668+i*8)) for i in range(12)]
    windows = [(0x7cad08,0x7cad38),(0x7cad40,0x7cad76),
               (0x6337b0,0x6337b8),(0x631610,0x63166c),
               (0x631878,0x631950),(0x169f60,0x169fb4)]
    listings=[]; rows={}
    for a,b in windows:
        check(a,b-a)
        listing=disasm(a,b); listings.append(listing)
        rows.update({row['address']:row for row in parse_lines(listing)})
    for pc,op,arg in [(0x7cad26,'bl',';0x169f60'),(0x7cad5c,'mov_s','r1,0x9'),(0x7cad5e,'asl_s','r1,r1,0xb'),
                      (0x7cad60,'bl',';0x145764'),(0x6318b6,'asl_s','r15,r14,0x3'),(0x6318b8,'sub_s','r15,r15,r14'),
                      (0x6318ba,'asl_s','r15,r15,0x2'),(0x6318c6,'btst_s','r0,0'),
                      (0x6318ca,'btst_s','r0,0x1'),(0x631918,'bl',';0x1450d8'),
                      (0x63191c,'and','r0,r0,0x2'),(0x631928,'ld_s','r1,[r15,0x10]'),
                      (0x63192a,'ldh.x','r16,[r15,20]'),(0x63193c,'bl',';0x1453e4')]:
        assert rows[pc]['op'] == op and arg in rows[pc]['args'], (hex(pc), rows.get(pc))
    out = ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('changecolor_capture_return_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False)
    (out/'disassembly.txt').write_text('\n'.join(listings))
    (out/'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    (out/'evidence.json').write_text(json.dumps({'status':'PASS_STATIC_BOUNDED',
        'maincode_sha256':hashlib.sha256(dump).hexdigest(),'spans':spans,
        'record':{'address':'0x981fbc','resource':'0x98202c','resource_id':'0x4800',
                  'class':'0x15','record_index':0,'argument':5,'target':2,'initial_flags':8},
        'limits':['Original file-backed bytes and candidate address map, not runtime state.',
                  'Event delivery, runtime record selection, flags, service returns, display and hardware not verified.']},indent=2)+'\n')
    print('PASS static ChangeColorMenu return:',out)

if __name__ == '__main__': main()
