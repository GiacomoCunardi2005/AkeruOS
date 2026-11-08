#!/usr/bin/env python3
"""Verify bounded V1.1 class-15 paging and original CaptureMenu geometries."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import disasm, locate, raw, u16, u32
from catalog_hiddenmenu import parse_lines


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    spans = []
    def check(addr, size):
        block, offset = locate(addr, size)
        data = raw(addr, size)
        assert data == dump[block['offset'] + offset:block['offset'] + offset + size], hex(addr)
        spans.append({'address': hex(addr), 'size': size, 'sha256': hashlib.sha256(data).hexdigest()})
        return data

    windows = [(0x631674, 0x6316b6), (0x631878, 0x631950),
               (0x63195c, 0x631a36), (0x631a38, 0x631b12),
               (0x631b14, 0x631bf0), (0x631bf0, 0x631c78),
               (0x631c80, 0x631c9e), (0x631ca0, 0x631d38),
               (0x631d40, 0x631d5e), (0x632664, 0x632694),
               (0x3341e4, 0x3342ca)]
    lines, texts = {}, []
    for start, end in windows:
        check(start, end-start)
        text = disasm(start, end)
        texts.append(text)
        lines.update({row['address']: row for row in parse_lines(text)})
    checks = [
        (0x63168c,'stb_s','r13,[r14,0x3]'),
        (0x631c06,'bl',';0x1450d8'), (0x631c0a,'and','r0,r0,0x10'), (0x631c14,'bne_s',';0x631c36'),
        (0x631c1e,'mov_s','r0,r13'), (0x631c20,'bl',';0x632664'),
        (0x631c24,'cmp_s','r0,0x1'), (0x631c26,'ble_s',';0x631c36'), (0x631c32,'stb_s','r0,[r1,0x3]'),
        (0x631c3e,'stb_s','r0,[r1,0x3]'), (0x631c42,'bl',';0x145490'),
        (0x631c4e,'and','r0,r0,512'), (0x631c66,'bl',';0x169d78'),
        (0x631c96,'bl',';0x1450d8'), (0x631c9a,'mov_s','r0,0'),
        (0x631cb8,'bl',';0x1450d8'), (0x631cbc,'and','r0,r0,0x20'), (0x631cc4,'beq_s',';0x631cca'),
        (0x631cce,'add','r5,r0,0x1'), (0x631cd2,'ldb','r0,[r14,46]'),
        (0x631cd8,'bl',';0x3342a8'), (0x631cdc,'ldb','r13,[r14,47]'),
        (0x631ce2,'ldb','r0,[r14,52]'), (0x631cea,'blt_s',';0x631d00'), (0x631cee,'bl',';0x632664'),
        (0x631cfc,'stb_s','r1,[r0,0x3]'), (0x631d02,'stb','r5,[r1,3]'),
        (0x631d08,'bl',';0x145490'), (0x631d14,'and','r0,r0,512'),
        (0x631d2c,'bl',';0x169d78'), (0x631d56,'bl',';0x1450d8'),
        (0x631d5a,'mov_s','r0,0'), (0x632672,'ldb','r1,[r13,47]'),
        (0x632676,'ldb','r0,[r0,52]'), (0x63267a,'sub_s','r0,r0,r1'),
        (0x63267c,'ldb','r1,[r13,46]'), (0x632680,'bl',';0x3341e4'),
        (0x632686,'cmp_s','r1,0'), (0x632688,'beq_s',';0x63268e'), (0x63268a,'add_s','r0,r0,0x1'),
        (0x33421c,'asl.f','r0,r0'), (0x334224,'sub.f','0,r1,r2'),
        (0x3342b4,'muludw','r0,r2'), (0x3342bc,'muludw','r0,r1'),
        (0x631896,'ldb','r0,[r0,47]'), (0x63189c,'bne_s',';0x6318b4'), (0x6318ac,'muludw','r0,r2'),
        (0x6318e6,'bl',';0x631e00'), (0x63193c,'bl',';0x1453e4'),
        (0x631980,'bgt_s',';0x63199e'), (0x63199e,'mov_s','r14,0x1'), (0x631a5c,'bgt_s',';0x631a7a'), (0x631a7a,'mov_s','r14,0x2'),
        (0x631b38,'bgt_s',';0x631b56'), (0x631b56,'mov_s','r14,0x3'),
        (0x6319d2,'bl',';0x631e00'), (0x631aae,'bl',';0x631e00'),
        (0x631b8a,'bl',';0x631e00'),
    ]
    for address, op, fragment in checks:
        row = lines[address]
        assert row['op'] == op and fragment in row['args'], (hex(address), row)
    for addr, value in [(0x6316b8,0x681b68),(0x631860,0x681b68),
                        (0x631950,0x681b6b),(0x631c78,0x681b68),
                        (0x631d38,0x681b68),(0x632660,0x681b6b)]:
        check(addr,4)
        assert u32(addr) == value
    check(0x77f664,0x60)
    events = [(u32(a),u32(a+4)) for a in range(0x77f664,0x77f6c4,8)]
    expected = [(0x4401,0x631674),(0x380,0x631bf0),(0x381,0x631c80),
                (0x400,0x631ca0),(0x401,0x631d40),(0x580,0x631878),
                (0x700,0x63195c),(0x2180,0x631a38),(0x2700,0x631b14)]
    assert all(pair in events for pair in expected)
    geometries = []
    for resource, ident, size, fixed, total in [(0x9801c0,0x4800,3,1,3), (0x980268,0x4801,4,0,4)]:
        d = check(resource,56)
        assert (u16(resource+4),u16(resource+6),d[46],d[47],d[52]) == (ident,0x15,size,fixed,total)
        check(u32(resource+48),28*total)
        pages, rem = divmod(total-fixed,size)
        pages += bool(rem)
        assert pages == 1 and fixed + size >= total
        geometries.append({'resource':hex(resource),'id':hex(ident),'page_size_byte_46':size,
                           'fixed_prefix_byte_47':fixed,'count_byte_52':total,'pages':pages,
                           'page_zero_slot_indices':[i if fixed > i else i for i in range(4)],
                           'accepted_slot_indices':[i for i in range(4) if i < total]})
    out = ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('class15_paging_static_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False)
    (out/'disassembly.txt').write_text('\n'.join(texts))
    (out/'evidence.json').write_text(json.dumps({'status':'PASS_STATIC_BOUNDED',
        'dump_sha256':hashlib.sha256(dump).hexdigest(),'checked_spans':spans,
        'events':[[hex(a),hex(b)] for a,b in events],'geometries':geometries,
        'limits':['Static inference for original resource bytes and page zero; runtime mutations and event delivery unobserved.',
                  'No simulator, queue, renderer, physical keys or hardware executed.']},indent=2)+'\n')
    (out/'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    print('PASS static class-15 paging and CaptureMenu original geometries:',out)


if __name__ == '__main__':
    main()
