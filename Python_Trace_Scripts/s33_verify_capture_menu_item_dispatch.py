#!/usr/bin/env python3
"""Verify a bounded static route from CaptureMenu items to object-open requests."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import disasm, locate, raw, u16, u32, cstring


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()

    def check(addr, length):
        block, offset = locate(addr, length)
        data = raw(addr, length)
        assert dump[block['offset'] + offset:block['offset'] + offset + length] == data, hex(addr)
        return data

    # These bounded instruction windows contain code only; literal pools checked separately.
    windows = [(0x6337b0, 0x6337b8), (0x145010, 0x145038),
               (0x631610, 0x63166c), (0x169f60, 0x169fb4), (0x631878, 0x631950),
               (0x7cb1b4, 0x7cb2e2), (0x631e98, 0x631ec8)]
    text = {}
    for start, end in windows:
        check(start, end - start)
        text[hex(start)] = disasm(start, end)
    checks = {
        0x6337b0: ['0x6337b8', '0x16', '0x145010'],
        0x145010: ['stw_s\tr1,[r2,0x4]', 'add2_s\tr1,r1,r0', 'ld_s\tr0,[r1,0]'],
        0x631610: ['0x631670', '0x169f60'],
        0x169f60: ['ldw_s.x\tr0,[r14,0]', 'ld_s\tr3,[r14,0x4]', 'jl_s.d\t[r3]'],
        0x631878: ['ldb\tr0,[r0,47]', 'ld_s\tr0,[r13,0x30]', 'btst_s\tr0,0x1',
                    '0x1450d8', 'ld_s\tr1,[r15,0x10]', 'ldh.x\tr16,[r15,20]', '0x1453e4'],
        0x7cb1b4: ['0x4801', 'cmp\tr0,187', '0x4800', '0x631e98'],
        0x631e98: ['ld_s\tr3,[r1,0x18]', 'bset_s\tr3,r3,0x1', 'bclr_s\tr3,r3,0x1'],
    }
    for address, needles in checks.items():
        for needle in needles:
            assert needle in text[hex(address)], (hex(address), needle)
    for addr in (0x6337b8, 0x631670):
        check(addr, 4)
    assert u32(0x6337b8) == 0x77f728
    check(0x77f728, 0x16 * 4)
    assert u32(0x77f728 + 0x15 * 4) == 0x631610
    assert u32(0x631670) == 0x77f664
    check(0x77f664, 0x60)
    events = [(u32(p), u32(p+4)) for p in range(0x77f664, 0x77f6c4, 8)]
    assert events[-1] == (0, 0) and (0x580, 0x631878) in events
    check(0x3f5908, 4)
    assert u32(0x3f5908) == 0x9802ac
    check(0x9802ac, 24)
    assert u16(0x9802b0) == 2 and u16(0x9802b2) == 3 and u32(0x9802b4) == 0x9802a0
    assert cstring(u32(0x9802c0)) == 'CaptureMenu'
    check(0x9802a0, 12)
    assert [u32(0x9802a0 + 4*i) for i in range(3)] == [0x9801c0, 0x980268, 0x3aba38]
    rows = []
    for resource, count in [(0x9801c0, 3), (0x980268, 4)]:
        check(resource, 56)
        kind = u16(resource + 4)
        assert u16(resource + 6) == 0x15 and raw(resource + 52, 1)[0] == count
        ptr = u32(resource + 48)
        check(ptr, count * 28)
        for index in range(count):
            addr = ptr + 28 * index
            arg, target, flags = u32(addr+16), struct.unpack('<h', raw(addr+20, 2))[0], u32(addr+24)
            assert target > 0
            check(0x3f5900 + 4*target, 4)
            desc = u32(0x3f5900 + 4*target)
            check(desc, 24)
            assert u16(desc+4) == target
            nameptr = u32(desc+20)
            name = cstring(nameptr)
            assert name is not None
            check(nameptr, len(name) + 1)
            rows.append({'list': hex(kind), 'index': index, 'record': hex(addr),
                         'icons_halfwords': [u16(addr+i) for i in (0,2,4)],
                         'word12': u32(addr+12), 'argument16': arg, 'target20': hex(target),
                         'target_descriptor': hex(desc), 'target_name': name, 'initial_flags24': hex(flags)})
    assert [(r['target20'], r['argument16']) for r in rows] == [
        ('0x87',0),('0x9d',2),('0x9d',3),('0x87',0),('0x7',0),('0xa',0),('0xbb',0)]
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('capture_menu_dispatch_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    (out/'disassembly.txt').write_text('\n'.join(text.values()))
    (out/'evidence.json').write_text(json.dumps({
        'status':'PASS_STATIC_BOUNDED', 'dump_sha256': hashlib.sha256(dump).hexdigest(),
        'source':'Nikon S33 V1.1 payloads, checked byte-for-byte against MainCode.dmp',
        'class_table':'0x77f728', 'class':'0x15', 'class_handler':'0x631610',
        'event_table':'0x77f664', 'event':'0x580', 'handler':'0x631878',
        'items':rows,
        'limits':['Static route conditional on table registration, event dispatch, selection and guards.',
                  'No UI execution, physical input, renderer or display verified.',
                  'Values at record +0/+2/+4 are not proven visible icon meanings.']}, indent=2)+'\n')
    (out/'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    print('PASS: class 0x15, event 0x580 and 7 conditional CaptureMenu destinations;', out)


if __name__ == '__main__':
    main()
