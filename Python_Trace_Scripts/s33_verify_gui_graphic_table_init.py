#!/usr/bin/env python3
"""Verify the candidate S33 V1.1 graphic table and decode capture indices offline."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct
import sys

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import disasm, locate, raw, u16, u32


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()

    def check(address, size):
        block, offset = locate(address, size)
        data = raw(address, size)
        assert data == dump[block['offset'] + offset:block['offset'] + offset + size], (hex(address), size)
        return data

    windows = [(0x159110, 0x159150), (0x23e704, 0x23e72c),
               (0x2d4f9c, 0x2d4fa4), (0x23b19c, 0x23b1a6),
               (0x23b20c, 0x23b22e), (0x23b234, 0x23b2dc)]
    assembly = {}
    for start, end in windows:
        check(start, end - start)
        assembly[start] = disasm(start, end)
    for start, needles in {
        0x159110: ['0x23e704', '0x23e740'],
        0x23e704: ['0x23e730', 'mov\tr1,887', '0x2d4f9c', '0x23b19c'],
        0x2d4f9c: ['st_s\tr0,[r2,0]', 'stw_s\tr1,[r2,0x4]'],
        0x23b19c: ['st_s\tr0,[r2,0]', 'stw_s\tr1,[r2,0x4]'],
        0x23b20c: ['add2_s\tr2,r2,r0', 'ld_s\tr3,[r2,0]', 'ldw_s.x\tr2,[r13,0x4]'],
        0x23b234: ['lsr_s\tr1,r3', 'btst_s\tr3,0', 'stb.ab\tr3,[r2,1]'],
    }.items():
        for needle in needles:
            assert needle in assembly[start], (hex(start), needle)
    check(0x23e730, 4)
    assert u32(0x23e730) == 0xea0660
    check(0xea0660, 887 * 4)
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('graphic_table_init_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    lists = {}
    ids = set()
    for address in (0x9801c0, 0x980268):
        head = check(address, 56)
        count = head[46]
        ptr = u32(address + 48)
        check(ptr, count * 28)
        items = [[u16(ptr + 28 * i + j) for j in (0, 2, 4)] for i in range(count)]
        ids.update(x for row in items for x in row)
        lists[hex(address)] = items
    assert lists == {'0x9801c0': [[606, 606, 606], [284, 285, 284], [806, 807, 806]],
                     '0x980268': [[606, 606, 606], [633, 634, 633], [413, 414, 413], [222, 223, 222]]}
    descriptors = []
    masks = {}
    for index in sorted(ids):
        assert 0 <= index < 887
        address = u32(0xea0660 + index * 4)
        desc = check(address, 20)
        width, height = struct.unpack_from('<hh', desc)
        source = struct.unpack_from('<I', desc, 16)[0]
        assert width > 0 and height > 0 and desc[8] == 1
        pixels = bytearray()
        cursor = source
        while len(pixels) < width * height:
            control = raw(cursor, 1)[0]
            cursor += 1
            count = min(control >> 1, width * height - len(pixels))
            if control & 1:
                pixels.extend(raw(cursor, count))
                cursor += count
            else:
                value = raw(cursor, 1)[0]
                cursor += 1
                pixels.extend(bytes([value]) * count)
        compressed = check(source, cursor - source)
        assert len(pixels) == width * height
        (out / f'{index:03}.indices').write_bytes(pixels)
        masks[index] = bytes(255 if value else 0 for value in pixels)
        Image.frombytes('L', (width, height), masks[index]).save(out / f'{index:03}_nonzero_mask.png')
        descriptors.append(dict(id=index, descriptor=hex(address), width=width, height=height,
                                descriptor_hex=desc.hex(), source=hex(source), compressed_bytes=len(compressed),
                                compressed_sha256=hashlib.sha256(compressed).hexdigest(),
                                indices_sha256=hashlib.sha256(pixels).hexdigest(),
                                indices_used=sorted(set(pixels))))
    for first, second in ((222, 223), (284, 285), (413, 414), (633, 634), (806, 807)):
        assert masks[first] == masks[second], (first, second)
    (out / 'disassembly.txt').write_text('\n'.join(assembly.values()))
    (out / 'evidence.json').write_text(json.dumps(dict(status='PASS_STATIC_AND_HOST_DECODE',
        dump_sha256=hashlib.sha256(dump).hexdigest(), table='0xea0660', limit=887,
        lists=lists, descriptors=descriptors,
        limits=['Initialization path reachability and state at runtime not proved.',
                'Host decode follows bounded static interpretation, not execution of original decoder.',
                'Masks map zero to black and all nonzero indices to white; palette, transparency and physical rendering are unverified.']), indent=2) + '\n')
    (out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    print('PASS: initialization, table, capture descriptors and indexed host decode;', out)


if __name__ == '__main__':
    main()
