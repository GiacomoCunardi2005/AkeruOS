#!/usr/bin/env python3
"""Verify ImageMode V1.1 list records and conditional text source mapping."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import cstring, disasm, locate, raw, u16, u32


def main():
    tbm = (ROOT / 'S33-sections/02_TBM_SK501_payload.bin').read_bytes()
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()

    def check(addr, size):
        block, offset = locate(addr, size)
        data = raw(addr, size)
        assert data == dump[block['offset'] + offset:block['offset'] + offset + size], hex(addr)
        return data

    check(0x3f5900 + 4 * 0x9b, 4)
    descriptor = u32(0x3f5900 + 4 * 0x9b)
    assert descriptor == 0x9814b8
    check(descriptor, 24)
    assert u16(descriptor + 4) == 0x9b and u16(descriptor + 6) == 10
    assert u32(descriptor + 8) == 0x981490 and cstring(u32(descriptor + 20)) == 'ImageMode'
    check(u32(descriptor + 20), len('ImageMode') + 1)
    check(0x981490, 40)
    check(0x3bb118, 300)
    assert u32(0x3bb118) == 0x18e209fe
    chunks = {}
    for index in (1, 5):
        offset = 0xc7a000 + u32(0x3bb118 + 4 + index * 4)
        length = u32(0x3bb118 + 152 + index * 4)
        assert 0 < length <= 0x3800 and offset + length <= len(tbm)
        data = tbm[offset:offset + length]
        assert data == dump[offset:offset + length] and struct.unpack_from('<I', data)[0] == 0x18e209fe
        chunks[index] = (offset, data)

    windows = {}
    for start, end in ((0x6316bc, 0x63176e), (0x63200a, 0x632016),
                       (0x6337c4, 0x6337f0), (0x1286c4, 0x1286fc)):
        check(start, end - start)
        windows[start] = disasm(start, end)
    assert u32(0x77f66c) == 0x4409 and u32(0x77f670) == 0x6316bc
    check(0x77f66c, 8)
    assert '0x631f44' in windows[0x6316bc]
    assert all(s in windows[0x63200a] for s in ('ld_s\tr0,[r13,0xc]', '0x6337c4'))
    assert all(s in windows[0x6337c4] for s in ('cmp\tr1,381', '0x1286c4'))
    assert all(s in windows[0x1286c4] for s in ('ld.as\tr1,[r0,r2]', 'add_s\tr0,r1,r12'))
    check(0x1286fc, 8)
    assert (u32(0x1286fc), u32(0x128700)) == (0x43e174, 0x43e768)

    lists = [(0x981218, 0x4800, 0x9811c4, 3, 3),
             (0x9812c0, 0x4801, 0x981250, 4, 4),
             (0x981368, 0x4802, 0x9812f8, 3, 4)]
    expected = [
        (21, 'Choose a size', 'Scegli formato'),
        (67, 'Photo size', 'Formato foto'),
        (68, 'Movie frame size', 'Formato fotogr. filmato'),
        (67, 'Photo size', 'Formato foto'),
        (265, 'Large (13 megapixels)', 'Grande (13 megapixel)'),
        (22, 'Medium (4 megapixels)', 'Medio (4 megapixel)'),
        (23, 'Small (2 megapixels)', 'Piccolo (2 megapixel)'),
        (68, 'Movie frame size', 'Formato fotogr. filmato'),
        (266, 'Large (1080p)', 'Grande (1080p)'),
        (24, 'Small (640)', 'Piccolo (640)'),
        (267, 'Small (old-fashioned)', 'Piccolo (antico)'),
    ]
    rows = []
    for resource, kind, table, page_size, count in lists:
        check(resource, 56)
        assert resource in [u32(0x981490 + 4 * i) for i in range(10)]
        assert (u16(resource + 4), u16(resource + 6)) == (kind, 0x15)
        assert (raw(resource + 46, 1)[0], u16(resource + 52), u32(resource + 48)) == (page_size, count, table)
        check(table, 28 * count)
        for i in range(count):
            address = table + 28 * i
            text_id, english, italian = expected[len(rows)]
            assert u32(address + 12) == text_id and 1 <= text_id < 381
            row = {'resource': hex(kind), 'resource_address': hex(resource), 'index': i,
                   'record': hex(address), 'text_id': text_id}
            for lang, expected_text in ((1, english), (5, italian)):
                base, data = chunks[lang]
                offset = struct.unpack_from('<I', data, 4 + 4 * text_id)[0]
                start = 0x5f8 + offset
                assert start < len(data)
                end = data.index(b'\0', start)
                text = data[start:end].decode('ascii')
                assert text == expected_text
                row['english' if lang == 1 else 'italian'] = text
                row['english_offset' if lang == 1 else 'italian_offset'] = hex(base + start)
            rows.append(row)
    assert len(rows) == len(expected)
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('imagemode_text_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'evidence.json').write_text(json.dumps({
        'status': 'PASS_STATIC_CONDITIONAL_TEXT',
        'tbm_sha256': hashlib.sha256(tbm).hexdigest(), 'dump_sha256': hashlib.sha256(dump).hexdigest(),
        'chunks': {str(i): {'offset': hex(base), 'length': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                   for i, (base, data) in chunks.items()},
        'items': rows,
        'limits': ['Assumes loader uses indicated block and backend matches TBM bytes.',
                   'Runtime resource registration, selected locale, input events and rendering are unobserved.']
    }, indent=2) + '\n')
    (out / 'disassembly.txt').write_text('\n'.join(windows.values()))
    (out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    print('PASS: three ImageMode lists, 11 records, two source blocks;', out)


if __name__ == '__main__':
    main()
