#!/usr/bin/env python3
"""Verify V1.1 ChangeColorMenu records and conditional language-block texts."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import cstring, locate, raw, u16, u32


def main():
    tbm = (ROOT / 'S33-sections/02_TBM_SK501_payload.bin').read_bytes()
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    def check(address, size):
        block, offset = locate(address, size)
        assert raw(address, size) == dump[block['offset'] + offset:block['offset'] + offset + size], hex(address)

    for address, size in ((0x3f5908, 4), (0x3f5918, 4), (0x3f5bec, 4),
                          (0x9802ac, 24), (0x98056c, 24), (0x982064, 24),
                          (0x89983c, 8), (0x98202c, 56), (0x981fbc, 112), (0x3bb118, 300)):
        check(address, size)
    assert u32(0x3f5908) == 0x9802ac and cstring(u32(0x9802c0)) == 'CaptureMenu'
    assert u32(0x3f5918) == 0x98056c and cstring(u32(0x980580)) == 'EVMenu'
    assert u32(0x3f5bec) == 0x982064 and cstring(u32(0x982078)) == 'ChangeColorMenu'
    for pointer, name in ((0x9802c0, 'CaptureMenu'), (0x980580, 'EVMenu'), (0x982078, 'ChangeColorMenu')):
        check(u32(pointer), len(name) + 1)
    assert (u16(0x982068), u16(0x98206a), u32(0x98206c)) == (0xbb, 2, 0x89983c)
    assert u32(0x89983c) == 0x98202c
    assert (u16(0x982030), u16(0x982032), u32(0x98205c), raw(0x982060, 1)[0]) == (0x4800, 0x15, 0x981fbc, 4)
    assert u32(0x3bb118) == 0x18e209fe
    expected = [
        (26, 5, 2, 8, [606, 606, 606], b'Change colors', b'Cambia colore'),
        (62, 0, 6, 0, [215, 216, 215], b'Brighter/darker', b'Pi\xf9 chiaro/pi\xf9 scuro'),
        (63, 1, 6, 0, [217, 218, 217], b'More vivid/less vivid', b'Pi\xf9 vivace/meno vivace'),
        (11, 2, 6, 0, [219, 220, 219], b'Highlight colors', b'Seleziona colore'),
    ]
    chunks = {}
    for lang in (1, 5):
        offset = 0xc7a000 + u32(0x3bb118 + 4 + lang * 4)
        length = u32(0x3bb118 + 152 + lang * 4)
        assert 0 < length <= 0x3800 and offset + length <= len(tbm)
        data = tbm[offset:offset + length]
        assert data == dump[offset:offset + length] and struct.unpack_from('<I', data)[0] == 0x18e209fe
        chunks[lang] = (offset, data)
    rows = []
    for index, (text_id, arg, dest, flags, icons, english, italian) in enumerate(expected):
        address = 0x981fbc + 28 * index
        assert [u16(address + i) for i in (0, 2, 4)] == icons
        assert (u32(address + 12), u32(address + 16), u16(address + 20), u32(address + 24)) == (text_id, arg, dest, flags)
        row = {'index': index, 'address': hex(address), 'text_id': text_id, 'argument': arg,
               'destination_id': dest, 'initial_flags': flags, 'icons_raw': icons}
        for lang, text in ((1, english), (5, italian)):
            base, data = chunks[lang]
            offset = 0x5f8 + struct.unpack_from('<I', data, 4 + 4 * text_id)[0]
            assert offset < len(data) and data[offset:data.index(b'\0', offset)] == text
            row['english' if lang == 1 else 'italian'] = text.decode('latin-1')
            row['english_offset' if lang == 1 else 'italian_offset'] = hex(base + offset)
        rows.append(row)
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('changecolor_items_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'evidence.json').write_text(json.dumps({
        'status': 'PASS_STATIC_CONDITIONAL', 'tbm_sha256': hashlib.sha256(tbm).hexdigest(),
        'dump_sha256': hashlib.sha256(dump).hexdigest(), 'items': rows,
        'language_blocks': {str(i): {'offset': hex(base), 'length': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                            for i, (base, data) in chunks.items()},
        'limits': ['Text assumes the previously studied lookup and backend matching TBM bytes.',
                   'Encoding beyond selected bytes, locale, event delivery, selected entry, rendering and settings effects are unverified.']
    }, indent=2, ensure_ascii=False) + '\n')
    (out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    print('PASS: four ChangeColorMenu records and conditional texts;', out)


if __name__ == '__main__':
    main()
