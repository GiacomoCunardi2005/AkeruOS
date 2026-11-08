#!/usr/bin/env python3
"""Inventory decodable JPEG candidates in the untouched firmware container."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import io
import json
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin'
data = source.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39'
out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('embedded_jpeg_%Y%m%dT%H%M%SZ')
out.mkdir(parents=True, exist_ok=False)
records, thumbs = [], []
pos = 0
while True:
    pos = data.find(b'\xff\xd8\xff', pos)
    if pos < 0:
        break
    end = data.find(b'\xff\xd9', pos + 3)
    if end >= 0:
        buf = data[pos:end + 2]
        try:
            im = Image.open(io.BytesIO(buf))
            im.load()
            records.append({'offset': hex(pos), 'bytes': len(buf), 'size': list(im.size),
                            'sha256': hashlib.sha256(buf).hexdigest()})
            if im.size == (160, 96):
                thumbs.append((pos, im.convert('RGB')))
        except (OSError, ValueError, SyntaxError):
            pass
    pos += 3
if thumbs:
    sheet = Image.new('RGB', (4 * 180, ((len(thumbs) + 3) // 4) * 120), 'white')
    draw = ImageDraw.Draw(sheet)
    for i, (offset, im) in enumerate(thumbs):
        x, y = i % 4 * 180, i // 4 * 120
        sheet.paste(im, (x, y))
        draw.text((x, y + 98), hex(offset), fill='black')
    sheet.save(out / '160x96_contact.png')
result = {'status': 'PASS_DECODED_CANDIDATES', 'firmware_sha256': digest, 'records': records,
          'limits': ['Searches SOI and first subsequent EOI only; not exhaustive.',
                     'Offsets are in the firmware container, not runtime addresses.',
                     'JPEG appearance alone does not establish GUI use.']}
(out / 'inventory.json').write_text(json.dumps(result, indent=2) + '\n')
(out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
print('PASS:', len(records), 'decodable JPEGs;', len(thumbs), '160x96;', out)
