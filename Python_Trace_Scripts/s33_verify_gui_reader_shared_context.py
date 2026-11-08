#!/usr/bin/env python3
"""Verify the bounded GUI reader and an independently configured shared source."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import disasm, locate, raw, u32

dump = (ROOT/'DUMPS/MainCode.dmp').read_bytes()
tbm = (ROOT/'S33-sections/02_TBM_SK501_payload.bin').read_bytes()
def checked(addr, size):
    block, off = locate(addr, size)
    data = raw(addr, size)
    assert data == dump[block['offset']+off:block['offset']+off+size]
    return data
for addr, size in [(0x2beafc,0xc0),(0x2bebc8,8),(0x7c9e38,0xa0),(0x159550,8),(0x159688,4),(0x9817a4,8)]:
    checked(addr, size)
assert u32(0x2bebc8)==u32(0x7c9ed4)==0x300008
assert u32(0x2bebcc)==0xd03000 and u32(0x159688)==0x3672a4
assert (u32(0x9817a4),u32(0x9817a8))==(0xa7b9,2715)
other=disasm(0x2beafc,0x2bebb6)
gui=disasm(0x7c9e38,0x7c9eca)
setter=disasm(0x159550,0x159558)
for needle in (';0x1593ac',';0x159550',';0x2bebcc',';0x159558',';0x1594a4'):
    assert needle in other,needle
for needle in (';0x1593ac',';0x159558',';0x1594a4'):
    assert needle in gui,needle
assert ';0x159550' not in gui
assert 'st_s\tr0,[r2,0]' in setter and 'st_s\tr1,[r2,0x4]' in setter
relative=u32(0x9817a4); size=u32(0x9817a8)
illustration=tbm[0x35c918+relative:0x35c918+relative+size]
other_bytes=tbm[0xd03000+relative:0xd03000+relative+size]
assert len(illustration)==len(other_bytes)==size and illustration!=other_bytes
out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('jpeg_shared_context_%Y%m%dT%H%M%SZ')
out.mkdir(parents=True,exist_ok=False)
(out/'gnu_windows.txt').write_text(other+'\n'+gui+'\n'+setter)
(out/'evidence.json').write_text(json.dumps({'status':'PASS_STATIC_BOUNDED',
 'dump_sha256':hashlib.sha256(dump).hexdigest(),'tbm_sha256':hashlib.sha256(tbm).hexdigest(),
 'lock_id':'0x300008','other_setter_call':'0x2beb6a','other_base':'0xd03000',
 'gui_call':'0x7c9eac','index':14,'relative':'0xa7b9',
 'other_offset':'0xd0d7b9','illustration_offset':'0x3670d1',
 'other_bytes_sha256':hashlib.sha256(other_bytes).hexdigest(),
 'illustration_sha256':hashlib.sha256(illustration).hexdigest(),
 'limits':['Static conditional paths only; no scheduler, locking, or runtime ordering proved.',
 'Release and other services not executed; no proof context persists after release.',
 'TBM comparison assumes that exact file and configured offset; selector 6 mapping unknown.']},indent=2)+'\n')
(out/'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
print('PASS: shared setter, lock ID, GUI call and conditional TBM comparison;',out)
