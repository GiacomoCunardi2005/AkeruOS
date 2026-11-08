#!/usr/bin/env python3
"""Check the V1.1 diagnostic return object and its two exposure editors."""
from datetime import datetime, timezone
from pathlib import Path
import json, sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import raw, locate, u16, u32, cstring, sha


def main():
 dump=(ROOT/'DUMPS/MainCode.dmp').read_bytes()
 def checked(addr, size):
  block, off=locate(addr,size); value=raw(addr,size)
  assert value==dump[block['offset']+off:block['offset']+off+size],hex(addr)
  return value
 objects=[]
 for index,descriptor,title in [(0x36,0x987af8,'DEBUG MODE MENU'),(0x3e,0x989cd8,'EXPOSURE COMPENSATION'),(0x3f,0x989fcc,'ISO Speed')]:
  table=0x3f5900+index*4;checked(table,4);assert u32(table)==descriptor
  checked(descriptor,24);assert u16(descriptor+4)==index
  array=u32(descriptor+8);checked(array,4);resource=u32(array)
  checked(resource,36);string=u32(resource+32);checked(string,len(title)+1);assert cstring(string)==title
  objects.append(dict(id=hex(index),descriptor=hex(descriptor),title=title,title_address=hex(string)))
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('debug_return_identity_static_%Y%m%dT%H%M%SZ');out.mkdir(parents=True)
 (out/'evidence.json').write_text(json.dumps(dict(status='PASS_STATIC_OBJECT_IDENTITIES',dump_sha256=sha(dump),objects=objects,limits=['Static object names and descriptor bytes; no object loader or rendering executed.']),indent=2)+'\n')
 (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
 print('PASS: three original object descriptors and titles:',out)

if __name__=='__main__':main()
