#!/usr/bin/env python3
"""Cross-check four class-15 event slots against input records and liveview."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import raw,locate,u32,disasm

def main():
 dump=(ROOT/'DUMPS/MainCode.dmp').read_bytes()
 def checked(a,n):
  b,o=locate(a,n);data=raw(a,n);assert data==dump[b['offset']+o:b['offset']+o+n],hex(a);return data
 def events(address):
  rows=[]
  for i in range(128):
   a=address+i*8;checked(a,8);e,handler=u32(a),u32(a+4);rows.append((e,handler))
   if e==0:return rows
  raise AssertionError('event table has no terminator')
 checked(0x392f04,16*20);checked(0x16f72c,0x60);checked(0x16f86c,0x80)
 lists={x:events(x) for x in (0x7833ec,0x77f664)}
 target=[(6,12,11,0x580,0x631878),(7,7,14,0x700,0x63195c),(8,8,67,0x2180,0x631a38),(9,13,78,0x2700,0x631b14)]
 rows=[]
 for slot,(i,bit,key,event,callback) in enumerate(target):
  a=0x392f04+20*i;data=raw(a,20);assert int.from_bytes(data[:8],'little')==1<<bit and data[8]==bit and data[9]==key
  assert key<0x61 and key<<7==event and (event,callback) in lists[0x77f664]
  found=[h for e,h in lists[0x7833ec] if e==event]
  rows.append({'slot':slot,'input_bit':bit,'logical_key':key,'event_nonzero':hex(event),'event_zero':hex(event+1),
      'class15_callback':hex(callback),'liveview_explicit_handler':hex(found[0]) if found else None})
 assert [r['liveview_explicit_handler'] for r in rows]==['0x65440c','0x65426c','0x655f34',None]
 w=disasm(0x16f72c,0x16f78c);assert 'asl_s\tr1,r1,0x7' in w and 'cmp_s\tr13,0x61' in w
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('four_slot_mapping_%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
 (out/'evidence.json').write_text(json.dumps({'status':'PASS_STATIC_BOUNDED','dump_sha256':hashlib.sha256(dump).hexdigest(),
  'class15_table':'0x77f664','liveview_table':'0x7833ec','rows':rows,
  'limitations':['Input source and event delivery conditional; physical identity and top-to-bottom order unknown.',
                 'Liveview handler absent for 0x2700 does not prove absence from fallback or other pathways.',
                 'Original event generator can be gated or filtered; no hardware observed.']},indent=2)+'\n')
 (out/'gnu_window.txt').write_text(w);(out/'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
 print('PASS: four input records, class slots and bounded liveview table;',out)
if __name__=='__main__':main()
