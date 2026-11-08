#!/usr/bin/env python3
"""Connect CaptureMenu text IDs to language blocks in the original TBM image."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import disasm,locate,raw,u16,u32

def main():
 tbm=(ROOT/'S33-sections/02_TBM_SK501_payload.bin').read_bytes()
 dump=(ROOT/'DUMPS/MainCode.dmp').read_bytes()
 def checked(a,n):
  b,o=locate(a,n);v=raw(a,n);assert v==dump[b['offset']+o:b['offset']+o+n],hex(a);return v
 for a,n in [(0x3bb118,300),(0x1eb1a4,8),(0x128574,0xa4),(0x128620,0x94),(0x1286c4,0x40),(0x98016c,84),(0x9801f8,112)]:checked(a,n)
 assert u32(0x1eb1a8)==0x3bb118 and u32(0x12855c)==0x366864
 assert u32(0x12861c)==0xc7a000 and u32(0x1286b8)==0x43e170
 assert u32(0x1286fc)==0x43e174 and u32(0x128700)==0x43e768
 assert u32(0x3bb118)==0x18e209fe
 chunks=[]
 for i in range(37):
  off=u32(0x3bb118+4+i*4);size=u32(0x3bb118+152+i*4);pos=0xc7a000+off
  assert 0<size<=0x3800 and pos+size<=len(tbm)
  data=tbm[pos:pos+size];assert data==dump[pos:pos+size] and struct.unpack_from('<I',data)[0]==0x18e209fe
  if chunks:assert pos==chunks[-1]['offset']+chunks[-1]['length']
  chunks.append({'index':i,'offset':pos,'length':size,'sha256':hashlib.sha256(data).hexdigest()})
 windows=[disasm(0x1eb1a4,0x1eb1a8),disasm(0x1285f4,0x128618),disasm(0x128620,0x1286b4),disasm(0x1286c4,0x1286fc)]
 for i,needle in [(0,'ld_s\tr0,[pcl,0x4]'),(1,';0x159550'),(1,';0x128620'),(2,';0x159558'),(2,';0x1286b8'),(3,';0x1286fc'),(3,';0x128700')]:assert needle in windows[i],needle
 records=[(0x4800,0x98016c,3),(0x4801,0x9801f8,4)]
 expected={1:['Flash mode/self-timer','Flash','Self-timer','More picture options','Choose a style','Decorate','Change colors'],
           5:['Modo flash/autoscatto','Flash','Autoscatto','Altre opzioni foto','Scegli stile','Decora','Cambia colore']}
 ids=[59,91,92,60,61,1,26];rows=[]
 for group,table,count in records:
  for index in range(count):
   rec=table+28*index;rows.append({'list':hex(group),'index':index,'record':hex(rec),'text_id':u32(rec+12)})
 assert [r['text_id'] for r in rows]==ids
 for lang,strings in expected.items():
  rec=chunks[lang];part=tbm[rec['offset']:rec['offset']+rec['length']]
  for row,expected_text in zip(rows,strings):
   i=row['text_id'];assert 1<=i<381
   off=struct.unpack_from('<I',part,4+4*i)[0];start=0x5f8+off
   assert start<len(part);end=part.index(b'\0',start);s=part[start:end].decode('ascii');assert s==expected_text
   row['english' if lang==1 else 'italian']=s
   row['english_offset' if lang==1 else 'italian_offset']=rec['offset']+start
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('capture_text_source_%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
 (out/'gnu_windows.txt').write_text('\n'.join(windows))
 (out/'evidence.json').write_text(json.dumps({'status':'PASS_STATIC_LANGUAGE_BLOCKS',
  'tbm_sha256':hashlib.sha256(tbm).hexdigest(),'dump_sha256':hashlib.sha256(dump).hexdigest(),
  'table':'0x3bb118','reader_base':'0xc7a000','chunks':chunks,'items':rows,
  'limits':['Conditional source mapping assumes indicated loader path and matching file TBM.',
            'Current locale index, actual backend, runtime buffer, font encoding and displayed UI unobserved.',
            'ASCII verified only for seven selected strings in blocks 1 and 5.']},indent=2)+'\n')
 (out/'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
 print('PASS: 37 source blocks, seven English and Italian text candidates;',out)
if __name__=='__main__':main()
