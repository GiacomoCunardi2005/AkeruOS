#!/usr/bin/env python3
"""Run original GUI text lookup with original language blocks mapped as fixtures."""
from datetime import datetime,timezone
from types import SimpleNamespace
import hashlib,json,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,locate,u32,disasm

def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('menu_text_record_fragments_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-text-lookup-original-language-data'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();dump=ROOT/'DUMPS/MainCode.dmp';d=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  tbm=ROOT/'S33-sections/02_TBM_SK501_payload.bin';t=tbm.read_bytes();r.input_hashes[str(tbm)]=sha(tbm)
  for a,n in [(0x6337c4,0x2e),(0x1286c4,0x40),(0x3bb118,300),(0x63200a,12),(0x632540,26)]:
   b,o=locate(a,n);assert raw(a,n)==d[b['offset']+o:b['offset']+o+n]
  assert u32(0x1286fc)==0x43e174 and u32(0x128700)==0x43e768
  (out/'gnu_windows.txt').write_text(disasm(0x6337c4,0x6337f2)+disasm(0x1286c4,0x1286fc))
  tests=[('fragments',x,1) for x in (26,64,88,0x2200000,0x2200008,0x2200010,0x2200020)]
  asm=''
  for i,(route,key,flag) in enumerate(tests):
   a=0x2001000+i*64
   asm+=f""" mov r20,{a:#x}
 mov r1,0x366868
 mov r0,1
 stb r0,[r1]
 st sp,[r20,4]
 mov r13,0x2003000
 mov r1,{key:#x}
 st r1,[r13,12]
 mov fp,0x2004000
 mov r26,after_lookup_{i}
 mov r12,0x63200a
 j [r12]
 after_lookup_{i}:
 ld r0,[fp,-40]
 st r0,[r20]
 mov r0,42
 st r0,[fp,-56]
 mov r0,43
 st r0,[fp,-72]
 mov r0,46
 st r0,[fp,-16]
 mov r0,45
 mov r23,40
 mov r18,41
 mov r26,after_draw_{i}
 mov r12,0x632540
 j [r12]
 after_draw_{i}:
 mov r1,0x2005000
 ld r0,[r1,16]
 st r0,[r20,12]
 ld r0,[r1,0]
 st r0,[r20,16]
 ld r0,[r1,4]
 st r0,[r20,20]
 ld r0,[r1,8]
 st r0,[r20,24]
 ld r0,[r1,12]
 st r0,[r20,28]
 ld r0,[r1,20]
 st r0,[r20,32]
 ld r0,[r1,24]
 st r0,[r20,36]
 st sp,[r20,8]
"""
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  elf=compile_probe(r,'cases',asm)
  def mapping(p,a,n):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  images={i:bytearray(PS[i]) for i in (0,1,2)}; maps=[];patches=[]
  def binary(name,code):
   e=compile_probe(r,name,code);p=out/(name+'.bin');result=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',e,p]);assert result.returncode==0,result.stdout
   data=p.read_bytes();p.write_bytes(data+bytes(8+(-len(data))%8));return p
  fixtures=[('stop_lookup',0x632016,' j [r26]\n'),('stop_draw',0x63255a,' j [r26]\n'),('draw_recorder',0x186d08,' mov r12,0x2005000\n st r0,[r12]\n st r1,[r12,4]\n st r2,[r12,8]\n st r3,[r12,12]\n st r4,[r12,16]\n st r5,[r12,20]\n st r6,[r12,24]\n j_s [blink]\n')]
  for i,(name,addr,code) in enumerate(fixtures):
   target=0x2030000+i*0x400;p=binary(name,code);maps+=mapping(p,target,p.stat().st_size)
   entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
   block,off=locate(addr,8);original=bytes(images[block['index']][off:off+8]);assert original==raw(addr,8)
   images[block['index']][off:off+8]=entry;patches.append({'name':name,'address':hex(addr),'original':original.hex(),'fixture':entry.hex()})
  blocks=list(maps)
  for i,img in images.items():
   p=out/f'block{i}_fixture.bin';p.write_bytes(img);blocks+=mapping(p,BS[i]['load_address_candidate'],len(img))
  for name,addr,size in [('record',0x2003000,32),('frame',0x2003f00,512),('args',0x2005000,32)]:
   p=out/(name+'.bin');p.write_bytes(bytes(size));blocks+=mapping(p,addr,size)
  expected={'english':['Change colors','Settings','Camera settings','ISO','f/','Tempo','Mono RAW'],
   'italian':['Cambia colore','Impostazioni','Impostazioni fotocamera','ISO','f/','Tempo','Mono RAW']}
  custom=bytearray(64)
  for pos,label in [(0,b'ISO'),(8,b'f/'),(16,b'Tempo'),(32,b'Mono RAW')]: custom[pos:pos+len(label)]=label
  custom_file=out/'custom_labels.bin';custom_file.write_bytes(custom)
  results=[]
  for lang,index in [('english',1),('italian',5)]:
   offset=0xc7a000+u32(0x3bb118+4+index*4);size=u32(0x3bb118+152+index*4);blob=t[offset:offset+size]
   assert blob==d[offset:offset+size] and len(blob)==size
   p=out/(lang+'_fixture.bin');p.write_bytes(blob);maps=blocks+mapping(p,0x43e170,size)+mapping(custom_file,0x2200000,len(custom))
   statefile=out/(lang+'_cases.bin');statefile.write_bytes(bytes(len(tests)*64));maps+=mapping(statefile,0x2001000,len(tests)*64)
   case,log=r.run(lang,'/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
   trace=(out/(lang+'.trace')).read_text()
   for addr in ('0x63200a','0x63200c','0x632540','0x63254a','0x632556'):
    assert sum(line.startswith(addr+' ') for line in trace.splitlines())==len(tests),addr
   assert custom_file.read_bytes()==custom
   assert p.read_bytes()==blob
   values=statefile.read_bytes()
   for i,(route,key,flag) in enumerate(tests):
    ptr,sp1,sp2,drawptr,r0,r1,r2,r3,r5,r6=struct.unpack_from('<10I',values,i*64);assert sp1==sp2
    assert drawptr==ptr and (r0,r1,r2,r3,r5,r6)==(40,42,41,43,45,46),(lang,key,drawptr,ptr)
    want=key if key>=381 else 0x43e768+struct.unpack_from('<I',blob,4+4*key)[0]
    assert ptr==want,(lang,route,key,hex(ptr),hex(want))
    text=None
    if i<7:
     data=custom if ptr>=0x2200000 else blob
     p=ptr-(0x2200000 if ptr>=0x2200000 else 0x43e170);end=data.index(b'\0',p);text=data[p:end].decode('ascii');assert text==expected[lang][i]
    results.append({'language_fixture':lang,'entry':route,'id':key,'enabled':flag,'returned':hex(ptr),'text':text,'draw_fixture_argument':hex(drawptr),'stack_preserved':True})
  (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'cases.json').write_text(json.dumps(results,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(__import__('pathlib').Path(__file__).read_bytes())
  r.results.update(status='PASS_SYNTHETIC_RECORD_TEXT_FRAGMENTS_CPU',scenarios=results,
   assumptions=['Original fragments 63200a..632012 and 632540..632556 are entered separately by the harness; text draw routine is a recorder fixture. Original 6337c4 and 1286c4; original language blocks mapped as synthetic RAM.',
                'Flag at 366868 and entry inputs set explicitly; no firmware bytes altered.'],
   limits=['No complete control draw flow, original text renderer, loader, runtime locale, display or hardware execution.',
           'Synthetic RAM mapping does not establish physical memory availability.',
           'Direct pointers come from synthetic memory and are not validated by wrapper; no proof of draw routine or physical mapping.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS: 14 record/lookup and draw-argument fragment cases over English and Italian fixture blocks;',out,flush=True)
if __name__=='__main__':main()
