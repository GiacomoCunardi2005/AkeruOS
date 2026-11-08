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
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('capture_text_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-text-lookup-original-language-data'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();dump=ROOT/'DUMPS/MainCode.dmp';d=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  tbm=ROOT/'S33-sections/02_TBM_SK501_payload.bin';t=tbm.read_bytes();r.input_hashes[str(tbm)]=sha(tbm)
  for a,n in [(0x6337c4,0x2e),(0x1286c4,0x40),(0x3bb118,300)]:
   b,o=locate(a,n);assert raw(a,n)==d[b['offset']+o:b['offset']+o+n]
  assert u32(0x1286fc)==0x43e174 and u32(0x128700)==0x43e768
  (out/'gnu_windows.txt').write_text(disasm(0x6337c4,0x6337f2)+disasm(0x1286c4,0x1286fc))
  tests=[('wrapper',x,1) for x in (1,26,59,60,61,91,92,380)]+[('wrapper',59,0),('wrapper',0,1),('wrapper',381,1),('direct',0xffffffff,1),('direct',381,1),('direct',59,0)]
  asm=''
  for i,(route,key,flag) in enumerate(tests):
   a=0x2001000+i*64;entry=0x6337c4 if route=='wrapper' else 0x1286c4
   asm+=f''' mov r20,{a:#x}
 mov r1,0x366868
 mov r0,{flag}
 stb r0,[r1]
 st sp,[r20,4]
 mov r0,{key:#x}
 mov r12,{entry:#x}
 jl [r12]
 st r0,[r20]
 st sp,[r20,8]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  elf=compile_probe(r,'cases',asm)
  def mapping(p,a,n):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  blocks=[]
  for i in (0,1,2):
   p=out/f'block{i}_original.bin';p.write_bytes(PS[i]);blocks+=mapping(p,BS[i]['load_address_candidate'],len(PS[i]))
  expected={'english':['Decorate','Change colors','Flash mode/self-timer','More picture options','Choose a style','Flash','Self-timer'],
   'italian':['Decora','Cambia colore','Modo flash/autoscatto','Altre opzioni foto','Scegli stile','Flash','Autoscatto']}
  results=[]
  for lang,index in [('english',1),('italian',5)]:
   offset=0xc7a000+u32(0x3bb118+4+index*4);size=u32(0x3bb118+152+index*4);blob=t[offset:offset+size]
   assert blob==d[offset:offset+size] and len(blob)==size
   p=out/(lang+'_fixture.bin');p.write_bytes(blob);maps=blocks+mapping(p,0x43e170,size)
   statefile=out/(lang+'_cases.bin');statefile.write_bytes(bytes(len(tests)*64));maps+=mapping(statefile,0x2001000,len(tests)*64)
   case,log=r.run(lang,'/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
   values=statefile.read_bytes()
   for i,(route,key,flag) in enumerate(tests):
    ptr,sp1,sp2=struct.unpack_from('<III',values,i*64);assert sp1==sp2
    if route=='wrapper' and key==0: want=0
    elif route=='wrapper' and key>=381:want=key
    elif not flag or key>=381:want=0x36686c
    else:want=0x43e768+struct.unpack_from('<I',blob,4+4*key)[0]
    assert ptr==want,(lang,route,key,hex(ptr),hex(want))
    text=None
    if i<7:
     p=ptr-0x43e170;end=blob.index(b'\0',p);text=blob[p:end].decode('ascii');assert text==expected[lang][i]
    results.append({'language_fixture':lang,'entry':route,'id':key,'enabled':flag,'returned':hex(ptr),'text':text,'stack_preserved':True})
  (out/'cases.json').write_text(json.dumps(results,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(__import__('pathlib').Path(__file__).read_bytes())
  r.results.update(status='PASS_GUI_TEXT_LOOKUP_ORIGINAL_CPU',scenarios=results,
   assumptions=['Original 6337c4 and 1286c4; original TBM language blocks mapped as synthetic RAM.',
                'Flag at 366868 and entry inputs set explicitly; no firmware bytes altered.'],
   limits=['No original loader, filesystem, runtime locale, display or hardware execution.',
           'Synthetic RAM mapping does not establish physical memory availability.',
           'ASCII conclusions limited to seven selected strings per language.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS: 28 original lookup cases over English and Italian fixture blocks;',out,flush=True)
if __name__=='__main__':main()
