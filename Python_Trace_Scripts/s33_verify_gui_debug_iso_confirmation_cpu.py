#!/usr/bin/env python3
"""Execute the original ISO confirmation and control getter with synthetic GUI lists."""
from datetime import datetime, timezone
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32, disasm


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('debug_iso_confirmation_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-debug-iso-confirmation'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); dump=ROOT/'DUMPS/MainCode.dmp'; d=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x7d25b0,0x40),(0x6410f4,0x34),(0xd03b8,0x1c),(0x17c320,0xc8),(0xde78c,0x40),(0x989ff8,24),(0x989da4,480),(0x989f84,68),(0x98a01a,189)]:
   b,o=locate(a,n); assert raw(a,n)==d[b['offset']+o:b['offset']+o+n]
  assert u32(0x98a000)==0x4801 and u32(0x98a004)==0x7d25b0 and u32(0x989fc4)==0x989da4
  (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in [(0x7d25b0,0x7d25f0),(0x6410f4,0x641128),(0xd03b8,0xd03d4),(0x17c320,0x17c3e8)]))
  images={i:bytearray(PS[i]) for i in (0,1,2,4,5)}; maps=[]; patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm); p=out/(name+'.bin')
   x=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]); assert x.returncode==0,x.stdout
   v=p.read_bytes(); p.write_bytes(v+bytes(8+(-len(v))%8)); return p
  def mapping(p,a,n):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  common=' mov r10,0x2000000\n ld r10,[r10]\n'
  services=[('control',0x145790,common+' ld r11,[r10,12]\n add r11,r11,1\n st r11,[r10,12]\n ld r0,[r10,48]\n j_s [blink]\n'),
   ('open',0x1453e4,common+' st r0,[r10,16]\n st r1,[r10,20]\n ld r11,[r10,24]\n add r11,r11,1\n st r11,[r10,24]\n mov r0,0\n j_s [blink]\n')]
  for i,(name,addr,asm) in enumerate(services):
   dst=0x2030000+i*0x400; p=binary(name,asm); maps+=mapping(p,dst,p.stat().st_size)
   entry=binary('entry_'+name,f' mov_s r12,{dst:#x}\n j_s [r12]\n').read_bytes()[:8]
   b,o=locate(addr,8); before=bytes(images[b['index']][o:o+8]); assert before==raw(addr,8)
   images[b['index']][o:o+8]=entry; patches.append({'name':name,'address':hex(addr),'original':before.hex(),'fixture':entry.hex()})
  # Original static records: Exit, Auto and numeric ISO 50 through 3200.
  converted=[0,50,64,80,100,120,125,140,160,200,250,280,320,400,500,640,800,1000,1250,1600,2000,2500,3200]
  labels=['Exit','Auto']+['ISO '+str(v) for v in converted[1:]]
  records=[]
  for i,label in enumerate(labels):
   addr=0x989da4+i*20; ptr=u32(addr+8); value=u32(addr+12)
   got=raw(ptr,len(label)+1); assert got==label.encode()+b'\0'
   assert value==(0xffffffff if i==0 else i-1)
   records.append({'position':i,'address':hex(addr),'label_pointer':hex(ptr),'label':label,'value':value})
  (out/'original_records.json').write_text(json.dumps(records,indent=2)+'\n')
  # Values/counts in the control context are assumed; the pointed-to records are original.
  tests=[(v['value'],v['position'],24,None if v['position']==0 else converted[v['value']],False) for v in records]
  tests += [(0,24,24,0,False),(0x106,0,1,125,True)]
  state=bytearray(len(tests)*96); contexts=bytearray(len(tests)*0x100); asm=' mov r20,0x2000000\n'
  for i,(value,selected,count,want,synthetic) in enumerate(tests):
   a=0x2001000+i*96; ctx=0x2100000+i*0x100
   struct.pack_into('<I',state,i*96+48,ctx); contexts[i*0x100+37]=count; contexts[i*0x100+38]=selected
   struct.pack_into('<I',contexts,i*0x100+0x40,ctx+0x80 if synthetic else 0x989da4); struct.pack_into('<I',contexts,i*0x100+0x8c,value)
   asm+=f''' mov r21,{a:#x}
 st r21,[r20]
 mov r1,0x365787
 mov r0,88
 stb r0,[r1]
 mov r1,0x367bc8
 mov r0,77
 stb r0,[r1]
 mov r1,0x37fbf2
 mov r0,555
 sth r0,[r1]
 st sp,[r21,28]
 mov r0,0
 mov r1,0x4801
 mov r2,0
 mov r12,0x7d25b0
 jl [r12]
 mov r1,0x365787
 ldb r0,[r1]
 st r0,[r21]
 mov r1,0x367bc8
 ldb r0,[r1]
 st r0,[r21,4]
 mov r1,0x37fbf2
 ldh r0,[r1]
 st r0,[r21,8]
 st sp,[r21,32]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,image in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin'; p.write_bytes(image); maps+=mapping(p,BS[i]['load_address_candidate'],len(image))
  p=out/'cases.bin'; p.write_bytes(state); maps+=mapping(p,0x2001000,len(state)); statefile=p
  p=out/'current.bin'; p.write_bytes(bytes(8)); maps+=mapping(p,0x2000000,8)
  p=out/'contexts.bin'; p.write_bytes(contexts); maps+=mapping(p,0x2100000,len(contexts))
  elf=compile_probe(r,'cases',asm); case,log=r.run('cases','/result/'+elf.name,maps,trace=True); assert case['exit_code']==0 and case['fault'] is None,log
  got=statefile.read_bytes(); rows=[]
  for i,(value,selected,count,want,synthetic) in enumerate(tests):
   w=struct.unpack_from('<9I',got,i*96)
   expected=(88,77,555) if want is None else ((value if selected<count else 0)&255,(value if selected<count else 0)&255,want)
   assert tuple(w[:3])==expected and w[3]==2 and tuple(w[4:7])==(0x36,0,1) and w[7]==w[8],(i,w,expected)
   rows.append({'record_value':value,'selected':selected,'count':count,'debug_byte':w[0],'current_index':w[1],
    'converted':w[2],'synthetic_record':synthetic,'control_calls':w[3],'open_id':hex(w[4]),'open_calls':w[6],'stack_preserved':True})
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n'); (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(__import__('pathlib').Path(__file__).read_bytes())
  r.results.update(status='PASS_DEBUG_ISO_CONFIRMATION_SYNTHETIC',scenarios=rows,
   assumptions=['Original confirmation callback, getter, setter/converter and 24 static records; control count, selection and RAM are synthetic.',
                'Control retrieval and GUI opening replaced by explicit fixtures.'],
   limits=['Does not establish runtime list loading, event delivery, active screen, display, sensor gain or AE behavior.',
           'Out-of-range and 16-bit minus-one tests are synthetic edge cases; no claim they occur in the camera.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e)); raise
 finally:r.save()
 print('PASS: 26 debug ISO confirmation cases;',out,flush=True)
if __name__=='__main__':main()
