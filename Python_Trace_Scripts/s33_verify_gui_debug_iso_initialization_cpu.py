#!/usr/bin/env python3
"""Run original debug ISO initialization against original records and synthetic controls."""
from datetime import datetime, timezone
from types import SimpleNamespace
import json, struct, sys
from pathlib import Path
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32, disasm


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('debug_iso_initialization_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-debug-iso-initialization'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); dump=ROOT/'DUMPS/MainCode.dmp'; d=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x7d2564,0x4c),(0x17c3e8,16),(0x641064,0x6c),(0x641128,0x4c),(0x989da4,480)]:
   b,o=locate(a,n); assert raw(a,n)==d[b['offset']+o:b['offset']+o+n]
  assert u32(0x17c3e8)==0x367bc8 and u32(0x6410cc)==0x440c
  for i in range(24): assert u32(0x989da4+i*20+12)==(0xffffffff if not i else i-1) and u32(0x989da4+i*20+16)==0
  (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in [(0x7d2564,0x7d25b0),(0x17c3f0,0x17c3f8),(0x641064,0x6410d0),(0x641128,0x641174)]))
  images={i:bytearray(PS[i]) for i in (0,1,2,4,5)}; maps=[]; patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm); p=out/(name+'.bin')
   x=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]); assert x.returncode==0,x.stdout
   v=p.read_bytes(); p.write_bytes(v+bytes(8+(-len(v))%8)); return p
  def mapping(p,a,n):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  common=' mov r10,0x2000000\n ld r10,[r10]\n'
  services=[('control',0x145654,common+' st r1,[r10,12]\n ld r0,[r10,48]\n j_s [blink]\n'),
   ('refresh',0x145490,common+' ld r11,[r10,16]\n add r11,r11,1\n st r11,[r10,16]\n j_s [blink]\n'),
   ('get8',0x14503c,' mov r0,0x55\n j_s [blink]\n'),('get4',0x14504c,' mov r0,0x1234\n j_s [blink]\n'),
   ('dispatch',0x169d78,common+' st r0,[r10,20]\n st r1,[r10,24]\n st r2,[r10,28]\n ld r11,[r10,32]\n add r11,r11,1\n st r11,[r10,32]\n j_s [blink]\n')]
  for i,(name,addr,asm) in enumerate(services):
   dst=0x2030000+i*0x400; p=binary(name,asm); maps+=mapping(p,dst,p.stat().st_size)
   entry=binary('entry_'+name,f' mov_s r12,{dst:#x}\n j_s [r12]\n').read_bytes()[:8]
   b,o=locate(addr,8); before=bytes(images[b['index']][o:o+8]); assert before==raw(addr,8)
   images[b['index']][o:o+8]=entry; patches.append({'name':name,'address':hex(addr),'original':before.hex(),'fixture':entry.hex()})
  # A zero count, NULL control and a modified synthetic copy test guards, not real camera states.
  tests=[(v,24,False,False) for v in range(24)]+[(255,24,False,False),(0,0,False,False),(4,3,False,False),(6,24,True,False),(0,24,False,True)]
  state=bytearray(len(tests)*96); contexts=bytearray(len(tests)*0x300); asm=' mov r20,0x2000000\n'
  for i,(value,count,disabled,null) in enumerate(tests):
   a=0x2001000+i*96; ctx=0x2100000+i*0x300
   struct.pack_into('<I',state,i*96+48,0 if null else ctx); contexts[i*0x300+37]=count; contexts[i*0x300+38]=99
   struct.pack_into('<I',contexts,i*0x300+0x40,ctx+0x80 if disabled else 0x989da4)
   if disabled:
    contexts[i*0x300+0x80:i*0x300+0x80+480]=raw(0x989da4,480)
    struct.pack_into('<I',contexts,i*0x300+0x80+7*20+16,1)
   asm+=f''' mov r21,{a:#x}
 st r21,[r20]
 mov r1,0x367bc8
 mov r0,{value}
 stb r0,[r1]
 st sp,[r21,36]
 mov r0,0
 mov r1,0
 mov r2,0
 mov r12,0x7d2564
 jl [r12]
 st r0,[r21]
 st sp,[r21,40]
 mov r1,{ctx+38:#x}
 ldb r0,[r1]
 st r0,[r21,4]
 mov r1,0x367bc8
 ldb r0,[r1]
 st r0,[r21,8]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,image in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin'; p.write_bytes(image); maps+=mapping(p,BS[i]['load_address_candidate'],len(image))
  p=out/'cases.bin'; p.write_bytes(state); maps+=mapping(p,0x2001000,len(state)); statefile=p
  p=out/'current.bin'; p.write_bytes(bytes(8)); maps+=mapping(p,0x2000000,8)
  p=out/'contexts.bin'; p.write_bytes(contexts); maps+=mapping(p,0x2100000,len(contexts))
  elf=compile_probe(r,'cases',asm); case,log=r.run('cases','/result/'+elf.name,maps,trace=True); assert case['exit_code']==0 and case['fault'] is None,log
  got=statefile.read_bytes(); rows=[]
  for i,(value,count,disabled,null) in enumerate(tests):
   w=struct.unpack_from('<11I',got,i*96); position=value+1 if value<=22 and value+1<count else 0
   applied=not null and count>0 and not disabled
   selected=position if applied else 99
   assert w[0]==0 and w[1]==selected and w[2]==value and w[3]==0x4801 and w[4]==int(applied) and w[8]==int(applied) and w[9]==w[10],(i,w,selected)
   if applied: assert tuple(w[5:8])==(0x55,0x440c,0x12340000|position),(i,w)
   rows.append({'current_index':value,'count':count,'control_null':null,'synthetic_disabled_record':disabled,'expected_requested_position':position,'selected_after':w[1],'refresh_calls':w[4],'dispatch_calls':w[8],'stack_preserved':True})
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n'); (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_DEBUG_ISO_INITIALIZATION_SYNTHETIC',scenarios=rows,
   assumptions=['Original initialization handler, getter, lookup, selector and 24 records; synthetic control context and index.', 'Control retrieval, refresh, two GUI getters and event dispatch are fixtures.'],
   limits=['Direct handler call; list lifecycle, delivery, display, camera, persistence and sensor not proven.', 'Disabled, zero-count and null-control cases are synthetic guard tests.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e)); raise
 finally:r.save()
 print('PASS:',len(tests),'debug ISO initialization cases;',out,flush=True)
if __name__=='__main__':main()
