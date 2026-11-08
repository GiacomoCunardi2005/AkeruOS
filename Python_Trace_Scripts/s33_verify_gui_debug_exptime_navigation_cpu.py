#!/usr/bin/env python3
"""Run original debug exposure-time navigation and normalization with UI fixtures."""
from datetime import datetime,timezone
from types import SimpleNamespace
import json,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,locate,u32,disasm

def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('debug_time_navigation_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-debug-exptime-navigation'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();dump=ROOT/'DUMPS/MainCode.dmp';d=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x7d23c8,0x9c),(0x7d24bc,0x6a),(0x989cf8,72),(0x7d2354,4)]:
   b,o=locate(a,n);assert raw(a,n)==d[b['offset']+o:b['offset']+o+n]
  assert u32(0x7d2354)==0x899abc
  events={u32(0x989cf8+i*8):u32(0x989cfc+i*8) for i in range(9)}
  assert events[0x380]==0x7d23c8 and events[0x400]==0x7d241c
  windows=[]
  for a,b in [(0x7d23c8,0x7d241c),(0x7d241c,0x7d2464),(0x7d24bc,0x7d2526)]:windows.append(disasm(a,b))
  (out/'gnu_windows.txt').write_text('\n'.join(windows))
  images={i:bytearray(PS[i]) for i in (0,1,2,4,5)};maps=[];patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm);p=out/(name+'.bin');x=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert x.returncode==0,x.stdout
   v=p.read_bytes();p.write_bytes(v+bytes(8+(-len(v))%8));return p
  def mapping(p,a,n):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  common=' mov r10,0x2000000\n ld r10,[r10]\n'
  services=[('format',0x12ce54,' mov r0,0\n j_s [blink]\n'),
    ('resource',0x145654,' mov r0,0x2100000\n j_s [blink]\n'),
    ('set_text',0x633020,' mov r0,0\n j_s [blink]\n'),
    ('refresh',0x145490,' mov r0,0\n j_s [blink]\n'),
    ('timer',0x14905c,common+' ld r11,[r10,12]\n add r11,r11,1\n st r11,[r10,12]\n mov r0,0\n j_s [blink]\n')]
  for i,(name,addr,asm) in enumerate(services):
   dst=0x2030000+i*0x400;p=binary(name,asm);maps+=mapping(p,dst,p.stat().st_size)
   entry=binary('entry_'+name,f' mov_s r12,{dst:#x}\n j_s [r12]\n').read_bytes()[:8]
   b,o=locate(addr,8);before=bytes(images[b['index']][o:o+8]);assert before==raw(addr,8)
   images[b['index']][o:o+8]=entry;patches.append({'name':name,'address':hex(addr),'original':before.hex(),'fixture':entry.hex()})
  tests=[(0x380,0,120),(0x380,120,121),(0x380,3999,0),(0x400,0,119),(0x400,2,1),(0x400,1,0)]
  state=bytearray(len(tests)*64);asm=' mov r20,0x2000000\n'
  for i,(event,value,want) in enumerate(tests):
   a=0x2001000+i*64
   asm+=f''' mov r21,{a:#x}
 st r21,[r20]
 mov r1,0x899ad0
 mov r0,{value}
 st r0,[r1]
 mov r1,0x899ac0
 mov r0,0x2100000
 st r0,[r1]
 st sp,[r21,16]
 mov r0,0
 mov r1,{event:#x}
 mov r2,0
 mov r12,{events[event]:#x}
 jl [r12]
 mov r1,0x899ad0
 ld r0,[r1]
 st r0,[r21]
 mov r1,0x899acc
 ldb r0,[r1]
 st r0,[r21,4]
 st sp,[r21,20]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,image in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(image);maps+=mapping(p,BS[i]['load_address_candidate'],len(image))
  p=out/'cases.bin';p.write_bytes(state);maps+=mapping(p,0x2001000,len(state));statefile=p
  p=out/'current.bin';p.write_bytes(bytes(8));maps+=mapping(p,0x2000000,8)
  p=out/'context.bin';p.write_bytes(bytes(256));maps+=mapping(p,0x2100000,256)
  elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
  got=statefile.read_bytes();rows=[]
  for i,(event,value,want) in enumerate(tests):
   w=struct.unpack_from('<6I',got,i*64);direction=0 if event==0x380 else 1
   assert w[0]==want and w[1]==direction and w[3]==1 and w[4]==w[5],(event,value,w,want)
   rows.append({'event':hex(event),'input':value,'result':w[0],'direction_byte':w[1],'timer_calls':w[3],'stack_preserved':True})
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(__import__('pathlib').Path(__file__).read_bytes())
  r.results.update(status='PASS_DEBUG_TIME_NAVIGATION_BOUNDED',scenarios=rows,
   assumptions=['Original up/down handlers and 7d24bc normalization, synthetic UI state.',
                'Formatting, resource, text, refresh and timer services replaced by explicit fixtures.'],
   limits=['No key hardware, event delivery, timer repeat, display, capture or AE arbitration.',
           'Inputs 0,1,2,120,3999 are synthetic; no claim about physical time units.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS: six synthetic debug exposure navigation cases;',out,flush=True)
if __name__=='__main__':main()
