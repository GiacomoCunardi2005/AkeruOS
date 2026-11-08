#!/usr/bin/env python3
"""Run manager -> original 4403 delivery -> diagnostic UI wrapper on synthetic RAM."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,locate,u16,u32


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('debug_window_entry_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-debug-window-entry'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();dump=ROOT/'DUMPS/MainCode.dmp';data=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x145180,0x270),(0x169d78,0xa4),(0x16a6e4,0xc0),(0x16a028,0x34),(0x7d22f0,0x38),(0x7d252c,0x38),(0x20e814,0x34),(0x169f60,0x54),(0x14510c,0x44),(0x3e8bb4,67*8),(0x989cd8,24),(0x989fcc,24),(0x3f5900,4)]:
   b,o=locate(a,n);assert raw(a,n)==data[b['offset']+o:b['offset']+o+n],hex(a)
  assert u32(0x3f5900)==0
  for a,index,main in [(0x989cd8,0x3e,0x7d22f0),(0x989fcc,0x3f,0x7d252c)]:
   assert u16(a+4)==index and u32(a+12)==main and u32(0x3f5900+index*4)==a
  images={i:bytearray(PS[i]) for i in (0,1,4,5)};maps=[];patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm);path=out/(name+'.bin');res=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path]);assert res.returncode==0,res.stdout
   value=path.read_bytes();path.write_bytes(value+bytes(8+(-len(value))%8));return path
  def mapping(path,addr):return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{path.stat().st_size}']
  common=' mov r10,0x2000000\n ld r10,[r10]\n'
  cases=[('time',0x989cd8),('iso',0x989fcc)]
  # 4401, 4405 and final drawing are deliberately not executed here.
  services=[('get_control',0x145790,' mov r0,0\n j_s [blink]\n'),
   ('event_4401',0x16a05c,common+' st r1,[r10,32]\n ld r11,[r10,36]\n add r11,r11,1\n st r11,[r10,36]\n mov r0,0\n j_s [blink]\n'),
   ('event_4405',0x16a188,common+' st r1,[r10,40]\n ld r11,[r10,44]\n add r11,r11,1\n st r11,[r10,44]\n mov r0,-2\n j_s [blink]\n'),
   ('render_a',0x145150,' mov r0,0\n j_s [blink]\n'),('render_b',0x145158,' mov r0,0\n j_s [blink]\n')]
  for i,(name,addr,asm) in enumerate(services):
   target=0x2030000+i*0x400;path=binary(name,asm);maps+=mapping(path,target)
   entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
   b,o=locate(addr,8);before=bytes(images[b['index']][o:o+8]);assert before==raw(addr,8);images[b['index']][o:o+8]=entry
   patches.append(dict(name=name,address=hex(addr),original=before.hex(),fixture=entry.hex()))
  asm=' mov r20,0x2000000\n'
  for i,(name,desc) in enumerate(cases):
   s=0x2001000+i*96
   asm+=f''' mov r21,{s:#x}
 st r21,[r20]
 mov r1,0x366e94
 mov r0,0x3f5900
 st r0,[r1,8]
 mov r0,197
 sth r0,[r1,12]
 mov r0,0
 st r0,[r1,16]
 st r0,[r1,20]
 stb r0,[r1,39]
 mov r1,0x367808
 st r0,[r1]
 mov r1,0x367810
 st r0,[r1]
 st sp,[r21,16]
 mov r0,{desc:#x}
 mov r1,123
 mov r12,0x145180
 jl [r12]
 st r0,[r21]
 mov r1,0x366e94
 ld r0,[r1,16]
 st r0,[r21,4]
 st sp,[r21,20]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,img in images.items():
   path=out/f'block{i}_LAB_FIXTURE.bin';path.write_bytes(img);maps+=mapping(path,BS[i]['load_address_candidate'])
  state=out/'cases.bin';state.write_bytes(bytes(len(cases)*96));maps+=mapping(state,0x2001000)
  p=out/'current.bin';p.write_bytes(bytes(8));maps+=mapping(p,0x2000000)
  elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
  trace=(out/'cases.trace').read_text();rows=[];buf=state.read_bytes()
  for i,(name,desc) in enumerate(cases):
   w=struct.unpack_from('<12I',buf,i*96)
   assert (w[0],w[1],w[4]==w[5],w[8],w[9],w[10],w[11])==(1,desc,True,0x4401,1,0x4405,1),(name,w)
   rows.append(dict(screen=name,descriptor=hex(desc),manager_result=w[0],current=hex(w[1]),event_4401_calls=w[9],event_4405_calls=w[11],stack_preserved=True))
  for address in ('0x169d78','0x16a6e4','0x16a028','0x7d22f0','0x7d252c','0x14510c'):
   assert address in trace,address
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_DEBUG_WINDOW_4403_ENTRY_BOUNDED',scenarios=rows,assumptions=['Original manager and event 4403 dispatch to original debug wrappers with original descriptors and tables; synthetic manager state.', 'Control retrieval, 4401, 4405, and final rendering are fixtures; 4405 returns synthetic -2.'],limits=['Does not execute real 4401/4405, rendering, actual runtime lifecycle, physical input or camera.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS: two diagnostic manager entry paths with bounded fixtures;',out,flush=True)
if __name__=='__main__':main()
