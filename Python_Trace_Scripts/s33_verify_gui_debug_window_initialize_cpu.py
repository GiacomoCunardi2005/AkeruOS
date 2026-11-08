#!/usr/bin/env python3
"""Run diagnostic window entry with original 4403 and 4405 handlers."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,locate,u16,u32


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('debug_window_initialize_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-debug-window-initialize'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();dump=ROOT/'DUMPS/MainCode.dmp';data=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x145180,0x270),(0x169d78,0xa4),(0x16a6e4,0xc0),(0x16a028,0x34),(0x16a188,0x74),(0x7d22f0,0x38),(0x7d252c,0x38),(0x7d2328,0x2c),(0x7d2564,0x4c),(0x641128,0x4c),(0x20e814,0x34),(0x169f60,0x54),(0x14510c,0x44),(0x3e8bb4,67*8),(0x989cd8,24),(0x989fcc,24),(0x989da4,480),(0x899ac4,5),(0x3f5900,4)]:
   b,o=locate(a,n);assert raw(a,n)==data[b['offset']+o:b['offset']+o+n],hex(a)
  assert u32(0x3f5900)==0
  assert raw(0x899ac4,5)==b'AUTO\0' and u32(0x989da4+7*20+12)==6
  for a,index,main in [(0x989cd8,0x3e,0x7d22f0),(0x989fcc,0x3f,0x7d252c)]:
   assert u16(a+4)==index and u32(a+12)==main and u32(0x3f5900+index*4)==a
  images={i:bytearray(PS[i]) for i in (0,1,2,4,5)};maps=[];patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm);path=out/(name+'.bin');res=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path]);assert res.returncode==0,res.stdout
   value=path.read_bytes();path.write_bytes(value+bytes(8+(-len(value))%8));return path
  def mapping(path,addr):return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{path.stat().st_size}']
  common=' mov r10,0x2000000\n ld r10,[r10]\n'
  cases=[('time',0x989cd8),('iso',0x989fcc)]
  # 4401, selection, text and final drawing remain fixtures.
  services=[('get_control',0x145790,' mov r0,0x2100000\n j_s [blink]\n'),
   ('get_resource',0x145654,' mov r0,0x2100000\n j_s [blink]\n'),
   ('event_4401',0x16a05c,common+' st r1,[r10,32]\n ld r11,[r10,36]\n add r11,r11,1\n st r11,[r10,36]\n mov r0,0\n j_s [blink]\n'),
   ('select',0x641064,common+' st r1,[r10,48]\n ld r11,[r10,52]\n add r11,r11,1\n st r11,[r10,52]\n mov r0,0\n j_s [blink]\n'),
   ('set_text',0x633020,common+' st r1,[r10,56]\n ld r11,[r10,60]\n add r11,r11,1\n st r11,[r10,60]\n mov r0,0\n j_s [blink]\n'),
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
 mov r1,0x367bc8
 mov r0,6
 stb r0,[r1]
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
  ctx=bytearray(256);ctx[37]=24;ctx[38]=99;struct.pack_into('<I',ctx,64,0x989da4)
  p=out/'control.bin';p.write_bytes(ctx);maps+=mapping(p,0x2100000)
  elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
  trace=(out/'cases.trace').read_text();rows=[];buf=state.read_bytes()
  for i,(name,desc) in enumerate(cases):
   w=struct.unpack_from('<16I',buf,i*96)
   assert (w[0],w[1],w[4]==w[5],w[8],w[9])==(1,desc,True,0x4401,1),(name,w)
   if name=='time':assert (w[13],w[14],w[15])==(0,0x899ac4,1),(name,w)
   else:assert (w[12],w[13],w[15])==(7,1,0),(name,w)
   rows.append(dict(screen=name,descriptor=hex(desc),manager_result=w[0],current=hex(w[1]),event_4401_calls=w[9],selected_index=w[12] if name=='iso' else None,selection_calls=w[13] if name=='iso' else 0,text_pointer=hex(w[14]) if name=='time' else None,text_calls=w[15],stack_preserved=True))
  for address in ('0x169d78','0x16a6e4','0x16a028','0x16a188','0x7d22f0','0x7d252c','0x7d2328','0x7d2564','0x14510c'):
   assert address in trace,address
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_DEBUG_WINDOW_4405_INITIALIZATION_BOUNDED',scenarios=rows,assumptions=['Original manager, dispatch, 4405 handlers, debug wrappers and original ISO list; synthetic manager and control state.', 'Control retrieval, 4401, ISO selection, text and drawing are fixtures.'],limits=['Does not execute real 4401, actual control selection or rendering, actual runtime lifecycle, physical input or camera.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS: two diagnostic manager initializations with bounded fixtures;',out,flush=True)
if __name__=='__main__':main()
