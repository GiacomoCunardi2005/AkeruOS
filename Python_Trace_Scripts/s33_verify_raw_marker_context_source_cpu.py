#!/usr/bin/env python3
"""Trace the marker context byte from the original snapshot getter in synthetic RAM."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import BUILD,LAB,compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,ORIGINAL,EXPECTED,raw,locate,disasm,u32


def main():
 out=ROOT/'Risultati/Mono_RAW'/datetime.now(timezone.utc).strftime('raw_marker_context_source_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='raw-marker-context-source'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();assert sha(ORIGINAL)==EXPECTED
  dump=ROOT/'DUMPS/MainCode.dmp';data=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  sim=LAB/'install/bin/arc-elf32-run';assert sha(sim)==json.loads(BUILD.read_text())['experimental_sha256']
  r.experimental_engine=LAB;r.input_hashes[str(sim)]=sha(sim);r.input_hashes[str(BUILD)]=sha(BUILD)
  spans=[(0x1b8f82,0x1b8fa8),(0xdf304,0xdf34a),(0xdf46c,0xdf478),(0xf6f14,0xf6f18),(0x128c20,0x128c60)]
  for a,b in spans:
   block,off=locate(a,b-a);assert raw(a,b-a)==data[block['offset']+off:block['offset']+off+b-a]
  assert u32(0xf6f18)==0x380574 and u32(0x1b92d4)==0x368790
  (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in spans))
  images={i:bytearray(PS[i]) for i in range(2)};maps=[];patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm);p=out/(name+'.bin');v=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert v.returncode==0,v.stdout
   data=p.read_bytes();p.write_bytes(data+bytes(8+(-len(data))%8));return p
  def mapping(p,addr):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{addr:#x},{p.stat().st_size}']
  fixtures=[('early_return',0xdf34a,' mov_s r12,0xdf46c\n j_s [r12]\n'),('other_service',0x170aac,' mov r0,0\n j_s [blink]\n'),('stop',0x1b8fa8,' j [r26]\n')]
  for i,(name,addr,asm) in enumerate(fixtures):
   target=0x2030000+i*0x400;p=binary('fixture_'+name,asm);maps+=mapping(p,target)
   entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
   block,off=locate(addr,8);image=images[block['index']];before=bytes(image[off:off+8]);assert before==raw(addr,8)
   image[off:off+8]=entry;patches.append(dict(name=name,address=hex(addr),original=before.hex(),fixture=entry.hex()))
  tests=[('zero',0,0xa5,0x5a),('eleven',11,0x5a,0xa5),('high',202,0x11,0x22)]
  asm=''
  for i,(name,value,left,right) in enumerate(tests):
   case=0x2001000+i*32
   asm+=f''' mov r20,{case:#x}
 mov r1,0x380913
 mov r0,{left}
 stb r0,[r1]
 mov r0,{value}
 stb r0,[r1,1]
 mov r0,{right}
 stb r0,[r1,2]
 mov r1,0x36879c
 mov r0,0xee
 stb r0,[r1]
 st sp,[r20]
 sub sp,sp,256
 add fp,sp,204
 mov r0,10
 st r0,[fp,-204]
 mov r0,0
 st r0,[fp,-196]
 mov r25,0
 mov r13,0
 mov r26,after_{i}
 mov r12,0x1b8f82
 j [r12]
 after_{i}:
 mov r1,0x36879c
 ldb r0,[r1]
 st r0,[r20,4]
 ldb r0,[fp,-160]
 st r0,[r20,8]
 ld sp,[r20]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,image in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(image);maps+=mapping(p,BS[i]['load_address_candidate'])
  p=out/'results.bin';p.write_bytes(bytes(len(tests)*32));maps+=mapping(p,0x2001000)
  elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
  rows=[]
  for i,(name,value,left,right) in enumerate(tests):
   sp,context,local=struct.unpack_from('<3I',p.read_bytes(),32*i)
   assert (context,local)==(value,value),(name,context,local)
   rows.append(dict(case=name,snapshot_byte=value,left_neighbor=left,right_neighbor=right,local=local,context_byte=context))
  trace=(out/'cases.trace').read_text()
  for addr in ('0x1b8f82','0x0df304','0x0f6f14','0x128c20','0x0df344','0x1b8fa6'):
   assert any(line.startswith(addr+' ') for line in trace.splitlines()),addr
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_RAW_CONTEXT_SOURCE_CPU_SYNTHETIC',scenarios=rows,assumptions=['Original 1B8F82 fragment, DF304 prefix, F6F14 and 128C20; early-return trampoline skips remaining getter fields.', 'Caller frame, context, snapshot and neighbor bytes synthetic; service 170AAC fixture.'],limits=['No full DF304, acquisition, scheduler, physical RAM or hardware.', 'No producer of snapshot byte, stability or relationship with real shooting mode established.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS',out,flush=True)
if __name__=='__main__':main()
