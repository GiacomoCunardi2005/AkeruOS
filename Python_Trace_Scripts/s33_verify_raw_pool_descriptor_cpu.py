#!/usr/bin/env python3
"""Run original pool allocation and descriptor acquisition using synthetic services."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, disasm


def main():
 out=ROOT/'Risultati/Mono_RAW'/datetime.now(timezone.utc).strftime('pool_descriptor_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='synthetic-raw-pool-descriptor'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); build=json.loads(BUILD.read_text()); sim=LAB/'install/bin/arc-elf32-run'; assert sha(sim)==build['experimental_sha256']; r.experimental_engine=LAB; r.input_hashes[str(sim)]=sha(sim); r.input_hashes[str(BUILD)]=sha(BUILD); dump=ROOT/'DUMPS/MainCode.dmp'; data=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
  for addr,size in [(0x18e1c8,0x80),(0x18e4b4,0x120),(0x18e8b4,0x44),(0x18ed60,0xec)]:
   b,o=locate(addr,size); assert raw(addr,size)==data[b['offset']+o:b['offset']+o+size]
  (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in [(0x18e1c8,0x18e248),(0x18e4b4,0x18e5d4),(0x18e8b4,0x18e8f8),(0x18ed60,0x18ee48)]))
  image=bytearray(PS[0]); maps=[]; patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm); path=out/(name+'.bin'); p=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path]); assert p.returncode==0,p.stdout
   content=path.read_bytes(); path.write_bytes(content+bytes(8+(-len(content))%8)); return path
  def mapping(path,addr):return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{path.stat().st_size}']
  fixtures={
   0x1593ac:('lock', ' mov r0,0\n j_s [blink]\n'),
   0x1594a4:('unlock',' mov r0,0\n j_s [blink]\n'),
   0xad90c:('zero',' mov r2,0\n cmp r1,0\n beq 2f\n1: stb r2,[r0]\n add r0,r0,1\n sub.f r1,r1,1\n bne 1b\n2: j_s [blink]\n'),
   0x12a71c:('region',' mov r3,0x2400000\n st r3,[r1]\n mov r3,0x2200000\n ld r3,[r3,8]\n st r3,[r2]\n mov r0,0\n j_s [blink]\n'),
   0x27722c:('queue_push',' mov r2,0x2200000\n ld r3,[r2]\n asl r12,r3,2\n add r12,r12,r2\n st r1,[r12,32]\n add r3,r3,1\n st r3,[r2]\n mov r0,0\n j_s [blink]\n'),
   0x277244:('queue_pop',' mov r2,0x2200000\n ld r3,[r2,4]\n ld r12,[r2]\n cmp r3,r12\n bhs 1f\n asl r12,r3,2\n add r12,r12,r2\n ld r12,[r12,32]\n st r12,[r1]\n add r3,r3,1\n st r3,[r2,4]\n mov r0,0\n j_s [blink]\n1: mov r0,0x200402\n j_s [blink]\n'),
   0x12a748:('metadata',' mov r2,0x12345678\n st r2,[r1,12]\n mov r0,0\n j_s [blink]\n'),
   0x141ce8:('open',' mov r0,0\n j_s [blink]\n'),
   0x141e14:('event',' mov r0,0\n j_s [blink]\n')}
  for i,(addr,(name,asm)) in enumerate(fixtures.items()):
   dest=0x2030000+i*0x1000; path=binary('fixture_'+name,asm);maps+=mapping(path,dest)
   entry=binary('entry_'+name,f' mov_s r12,{dest:#x}\n j_s [r12]\n').read_bytes()[:8]
   b,o=locate(addr,8);assert b['index']==0 and bytes(image[o:o+8])==raw(addr,8)
   patches.append(dict(address=hex(addr),name=name,original=bytes(image[o:o+8]).hex(),fixture=entry.hex()))
   image[o:o+8]=entry
  tests=[('no_frames',2,0xD000,0),('one_frame',2,0x1D000,1),('four_frames',2,0x4D000,4),('twenty_cap',2,0x1ED000,20),('no_descriptor',0,0x13000,1)]
  # pool reserved = 0x1000 + 0x2000 + descriptor_count * 0x5000; frame=0x10000
  asm=''
  for i,(name,n,size,frames) in enumerate(tests):
   s=0x2000000+128*i
   asm+=f''' mov r20,{s:#x}
 mov r1,0x2200000
 mov r0,0
 st r0,[r1]
 st r0,[r1,4]
 mov r0,{size:#x}
 st r0,[r1,8]
 mov r1,0x47d7c4
 mov r0,0
 st r0,[r1]
 mov r1,0x2400004
 st r0,[r1]
 st r0,[r1,4]
 mov r1,0x368024
 st r0,[r1,28]
 st r0,[r1,32]
 stb r0,[r1,24]
 mov r0,0x1000
 st r0,[r1,16]
 mov r0,0x2000
 st r0,[r1,20]
 mov r0,{n}
 stb r0,[r1,52]
 st sp,[r20,64]
 mov r0,8
 mov r1,0x10000
 mov r2,{s+8:#x}
 mov r3,{s+12:#x}
 mov r12,0x18e4b4
 jl [r12]
 st r0,[r20]
 mov r1,0x2200000
 ld r0,[r1]
 st r0,[r20,16]
 mov r0,0
 mov r1,{s+24:#x}
 mov r2,0
 mov r12,0x18ed60
 jl [r12]
 st r0,[r20,4]
 mov r1,0x368040
 ld r0,[r1]
 st r0,[r20,20]
 mov r1,0x47d7c4
 ld r0,[r1]
 st r0,[r20,28]
 mov r1,0x2400004
 ld r0,[r1]
 st r0,[r20,32]
 mov r1,0x2400008
 ld r0,[r1]
 st r0,[r20,36]
 st sp,[r20,68]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  path=out/'block0_LAB_FIXTURE.bin';path.write_bytes(image);maps+=mapping(path,BS[0]['load_address_candidate'])
  for name,addr,size in [('state.bin',0x2000000,128*len(tests)),('queue.bin',0x2200000,256),('region.bin',0x2400000,0x1000),('context.bin',0x368000,0x1000),('tables.bin',0x47d000,0x1000)]:
   p=out/name;p.write_bytes(bytes(size));maps+=mapping(p,addr)
  elf=compile_probe(r,'cases',asm); case,log=r.run('cases','/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
  values=(out/'state.bin').read_bytes(); rows=[]
  for i,(name,n,size,frames) in enumerate(tests):
   w=struct.unpack_from('<18I',values,i*128); expected_data=0x2400000+0x1000+n*0x5000
   assert w[0]==0 and w[2]==frames and w[4]==frames and (w[3]&255)==bool(frames) and w[16]==w[17],(name,w)
   if frames and n:
    assert (w[1],w[5],w[6],w[7],w[8],w[9])==(0,0x47d6d0,0x2400000,1,expected_data,0x12345678),(name,w)
   elif frames:
    assert w[1]==0x40100003 and w[5]==0x47d6d0 and w[6]==0,(name,w)
   else:
    assert w[1]==0x40100003 and w[5]==0 and w[6]==0,(name,w)
   rows.append(dict(case=name,descriptors=n,region_size=hex(size),frame_count=frames,init_return=hex(w[0]),acquire_return=hex(w[1]),queue_node=hex(w[5]),descriptor=hex(w[6]),descriptor_state=w[7],descriptor_data=hex(w[8]),descriptor_metadata=hex(w[9]),stack_preserved=True))
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_SYNTHETIC_POOL_DESCRIPTOR',scenarios=rows,assumptions=['Original pool initializer, arithmetic helpers, descriptor initialize/reserve, acquire and queue wrapper; all inputs are synthetic; experimental DSP simulator.', 'Services lock, zero, region, queue, metadata and condition are fixtures, with no concurrency.'],limits=['Region and queue addresses, size, reserved space and frame size are synthetic, not measured camera RAM or RAW dimensions.', 'Direct calls bypass caller, capture, DSP, image pipeline and physical devices; no actual frame, CFA packing, buffer lifetime or hardware proven.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS: five synthetic pool/descriptor cases;',out,flush=True)
if __name__=='__main__':main()
