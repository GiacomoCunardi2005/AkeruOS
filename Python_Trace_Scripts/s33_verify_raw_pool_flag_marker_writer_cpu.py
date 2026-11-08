#!/usr/bin/env python3
"""Run original state producer and pool acquisition using synthetic services."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, re, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, disasm, ORIGINAL, EXPECTED


def main():
 out=ROOT/'Risultati/Mono_RAW'/datetime.now(timezone.utc).strftime('pool_flag_marker_writer_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='synthetic-pool-flag-marker-writer'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); assert sha(ORIGINAL)==EXPECTED; build=json.loads(BUILD.read_text()); sim=LAB/'install/bin/arc-elf32-run'; assert sha(sim)==build['experimental_sha256']; r.experimental_engine=LAB; r.input_hashes[str(sim)]=sha(sim); r.input_hashes[str(BUILD)]=sha(BUILD); dump=ROOT/'DUMPS/MainCode.dmp'; data=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
  for addr,size in [(0x18e1c8,0x80),(0x18e4b4,0x120),(0x18e8b4,0x44),(0x18ed60,0xec),(0x141ce0,0xa0),(0xc78a0,0x10),(0x12be64,0x10),(0xcbaf0,0x110),(0x141cc4,0x24),(0xd08ec,0x40),(0xcad30,8),(0x28d5bc,0xac),(0x35231c,32),(0x65f230,0x36),(0x1b9ea8,0x78),(0x1b8f24,0xe4)]:
   b,o=locate(addr,size); assert raw(addr,size)==data[b['offset']+o:b['offset']+o+size]
  (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in [(0x18e1c8,0x18e248),(0x18e4b4,0x18e5d4),(0x18e8b4,0x18e8f8),(0x18ed60,0x18ee48),(0x141ce0,0x141d80),(0xc78a0,0xc78b0),(0x12be64,0x12be74),(0xcbaf0,0xcbbb4),(0xcbbc8,0xcbbd4),(0x141cc4,0x141cda),(0x141ce0,0x141ce8),(0xd08ec,0xd0924),(0xcad30,0xcad38)]))
  flow='\n'.join(disasm(a,b) for a,b in [(0x65f230,0x65f266),(0x1b9ea8,0x1b9f20),(0x1b8f24,0x1b9008)])
  for addr,operation,arg in [(0x65f25c,'mov_s','r2,0'),(0x65f262,'bl',';0x1b9ea8'),(0x1b9eba,'mov_s','r21,r2'),(0x1b9f0e,'mov_s','r2,r21'),(0x1b9f1e,'bl_s',';0x1b8f24'),(0x1b8f3c,'st','r2,[fp,-200]'),(0x1b8ffc,'ld','r0,[fp,-200]'),(0x1b9004,'bl',';0x18ed60')]:
   line=next(line for line in flow.splitlines() if re.match(rf'^\s*{addr:x}:',line))
   assert re.search(rf'\b{re.escape(operation)}\s',line) and arg in line,line
  (out/'capture_flow.txt').write_text(flow)
  images={i:bytearray(PS[i]) for i in range(2)}; maps=[]; patches=[]
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
   0x12845c:('state_predicate_service',' mov r0,0\n j_s [blink]\n'),
   0xde1f4:('state_completion',' mov r0,0\n j_s [blink]\n'),
   0x1436a4:('config',' mov r0,0\n j_s [blink]\n'),
   0xc784c:('region_mode',' mov r0,0\n j_s [blink]\n'),
   0x141e14:('event',' mov r0,0\n j_s [blink]\n'),
   0x141ed8:('intermediate',' mov r0,0\n j_s [blink]\n'),
   0x28d4d4:('writer',' mov r10,0x2210000\n st r2,[r10]\n st r3,[r10,4]\n mov r0,1\n st r0,[r10,8]\n mov r0,0\n j_s [blink]\n'),
   0x1b933a:('stop',' j [r26]\n')}
  for i,(addr,(name,asm)) in enumerate(fixtures.items()):
   dest=0x2030000+i*0x1000; path=binary('fixture_'+name,asm);maps+=mapping(path,dest)
   entry=binary('entry_'+name,f' mov_s r12,{dest:#x}\n j_s [r12]\n').read_bytes()[:8]
   b,o=locate(addr,8);image=images[b['index']];assert bytes(image[o:o+8])==raw(addr,8)
   patches.append(dict(address=hex(addr),name=name,original=bytes(image[o:o+8]).hex(),fixture=entry.hex()))
   image[o:o+8]=entry
  tests=[('state_0a',0,2,10)]
  # Region, reserved sizes, and descriptor count are synthetic.
  asm=' mov r0,0x366000\n mov r1,0x1000\n mov r12,0xad90c\n jl [r12]\n mov r0,0x368000\n mov r1,0x1000\n mov r12,0xad90c\n jl [r12]\n'
  for i,(name,first,second,state) in enumerate(tests):
   n=2; size=0x10000000
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
 mov r1,0x366e34
 mov r0,2
 st r0,[r1]
 mov r1,0xc8e80c
 mov r0,4
 stb r0,[r1]
 mov r0,{first}
 mov r1,{second}
 mov r2,0
 add r3,r20,44
 mov r12,0xcbaf0
 jl [r12]
 mov r1,0x366e34
 ld r0,[r1]
 st r0,[r20,48]
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
 mov r1,0x47d6e4
 ld r0,[r1]
 st r0,[r20,40]
 mov r1,0x2200000
 ld r0,[r1]
 st r0,[r20,16]
 st sp,[r20,68]
 mov r1,0x36c26e
 mov r0,1
 stb r0,[r1]
 mov r1,0x366f90
 mov r0,3
 st r0,[r1]
 mov r1,0x36879c
 mov r0,0
 stb r0,[r1]
 mov r1,0x2020000
 ld r0,[r20,24]
 st r0,[r1]
 st sp,[r20,72]
 bl gate_{i}
 b after_{i}
 .align 4
 gate_{i}:
 push_s blink
 mov r12,0x334104
 jl [r12]
 st.aw fp,[sp,-4]
 mov fp,sp
 sub sp,sp,204
 mov r0,10
 st r0,[fp,-204]
 mov r15,0x2020000
 mov r16,0
 mov r26,after_{i}
 mov r12,0x1b91ec
 j [r12]
 after_{i}:
 ld sp,[r20,72]
 mov r1,0x2210000
 ld r0,[r1]
 st r0,[r20,80]
 ld r0,[r1,4]
 st r0,[r20,84]
 ld r0,[r1,8]
 st r0,[r20,88]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,image in images.items():
   path=out/f'block{i}_LAB_FIXTURE.bin';path.write_bytes(image);maps+=mapping(path,BS[i]['load_address_candidate'])
  for name,addr,size in [('state.bin',0x2000000,128*len(tests)),('outer.bin',0x2020000,16),('writer.bin',0x2210000,16),('queue.bin',0x2200000,256),('region.bin',0x2400000,0xb000+4208*3152+31*2*4208+64),('mode.bin',0xc8e000,0x1000),('tables.bin',0x47d000,0x1000)]:
   p=out/name
   if name=='region.bin':
    initial=bytearray([0xa4])*size; bits=list(raw(0x35231c,32))
    offsets=[0xb000+4208*3152+i*2*4208 for i in range(32)]
    for i,off in enumerate(offsets):initial[off]=0xa4|(bits[i]^1)
    p.write_bytes(initial)
   else:p.write_bytes(bytes(size))
   maps+=mapping(p,addr)
  elf=compile_probe(r,'cases',asm); case,log=r.run('cases','/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
  values=(out/'state.bin').read_bytes(); rows=[]
  for i,(name,first,second,state) in enumerate(tests):
   w=struct.unpack_from('<18I',values,i*128)
   expected_data=0x2400000+0x1000+2*0x5000
   assert (w[11]&255)==state and w[12]==0 and w[1]==0 and w[5]==0x47d6d0 and w[6]==0x2400000 and w[7]==1 and w[8]==expected_data and w[10]-w[8]==0xca6400 and w[16]==w[17], (name,w)
   pointer,length,calls=struct.unpack_from('<3I',values,i*128+80);assert (pointer,length,calls)==(expected_data,26527232,1)
   rows.append(dict(case=name,first=first,second=second,state=w[11]&255,pool_selector_after_producer=w[12],descriptor=hex(w[6]),first_data=hex(w[8]),second_data=hex(w[10]),stride=hex(w[10]-w[8]),stack_preserved=True))
  result=(out/'region.bin').read_bytes()
  changed=[i for i in range(0xb000,len(initial)) if initial[i]!=result[i]]
  assert changed==offsets,(len(changed),changed[:5])
  second=0xb000+0xca6400
  assert sum(i>=second for i in changed)==31
  trace=(out/'cases.trace').read_text()
  for pc in ('0x18ed60','0x18e4b4','0x1b91ec','0x28d5bc','0x1b9292','0x1b9336'):
   assert any(line.startswith(pc+' ') for line in trace.splitlines()),pc
  lines=trace.splitlines()
  marker_index=next(i for i,line in enumerate(lines) if line.startswith('0x28d5bc '))
  writer_index=next(i for i,line in enumerate(lines) if line.startswith('0x1b9336 '))
  assert marker_index < writer_index
  rows[0].update(writer_requested=26527232,writer_pointer=hex(expected_data),marker_changes=len(changed),before_second=sum(i<second for i in changed),at_or_after_second=sum(i>=second for i in changed),marker_offsets_from_second=[i-second for i in changed])
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_SYNTHETIC_POOL_FLAG_MARKER_WRITER_CPU',scenarios=rows,assumptions=['Original CBAF0 state producer and 18ED60, 141CE8 and pool initializer; invocations sequenced by harness; inputs synthetic; experimental DSP simulator.', 'State predicate service and completion, lock, zero, region, queue, metadata and conditions are fixtures; no concurrency.'],limits=['State producer inputs, mode, initial pool selector, region and queue, reserved sizes, and descriptor count are synthetic; pointers are not dereferenced.', 'Gate entered directly; marker original, writer fixture; no capture, sensor, true pool allocation, physical RAM or JPEG verified.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS: synthetic pool, flag, marker and writer gate;',out,flush=True)
if __name__=='__main__':main()
