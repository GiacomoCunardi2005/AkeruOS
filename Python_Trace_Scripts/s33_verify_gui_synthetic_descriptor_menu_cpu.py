#!/usr/bin/env python3
"""Connect original key/queue/manager dispatcher to C menu via a synthetic descriptor."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('synthetic_descriptor_menu_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='synthetic-descriptor-menu-model'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); build=json.loads(BUILD.read_text()); sim=LAB/'install/bin/arc-elf32-run'
  assert sha(sim)==build['experimental_sha256']; r.experimental_engine=LAB
  sources=[ROOT/'AkeruOS/ui/menu.c',ROOT/'AkeruOS/ui/menu.h',Path(__file__),ROOT/'DUMPS/MainCode.dmp',sim,BUILD]
  for p in sources:r.input_hashes[str(p)]=sha(p)
  dump=sources[3].read_bytes()
  for address,size in [(0x16f6a4,0x88),(0x16f72c,0x13c),(0x17bc7c,0x68),(0x17bd4c,0x4c),(0x169d78,0x124),(0x16a028,0x34),(0x16a6e4,0xc0),(0x145020,0x5c),(0x77f728,0x58),(0x9802ac,0x1c),(0x7cafe8,8)]:
   block,offset=locate(address,size);assert raw(address,size)==dump[block['offset']+offset:block['offset']+offset+size]
  images={i:bytearray(PS[i]) for i in (0,1,2,3,4,5)};maps=[];patches=[]
  def run(name,args):
   result=r.command(name,args);assert result.returncode==0,result.stdout;return result.stdout
  def mapping(p,a,n):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  stub=compile_probe(r,'noop',' mov r0,0\n j_s [blink]\n');p=out/'noop.bin'
  run('extract_stub',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',stub,p]);b=p.read_bytes();p.write_bytes(b+bytes(8+(-len(b))%8));maps+=mapping(p,0x2030000,p.stat().st_size)
  entry=compile_probe(r,'noop_entry',' mov_s r12,0x2030000\n j_s [r12]\n');p=out/'noop_entry.bin'
  run('extract_entry',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',entry,p]);patch=p.read_bytes()[:8]
  for address in (0x1593ac,0x1594a4,0x1786e8,0x179354,0x158cbc,0x17c150):
   block,offset=locate(address,8);before=bytes(images[block['index']][offset:offset+8]);assert before==raw(address,8)
   images[block['index']][offset:offset+8]=patch;patches.append(dict(address=hex(address),original=before.hex(),fixture=patch.hex()))
  keys=[11,14,67,78];events=[0x580,0x700,0x2180,0x2700]
  actions=[[1,1,0,7],[1,2,3,4],[1,5,6,0]]
  views=[[1,2,0,0],[0,1,1,1],[0,2,2,2]]
  tests=[(view,slot) for view in range(3) for slot in range(4)]
  asm=' mov r20,0x2000000\n'
  for i,(view,slot) in enumerate(tests):
   a=0x2001000+i*96
   asm+=f''' mov r21,{a:#x}
 st r21,[r20]
 mov r0,{view}
 st r0,[r21]
 st sp,[r21,24]
 mov r0,0
 mov r1,0x681b6b
 stb r0,[r1]
 mov r1,0x367bbc
 st r0,[r1]
 mov r1,0x3678f9
 mov r0,1
 stb r0,[r1]
 mov r1,{0x446808+keys[slot]*4+2:#x}
 sth r0,[r1]
 mov r0,255
 mov r1,{keys[slot]}
 mov r2,1
 mov r3,1
 mov r12,0x16f72c
 jl [r12]
 mov r0,{a+32:#x}
 mov r12,0x17bd4c
 jl [r12]
 st r0,[r21,44]
 mov r1,0x366e94
 mov r0,0x77f728
 st r0,[r1]
 mov r0,22
 sth r0,[r1,4]
 mov r0,0x2050000
 st r0,[r1,16]
 mov r0,0
 st r0,[r1,24]
 mov r1,0x367814
 mov r0,1
 stb r0,[r1]
 ld r0,[r21,32]
 ldh.x r1,[r21,36]
 ld r2,[r21,40]
 mov r12,0x169e1c
 jl [r12]
 st r0,[r21,8]
 ld r0,[r21,4]
 st r0,[r21,64]
 mov r0,255
 mov r1,{keys[slot]}
 mov r2,0
 mov r3,1
 mov r12,0x16f72c
 jl [r12]
 mov r0,{a+48:#x}
 mov r12,0x17bd4c
 jl [r12]
 st r0,[r21,60]
 mov r0,99
 st r0,[r21,4]
 ld r0,[r21,48]
 ldh.x r1,[r21,52]
 ld r2,[r21,56]
 mov r12,0x169e1c
 jl [r12]
 st r0,[r21,16]
 ld r0,[r21,4]
 st r0,[r21,12]
 ld r0,[r21]
 st r0,[r21,20]
 st sp,[r21,28]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\nmenu_callback:\n push_s blink\n mov r0,0x2000000\n ld r0,[r0]\n add r2,r0,4\n bl akeru_menu_event\n pop_s blink\n j_s [blink]\n'
  statefile=out/'cases.bin';statefile.write_bytes(bytes(len(tests)*96));maps+=mapping(statefile,0x2001000,len(tests)*96)
  p=out/'current.bin';p.write_bytes(bytes(8));maps+=mapping(p,0x2000000,8)
  for name,addr in (('key_state',0x446000),('queue',0x47a000)):
   p=out/(name+'.bin');p.write_bytes(bytes(0x2000));maps+=mapping(p,addr,0x2000)
  flags=['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-O2','-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-c']
  run('compile_menu',flags+[sources[0],'-o',out/'menu.o'])
  (out/'cases.s').write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n'+asm+'\n.section .stack,"aw",@nobits\n.align 16\n.space 16384\n')
  run('assemble',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',out/'cases.o',out/'cases.s'])
  run('link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',LEGACY/'tests/smoke.ld','-o',out/'cases.elf',out/'cases.o',out/'menu.o'])
  assert not run('undefined',['arc-snps-elf-nm','-u',out/'cases.elf']).strip()
  symbols=run('symbols',['arc-snps-elf-nm',out/'cases.elf']).splitlines()
  entries=[int(line.split()[0],16) for line in symbols if line.endswith(' T akeru_menu_event')]
  assert len(entries)==1
  callbacks=[int(line.split()[0],16) for line in symbols if line.endswith(' t menu_callback')]
  assert len(callbacks)==1
  block,offset=locate(0x7cafe8,8)
  assert bytes(images[block['index']][offset:offset+8])==raw(0x7cafe8,8)
  descriptor=bytearray(raw(0x9802ac,28))
  assert struct.unpack_from('<I',descriptor,12)[0]==0x7cafe8
  struct.pack_into('<I',descriptor,12,callbacks[0])
  p=out/'synthetic_descriptor.bin';p.write_bytes(descriptor+bytes(4));maps+=mapping(p,0x2050000,32)
  (out/'descriptor_change.json').write_text(json.dumps(dict(source='0x9802ac',synthetic_address='0x2050000',original_callback='0x7cafe8',synthetic_callback=hex(callbacks[0]),original_descriptor=raw(0x9802ac,28).hex(),synthetic_descriptor=descriptor.hex()),indent=2)+'\n')
  for i,image in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(image);maps+=mapping(p,BS[i]['load_address_candidate'],len(image))
  case,log=r.run('cases','/result/cases.elf',maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
  assert 'S33_DSP_GUARD' not in log
  data=statefile.read_bytes();rows=[]
  for i,(view,slot) in enumerate(tests):
   w=struct.unpack_from('<17I',data,i*96)
   assert (w[0],w[1],w[2],w[3],w[4],w[5],w[16])==(views[view][slot],0,1,0,1,views[view][slot],actions[view][slot]) and w[6]==w[7],(view,slot,w)
   assert struct.unpack_from('<Ih2xII',data,i*96+32)==(0,events[slot],0,1)
   assert struct.unpack_from('<Ih2xII',data,i*96+48)==(0,events[slot]|1,0,1)
   rows.append(dict(initial_screen=view,logical_key=keys[slot],event=hex(events[slot]),action=w[16],screen=w[0],handled=w[2],release_action=w[3],release_handled=w[4],stack_preserved=True))
  trace=(out/'cases.trace').read_text()
  assert sum(int(line.split()[0],16)==entries[0] for line in trace.splitlines() if line.startswith('0x'))==24
  assert sum(int(line.split()[0],16)==callbacks[0] for line in trace.splitlines() if line.startswith('0x'))==24
  for address in ('0x16f72c','0x16f6b0','0x17bc7c','0x17bd4c','0x169e1c','0x169d78','0x14505c'):
   assert any(line.startswith(address+' ') for line in trace.splitlines()),address
  assert all(sha(p)==r.input_hashes[str(p)] for p in sources)
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_SYNTHETIC_DESCRIPTOR_TO_C_MENU',scenarios=rows,
   assumptions=['Original logical key writer, event producer, queue and manager dispatch on synthetic state; A synthetic copy of the CaptureMenu descriptor points to a laboratory bridge to ARC700 C menu; original callback bytes unchanged.',
                'Harness explicitly extracts each event and calls dispatcher 169E1C; current descriptor and absence of active control are synthetic; synchronization, notification and filtering are fixtures.'],
   limits=['No physical input, scheduler, menu lifecycle, rendering or integration into original firmware.',
           'Event state 1/0 does not establish physical key polarity; actions are requests, not applied settings.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS:',len(tests),'synthetic-descriptor menu cases;',out,flush=True)
if __name__=='__main__':main()
