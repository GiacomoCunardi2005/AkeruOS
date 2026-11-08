#!/usr/bin/env python3
"""Exercise original 20D5C4 with synthetic status and ordinary-storage MMIO."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('liveview_fe80158_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='liveview-fe80158'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();sim=LAB/'install/bin/arc-elf32-run';assert sha(sim)==json.loads(BUILD.read_text())['experimental_sha256'];r.experimental_engine=LAB
  dump=ROOT/'DUMPS/MainCode.dmp'
  for p in (sim,BUILD,dump,Path(__file__)):r.input_hashes[str(p)]=sha(p)
  data=dump.read_bytes()
  for a,n in ((0x20d5c4,0x50),(0x12c9bc,8),(0x1f0980,8),(0x177fa8,8)):
   b,o=locate(a,n);assert raw(a,n)==data[b['offset']+o:b['offset']+o+n]
  images={i:bytearray(PS[i]) for i in (0,1,2,3,4,5)};maps=[];patches=[]
  def mapping(p,a,n):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  def binary(name,asm):
   elf=compile_probe(r,name,asm);p=out/(name+'.bin');q=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert q.returncode==0,q.stdout
   b=p.read_bytes();p.write_bytes(b+bytes(8+(-len(b))%8));return p
  common=' mov r10,0x2000000\n ld r10,[r10]\n'
  services=[('setup',0x12c9bc,' mov r0,0\n j_s [blink]\n'),('status',0x1f0980,common+' ld r0,[r10]\n j_s [blink]\n'),
   ('service',0x177fa8,common+''' ld r11,[r10,4]
 asl r12,r11,4
 add r12,r10,r12
 st r0,[r12,16]
 st r1,[r12,20]
 st r2,[r12,24]
 add r11,r11,1
 st r11,[r10,4]
 mov r0,0
 j_s [blink]
''')]
  for i,(name,a,asm) in enumerate(services):
   dst=0x2030000+i*0x400;p=binary(name,asm);maps+=mapping(p,dst,p.stat().st_size)
   entry=binary('entry_'+name,f' mov_s r12,{dst:#x}\n j_s [r12]\n').read_bytes()[:8]
   b,o=locate(a,8);before=bytes(images[b['index']][o:o+8]);assert before==raw(a,8)
   images[b['index']][o:o+8]=entry;patches.append(dict(name=name,address=hex(a),original=before.hex(),fixture=entry.hex()))
  tests=[(0x1ffff,0xffff),(0x20000,0xffff),(0x20000,0xfffe),(0x20001,1),(0x20001,0)]
  state=bytearray(len(tests)*80);asm=''
  for i,(status,seed) in enumerate(tests):
   struct.pack_into('<I',state,i*80,status);a=0x2001000+i*80
   asm+=f''' mov r20,{a:#x}
 mov r1,0x2000000
 st r20,[r1]
 mov r1,0xfe80158
 mov r0,{seed:#x}
 sth r0,[r1]
 st sp,[r20,48]
 mov r12,0x20d5c4
 jl [r12]
 st r0,[r20,8]
 mov r1,0xfe80158
 ldh r0,[r1]
 st r0,[r20,12]
 st sp,[r20,52]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,d in images.items():
   p=out/f'block{i}.bin';p.write_bytes(d);maps+=mapping(p,BS[i]['load_address_candidate'],len(d))
  p=out/'state.bin';p.write_bytes(state);maps+=mapping(p,0x2001000,len(state))
  q=out/'current.bin';q.write_bytes(bytes(8));maps+=mapping(q,0x2000000,8)
  q=out/'mmio.bin';q.write_bytes(bytes(8));maps+=mapping(q,0xfe80158,8)
  elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert case['exit_code']==0 and case['fault'] is None,log
  got=p.read_bytes();rows=[]
  for i,(status,seed) in enumerate(tests):
   words=struct.unpack_from('<14I',got,i*80);calls=words[1];final=words[3];expected=seed if status<0x20000 else seed&0xfffe
   assert final==expected and words[12]==words[13]
   assert calls==(1 if status<0x20000 else 2),(i,words)
   first=tuple(words[4:7]);second=tuple(words[8:11])
   if calls==2: assert first==(30,3,0x3000) and second[0:2]==(10,3)
   else: assert first[0:2]==(10,3)
   rows.append(dict(status=hex(status),seed=hex(seed),final=hex(final),calls=calls,service_args=[list(first)]+([list(second)] if calls==2 else []),stack_preserved=True))
  trace=(out/'cases.trace').read_text().splitlines()
  assert sum(x.startswith('0x20d5f0 ') for x in trace)==4
  assert sum(x.startswith('0x20d5f8 ') for x in trace)==4
  assert all(sha(p)==r.input_hashes[str(p)] for p in (sim,BUILD,dump,Path(__file__)))
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_FE80158_SYNTHETIC',scenarios=rows,assumptions=['Status and services are fixtures; MMIO is ordinary synthetic storage.'],limits=['No real MMIO effects or timings, liveview transition, GUI, physical camera or button.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS:',len(tests),'cases;',out,flush=True)
if __name__=='__main__':main()
