#!/usr/bin/env python3
"""Run CaptureMenu record state updater and slot handlers on isolated copies."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u16, u32, disasm


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('capture_init_slot_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-capture-init-slot'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); build=json.loads(BUILD.read_text()); sim=LAB/'install/bin/arc-elf32-run'
  assert sha(sim)==build['experimental_sha256']; r.experimental_engine=LAB
  r.input_hashes[str(sim)]=sha(sim); r.input_hashes[str(BUILD)]=sha(BUILD)
  dump=ROOT/'DUMPS/MainCode.dmp'; d=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
  spans=[(0x7cb1b4,0x130),(0x631e98,0x30),(0x631a38,0x1b8),(0x980268,56),(0x9801f8,112)]
  for a,n in spans:
   b,o=locate(a,n); assert raw(a,n)==d[b['offset']+o:b['offset']+o+n],hex(a)
  assert u16(0x98026e)==0x15 and u32(0x980298)==0x9801f8 and raw(0x98029c,1)==b'\x04'
  assert [u16(0x9801f8+28*i+20) for i in range(4)]==[0x87,7,10,0xbb]
  (out/'gnu_windows.txt').write_text(disasm(0x7cb1b4,0x7cb2e4)+disasm(0x631e98,0x631ec8)+disasm(0x631a38,0x631bf0))
  images={i:bytearray(PS[i]) for i in (0,1,2,3,4,5)}; maps=[]; patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm); p=out/(name+'.bin')
   x=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]); assert x.returncode==0,x.stdout
   v=p.read_bytes(); p.write_bytes(v+bytes(8+(-len(v))%8)); return p
  def mapping(p,a,n): return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  cur=' mov r10,0x2000000\n ld r10,[r10]\n'
  count=lambda o:f' ld r11,[r10,{o}]\n add r11,r11,1\n st r11,[r10,{o}]\n'
  services=[('current_resource',0x1457d4,' mov r0,0x4801\n j_s [blink]\n'),
   ('mode_a',0xcad30,cur+' ld r0,[r10,32]\n j_s [blink]\n'),('mode_b',0xca310,cur+' ld r0,[r10,36]\n j_s [blink]\n'),
   ('select',0x631e00,cur+' st r1,[r10,20]\n'+count(16)+' mov r0,0\n j_s [blink]\n'),
   ('state',0x14503c,' mov r0,0\n j_s [blink]\n'),('refresh',0x145150,' mov r0,0\n j_s [blink]\n'),
   ('condition',0x817ba8,' mov r0,0\n j_s [blink]\n'),('action',0x171c30,' mov r0,0\n j_s [blink]\n'),
   ('delay',0x145c3c,' mov r0,0\n j_s [blink]\n'),('attributes',0x1450d8,' mov r0,2\n j_s [blink]\n'),
   ('open',0x1453e4,cur+' st r0,[r10,8]\n st r1,[r10,12]\n'+count(4)+' mov r0,0\n j_s [blink]\n')]
  for i,(name,a,asm) in enumerate(services):
   dst=0x2030000+i*0x400; p=binary(name,asm); maps+=mapping(p,dst,p.stat().st_size)
   entry=binary('entry_'+name,f' mov_s r12,{dst:#x}\n j_s [r12]\n').read_bytes()[:8]
   b,o=locate(a,8); before=bytes(images[b['index']][o:o+8]); assert before==raw(a,8)
   images[b['index']][o:o+8]=entry; patches.append(dict(name=name,address=hex(a),original=before.hex(),fixture=entry.hex()))
  tests=[(a,b,slot) for a,b in ((0,0),(44,7),(44,0)) for slot in (2,3)]
  state=bytearray(len(tests)*64); contexts=bytearray(len(tests)*192); asm=' mov r20,0x2000000\n'
  for i,(a,b,slot) in enumerate(tests):
   s=0x2001000+i*64; c=0x2100000+i*192; rec=c+64
   contexts[i*192:i*192+56]=raw(0x980268,56); contexts[i*192+64:i*192+176]=raw(0x9801f8,112)
   struct.pack_into('<I',contexts,i*192+48,rec)
   # Every initial record has bit 1 set to exercise the updater's clear pass.
   for k in range(4):
    off=i*192+64+28*k+24
    struct.pack_into('<I',contexts,off,struct.unpack_from('<I',contexts,off)[0]|2)
   struct.pack_into('<II',state,i*64+32,a,b)
   h=(0x631a38,0x631b14)[slot-2]; ev=(0x2180,0x2700)[slot-2]
   asm+=f''' mov r21,{s:#x}
 st r21,[r20]
 st sp,[r21,24]
 mov r0,{c:#x}
 mov r1,0x89985c
 st r0,[r1]
 mov r1,0x681b6b
 mov r2,0
 stb r2,[r1]
 mov r12,0x7cb1b4
 jl [r12]
 mov r0,{c:#x}
 mov r1,{ev:#x}
 mov r2,0
 mov r12,{h:#x}
 jl [r12]
 st r0,[r21]
 st sp,[r21,28]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,image in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin'; p.write_bytes(image); maps+=mapping(p,BS[i]['load_address_candidate'],len(image))
  statefile=out/'cases.bin'; statefile.write_bytes(state); maps+=mapping(statefile,0x2001000,len(state))
  contextfile=out/'contexts.bin'; contextfile.write_bytes(contexts); maps+=mapping(contextfile,0x2100000,len(contexts))
  p=out/'current.bin'; p.write_bytes(bytes(8)); maps+=mapping(p,0x2000000,8)
  elf=compile_probe(r,'cases',asm); case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert case['exit_code']==0 and case['fault'] is None,log
  assert 'S33_DSP_GUARD' not in log
  got=statefile.read_bytes(); ctx=contextfile.read_bytes(); rows=[]
  for i,(a,b,slot) in enumerate(tests):
   flags=[struct.unpack_from('<I',ctx,i*192+64+28*k+24)[0] for k in range(4)]
   blocked=(a!=44 or b==7); expected=[8,0,2 if blocked else 0,2 if blocked else 0]
   assert flags==expected,(a,b,slot,flags,expected)
   w=struct.unpack_from('<8I',got,i*64); assert w[0]==1 and w[6]==w[7],w
   assert (w[1],w[4])==((0,0) if blocked else (1,1)),(a,b,slot,w)
   if not blocked: assert (w[2],w[3],w[5])==((10,0,2) if slot==2 else (187,0,3)),w
   rows.append(dict(mode_a=a,mode_b=b,slot=slot,record_flags=flags,open_calls=w[1],destination=(hex(w[2]) if w[1] else None),argument=(w[3] if w[1] else None),stack_preserved=True))
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n'); (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_CAPTURE_INIT_SLOT_LAB',scenarios=rows,
   assumptions=['Original updater and slot handler run directly on copied resource and records; initial bit 1 artificially set in all records.',
    'Resource ID, status getters, selection, attributes and opening are fixtures; experimental GNU DSP v7 for MULUDW.'],
   limits=['No dispatcher, real initialization, active control or task ordering established.',
    'No display, camera, physical inputs, or writable physical memory established.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e)); raise
 finally:r.save()
 print('PASS:',len(tests),'CaptureMenu updater-to-slot cases;',out,flush=True)
if __name__=='__main__':main()
