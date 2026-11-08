#!/usr/bin/env python3
"""Run the original F7844 entry with synthetic services and two selectors."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, locate, raw


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('iris_original_entry_cpu_%Y%m%dT%H%M%S%fZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='iris-original-entry'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); dump=ROOT/'DUMPS/MainCode.dmp'; data=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0xf7844,0xa2),(0xf7ab0,0xe),(0x149548,0x74),(0x18b8d4,0x100),(0x235a10,0x1c8)]:
   b,o=locate(a,n); assert raw(a,n)==data[b['offset']+o:b['offset']+o+n]
  images={i:bytearray(PS[i]) for i in (0,1,4,5)}; maps=[]; patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm); p=out/(name+'.bin')
   assert r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]).returncode==0
   d=p.read_bytes(); p.write_bytes(d+bytes(8+(-len(d))%8)); return p
  def mapping(p,a):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{p.stat().st_size}']
  common=' mov r10,0x2000000\n ld r10,[r10]\n'
  epilogue=' mov r12,0xf7ab2\n j [r12]\n'
  services=[
   ('skip_path',0xf7952,common+' mov r11,1\n st r11,[r10,4]\n'+epilogue),
   ('fragment_exit',0xf78e6,common+' mov r11,2\n st r11,[r10,4]\n st r20,[r10,8]\n'+epilogue),
   ('resource_acquire',0x2c4984,common+' mov r11,0x4567\n st r11,[r2]\n mov r0,0\n j_s [blink]\n'),
   ('resource_register',0xc9664,' mov r0,0\n j_s [blink]\n'),('resource_unlock',0xc9700,' mov r0,0\n j_s [blink]\n'),
   ('resource_ready',0x234e28,' mov r0,0\n j_s [blink]\n'),('helper_busy',0x235da0,' mov r0,0\n j_s [blink]\n'),
   ('request_busy',0x234f1c,' mov r0,0\n j_s [blink]\n'),('lock',0x1786e8,' mov r0,0\n j_s [blink]\n'),
   ('unlock',0x179354,' mov r0,0\n j_s [blink]\n'),('event_clear',0x158ce0,' mov r0,0\n j_s [blink]\n'),
   ('post',0x145f28,common+' st r1,[r10,12]\n ld r11,[r10,16]\n add r11,r11,1\n st r11,[r10,16]\n mov r0,0\n j_s [blink]\n')]
  services += [(name,a,' mov r0,0\n j_s [blink]\n') for name,a in [('pre1',0x178604),('pre2',0xf76d4),('pre3',0x1505e0),('pre4',0x1785f8),('mode',0x11d074)]]
  for i,(name,a,code) in enumerate(services):
   dest=0x2030000+i*0x400; p=binary(name,code); maps+=mapping(p,dest)
   entry=binary('entry_'+name,f' mov_s r12,{dest:#x}\n j_s [r12]\n').read_bytes()[:8]
   b,o=locate(a,8); before=bytes(images[b['index']][o:o+8]); assert before==raw(a,8)
   images[b['index']][o:o+8]=entry; patches.append(dict(name=name,address=hex(a),original=before.hex(),fixture=entry.hex()))
  cb=binary('resource_callback',' mov r0,0\n j_s [blink]\n'); maps+=mapping(cb,0x2035000)
  asm=' mov r20,0x2000000\n'
  for i,selector in enumerate((1,0)):
   case=0x2001000+64*i
   asm+=f''' mov r21,{case:#x}
 st r21,[r20]
 st sp,[r21,20]
 mov r1,0x36a480
 mov r0,0x1234
 sth r0,[r1]
 mov r1,0x36a48a
 mov r0,0
 sth r0,[r1]
 mov r1,0x36a498
 mov r0,0x2035000
 st r0,[r1]
 mov r1,0x36a49c
 st r0,[r1]
 mov r1,0x36a4a0
 mov r0,0
 st r0,[r1]
 mov r1,0x36a47e
 stb r0,[r1]
 mov r1,0x36a482
 stb r0,[r1]
 mov r1,0x367fea
 mov r0,9
 stb r0,[r1]
 mov r1,0x38068f
 mov r0,1
 stb r0,[r1]
 mov r1,0x3ebd3c
 mov r0,0x2003000
 st r0,[r1]
 mov r1,0xfef0388
 mov r0,0xa5a7
 sth r0,[r1]
 mov r1,0xff04024
 mov r0,0xa5b8
 sth r0,[r1]
 mov r0,0x80
 mov r1,{selector}
 mov r2,0
 mov r12,0xf7844
 jl [r12]
 mov r1,0x367fea
 ldb r0,[r1]
 st r0,[r21,24]
 mov r1,0x36a480
 ldh r0,[r1]
 st r0,[r21,28]
 st sp,[r21,32]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,img in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(img);maps+=mapping(p,BS[i]['load_address_candidate'])
  cases=out/'cases.bin';cases.write_bytes(bytes(128));maps+=mapping(cases,0x2001000)
  for name,a,n in [('current',0x2000000,8),('mmio_fef',0xfef0300,512),('mmio_gpio',0xff04000,512),('fake_device',0x2003000,512)]:
   p=out/(name+'.bin');p.write_bytes(bytes(n));maps+=mapping(p,a)
  elf=compile_probe(r,'cases',asm); result,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert result['exit_code']==0 and result['fault'] is None,log
  rows=[]
  for i,selector in enumerate((1,0)):
   w=struct.unpack_from('<16I',cases.read_bytes(),i*64)
   assert w[5]==w[8],(i,w)
   if selector:assert (w[1],w[2],w[3],w[4],w[6],w[7])==(1,0,0,0,9,0x1234),(i,w)
   else:assert (w[1],w[2],w[3],w[4],w[6],w[7])==(2,0,0x235ae4,1,1,0x1235),(i,w)
   rows.append(dict(selector=selector,exit_fixture=w[1],fragment_return=w[2],post_handler=w[3],post_count=w[4],state=w[6],generation=w[7],stack_restored=w[5]==w[8]))
  trace=(out/'cases.trace').read_text().splitlines()
  for pc,count in [('0x0f7844 ',2),('0x0f78be ',1),('0x149550 ',1),('0x18b954 ',1)]:assert sum(x.startswith(pc) for x in trace)==count,(pc,count)
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  assert sha(dump)==r.input_hashes[str(dump)]
  r.results.update(status='PASS_IRIS_ORIGINAL_ENTRY_SYNTHETIC',scenarios=rows,limits=['F7844 entered with synthetic state and services; both later branches exit through fixtures and the original epilogue.', 'No execution of D6A80, no scheduler, actuator, optical calibration or GUI binding.']);r.finish()
 finally:r.save()
 print('PASS: selectors 1 and 0;',out,flush=True)
if __name__=='__main__':main()
