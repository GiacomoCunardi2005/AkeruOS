#!/usr/bin/env python3
"""Exercise the V1.1 iris helper with synthetic services, not optical hardware."""
from datetime import datetime, timezone
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, disasm


def main():
 real='--real-request' in sys.argv
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime(('iris_async_real_request_cpu_' if real else 'iris_async_helper_cpu_')+'%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='iris-async-helper'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();dump=ROOT/'DUMPS/MainCode.dmp';data=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x18b954,0x80),(0x18b788,4),(0x18b8d0,4),(0x18b8f8,4)]:
   block,off=locate(a,n);assert raw(a,n)==data[block['offset']+off:block['offset']+off+n]
  (out/'gnu_windows.txt').write_text(disasm(0x18b954,0x18b9d4))
  images={i:bytearray(PS[i]) for i in (0,1,4,5)};maps=[];patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm);p=out/(name+'.bin')
   assert r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]).returncode==0
   b=p.read_bytes();p.write_bytes(b+bytes(8+(-len(b))%8));return p
  def mapping(p,a):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{p.stat().st_size}']
  common=' mov r10,0x2000000\n ld r10,[r10]\n'
  services=[
   ('generation',0x235abc,common+' ld r11,[r10,32]\n add r11,r11,1\n st r11,[r10,32]\n cmp r11,1\n bne 1f\n ld r0,[r10,8]\n j_s [blink]\n1:\n ld r0,[r10,12]\n j_s [blink]\n'),
   ('busy',0x235da0,common+' ld r11,[r10,36]\n add r11,r11,1\n st r11,[r10,36]\n ld r0,[r10,16]\n j_s [blink]\n'),
   ('request',0x235b0c,common+' ld r11,[r10,40]\n add r11,r11,1\n st r11,[r10,40]\n st r0,[r10,48]\n st r1,[r10,52]\n st r2,[r10,56]\n st r3,[r10,60]\n ld r0,[r10,20]\n j_s [blink]\n'),
   ('release',0x23524c,common+' ld r11,[r10,44]\n add r11,r11,1\n st r11,[r10,44]\n st r0,[r10,68]\n mov r0,0\n j_s [blink]\n'),
   ('cleanup',0x18b9d4,common+' ld r11,[r10,64]\n add r11,r11,1\n st r11,[r10,64]\n mov r0,0\n j_s [blink]\n')]
  if real:
   for a,n in [(0x235b0c,0xcc),(0x2358f4,0x5c),(0x235950,0x60)]:
    block,off=locate(a,n);assert raw(a,n)==data[block['offset']+off:block['offset']+off+n]
   services=[s for s in services if s[0]!='request']
   services += [('lock',0x1786e8,' mov r0,0\n j_s [blink]\n'),('unlock',0x179354,' mov r0,0\n j_s [blink]\n'),
    ('request_busy',0x234f1c,common+' ld r0,[r10,20]\n j_s [blink]\n'),
    ('event_clear',0x158ce0,' mov r0,0\n j_s [blink]\n'),
    ('post',0x145f28,common+' ld r11,[r10,40]\n add r11,r11,1\n st r11,[r10,40]\n st r0,[r10,48]\n st r1,[r10,52]\n st r2,[r10,56]\n st r3,[r10,60]\n mov r0,0\n j_s [blink]\n'),
    ('wait',0x158d04,common+' ld r11,[r10,72]\n add r11,r11,1\n st r11,[r10,72]\n mov r0,0\n j_s [blink]\n')]
  for i,(name,addr,asm) in enumerate(services):
   target=0x2030000+i*0x400;p=binary(name,asm);maps+=mapping(p,target)
   entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
   block,off=locate(addr,8);before=bytes(images[block['index']][off:off+8]);assert before==raw(addr,8)
   images[block['index']][off:off+8]=entry;patches.append(dict(name=name,address=hex(addr),original=before.hex(),fixture=entry.hex()))
  # initial, desired, first/second generation guard, busy status, request result
  tests=[(9,1,0,1,0,1),(9,9,1,1,0,1),(9,9,1,0,0,1),
         (9,1,1,1,1,1),(9,1,1,1,0,1),(9,1,1,1,0,0),(1,9,1,1,0,1)]
  if real:tests=[(9,1,1,1,0,0),(1,9,1,1,0,0),(9,1,1,1,0,1)]
  asm=' mov r20,0x2000000\n'
  for i,(initial,want,g1,g2,busy,request) in enumerate(tests):
   a=0x2001000+i*96
   asm+=f''' mov r21,{a:#x}
 st r21,[r20]
 mov r1,0x367fea
 mov r0,{initial}
 stb r0,[r1]
 mov r0,{g1}
 st r0,[r21,8]
 mov r0,{g2}
 st r0,[r21,12]
 mov r0,{busy}
 st r0,[r21,16]
 mov r0,{request}
 st r0,[r21,20]
 mov r1,0x36a480
 mov r0,0x1234
 sth r0,[r1]
 mov r1,0x36a482
 mov r0,0
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
 st sp,[r21,24]
 mov r0,{want}
 mov r1,0x1234
 mov r12,0x18b954
 jl [r12]
 st r0,[r21]
 mov r1,0x367fea
 ldb r0,[r1]
 st r0,[r21,4]
 mov r1,0xfef0388
 ldh r0,[r1]
 st r0,[r21,76]
 mov r1,0xff04024
 ldh r0,[r1]
 st r0,[r21,80]
 mov r1,0x36a482
 ldb r0,[r1]
 st r0,[r21,84]
 st sp,[r21,28]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,image in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(image);maps+=mapping(p,BS[i]['load_address_candidate'])
  p=out/'cases.bin';p.write_bytes(bytes(len(tests)*96));maps+=mapping(p,0x2001000)
  current=out/'current.bin';current.write_bytes(bytes(8));maps+=mapping(current,0x2000000)
  for name,addr in [('mmio_fef',0xfef0300),('mmio_gpio',0xff04000),('fake_device',0x2003000)]:
   region=out/(name+'.bin');region.write_bytes(bytes(512));maps+=mapping(region,addr)
  elf=compile_probe(r,'cases',asm);result,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert result['exit_code']==0 and result['fault'] is None,log
  expected=[(0,9,(1,0,0,0),0),(1,9,(2,0,0,1),0),(0,9,(2,0,0,0),0),
            (0,9,(1,1,0,1),0),(1,1,(1,1,1,0),0),(0,9,(1,1,1,0),1),(1,9,(1,1,1,0),0)]
  if real:expected=[(1,1,(2,1,1,0),0),(1,9,(2,1,1,0),0),(0,9,(2,1,0,0),1)]
  rows=[]
  for i,(test,want) in enumerate(zip(tests,expected)):
   w=struct.unpack_from('<22I',p.read_bytes(),i*96);ret,state,counts,cleanup=want
   assert (w[0],w[1],w[6]==w[7],tuple(w[8:12]),w[16])==(ret,state,True,counts,cleanup),(i,w)
   if counts[2]:assert tuple(w[12:16])==((0x36a494,0x235ae4,0x3a98,0) if real else (0x1234,test[1],0,0x3a98)),(i,w)
   if counts[3]:assert w[17]==2,(i,w)
   if real:
    expected_mmio=(0xa5a7,0xa5b8,0x15) if test[5] else (0xa5a4,0xa5b0 if test[1]==1 else 0xa5a8,0)
    assert tuple(w[19:22])==expected_mmio and w[18]==0,(i,w)
   rows.append(dict(initial=test[0],desired=test[1],guard1=test[2],guard2=test[3],busy=test[4],request_result=test[5],returned=ret,state=state,counts=counts,cleanup=cleanup,request_args=list(w[12:16]) if counts[2] else None))
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(__import__('pathlib').Path(__file__).read_bytes())
  assert sha(dump)==r.input_hashes[str(dump)]
  trace=(out/'cases.trace').read_text()
  if real:
   assert sum(line.startswith('0x235b0c ') for line in trace.splitlines())==3
   assert not any(line.startswith('0x158d04 ') for line in trace.splitlines())
  r.results.update(status='PASS_IRIS_ASYNC_ORIGINAL_REQUEST' if real else 'PASS_IRIS_ASYNC_HELPER_FIXTURE',scenarios=rows,assumptions=['Original V1.1 helper, synthetic state and service fixture returns.'],limits=['Synthetic MMIO and services; no scheduler, physical actuator, deferred callback or GUI binding.']);r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS:',len(tests),'iris helper cases;',out,flush=True)
if __name__=='__main__':main()
