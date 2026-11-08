#!/usr/bin/env python3
"""Test V1.1 iris claim, generation guard and async request with fixtures."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate


def main():
 complete='--completion' in sys.argv
 post_fail='--post-fail' in sys.argv
 zero='--exposure-zero' in sys.argv
 table='--exposure-table' in sys.argv
 producer=zero or table or '--exposure-producer' in sys.argv
 copied=producer or '--exposure-copy' in sys.argv
 exposure='--exposure-fragment' in sys.argv or copied
 assert sum((complete,post_fail,exposure)) <= 1 and len(sys.argv) <= 2
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime(('iris_exposure_zero_cpu_' if zero else 'iris_exposure_table_cpu_' if table else 'iris_exposure_producer_cpu_' if producer else 'iris_exposure_copy_cpu_' if copied else 'iris_exposure_fragment_cpu_' if exposure else 'iris_post_failure_cpu_' if post_fail else 'iris_claim_completion_cpu_' if complete else 'iris_claim_async_cpu_')+'%Y%m%dT%H%M%S%fZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='iris-claim-async'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();dump=ROOT/'DUMPS/MainCode.dmp';data=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x18b928,0x2c),(0x18b954,0x80),(0x235a10,0xaa),(0x235abc,0x24),(0x235b0c,0xcc),(0x2358f4,0x5c),(0x235950,0x60)]:
   b,o=locate(a,n);assert raw(a,n)==data[b['offset']+o:b['offset']+o+n]
  if zero:
   for a,n in [(0x3663a4,4),(0x37fbd0,0x4a0)]:
    b,o=locate(a,n);assert raw(a,n)==bytes(n)==data[b['offset']+o:b['offset']+o+n]
  if exposure:
   for a,n in [(0xf78be,0x30),(0x149548,0x74),(0x14863c,0x28),(0x18b8d4,0x54)]:
    b,o=locate(a,n);assert raw(a,n)==data[b['offset']+o:b['offset']+o+n]
  if copied:
   for a,n in [(0xf7568,0x3c),(0xf7540,4),(0x128c20,8)]:
    b,o=locate(a,n);assert raw(a,n)==data[b['offset']+o:b['offset']+o+n]
  if producer:
   for a,n in [(0xfdc9e,0x4c),(0xfdd00,4),(0xf6f0c,8)]:
    b,o=locate(a,n);assert raw(a,n)==data[b['offset']+o:b['offset']+o+n]
  if table:
   for a,n in [(0xff720,0x118),(0xff5d4,8)]:
    b,o=locate(a,n);assert raw(a,n)==data[b['offset']+o:b['offset']+o+n]
  images={i:bytearray(PS[i]) for i in (0,1,4,5)};maps=[];patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm);p=out/(name+'.bin')
   assert r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]).returncode==0
   b=p.read_bytes();p.write_bytes(b+bytes(8+(-len(b))%8));return p
  def mapping(p,a):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{p.stat().st_size}']
  common=' mov r10,0x2000000\n ld r10,[r10]\n'
  services=[
   ('resource_acquire',0x2c4984,common+' mov r11,0x4567\n st r11,[r2]\n ld r0,[r10,8]\n j_s [blink]\n'),
   ('resource_register',0xc9664,' mov r0,0\n j_s [blink]\n'),
   ('resource_unlock',0xc9700,' mov r0,0\n j_s [blink]\n'),
   ('resource_ready',0x234e28,' mov r0,0\n j_s [blink]\n'),
   ('helper_busy',0x235da0,' mov r0,0\n j_s [blink]\n'),
   ('request_busy',0x234f1c,common+' ld r0,[r10,12]\n j_s [blink]\n'),
   ('release',0x23524c,common+' ld r11,[r10,44]\n add r11,r11,1\n st r11,[r10,44]\n mov r0,0\n j_s [blink]\n'),
   ('cleanup',0x18b9d4,common+' ld r11,[r10,48]\n add r11,r11,1\n st r11,[r10,48]\n mov r0,0\n j_s [blink]\n'),
   ('lock',0x1786e8,' mov r0,0\n j_s [blink]\n'),('unlock',0x179354,' mov r0,0\n j_s [blink]\n'),
   ('event_clear',0x158ce0,' mov r0,0\n j_s [blink]\n'),
   ('post',0x145f28,common+' st r1,[r10,52]\n ld r11,[r10,56]\n add r11,r11,1\n st r11,[r10,56]\n'+(' mov r0,7\n' if post_fail else ' mov r0,0\n')+' j_s [blink]\n'),
   ('wait',0x158d04,common+' ld r11,[r10,60]\n add r11,r11,1\n st r11,[r10,60]\n mov r0,0\n j_s [blink]\n')]
  if complete or post_fail:
   for a,n in [(0x235ae4,0x14),(0x2359b0,0x60),(0x23524c,0xc4),(0x235de8,0x30)]:
    b,o=locate(a,n);assert raw(a,n)==data[b['offset']+o:b['offset']+o+n]
   services=[s for s in services if s[0] not in ('release','cleanup')]
   services += [(name,addr,' mov r0,0\n j_s [blink]\n') for name,addr in
    [('delay',0x23c620),('release_type2',0x235c60),('release_common',0x234f98),
     ('release_service',0x2c4b14),('post_context',0x239264),('post_check',0x2c4f90)]]
  if exposure:
   services.append(('exposure_fragment_exit',0xf78e6,' j [r19]\n'))
  if producer: services.append(('producer_fragment_exit',0xfdce2,' j [r19]\n'))
  for i,(name,addr,asm) in enumerate(services):
   target=0x2030000+i*0x400;p=binary(name,asm);maps+=mapping(p,target)
   entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
   block,off=locate(addr,8);before=bytes(images[block['index']][off:off+8]);assert before==raw(addr,8)
   images[block['index']][off:off+8]=entry;patches.append(dict(name=name,address=hex(addr),original=before.hex(),fixture=entry.hex()))
  cb=binary('resource_callback',' mov r0,0\n j_s [blink]\n');maps+=mapping(cb,0x2035000)
  # initial state, target, acquire status, invalidate after claim, request busy
  tests=[(9,1,0,0,0),(1,9,0,0,0),(9,1,0,1,0),(9,9,0,0,0),(9,1,3,0,0),(9,1,0,0,1),(9,1,0,0,0)]
  if complete or post_fail:tests=tests[:2]
  if exposure:tests=[(9,1,0,0,0),(1,9,0,0,0),(9,9,0,0,0),(9,1,3,0,0),(9,1,0,0,1)]
  if zero: tests[0]=(9,0,0,0,0)
  asm=' mov r20,0x2000000\n'
  for i,(initial,target,acquire,stale,busy) in enumerate(tests):
   addr=0x2001000+i*128
   generation=0xffff if i==6 else 0x1234
   asm+=f''' mov r21,{addr:#x}
 st r21,[r20]
 mov r0,{acquire}
 st r0,[r21,8]
 mov r0,{busy}
 st r0,[r21,12]
 mov r1,0x36a480
 mov r0,{generation:#x}
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
 mov r0,0
 stb r0,[r1]
 mov r1,0x36a482
 stb r0,[r1]
 mov r1,0x367fea
 mov r0,{initial}
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
 mov r0,0xbeef
 sth r0,[r21,16]
 st sp,[r21,24]
'''
   if exposure:
    if copied:
     asm+=f''' mov r1,0x38068e
 mov r0,0xa5
 stb r0,[r1]
 stb r0,[r1,1]
 stb r0,[r1,2]
 mov r1,0x38077e
 mov r0,0x51
 stb r0,[r1]
 mov r0,0x52
 stb r0,[r1,2]
'''
     if producer:
      sel=i%2
      asm+=f''' mov r1,0x38077f
 mov r0,0xa5
 stb r0,[r1]
 mov r1,0x38003d
 mov r0,{target if sel==0 and not table else 0x33}
 stb r0,[r1]
 mov r0,{target if sel==1 and not table else 0x44}
 stb r0,[r1,1]
'''
      if table:
       asm+=f''' mov r1,0x2007000
 mov r0,{target if sel==0 else 0x33}
 stb r0,[r1,4]
 mov r0,{target if sel==1 else 0x44}
 stb r0,[r1,5]
 mov r0,10
 stb r0,[r1,12]
 mov r0,20
 stb r0,[r1,13]
 mov r0,30
 stb r0,[r1,14]
 mov r0,40
 stb r0,[r1,15]
'''
      asm+=f'''
 mov r1,0x3663a4
 mov r0,{0x2007000 if table else 0:#x}
 st r0,[r1]
 mov fp,{0x2006000+i*64+40:#x}
 mov r0,{(255 if i==2 else 20 if sel else 10) if table else sel}
 stb r0,[fp,-31]
 mov r14,0x380754
 mov r19,producer_return_{i}
 mov r12,0xfdc9e
 j [r12]
producer_return_{i}:
 mov r1,0x38077f
 ldb r0,[r1]
 st r0,[r21,108]
'''
     else:
      asm+=f''' mov r1,0x38077f
 mov r0,{target}
 stb r0,[r1]
'''
     asm+='''
 mov r12,0xf7568
 jl [r12]
 mov r1,0x38068e
 ldb r0,[r1]
 st r0,[r21,112]
 ldb r0,[r1,1]
 st r0,[r21,116]
 ldb r0,[r1,2]
 st r0,[r21,120]
'''
    else: asm+=f''' mov r1,0x38068f
 mov r0,{target}
 stb r0,[r1]
'''
    asm+=f'''
 mov fp,{0x2006000+i*64+40:#x}
 mov r0,0xbeef
 sth r0,[fp,-4]
 mov r1,0x380770
 mov r19,exposure_return_{i}
 mov r20,0
 mov r12,0xf78be
 j [r12]
exposure_return_{i}:
 st r20,[r21]
 st r0,[r21,4]
 ldh r0,[fp,-4]
 sth r0,[r21,16]
 mov r20,0x2000000
'''
   else:
    asm+=f'''
 add r0,r21,16
 mov r12,0x18b928
 jl [r12]
 st r0,[r21]
 cmp r0,0
 bne done_{i}
 mov r1,0x36a480
 ldh r0,[r1]
 add r0,r0,{stale}
 sth r0,[r1]
 mov r0,{target}
 ldh r1,[r21,16]
 mov r12,0x18b954
 jl [r12]
 st r0,[r21,4]
'''
   if complete:
    asm+=f''' mov r1,0x36a48a
 ldh r0,[r1]
 st r0,[r21,80]
 mov r1,0x36a46a
 ldb r0,[r1]
 st r0,[r21,84]
 mov r12,0x235ae4
 jl [r12]
 mov r1,0x36a48a
 ldh r0,[r1]
 st r0,[r21,88]
 mov r1,0x36a46a
 ldb r0,[r1]
 st r0,[r21,92]
 mov r1,0xff04024
 ldh r0,[r1]
 st r0,[r21,96]
 add r0,r21,120
 mov r12,0x18b928
 jl [r12]
 st r0,[r21,100]
 mov r0,{initial}
 ldh r1,[r21,120]
 mov r12,0x18b954
 jl [r12]
 st r0,[r21,104]
 mov r12,0x235ae4
 jl [r12]
 mov r1,0x36a48a
 ldh r0,[r1]
 st r0,[r21,108]
 mov r1,0x36a46a
 ldb r0,[r1]
 st r0,[r21,112]
 mov r1,0x36a480
 ldh r0,[r1]
 st r0,[r21,116]
'''
   asm+=f'''
done_{i}:
 mov r1,0x367fea
 ldb r0,[r1]
 st r0,[r21,32]
 mov r1,0x36a480
 ldh r0,[r1]
 st r0,[r21,36]
 mov r1,0x36a48a
 ldh r0,[r1]
 st r0,[r21,40]
 mov r1,0xfef0388
 ldh r0,[r1]
 st r0,[r21,64]
 mov r1,0xff04024
 ldh r0,[r1]
 st r0,[r21,68]
 mov r1,0x36a482
 ldb r0,[r1]
 st r0,[r21,72]
 mov r1,0x36a47e
 ldb r0,[r1]
 st r0,[r21,76]
 st sp,[r21,28]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,img in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(img);maps+=mapping(p,BS[i]['load_address_candidate'])
  p=out/'cases.bin';p.write_bytes(bytes(len(tests)*128));maps+=mapping(p,0x2001000)
  for name,addr,size in [('current',0x2000000,8),('mmio_fef',0xfef0300,512),('mmio_gpio',0xff04000,512),('fake_device',0x2003000,512)]:
   region=out/(name+'.bin');region.write_bytes(bytes(size));maps+=mapping(region,addr)
  if exposure:
   region=out/'fragment_frames.bin';region.write_bytes(bytes(len(tests)*64));maps+=mapping(region,0x2006000)
  if table:
   region=out/'lookup_table.bin';region.write_bytes(bytes(32));maps+=mapping(region,0x2007000)
  elf=compile_probe(r,'cases',asm);result,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert result['exit_code']==0 and result['fault'] is None,log
  expected=[(0,1,0x1234,1,0x1235,0,0,0x235ae4,1,0xa5a4,0xa5b0,0),
            (0,1,0x1234,9,0x1235,0,0,0x235ae4,1,0xa5a4,0xa5a8,0),
            (0,0,0x1234,9,0x1235,0,0,0,0,0xa5a7,0xa5b8,0),
            (0,1,0x1234,9,0x1234,1,0,0,0,0xa5a7,0xa5b8,0),
            (3,0,0xbeef,9,0x1234,0,0,0,0,0xa5a7,0xa5b8,0),
            (0,0,0x1234,9,0x1234,0,1,0,0,0xa5a7,0xa5b8,0x15),
            (0,1,0xffff,1,0,0,0,0x235ae4,1,0xa5a4,0xa5b0,0)]
  if post_fail:
   expected=[(0,0,0x1234,initial,0x1235,0,0,0x235ae4,1,0xa5a4,0xa5a0,0) for initial in (9,1)]
  if exposure:
   expected=[(0,1,0x1234,1,0x1235,4,0,0,0x235ae4,1,0xa5a4,0xa5b0,0,1),
             (0,1,0x1234,9,0x1235,4,0,0,0x235ae4,1,0xa5a4,0xa5a8,0,1),
             (0,9,0xbeef,9,0x1234,0,0,0,0,0,0xa5a7,0xa5b8,0,0),
             (3,3,0xbeef,9,0x1234,0,0,0,0,0,0xa5a7,0xa5b8,0,1),
             (0,0,0x1234,9,0x1234,4,0,1,0,0,0xa5a7,0xa5b8,0x15,1)]
  if zero: expected[0]=(0,1,0x1234,0,0x1235,4,0,0,0x235ae4,1,0xa5a4,0xa5b0,0,1)
  rows=[]
  for i,(test,want) in enumerate(zip(tests,expected)):
   w=struct.unpack_from('<20I',p.read_bytes(),i*128);handle=struct.unpack_from('<H',p.read_bytes(),i*128+16)[0]
   if exposure:
    actual=(w[0],w[1],handle,w[8],w[9],w[10],w[11],w[12],w[13],w[14],w[16],w[17],w[18],w[19])
    assert actual==want and w[6]==w[7] and w[15]==0,(i,actual,w)
    if copied: assert struct.unpack_from('<3I',p.read_bytes(),i*128+112)==(0x51,test[1],0x52),(i,test)
    if producer: assert struct.unpack_from('<I',p.read_bytes(),i*128+108)[0]==test[1],(i,test)
    rows.append(dict(initial=test[0],desired=test[1],acquire_status=test[2],busy=bool(test[4]),claim_return=w[0],fragment_return=w[1],handle=handle,state=w[8],generation=w[9],ownership_bits=w[10],release_calls=w[11],cleanup_calls=w[12],post_handler=w[13],post_count=w[14],mmio=[w[16],w[17]],status=w[18],marker=w[19],stack_preserved=w[6]==w[7]))
    continue
   if complete:
    extra=struct.unpack_from('<11I',p.read_bytes(),i*128+80)
    assert (w[0],w[1],handle,w[8],w[9],w[10],w[13],w[14],w[15],w[19])==(0,1,0x1234,test[0],0x1236,0,0x235ae4,2,0,1),(i,w)
    assert extra[:10]==(4,1,0,0,0xa5a0,0,1,0,0,0x1236),(i,extra)
    assert extra[10]&0xffff==0x1235 and w[6]==w[7],(i,w,extra)
    rows.append(dict(initial=test[0],first_target=test[1],first_handle=handle,second_handle=extra[10]&0xffff,before_completion_ownership=extra[0],before_completion_status=extra[1],after_completion_ownership=extra[2],after_completion_status=extra[3],second_claim=extra[5],second_request=extra[6],final_ownership=extra[7],final_status=extra[8],final_generation=extra[9],posts=w[14]));continue
   actual=(w[0],w[1],handle,w[8],w[9],w[11],w[12],w[13],w[14],w[16],w[17],w[18])
   assert actual==want and w[6]==w[7] and w[15]==0 and w[19]==1,(i,actual,w)
   assert w[10]==(0 if post_fail or test[2] else 4),(i,w)
   rows.append(dict(initial=test[0],desired=test[1],acquire_status=test[2],invalidated=bool(test[3]),busy=bool(test[4]),claim_return=w[0],helper_return=w[1],handle=handle,state=w[8],generation=w[9],ownership_bits=w[10],release_calls=w[11],cleanup_calls=w[12],post_handler=w[13],post_count=w[14],mmio=[w[16],w[17]],status=w[18],marker=w[19]))
  trace=(out/'cases.trace').read_text()
  if exposure:
   assert sum(line.startswith('0x0f78be ') for line in trace.splitlines())==5
   assert sum(line.startswith('0x149550 ') for line in trace.splitlines())==4
   assert sum(line.startswith('0x18b954 ') for line in trace.splitlines())==3
   if copied:
    assert sum(line.startswith('0x0f7568 ') for line in trace.splitlines())==5
    assert sum(line.startswith('0x128c20 ') for line in trace.splitlines())>=5
   if producer:
    assert sum(line.startswith('0x0fdc9e ') for line in trace.splitlines())==5
    if table:
     assert sum(line.startswith('0x0ff720 ') for line in trace.splitlines())==5
     assert sum(line.startswith('0x0ff758 ') for line in trace.splitlines())==1
    else:
     assert sum(line.startswith('0x0fdcb2 ') for line in trace.splitlines())==3
     assert sum(line.startswith('0x0fdcc4 ') for line in trace.splitlines())==2
  else:
   assert sum(line.startswith('0x18b928 ') for line in trace.splitlines())==(4 if complete else 2 if post_fail else 7)
   assert sum(line.startswith('0x18b954 ') for line in trace.splitlines())==(4 if complete else 2 if post_fail else 6)
  if complete:assert sum(line.startswith('0x235ae4 ') for line in trace.splitlines())==4
  if post_fail:
   assert sum(line.startswith('0x18b9d4 ') for line in trace.splitlines())==2
   assert not any(line.startswith('0x235ae4 ') for line in trace.splitlines())
  assert not any(line.startswith('0x158d04 ') for line in trace.splitlines())
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  assert sha(dump)==r.input_hashes[str(dump)]
  r.results.update(status='PASS_IRIS_EXPOSURE_ZERO_SYNTHETIC' if zero else 'PASS_IRIS_EXPOSURE_TABLE_SYNTHETIC' if table else 'PASS_IRIS_EXPOSURE_PRODUCER_SYNTHETIC' if producer else 'PASS_IRIS_EXPOSURE_COPY_SYNTHETIC' if copied else 'PASS_IRIS_EXPOSURE_FRAGMENT_SYNTHETIC' if exposure else 'PASS_IRIS_POST_FAILURE_SYNTHETIC' if post_fail else 'PASS_IRIS_CLAIM_COMPLETION_SYNTHETIC' if complete else 'PASS_IRIS_CLAIM_ASYNC_SYNTHETIC',scenarios=rows,assumptions=['Original claim, acquire, generation guard, helper and request with fixture resource services and MMIO.', 'Entry at 0xf78be assumes upstream branches and a synthetic frame; exit is a fixture.' if exposure else 'Post returns injected error 7.' if post_fail else 'Post returns success.']+(['The harness sets a synthetic 4x4 lookup table and enters FDC9E with global 3663A4 pointing to it, then calls F7568 before F78BE; exits are fixtures.'] if table else ['The harness sets input bytes and enters FDC9E with global 3663A4=0, then calls F7568 before F78BE; exits are fixtures.'] if producer else ['The harness writes candidate source byte 38077F and explicitly calls original F7568 before entering the fragment.'] if copied else []),limits=['No scheduler, concurrency, physical actuator, optical measurement or GUI binding.', 'Fragment does not establish automatic exposure mode or physical behaviour.' if exposure else 'Failed post is injected; underlying post and release services are fixtures.' if post_fail else 'Completion is explicitly invoked by the harness.' if complete else 'Completion is not executed.']);r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS:',len(tests),'iris claim and async cases;',out,flush=True)
if __name__=='__main__':main()
