#!/usr/bin/env python3
"""Run follow-up logical key events after original CaptureMenu record initialization."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,locate,raw,u16,u32


def main():
 assert sys.argv[1:] in ([], ['--ui-mode-23'])
 ui_mode = 0x23 if sys.argv[1:] else 0
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('snapshot_capture_followup_key_cpu_%Y%m%dT%H%M%S%fZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='snapshot-capture-followup-key'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();build=json.loads(BUILD.read_text());sim=LAB/'install/bin/arc-elf32-run';assert sha(sim)==build['experimental_sha256'];r.experimental_engine=LAB;r.input_hashes[str(sim)]=sha(sim);r.input_hashes[str(BUILD)]=sha(BUILD);dump=ROOT/'DUMPS/MainCode.dmp';data=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x145020,0x1c),(0x77f728,0x58),(0x631610,0xac),(0x6333fc,0x46),(0x77f6d8,0x28),(0x77f664,0x60),(0x1455e4,0x70),(0x16a17c,8),(0x16a93c,8),(0x16a944,14),(0x9802a0,12),(0x9801c0,56),(0x980268,56),(0x3aba38,12),(0x2d62d8,0x28),(0x1406d0,0x30),(0x16ec38,0x4e),(0x16e6e0,0x150),(0x16f86c,0x80),(0x392f04,320),(0x16f6a4,0x88),(0x16f72c,0x13c),(0x17bc7c,0x68),(0x17bd4c,0x4c),(0x169d78,0x124),(0x16a028,0x34),(0x16a6e4,0xc0),(0x6593a0,0x1a8),(0x65c46c,0x248),(0x783b08,0x140),(0x3f5908,4),(0x783ae8,28),(0x145180,0x270),(0x7cafe8,0x50),(0x7cb03c,0x68),(0x7cb118,0xa0),(0x7cb1b4,0x130),(0x631e98,0x30),(0x631a38,0x1b8),(0x98016c,84),(0x9801f8,112),(0x169f60,0x60),(0x982384,48),(0x9802ac,28)]:
   b,o=locate(a,n);assert raw(a,n)==data[b['offset']+o:b['offset']+o+n]
  assert [u32(0x9802a0+4*i) for i in range(3)]==[0x9801c0,0x980268,0x3aba38]
  assert [u16(a+6) for a in (0x9801c0,0x980268,0x3aba38)]==[0x15,0x15,1]
  assert (u32(0x16a17c),u32(0x16a180))==(0x16a93c,0x16a944)
  assert u32(0x77f728+21*4)==0x631610 and u32(0x77f728+4)==0x6333fc
  assert any(u32(0x77f664+i)==0x4401 and u32(0x77f668+i)==0x631674 for i in range(0,0x60,8))
  assert u32(0x3f5908)==0x9802ac and u32(0x783bb0)==0x700 and u32(0x783bb4)==0x65c46c and u32(0x783bb8)==0x2180 and u32(0x783bbc)==0x65c46c
  assert u32(0x7cb038)==0x899860 and u32(0x7cb1ac)==0x899858 and u32(0x7cb1b0)==0x4801
  images={i:bytearray(PS[i]) for i in (0,1,2,3,4,5)};maps=[];patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm);p=out/(name+'.bin')
   assert r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]).returncode==0
   d=p.read_bytes();p.write_bytes(d+bytes(8+(-len(d))%8));return p
  def mapping(p,a):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{p.stat().st_size}']
  cur=' mov r10,0x2000000\n ld r10,[r10]\n'
  services=[('focus',0x145764,cur+' st r1,[r10,40]\n mov r0,0\n j_s [blink]\n'),
   ('visibility',0x145b08,cur+' ld r11,[r10,20]\n asl r12,r11,3\n add r12,r10,r12\n st r1,[r12,24]\n st r2,[r12,28]\n add r11,r11,1\n st r11,[r10,20]\n mov r0,0\n j_s [blink]\n'),
   ('resource',0x145654,cur+' st r1,[r10,16]\n cmp r1,0x4800\n mov r0,0x9801c0\n beq resource_done\n mov r0,0x980268\nresource_done:\n j_s [blink]\n'),
   ('side_effect',0xd139c,cur+' st r0,[r10,44]\n st r1,[r10,48]\n mov r0,0\n j_s [blink]\n'),
   ('pre',0xcaff8,' mov r0,0\n j_s [blink]\n'),('setup',0xce6f4,' mov r0,0\n j_s [blink]\n'),('cb890',0xcb890,' mov r0,0\n j_s [blink]\n'),('cf5e0',0xcf5e0,' mov r0,0\n j_s [blink]\n'),('c975c',0xc975c,' mov r0,0\n j_s [blink]\n'),('skip_optional',0xd1a00,' mov r0,1\n j_s [blink]\n'),('refresh',0x145150,' mov r0,0\n j_s [blink]\n')]
  services += [(name,a,code) for name,a,code in [('mode',0xcad30,' mov r0,0x46\n j_s [blink]\n'),('key_get',0x16f920,' mov r0,0\n j_s [blink]\n'),('guardca',0xca310,' mov r0,0\n j_s [blink]\n'),('guardstate',0xd10c4,' mov r0,0\n j_s [blink]\n'),('handlergate',0x14918c,' mov r0,1\n j_s [blink]\n'),('handlerflag',0x12845c,' mov r0,0\n j_s [blink]\n'),('selection',0x632798,' mov r0,0\n j_s [blink]\n'),('lock',0x1593ac,' mov r0,0\n j_s [blink]\n'),('unlock',0x1594a4,' mov r0,0\n j_s [blink]\n'),('manager_refresh',0x145158,' mov r0,0\n j_s [blink]\n'),('manager_attr',0x1450d8,' mov r0,2\n j_s [blink]\n'),('ui_mode_fixture',0x1286bc,f' mov r0,{ui_mode:#x}\n j_s [blink]\n'),('current_resource_id',0x1457d4,' mov r0,0x89985c\n ld r0,[r0]\n ldh r0,[r0,4]\n j_s [blink]\n'),('queue_lock',0x1786e8,' mov r0,0\n j_s [blink]\n'),('queue_unlock',0x179354,' mov r0,0\n j_s [blink]\n'),('queue_notify',0x158cbc,' mov r0,0\n j_s [blink]\n'),('queue_filter',0x17c150,' mov r0,0\n j_s [blink]\n')]]
  for i,(name,a,asm) in enumerate(services):
   dst=0x2030000+i*0x400;p=binary(name,asm);maps+=mapping(p,dst)
   entry=binary('entry_'+name,f' mov_s r12,{dst:#x}\n j_s [r12]\n').read_bytes()[:8]
   b,o=locate(a,8);before=bytes(images[b['index']][o:o+8]);assert before==raw(a,8)
   images[b['index']][o:o+8]=entry;patches.append(dict(name=name,address=hex(a),original=before.hex(),fixture=entry.hex()))
  wrapper=binary('autoscene_lifecycle_wrapper',""" mov r11,0x700
 cmp r1,r11
 beq original_key
 mov r11,0x2180
 cmp r1,r11
 beq original_key
 mov r11,0x701
 cmp r1,r11
 beq original_key
 mov r11,0x2181
 cmp r1,r11
 beq original_key
 mov r0,0
 j_s [blink]
original_key:
 mov r12,0x6593a0
 j [r12]
""")
  maps+=mapping(wrapper,0x2090000)
  b,o=locate(0x783af4,4);before=bytes(images[b['index']][o:o+4]);assert before==struct.pack('<I',0x6593a0)==raw(0x783af4,4)
  images[b['index']][o:o+4]=struct.pack('<I',0x2090000);patches.append(dict(name='autoscene_lifecycle_wrapper',address='0x783af4',original=before.hex(),fixture=struct.pack('<I',0x2090000).hex()))
  b,o=locate(0x3f5908,4);assert bytes(images[b['index']][o:o+4])==raw(0x3f5908,4)==struct.pack('<I',0x9802ac)
  tests=[(0x2180,0,67),(0x2180,0,78),(0x2180,1,67),(0x2180,1,78)];asm=' mov r20,0x2000000\n'
  for i,(event,guard,key) in enumerate(tests):
   seeds=[(a,u32(a)|2) for a in [0x98016c+28*k+24 for k in range(3)]+[0x9801f8+28*k+24 for k in range(4)]]
   asm+=''.join(f' mov r1,{a:#x}\n mov r0,{v:#x}\n st r0,[r1]\n' for a,v in seeds)
   asm+=f''' mov r21,{0x2001000+i*128:#x}
 st r21,[r20]
 mov r0,{0x2800000+i*64:#x}
 st r0,[r21,60]
 st sp,[r21,52]
 mov r0,0
 mov r1,0x9801c8
 st r0,[r1]
 mov r1,0x980270
 st r0,[r1]
 mov r1,0x3aba40
 st r0,[r1]
 mov r1,0x681b6c
 mov r0,0xa2
 stb r0,[r1]
 mov r0,0xa3
 stb r0,[r1,1]
 mov r1,0x681b74
 mov r0,0xa4
 stb r0,[r1]
 mov r1,0x9802ac
 mov r0,{u32(0x9802ac):#x}
 st r0,[r1]
 mov r1,0x783ae8
 mov r0,{u32(0x783ae8):#x}
 st r0,[r1]
 mov r1,0x89985c
 mov r0,0xdeadbeef
 st r0,[r1]
 mov r1,0x899860
 mov r0,0xcccc
 st r0,[r1]
 mov r1,0x366e94
 mov r0,0x77f728
 st r0,[r1]
 mov r0,22
 sth r0,[r1,4]
 mov r0,0x3f5900
 st r0,[r1,8]
 mov r0,197
 sth r0,[r1,12]
 mov r0,0x783ae8
 st r0,[r1,16]
 mov r0,0
 st r0,[r1,20]
 st r0,[r1,24]
 mov r0,{guard}
 stb r0,[r1,39]
 mov r1,0x367814
 mov r0,1
 stb r0,[r1]
 mov r1,0x681b6b
 mov r0,0
 stb r0,[r1]
 mov r1,0x367bbc
 st r0,[r1]
 mov r1,0x3678f9
 mov r0,1
 stb r0,[r1]
 mov r1,{0x446808+(14 if event==0x700 else 67)*4+2:#x}
 sth r0,[r1]
 mov r1,0x366de8
 mov r0,0x16ec38
 st r0,[r1]
 mov r1,0x3678e8
 mov r0,0x392f04
 st r0,[r1]
 mov r0,16
 sth r0,[r1,4]
 mov r0,1
 stb r0,[r1,6]
 mov r0,0xfc000000
 st r0,[r1,8]
 mov r0,0
 st r0,[r1,12]
 mov r1,0x3678a2
 stb r0,[r1]
 mov r1,0xfe70224
 mov r0,0xffff
 sth r0,[r1]
 mov r0,{0xffff ^ (1 << (7 if event==0x700 else 8)):#x}
 sth r0,[r1,4]
 mov r12,0x2d62d8
 jl [r12]
 st r0,[r21,96]
 mov r12,0x1406d0
 jl [r12]
 add r0,r21,64
 mov r12,0x17bd4c
 jl [r12]
 st r0,[r21,76]
 ld r0,[r21,64]
 ldh.x r1,[r21,68]
 ld r2,[r21,72]
 mov r12,0x169e1c
 jl [r12]
 st r0,[r21]
 mov r1,0x366ea4
 ld r0,[r1]
 st r0,[r21,4]
 mov r1,0x899860
 ld r0,[r1]
 st r0,[r21,8]
 mov r1,0x89985c
 ld r0,[r1]
 st r0,[r21,12]
 st sp,[r21,56]
 mov r1,0xfe70224
 mov r0,0xffff
 sth r0,[r1]
 sth r0,[r1,4]
 mov r12,0x2d62d8
 jl [r12]
 st r0,[r21,100]
 mov r12,0x1406d0
 jl [r12]
 add r0,r21,80
 mov r12,0x17bd4c
 jl [r12]
 st r0,[r21,92]
 ld r0,[r21,80]
 ldh.x r1,[r21,84]
 ld r2,[r21,88]
 mov r12,0x169e1c
 jl [r12]
 st r0,[r21,104]
 mov r1,0x366ea4
 ld r0,[r1]
 st r0,[r21,108]
 mov r1,0x899860
 ld r0,[r1]
 st r0,[r21,112]
 mov r1,0x89985c
 ld r0,[r1]
 st r0,[r21,116]
 ld r0,[r21,20]
 st r0,[r21,120]
 st sp,[r21,124]
 ld r2,[r21,60]
'''
   asm+=''.join(f' mov r1,{a:#x}\n ld r0,[r1]\n st r0,[r2,{j*4}]\n' for j,(a,_) in enumerate(seeds))
   asm+=''' mov r1,0x9801c8
 ld r0,[r1]
 st r0,[r2,28]
 mov r1,0x980270
 ld r0,[r1]
 st r0,[r2,32]
 mov r1,0x3aba40
 ld r0,[r1]
 st r0,[r2,36]
 mov r1,0x681b6c
 ldb r0,[r1]
 st r0,[r2,40]
 ldb r0,[r1,1]
 st r0,[r2,44]
 mov r1,0x681b74
 ldb r0,[r1]
 st r0,[r2,48]
''' 
   if not guard:
    asm+=f''' mov r22,{0x2900000+i*64:#x}
 mov r1,0x366eac
 mov r0,0x980268
 st r0,[r1]
 mov r1,{0x446808+key*4+2:#x}
 mov r0,1
 sth r0,[r1]
 mov r0,255
 mov r1,{key}
 mov r2,1
 mov r3,1
 mov r12,0x16f72c
 jl [r12]
 mov r0,r22
 mov r12,0x17bd4c
 jl [r12]
 st r0,[r22,12]
 ld r0,[r22]
 ldh.x r1,[r22,4]
 ld r2,[r22,8]
 mov r12,0x169e1c
 jl [r12]
 st r0,[r22,16]
 mov r1,0x366ea4
 ld r0,[r1]
 st r0,[r22,20]
 st sp,[r22,24]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,img in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(img);maps+=mapping(p,BS[i]['load_address_candidate'])
  cases=out/'cases.bin';cases.write_bytes(bytes(128*len(tests)));maps+=mapping(cases,0x2001000)
  current=out/'current.bin';current.write_bytes(bytes(8));maps+=mapping(current,0x2000000)
  for name,addr in [('logical_keys',0x446000),('nikon_queue',0x47a000)]:
   region=out/(name+'.bin');region.write_bytes(bytes(0x2000));maps+=mapping(region,addr)
  mmio=out/'mmio_input.bin';mmio.write_bytes(bytes(12));maps+=['--memory-mapfile','/result/'+mmio.name,'--memory-region','0xfe70224,8']
  resources=out/'resource_events.bin';resources.write_bytes(bytes(len(tests)*64));maps+=mapping(resources,0x2800000)
  follow=out/'followup.bin';follow.write_bytes(bytes(64*len(tests)));maps+=mapping(follow,0x2900000)
  elf=compile_probe(r,'cases',asm);result,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert result['exit_code']==0 and result['fault'] is None,log
  expected=[(1,0x9802ac,5,0x980268,0x4801,2,0x4800,0,0x4801,1,0x4801,12,1)]*2+[(1,0x783ae8,0xcccc,0xdeadbeef,0,0,0,0,0,0,0,0,0)]*2
  rows=[]
  for i,(event,guard,key) in enumerate(tests):
   w=struct.unpack_from('<16I',cases.read_bytes(),i*128)
   assert w[:13]==expected[i] and w[13]==w[14],(i,w)
   after=struct.unpack_from('<6I',cases.read_bytes(),i*128+104)
   assert after==(1,w[1],w[2],w[3],w[5],w[13]),(i,w,after)
   bit=7 if event==0x700 else 8
   assert struct.unpack_from('<II',cases.read_bytes(),i*128+96)==(0x3ffffff^(1<<bit),0x3ffffff),(i,bit)
   assert struct.unpack_from('<Ih2xII',cases.read_bytes(),i*128+64)==(0,event,0,1),(i,event)
   assert struct.unpack_from('<Ih2xII',cases.read_bytes(),i*128+80)==(0,event|1,0,1),(i,event)
   resource=struct.unpack_from('<16I',resources.read_bytes(),i*64)
   assert resource[:7]==([(10,2,2,8,0,2,2),(10,2,2,8,0,2,2),(10,2,2,10,2,2,2),(10,2,2,10,2,2,2)][i]),(i,resource)
   assert resource[10:13]==((int(ui_mode == 0x23),0,0) if not guard else (0xa2,0xa3,0xa4)),(i,resource)
   assert resource[7:10]==((0x9802ac,)*3 if not guard else (0,0,0)),(i,resource)
   rows.append(dict(record_flags_4800=list(resource[:3]),record_flags_4801=list(resource[3:7]),class15_state=list(resource[10:13]),ui_mode_fixture=hex(ui_mode),snapshot_bit=bit,logical_key=14 if event==0x700 else 67,event=hex(event),release=hex(event|1),guard=guard,dispatcher=w[0],descriptor=hex(w[1]),argument=w[2],selected=hex(w[3]),resource_id=hex(w[4]),visibility_calls=w[5],release_dispatch_return=after[0],descriptor_after_release=hex(after[1]),release_preserved_observed_fields=True,visibility=[[hex(w[6]),w[7]],[hex(w[8]),w[9]]] if w[5] else [],focus=hex(w[10]),stack_preserved=w[13]==w[14]))
  for i,(event,guard,key) in enumerate(tests):
   f=follow.read_bytes()[i*64:(i+1)*64]
   if guard:
    assert f==bytes(64),(i,f)
    rows[i]['followup']='not dispatched: manager guard active'
   else:
    assert struct.unpack_from('<Ih2xII',f)==(0,0x2180 if key==67 else 0x2700,0,1),(i,f)
    dispatch,descriptor,sp=struct.unpack_from('<3I',f,16)
    assert (dispatch,descriptor,sp)==(1,0x9802ac,struct.unpack_from('<I',cases.read_bytes(),i*128+52)[0]),(i,dispatch,descriptor,sp)
    rows[i]['followup']=dict(logical_key=key,event=hex(0x2180 if key==67 else 0x2700),dispatch=dispatch,descriptor=hex(descriptor),stack_preserved=True)
  trace=(out/'cases.trace').read_text()
  for pc,n in [('0x1453e4 ',4),('0x7cb1b4 ',2),('0x631a38 ',1),('0x631b14 ',1),('0x631a8c ',1),('0x631b68 ',1)]:
   assert sum(line.startswith(pc) for line in trace.splitlines())==n,(pc,n)
  assert '0x631a8c  ld_s r0,[r15,0x18]   - cr16 <- 0x2' in trace
  assert '0x631b68  ld_s r0,[r15,0x18]   - cr16 <- 0x2' in trace
  assert not any(line.startswith('0x631e00 ') for line in trace.splitlines())

  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  assert sha(dump)==r.input_hashes[str(dump)]
  r.results.update(status='PASS_SNAPSHOT_FOLLOWUP_KEY_SYNTHETIC',ui_mode_fixture=hex(ui_mode),scenarios=rows,assumptions=['The harness writes synthetic MMIO, invokes the original snapshot reader and callback, and explicitly extracts and dispatches the resulting queue records. ID 2 points to the original CaptureMenu. AutoScene lifecycle is a fixture that forwards only those key events.', 'Mode 0x46, guards, locks, UI mode, focus, visibility and setup are synthetic. Original lookup, class 1 and class 15 handlers, 0x7cb1b4 and 0x631e98 execute with original enumeration and delivery; resource lookup and current ID are fixtures, initial record flag bit 1 is seeded.'],limits=['The harness explicitly dispatches the first press and release, then injects logical key 67 or 78 and dispatches its press; the second release is not generated. Active control is forcibly set to original 0x980268 after entry. No physical MMIO input, scheduler, full controls, rendering, physical keys or camera behavior established.']);r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS:',len(tests),'initialization and follow-up cases;',out,flush=True)
if __name__=='__main__':main()
