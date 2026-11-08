#!/usr/bin/env python3
"""Run AutoScene keys through original manager and CaptureMenu entry callbacks."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,locate,raw,u32


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('autoscene_capture_entry_cpu_%Y%m%dT%H%M%S%fZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='autoscene-capture-entry'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();dump=ROOT/'DUMPS/MainCode.dmp';data=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x169d78,0x124),(0x16a028,0x34),(0x16a6e4,0xc0),(0x6593a0,0x1a8),(0x65c46c,0x248),(0x783b08,0x140),(0x3f5908,4),(0x783ae8,28),(0x145180,0x270),(0x7cafe8,0x50),(0x7cb03c,0x68),(0x7cb118,0xa0),(0x169f60,0x60),(0x982384,48),(0x9802ac,28)]:
   b,o=locate(a,n);assert raw(a,n)==data[b['offset']+o:b['offset']+o+n]
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
   ('resource',0x145654,cur+' st r1,[r10,16]\n cmp r1,0x4800\n mov r0,0x2200000\n beq resource_done\n mov r0,0x2200100\nresource_done:\n j_s [blink]\n'),
   ('side_effect',0xd139c,cur+' st r0,[r10,44]\n st r1,[r10,48]\n mov r0,0\n j_s [blink]\n'),
   ('pre',0xcaff8,' mov r0,0\n j_s [blink]\n'),('setup',0xce6f4,' mov r0,0\n j_s [blink]\n'),('cb890',0xcb890,' mov r0,0\n j_s [blink]\n'),('cf5e0',0xcf5e0,' mov r0,0\n j_s [blink]\n'),('c975c',0xc975c,' mov r0,0\n j_s [blink]\n'),('records',0x7cb1b4,' mov r0,0\n j_s [blink]\n'),('skip_optional',0xd1a00,' mov r0,1\n j_s [blink]\n'),('refresh',0x145150,' mov r0,0\n j_s [blink]\n')]
  services += [(name,a,code) for name,a,code in [('mode',0xcad30,' mov r0,0x46\n j_s [blink]\n'),('key_get',0x16f920,' mov r0,0\n j_s [blink]\n'),('guardca',0xca310,' mov r0,0\n j_s [blink]\n'),('guardstate',0xd10c4,' mov r0,0\n j_s [blink]\n'),('handlergate',0x14918c,' mov r0,1\n j_s [blink]\n'),('handlerflag',0x12845c,' mov r0,0\n j_s [blink]\n'),('selection',0x632798,' mov r0,0\n j_s [blink]\n'),('lock',0x1593ac,' mov r0,0\n j_s [blink]\n'),('unlock',0x1594a4,' mov r0,0\n j_s [blink]\n'),('manager_refresh',0x145158,' mov r0,0\n j_s [blink]\n'),('manager_attr',0x1450d8,' mov r0,2\n j_s [blink]\n'),('resources_lifecycle',0x1455e4,' mov r0,0\n j_s [blink]\n')]]
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
  tests=[(0x700,0),(0x2180,0),(0x700,1),(0x2180,1)];asm=' mov r20,0x2000000\n'
  for i,(event,guard) in enumerate(tests):
   asm+=f''' mov r21,{0x2001000+i*64:#x}
 st r21,[r20]
 st sp,[r21,52]
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
 mov r0,0
 mov r1,{event:#x}
 mov r2,0
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
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,img in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(img);maps+=mapping(p,BS[i]['load_address_candidate'])
  cases=out/'cases.bin';cases.write_bytes(bytes(64*len(tests)));maps+=mapping(cases,0x2001000)
  current=out/'current.bin';current.write_bytes(bytes(8));maps+=mapping(current,0x2000000)
  elf=compile_probe(r,'cases',asm);result,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert result['exit_code']==0 and result['fault'] is None,log
  expected=[(1,0x9802ac,4,0x2200000,0x4800,2,0x4800,1,0x4801,0,0x4800,11,3),
            (1,0x9802ac,5,0x2200100,0x4801,2,0x4800,0,0x4801,1,0x4801,12,1),
            (1,0x783ae8,0xcccc,0xdeadbeef,0,0,0,0,0,0,0,0,0),
            (1,0x783ae8,0xcccc,0xdeadbeef,0,0,0,0,0,0,0,0,0)]
  rows=[]
  for i,(event,guard) in enumerate(tests):
   w=struct.unpack_from('<16I',cases.read_bytes(),i*64)
   assert w[:13]==expected[i] and w[13]==w[14],(i,w)
   rows.append(dict(event=hex(event),guard=guard,dispatcher=w[0],descriptor=hex(w[1]),argument=w[2],selected=hex(w[3]),resource_id=hex(w[4]),visibility_calls=w[5],visibility=[[hex(w[6]),w[7]],[hex(w[8]),w[9]]] if w[5] else [],focus=hex(w[10]),stack_preserved=w[13]==w[14]))
  trace=(out/'cases.trace').read_text()
  for pc,n in [('0x169e1c ',4),('0x6593a0 ',4),('0x65c46c ',4),('0x65c5f8 ',4),('0x1453e4 ',4),('0x145180 ',4),('0x7cb020 ',2),('0x7cb03c ',2),('0x7cb118 ',2)]:
   assert sum(line.startswith(pc) for line in trace.splitlines())==n,(pc,n)
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  assert sha(dump)==r.input_hashes[str(dump)]
  r.results.update(status='PASS_AUTOSCENE_CAPTURE_ORIGINAL_ID2_SYNTHETIC',scenarios=rows,assumptions=['Events 700 and 2180 are directly supplied to the original manager dispatcher; original ID 2 points to the original CaptureMenu. AutoScene lifecycle is a fixture that forwards only those key events.', 'Mode 0x46, guards, locks, resource lifecycle, focus, visibility and setup are synthetic; initial manager state and controls are fixtures.'],limits=['No scheduler, full control construction, rendering, physical keys or camera behavior established.']);r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS:',len(tests),'AutoScene-to-CaptureMenu cases;',out,flush=True)
if __name__=='__main__':main()
