#!/usr/bin/env python3
"""Trace logical key, ISO initialization and confirmation in one bounded CPU session."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u16, u32, disasm


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('exposure_dual_transition_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-exposure-dual-transition'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); build=json.loads(BUILD.read_text()); sim=LAB/'install/bin/arc-elf32-run'
  assert sha(sim)==build['experimental_sha256']; r.experimental_engine=LAB
  r.input_hashes[str(sim)]=sha(sim); r.input_hashes[str(BUILD)]=sha(BUILD)
  dump=ROOT/'DUMPS/MainCode.dmp'; d=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
  spans=[(0x987af8,28),(0x3f59d8,4),(0x7d2394,0xd0),(0x7d249c,0x20),(0x7d24bc,0x6a),(0x989cf8,72),(0xd03e0,0x28),(0xde7b4,0x1c),(0x899ad4,11),(0x7d25b0,0x40),(0x6410f4,0x34),(0xd03b8,0x1c),(0x17c320,0xc8),(0xde78c,0x40),(0x989ff8,24),(0x98a01a,189),(0x1453e4,0x10),(0x145180,0x270),(0x1455e4,0x70),(0x7d22f0,0x38),(0x7d252c,0x38),(0x989cd8,24),(0x989fcc,24),(0x989da4,480),(0x899ac4,5),(0x989bc4,12),(0x989bf8,12),(0x989c20,12),(0x989c48,12),(0x989c70,12),(0x989c98,12),(0x989d70,12),(0x989f84,12),(0x16f6a4,0x88),(0x16f72c,0x13c),(0x17bc7c,0x68),(0x17bd4c,0x4c),(0x7cafe8,0x60),(0x20e814,0x34),(0x20e940,0x120),(0x17c074,0x74),(0x3e8bb4,67*8),(0x169d78,0x124),(0x16a028,0x34),(0x16a6e4,0xc0),(0x145020,0x5c),(0x77f728,0x58),(0x9802ac,0x1c),(0x631610,0x34),(0x631878,0x378),(0x77f664,0x60),(0x9801c0,56),(0x98016c,84),
         (0x980268,56),(0x9801f8,112),(0x98202c,56),(0x981fbc,112)]
  for a,n in spans:
   b,o=locate(a,n); assert raw(a,n)==d[b['offset']+o:b['offset']+o+n],hex(a)
  assert u32(0x3f5900+0x36*4)==0x987af8
  time_events={u32(0x989cf8+8*i):u32(0x989cfc+8*i) for i in range(9)}
  assert (time_events[0x380],time_events[0x580],time_events[0x480])==(0x7d23c8,0x7d2394,0x7d249c)
  keys=[11,14,67,78]
  events=[0x580,0x700,0x2180,0x2700]; handlers=[0x631878,0x63195c,0x631a38,0x631b14]
  assert all(any(u32(0x77f664+i)==e and u32(0x77f668+i)==h for i in range(0,0x60,8)) for e,h in zip(events,handlers))
  resources=[('Capture4800',0x9801c0,0x98016c,3,1,3),('Capture4801',0x980268,0x9801f8,4,0,4),('ChangeColor4800',0x98202c,0x981fbc,3,1,4)]
  for _,res,records,size,prefix,count in resources:
   assert u16(res+6)==0x15 and raw(res+46,2)==bytes((size,prefix)) and u32(res+48)==records and raw(res+52,1)[0]==count
  (out/'gnu_windows.txt').write_text(disasm(0x631878,0x631bf0))
  images={i:bytearray(PS[i]) for i in (0,1,2,3,4,5)}; maps=[]; patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm); p=out/(name+'.bin')
   x=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]); assert x.returncode==0,x.stdout
   v=p.read_bytes(); p.write_bytes(v+bytes(8+(-len(v))%8)); return p
  def mapping(p,a,n): return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  cur=' mov r10,0x2000000\n ld r10,[r10]\n'
  count=lambda o:f' ld r11,[r10,{o}]\n add r11,r11,1\n st r11,[r10,{o}]\n'
  services=[('lock',0x1593ac,' mov r0,0\n j_s [blink]\n'),('unlock',0x1594a4,' mov r0,0\n j_s [blink]\n'),('queue_lock',0x1786e8,' mov r0,0\n j_s [blink]\n'),('queue_unlock',0x179354,' mov r0,0\n j_s [blink]\n'),('notify',0x158cbc,' mov r0,0\n j_s [blink]\n'),('filter',0x17c150,' mov r0,0\n j_s [blink]\n'),('select',0x631e00,cur+' st r1,[r10,20]\n'+count(16)+' mov r0,0\n j_s [blink]\n'),
('refresh',0x145150,' mov r0,0\n j_s [blink]\n'),
   ('condition',0x817ba8,' mov r0,0\n j_s [blink]\n'),('action',0x171c30,' mov r0,0\n j_s [blink]\n'),
   ('delay',0x145c3c,' mov r0,0\n j_s [blink]\n'),('attributes',0x1450d8,' mov r0,2\n j_s [blink]\n'),
   ('get_resource',0x145654,' mov r0,0x2200000\n j_s [blink]\n'),('iso_select',0x641064,cur+' st r1,[r10,8]\n'+count(4)+' mov r0,0\n j_s [blink]\n'),('set_text',0x633020,cur+' st r1,[r10,12]\n'+count(4)+' mov r0,0\n j_s [blink]\n'),('render_b',0x145158,' mov r0,0\n j_s [blink]\n'),('format',0x12ce54,' mov r0,0\n j_s [blink]\n'),('update',0x145490,' mov r0,0\n j_s [blink]\n'),('timer',0x14905c,' mov r0,0\n j_s [blink]\n')]
  for i,(name,a,asm) in enumerate(services):
   dst=0x2030000+i*0x400; p=binary(name,asm); maps+=mapping(p,dst,p.stat().st_size)
   entry=binary('entry_'+name,f' mov_s r12,{dst:#x}\n j_s [r12]\n').read_bytes()[:8]
   b,o=locate(a,8); before=bytes(images[b['index']][o:o+8]); assert before==raw(a,8)
   images[b['index']][o:o+8]=entry; patches.append(dict(name=name,address=hex(a),original=before.hex(),fixture=entry.hex()))
  # Both diagnostic screens are in the same synthetic list; return is the original debug menu.
  tests=[('ISO125',0x3f,0),('Exit',0x3f,0),('conferma',0x3e,1),('annulla',0x3e,1)]
  state=bytearray(len(tests)*128); contexts=bytearray(len(tests)*192); asm=' mov r20,0x2000000\n'
  for i,(label,dest,slot) in enumerate(tests):
   s=0x2001000+i*128; c=0x2100000+i*192
   contexts[i*192:i*192+56]=raw(0x980268,56)
   # CaptureMenu 0x4801 layout: four entries, zero prefix, page zero.
   struct.pack_into('<I',contexts,i*192+48,c+64)
   for j,(target,arg) in enumerate(((0x3f,0),(0x3e,0),(0,0),(0,0))):
    off=i*192+64+j*28
    contexts[off:off+28]=raw(0x9801f8+j*28,28)
    struct.pack_into('<I',contexts,off+16,arg)
    struct.pack_into('<h',contexts,off+20,target)
    struct.pack_into('<I',contexts,off+24,0)
   asm+=f''' mov r21,{s:#x}
 st r21,[r20]
 st sp,[r21,24]
 mov r0,0
 mov r1,0x681b6b
 stb r0,[r1]
 mov r1,0x367bbc
 mov r0,0
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
 mov r0,{s+32:#x}
 mov r12,0x17bd4c
 jl [r12]
 st r0,[r21,44]
 mov r1,0x366e94
 mov r0,0x77f728
 st r0,[r1]
 mov r0,22
 sth r0,[r1,4]
 mov r0,0x3f5900
 st r0,[r1,8]
 mov r0,197
 sth r0,[r1,12]
 mov r0,0
 st r0,[r1,20]
 stb r0,[r1,39]
 mov r0,0x9802ac
 st r0,[r1,16]
 mov r0,{c:#x}
 st r0,[r1,24]
 mov r1,0x367814
 mov r0,1
 stb r0,[r1]
 ld r0,[r21,32]
 ldh.x r1,[r21,36]
 ld r2,[r21,40]
 mov r12,0x169e1c
 jl [r12]
 st r0,[r21]
 mov r1,0x366ea4
 ld r0,[r1]
 st r0,[r21,8]
 st sp,[r21,28]
'''
   if label in ('ISO125','Exit'):
    asm+=f''' mov r1,0x366eac
 mov r0,0x2200000
 st r0,[r1]
 mov r1,0x2200026
 mov r0,{7 if label == 'ISO125' else 0}
 stb r0,[r1]
 mov r1,0x365787
 mov r0,88
 stb r0,[r1]
 mov r1,0x367bc8
 mov r0,77
 stb r0,[r1]
 mov r1,0x37fbf2
 mov r0,555
 sth r0,[r1]
 mov r0,0
 mov r1,0x4801
 mov r2,0
 mov r12,0x169e1c
 jl [r12]
 mov r1,0x365787
 ldb r0,[r1]
 st r0,[r21,64]
 mov r1,0x367bc8
 ldb r0,[r1]
 st r0,[r21,68]
 mov r1,0x37fbf2
 ldh r0,[r1]
 st r0,[r21,72]
 mov r1,0x366ea4
 ld r0,[r1]
 st r0,[r21,76]
 st sp,[r21,80]
'''
   else:
    asm+=f''' mov r1,0x366eac
 mov r0,0
 st r0,[r1]
 mov r1,0x899ad0
 mov r0,120
 st r0,[r1]
 mov r1,0x899ac0
 mov r0,0x2200000
 st r0,[r1]
 mov r1,0x365788
 mov r0,0x12345678
 st r0,[r1]
 mov r1,0x37fbf4
 st r0,[r1]
 mov r0,0
 mov r1,0x380
 mov r2,0
 mov r12,0x169e1c
 jl [r12]
 mov r1,0x899ad0
 ld r0,[r1]
 st r0,[r21,64]
 mov r1,0x365788
 ld r0,[r1]
 st r0,[r21,68]
 mov r1,0x37fbf4
 ld r0,[r1]
 st r0,[r21,72]
 mov r0,0
 mov r1,{0x580 if label == 'conferma' else 0x480:#x}
 mov r2,0
 mov r12,0x169e1c
 jl [r12]
 mov r1,0x365788
 ld r0,[r1]
 st r0,[r21,84]
 mov r1,0x37fbf4
 ld r0,[r1]
 st r0,[r21,88]
 mov r1,0x366ea4
 ld r0,[r1]
 st r0,[r21,76]
 st sp,[r21,80]
'''
   asm+=f''' mov r0,255
 mov r1,{keys[slot]}
 mov r2,0
 mov r3,1
 mov r12,0x16f72c
 jl [r12]
 mov r0,{s+48:#x}
 mov r12,0x17bd4c
 jl [r12]
 st r0,[r21,60]
''' 
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,image in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin'; p.write_bytes(image); maps+=mapping(p,BS[i]['load_address_candidate'],len(image))
  statefile=out/'cases.bin'; statefile.write_bytes(state); maps+=mapping(statefile,0x2001000,len(state))
  p=out/'contexts.bin'; p.write_bytes(contexts); maps+=mapping(p,0x2100000,len(contexts))
  p=out/'current.bin'; p.write_bytes(bytes(8)); maps+=mapping(p,0x2000000,8)
  ctx=bytearray(256);ctx[37]=24;ctx[38]=99;struct.pack_into('<I',ctx,64,0x989da4)
  p=out/'debug_control.bin';p.write_bytes(ctx);maps+=mapping(p,0x2200000,len(ctx))
  for name,addr in (('debug_state',0x47c000),('timer_state',0x443000),('key_state',0x446000),('queue',0x47a000)):
   p=out/(name+'.bin');p.write_bytes(bytes(0x2000));maps+=mapping(p,addr,0x2000)
  elf=compile_probe(r,'cases',asm); case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert case['exit_code']==0 and case['fault'] is None,log
  assert 'S33_DSP_GUARD' not in log
  got=statefile.read_bytes(); rows=[]
  for i,(label,dest,slot) in enumerate(tests):
   w=struct.unpack_from('<23I',got,i*128)
   assert (w[0],w[2],w[4],w[5])==(1,0x989fcc if slot==0 else 0x989cd8,1,slot),(label,w)
   assert w[6]==w[7] and w[1]>=1,(label,w)
   assert struct.unpack_from('<Ih2xII',got,i*128+32)==(0,events[slot],0,1),(label,w)
   assert struct.unpack_from('<Ih2xII',got,i*128+48)==(0,events[slot]|1,0,1),(label,w)
   if slot==0:
    expected=(6,6,125) if label=='ISO125' else (88,77,555)
    assert tuple(w[16:19])==expected and w[19]==0x987af8 and w[20]==w[6],(label,w)
    rows.append(dict(action=label,slot=slot,final_values=list(w[16:19]),final_descriptor=hex(w[19])))
   else:
    assert tuple(w[16:19])==(121,0x12345678,0x12345678),(label,w)
    want=121000 if label=='conferma' else 0x12345678
    assert (w[19],w[20],w[21],w[22])==(0x987af8,w[6],want,want),(label,w)
    rows.append(dict(action=label,slot=slot,final_values=list(w[21:23]),final_descriptor=hex(w[19])))
  trace=(out/'cases.trace').read_text()
  for address in ('0x16f72c','0x16f6b0','0x17bc7c','0x17bd4c','0x169e1c','0x1453f4','0x169d78','0x16a6e4','0x16a028','0x14505c','0x145020','0x631610','0x169f60','0x1453e4','0x145180','0x7d22f0','0x7d23c8','0x7d2394','0x7d249c','0x7d252c','0x7d25b0','0x6410f4'):
   assert any(line.startswith(address+' ') for line in trace.splitlines()),address
  assert sum(line.startswith('0x1453e4 ') for line in trace.splitlines())==8
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n'); (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_EXPOSURE_DUAL_TRANSITION_BOUNDED_LAB',scenarios=rows,
   assumptions=['Original key writer, queue enqueue/dequeue, manager dispatch, class lookup, open, debug initialization and confirmation instructions; CaptureMenu descriptor and records copied and edited in synthetic RAM, page 0 and permissive guards.',
    'Services are fixtures including synchronization, key filter, attribute value 2, synthetic debug resource and text/selection fixtures; experimental GNU DSP v7 for MULUDW; manager current object and active control are synthetic.'],
   limits=['Logical key state is injected and the dequeued event is explicitly handed to manager dispatcher 169E1C; no scheduler loop or physical button; ISO selection, time edit and confirm/cancel events are injected; both original screens return to debug menu, not the synthetic exposure list.',
    'No display, physical key, exposure time units, AE, persistence, camera or physical RAM mapping; no Mono RAW implementation.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e)); raise
 finally:r.save()
 print('PASS:',len(tests),'synthetic-dual-screen cases;',out,flush=True)
if __name__=='__main__':main()
