#!/usr/bin/env python3
"""Exercise four original class-15 handlers with synthetic routing records, offline only."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u16, u32, disasm


def main():
 producer=sys.argv[1:]==['--producer']
 timeout=producer or sys.argv[1:]==['--timeout']
 combined=timeout or sys.argv[1:]==['--combined']
 assert sys.argv[1:] in ([],['--combined'],['--timeout'],['--producer'])
 prefix='monitor_producer_four_routes_cpu_' if producer else ('monitor_timeout_four_routes_cpu_' if timeout else ('monitor_combined_four_routes_cpu_' if combined else 'monitor_rearm_four_routes_cpu_'))
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime(prefix+'%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-monitor-rearm-four-routes'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); build=json.loads(BUILD.read_text()); sim=LAB/'install/bin/arc-elf32-run'
  assert sha(sim)==build['experimental_sha256']; r.experimental_engine=LAB
  r.input_hashes[str(sim)]=sha(sim); r.input_hashes[str(BUILD)]=sha(BUILD)
  dump=ROOT/'DUMPS/MainCode.dmp'; d=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
  spans=[(0x242040,0x90),(0x242104,0x120),(0x2b7190,0x1c),(0x2d62b0,0x28),(0x2d62d8,0x28),(0x1406d0,0x30),(0x16ec38,0x4e),(0x16e6e0,0x150),(0x16f86c,0x80),(0x392f04,320),(0x16f6a4,0x88),(0x16f72c,0x13c),(0x17bc7c,0x68),(0x17bd4c,0x4c),(0x631610,0x34),(0x631878,0x378),(0x77f664,0x60),(0x9801c0,56),(0x98016c,84),
         (0x980268,56),(0x9801f8,112),(0x98202c,56),(0x981fbc,112)]
  for a,n in spans:
   b,o=locate(a,n); assert raw(a,n)==d[b['offset']+o:b['offset']+o+n],hex(a)
  assert u32(0x24221c)==0x2420b4 and u32(0x24220c)==0x36a6c8
  bits=[12,7,8,13]
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
  notify=''' mov r10,0x3200002
 cmp r0,r10
 bne done_notify
 mov r10,0x200a000
 ld r11,[r10,8]
 or r11,r11,r1
 st r11,[r10,8]
done_notify:
 mov r0,0
 j_s [blink]
'''
  services=[('timer_schedule',0x145bf4,' mov r10,0x2009000\n st r0,[r10]\n st r1,[r10,4]\n st r2,[r10,8]\n st r3,[r10,12]\n st r4,[r10,16]\n mov r0,0\n j_s [blink]\n'),('timer_clear',0x145c2c,' mov r0,0\n j_s [blink]\n'),('timer_guard',0x158fd0,' mov r0,0\n j_s [blink]\n'),('monitor_disable',0x2d61cc,' mov r0,0\n j_s [blink]\n'),('monitor_cleanup',0x2b71f0,' mov r0,0\n j_s [blink]\n'),('monitor_enable',0x2d6198,' mov r0,0\n j_s [blink]\n'),('prepare_snapshot',0x2d627c,' mov r0,0\n j_s [blink]\n'),('lock',0x1593ac,' mov r0,0\n j_s [blink]\n'),('unlock',0x1594a4,' mov r0,0\n j_s [blink]\n'),('queue_lock',0x1786e8,' mov r0,0\n j_s [blink]\n'),('queue_unlock',0x179354,' mov r0,0\n j_s [blink]\n'),('notify',0x158cbc,' mov r0,0\n j_s [blink]\n'),('filter',0x17c150,' mov r0,0\n j_s [blink]\n'),('select',0x631e00,cur+' st r1,[r10,20]\n'+count(16)+' mov r0,0\n j_s [blink]\n'),
   ('input_status',0x2d6200,' mov r10,0x200a000\n ld r0,[r10]\n j_s [blink]\n'),('input_ack',0x2d6214,' mov r10,0x200a000\n st r0,[r10,4]\n mov r0,0\n j_s [blink]\n'),
   ('state',0x14503c,' mov r0,0\n j_s [blink]\n'),('refresh',0x145150,' mov r0,0\n j_s [blink]\n'),
   ('condition',0x817ba8,' mov r0,0\n j_s [blink]\n'),('action',0x171c30,' mov r0,0\n j_s [blink]\n'),
   ('delay',0x145c3c,' mov r0,0\n j_s [blink]\n'),('attributes',0x1450d8,' mov r0,2\n j_s [blink]\n'),
   ('open',0x1453e4,cur+' st r0,[r10,8]\n st r1,[r10,12]\n'+count(4)+' mov r0,0\n j_s [blink]\n')]
  services=[(name,a,notify if name=='notify' else asm) for name,a,asm in services]
  for i,(name,a,asm) in enumerate(services):
   dst=0x2030000+i*0x400; p=binary(name,asm); maps+=mapping(p,dst,p.stat().st_size)
   entry=binary('entry_'+name,f' mov_s r12,{dst:#x}\n j_s [r12]\n').read_bytes()[:8]
   b,o=locate(a,8); before=bytes(images[b['index']][o:o+8]); assert before==raw(a,8)
   images[b['index']][o:o+8]=entry; patches.append(dict(name=name,address=hex(a),original=before.hex(),fixture=entry.hex()))
  # First slot has alternative diagnostic destinations, not a constructed submenu.
  routes=[('ISO',0x3f),('tempo',0x3e)]
  tests=[(label,dest,slot) for label,dest in routes for slot in range(4)]
  state=bytearray(len(tests)*64); contexts=bytearray(len(tests)*192); asm=' mov r20,0x2000000\n'
  for i,(label,dest,slot) in enumerate(tests):
   s=0x2001000+i*64; c=0x2100000+i*192
   def monitor_input(mask, index):
    if not producer:
     return f' mov r0,{mask:#x}\n mov r12,0x242104\n jl [r12]\n'
    source=1 if mask==0x100 else 2
    return f''' mov r1,0x200a000
 mov r0,{source}
 st r0,[r1]
 mov r0,0
 st r0,[r1,8]
 mov r12,0x242040
 jl [r12]
 mov r1,0x200a000
 mov r2,{0x200b000+i*48+index*16:#x}
 ld r0,[r1,4]
 st r0,[r2]
 ld r0,[r1,8]
 st r0,[r2,4]
 mov r12,0x242104
 jl [r12]
'''
   timeout_asm=f''' mov r1,0x36a6c8
 mov r0,0x1234
 st r0,[r1]
 mov r12,0x2420b4
 jl [r12]
 mov r1,0x5545f8
 mov r2,{0x2007000+i*24:#x}
 ld r0,[r1,32]
 st r0,[r2]
 ld r0,[r1,60]
 st r0,[r2,4]
 mov r1,0x36a6c8
 ld r0,[r1]
 st r0,[r2,16]
 {monitor_input(0x100,0)}
 mov r1,0x5545f8
 mov r2,{0x2007000+i*24:#x}
 ld r0,[r1,52]
 st r0,[r2,8]
 mov r0,{0x2008000+i*16:#x}
 mov r12,0x17bd4c
 jl [r12]
 mov r2,{0x2007000+i*24:#x}
 st r0,[r2,12]
 {monitor_input(0x200,1)}
''' if timeout else ''
   bit=bits[slot]
   reg_a=0xffff & ~(1 << (bit-10)) if bit in (12,13) else 0xffff
   reg_b=0xffff & ~(1 << bit)
   snapshot=(reg_a << 10) | reg_b
   assert snapshot == (0x3ffffff ^ (1 << bit))
   contexts[i*192:i*192+56]=raw(0x980268,56)
   # CaptureMenu 0x4801 layout: four entries, zero prefix, page zero.
   struct.pack_into('<I',contexts,i*192+48,c+64)
   for j,(target,arg) in enumerate(((dest,0),(0xbb,0),(0,0),(0xb7,1))):
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
 mov r1,0x5545f8
 mov r0,0x1406d0
 st r0,[r1,24]
 mov r0,0
 st r0,[r1,44]
 st r0,[r1,52]
 st r0,[r1,56]
 st r0,[r1,60]
 mov r0,2
 st r0,[r1,32]
 mov r1,0x36a6c8
 mov r0,0
 st r0,[r1]
 mov r1,0xfe7021c
 mov r0,0
 sth r0,[r1]
 sth r0,[r1,4]
 mov r1,0xfe70224
 mov r0,{reg_a:#x}
 sth r0,[r1]
 mov r0,{reg_b:#x}
 sth r0,[r1,4]
 mov r0,0x100
 mov r12,0x242104
 jl [r12]
 mov r1,0x5545f8
 ld r0,[r1,48]
 mov r1,{0x2002000+i*8:#x}
 st r0,[r1]
 mov r0,{s+32:#x}
 mov r12,0x17bd4c
 jl [r12]
 st r0,[r21,44]
 mov r0,{c:#x}
 ldh.x r1,[r21,36]
 mov r2,0
 mov r12,0x631610
 jl [r12]
 st r0,[r21]
 st sp,[r21,28]
 mov r1,0xfe70224
 mov r0,0xffff
 sth r0,[r1]
 sth r0,[r1,4]
 mov r1,0xfe7021c
 mov r0,0xffff
 sth r0,[r1]
 sth r0,[r1,4]
 mov r1,0x5545f8
 ld r0,[r1,32]
 mov r2,{0x2004000+i*16:#x}
 st r0,[r2]
 mov r0,{0x300 if combined else 0x200:#x}
 mov r12,0x242104
 jl [r12]
 mov r1,0x5545f8
 ld r0,[r1,32]
 mov r2,{0x2004000+i*16:#x}
 st r0,[r2,4]
 ld r0,[r1,44]
 st r0,[r2,8]
 mov r0,{0x2006000+i*16:#x}
 mov r12,0x17bd4c
 jl [r12]
 mov r2,{0x2004000+i*16:#x}
 st r0,[r2,12]
 mov r1,0x5545f8
 ld r0,[r1,52]
 mov r2,{0x2006000+i*16:#x}
 st r0,[r2,12]
 ld r0,[r1,56]
 st r0,[r2,8]
 ld r0,[r1,48]
 st r0,[r2,4]
 {timeout_asm}
 {monitor_input(0x100,2)}
 mov r1,0x5545f8
 ld r0,[r1,48]
 mov r1,{0x2002004+i*8:#x}
 st r0,[r1]
 mov r0,{s+48:#x}
 mov r12,0x17bd4c
 jl [r12]
 st r0,[r21,60]
''' 
  asm+=" mov r1,0xfe7021c\n mov r0,0\n sth r0,[r1]\n sth r0,[r1,4]\n"
  for j,(target,mode,callback) in enumerate(((1,2,0x1406d0),(0,1,0x1406d0),(0,2,0))):
   asm+=f""" mov r1,0x5545f8
 mov r0,{callback:#x}
 st r0,[r1,24]
 mov r0,{mode}
 st r0,[r1,32]
 mov r0,{target}
 st r0,[r1,44]
 mov r0,0x12345678
 st r0,[r1,48]
 mov r0,0
 st r0,[r1,52]
 st r0,[r1,56]
 mov r1,0x3678f0
 mov r0,0xfc000000
 st r0,[r1]
 mov r0,0x100
 mov r12,0x242104
 jl [r12]
 mov r1,0x5545f8
 mov r2,{0x2003000+j*16:#x}
 ld r0,[r1,52]
 st r0,[r2]
 ld r0,[r1,56]
 st r0,[r2,4]
 ld r0,[r1,48]
 st r0,[r2,8]
 mov r1,0x3678f0
 ld r0,[r1]
 st r0,[r2,12]
"""
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,image in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin'; p.write_bytes(image); maps+=mapping(p,BS[i]['load_address_candidate'],len(image))
  statefile=out/'cases.bin'; statefile.write_bytes(state); maps+=mapping(statefile,0x2001000,len(state))
  p=out/'contexts.bin'; p.write_bytes(contexts); maps+=mapping(p,0x2100000,len(contexts))
  p=out/'rearm.bin'; p.write_bytes(bytes(136)); maps+=mapping(p,0x2004000,len(tests)*16)
  p=out/'intermediate.bin'; p.write_bytes(bytes(len(tests)*16)); maps+=mapping(p,0x2006000,len(tests)*16)
  p=out/'timeout.bin'; p.write_bytes(bytes(len(tests)*24)); maps+=mapping(p,0x2007000,len(tests)*24)
  p=out/'timeout_queue.bin'; p.write_bytes(bytes(len(tests)*16)); maps+=mapping(p,0x2008000,len(tests)*16)
  p=out/'timer_args.bin'; p.write_bytes(bytes(24)); maps+=mapping(p,0x2009000,20)
  p=out/'input_fixture.bin'; p.write_bytes(bytes(16)); maps+=mapping(p,0x200a000,16)
  p=out/'producer_events.bin'; p.write_bytes(bytes(len(tests)*48)); maps+=mapping(p,0x200b000,len(tests)*48)
  p=out/'negative.bin'; p.write_bytes(bytes(64)); maps+=mapping(p,0x2003000,48)
  p=out/'snapshots.bin'; p.write_bytes(bytes(len(tests)*8)); maps+=mapping(p,0x2002000,len(tests)*8)
  p=out/'mmio_storage.bin'; p.write_bytes(bytes(24)); maps+=mapping(p,0xfe7021c,16)
  p=out/'current.bin'; p.write_bytes(bytes(8)); maps+=mapping(p,0x2000000,8)
  for name,addr in (('key_state',0x446000),('queue',0x47a000),('monitor',0x554000)):
   p=out/(name+'.bin');p.write_bytes(bytes(0x2000));maps+=mapping(p,addr,0x2000)
  elf=compile_probe(r,'cases',asm); case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert case['exit_code']==0 and case['fault'] is None,log
  assert 'S33_DSP_GUARD' not in log
  got=statefile.read_bytes(); snapshots=(out/'snapshots.bin').read_bytes(); rows=[]
  for i,(label,dest,slot) in enumerate(tests):
   targets=[dest,0xbb,0,0xb7]; args=[0,0,0,1]; target=targets[slot]; arg=args[slot]
   w=struct.unpack_from('<8I',got,i*64)
   assert struct.unpack_from('<II',snapshots,i*8)==(0x3ffffff ^ (1 << bits[slot]),0x3ffffff)
   opens=bool(target)
   assert (w[0],w[1],w[4],w[5])==(1 if opens else 0,int(opens),1,slot),(label,slot,w)
   assert w[6]==w[7],(label,slot,w)
   assert struct.unpack_from('<Ih2xII',got,i*64+32)==(0,events[slot],0,1),(label,slot)
   assert struct.unpack_from('<Ih2xII',got,i*64+48)==(0,events[slot]|1,0,1),(label,slot)
   if opens: assert (w[2],w[3])==(target,arg),(label,slot,w)
   rows.append(dict(variant=label,slot=slot,event=hex(events[slot]),index=slot,
     destination=hex(target) if opens else None,argument=arg if opens else None,
     return_value=w[0],select_calls=w[4],open_calls=w[1],stack_preserved=True))
  rearm=(out/'rearm.bin').read_bytes()
  assert all(struct.unpack_from('<4I',rearm,i*16)==(1,2,0xffff03ff,0) for i in range(len(tests)))
  intermediate=(out/'intermediate.bin').read_bytes()
  for i,(_,_,slot) in enumerate(tests):
   assert struct.unpack_from('<3I',intermediate,i*16+4)==(0x3ffffff ^ (1 << bits[slot]),1,int(combined))
  if timeout:
   data=(out/'timeout.bin').read_bytes()
   assert all(struct.unpack_from('<5I',data,i*24)==(1,1,2,0,0) for i in range(len(tests)))
  if producer:
   data=(out/'producer_events.bin').read_bytes()
   for i in range(len(tests)):
    assert [struct.unpack_from('<2I',data,i*48+j*16) for j in range(3)]==[(1,0x100),(2,0x200),(1,0x100)]
  assert struct.unpack_from('<5I',(out/'timer_args.bin').read_bytes())==(0x2420b4,0,1,0x3a98,0x36a6c8)
  negative=(out/'negative.bin').read_bytes()
  assert [struct.unpack_from('<4I',negative,i*16) for i in range(3)] == [(1,0,0x12345678,0xfc000000),(1,0,0x12345678,0xfc000000),(0,1,0x3ffffff,0xfc000000)]
  trace=(out/'cases.trace').read_text()
  if timeout: assert any(line.startswith('0x2420b4 ') for line in trace.splitlines())
  if producer: assert any(line.startswith('0x242040 ') for line in trace.splitlines())
  for address in ('0x242104','0x2b7190','0x2d62b0','0x2d62d8','0x1406d0','0x16ec38','0x16e6e0','0x16f86c','0x16f72c','0x16f6b0','0x17bc7c','0x17bd4c','0x631610','0x169f60'):
   assert any(line.startswith(address+' ') for line in trace.splitlines()),address
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n'); (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_MONITOR_REARM_FOUR_ROUTES_BOUNDED_LAB',combined_bits=combined,timeout_injected=timeout,producer_injected=producer,scenarios=rows, negative_cases=['mismatch','mode_not_2','null_callback'],
   assumptions=['Original key writer, queue enqueue/dequeue, class dispatcher and handler instructions; CaptureMenu descriptor and records copied and edited in synthetic RAM, page 0 and permissive guards.',
    'Services are fixtures including synchronization, key filter, attribute value 2 and recorder for open; experimental GNU DSP v7 for MULUDW.'],
   limits=['Original monitor bits 8 and 9, comparison reader, snapshot reader and indirect callback run with synthetic context and ordinary-storage MMIO. Harness injects bit 9 alone or bits 8 and 9 together; timeout variant manually invokes original timer callback. Producer variant executes 242040 with synthetic input/ack and a notification recorder, then the harness explicitly delivers recorded bits to 242104. Timers and external services are fixtures. The harness installs the callback; event task and registration are not executed. The dequeued event is explicitly handed to the class wrapper; no scheduler, WindowManager routing or physical button; the ISO and time routes are alternatives, not one submenu.',
    'No display, actual resource lifecycle, firmware execution sequence, camera or physical RAM mapping; no Mono RAW implementation.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e)); raise
 finally:r.save()
 print('PASS:',len(tests),'synthetic-rearm cases;',out,flush=True)
if __name__=='__main__':main()
