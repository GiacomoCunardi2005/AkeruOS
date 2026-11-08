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
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('mmio_snapshot_four_routes_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-mmio-snapshot-four-routes'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); build=json.loads(BUILD.read_text()); sim=LAB/'install/bin/arc-elf32-run'
  assert sha(sim)==build['experimental_sha256']; r.experimental_engine=LAB
  r.input_hashes[str(sim)]=sha(sim); r.input_hashes[str(BUILD)]=sha(BUILD)
  dump=ROOT/'DUMPS/MainCode.dmp'; d=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
  spans=[(0x2d62d8,0x28),(0x1406d0,0x30),(0x16ec38,0x4e),(0x16e6e0,0x150),(0x16f86c,0x80),(0x392f04,320),(0x16f6a4,0x88),(0x16f72c,0x13c),(0x17bc7c,0x68),(0x17bd4c,0x4c),(0x631610,0x34),(0x631878,0x378),(0x77f664,0x60),(0x9801c0,56),(0x98016c,84),
         (0x980268,56),(0x9801f8,112),(0x98202c,56),(0x981fbc,112)]
  for a,n in spans:
   b,o=locate(a,n); assert raw(a,n)==d[b['offset']+o:b['offset']+o+n],hex(a)
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
  services=[('lock',0x1593ac,' mov r0,0\n j_s [blink]\n'),('unlock',0x1594a4,' mov r0,0\n j_s [blink]\n'),('queue_lock',0x1786e8,' mov r0,0\n j_s [blink]\n'),('queue_unlock',0x179354,' mov r0,0\n j_s [blink]\n'),('notify',0x158cbc,' mov r0,0\n j_s [blink]\n'),('filter',0x17c150,' mov r0,0\n j_s [blink]\n'),('select',0x631e00,cur+' st r1,[r10,20]\n'+count(16)+' mov r0,0\n j_s [blink]\n'),
   ('state',0x14503c,' mov r0,0\n j_s [blink]\n'),('refresh',0x145150,' mov r0,0\n j_s [blink]\n'),
   ('condition',0x817ba8,' mov r0,0\n j_s [blink]\n'),('action',0x171c30,' mov r0,0\n j_s [blink]\n'),
   ('delay',0x145c3c,' mov r0,0\n j_s [blink]\n'),('attributes',0x1450d8,' mov r0,2\n j_s [blink]\n'),
   ('open',0x1453e4,cur+' st r0,[r10,8]\n st r1,[r10,12]\n'+count(4)+' mov r0,0\n j_s [blink]\n')]
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
 mov r1,0xfe70224
 mov r0,{reg_a:#x}
 sth r0,[r1]
 mov r0,{reg_b:#x}
 sth r0,[r1,4]
 mov r12,0x2d62d8
 jl [r12]
 mov r1,{0x2002000+i*8:#x}
 st r0,[r1]
 mov r12,0x1406d0
 jl [r12]
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
 mov r12,0x2d62d8
 jl [r12]
 mov r1,{0x2002004+i*8:#x}
 st r0,[r1]
 mov r12,0x1406d0
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
  p=out/'snapshots.bin'; p.write_bytes(bytes(len(tests)*8)); maps+=mapping(p,0x2002000,len(tests)*8)
  p=out/'mmio_storage.bin'; p.write_bytes(bytes(16)); maps+=mapping(p,0xfe70224,8)
  p=out/'current.bin'; p.write_bytes(bytes(8)); maps+=mapping(p,0x2000000,8)
  for name,addr in (('key_state',0x446000),('queue',0x47a000)):
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
  trace=(out/'cases.trace').read_text()
  for address in ('0x2d62d8','0x1406d0','0x16ec38','0x16e6e0','0x16f86c','0x16f72c','0x16f6b0','0x17bc7c','0x17bd4c','0x631610','0x169f60'):
   assert any(line.startswith(address+' ') for line in trace.splitlines()),address
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n'); (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_MMIO_SNAPSHOT_FOUR_ROUTES_BOUNDED_LAB',scenarios=rows,
   assumptions=['Original key writer, queue enqueue/dequeue, class dispatcher and handler instructions; CaptureMenu descriptor and records copied and edited in synthetic RAM, page 0 and permissive guards.',
    'Services are fixtures including synchronization, key filter, attribute value 2 and recorder for open; experimental GNU DSP v7 for MULUDW.'],
   limits=['Original snapshot reader runs on synthetic ordinary-storage MMIO values; the harness explicitly passes its result to callback 1406D0; monitor and registration are not executed. The dequeued event is explicitly handed to the class wrapper; no scheduler, WindowManager routing or physical button; the ISO and time routes are alternatives, not one submenu.',
    'No display, actual resource lifecycle, firmware execution sequence, camera or physical RAM mapping; no Mono RAW implementation.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e)); raise
 finally:r.save()
 print('PASS:',len(tests),'synthetic-MMIO cases;',out,flush=True)
if __name__=='__main__':main()
