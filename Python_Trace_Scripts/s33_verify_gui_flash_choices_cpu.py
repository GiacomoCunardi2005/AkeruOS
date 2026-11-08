#!/usr/bin/env python3
"""Trace Nikon flash menu records through the original event path in synthetic RAM."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe, BUILD, LAB
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32, disasm


def main():
 assert sys.argv[1:] in ([], ['--apply-original'], ['--consumer'], ['--model'], ['--dispatch'], ['--queue'], ['--snapshot'])
 consumer = sys.argv[1:] == ['--consumer']
 snapshot = sys.argv[1:] == ['--snapshot']
 queue = snapshot or sys.argv[1:] == ['--queue']
 dispatch = queue or sys.argv[1:] == ['--dispatch']
 model = dispatch or sys.argv[1:] == ['--model']
 apply_original = bool(sys.argv[1:])
 prefix = 'flash_model_snapshot_cpu_' if snapshot else ('flash_model_queue_cpu_' if queue else ('flash_model_dispatch_cpu_' if dispatch else ('flash_model_bridge_cpu_' if model else ('flash_menu_consumer_cpu_' if consumer else ('flash_apply_original_cpu_' if apply_original else 'flash_choices_cpu_')))))
 out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime(prefix+'%Y%m%dT%H%M%S%fZ')
 r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='gui-flash-choices'))
 print('Prove:', out, flush=True)
 try:
  r.prepare()
  if dispatch:
   sim=LAB/'install/bin/arc-elf32-run'; assert sha(sim)==json.loads(BUILD.read_text())['experimental_sha256']
   r.experimental_engine=LAB; r.input_hashes[str(sim)]=sha(sim); r.input_hashes[str(BUILD)]=sha(BUILD)
  dump = ROOT / 'DUMPS/MainCode.dmp'; data = dump.read_bytes(); r.input_hashes[str(dump)] = sha(dump)
  if model:
   for source in (ROOT/'AkeruOS/ui/menu.c',ROOT/'AkeruOS/ui/menu.h'): r.input_hashes[str(source)]=sha(source)
  tbm = ROOT / 'S33-sections/02_TBM_SK501_payload.bin'; image = tbm.read_bytes(); r.input_hashes[str(tbm)] = sha(tbm)
  spans = [(0x784640,112), (0x784714,80), (0x6646c0,0x30), (0x664890,0x14a), (0x631d60,0x38), (0x631db8,0x48), (0x632694,0x66), (0xcde44,0x13a), (0xcdc80,0x16e), (0xcddf0,0x50)]
  for a,n in spans:
   b,o = locate(a,n); assert raw(a,n) == data[b['offset']+o:b['offset']+o+n], hex(a)
  assert u32(0x6647f0)==0x6820c0 and u32(0xcddf4)==0xc8ec0e and u32(0xcde14)==0xc8ec0d
  if apply_original:
   for a,n in ((0xde3a4,0x50),(0xde214,4),(0xf6f0c,8)):
    b,o=locate(a,n); assert raw(a,n)==data[b['offset']+o:b['offset']+o+n],hex(a)
  if queue:
   for a,n in ((0x16f6a4,0x88),(0x16f72c,0x13c),(0x17bc7c,0x68),(0x17bd4c,0x4c)):
    b,o=locate(a,n); assert raw(a,n)==data[b['offset']+o:b['offset']+o+n],hex(a)
  if snapshot:
   for a,n in ((0x2d62d8,0x28),(0x1406d0,0x30),(0x16ec38,0x4e),(0x16e6e0,0x150),(0x16f86c,0x80),(0x392f04,320)):
    b,o=locate(a,n); assert raw(a,n)==data[b['offset']+o:b['offset']+o+n],hex(a)
   assert u32(0xf6f10)==0x37fbd0
  if consumer:
   b,o=locate(0xe27e8,0xe0); assert raw(0xe27e8,0xe0)==data[b['offset']+o:b['offset']+o+0xe0]
  if dispatch:
   for a,n in ((0x169d78,0x124),(0x145020,0x5c),(0x77f728,0x58),(0x9802ac,28)):
    b,o=locate(a,n); assert raw(a,n)==data[b['offset']+o:b['offset']+o+n],hex(a)
  choices = [(0x700, 16, 4, 'Auto flash', 'Flash auto'), (0x2180, 18, 1, 'Flash off', 'No flash'), (0x2700, 17, 8, 'Always fire flash', 'Flash sempre attivo')]
  rows = []
  for i,(event, text_id, value, english, italian) in enumerate(choices,1):
   record = 0x784640+28*i
   assert u32(record+12)==text_id and u32(record+16)==value
   texts=[]
   for lang in (1,5):
    off=u32(0x3bb118+4+4*lang); size=u32(0x3bb118+152+4*lang); base=0xc7a000+off
    chunk=image[base:base+size]; assert chunk==data[base:base+size]
    start=0x5f8+struct.unpack_from('<I',chunk,4+4*text_id)[0]
    texts.append(chunk[start:chunk.index(b'\0',start)].decode('ascii'))
   assert texts==[english,italian], texts
   rows.append(dict(event=hex(event),record=hex(record),text_id=text_id,value=value,english=english,italian=italian))
  images={i:bytearray(PS[i]) for i in ((0,1,2,3,4,5,8) if dispatch else ((0,1,2,3,8) if apply_original else (0,2,3,8)))}; maps=[]; patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm); p=out/(name+'.bin')
   x=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]); assert x.returncode==0,x.stdout
   b=p.read_bytes(); p.write_bytes(b+bytes(8+(-len(b))%8)); return p
  def mapping(p,a,n): return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  def install(name,addr,asm):
   p=binary(name,asm); fixture=0x2030000+len(patches)*0x100
   maps.extend(mapping(p,fixture,p.stat().st_size))
   jump=binary('jump_'+name,f' mov_s r12,{fixture:#x}\n j_s [r12]\n').read_bytes()[:8]
   b,o=locate(addr,8); before=bytes(images[b['index']][o:o+8]); assert before==raw(addr,8)
   images[b['index']][o:o+8]=jump; patches.append(dict(name=name,address=hex(addr),original=before.hex(),fixture=jump.hex()))
  install('mode',0xcad30,' mov r10,0x2000000\n ld r10,[r10]\n ld r0,[r10]\n j_s [blink]\n')
  install('mode46_enabled',0xce8f0,' mov r0,1\n j_s [blink]\n')
  if not apply_original: install('apply_record',0xde3a4,' mov r10,0x2000000\n ld r10,[r10]\n st r0,[r10,4]\n j_s [blink]\n')
  install('open_record',0x1453e4,' mov r10,0x2000000\n ld r10,[r10]\n st r0,[r10,8]\n st r1,[r10,12]\n j_s [blink]\n')
  for name,addr in [('notify',0xcbdf8),('refresh',0x177030)]: install(name,addr,' mov r0,0\n j_s [blink]\n')
  if dispatch:
   for name,addr in [('lock',0x1593ac),('unlock',0x1594a4),('dispatch1',0x1786e8),('dispatch2',0x179354),('dispatch3',0x158cbc),('dispatch4',0x17c150)]:
    install(name,addr,' mov r0,0\n j_s [blink]\n')
  if consumer:
   install('measurement',0xfd1d8,' mov r0,0\n j_s [blink]\n')
   install('copy',0x128c20,' mov r1,0\n st r1,[r0,4]\n j_s [blink]\n')
   install('fill',0xf6f54,' j_s [blink]\n')
   install('condition_object',0xf6f04,' mov r0,0x2005000\n j_s [blink]\n')
   install('flag',0x103fd8,' mov r0,0\n j_s [blink]\n')
  tests=[(event,value,mode,guard) for event,_,value,_,_ in choices if not model or value in (1,8) for mode in (0x2c,0x46,8) for guard in ((0,1) if consumer else (0,))]
  asm=(' sr 0,[0x48]\n' if queue else '')+' mov r20,0x2000000\n'
  for i,(event,value,mode,guard) in enumerate(tests):
   asm+=f''' mov r21,{0x2001000+i*64:#x}
 st r21,[r20]
 mov r0,{mode}
 st r0,[r21]
 mov r0,0x4004
 mov r1,0x6820c0
 sth r0,[r1]
 mov r0,0
 sth r0,[r1,2]
 mov r0,0x2003000
 st r0,[r1,4]
 mov r0,2
 stb r0,[r1,10]
 mov r1,0x2003000
 mov r0,0x784640
 st r0,[r1,48]
 mov r0,4
 stb r0,[r1,47]
 stb r0,[r1,52]
 mov r1,0xc8ec0d
 mov r0,0xa5
 stb r0,[r1]
 mov r0,0xb6
 stb r0,[r1,1]
'''
   if apply_original:
    asm+=''' mov r1,0x37fbd0
 mov r0,0xa7
 stb r0,[r1,6]
 mov r2,0x1a6
 add r2,r1,r2
 stb r0,[r2]
 mov r2,0x1ac
 add r2,r1,r2
 mov r0,0x12345678
 st r0,[r2]
'''
   asm+=f'''
 st sp,[r21,16]
'''
   if model:
    asm+=''' mov r0,0
 st r0,[r21,56]
'''
    if dispatch:
     asm+=''' mov r1,0x366e94
 mov r0,0x77f728
 st r0,[r1]
 mov r0,22
 sth r0,[r1,4]
 mov r0,0x2050000
 st r0,[r1,16]
 mov r0,0
 st r0,[r1,24]
 mov r1,0x367814
 mov r0,1
 stb r0,[r1]
'''
    if queue:
     asm+=''' mov r0,0
 mov r1,0x681b6b
 stb r0,[r1]
 mov r1,0x367bbc
 st r0,[r1]
 mov r1,0x3678f9
 mov r0,1
 stb r0,[r1]
'''
    if snapshot:
     asm+=''' mov r1,0x366de8
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
'''
    for step,e in enumerate((0x580,0x2700,0x2180,0x700 if value==8 else 0x2180)):
     if queue:
      key={0x580:11,0x2700:78,0x2180:67,0x700:14}[e]; a=0x2006000+(i*4+step)*64
      asm+=f''' mov r22,{a:#x}
 mov r1,{0x446808+key*4+2:#x}
 mov r0,1
 sth r0,[r1]
'''
      if snapshot:
       bit={0x580:12,0x2700:13,0x2180:8,0x700:7}[e]
       ra=0xffff & ~(1<<(bit-10)) if bit in (12,13) else 0xffff; rb=0xffff & ~(1<<bit)
       snap=0x2008000+(i*4+step)*8
       asm+=f''' mov r1,0xfe70224
 mov r0,{ra:#x}
 sth r0,[r1]
 mov r0,{rb:#x}
 sth r0,[r1,4]
 mov r12,0x2d62d8
 jl [r12]
 mov r1,{snap:#x}
 st r0,[r1]
 mov r12,0x1406d0
 jl [r12]
'''
      else: asm+=f'''
 mov r0,255
 mov r1,{key}
 mov r2,1
 mov r3,1
 mov r12,0x16f72c
 jl [r12]
'''
      asm+='''
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
 ld r0,[r21,60]
 st r0,[r22,20]
'''
      if snapshot:
       asm+=f''' mov r1,0xfe70224
 mov r0,0xffff
 sth r0,[r1]
 sth r0,[r1,4]
 mov r12,0x2d62d8
 jl [r12]
 mov r1,{snap+4:#x}
 st r0,[r1]
 mov r12,0x1406d0
 jl [r12]
'''
      else: asm+=f'''
 mov r0,255
 mov r1,{key}
 mov r2,0
 mov r3,1
 mov r12,0x16f72c
 jl [r12]
'''
      asm+='''
 add r0,r22,32
 mov r12,0x17bd4c
 jl [r12]
 st r0,[r22,44]
 ld r0,[r22,32]
 ldh.x r1,[r22,36]
 ld r2,[r22,40]
 mov r12,0x169e1c
 jl [r12]
 st r0,[r22,48]
 ld r0,[r21,60]
 st r0,[r22,52]
 add r0,r21,60
 bl akeru_menu_take_action
 st r0,[r22,56]
 ld r0,[r21,56]
 st r0,[r22,60]
'''
     elif dispatch:
      asm+=f' mov r0,0\n mov r1,{e:#x}\n mov r2,0\n mov r12,0x169e1c\n jl [r12]\n'
     else:
      asm+=f' add r0,r21,56\n mov r1,{e:#x}\n add r2,r21,60\n bl akeru_menu_event\n'
    if queue: asm+=' ld r0,[r22,56]\n st r0,[r21,60]\n'
    asm+=f'''
 ld r0,[r21,60]
 mov r1,0
 cmp r0,8
 bne model_off_{i}
 mov r1,0x2700
 b model_selected_{i}
model_off_{i}:
 cmp r0,9
 bne model_selected_{i}
 mov r1,0x2180
model_selected_{i}:
'''
   else:
    asm+=f' mov r1,{event:#x}\n'
   asm+='''
 mov r0,0
 mov r2,0
 mov r12,0x6646c0
 jl [r12]
 st sp,[r21,20]
 mov r1,0xc8ec0d
 ldb r0,[r1]
 st r0,[r21,24]
 ldb r0,[r1,1]
 st r0,[r21,28]
'''
   if apply_original:
    asm+=''' mov r1,0x37fbd0
 ldb r0,[r1,6]
 st r0,[r21,32]
 mov r2,0x1a6
 add r2,r1,r2
 ldb r0,[r2]
 st r0,[r21,36]
 mov r2,0x1ac
 add r2,r1,r2
 ld r0,[r2]
 st r0,[r21,40]
 mov r12,0xde3e4
 jl [r12]
 st r0,[r21,44]
'''
   if consumer:
    asm+=f''' mov r1,0x2005000
 mov r0,{guard}
 st r0,[r1,32]
 mov r1,0x2004000
 mov r0,1
 stb r0,[r1,41]
 mov r0,0
 sth r0,[r1,76]
 mov r12,0xe27e8
 jl [r12]
 st r0,[r21,48]
 st sp,[r21,52]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  if dispatch:
   asm+='menu_callback:\n push_s blink\n mov r0,0x2000000\n ld r0,[r0]\n add r2,r0,60\n add r0,r0,56\n bl '+('akeru_menu_defer_event' if queue else 'akeru_menu_event')+'\n pop_s blink\n j_s [blink]\n'
  for i,img in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(img);maps+=mapping(p,BS[i]['load_address_candidate'],len(img))
  regions=[('current',0x2000000,8),('cases_data',0x2001000,len(tests)*64),('context',0x2003000,256)]
  if consumer: regions += [('consumer_context',0x2004000,256),('condition',0x2005000,256)]
  if queue: regions += [('steps',0x2006000,len(tests)*4*64),('key_state',0x446000,0x2000),('queue_state',0x47a000,0x2000)]
  if snapshot: regions += [('snapshots',0x2008000,len(tests)*4*8),('mmio',0xfe70224,8)]
  for name,addr,size in regions:
   p=out/(name+'.bin'); p.write_bytes(bytes(size+(addr%8))); maps+=mapping(p,addr,size)
  if model:
   (out/'cases.s').write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n'+asm+'\n.section .stack,"aw",@nobits\n.align 16\n.space 16384\n')
   for name,cmd in [('compile_menu',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-O2','-ffreestanding','-fno-builtin','-c',ROOT/'AkeruOS/ui/menu.c','-o',out/'menu.o']),('assemble',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',out/'cases.o',out/'cases.s']),('link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',LEGACY/'tests/smoke.ld','-o',out/'cases.elf',out/'cases.o',out/'menu.o'])]:
    result=r.command(name,cmd); assert result.returncode==0,result.stdout
   elf=out/'cases.elf'
   if dispatch:
    result=r.command('symbols',['arc-snps-elf-nm',elf]); assert result.returncode==0
    callbacks=[int(line.split()[0],16) for line in result.stdout.splitlines() if line.endswith(' t menu_callback')]; assert len(callbacks)==1
    desc=bytearray(raw(0x9802ac,28)); assert struct.unpack_from('<I',desc,12)[0]==0x7cafe8
    struct.pack_into('<I',desc,12,callbacks[0]); p=out/'synthetic_descriptor.bin';p.write_bytes(desc+bytes(4));maps+=mapping(p,0x2050000,p.stat().st_size)
  else: elf=compile_probe(r,'cases',asm)
  result,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert result['exit_code']==0 and result['fault'] is None,log
  data_cases=(out/'cases_data.bin').read_bytes(); cases=[]
  for i,(event,value,mode,guard) in enumerate(tests):
   w=struct.unpack_from('<8I',data_cases,i*64)
   applied=value if mode!=8 else 26
   expected46=value if mode==0x46 else 0xa5; expected2c=value if mode==0x2c else 0xb6
   assert w==(mode,0 if apply_original else applied,0x87,0,w[4],w[4],expected46,expected2c),(i,w)
   extra=struct.unpack_from('<3I',data_cases,i*64+32)
   readback=struct.unpack_from('<I',data_cases,i*64+44)[0]
   if apply_original: assert extra==(applied,applied,0) and readback==applied,(i,extra,readback)
   consumer_result,consumer_sp=struct.unpack_from('<2I',data_cases,i*64+48)
   if consumer: assert consumer_sp==w[4] and consumer_result==(0 if guard and applied!=1 else 8),(i,consumer_result,consumer_sp)
   model_screen,model_action=struct.unpack_from('<2I',data_cases,i*64+56)
   if model: assert (model_screen,model_action)==(4,8 if value==8 else 9),(i,model_screen,model_action)
   cases.append(dict(event=hex(event),mode=hex(mode),record_value=value,apply_argument=applied,stored_mode46=w[6],stored_mode2c=w[7],object_offsets={'0x6':extra[0],'0x1a6':extra[1],'0x1ac':extra[2]} if apply_original else None,object_readback=readback if apply_original else None,consumer_guard=guard if consumer else None,consumer_result=consumer_result if consumer else None,model_action=model_action if model else None,open_object=hex(w[2]),open_argument=w[3],stack_preserved=True))
  trace=(out/'cases.trace').read_text()
  for address,count in [(0x6646c0,len(tests)),(0x632694,len(tests)),(0x631d60,len(tests)),(0xcde44,len(tests)),(0xcdc80,len(tests))]:
   assert sum(line.startswith(f'0x{address:06x} ') for line in trace.splitlines())==count,hex(address)
  if apply_original:
   for address,count in [(0xde3a4,len(tests)),(0xde3e4,len(tests)*(2 if consumer else 1)),(0xf6f0c,len(tests)*(5 if consumer else 4))]:
    assert sum(line.startswith(f'0x{address:06x} ') for line in trace.splitlines())==count,hex(address)
  if consumer: assert sum(line.startswith('0x0e27e8 ') for line in trace.splitlines())==len(tests)
  if dispatch: assert sum(line.startswith('0x169e1c ') for line in trace.splitlines())==len(tests)*(8 if queue else 4)
  if queue:
   steps=(out/'steps.bin').read_bytes()
   for i,(event,value,mode,guard) in enumerate(tests):
    for step,e in enumerate((0x580,0x2700,0x2180,0x700 if value==8 else 0x2180)):
     off=(i*4+step)*64; w=struct.unpack_from('<16I',steps,off); action=1 if step<3 else (8 if value==8 else 9)
     assert struct.unpack_from('<Ih2xII',steps,off)==(0,e,0,1),(i,step,w)
     assert struct.unpack_from('<Ih2xII',steps,off+32)==(0,e|1,0,1),(i,step,w)
     assert (w[4],w[5],w[12],w[13],w[14],w[15])==(1,action,1,action,action,(1,3,4,4)[step]),(i,step,w)
   for address in ('0x16f72c','0x16f6b0','0x17bc7c','0x17bd4c'):
    assert any(line.startswith(address+' ') for line in trace.splitlines()),address
  if snapshot:
   snapshots=(out/'snapshots.bin').read_bytes()
   for i,(event,value,mode,guard) in enumerate(tests):
    for step,e in enumerate((0x580,0x2700,0x2180,0x700 if value==8 else 0x2180)):
     bit={0x580:12,0x2700:13,0x2180:8,0x700:7}[e]
     assert struct.unpack_from('<II',snapshots,(i*4+step)*8)==(0x3ffffff^(1<<bit),0x3ffffff)
   for address in ('0x2d62d8','0x1406d0','0x16ec38','0x16e6e0','0x16f86c'):
    assert any(line.startswith(address+' ') for line in trace.splitlines()),address
  (out/'choices.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'cases.json').write_text(json.dumps(cases,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'gnu_windows.txt').write_text(disasm(0x664890,0x6649d8)+disasm(0x631d60,0x631d96)+disasm(0x632694,0x6326fa)+disasm(0xcde44,0xcde68)+disasm(0xcdece,0xcded6))
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  assert sha(dump)==r.input_hashes[str(dump)] and sha(tbm)==r.input_hashes[str(tbm)]
  r.results.update(status='PASS_FLASH_MODEL_SNAPSHOT_SYNTHETIC' if snapshot else ('PASS_FLASH_MODEL_QUEUE_SYNTHETIC' if queue else ('PASS_FLASH_MODEL_DISPATCH_SYNTHETIC' if dispatch else ('PASS_FLASH_MODEL_BRIDGE_SYNTHETIC' if model else ('PASS_FLASH_MENU_CONSUMER_SYNTHETIC' if consumer else ('PASS_FLASH_APPLY_ORIGINAL_SYNTHETIC' if apply_original else 'PASS_FLASH_MENU_CHOICES_SYNTHETIC'))))),choices=rows,scenarios=cases,assumptions=['Synthetic menu context with original records, injected events and unfiltered wrapper.','Modes 0x2c, 0x46 and 8 are supplied by fixture; mode46 guard returns 1.','Notification, refresh and window open are fixtures.' if apply_original else 'Apply, notification, refresh and window open are fixtures.'] + (['The bank calls consumer after the menu; measurement, initialization, condition object and final flag are fixtures.'] if consumer else []) + (['The harness maps model FLASH_ON/OFF to original events 2700/2180 and invokes the original wrapper; this mapping is a laboratory bridge.'] if model else []) + (['The harness extracts each logical-key queue record and calls the original dispatcher; it takes each pending action after release.'] if queue else (['The harness injects four presses directly into the original dispatcher; current descriptor and callback are synthetic.'] if dispatch else [])) + (['Snapshot reader uses synthetic MMIO; harness explicitly calls 1406D0 with each snapshot.'] if snapshot else []),limits=['No physical button mapping, display, scheduler, device actuation or actual camera mode.', 'Mode 8 default readback is 26; no inference of intended flash support.', 'Object storage is synthetic, not an observed camera RAM state.' if apply_original else 'Language names are conditional on verified resource loader and language blocks.'])
  r.finish()
 except Exception as e:
  r.results.update(status='FAIL',error=repr(e)); raise
 finally:r.save()
 print('PASS:',len(tests),'synthetic flash selection cases;',out,flush=True)
if __name__=='__main__':main()
