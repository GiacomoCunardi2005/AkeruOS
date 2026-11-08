#!/usr/bin/env python3
"""Connect original key/queue/manager dispatcher to C menu through a laboratory callback."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate


def main():
 queued='--queued' in sys.argv
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime(('manager_buffered_menu_cpu_' if queued else 'manager_deferred_menu_cpu_')+'%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='original-manager-menu-model'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); build=json.loads(BUILD.read_text()); sim=LAB/'install/bin/arc-elf32-run'
  assert sha(sim)==build['experimental_sha256']; r.experimental_engine=LAB
  sources=[ROOT/'AkeruOS/ui/menu.c',ROOT/'AkeruOS/ui/menu.h',Path(__file__),ROOT/'DUMPS/MainCode.dmp',sim,BUILD]
  for p in sources:r.input_hashes[str(p)]=sha(p)
  dump=sources[3].read_bytes()
  for address,size in [(0x15af1c,0x2e),(0x17bc24,8),(0x16f6a4,0x88),(0x16f72c,0x13c),(0x17bc7c,0x68),(0x17bd4c,0x4c),(0x169d78,0x124),(0x16a028,0x34),(0x16a6e4,0xc0),(0x145020,0x5c),(0x77f728,0x58),(0x9802ac,0x1c),(0x7cafe8,8)]:
   block,offset=locate(address,size);assert raw(address,size)==dump[block['offset']+offset:block['offset']+offset+size]
  images={i:bytearray(PS[i]) for i in (0,1,2,3,4,5)};maps=[];patches=[]
  def run(name,args):
   result=r.command(name,args);assert result.returncode==0,result.stdout;return result.stdout
  def mapping(p,a,n):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  stub=compile_probe(r,'noop',' mov r0,0\n j_s [blink]\n');p=out/'noop.bin'
  run('extract_stub',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',stub,p]);b=p.read_bytes();p.write_bytes(b+bytes(8+(-len(b))%8));maps+=mapping(p,0x2030000,p.stat().st_size)
  entry=compile_probe(r,'noop_entry',' mov_s r12,0x2030000\n j_s [r12]\n');p=out/'noop_entry.bin'
  run('extract_entry',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',entry,p]);patch=p.read_bytes()[:8]
  for address in (0x1593ac,0x1594a4,0x1786e8,0x179354,0x158cbc,0x17c150):
   block,offset=locate(address,8);before=bytes(images[block['index']][offset:offset+8]);assert before==raw(address,8)
   images[block['index']][offset:offset+8]=patch;patches.append(dict(address=hex(address),original=before.hex(),fixture=patch.hex()))
  stop=compile_probe(r,'loop_stop',' mov r0,0\n mov r8,1\n trap_s 1\n');p=out/'loop_stop.bin'
  run('extract_stop',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',stop,p]);b=p.read_bytes();p.write_bytes(b+bytes(8+(-len(b))%8));maps+=mapping(p,0x2031000,p.stat().st_size)
  stop_entry=compile_probe(r,'loop_stop_entry',' mov_s r12,0x2031000\n j_s [r12]\n');p=out/'loop_stop_entry.bin'
  run('extract_stop_entry',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',stop_entry,p]);patch=p.read_bytes()[:8]
  block,offset=locate(0x17bc24,8);before=bytes(images[block['index']][offset:offset+8]);assert before==raw(0x17bc24,8)
  images[block['index']][offset:offset+8]=patch;patches.append(dict(address='0x17bc24',original=before.hex(),fixture=patch.hex(),purpose='stop loop at next empty-queue wait'))
  keys=[11,14,67,78];events=[0x580,0x700,0x2180,0x2700]
  actions=[[1,1,0,7],[1,2,3,1],[1,5,6,0]]
  views=[[1,2,0,0],[0,1,1,3],[0,2,2,2]]
  tests=[(view,slot) for view in range(3) for slot in range(4)]
  asm=' mov r20,0x2000000\n'
  for i,(view,slot) in enumerate(tests):
   a=0x2001000+i*96
   asm+=f''' mov r21,{a:#x}
 st r21,[r20]
 mov r0,{view}
 st r0,[r21]
 st sp,[r21,24]
 mov r0,0
 mov r1,0x681b6b
 stb r0,[r1]
 mov r1,0x367bbc
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
 mov r0,{a+32:#x}
 mov r12,0x17bd4c
 jl [r12]
 st r0,[r21,44]
 mov r1,0x366e94
 mov r0,0x77f728
 st r0,[r1]
 mov r0,22
 sth r0,[r1,4]
 mov r0,0x9802ac
 st r0,[r1,16]
 mov r0,0
 st r0,[r1,24]
 mov r1,0x367814
 mov r0,1
 stb r0,[r1]
 ld r0,[r21,32]
 ldh.x r1,[r21,36]
 ld r2,[r21,40]
 mov r12,0x169e1c
 jl [r12]
 st r0,[r21,8]
 ld r0,[r21,4]
 st r0,[r21,64]
 mov r0,255
 mov r1,{keys[slot]}
 mov r2,0
 mov r3,1
 mov r12,0x16f72c
 jl [r12]
 mov r0,{a+48:#x}
 mov r12,0x17bd4c
 jl [r12]
 st r0,[r21,60]
 ld r0,[r21,48]
 ldh.x r1,[r21,52]
 ld r2,[r21,56]
 mov r12,0x169e1c
 jl [r12]
 st r0,[r21,16]
 ld r0,[r21,4]
 st r0,[r21,12]
 add r0,r21,4
 bl akeru_menu_take_action
 st r0,[r21,68]
 ld r0,[r21]
 st r0,[r21,20]
 st sp,[r21,28]
'''
  # A second action arrives while ISO is pending; only the harness retries it.
  asm+='''
 mov r21,0x2003000
 st r21,[r20]
 mov r0,1
 st r0,[r21]
 mov r0,2
 st r0,[r21,4]
 mov r0,0
 mov r1,0x681b6b
 stb r0,[r1]
 mov r1,0x367bbc
 st r0,[r1]
 mov r1,0x3678f9
 mov r0,1
 stb r0,[r1]
 mov r1,0x446916
 sth r0,[r1]
 mov r0,255
 mov r1,67
 mov r2,1
 mov r3,1
 mov r12,0x16f72c
 jl [r12]
 add r0,r21,32
 mov r12,0x17bd4c
 jl [r12]
 st r0,[r21,44]
 ld r0,[r21,32]
 ldh.x r1,[r21,36]
 ld r2,[r21,40]
 mov r12,0x169e1c
 jl [r12]
 st r0,[r21,8]
 ld r0,[r21,72]
 st r0,[r21,48]
 ld r0,[r21]
 st r0,[r21,12]
 ld r0,[r21,4]
 st r0,[r21,16]
 add r0,r21,4
 bl akeru_menu_take_action
 st r0,[r21,20]
 ld r0,[r21,32]
 ldh.x r1,[r21,36]
 ld r2,[r21,40]
 mov r12,0x169e1c
 jl [r12]
 st r0,[r21,24]
 ld r0,[r21,72]
 st r0,[r21,52]
 ld r0,[r21,4]
 st r0,[r21,28]
 mov r21,0x2004000
 st r21,[r20]
 mov r0,1
 st r0,[r21]
 mov r0,2
 st r0,[r21,4]
 mov r0,0
 mov r1,0x681b6b
 stb r0,[r1]
 mov r1,0x367bbc
 st r0,[r1]
 mov r1,0x3678f9
 mov r0,1
 stb r0,[r1]
 mov r1,0x446916
 sth r0,[r1]
 mov r1,0x446836
 sth r0,[r1]
 mov r0,255
 mov r1,67
 mov r2,1
 mov r3,1
 mov r12,0x16f72c
 jl [r12]
 mov r0,255
 mov r1,11
 mov r2,1
 mov r3,1
 mov r12,0x16f72c
 jl [r12]
 sub sp,sp,16
 mov r13,sp
 mov r12,0x15af2e
 j [r12]
menu_callback:
 push_s blink
 mov r0,0x2000000
 ld r0,[r0]
 mov r3,0x2004000
 cmp r0,r3
 bne 1f
 ld r3,[r0,76]
 asl r3,r3,2
 add r3,r0,r3
 st r1,[r3,80]
 ld r3,[r0,76]
 add r3,r3,1
 st r3,[r0,76]
1:
 add r2,r0,4
 bl akeru_menu_defer_event
 mov r1,0x2000000
 ld r1,[r1]
 st r0,[r1,72]
 mov r3,0x2004000
 cmp r1,r3
 bne 2f
 ld r3,[r1,76]
 sub r3,r3,1
 asl r3,r3,2
 add r3,r1,r3
 st r0,[r3,88]
2:
 pop_s blink
 j_s [blink]
'''
  if queued:
   needle=' mov r0,2\n st r0,[r21,4]\n'
   pos=asm.rfind(needle);assert pos>=0
   asm=asm[:pos]+asm[pos:].replace(needle,' mov r0,1\n st r0,[r21,24]\n',1)
   needle=' add r2,r0,4\n bl akeru_menu_defer_event\n'
   assert asm.count(needle)==1
   asm=asm.replace(needle,''' mov r3,0x2004000
 cmp r0,r3
 bne 3f
 bl akeru_menu_enqueue
 b 4f
3:
 add r2,r0,4
 bl akeru_menu_defer_event
4:
''')
   asm+='''
loop_finish:
 mov r21,0x2004000
 mov r0,r21
 mov r1,0
 bl akeru_menu_complete
 st r0,[r21,32]
 mov r0,r21
 bl akeru_menu_next
 st r0,[r21,36]
 mov r0,r21
 mov r1,0
 bl akeru_menu_complete
 st r0,[r21,40]
 mov r0,r21
 bl akeru_menu_next
 st r0,[r21,44]
 ld r0,[r21]
 st r0,[r21,48]
 mov r0,r21
 mov r1,0
 bl akeru_menu_complete
 st r0,[r21,52]
 mov r0,r21
 bl akeru_menu_next
 st r0,[r21,56]
 mov r0,0
 mov r8,1
 trap_s 1
'''
  statefile=out/'cases.bin';statefile.write_bytes(bytes(len(tests)*96));maps+=mapping(statefile,0x2001000,len(tests)*96)
  busyfile=out/'busy.bin';busyfile.write_bytes(bytes(96));maps+=mapping(busyfile,0x2003000,96)
  loopfile=out/'loop.bin';loopfile.write_bytes(bytes(96));maps+=mapping(loopfile,0x2004000,96)
  p=out/'current.bin';p.write_bytes(bytes(8));maps+=mapping(p,0x2000000,8)
  for name,addr in (('key_state',0x446000),('queue',0x47a000)):
   p=out/(name+'.bin');p.write_bytes(bytes(0x2000));maps+=mapping(p,addr,0x2000)
  flags=['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-O2','-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-c']
  run('compile_menu',flags+[sources[0],'-o',out/'menu.o'])
  (out/'cases.s').write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n'+asm+'\n.section .stack,"aw",@nobits\n.align 16\n.space 16384\n')
  run('assemble',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',out/'cases.o',out/'cases.s'])
  run('link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',LEGACY/'tests/smoke.ld','-o',out/'cases.elf',out/'cases.o',out/'menu.o'])
  assert not run('undefined',['arc-snps-elf-nm','-u',out/'cases.elf']).strip()
  symbols=run('symbols',['arc-snps-elf-nm',out/'cases.elf']).splitlines()
  entries=[int(line.split()[0],16) for line in symbols if line.endswith(' T akeru_menu_defer_event')]
  assert len(entries)==1
  callbacks=[int(line.split()[0],16) for line in symbols if line.endswith(' t menu_callback')]
  assert len(callbacks)==1
  if queued:
   finish=[int(line.split()[0],16) for line in symbols if line.endswith(' t loop_finish')];assert len(finish)==1
   trampoline=compile_probe(r,'loop_finish_entry',f' mov_s r12,{finish[0]:#x}\n j_s [r12]\n')
   p=out/'loop_finish_entry.bin';run('extract_finish',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',trampoline,p])
   stopfile=out/'loop_stop.bin';b=p.read_bytes();assert len(b)<=stopfile.stat().st_size
   stopfile.write_bytes(b+bytes(stopfile.stat().st_size-len(b)))
  callback_entry=compile_probe(r,'callback_entry',f' mov_s r12,{callbacks[0]:#x}\n j_s [r12]\n')
  p=out/'callback_entry.bin'
  run('extract_callback',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',callback_entry,p])
  patch=p.read_bytes()[:8];block,offset=locate(0x7cafe8,8);before=bytes(images[block['index']][offset:offset+8]);assert before==raw(0x7cafe8,8)
  images[block['index']][offset:offset+8]=patch;patches.append(dict(address='0x7cafe8',original=before.hex(),fixture=patch.hex(),purpose='laboratory callback to C model'))
  for i,image in images.items():
   p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(image);maps+=mapping(p,BS[i]['load_address_candidate'],len(image))
  case,log=r.run('cases','/result/cases.elf',maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
  assert 'S33_DSP_GUARD' not in log
  data=statefile.read_bytes();rows=[]
  for i,(view,slot) in enumerate(tests):
   w=struct.unpack_from('<18I',data,i*96)
   assert (w[0],w[1],w[2],w[3],w[4],w[5],w[16])==(views[view][slot],0,1,actions[view][slot],1,views[view][slot],actions[view][slot]) and w[6]==w[7] and w[17]==actions[view][slot],(view,slot,w)
   assert struct.unpack_from('<Ih2xII',data,i*96+32)==(0,events[slot],0,1)
   assert struct.unpack_from('<Ih2xII',data,i*96+48)==(0,events[slot]|1,0,1)
   rows.append(dict(initial_screen=view,logical_key=keys[slot],event=hex(events[slot]),action=w[16],screen=w[0],handled=w[2],release_action=w[3],release_handled=w[4],stack_preserved=True))
  trace=(out/'cases.trace').read_text()
  busy=struct.unpack_from('<14I',busyfile.read_bytes())
  assert (busy[2],busy[3],busy[4],busy[5],busy[6],busy[7],busy[11],busy[12],busy[13])==(1,1,2,2,1,3,1,0xfffffffe,1),busy
  assert struct.unpack_from('<Ih2xI',busyfile.read_bytes(),32)==(0,0x2180,0),busy
  loop=struct.unpack_from('<24I',loopfile.read_bytes())
  if queued:
   assert (loop[0],loop[5],loop[6],loop[7],loop[8],loop[9],loop[10],loop[11],loop[12],loop[13],loop[14],loop[19],loop[20],loop[21],loop[22],loop[23])==(1,0,0,0,1,3,1,0,1,0xffffffff,0,2,0x2180,0x580,1,1),loop
  else:
   assert (loop[0],loop[1],loop[18],loop[19],loop[20],loop[21],loop[22],loop[23])==(1,2,0xfffffffe,2,0x2180,0x580,0xfffffffe,0xfffffffe),loop
  assert sum(int(line.split()[0],16)==entries[0] for line in trace.splitlines() if line.startswith('0x'))==(26 if queued else 28)
  assert sum(int(line.split()[0],16)==callbacks[0] for line in trace.splitlines() if line.startswith('0x'))==28
  assert sum(line.startswith('0x15af2e ') for line in trace.splitlines())==3
  for address in ('0x16f72c','0x16f6b0','0x17bc7c','0x17bd4c','0x169e1c','0x169d78','0x7cafe8'):
   assert any(line.startswith(address+' ') for line in trace.splitlines()),address
  assert all(sha(p)==r.input_hashes[str(p)] for p in sources)
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'busy.json').write_text(json.dumps(dict(manager_busy_return=busy[2],callback_busy_return=-2,screen_after_busy=busy[3],pending_after_busy=busy[4],taken=busy[5],manager_retry_return=busy[6],callback_retry_return=busy[13],pending_after_retry=busy[7],queue_extract_return=busy[11]),indent=2)+'\n')
  loop_result=dict(callback_count=loop[19],events=[hex(loop[20]),hex(loop[21])])
  if queued: loop_result.update(callback_returns=[1,1],actions=[loop[9]],discarded_events=['0x580'],screen_after=loop[0],queue_count=loop[5],stop='fixture drains queue and terminates')
  else: loop_result.update(initial_pending=2,screen_after=loop[0],pending_after=loop[1],callback_returns=[-2,-2],stop='fixture at next empty-queue wait')
  (out/'loop.json').write_text(json.dumps(loop_result,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_MANAGER_BUFFERED_ACTION' if queued else 'PASS_MANAGER_DEFERRED_ACTION',scenarios=rows,
   assumptions=['Original logical key writer, event producer, queue and manager dispatch on synthetic state; CaptureMenu callback replaced by a laboratory bridge to the deferred ARC700 C menu adapter.',
                'First cases have harness extraction and dispatch; final case enters original loop at 15AF2E with a prepared stack and stops at an empty-queue wait fixture; current descriptor and absence of active control are synthetic; synchronization, notification and filtering are fixtures.'],
   limits=['No physical input, scheduler, menu lifecycle, rendering or integration into original firmware.',
           'Single-threaded sequential test only; the harness completes actions; bounded queue overflow and modal event validity require a device policy.' if queued else 'Single-threaded sequential test only; full pending slot returns -2 and retry must be provided by caller; no action execution or concurrency guarantee.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS:',len(tests),'manager-to-menu cases;',out,flush=True)
if __name__=='__main__':main()
