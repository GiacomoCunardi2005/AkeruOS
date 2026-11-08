#!/usr/bin/env python3
"""Run original V1.1 WindowManager transition with synthetic callbacks."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32, disasm


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('window_transition_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-window-transition'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); dump=ROOT/'DUMPS/MainCode.dmp'; data=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x14503c,14),(0x14507c,28),(0x14510c,68),(0x145180,0x270),(0x169d78,8),(0x17bf60,8)]:
   block,off=locate(a,n);assert raw(a,n)==data[block['offset']+off:block['offset']+off+n]
  assert [u32(a) for a in (0x145350,0x145358,0x14535c,0x145370,0x145378)]==[0x366e94,0x366eb0,0x4403,0x4401,0x4405]
  (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in [(0x145180,0x1451b8),(0x1451b8,0x14520e),(0x1452e0,0x14530c),(0x145310,0x145350),(0x14537c,0x1453f2)]))
  images={i:bytearray(PS[i]) for i in (0,1,4,5)};maps=[];patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm);path=out/(name+'.bin');res=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path]);assert res.returncode==0,res.stdout
   value=path.read_bytes();path.write_bytes(value+bytes(8+(-len(value))%8));return path
  def mapping(path,addr):return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{path.stat().st_size}']
  dispatch=''' mov r10,0x2000000
 ld r10,[r10]
 ld r11,[r10,12]
 asl r12,r11,4
 add r12,r12,r10
 st r0,[r12,64]
 st r1,[r12,68]
 st r2,[r12,72]
 add r11,r11,1
 st r11,[r10,12]
 cmp r1,0x4403
 bne check_finish
 cmp r0,0x2100000
 bne other_start
 ld r0,[r10,0]
 j_s [blink]
other_start:
 ld r0,[r10,4]
 j_s [blink]
check_finish:
 cmp r1,0x4405
 bne normal
 ld r0,[r10,8]
 j_s [blink]
normal:
 mov r0,0
 j_s [blink]
'''
  for i,(name,addr,asm) in enumerate([('dispatch',0x169d78,dispatch),('publish',0x17bf60,' mov r0,0\n j_s [blink]\n')]):
   target=0x2030000+i*0x400;path=binary(name,asm);maps+=mapping(path,target)
   entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
   block,off=locate(addr,8);before=bytes(images[block['index']][off:off+8]);assert before==raw(addr,8);images[block['index']][off:off+8]=entry
   patches.append(dict(name=name,address=hex(addr),original=before.hex(),fixture=entry.hex()))
  # Missing ID response -2 permits the manager to continue; -1 requests fallback.
  tests=[('ordinary',0xfffffffe,0xfffffffe,0xfffffffe,0,0),('abort_4403',0xffffffff,0xfffffffe,0xfffffffe,0,0),
         ('redirect_4403',0x00070005,0xfffffffe,0xfffffffe,0,0),('fallback_absent_4405',0xfffffffe,0xfffffffe,0xffffffff,0,0),
         ('fallback_previous',0xffffffff,0xfffffffe,0xfffffffe,0x2100040,0),
         ('fallback_previous_blocked',0xffffffff,0xfffffffe,0xfffffffe,0x2100040,0x200)]
  state=bytearray(len(tests)*256); asm=' mov r20,0x2000000\n'
  for i,(name,a,b,c,previous,flags) in enumerate(tests):
   addr=0x2001000+i*256;struct.pack_into('<III',state,i*256,a,b,c)
   asm+=f''' mov r21,{addr:#x}
 st r21,[r20]
 mov r1,0x366e94
 mov r0,0x2101000
 st r0,[r1,8]
 mov r0,6
 sth r0,[r1,12]
 mov r0,{previous:#x}
 st r0,[r1,16]
 mov r0,0
 st r0,[r1,20]
 stb r0,[r1,39]
 mov r1,0x2100040
 mov r0,{flags:#x}
 st r0,[r1]
 st sp,[r21,16]
 mov r0,0x2100000
 mov r1,123
 mov r12,0x145180
 jl [r12]
 st r0,[r21,20]
 mov r1,0x366e94
 ld r0,[r1,16]
 st r0,[r21,24]
 ld r0,[r1,20]
 st r0,[r21,28]
 st sp,[r21,32]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,img in images.items():
   path=out/f'block{i}_LAB_FIXTURE.bin';path.write_bytes(img);maps+=mapping(path,BS[i]['load_address_candidate'])
  path=out/'cases.bin';path.write_bytes(state);maps+=mapping(path,0x2001000);statefile=path
  path=out/'current.bin';path.write_bytes(bytes(8));maps+=mapping(path,0x2000000)
  path=out/'descriptors.bin';path.write_bytes(bytes(128));maps+=mapping(path,0x2100000)
  table=bytearray(24);struct.pack_into('<I',table,20,0x2100040);path=out/'table.bin';path.write_bytes(table);maps+=mapping(path,0x2101000)
  elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
  rows=[];buf=statefile.read_bytes()
  for i,(name,a,b,c,previous,flags) in enumerate(tests):
   base=i*256;count,sp0,ret,current,other,sp1=struct.unpack_from('<6I',buf,base+12)
   assert count<=8 and sp0==sp1,(name,count,sp0,sp1)
   events=[struct.unpack_from('<3I',buf,base+64+j*16) for j in range(count)]
   rows.append(dict(name=name,returned=ret,current=hex(current),other=hex(other),events=[dict(descriptor=hex(x),event=hex(y),argument=hex(z)) for x,y,z in events],stack_preserved=True))
  (out/'observed.json').write_text(json.dumps(rows,indent=2)+'\n')
  expected=[(1,0x2100000,[0x4403,0x4401,0x4405]),(0,0,[0x4403]),(1,0x2100040,[0x4403,0x4403,0x4401,0x4405]),(0,0,[0x4403,0x4401,0x4405,0x4406,0x4402]),
            (1,0x2100040,[0x4403,0x4403,0x4401,0x4405]),(0,0x2100040,[0x4403])]
  for row,(ret,current,evs) in zip(rows,expected):
   assert row['returned']==ret and int(row['current'],16)==current and [int(x['event'],16) for x in row['events']]==evs,row
  assert [int(x['descriptor'],16) for x in rows[2]['events']]==[0x2100000,0x2100040,0x2100040,0x2100040]
  assert int(rows[0]['events'][1]['argument'],16)==123 and int(rows[2]['events'][2]['argument'],16)==7
  assert [int(x['descriptor'],16) for x in rows[4]['events']]==[0x2100000,0x2100040,0x2100040,0x2100040]
  assert int(rows[4]['events'][2]['argument'],16)==0
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_WINDOW_TRANSITION_SYNTHETIC_CALLBACKS',scenarios=rows,assumptions=['Original manager 145180 and interpreter 14510C; synthetic descriptors, table and callback responses.', 'Event dispatcher and publication service are fixtures.'],limits=['No actual callbacks, real UI, concurrency, rendering or physical camera.', 'Synthetic previous descriptor flags are 0 or 0x200; only specified paths are covered.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS: six synthetic WindowManager transitions;',out,flush=True)
if __name__=='__main__':main()
