#!/usr/bin/env python3
"""Exercise ISO setter, list initialization, and confirmation with shared synthetic state."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32, disasm


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('debug_iso_roundtrip_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-debug-iso-roundtrip'))
 print('Prove:',out,flush=True)
 try:
  r.prepare(); dump=ROOT/'DUMPS/MainCode.dmp'; data=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x7d2564,0x8c),(0x17c3e8,16),(0x641064,0x110),(0xd03b8,0x1c),(0x17c320,0xc8),(0xde78c,0x40),(0x989da4,480)]:
   block,off=locate(a,n); assert raw(a,n)==data[block['offset']+off:block['offset']+off+n]
  for i in range(24): assert u32(0x989da4+i*20+12)==(0xffffffff if not i else i-1) and u32(0x989da4+i*20+16)==0
  (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in [(0x7d2564,0x7d25f0),(0x641064,0x641174),(0xd03b8,0xd03d4),(0x17c320,0x17c3e8)]))
  images={i:bytearray(PS[i]) for i in (0,1,2,4,5)}; maps=[]; patches=[]
  def binary(name,asm):
   elf=compile_probe(r,name,asm); path=out/(name+'.bin'); result=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path]); assert result.returncode==0,result.stdout
   content=path.read_bytes(); path.write_bytes(content+bytes(8+(-len(content))%8)); return path
  def mapping(path,addr): return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{path.stat().st_size}']
  common=' mov r10,0x2000000\n ld r10,[r10]\n'
  services=[('init_control',0x145654,common+' ld r0,[r10,48]\n j_s [blink]\n'),
   ('confirm_control',0x145790,common+' ld r0,[r10,48]\n j_s [blink]\n'),
   ('refresh',0x145490,' mov r0,0\n j_s [blink]\n'),('get8',0x14503c,' mov r0,0x55\n j_s [blink]\n'),
   ('get4',0x14504c,' mov r0,0x1234\n j_s [blink]\n'),('dispatch',0x169d78,' mov r0,0\n j_s [blink]\n'),
   ('open',0x1453e4,common+' st r0,[r10,16]\n st r1,[r10,20]\n ld r11,[r10,24]\n add r11,r11,1\n st r11,[r10,24]\n mov r0,0\n j_s [blink]\n')]
  for i,(name,addr,asm) in enumerate(services):
   target=0x2030000+i*0x400; path=binary(name,asm); maps+=mapping(path,target)
   entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
   block,off=locate(addr,8); before=bytes(images[block['index']][off:off+8]); assert before==raw(addr,8)
   images[block['index']][off:off+8]=entry; patches.append(dict(name=name,address=hex(addr),original=before.hex(),fixture=entry.hex()))
  tests=[(0,0),(6,125),(19,1600),(22,3200),(23,6400),(255,0)]
  state=bytearray(len(tests)*96); contexts=bytearray(len(tests)*256); asm=' mov r20,0x2000000\n'
  for i,(index,converted) in enumerate(tests):
   addr=0x2001000+i*96; ctx=0x2100000+i*256
   struct.pack_into('<I',state,i*96+48,ctx); contexts[i*256+37]=24; contexts[i*256+38]=99; struct.pack_into('<I',contexts,i*256+0x40,0x989da4)
   asm+=f''' mov r21,{addr:#x}
 st r21,[r20]
 st sp,[r21,28]
 mov r0,{index}
 mov r12,0xd03b8
 jl [r12]
 mov r0,0
 mov r1,0
 mov r2,0
 mov r12,0x7d2564
 jl [r12]
 mov r1,{ctx+38:#x}
 ldb r0,[r1]
 st r0,[r21]
 mov r1,0x365787
 ldb r0,[r1]
 st r0,[r21,4]
 mov r1,0x37fbf2
 ldh r0,[r1]
 st r0,[r21,8]
 mov r0,0
 mov r1,0x4801
 mov r2,0
 mov r12,0x7d25b0
 jl [r12]
 mov r1,0x365787
 ldb r0,[r1]
 st r0,[r21,32]
 mov r1,0x367bc8
 ldb r0,[r1]
 st r0,[r21,36]
 mov r1,0x37fbf2
 ldh r0,[r1]
 st r0,[r21,40]
 st sp,[r21,44]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  for i,image in images.items():
   path=out/f'block{i}_LAB_FIXTURE.bin'; path.write_bytes(image); maps+=mapping(path,BS[i]['load_address_candidate'])
  sf=out/'cases.bin'; sf.write_bytes(state); maps+=mapping(sf,0x2001000)
  path=out/'current.bin'; path.write_bytes(bytes(8)); maps+=mapping(path,0x2000000)
  path=out/'contexts.bin'; path.write_bytes(contexts); maps+=mapping(path,0x2100000)
  elf=compile_probe(r,'cases',asm); case,log=r.run('cases','/result/'+elf.name,maps,trace=True); assert case['exit_code']==0 and case['fault'] is None,log
  rows=[]
  for i,(index,converted) in enumerate(tests):
   w=struct.unpack_from('<12I',sf.read_bytes(),i*96); position=index+1 if index<=22 else 0
   assert tuple(w[:3])==(position,index,converted) and tuple(w[4:7])==(0x36,0,1) and tuple(w[8:11])==(index,index,converted) and w[7]==w[11],(i,w)
   rows.append(dict(initial_index=index,selected_position=position,initial_value=converted,confirmed_index=w[8],confirmed_value=w[10],open_request=[w[4],w[5]],stack_preserved=True))
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n'); (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_DEBUG_ISO_ROUNDTRIP_SYNTHETIC',scenarios=rows,
   assumptions=['Original setter, initialization, list lookup, selector, confirmation and getter with original records.', 'Synthetic control, count, caller and seven GUI service fixtures; no user navigation between initialization and confirmation.'],
   limits=['No actual event delivery, list lifecycle, rendering, sensor gain, AE or persistence.', 'Out-of-list indices are injected; no claim these occur in normal use.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e)); raise
 finally:r.save()
 print('PASS: six synthetic ISO reopen/confirm paths;',out,flush=True)
if __name__=='__main__':main()
