#!/usr/bin/env python3
"""Run diagnostic UI wrappers and real redirect interpreter on lifecycle events."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,locate,u32


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('debug_lifecycle_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-debug-lifecycle'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();dump=ROOT/'DUMPS/MainCode.dmp';data=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  for a,n in [(0x7d22f0,0x38),(0x7d252c,0x38),(0x20e814,0x34),(0x169f60,0x54),(0x14510c,0x44),(0x3e8bb4,67*8),(0x989cf8,72),(0x989ff8,24),(0x3f5900,4),(0x899abc,2),(0x989fec,10)]:
   b,o=locate(a,n);assert raw(a,n)==data[b['offset']+o:b['offset']+o+n],hex(a)
  assert u32(0x3f5900)==0
  for base,size in [(0x3e8bb4,67),(0x989cf8,9),(0x989ff8,3)]:
   events=[u32(base+i*8) for i in range(size)];assert events[-1]==0 and 0x4401 not in events and 0x4403 not in events
  tests=[(name,addr,event) for name,addr in [('time',0x7d22f0),('iso',0x7d252c)] for event in (0x4401,0x4403)]
  asm=''
  for i,(name,wrapper,event) in enumerate(tests):
   s=0x2001000+i*64
   asm+=f''' mov r21,{s:#x}
 mov r1,0x366e94
 mov r0,0x3f5900
 st r0,[r1,8]
 mov r0,197
 sth r0,[r1,12]
 st sp,[r21,24]
 mov r0,0x2100000
 mov r1,{event:#x}
 mov r2,0x2100040
 mov r12,{wrapper:#x}
 jl [r12]
 st r0,[r21]
 mov r1,0x2100040
 add r2,r21,16
 add r3,r21,20
 mov r12,0x14510c
 jl [r12]
 st r0,[r21,4]
 st sp,[r21,28]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  maps=[]
  def mapping(path,addr):return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{path.stat().st_size}']
  for i in (0,1,4,5):
   path=out/f'block{i}_ORIGINAL.bin';path.write_bytes(PS[i]);maps+=mapping(path,BS[i]['load_address_candidate'])
  state=out/'cases.bin';state.write_bytes(bytes(len(tests)*64));maps+=mapping(state,0x2001000)
  desc=out/'descriptors.bin';desc.write_bytes(bytes(128));maps+=mapping(desc,0x2100000)
  elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault'] is None,log
  rows=[];buf=state.read_bytes()
  for i,(name,wrapper,event) in enumerate(tests):
   w=struct.unpack_from('<8I',buf,i*64)
   assert (w[0],w[1],w[4],w[5],w[6]==w[7])==(0,1,0,0,True),(i,w)
   rows.append(dict(screen=name,event=hex(event),wrapper_return=w[0],interpreter_return=w[1],destination=w[4],argument=w[5],stack_preserved=True))
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_DEBUG_LIFECYCLE_EVENTS_BOUNDED',scenarios=rows,assumptions=['Original wrapper, local and common event tables, dispatcher, fallback, interpreter and object table; synthetic caller and descriptors.', 'Original initial filter data and object table are mapped; manager registry and callback context are synthetic.'],limits=['Direct wrapper invocation and separate interpreter call, no manager lifecycle, rendering, camera or runtime filter state.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS: four diagnostic lifecycle events;',out,flush=True)
if __name__=='__main__':main()
