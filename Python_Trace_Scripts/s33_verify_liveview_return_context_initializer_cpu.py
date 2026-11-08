#!/usr/bin/env python3
"""Test V1.1 context initializer for liveview return, with synthetic RAM."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('liveview_context_initializer_cpu_%Y%m%dT%H%M%SZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='liveview-context-initializer'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();sim=LAB/'install/bin/arc-elf32-run';build=json.loads(BUILD.read_text())
  assert sha(sim)==build['experimental_sha256'];r.experimental_engine=LAB
  dump=ROOT/'DUMPS/MainCode.dmp'
  for p in (sim,BUILD,dump,Path(__file__)):r.input_hashes[str(p)]=sha(p)
  data=dump.read_bytes()
  for a,n in ((0x109a28,12),(0x109a88,0x30),(0xad90c,8),(0x13a954,0x54)):
   b,o=locate(a,n);assert raw(a,n)==data[b['offset']+o:b['offset']+o+n]
  tests=[(0,0),(0xa5,0x7f),(0x123,0x1ff)]
  asm=''
  for i,(first,field) in enumerate(tests):
   addr=0x2001000+i*96
   asm+=f''' mov r0,0x43c4f3
 mov r1,0xa5
 mov r2,78
 mov r12,0x13a954
 jl [r12]
 mov r0,{first:#x}
 mov r1,{field:#x}
 mov r12,0x109a88
 jl [r12]
 mov r0,{addr:#x}
 mov r1,0x43c4f3
 mov r2,78
 mov r12,0x128c20
 jl [r12]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  maps=[]
  def mapping(p,a,n):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
  for i in (0,1,2,3,4,5):
   p=out/f'block{i}.bin';p.write_bytes(PS[i]);maps+=mapping(p,BS[i]['load_address_candidate'],len(PS[i]))
  p=out/'context.bin';p.write_bytes(bytes(512));maps+=mapping(p,0x43c400,512)
  p=out/'cases.bin';p.write_bytes(bytes(96*len(tests)));maps+=mapping(p,0x2001000,96*len(tests))
  elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert case['exit_code']==0 and case['fault'] is None,log
  records=p.read_bytes(); rows=[]
  for i,(first,field) in enumerate(tests):
   b=records[i*96:i*96+78];expected=bytearray(78);expected[0]=expected[-1]=0xa5;expected[1]=first&255;expected[75]=field&255
   assert b==expected,(i,b.hex(),expected.hex())
   rows.append(dict(args=[first,field],offset0=b[1],offset74=b[75],offset75=b[76],guard_before=b[0],guard_after=b[77],bytes=b.hex()))
  trace=(out/'cases.trace').read_text().splitlines()
  for address in ('0x109a88','0x109a28','0x0ad90c','0x13a954','0x128c20'):
   assert sum(x.startswith(address+' ') for x in trace)>=len(tests),address
  assert all(sha(p)==r.input_hashes[str(p)] for p in (sim,BUILD,dump,Path(__file__)))
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_LIVEVIEW_CONTEXT_INIT_SYNTHETIC',scenarios=rows,
   assumptions=['Original V1.1 initializer, getter, clear and copy code executed in synthetic ordinary RAM, no modeled peripheral.'],
   limits=['Direct initializer call with invented arguments; no evidence of runtime caller, physical RAM, actual context values, liveview return, GUI or camera.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS:',len(tests),'cases;',out,flush=True)
if __name__=='__main__':main()
