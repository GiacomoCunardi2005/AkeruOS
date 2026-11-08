#!/usr/bin/env python3
"""Check original iris conversion in null and synthetic-table contexts."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32


def main():
 out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('iris_conversion_cpu_%Y%m%dT%H%M%S%fZ')
 r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='iris-conversion'))
 print('Prove:',out,flush=True)
 try:
  r.prepare();dump=ROOT/'DUMPS/MainCode.dmp';d=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
  for a,n in ((0xff720,0x118),(0xff5d4,8),(0x18b8d4,12)):
   b,o=locate(a,n);assert raw(a,n)==d[b['offset']+o:b['offset']+o+n],hex(a)
  assert u32(0x18b8dc)==0x367fea
  table=bytearray(16);table[4:8]=bytes((1,9,9,32));table[12:16]=bytes((10,20,30,40))
  cases=[(kind,value) for kind in (0,1) for value in (0,1,9,255)]
  asm=''
  for i,(kind,value) in enumerate(cases):
   asm+=f''' mov r21,{0x2001000+i*32:#x}
 mov r1,0x3663a4
 mov r0,{0x2007000 if kind else 0:#x}
 st r0,[r1]
 mov r1,0x367fea
 mov r0,{value}
 stb r0,[r1]
 st sp,[r21,16]
 mov r12,0x18b8d4
 jl [r12]
 st r0,[r21]
 mov r2,r0
 mov r0,1
 mov r1,3
 mov r12,0xff720
 jl [r12]
 st r0,[r21,4]
 mov r2,r0
 mov r0,3
 mov r1,1
 mov r12,0xff720
 jl [r12]
 st r0,[r21,8]
 st sp,[r21,20]
'''
  asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
  maps=[]
  def mapping(name,address,data):
   p=out/(name+'.bin');p.write_bytes(data);maps.extend(['--memory-mapfile','/result/'+p.name,'--memory-region',f'{address:#x},{len(data)}']);return p
  for i in (0,1,4,5):mapping('block'+str(i),BS[i]['load_address_candidate'],PS[i])
  state=mapping('cases',0x2001000,bytes(len(cases)*32));tablefile=mapping('table',0x2007000,bytes(table))
  elf=compile_probe(r,'probe',asm);result,log=r.run('probe','/result/'+elf.name,maps,trace=True)
  assert result['exit_code']==0 and result['fault'] is None,log
  payload=state.read_bytes();rows=[]
  for i,(kind,value) in enumerate(cases):
   w=struct.unpack_from('<8I',payload,i*32)
   middle=(0 if value==1 else 1) if not kind else (20 if value==9 else 10)
   final=(1 if middle==0 else 9) if not kind else (9 if middle==20 else 1)
   assert (w[0],w[1],w[2])==(value,middle,final) and w[4]==w[5],(kind,value,w)
   rows.append(dict(context='synthetic_table' if kind else 'null',initial=value,intermediate=middle,final=final,stack_preserved=True))
  assert tablefile.read_bytes()==table and sha(dump)==r.input_hashes[str(dump)]
  trace=(out/'probe.trace').read_text()
  assert sum(line.startswith('0x18b8d4 ') for line in trace.splitlines())==8
  assert sum(line.startswith('0x0ff720 ') for line in trace.splitlines())==16
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_IRIS_CONVERSION_SYNTHETIC',scenarios=rows,assumptions=['Original getter 18B8D4 and FF720 executed in an imposed sequence; no firmware code patched.', 'The input byte and global pointer are synthetic; non-null table is 16 synthetic bytes with a duplicate 9.'],limits=['Null fallback and synthetic table do not prove runtime configuration, physical aperture, AE, real button events or camera behavior.', 'Direct round trip is imposed by harness; no claim that FDC9E calls FF720 with a null pointer.'])
  r.finish()
 except Exception as e:r.results.update(status='FAIL',error=repr(e));raise
 finally:r.save()
 print('PASS:',len(cases),'iris conversion cases;',out,flush=True)

if __name__=='__main__':main()
