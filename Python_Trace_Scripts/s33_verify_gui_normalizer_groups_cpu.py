#!/usr/bin/env python3
"""Test original input normalizer on every combination of four GUI bits."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate


def main():
 out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('normalizer_groups_cpu_%Y%m%dT%H%M%SZ')
 r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='gui-normalizer-groups'))
 print('Prove:', out, flush=True)
 try:
  r.prepare(); build = json.loads(BUILD.read_text()); sim = LAB / 'install/bin/arc-elf32-run'
  assert sha(sim) == build['experimental_sha256']; r.experimental_engine = LAB
  dump = ROOT / 'DUMPS/MainCode.dmp'
  for p in (sim, BUILD, dump, Path(__file__)): r.input_hashes[str(p)] = sha(p)
  d = dump.read_bytes()
  for addr, n in ((0x16e6e0, 0x158), (0x335c4c, 0x30)):
   b, off = locate(addr, n); assert raw(addr,n) == d[b['offset']+off:b['offset']+off+n]
  bits = (12,7,8,13); tests = [(gate,mask) for gate in (0,1) for mask in range(16)]
  data = bytearray(len(tests)*24); asm = ''
  for i,(gate,mask) in enumerate(tests):
   lo = 0xfc000000 | sum(1 << b for j,b in enumerate(bits) if mask & (1 << j))
   struct.pack_into('<II', data, i*24, lo, 0)
   addr = 0x2001000 + i*24
   asm += f''' mov r1,0x36789c
 mov r0,0
 st r0,[r1]
 mov r1,0x3678a2
 mov r0,{gate}
 stb r0,[r1]
 mov r0,{addr:#x}
 mov r12,0x16e6e0
 jl [r12]
 mov r1,{addr+8:#x}
 st r0,[r1]
 mov r1,0x3678a2
 ldb r0,[r1]
 mov r1,{addr+12:#x}
 st r0,[r1]
'''
  asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
  maps=[]
  def mapping(p,addr,length): return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{addr:#x},{length}']
  for i in range(6):
   p=out/f'block{i}.bin'; p.write_bytes(PS[i]); maps+=mapping(p,BS[i]['load_address_candidate'],len(PS[i]))
  state=out/'cases.bin'; state.write_bytes(data); maps+=mapping(state,0x2001000,len(data))
  elf=compile_probe(r,'cases',asm); result,log=r.run('cases','/result/'+elf.name,maps,trace=True)
  assert result['exit_code']==0 and result['fault'] is None,log
  got=state.read_bytes(); rows=[]
  for i,(gate,mask) in enumerate(tests):
   lo=0xfc000000 | sum(1<<b for j,b in enumerate(bits) if mask & (1<<j))
   group_a=bool(mask & 2)+bool(mask & 4); group_b=bool(mask & 1)+bool(mask & 8)
   accepted=gate==1 or (group_a<=1 and group_b<=1)
   expected=lo | (1 if gate else 0)
   actual=struct.unpack_from('<IIII',got,i*24)
   assert actual==(expected if accepted else lo,0,int(accepted),0),(gate,mask,actual)
   rows.append(dict(gate=gate,slots=[j+1 for j in range(4) if mask & (1<<j)],input=hex(lo),accepted=accepted,output=hex(actual[0])))
  trace=(out/'cases.trace').read_text().splitlines()
  assert sum(line.startswith('0x16e6e0 ') for line in trace)==len(tests)
  assert all(sha(p)==r.input_hashes[str(p)] for p in (sim,BUILD,dump,Path(__file__)))
  (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n')
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_NORMALIZER_GROUPS_SYNTHETIC',scenarios=rows,
   assumptions=['Original normalizer on synthetic inputs and gate state; low baseline 0xfc000000, high 0, mirror 0.'],
   limits=['Four selected bits only; gate forced by harness. No physical input, monitor, queue, scheduler or camera.'])
  r.finish()
 except Exception as e:
  r.results.update(status='FAIL',error=repr(e)); raise
 finally: r.save()
 print('PASS:',len(tests),'synthetic normalizer cases;',out,flush=True)

if __name__=='__main__': main()
