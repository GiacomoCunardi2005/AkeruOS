#!/usr/bin/env python3
"""Check the two-source snapshot bits using original ARC code and synthetic MMIO."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate


def main():
 out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('snapshot_or_sources_cpu_%Y%m%dT%H%M%SZ')
 r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='gui-snapshot-or-sources'))
 print('Prove:', out, flush=True)
 try:
  r.prepare()
  build = json.loads(BUILD.read_text()); sim = LAB / 'install/bin/arc-elf32-run'
  assert sha(sim) == build['experimental_sha256']; r.experimental_engine = LAB
  dump = ROOT / 'DUMPS/MainCode.dmp'
  for p in (sim, BUILD, dump, Path(__file__)):
   r.input_hashes[str(p)] = sha(p)
  a, n = 0x2d62d8, 0x28
  b, off = locate(a, n)
  assert raw(a, n) == dump.read_bytes()[b['offset'] + off:b['offset'] + off + n]
  tests = [(bit, av, bv) for bit in (12, 13) for av in (0, 1) for bv in (0, 1)]
  asm = ''
  for i, (bit, av, bv) in enumerate(tests):
   reg_a = (0xffff & ~(1 << (bit - 10))) | (av << (bit - 10))
   reg_b = (0xffff & ~(1 << bit)) | (bv << bit)
   asm += f''' mov r1,0xfe70224
 mov r0,{reg_a:#x}
 sth r0,[r1]
 mov r0,{reg_b:#x}
 sth r0,[r1,4]
 mov r12,0x2d62d8
 jl [r12]
 mov r1,{0x2001000 + 4*i:#x}
 st r0,[r1]
'''
  asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
  maps = []
  def mapping(p, addr, length):
   return ['--memory-mapfile', '/result/' + p.name, '--memory-region', f'{addr:#x},{length}']
  for i in range(6):
   p = out / f'block{i}.bin'; p.write_bytes(PS[i]); maps += mapping(p, BS[i]['load_address_candidate'], len(PS[i]))
  p = out / 'mmio.bin'; p.write_bytes(bytes(16)); maps += mapping(p, 0xfe70224, 8)
  output = out / 'snapshots.bin'; output.write_bytes(bytes(32)); maps += mapping(output, 0x2001000, 32)
  elf = compile_probe(r, 'cases', asm)
  result, log = r.run('cases', '/result/' + elf.name, maps, trace=True)
  assert result['exit_code'] == 0 and result['fault'] is None, log
  values = struct.unpack('<8I', output.read_bytes()); rows = []
  for (bit, av, bv), value in zip(tests, values):
   expected = 0x3ffffff if av or bv else 0x3ffffff ^ (1 << bit)
   assert value == expected, (bit, av, bv, hex(value), hex(expected))
   rows.append(dict(snapshot_bit=bit, first_source=av, second_source=bv, snapshot=hex(value), result_bit=(value >> bit) & 1))
  trace = (out / 'cases.trace').read_text().splitlines()
  assert sum(line.startswith('0x2d62d8 ') for line in trace) == len(tests)
  assert all(sha(p) == r.input_hashes[str(p)] for p in (sim, BUILD, dump, Path(__file__)))
  (out / 'cases.json').write_text(json.dumps(rows, indent=2) + '\n')
  (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
  r.results.update(status='PASS_SNAPSHOT_OR_SOURCES_SYNTHETIC', scenarios=rows,
   assumptions=['Original V1.1 snapshot reader executed on synthetic ordinary-storage MMIO; all other input bits are set to one.'],
   limits=['Reader only: no callback, monitor, queue, key events, physical buttons, atomicity, camera or physical MMIO behavior.'])
  r.finish()
 except Exception as e:
  r.results.update(status='FAIL', error=repr(e)); raise
 finally:
  r.save()
 print('PASS:', len(tests), 'synthetic MMIO cases;', out, flush=True)

if __name__ == '__main__':
 main()
