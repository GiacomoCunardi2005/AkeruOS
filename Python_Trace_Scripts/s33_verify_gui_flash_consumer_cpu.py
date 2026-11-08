#!/usr/bin/env python3
"""Exercise the original flash-value consumer with controlled synthetic inputs."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, disasm


def main():
 out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('flash_consumer_cpu_%Y%m%dT%H%M%S%fZ')
 r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='gui-flash-consumer'))
 print('Prove:', out, flush=True)
 try:
  r.prepare()
  dump = ROOT / 'DUMPS/MainCode.dmp'; data = dump.read_bytes(); r.input_hashes[str(dump)] = sha(dump)
  for addr, size in ((0xe27e8, 0xe0), (0xde3a4, 0x50), (0xf6f0c, 8)):
   block, offset = locate(addr, size); assert raw(addr, size) == data[block['offset']+offset:block['offset']+offset+size]
  images = {i:bytearray(PS[i]) for i in (0, 1, 8)}; maps = []; patches = []
  def binary(name, asm):
   elf = compile_probe(r, name, asm); path = out / (name + '.bin')
   result = r.command(name + '_extract', [TOOLCHAIN/'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, path]); assert result.returncode == 0
   b = path.read_bytes(); path.write_bytes(b + bytes(8 + (-len(b)) % 8)); return path
  def mapping(path, addr, size): return ['--memory-mapfile', '/result/' + path.name, '--memory-region', f'{addr:#x},{size}']
  def install(name, addr, asm):
   path = binary(name, asm); target = 0x2030000 + 0x100 * len(patches); maps.extend(mapping(path, target, path.stat().st_size))
   jump = binary('jump_' + name, f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
   block, offset = locate(addr, 8); original = bytes(images[block['index']][offset:offset+8]); assert original == raw(addr, 8)
   images[block['index']][offset:offset+8] = jump; patches.append(dict(name=name, address=hex(addr), original=original.hex(), fixture=jump.hex()))
  install('measurement', 0xfd1d8, ' mov r0,0\n j_s [blink]\n')
  install('copy', 0x128c20, ' mov r1,0\n st r1,[r0,4]\n j_s [blink]\n')
  install('fill', 0xf6f54, ' j_s [blink]\n')
  install('condition_object', 0xf6f04, ' mov r0,0x2004000\n j_s [blink]\n')
  install('flag', 0x103fd8, ' mov r0,0\n j_s [blink]\n')
  tests = [(value, guard) for value in (1, 4, 8, 26) for guard in (0, 1)]
  asm = ''
  for i, (value, guard) in enumerate(tests):
   asm += f''' mov r0,{value}
 mov r12,0xde3a4
 jl [r12]
 mov r1,0x2004000
 mov r0,{guard}
 st r0,[r1,32]
 mov r1,0x2003000
 mov r0,1
 stb r0,[r1,41]
 mov r0,0
 sth r0,[r1,76]
 mov r21,{0x2001000+i*16:#x}
 st sp,[r21]
 mov r0,0
 mov r12,0xe27e8
 jl [r12]
 st r0,[r21,4]
 st sp,[r21,8]
'''
  asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
  for index, image in images.items():
   path = out / f'block{index}_LAB_FIXTURE.bin'; path.write_bytes(image); maps += mapping(path, BS[index]['load_address_candidate'], len(image))
  for name, address, size in [('cases_data',0x2001000,len(tests)*16),('context',0x2003000,256),('condition',0x2004000,256)]:
   path = out / (name + '.bin'); path.write_bytes(bytes(size)); maps += mapping(path, address, size)
  elf = compile_probe(r, 'cases', asm); result, log = r.run('cases', '/result/'+elf.name, maps, trace=True)
  assert result['exit_code'] == 0 and result['fault'] is None, log
  payload = (out/'cases_data.bin').read_bytes(); cases = []
  for i,(value, guard) in enumerate(tests):
   before, answer, after, _ = struct.unpack_from('<4I', payload, i*16)
   expected = 0 if guard and value != 1 else 8
   assert before == after and answer == expected, (value,guard,before,answer,after)
   cases.append(dict(value=value, guard=guard, result=answer, stack_preserved=True))
  trace=(out/'cases.trace').read_text()
  for addr, count in ((0xe27e8,8),(0xde3a4,8),(0xde3e4,8)):
   assert sum(line.startswith(f'0x{addr:06x} ') for line in trace.splitlines()) == count, hex(addr)
  (out/'cases.json').write_text(json.dumps(cases,indent=2)+'\n'); (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
  (out/'gnu_window.txt').write_text(disasm(0xe27e8,0xe28c8))
  (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes()); assert sha(dump)==r.input_hashes[str(dump)]
  r.results.update(status='PASS_FLASH_CONSUMER_SYNTHETIC', scenarios=cases, assumptions=['Setter and consumer run sequentially; measurements, local initialization, condition object and final flag are fixtures.','Context byte +0x29=1, signed halfword +0x4c=0 and fixture measurement=0.'], limits=['No original scheduler, physical camera, flash actuation or meaning of result established.'])
  r.finish()
 except Exception as e:
  r.results.update(status='FAIL',error=repr(e)); raise
 finally: r.save()
 print('PASS:',len(tests),'cases;',out,flush=True)

if __name__ == '__main__': main()
