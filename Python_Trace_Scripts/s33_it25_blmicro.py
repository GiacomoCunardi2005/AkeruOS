#!/usr/bin/env python3
"""Micro-test iterazione 25: il sim GNU ARC700 esegue correttamente le b 32-bit
di coda degli handler slot di AutoSceneLiveView con displacement negativo grande?
b a 0x65C5D8 (W=0xFF4F03E1, GNU: -5152 -> 0x65B1B8; predizione wrap it.44: +3040 -> 0x65D1D8)
b a 0x65C6F2 (W=0xCFFE9D00, GNU: -10084 -> 0x659F8C; predizione wrap: +6108 -> 0x65AE56)
Byte ORIGINALI del blocco 2, solo il minimo mappato; niente target.
"""
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads
from s33_run_gnu_arc700 import LEGACY, TOOLCHAIN, Runner, elf_loads

STACK = 0xC8F000


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / ('tmp/it25/blmicro_' + stamp)
    print('Prove:', out, flush=True)
    blocks, payloads, _ = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}

    cases = [('tailb_press', 0x65C5D8), ('tailb_rel', 0x65C6F2)]
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN,
                               output=out, action='it25-blmicro'))
    r.prepare()
    r.results['cases'] = []
    for name, badr in cases:
        word = payloads[2][badr - base[2]:badr - base[2] + 4]
        s = out / f'{name}.s'
        s.write_text(
            '.section .text,"ax",@progbits\n.global _start\n_start:\n'
            f' mov sp,{hex(STACK)}\n'
            f' mov r12,{hex(badr)}\n'
            ' j_s [r12]\n'
            f'.section .tailb,"ax",@progbits\n .org 0\n'
            + ''.join(f' .byte {b}\n' for b in word) +
            '.section .stack,"aw",@nobits\n.align 16\n .space 16384\n')
        obj = out / f'{name}.o'
        assert r.command(f'{name}_as', [
            TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL',
            '-o', obj, s]).returncode == 0
        bo = out / f'{name}_bin.o'
        binf = out / f'{name}.bin'
        binf.write_bytes(word)
        assert r.command(f'{name}_oc', [
            TOOLCHAIN / 'arc-elf32-objcopy', '-I', 'binary',
            '-O', 'elf32-littlearc', '-B', 'arc', '--rename-section',
            '.data=.tailb,alloc,load,readonly,code,contents',
            '--change-section-vma', f'.data={hex(badr)}',
            '--strip-all', binf, bo]).returncode == 0
        elf = out / f'{name}.elf'
        ld = out / f'{name}.ld'
        ld.write_text('ENTRY(_start)\nSECTIONS {\n'
                      '  .text 0x1000 : { *(.text .text.*) }\n'
                      f'  .tailb {hex(badr)} : {{ *(.tailb) }}\n'
                      f'  .stack {hex(STACK)} (NOLOAD) : {{ *(.stack .stack.*) }}\n'
                      '}\n')
        assert r.command(f'{name}_ld', [
            TOOLCHAIN / 'arc-elf32-ld', '-EL', '-T', ld, '-o', elf,
            obj, bo]).returncode == 0
        case, _ = r.run(name, '/result/' + f'{name}.elf')
        print(name, 'word', word.hex(),
              'fault', case['fault'], 'exit', case['exit_code'],
              'insn', case['instructions'], flush=True)
        r.results['cases'].append(dict(name=name, word=word.hex(),
                                        fault=case['fault']))
    r.results['status'] = 'DONE'
    (out / 'micro.json').write_text(repr(r.results['cases']))
    print('DONE', stamp)


if __name__ == '__main__':
    main()
