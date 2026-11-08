#!/usr/bin/env python3
"""Verify the experimental one-bit scanline on host and GNU ARC700."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import subprocess
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha


def main():
    out = ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('akeru_mono_scanline_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='akeru-mono-scanline'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        src = ROOT/'AkeruOS/ui/mono_scanline.c'; header = ROOT/'AkeruOS/ui/mono_scanline.h'; test = ROOT/'AkeruOS/tests/mono_scanline_test.c'
        for p in (src, header, test, Path(__file__)):
            r.input_hashes[str(p)] = sha(p)
        def run(name, args):
            result = r.command(name, args)
            assert result.returncode == 0, result.stdout
            return result.stdout
        run('host_compile', ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                             '-I'+str(ROOT/'AkeruOS'), src, test, '-o', out/'host_test'])
        run('host_test', [out/'host_test'])
        flags = ['arc-snps-elf-gcc', '-mcpu=arc700', '-mno-sdata', '-mlong-calls', '-O2',
                 '-ffreestanding', '-fno-builtin', '-Wall', '-Wextra', '-Werror', '-I'+str(ROOT/'AkeruOS')]
        run('compile_menu', flags+['-c', src, '-o', out/'menu.o'])
        run('compile_test', flags+['-DAKERU_GNU_TEST', '-c', test, '-o', out/'test.o'])
        (out/'start.s').write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n'
            ' mov sp,_stack_top\n bl main\n mov r8,1\n trap_s 1\n'
            '.global test_fail\ntest_fail:\n mov r0,1\n mov r8,1\n trap_s 1\n'
            '.section .stack,"aw",@nobits\n.align 16\n.space 16384\n_stack_top:\n')
        run('assemble', [TOOLCHAIN/'arc-elf32-as', '-mcpu=arc700', '-EL', '-o', out/'start.o', out/'start.s'])
        libgcc = run('libgcc', ['arc-snps-elf-gcc', '-mcpu=arc700', '-mno-sdata', '-mlong-calls', '-print-libgcc-file-name']).strip()
        run('link', [TOOLCHAIN/'arc-elf32-ld', '-EL', '-T', LEGACY/'tests/smoke.ld', '-o', out/'menu_test.elf',
                     out/'start.o', out/'test.o', out/'menu.o', libgcc])
        assert not run('undefined', ['arc-snps-elf-nm', '-u', out/'menu_test.elf']).strip()
        case, log = r.run('menu_model', '/result/menu_test.elf')
        assert case['exit_code'] == 0 and case['fault'] is None, log
        assert all(sha(p) == r.input_hashes[str(p)] for p in (src, header, test, Path(__file__)))
        r.results.update(status='PASS_MONO_SCANLINE_HOST_AND_GNU_ARC700',
            assumptions=['Valid buffer sizes and lifetimes are the caller responsibility; synthetic test covers offsets 0..15 and widths 0..24.'],
            limits=['Prototype only; no camera integration or buffer capacity validation by this ABI.'],
            hardware_tested=False, installable=False)
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc)); raise
    finally:
        r.save()
    print('PASS one-bit scanline host and GNU ARC700:', out, flush=True)


if __name__ == '__main__':
    main()
