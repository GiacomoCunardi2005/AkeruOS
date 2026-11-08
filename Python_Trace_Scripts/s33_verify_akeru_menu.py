#!/usr/bin/env python3
"""Run the isolated four-slot menu model on host and GNU ARC700."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import subprocess
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha


def main():
    out = ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('akeru_menu_model_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='akeru-menu-model'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        src = ROOT/'AkeruOS/ui/menu.c'; header = ROOT/'AkeruOS/ui/menu.h'; test = ROOT/'AkeruOS/tests/menu_test.c'
        labels = ROOT/'AkeruOS/ui/menu_labels.c'
        iris = ROOT/'AkeruOS/camera/iris_action.c'; iris_header = ROOT/'AkeruOS/camera/iris_action.h'
        for p in (src, header, labels, iris, iris_header, test, Path(__file__)):
            r.input_hashes[str(p)] = sha(p)
        def run(name, args):
            result = r.command(name, args)
            assert result.returncode == 0, result.stdout
            return result.stdout
        run('host_compile', ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                             '-I'+str(ROOT/'AkeruOS'), src, labels, iris, test, '-o', out/'host_test'])
        run('host_test', [out/'host_test'])
        flags = ['arc-snps-elf-gcc', '-mcpu=arc700', '-mno-sdata', '-mlong-calls', '-O2',
                 '-ffreestanding', '-fno-builtin', '-Wall', '-Wextra', '-Werror', '-I'+str(ROOT/'AkeruOS')]
        run('compile_menu', flags+['-c', src, '-o', out/'menu.o'])
        run('compile_labels', flags+['-c', labels, '-o', out/'labels.o'])
        run('compile_iris', flags+['-c', iris, '-o', out/'iris.o'])
        run('compile_test', flags+['-DAKERU_GNU_TEST', '-c', test, '-o', out/'test.o'])
        (out/'start.s').write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n'
            ' mov sp,_stack_top\n bl main\n mov r8,1\n trap_s 1\n'
            '.global test_fail\ntest_fail:\n mov r8,1\n trap_s 1\n'
            '.section .stack,"aw",@nobits\n.align 16\n.space 16384\n_stack_top:\n')
        run('assemble', [TOOLCHAIN/'arc-elf32-as', '-mcpu=arc700', '-EL', '-o', out/'start.o', out/'start.s'])
        run('link', [TOOLCHAIN/'arc-elf32-ld', '-EL', '-T', LEGACY/'tests/smoke.ld', '-o', out/'menu_test.elf',
                     out/'start.o', out/'test.o', out/'menu.o', out/'labels.o', out/'iris.o'])
        assert not run('undefined', ['arc-snps-elf-nm', '-u', out/'menu_test.elf']).strip()
        case, log = r.run('menu_model', '/result/menu_test.elf')
        assert case['exit_code'] == 0 and case['fault'] is None, log
        assert all(sha(p) == r.input_hashes[str(p)] for p in (src, header, labels, iris, iris_header, test, Path(__file__)))
        r.results.update(status='PASS_MENU_MODEL_HOST_AND_GNU_ARC700',
            assumptions=['Injected event IDs and abstract slot indices with in-memory state; actions are requests, not applied settings.'],
            limits=['Events injected by test; no original queue/dispatcher, physical button mapping, Nikon GUI lifecycle, display, capture, sensor, persistence or camera binding.',
                    'ISO and shutter open external screens; aperture positions and color/mono are requests; third main slot has no action.',
                    'Labels are model data only, without a renderer or Nikon resource binding.'],
            hardware_tested=False, installable=False)
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc)); raise
    finally:
        r.save()
    print('PASS host and GNU ARC700:', out, flush=True)


if __name__ == '__main__':
    main()
