#!/usr/bin/env python3
"""Execute the held-handle routing prototype on GNU ARC with I/O fixtures."""
from datetime import datetime, timezone
from types import SimpleNamespace
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha


def main():
    assert sys.argv[1:] in ([], ['--scope'], ['--range'], ['--checked'], ['--map'])
    mapped = sys.argv[1:] == ['--map']
    checked = sys.argv[1:] == ['--checked']
    scope = sys.argv[1:] == ['--scope']
    rng = sys.argv[1:] == ['--range']
    out = ROOT / 'Risultati/Runtime_Kernel' / ('MEMDUMP_Map_Adapter' if mapped else 'MEMDUMP_Checked_Adapter' if checked else 'MEMDUMP_Held_Scope' if scope else 'MEMDUMP_Range_Adapter' if rng else 'MEMDUMP_Held_Adapter') / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    runner = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='memdump-held-adapter'))
    print('Prove:', out, flush=True)
    try:
        runner.prepare()
        (out / 'start.s').write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n bl run_checks\n mov r8,1\n trap_s 1\n.section .stack,"aw",@nobits\n.align 16\n.space 16384\n')
        flags = ['-mcpu=arc700', '-mno-sdata', '-mlong-calls', '-O2', '-ffreestanding', '-fno-builtin', '-Wall', '-Wextra', '-Werror', '-I', ROOT / 'AkeruOS']
        sources = [ROOT / ('AkeruOS/nikon_v11_memdump_map.c' if mapped else 'AkeruOS/nikon_v11_memdump_held_checked.c' if checked else 'AkeruOS/nikon_v11_memdump_held_range.c' if rng else 'AkeruOS/nikon_v11_memdump_held.c')]
        if mapped:
            sources += [ROOT / 'AkeruOS/tests/nikon_v11_memdump_map_test.c']
        elif checked:
            sources += [ROOT / 'AkeruOS/tests/nikon_v11_memdump_checked_test.c']
        elif rng:
            sources += [ROOT / 'AkeruOS/tests/nikon_v11_memdump_range_test.c']
        elif scope:
            sources += [ROOT / 'AkeruOS/nikon_v11_memdump_held_scope.c', ROOT / 'AkeruOS/tests/nikon_v11_memdump_scope_test.c']
        else:
            sources += [ROOT / 'AkeruOS/tests/nikon_v11_memdump_held_test.c']
        objects = []
        for source in sources:
            obj = out / (source.stem + '.o')
            result = runner.command(source.stem + '_compile', [TOOLCHAIN / 'arc-elf32-gcc', *flags, '-c', source, '-o', obj])
            assert result.returncode == 0, result.stdout
            objects.append(obj)
        start = out / 'start.o'
        result = runner.command('start_as', [TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL', '-o', start, out / 'start.s'])
        assert result.returncode == 0, result.stdout
        elf = out / 'adapter_test.elf'
        result = runner.command('link', [TOOLCHAIN / 'arc-elf32-ld', '-EL', '-T', LEGACY / 'tests/smoke.ld', '-o', elf, start, *objects])
        assert result.returncode == 0, result.stdout
        case, log = runner.run('adapter', '/result/' + elf.name, trace=True)
        assert case['exit_code'] == 0 and case['fault'] is None, log
        runner.results.update(status='PASS_RANGE_ADAPTER_CPU_FIXTURES' if rng else 'PASS_HELD_ADAPTER_CPU_FIXTURES', source_hashes={str(p.relative_to(ROOT)): sha(p) for p in sources},
            limits=['Current-task identity, handle publication, concurrency and both Nikon I/O routines are fixtures.', 'No hook, physical scheduler, SD, complete dump or hardware tested.'])
        runner.finish()
    except Exception as exc:
        runner.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        runner.save()
    print('PASS held adapter GNU ARC fixtures:', out, flush=True)


if __name__ == '__main__':
    main()
