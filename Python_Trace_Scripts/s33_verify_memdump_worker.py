#!/usr/bin/env python3
"""Compile and execute the isolated MEMDUMP task prototype with a synthetic scheduler."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha

HARNESS = r'''
#include "nikon_v11_runtime.h"
#include "nikon_v11_memdump_worker.h"
static struct akeru_nikon_v11_task_template saved;
static unsigned dumps, starts, id, run_inline, base_error, base_mode;
static uint32_t volume_error;
static uint8_t volume_ready = 1;
static unsigned exists, open_error, close_error, close_retains;
#ifndef TEST_ORIGINAL_VOLUME
static unsigned delay_calls, ready_after;
#endif
void nikon_v11_memdump_original(void) { ++dumps; }
uint32_t nikon_v11_volume_status_original(const char *name, uint8_t *ready) {
    if (name[0]!='B' || name[1]!=':' || name[2]!=0) return 9;
    if (volume_error) return volume_error;
    *ready=volume_ready;
    return 0;
}
uint32_t nikon_v11_output_base_original(char *s) {
    if (base_error) return base_error;
    s[0] = base_mode == 1 ? 'A' : 'B'; s[1] = ':';
    s[2] = base_mode == 2 ? 'X' : 0; s[3] = 0;
    return 0;
}
uint32_t nikon_v11_open_new_original(const char *name, uint32_t mode, void **handle) {
    if (name[0]!='B' || name[1]!=':' || mode!=3 || *handle) return 8;
    if (exists || open_error) return 0x1a00011;
    exists=1; *handle=(void *)0x1234; return 0;
}
uint32_t nikon_v11_close_original(void **handle) {
    if ((uintptr_t)*handle!=0x1234 || close_error) return 9;
    if (!close_retains) *handle=0;
    return 0;
}
void nikon_v11_delay_ms_original(uint32_t ms) {
#ifndef TEST_ORIGINAL_VOLUME
    if (ms==1000 && ++delay_calls==ready_after && ready_after) volume_ready=1;
#else
    (void)ms;
#endif
}
void nikon_v11_get_ticks_original(struct akeru_nikon_v11_ticks *t) { (void)t; }
uint32_t nikon_v11_ticks_to_time_original(const struct akeru_nikon_v11_ticks *t,
    struct akeru_nikon_v11_seconds_ms *s) { (void)t; (void)s; return 0; }
uint32_t nikon_v11_create_task_original(uint32_t cpu, uint32_t index,
    const struct akeru_nikon_v11_task_template *task) {
    if (cpu || index) return 0;
    ++starts; saved = *task;
    if (run_inline && id) saved.entry(saved.parameter);
    return id;
}
int run_checks(void) {
    uint32_t result = 99;
    if (akeru_nikon_v11_memdump_start(17, 0) != AKERU_NIKON_V11_ARGUMENT || starts) return 1;
    if (akeru_nikon_v11_memdump_start(17, &result) != AKERU_NIKON_V11_CREATE || result || dumps) return 2;
    id=42;
    if (akeru_nikon_v11_memdump_start(17, &result) || result!=42 || starts!=2 || dumps) return 3;
    if (!saved.entry || saved.stack_bytes!=0x8000 || saved.priority!=17 || saved.index || saved.parameter || saved.attributes || saved.timeslice) return 4;
    saved.entry(saved.parameter);
    if (dumps!=1) return 5;
    volume_ready=0; saved.entry(saved.parameter); volume_ready=1;
    volume_error=1; saved.entry(saved.parameter); volume_error=0;
    if (dumps!=1) return 8;
    base_error=1; saved.entry(saved.parameter); base_error=0;
    base_mode=1; saved.entry(saved.parameter);
    base_mode=2; saved.entry(saved.parameter);
    if (dumps!=1) return 7;
    base_mode=0;
    saved.entry(saved.parameter); /* existing file */
    if (dumps!=1) return 9;
    exists=0; open_error=1; saved.entry(saved.parameter); open_error=0;
    if (dumps!=1 || exists) return 10;
    close_error=1; saved.entry(saved.parameter); close_error=0;
    if (dumps!=1 || !exists) return 11;
    exists=0; close_retains=1; saved.entry(saved.parameter); close_retains=0;
    if (dumps!=1 || !exists) return 12;
    exists=0;
    run_inline=1;
    if (akeru_nikon_v11_memdump_start(19, &result) || result!=42 || dumps!=2 || saved.priority!=19 || starts!=3) return 6;
#ifndef TEST_ORIGINAL_VOLUME
    exists=0; volume_ready=0; delay_calls=0; ready_after=2;
    saved.entry(saved.parameter);
    if (delay_calls!=2 || !volume_ready || dumps!=3 || !exists) return 13;
    exists=0; volume_ready=0; delay_calls=0; ready_after=0;
    saved.entry(saved.parameter);
    if (delay_calls!=29 || dumps!=3 || exists) return 14;
#endif
    return 0;
}
'''


def main():
    out = ROOT / 'Risultati/Runtime_Kernel/MEMDUMP_Worker_Prototype' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    runner = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='memdump-task-prototype'))
    print('Prove:', out, flush=True)
    try:
        runner.prepare()
        (out / 'harness.c').write_text(HARNESS)
        (out / 'start.s').write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n bl run_checks\n mov r8,1\n trap_s 1\n.section .stack,"aw",@nobits\n.align 16\n.space 16384\n')
        flags = ['-mcpu=arc700', '-mno-sdata', '-mlong-calls', '-O2', '-ffreestanding', '-fno-builtin', '-Wall', '-Wextra', '-Werror', '-I', ROOT / 'AkeruOS']
        sources = [ROOT/'AkeruOS/nikon_v11_runtime.c', ROOT/'AkeruOS/nikon_v11_memdump_worker.c', out/'harness.c']
        objects = []
        for source in sources:
            obj = out/(source.stem+'.o')
            p = runner.command(source.stem+'_compile', [TOOLCHAIN/'arc-elf32-gcc', *flags, '-c', source, '-o', obj])
            assert p.returncode == 0, p.stdout
            objects.append(obj)
        start = out/'start.o'
        p=runner.command('start_as',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',start,out/'start.s'])
        assert p.returncode==0,p.stdout
        elf=out/'worker_test.elf'
        p=runner.command('link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',LEGACY/'tests/smoke.ld','-o',elf,start,*objects])
        assert p.returncode==0,p.stdout
        case, log=runner.run('worker','/result/'+elf.name,trace=True)
        assert case['exit_code']==0 and case['fault'] is None, log
        runner.results.update(status='PASS_MEMDUMP_WORKER_CPU_SYNTHETIC_SCHEDULER', source_hashes={str(p.relative_to(ROOT)):sha(p) for p in sources[:2]},
            assumptions=['The scheduler, volume status, path lookup, task creation, and diagnostic writer are explicit C fixtures.', 'One task is invoked by the harness after creation, another before creation returns.'],
            limits=['The path may change after this separate check.', 'No hook, mounted SD, file protection, runtime priority, stack bound, persistent memory or physical execution established.'])
        runner.finish()
    except Exception as exc:
        runner.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        runner.save()
    print('PASS isolated MEMDUMP worker with synthetic scheduler:',out,flush=True)


if __name__=='__main__':
    main()
