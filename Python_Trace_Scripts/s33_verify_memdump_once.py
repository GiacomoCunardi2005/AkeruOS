#!/usr/bin/env python3
"""Verify the one-shot task claim on ARC with original critical-section routines."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS

HARNESS=r'''
#include <stdint.h>
#include "nikon_v11_memdump_once.h"
#include "nikon_v11_runtime.h"
static volatile uint32_t claim;
static unsigned calls, reenter, failure, bad;
int akeru_nikon_v11_memdump_start(uint32_t priority, uint32_t *id) {
    if (*(volatile uint32_t *)0x2019068 || priority!=19) bad=1;
    ++calls;
    if (reenter) {
        uint32_t nested=99;
        if (akeru_nikon_v11_memdump_start_once(&claim,19,&nested)!=1 || nested || calls!=1) bad=1;
    }
    *id=failure?0:42;
    return failure?AKERU_NIKON_V11_CREATE:AKERU_NIKON_V11_OK;
}
int run_checks(void) {
    uint32_t id=99;
    if (akeru_nikon_v11_memdump_start_once(0,19,&id)!=AKERU_NIKON_V11_ARGUMENT) return 1;
    if (akeru_nikon_v11_memdump_start_once(&claim,19,0)!=AKERU_NIKON_V11_ARGUMENT) return 2;
    if (akeru_nikon_v11_memdump_start_once(&claim,19,(uint32_t *)&claim)!=AKERU_NIKON_V11_ARGUMENT) return 3;
    reenter=1;
    if (akeru_nikon_v11_memdump_start_once(&claim,19,&id) || id!=42 || claim!=1 || calls!=1 || bad) return 4;
    id=99;
    if (akeru_nikon_v11_memdump_start_once(&claim,19,&id)!=1 || id || calls!=1) return 5;
    claim=0;calls=0;reenter=0;failure=1;
    if (akeru_nikon_v11_memdump_start_once(&claim,19,&id)!=AKERU_NIKON_V11_CREATE || claim || calls!=1) return 6;
    failure=0;
    if (akeru_nikon_v11_memdump_start_once(&claim,19,&id) || claim!=1 || id!=42 || calls!=2 || bad) return 7;
    if (*(volatile uint32_t *)0x2019068) return 8;
    return 0;
}
'''


def main():
    out=ROOT/'Risultati/Runtime_Kernel/MEMDUMP_Once'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='memdump-once-original-critical'))
    print('Prove:',out,flush=True)
    try:
        r.prepare();(out/'harness.c').write_text(HARNESS)
        (out/'start.s').write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n bl run_checks\n mov r8,1\n trap_s 1\n.section .stack,"aw",@nobits\n.align 16\n.space 16384\n')
        flags=['-mcpu=arc700','-mno-sdata','-mlong-calls','-O2','-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-I',ROOT/'AkeruOS']
        objs=[]
        for src in (ROOT/'AkeruOS/nikon_v11_memdump_once.c',out/'harness.c'):
            obj=out/(src.stem+'.o');p=r.command(src.stem+'_compile',[TOOLCHAIN/'arc-elf32-gcc',*flags,'-c',src,'-o',obj]);assert p.returncode==0,p.stdout;objs.append(obj)
        start=out/'start.o';p=r.command('start_as',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',start,out/'start.s']);assert p.returncode==0,p.stdout
        elf=out/'once.elf';p=r.command('link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',LEGACY/'tests/smoke.ld','--defsym=nikon_v11_enter_critical_original=0x1786e8','--defsym=nikon_v11_leave_critical_original=0x179354','-o',elf,start,*objs]);assert p.returncode==0,p.stdout
        main0=out/'main0.bin';main0.write_bytes(PS[0]);p1=bytearray(PS[1]);struct.pack_into('<I',p1,0x369348-BS[1]['load_address_candidate'],0x2018000);main1=out/'main1.bin';main1.write_bytes(p1)
        memory=bytearray(0x2000);struct.pack_into('<I',memory,0x1c,0x2019000)
        state=out/'kernel.bin';state.write_bytes(memory)
        maps=['--memory-mapfile','/result/main0.bin','--memory-region',f'{BS[0]["load_address_candidate"]:#x},{len(PS[0])}',
              '--memory-mapfile','/result/main1.bin','--memory-region',f'{BS[1]["load_address_candidate"]:#x},{len(p1)}',
              '--memory-mapfile','/result/kernel.bin','--memory-region','0x2018000,8192']
        case,log=r.run('once','/result/'+elf.name,maps,trace=True)
        assert case['exit_code']==0 and case['fault'] is None,log
        trace=(out/'once.trace').read_text();assert trace.count('0x1786e8  ')==6 and trace.count('0x179354  ')==6, 'critical calls missing'
        assert struct.unpack_from('<I',state.read_bytes(),0x1068)[0]==0
        r.results.update(status='PASS_ONCE_ORIGINAL_CRITICAL_SYNTHETIC_SCHEDULER',
            assumptions=['Original 1786E8/179354, synthetic kernel/task and status words; creation routine is fixture.', 'Reentry injected by fixture before creation returns; initial claim is zero.'],
            limits=['No physical IRQ, SMP, concurrent scheduler, persistent ownership, reload behavior or SD.', 'Failure releases claim; a created task permanently claims it even if it later refuses to dump.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS one-shot claim with original critical routines:',out,flush=True)


if __name__=='__main__':main()
