#!/usr/bin/env python3
"""Exercise the MEMDUMP worker using Nikon's original volume and path lookups."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner
from s33_verify_memdump_worker import HARNESS
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS


def main():
    out=ROOT/'Risultati/Runtime_Kernel/MEMDUMP_Worker_Path'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='memdump-worker-original-path'))
    print('Prove:',out,flush=True)
    try:
        r.prepare()
        harness=HARNESS.replace('static unsigned dumps, starts, id, run_inline, base_error, base_mode;',
                                'static unsigned dumps, starts, id, run_inline;')
        harness=harness.replace('static uint32_t volume_error;\nstatic uint8_t volume_ready = 1;\n', '')
        begin=harness.index('uint32_t nikon_v11_volume_status_original(')
        end=harness.index('uint32_t nikon_v11_output_base_original(',begin)
        harness=harness[:begin]+harness[end:]
        begin=harness.index('uint32_t nikon_v11_output_base_original(char *s) {')
        end=harness.index('uint32_t nikon_v11_open_new_original',begin)
        harness=harness[:begin]+harness[end:]
        old='''    base_error=1; saved.entry(saved.parameter); base_error=0;
    base_mode=1; saved.entry(saved.parameter);
    base_mode=2; saved.entry(saved.parameter);
    if (dumps!=1) return 7;
    base_mode=0;
'''
        new='''    *(volatile unsigned char *)0x366889 = 255; saved.entry(saved.parameter);
    *(volatile unsigned char *)0x366889 = 1; saved.entry(saved.parameter);
    *(volatile unsigned char *)0x366889 = 2; saved.entry(saved.parameter);
    if (dumps!=1) return 7;
    *(volatile unsigned char *)0x366889 = 0;
'''
        assert old in harness;harness=harness.replace(old,new)
        old_volume='''    volume_ready=0; saved.entry(saved.parameter); volume_ready=1;
    volume_error=1; saved.entry(saved.parameter); volume_error=0;
'''
        new_volume='''    *(volatile uint32_t *)0x442344 = 0; saved.entry(saved.parameter);
    *(volatile uint32_t *)0x442344 = 1;
    *(volatile unsigned char *)0x442340 = 0; saved.entry(saved.parameter);
    *(volatile unsigned char *)0x442340 = 3;
'''
        assert old_volume in harness;harness=harness.replace(old_volume,new_volume)
        (out/'harness.c').write_text('#define TEST_ORIGINAL_VOLUME\n'+harness)
        (out/'start.s').write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n bl run_checks\n mov r8,1\n trap_s 1\n.section .stack,"aw",@nobits\n.align 16\n.space 16384\n')
        flags=['-mcpu=arc700','-mno-sdata','-mlong-calls','-O2','-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-I',ROOT/'AkeruOS']
        sources=[ROOT/'AkeruOS/nikon_v11_runtime.c',ROOT/'AkeruOS/nikon_v11_memdump_worker.c',out/'harness.c'];objects=[]
        for source in sources:
            obj=out/(source.stem+'.o');p=r.command(source.stem+'_compile',[TOOLCHAIN/'arc-elf32-gcc',*flags,'-c',source,'-o',obj]);assert p.returncode==0,p.stdout;objects.append(obj)
        start=out/'start.o';p=r.command('start_as',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',start,out/'start.s']);assert p.returncode==0,p.stdout
        elf=out/'worker_path.elf';p=r.command('link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',LEGACY/'tests/smoke.ld','--defsym=nikon_v11_output_base_original=0x12b0dc','--defsym=nikon_v11_volume_status_original=0x12b8e8','-o',elf,start,*objects]);assert p.returncode==0,p.stdout
        main0=out/'main0.bin';main0.write_bytes(PS[0]);main1=out/'main1.bin';p1=bytearray(PS[1]);p1[0x366889-BS[1]['load_address_candidate']]=0;main1.write_bytes(p1)
        table=bytearray(0x200);table[0x40]=3;table[0x44]=1;table[0x4c:0x4f]=b'B:\0';table[0x84:0x87]=b'A:\0';table[0xbc:0xc4]=b'B:\\DCIM\0'
        table_file=out/'table.bin';table_file.write_bytes(table)
        maps=['--memory-mapfile','/result/main0.bin','--memory-region',f'{BS[0]["load_address_candidate"]:#x},{len(PS[0])}',
              '--memory-mapfile','/result/main1.bin','--memory-region',f'{BS[1]["load_address_candidate"]:#x},{len(p1)}',
              '--memory-mapfile','/result/table.bin','--memory-region',f'0x442300,{len(table)}']
        case,log=r.run('worker_path','/result/'+elf.name,maps,trace=True)
        assert case['exit_code']==0 and case['fault'] is None,log
        trace=(out/'worker_path.trace').read_text()
        assert trace.count('0x12b8e8  ')==69 and trace.count('0x12b0dc  ')==11 and trace.count('0x12b290  ')==11, 'original volume/path lookups not executed on expected entries'
        r.results.update(status='PASS_WORKER_WITH_ORIGINAL_VOLUME_AND_PATH_LOOKUPS',
            assumptions=['Original 12B8E8/12B154/12B3BC and 12B0DC/12B290 with synthetic volume index and table.', 'Task creation, scheduler and MEMDUMP write are explicit C fixtures.'],
            limits=['Path and status checks are separate from the writer and cannot prevent concurrent change.', 'No filesystem, actual SD readiness, exclusive file creation, task scheduler or physical hardware established.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS worker with original volume/path lookups and synthetic table:',out,flush=True)


if __name__=='__main__':main()
