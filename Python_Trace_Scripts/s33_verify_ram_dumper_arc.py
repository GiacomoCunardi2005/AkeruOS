#!/usr/bin/env python3
"""Execute the actual compiled ARC RAM dumper with declared RAM/file adapters."""
from types import SimpleNamespace
from pathlib import Path
import json
import re
import struct

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
from s33_read_ram_dump import parse_dump

STATE, OUTPUT, MEMORY, CODE = 0x2010000, 0x2020000, 0x2030000, 0x2000000
FIXTURE = r'''
#include "ram_dump.h"
#define S ((volatile uint32_t *)0x2010000)
#define O ((volatile uint8_t *)0x2020000)
static int arm(void *p) { (void)p; return S[0]==1 ? 0 : 1; }
static int wait_ms(void *p,uint32_t n) { (void)p; S[2]+=n; return 0; }
static uint32_t now_ms(void *p) { (void)p; return S[2]; }
static int read_ram(void *p,uint32_t address,uint8_t *out,uint32_t n) {
    uint32_t i; (void)p; S[3]++;
    if(S[0]==2)return -1;
    if(address<0x2030000u || address+n>0x2032000u)return -1;
    for(i=0;i<n;i++)out[i]=((const volatile uint8_t *)(uintptr_t)address)[i];
    return 0;
}
static int open_new(void *p,const char *name,void **file) {
    (void)p; S[4]++;S[1]=0;
    if(name[0]!='B'||name[1]!=':'||name[2]!='A')return -1;
    *file=(void *)0x2020000;return 0;
}
static int32_t write_bytes(void *p,void *file,const uint8_t *data,uint32_t n) {
    uint32_t i; (void)p;
    if(file!=(void *)0x2020000 || n>8192u-S[1])return -1;
    if(S[0]==3 && n>7)n=7;
    for(i=0;i<n;i++)O[S[1]+i]=data[i];
    S[1]+=n; S[5]++;return (int32_t)n;
}
static int close_file(void *p,void *file) {
    (void)p;(void)file;S[6]++;return S[0]==4 ? -1 : 0;
}
int akeru_dump_cpu_case(uint32_t mode) {
    struct akeru_ram_dumper d;
    struct akeru_dump_region ranges[2];
    int result;
    S[0]=mode;
    ranges[0].address=0x2030000;ranges[0].length=1040;
    ranges[1].address=0x2031000;ranges[1].length=31;
    akeru_ram_dump_defaults(&d);
    akeru_ram_dump_use_full_map(&d,ranges,2);
    d.max_snapshots=mode==5 ? 2 : 1;
    d.io.context=0;d.io.armed=arm;d.io.wait_ms=wait_ms;d.io.now_ms=now_ms;
    d.io.read_ram=read_ram;d.io.open_new=open_new;d.io.write=write_bytes;d.io.close=close_file;
    result=akeru_ram_dump_run(&d);
    S[7]=d.completed;S[8]=(uint32_t)result;S[9]=d.next_sequence;
    return result;
}
'''


def main():
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN,
        output=None, action='compiled-arc700-ram-dumper'))
    print('Evidence:', r.out, flush=True)
    try:
        r.prepare()
        source = ROOT/'AkeruOS/ram_dump.c'
        header = source.with_suffix('.h')
        for p in (source, header, Path(__file__)):
            r.input_hashes[str(p)] = sha(p)
            (r.out/p.name).write_bytes(p.read_bytes())
        fixture = r.out/'ram_dumper_cpu_fixture.c'
        fixture.write_text(FIXTURE)
        objects = []
        for src in (source, fixture):
            obj = r.out/(src.stem+'.o')
            p = r.command(src.stem+'_compile', [TOOLCHAIN/'arc-elf32-gcc',
                '-mcpu=arc700','-mno-sdata','-mlong-calls','-O2','-ffreestanding',
                '-fno-builtin','-Wall','-Wextra','-Werror','-I',source.parent,
                '-c',src,'-o',obj])
            assert p.returncode == 0, p.stdout
            objects.append(obj)
        link = r.out/'module.ld'
        link.write_text('SECTIONS { . = 0x2000000; .text : { *(.text .text.*) } '
                        '.rodata : { *(.rodata .rodata.*) } .data : { *(.data .data.*) } '
                        '.bss : { *(.bss .bss.*) *(COMMON) } }\n')
        module = r.out/'module.elf'
        p = r.command('module_link', [TOOLCHAIN/'arc-elf32-ld','-EL','-T',link,
                                      '-o',module,*objects])
        assert p.returncode == 0, p.stdout
        p = r.command('module_symbols', [TOOLCHAIN/'arc-elf32-nm','-n',module])
        assert p.returncode == 0
        entry = int(re.search(r'^([0-9a-f]+) T akeru_dump_cpu_case$', p.stdout, re.M)[1],16)
        binary = r.out/'module.bin'
        p = r.command('module_extract', [TOOLCHAIN/'arc-elf32-objcopy','-O','binary',module,binary])
        assert p.returncode == 0
        module_bytes = binary.read_bytes()
        binary.write_bytes(module_bytes+bytes(16))
        assert len(module_bytes) < STATE-CODE
        r.results.update(model='Compiled production dumper; explicit fake filesystem and RAM banks',
            assumptions=['Two declared synthetic RAM banks, not a physical Nikon RAM map',
                         'SD, RTOS wait, clock and file operations are compiled adapters',
                         'Captured bytes come from the actual mapped guest RAM via compiled loads'],
            limits=['No camera, real filesystem, task creation, boot or physical SD persistence',
                    'No claim of complete physical RAM coverage'], compiled_module_bytes=len(module_bytes))
        original_memory = bytes((i*17+3)&255 for i in range(8192))
        memory = r.out/'synthetic_ram.bin';memory.write_bytes(original_memory)
        expected_results = [0,1,-3,0,-2,0]
        for mode, expected in enumerate(expected_results):
            state = r.out/f'state_{mode}.bin';state.write_bytes(bytes(64))
            output = r.out/f'output_{mode}.bin';output.write_bytes(bytes(8192))
            caller = compile_probe(r, f'caller_{mode}',
                f' mov r0,{mode}\n mov r12,{entry:#x}\n jl [r12]\n'
                f' mov r1,{expected}\n cmp r0,r1\n bne fail\n mov r0,0\n b end\n'
                'fail:\n mov r0,7\nend:\n mov r8,1\n trap_s 1\n')
            options = []
            for path, address in ((binary,CODE),(state,STATE),(output,OUTPUT),(memory,MEMORY)):
                options += ['--memory-mapfile','/result/'+path.name,
                            '--memory-region',f'{address:#x},{path.stat().st_size}']
            case, log = r.run(f'arc_dumper_{mode}', '/result/'+caller.name, options)
            assert case['exit_code'] == 0 and case['fault'] is None, log
            values = struct.unpack('<16I',state.read_bytes())
            assert values[8] == expected & 0xffffffff
            if mode in (0,3,5):
                result = parse_dump(output.read_bytes()[:values[1]])
                assert result['coverage'] == 'all_declared_ram_banks'
                assert [x['data'] for x in result['regions']] == [original_memory[:1040], original_memory[4096:4127]]
                assert values[7] == (2 if mode==5 else 1)
                assert result['sequence'] == (1 if mode==5 else 0)
            if mode == 1:
                assert values[4] == values[6] == values[3] == 0
            if mode in (2,4):
                assert values[6] == 1 and values[7] == 0
            case.update(dumper_mode=mode, expected_return=expected,
                        completed=values[7], output_bytes=values[1])
            print('PASS ARC dumper mode',mode,flush=True)
        assert memory.read_bytes() == original_memory
        assert binary.read_bytes() == module_bytes+bytes(16)
        r.finish()
        r.results['status'] = 'PASS_COMPILED_ARC_RAM_DUMPER'
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:
        r.save()
    evidence = ROOT/'Risultati/Runtime_Kernel/RAM_Dumper/arc_latest.json'
    evidence.write_text(json.dumps(dict(evidence=str((r.out/'verified_evidence.json').relative_to(ROOT)),
                                         status=r.results['status']),indent=2)+'\n')
    print(r.results['status'], r.out/'verified_evidence.json',flush=True)


if __name__ == '__main__':
    main()
