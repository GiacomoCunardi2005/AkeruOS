#!/usr/bin/env python3
"""Execute original controller construction/defaults/init and endpoint preparation offline."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import gzip
import hashlib
import json
import re
import shutil
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, sha, elf_loads
from s33_verify_gnu_defined_memory import DefinedRunner, LAB, BUILD
from s33_trace_state_dispatch import verified_payloads
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import raw, disasm


class InitRunner(DefinedRunner):
    def command(self, name, args):
        if name == 'controller_init':
            args = list(args)
            # The 192-case instruction trace can exceed the shared runner's 10s limit.
            index = args.index('timeout') + 1
            assert args[index] == '10s'
            args[index] = '45s'
        return super().command(name, args)


def main():
    out=ROOT/'Risultati/AkeruUSB_RAM_Debug/Controller_Init'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    r=InitRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='usb-controller-init'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();r.experimental_engine=LAB;r.c_abi_nobits=True
        r.results['reference_tbib_entry']=r.results.pop('elf_entry')
        r.results['reference_tbib_segments']=r.results.pop('elf_segments')
        r.results.update(harness_entry='0x1000',hardware_tested=False,installable=False,
            assumptions=['Byte-identical original controller-constructor/default-parameters/initialization/open/configuration/submit chain at V1.1 addresses',
                'Explicit synthetic parent/controller/table/endpoint/USB descriptor/request and 1024-byte payload',
                'C ABI NOBITS supplied as zero; 128MiB synthetic RAM is not a physical Nikon RAM map'],
            limits=['Allocation returns explicit zeroed regions; lock, MMIO, delays, platform and module-query services are executable fixtures; hardware capability words are injected',
                'No payload transfer, DMA, cache, IRQ, completion/cancel, live allocator or scheduler evidence',
                'Default parameter profile only; endpoint1 bulk64/512; scatter/gather allocation at open only; submit PIO or linear DMA only; reset-complete/mode are injected',
                'Provisional existing GNU DSP model; not a silicon arithmetic measurement',
                'No binding or physical RAM whitelist, boot, residence, recovery or installation; NON_INSTALLARE'])
        assert sha(LAB/'install/bin/arc-elf32-run')==json.loads(BUILD.read_text())['engine_sha256']
        source=ROOT/'AkeruOS/tests/usb_controller_init_gnu_test.c'
        for p in (Path(__file__),source,ROOT/'AkeruOS/tests/usb_open_buffer_gnu_test.c',BUILD,LAB/'install/bin/arc-elf32-run',
                  ROOT/'AkeruOS/Makefile',ROOT/'S33-sections/analysis_codex/static_common.py',
                  ROOT/'Python_Trace_Scripts/s33_verify_gnu_defined_memory.py',
                  Path(shutil.which('arc-snps-elf-gcc')).resolve()):
            r.input_hashes[str(p)]=sha(p)
        for p in (source,Path(__file__),ROOT/'AkeruOS/tests/usb_open_buffer_gnu_test.c'):(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
        ranges=[(0x27864C,0x278770),(0x278854,0x278930),(0x278980,0x2789B0),
            (0x278F0C,0x278FA4),(0x2792D0,0x2794D0),(0x279658,0x279904),
            (0x279A5C,0x279A74),(0x243A54,0x243A58),(0x243BC8,0x243BE0),
            (0x2D834C,0x2DA2FC),(0x2DA724,0x2DAB68),(0x2DBCF8,0x2DBE4C),(0x2DBFB8,0x2DC214),(0x334110,0x334230),(0x3342A8,0x3342CC),
            (0x335B34,0x335C44),(0x336700,0x336764),(0x336E88,0x337194),
            (0xB17B0,0xB18B8),(0x3533A0,0x3533F8)]
        originals=[];assembly='';placements=''
        for a,b in ranges:
            p=out/f'original_{a:08x}.bin';p.write_bytes(raw(a,b-a));section=f'.original_{a:x}'
            assembly+=f'.section {section},"ax",@progbits\n.incbin "{p}"\n'
            placements+=f' {section} {a:#x} : {{ *({section}) }}\n'
            originals.append(dict(address=hex(a),size=b-a,sha256=sha(p),section=section))
        fixtures={0x243A0C:'init_alloc',0x243A38:'init_free',0x190D00:'init_module',0x263DCC:'init_platform',0x145C3C:'init_delay',0x19A774:'init_delay',0x243A50:'boundary_log',0x243B10:'boundary_log',
            0x1593AC:'boundary_acquire',0x1594A4:'boundary_release',
            0x243B2C:'init_read',0x243B6C:'init_write',0x243BA8:'init_modify'}
        for address,name in fixtures.items():
            section=f'.fixture_{address:x}'
            assembly+=f'.section {section},"ax",@progbits\n b {name}\n'
            placements+=f' {section} {address:#x} : {{ *({section}) }}\n'
        assembly+='.section .text.start,"ax",@progbits\n.global _start\n_start:\n mov sp,_stack_top\n bl main\n.global lab_stop\nlab_stop:\n mov r8,1\n trap_s 1\n'
        linker='ENTRY(_start)\nSECTIONS { . = 0x1000;\n .text : { *(.text.start) *(.text .text.*) }\n .rodata : { *(.rodata .rodata.*) }\n .data : { *(.data .data.*) }\n .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }\n'+placements+\
            ' .global 0x353400 (NOLOAD) : { . += 4; }\n .top_global 0x36B588 (NOLOAD) : { . += 4; }\n .context 0x500000 (NOLOAD) : { . += 0x1800; }\n .buffer 0x502000 (NOLOAD) : { . += 0x400; }\n .stack 0x510000 (NOLOAD) : { . += 16384; _stack_top = .; }\n}\n'
        (out/'lab.s').write_text(assembly);(out/'lab.ld').write_text(linker)
        def command(name,args):
            result=r.command(name,args);assert result.returncode==0,result.stdout;return result.stdout
        command('assemble',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',out/'lab.o',out/'lab.s'])
        command('compile',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-O2','-g',
            '-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-c',source,'-o',out/'test.o'])
        elf=out/'controller_init.elf'
        command('link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',out/'lab.ld','-o',elf,out/'lab.o',out/'test.o'])
        assert elf_loads(elf)[0]==0x1000
        assert not command('undefined',[TOOLCHAIN/'arc-elf32-nm','-u',elf]).strip()
        for item in originals:
            check=out/'section_check.bin'
            command('section_'+item['address'],[TOOLCHAIN/'arc-elf32-objcopy','--dump-section',f'{item["section"]}={check}',elf])
            assert sha(check)==item['sha256']
        case,log=r.run('controller_init','/result/controller_init.elf',trace=True,extract=True,ram='128-zero')
        assert case['exit_code']==0 and case['fault'] is None,log[-4000:]
        assert not any(tag in log for tag in ('S33_UNDEFINED','S33_AUX_UNKNOWN','S33_DSP_GUARD','runtime error:'))
        trace_path=out/'controller_init.trace';trace=trace_path.read_text()
        counts={}
        for pc,expected in [(0x278F30,192),(0x2D9E58,192),(0x2D9C68,192),
                            (0x2DA724,192),(0x27864C,192),(0x2792D0,192),
                            (0x2DBCF8,192),(0x278854,128),(0x2DBFB8,128)]:
            counts[hex(pc)]=len(re.findall(rf'^0x0*{pc:x}\s',trace,re.M))
            assert counts[hex(pc)]==expected,(hex(pc),counts[hex(pc)],expected)
        trace_sha=sha(trace_path)
        with trace_path.open('rb') as src,gzip.open(str(trace_path)+'.gz','wb') as dst:shutil.copyfileobj(src,dst)
        with gzip.open(str(trace_path)+'.gz','rb') as src:assert hashlib.file_digest(src,'sha256').hexdigest()==trace_sha
        trace_path.unlink()
        windows=[(0x2D9E58,0x2DA018),(0x2D9C68,0x2D9D38),(0x2D9DA0,0x2D9E58),
            (0x2DA724,0x2DA77A),(0x2DA77A,0x2DA944),(0x2DA944,0x2DA9D0),
            (0x2DA9D0,0x2DAAA4),(0x2DAAAC,0x2DAAD6),(0x2DAADE,0x2DAB68)]
        (out/'gnu_verified.txt').write_text('\n'.join(disasm(a,b) for a,b in windows))
        r.results.update(status='PASS_ORIGINAL_USB_CONTROLLER_CONSTRUCTOR_DEFAULTS_INIT_OPEN_SUBMIT_WITH_MMIO_FIXTURES',
            matrix_cases=192,integrated_submit_cases=128,scatter_open_cases=64,retained_without_programming=16,template_bytes_original_zero=88,
            original_ranges=originals,boundary_fixtures={hex(k):v for k,v in fixtures.items()},
            original_entry_calls=counts,trace_sha256=trace_sha,
            experimental_engine_sha256=sha(LAB/'install/bin/arc-elf32-run'),
            payload_hashes={str(b['index']):b['sha256'] for b in verified_payloads(ROOT)[0]})
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    (out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n')
    print(r.results['status'],r.out,flush=True)


if __name__=='__main__':main()
