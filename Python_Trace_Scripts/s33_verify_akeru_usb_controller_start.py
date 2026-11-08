#!/usr/bin/env python3
"""Execute original USB controller preparation; no physical bus or DMA access."""
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
from static_common import raw, disasm, u32


def main():
    out=ROOT/'Risultati/AkeruUSB_RAM_Debug/Controller_Start'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    r=DefinedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='usb-controller-start'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();r.experimental_engine=LAB;r.c_abi_nobits=True
        r.results['reference_tbib_entry']=r.results.pop('elf_entry')
        r.results['reference_tbib_segments']=r.results.pop('elf_segments')
        r.results.update(harness_entry='0x1000',assumptions=[
            'Byte-identical original routine/helper ranges placed at their V1.1 addresses',
            'Explicit synthetic controller/descriptor/stack/buffer and C ABI zero NOBITS',
            'Register helper values are injected; no dereference of physical MMIO',
            '128MiB synthetic GNU memory is not a physical Nikon RAM map'])
        assert sha(LAB/'install/bin/arc-elf32-run')==json.loads(BUILD.read_text())['engine_sha256']
        source=ROOT/'AkeruOS/tests/usb_controller_start_gnu_test.c'
        for p in (Path(__file__),source,BUILD,LAB/'install/bin/arc-elf32-run',
                  ROOT/'AkeruOS/Makefile',Path(shutil.which('arc-snps-elf-gcc')).resolve()):
            r.input_hashes[str(p)]=sha(p)
        for p in (source,Path(__file__)):(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
        originals=[];assembly='';placements=''
        ranges=[(0x2DBFB8,0x2DC214),(0x334110,0x3341E4),
                (0x3342A8,0x3342CC),(0x335B34,0x335C44),(0x336700,0x336764),
                (0x336F54,0x336F60),(0x336FCC,0x336FD8),(0x337014,0x337020),
                (0x337080,0x33708C),(0x337104,0x337110),(0x337158,0x337164)]
        for a,b in ranges:
            p=out/f'original_{a:08x}.bin';p.write_bytes(raw(a,b-a));section=f'.original_{a:x}'
            assembly+=f'.section {section},"ax",@progbits\n.incbin "{p}"\n'
            placements+=f' {section} {a:#x} : {{ *({section}) }}\n'
            originals.append(dict(address=hex(a),size=b-a,sha256=sha(p),section=section))
        assert u32(0x2DC174)==0x353400 and u32(0x2DC178)==0x243B6C
        for address,name in {0x243B2C:'controller_read',0x243B6C:'controller_write',0x243BA8:'controller_modify'}.items():
            section=f'.fixture_{address:x}'
            assembly+=f'.section {section},"ax",@progbits\n mov r12,{name}\n j [r12]\n'
            placements+=f' {section} {address:#x} : {{ *({section}) }}\n'
        assembly+='.section .text.start,"ax",@progbits\n.global _start\n_start:\n mov sp,_stack_top\n bl main\n.global lab_stop\nlab_stop:\n mov r8,1\n trap_s 1\n'
        linker='ENTRY(_start)\nSECTIONS { . = 0x1000;\n .text : { *(.text.start) *(.text .text.*) }\n .rodata : { *(.rodata .rodata.*) }\n .data : { *(.data .data.*) }\n .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }\n'+placements+\
            ' .global 0x353400 (NOLOAD) : { . += 4; }\n .context 0x500000 (NOLOAD) : { . += 0x300; }\n .buffer 0x502000 (NOLOAD) : { . += 0x100; }\n .stack 0x510000 (NOLOAD) : { . += 16384; _stack_top = .; }\n}\n'
        (out/'lab.s').write_text(assembly);(out/'lab.ld').write_text(linker)
        def command(name,args):
            result=r.command(name,args);assert result.returncode==0,result.stdout;return result.stdout
        command('assemble',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',out/'lab.o',out/'lab.s'])
        command('compile',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-O2','-g',
            '-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-c',source,'-o',out/'test.o'])
        elf=out/'controller.elf'
        command('link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',out/'lab.ld','-o',elf,out/'lab.o',out/'test.o'])
        assert elf_loads(elf)[0]==0x1000
        assert not command('undefined',[TOOLCHAIN/'arc-elf32-nm','-u',elf]).strip()
        for item in originals:
            check=out/'section_check.bin'
            command('section_'+item['address'],[TOOLCHAIN/'arc-elf32-objcopy','--dump-section',f'{item["section"]}={check}',elf])
            assert sha(check)==item['sha256']
        case,log=r.run('controller','/result/controller.elf',trace=True,extract=True,ram='128-zero')
        assert case['exit_code']==0 and case['fault'] is None,log[-4000:]
        assert not any(tag in log for tag in ('S33_UNDEFINED','S33_AUX_UNKNOWN','S33_DSP_GUARD','runtime error:'))
        trace=(out/'controller.trace').read_text()
        for pc in (0x2DBFB8,0x2DC110,0x2DC17C,0x2DC1CC,0x2DC20A,0x3342A8):
            assert re.search(rf'^0x0*{pc:x}\s',trace,re.M),hex(pc)
        starts=len(re.findall(r'^0x0*2dbfb8\s',trace,re.M));assert starts==290,starts
        trace_path=out/'controller.trace';trace_sha=sha(trace_path)
        with trace_path.open('rb') as src,gzip.open(str(trace_path)+'.gz','wb') as dst:shutil.copyfileobj(src,dst)
        with gzip.open(str(trace_path)+'.gz','rb') as src:assert hashlib.file_digest(src,'sha256').hexdigest()==trace_sha
        trace_path.unlink()
        windows=[(0x2DBFB8,0x2DC16A),(0x2DC17C,0x2DC214),(0x3342A8,0x3342CC)]
        (out/'gnu_verified.txt').write_text('\n'.join(disasm(a,b) for a,b in windows))
        # Original open copies descriptor byte2 bit7 into the controller's bit8.
        for a,expected in [(0x2792EA,'028f'),(0x279330,'412ac121c0b940250014760d2f1c'),
                           (0xB18AC,'4a220012690661424a230010')]:
            assert raw(a,len(expected)//2).hex()==expected
        (out/'direction_binding_static.txt').write_text(disasm(0x2792D0,0x27935E)+disasm(0xB18AC,0xB18B8))
        r.results.update(status='PASS_ORIGINAL_USB_CONTROLLER_START_WITH_HELPER_FIXTURES',
            controller_cases=290,original_ranges=originals,original_entry_calls=starts,
            direction_binding_static=dict(entry='0x2792d0',descriptor_byte=2,descriptor_bit=7,
                software_bit=8,setter='0xb18ac',hardware_observed=False),
            trace_sha256=trace_sha,experimental_engine_sha256=sha(LAB/'install/bin/arc-elf32-run'),
            payload_hashes={str(b['index']):b['sha256'] for b in verified_payloads(ROOT)[0]},
            hardware_tested=False,installable=False,
            limits=['Register helper reads/writes/RMW are fixtures; no physical width/MMIO/DMA/cache/IRQ proof',
                    'Direct calls use synthetic controller, descriptor, flags and buffer; no live initialization or dispatch',
                    'PIO and linear DMA preparation only; scatter/gather branch not executed',
                    'DSP multiply uses the existing provisional GNU model, not measured Nikon arithmetic',
                    'Buffer sentinel checks show only that preparation did not copy sampled payload words',
                    'Bit8=0 packet rounding may require padded buffer capacity; live binding/DMA ownership unproved'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    (out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n')
    print(r.results['status'],r.out,flush=True)


if __name__=='__main__':main()
