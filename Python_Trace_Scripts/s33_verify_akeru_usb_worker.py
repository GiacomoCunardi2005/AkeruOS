#!/usr/bin/env python3
"""Run byte-identical Nikon USB producers/callbacks/cancel in the pinned GNU CPU."""
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
import json,sys,shutil,re,gzip,hashlib
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha,elf_loads
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import raw,u32,disasm
from s33_trace_state_dispatch import verified_payloads


def main():
    out=ROOT/'Risultati/AkeruUSB_RAM_Debug/Worker'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='usb-original-worker'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare()
        r.results.update(assumptions=['Original byte-identical USB producer/callback/cancel ranges at original addresses',
            'Explicit synthetic globals, endpoints, vtable, buffers and stack; no reset/boot chain',
            'Explicit zero-filled 8 MiB laboratory RAM, not a Nikon physical RAM map',
            'Endpoint suite executes constructor/wrappers/queue/cancel with synthetic parent/controller state',
            'Controller start/read/write, allocation, resources, delay, event set, final callback bridge and logging are executable boundary fixtures'],
            limits=['No controller implementation, payload movement, DMA/cache/IRQ or RTOS scheduling',
                'Controller values and failure/oversized counts are injected, not hardware observations',
                'Polling-loop bounds are fixture stops, not timeouts or returns of the original cancel function',
                'Not the complete worker event-dispatch loop or AkeruRAM transport binding; NON_INSTALLARE'],
            hardware_tested=False,installable=False)
        r.results['reference_tbib_entry']=r.results.pop('elf_entry')
        r.results['reference_tbib_segments']=r.results.pop('elf_segments')
        r.results['harness_entry']='0x1000'
        sources=[Path(__file__),ROOT/'AkeruOS/tests/usb_worker_gnu_test.c',
            ROOT/'S33-sections/analysis_codex/static_common.py',ROOT/'Python_Trace_Scripts/s33_trace_state_dispatch.py',
            ROOT/'AkeruOS/tests/usb_endpoint_gnu_test.c']
        for p in sources:
            r.input_hashes[str(p)]=sha(p);(r.out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
        cc=Path(shutil.which('arc-snps-elf-gcc')).resolve();r.input_hashes[str(cc)]=sha(cc)
        def command(name,args):
            p=r.command(name,args);assert p.returncode==0,p.stdout;return p.stdout
        ranges=[(0x1905D8,0x1906B4),(0x1907CC,0x190804),(0x190BA8,0x190BAC),
            (0x190D54,0x1910B0),(0x334110,0x3341E4),(0x336700,0x336764),
            (0x336ED0,0x336EDC),(0x336F24,0x336F30),(0x337020,0x33702C),
            (0x337098,0x3370A4),(0x3370C8,0x3370D4),(0x3370EC,0x3370F8),
            (0x278854,0x2789E4),(0x278BCC,0x278CCC),(0x278D8C,0x278DD8),
            (0x279488,0x279568),(0x279658,0x2799B0),(0x279A5C,0x279A74),
            (0x3F764C,0x3F76C8),(0x336F3C,0x336F60),(0xB1840,0xB184C),
            (0x335B34,0x335C44)]
        originals=[];assembly='';placements=''
        for a,b in ranges:
            p=r.out/f'original_{a:08x}.bin';p.write_bytes(raw(a,b-a))
            section=f'.original_{a:x}'
            assembly+=f'.section {section},"ax",@progbits\n.incbin "{p}"\n'
            placements+=f' {section} {a:#x} : {{ *({section}) }}\n'
            originals.append(dict(address=hex(a),size=b-a,sha256=sha(p),section=section))
        fixtures={0x158CBC:'lab_event',0x19A774:'lab_delay',0x243A50:'lab_log',
            0x243B2C:'lab_read',0x243B6C:'lab_write',0x243B10:'ep_logging',
            0x243A0C:'ep_alloc',0x243A38:'ep_free',0x1593AC:'ep_acquire',
            0x1594A4:'ep_release',0x2DBFB8:'ep_start',0x2792D0:'ep_open'}
        for address,name in fixtures.items():
            section=f'.fixture_{address:x}'
            assembly+=f'.section {section},"ax",@progbits\n mov r12,{name}\n j [r12]\n'
            placements+=f' {section} {address:#x} : {{ *({section}) }}\n'
        assembly+='.section .text.start,"ax",@progbits\n.global _start\n_start:\n mov sp,_stack_top\n mov r0,TEST_MODE\n bl main\n.global lab_stop\nlab_stop:\n mov r8,1\n trap_s 1\n'
        linker='ENTRY(_start)\nSECTIONS {\n . = 0x1000;\n .text : { *(.text.start) *(.text .text.*) }\n .rodata : { *(.rodata .rodata.*) }\n .data : { *(.data .data.*) }\n .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }\n'+placements+\
            ' .globals 0x368000 (NOLOAD) : { . += 0x300; }\n .record 0x423C00 (NOLOAD) : { . += 64; }\n .requests 0x47D9C8 (NOLOAD) : { . += 0xB0; }\n .contexts 0x500000 (NOLOAD) : { . += 0x3000; }\n .stack 0x510000 (NOLOAD) : { . += 16384; _stack_top = .; }\n}\n'
        (r.out/'lab.s').write_text(assembly);(r.out/'lab.ld').write_text(linker)
        command('assemble',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',r.out/'lab.o',r.out/'lab.s'])
        command('compile',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls',
            '-O2','-g','-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-c',sources[1],'-o',r.out/'test.o'])
        command('compile_endpoints',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls',
            '-O2','-g','-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-c',sources[-1],'-o',r.out/'endpoints.o'])
        for mode,name,expected in [(0,'matrix',0),(1,'cancel_poll_30',97),(2,'cancel_poll_5',97),(3,'endpoints',0)]:
            elf=r.out/(name+'.elf')
            command(name+'_link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',r.out/'lab.ld',
                '--defsym',f'TEST_MODE={mode}','-o',elf,r.out/'lab.o',r.out/'test.o',r.out/'endpoints.o'])
            assert elf_loads(elf)[0]==0x1000
            assert not command(name+'_undefined',[TOOLCHAIN/'arc-elf32-nm','-u',elf]).strip()
            for item in originals:
                check=r.out/'section_check.bin'
                command(name+'_section_'+item['address'],[TOOLCHAIN/'arc-elf32-objcopy',
                    '--dump-section',f'{item["section"]}={check}',elf])
                assert sha(check)==item['sha256']
            case,text=r.run(name,'/result/'+elf.name,
                ['--memory-fill','0','--memory-region','0,0x800000'],trace=True,extract=True)
            assert case['exit_code']==expected and case['fault'] is None,text
            trace=(r.out/(name+'.trace')).read_text()
            if mode in (1,2):
                pc=0x19062E if mode==1 else 0x190662
                assert len(re.findall(rf'^0x0*{pc:x}\s',trace,re.M))>=5
            else:
                pcs=(0x278BCC,0x278854,0x279658,0x278930,0x279904,0x2794D0) if mode==3 else (0x190DAC,0x190EA4,0x190E1C,0x190F10,0x190D54,0x1905D8)
                for pc in pcs:
                    assert re.search(rf'^0x0*{pc:x}\s',trace,re.M),hex(pc)
            case.update(expected_exit=expected,declared_fixture_stop=mode in (1,2),ram='8MiB-synthetic-zero')
            trace_file=r.out/(name+'.trace');case['trace_sha256']=sha(trace_file)
            with trace_file.open('rb') as src,gzip.open(str(trace_file)+'.gz','wb') as dst:
                shutil.copyfileobj(src,dst)
            with gzip.open(str(trace_file)+'.gz','rb') as src:
                assert hashlib.file_digest(src,'sha256').hexdigest()==case['trace_sha256']
            trace_file.unlink()  # Lossless trace retained; avoid hundreds of MiB per matrix run.
            print('PASS',name,case['instructions'],flush=True)
        (r.out/'gnu_verified.txt').write_text(''.join(disasm(a,b) for a,b in [
            (0x1905D8,0x1906B4),(0x190D54,0x190FD4),(0x191054,0x1910B0),
            (0x334110,0x3341E4),(0x336700,0x336764),(0x278854,0x278930),
            (0x278930,0x27897E),(0x2789B0,0x2789E4),(0x278BCC,0x278CCA),
            (0x279488,0x279568),(0x279658,0x2799B0)]))
        assert u32(0x191014)==0x423C00 and u32(0x19102C)==0x190E1C and u32(0x191044)==0x190F10
        assert u32(0x278D9C)==0x51A360 and u32(0x278DAC)==0x278854 and u32(0x278DB0)==0x278930
        r.results.update(status='PASS_GNU_ORIGINAL_USB_PRODUCERS_CALLBACKS_CANCEL_WITH_BOUNDARIES',
            matrix_cases=44,endpoint_cases=16,bounded_polling_cases=2,original_ranges=originals,
            boundary_fixtures={hex(k):v for k,v in fixtures.items()},
            payload_hashes={str(b['index']):b['sha256'] for b in verified_payloads(ROOT)[0]})
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    (out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n')
    print(r.results['status'],r.out,flush=True)


if __name__=='__main__':main()
