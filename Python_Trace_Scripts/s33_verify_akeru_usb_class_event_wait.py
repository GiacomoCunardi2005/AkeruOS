#!/usr/bin/env python3
"""Execute original USB class notification through original event SET/query/CLEAR."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from collections import Counter
import json, re, shutil, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, sha, elf_loads
from s33_verify_gnu_defined_memory import DefinedRunner, LAB, BUILD
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import raw, u32


def main():
    out=ROOT/'Risultati/AkeruUSB_RAM_Debug/Class_Event_Wait'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    r=DefinedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='usb-class-event-wait'))
    print('Evidence:',out,flush=True)
    try:
        r.prepare(); r.experimental_engine=LAB; r.c_abi_nobits=True
        assert sha(LAB/'install/bin/arc-elf32-run')==json.loads(BUILD.read_text())['engine_sha256']
        source=ROOT/'AkeruOS/tests/usb_class_event_wait_gnu_test.c'
        for p in (Path(__file__),source,BUILD,LAB/'install/bin/arc-elf32-run'):
            r.input_hashes[str(p)]=sha(p)
        (out/'test.c.snapshot').write_bytes(source.read_bytes())
        (out/'verifier.py.snapshot').write_bytes(Path(__file__).read_bytes())
        assert [u32(0x373308+4*i) for i in range(3)]==[0x45564e4c,0x02200001,2]
        ranges=[(0xb2d34,0xb2d50),(0x158c8c,0x158e78),(0x1c4c2c,0x1c4c3c),
                (0x17b770,0x17b958),(0x1910c4,0x191110),(0x191448,0x19144c),
                (0x19199c,0x1919d4),(0x191b2c,0x191b3c),(0x23c758,0x23c940),(0x2c9994,0x2c9ae0),
                (0x334100,0x334230),(0x372a48,0x373d18)]
        assembly=''; placements=''; originals=[]
        for a,b in ranges:
            p=out/f'original_{a:x}.bin'; p.write_bytes(raw(a,b-a)); sec=f'.original_{a:x}'
            assembly+=f'.section {sec},"'+('aw' if a==0x372a48 else 'ax')+f'",@progbits\n.incbin "{p}"\n'
            placements+=f' {sec} {a:#x} : {{ *({sec}) }}\n'
            originals.append(dict(address=hex(a),size=b-a,sha256=sha(p),section=sec))
        assembly+='.section .fixture_log,"ax",@progbits\n b event_log\n'
        placements+=' .fixture_log 0x243a50 : { *(.fixture_log) }\n'
        assembly+='.section .text.start,"ax",@progbits\n.global _start\n_start:\n mov sp,_stack_top\n bl main\n.global lab_stop\nlab_stop:\n mov r8,1\n trap_s 1\n'
        linker=('ENTRY(_start)\nSECTIONS { . = 0x1000; .text : { *(.text.start) *(.text .text.*) }\n'
                '.rodata : { *(.rodata .rodata.*) } .data : { *(.data .data.*) } '
                '.bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }\n'+placements+
                ' .kernel_global 0x369348 (NOLOAD) : { . += 4; }\n'
                ' .trace_global 0x36a3a4 (NOLOAD) : { . += 8; }\n'
                ' .class_global 0x368114 (NOLOAD) : { . += 4; }\n'
                ' .worker_global 0x423c24 (NOLOAD) : { . += 1; }\n'
                ' .stack 0x520000 (NOLOAD) : { . += 16384; _stack_top = .; }\n}\n')
        (out/'lab.s').write_text(assembly); (out/'lab.ld').write_text(linker)
        def command(name,args):
            p=r.command(name,args); assert p.returncode==0,p.stdout; return p.stdout
        command('assemble',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',out/'lab.o',out/'lab.s'])
        command('compile',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-std=c11','-O2',
                '-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-c',source,'-o',out/'test.o'])
        elf=out/'event.elf'; command('link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',out/'lab.ld','-o',elf,out/'lab.o',out/'test.o'])
        assert elf_loads(elf)[0]==0x1000
        assert not command('undefined',[TOOLCHAIN/'arc-elf32-nm','-u',elf]).strip()
        for item in originals:
            check=out/'section_check.bin'
            command('section_'+item['address'],[TOOLCHAIN/'arc-elf32-objcopy','--dump-section',f'{item["section"]}={check}',elf])
            assert sha(check)==item['sha256']
        case,log=r.run('event','/result/event.elf',trace=True,extract=True,ram='128-zero')
        assert case['exit_code']==0 and case['fault'] is None,log[-2000:]
        assert not any(tag in log for tag in ('S33_UNDEFINED','S33_AUX_UNKNOWN','S33_DSP_GUARD','runtime error:'))
        trace=(out/'event.trace').read_text(); counts=Counter(int(m.group(1),16) for m in re.finditer(r'^0x([0-9a-f]+)\s',trace,re.M))
        for pc,minimum in [(0x19199c,6),(0x1910c4,6),(0x158cbc,8),(0x158c8c,12),(0x23c758,4),(0x158e28,2),(0x158ce0,2),(0x23c8ac,2),(0x158d04,8),(0x23c938,8),(0x2c9994,8)]:
            assert counts[pc]>=minimum,(hex(pc),counts[pc],minimum)
        r.results.update(status='PASS_CLASS_NOTIFICATION_WITH_ORIGINAL_EVENT_SET_WAIT_QUERY_CLEAR',
            scenarios=6,immediate_wait_cases=8,original_entries={hex(pc):counts[pc] for pc in (0x19199c,0x1910c4,0x158cbc,0x158c8c,0x23c758,0x158e28,0x158ce0,0x23c8ac,0x158d04,0x23c938,0x2c9994)},
            event_record='0x373308',event_id='0x02200001',hardware_tested=False,installable=False,
            original_ranges=originals,assumptions=['Event record and kernel/task/ready state manually prepared; empty waiter ring; endpoint close and logger are fixtures'],
            limits=['No queued waiter, scheduler switch, USB controller, IRQ, DMA, physical memory map or hardware; synthetic 128 MiB is not a physical map',
                    'Class invoked directly; endpoint close and prior full USB flow are separate evidence; no firmware installation'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    (out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n')
    print(r.results['status'],out,flush=True)


if __name__=='__main__':main()
