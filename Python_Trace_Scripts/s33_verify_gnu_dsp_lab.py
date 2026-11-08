#!/usr/bin/env python3
"""Verify a restricted provisional DSP experiment, preserving the reference GNU engine."""
from pathlib import Path
from types import SimpleNamespace
import json
import re
import struct
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha, elf_loads

LAB = ROOT/'work/gnu_arc700_dsp_lab_v7'
BUILD = ROOT/'outputs/gnu_arc700_dsp/build_v7/verified_evidence.json'


def compile_probe(runner, name, source):
    s = runner.out/f'{name}.s'; o = s.with_suffix('.o'); elf = s.with_suffix('.elf')
    s.write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n'+source+
                 '\n.section .stack,"aw",@nobits\n.align 16\n.space 16384\n')
    for suffix,cmd in [('as',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',o,s]),
                       ('ld',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',LEGACY/'tests/smoke.ld','-o',elf,o]),
                       ('disasm',[TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',elf])]:
        p = runner.command(name+'_'+suffix,cmd)
        assert p.returncode == 0,p.stdout
    assert elf_loads(elf)[0] == 0x1000
    return elf


def probe(runner, name, left, right, unsigned=False, mode=0, write_mode=True, f=False, dest=62):
    code = (0x280d0000 if unsigned else 0x280c0000) | (int(f)<<15) | (1<<6) | dest
    raw = struct.pack('<HH',code>>16,code&65535)
    high=(left>>16)*(right>>16)
    low=(left&65535)*(right&65535)
    asm = f' mov r0,{left:#x}\n mov r1,{right:#x}\n'
    if write_mode: asm += f' sr {mode},[0x41]\n'
    asm += (' mov r56,0x12345678\n mov r57,0x87654321\n'
            ' cmp r0,1\n lr r3,[0xa]\n .byte '+','.join(hex(x) for x in raw)+'\n'
            ' lr r4,[0xa]\n cmp r3,r4\n bne fail\n'
            f' mov r2,{low:#x}\n cmp r57,r2\n bne fail\n'
            f' mov r2,{high:#x}\n cmp r56,r2\n bne fail\n'
            f' cmp r0,{left:#x}\n bne fail\n cmp r1,{right:#x}\n bne fail\n'
            ' mov r0,0\n b finish\nfail:\n mov r0,7\nfinish:\n mov r8,1\n trap_s 1\n')
    elf = compile_probe(runner,name,asm)
    case, text = runner.run(name,f'/result/{elf.name}',trace=True,extract=True)
    domain = (high<=0x7fffffff and low<=0x7fffffff) if unsigned else ((left<=32767 and right<=32767) or left==0 or right==0)
    supported = domain and mode==0 and write_mode and not f and dest==62
    expected = 0 if supported else (4 if f or dest!=62 else 5)
    assert case['exit_code'] == expected,text
    assert case['fault'] is None
    if supported:
        assert re.search(rf'S33_DSP_LAB .*left={left:08x} right={right:08x} r56={high:08x} r57={low:08x} provisional=1',text)
        assert 'S33_DSP_GUARD' not in text
    else:
        if f or dest!=62:
            assert 'sfmt_empty' in (runner.out/f'{name}.trace').read_text()
        else: assert 'S33_DSP_GUARD' in text
    case.update(left=left,right=right,unsigned=unsigned,mode=mode,write_mode=write_mode,
                supported_experiment=supported,expected_exit=expected,
                instruction_bytes=raw.hex(' '),hardware_semantics_proven=False)
    print('PASS',name,flush=True)


def boot(runner, name, extra=()):
    options = ['--memory-fill','0','--memory-region','0x0fe800f8,2',
               '--memory-region','0x0fe80064,2','--memory-region','0x0fe80108,2']+list(extra)
    case,text = runner.run(name,'/result/tbib.elf',options,trace=True,extract=True)
    case['provisional_execution'] = True
    assert 'S33_DSP_LAB pc=01009b8c' in text
    if not extra:
        assert 'S33_DSP_GUARD' not in text
        assert case['exit_code']==11 and case['fault']==dict(size=2,operation='read',address='0xfe80100',pc='0x1009b94')
    else:
        assert case['exit_code']==11 and case['fault']==dict(size=2,operation='write',address='0xfe40004',pc='0x10091f8')
        assert 'S33_AUX_ARCH_RESET index=512' in text
        assert 'S33_IRQ_PRIORITY value=00000000' in text
        assert 'S33_AUX_UNKNOWN' not in text and 'runtime error:' not in text
        assert 'S33_DSP_GUARD' not in text
        assert text.count('S33_DSP_LAB pc=')>=5
    print('BOOT',name,case['exit_code'],case['fault'],flush=True)
    return case,text


def main():
    args=SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='dsp-lab-verify')
    runner=Runner(args)
    print('Evidence:',runner.out,flush=True)
    try:
        runner.prepare()
        build=json.loads(BUILD.read_text())
        assert sha(LAB/'install/bin/arc-elf32-run')==build['experimental_sha256']
        runner.input_hashes[str(LAB/'install/bin/arc-elf32-run')]=build['experimental_sha256']
        runner.input_hashes[str(BUILD)]=sha(BUILD)
        runner.experimental_engine=LAB
        runner.results.update(experimental_simulator_sha256=build['experimental_sha256'],
            model='Provisional DSP subset; unsigned non-saturating lane products and signed low-positive/zero, ZA/noF/MACMODE0',
            aux_bounds_fixed=True,
            independent_complete_semantics_proven=False)
        (runner.out/'dsp_verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        # Existing core paths must remain compatible with the pinned baseline.
        for name,rel in [('smoke','tests/smoke-fixed.elf'),('alias','tests/alias.elf')]+[(f'cpu_{i}',f'tests/arc700-suite/test-{i}.elf') for i in range(1,10)]:
            runner.input_hashes[str(LEGACY/rel)]=sha(LEGACY/rel)
            case,text=runner.run(name,'/work/'+rel)
            assert case['exit_code']==0 and case['fault'] is None
        runner.baseline(trace=True)
        for op in ('muldw','muludw'):
            pairs=[(0,0),(1,1),(2,3),(63,16),(32767,32767),(1,32767),(0,32767),
                   (0,0xffffffff),(0xffffffff,0),(0,0x10000)]
            if op=='muludw':pairs += [(0x10001,0x20003),(12000000,1),(12000000,0x10000),
                                      (0xffffffff,1),(0x12345678,0x1020304),(0x7fff7fff,0x7fff7fff)]
            for i,(a,b) in enumerate(pairs):
                probe(runner,f'{op}_{i}',a,b,unsigned=op=='muludw')
        for name,kw in [('negative',dict(left=0xffffffff,right=1)),
                        ('upper_lane',dict(left=65536,right=1)),
                        ('unsigned_saturation',dict(left=0xffffffff,right=0xffffffff,unsigned=True)),
                        ('mode',dict(left=1,right=1,mode=8)),
                        ('no_mode',dict(left=1,right=1,write_mode=False)),
                        ('flags',dict(left=1,right=1,f=True)),
                        ('destination',dict(left=1,right=1,dest=2))]:
            probe(runner,'reject_'+name,**kw)
        boot(runner,'tbib_dsp_to_clock100')
        boot(runner,'tbib_dsp_irq_to_device_write',['--memory-region','0x0fe80100,2'])
        runner.finish()
        runner.results['status']='PASS_EXPERIMENT_ONLY'
    except Exception as exc:
        runner.results.update(status='FAIL',error=repr(exc))
        raise
    finally:runner.save()
    print('PASS experiment only:',runner.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
