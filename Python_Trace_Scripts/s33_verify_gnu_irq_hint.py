#!/usr/bin/env python3
"""Verify only the declared empty-software-source model, with nonzero requests guarded."""
from pathlib import Path
from types import SimpleNamespace
import json
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe


def select(r,lab_rel,manifest_rel):
    lab=ROOT/lab_rel;manifest=ROOT/manifest_rel;j=json.loads(manifest.read_text())
    p=lab/'install/bin/arc-elf32-run';assert sha(p)==j['aux_fixed_sha256']
    r.experimental_engine=lab
    for p in (p,manifest):r.input_hashes[str(p)]=sha(p)


def main():
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='empty-software-irq-model'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();(r.out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        for name in ('s33_build_gnu_irq_hint.py','s33_verify_gnu_dsp_lab.py'):
            (r.out/name).write_bytes((ROOT/'Python_Trace_Scripts'/name).read_bytes())
        select(r,'work/gnu_arc700_srdelay_fixed_v2','outputs/gnu_arc700_srdelay/build_v2/verified_evidence.json')
        elf=compile_probe(r,'old_read',' lr r0,[0x201]\n mov r0,0\n mov r8,1\n trap_s 1\n')
        case,log=r.run('old_read',f'/result/{elf.name}',trace=True)
        assert case['exit_code']==5 and case['fault'] is None and 'S33_AUX_UNKNOWN index=513' in log
        select(r,'work/gnu_arc700_irq_hint_v1','outputs/gnu_arc700_irq_hint/build_v1/verified_evidence.json')
        for name,rel in [('smoke','tests/smoke-fixed.elf'),('alias','tests/alias.elf')]+[(f'cpu_{i}',f'tests/arc700-suite/test-{i}.elf') for i in range(1,10)]:
            r.input_hashes[str(LEGACY/rel)]=sha(LEGACY/rel)
            case,log=r.run(name,'/work/'+rel)
            assert case['exit_code']==0 and case['fault'] is None and 'runtime error:' not in log
        r.baseline(trace=True)
        tests=[('empty_read','lr r0,[0x201]\n cmp r0,0\n bne fail\n','S33_IRQ_HINT_EMPTY'),
               ('repeat_empty','lr r0,[0x201]\n lr r1,[0x201]\n or r0,r0,r1\n cmp r0,0\n bne fail\n','S33_IRQ_HINT_EMPTY'),
               ('clear_first','mov r0,0\n sr r0,[0x201]\n lr r1,[0x201]\n cmp r1,0\n bne fail\n','S33_IRQ_HINT_CLEAR'),
               ('clear_after_read','lr r1,[0x201]\n mov r0,0\n sr r0,[0x201]\n lr r1,[0x201]\n cmp r1,0\n bne fail\n','S33_IRQ_HINT_CLEAR')]
        for name,code,tag in tests:
            elf=compile_probe(r,name,code+'mov r0,0\n b finish\nfail:\n mov r0,7\nfinish:\n mov r8,1\n trap_s 1\n')
            case,log=r.run(name,f'/result/{elf.name}',trace=True)
            assert case['exit_code']==0 and case['fault'] is None and tag in log and 'runtime error:' not in log,log
            assert log.count('S33_IRQ_HINT_EMPTY')<=1
            case.update(empty_software_irq_source=True,physical_reset_proven=False)
            print('PASS',name,flush=True)
        for value in (1,3,31,32,0xffffffff):
            name=f'guard_request_{value:x}'
            elf=compile_probe(r,name,f'mov r0,{value:#x}\n sr r0,[0x201]\n mov r0,0\n mov r8,1\n trap_s 1\n')
            case,log=r.run(name,f'/result/{elf.name}',trace=True)
            assert case['exit_code']==5 and case['fault'] is None and f'S33_IRQ_HINT_UNSUPPORTED request={value:08x}' in log,log
            assert 'runtime error:' not in log
            case.update(unsupported_request=value,delivery_not_implemented=True)
            print('PASS',name,flush=True)
        r.finish();r.results.update(status='PASS_EMPTY_SOURCE_MODEL',nonzero_irq_delivery_implemented=False,
            model='Fresh emulator without host software IRQ injection or accepted nonzero guest requests',
            limits=['Empty initial source is declared simulator context, not physical reset evidence',
                    'SR0 clear verified only from empty; pending interrupt cancellation needs full delivery model',
                    'Reserved/invalid nonzero writes guarded rather than pretending complete architectural behavior'])
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.results['status'],r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
