#!/usr/bin/env python3
"""Check AUX bounds in the corrected shared bank, including rejection of unknown reads."""
from pathlib import Path
from types import SimpleNamespace
import json
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe

LAB=ROOT/'work/gnu_arc700_aux_fixed_v2'
BUILD=ROOT/'outputs/gnu_arc700_aux/build_v2/verified_evidence.json'


def main():
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='aux-fixed-verification'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();build=json.loads(BUILD.read_text())
        assert sha(LAB/'install/bin/arc-elf32-run')==build['aux_fixed_sha256']
        r.experimental_engine=LAB
        r.input_hashes[str(BUILD)]=sha(BUILD)
        r.input_hashes[str(LAB/'install/bin/arc-elf32-run')]=build['aux_fixed_sha256']
        for name in ('cpu5.h','cpu6.h','cpu7.h'):
            p=LAB/'source/gnu-arc700-sim-src/sim/arc'/name
            assert sha(p)==build['headers'][name]['fixed']
            r.input_hashes[str(p)]=sha(p)
        r.results.update(aux_fixed_sha256=build['aux_fixed_sha256'],dsp_extensions_added=False,
                         aux_capacity=2048,core_instruction_semantics_otherwise_changed=False)
        (r.out/'aux_verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        for name,rel in [('smoke','tests/smoke-fixed.elf'),('alias','tests/alias.elf')]+[(f'cpu_{i}',f'tests/arc700-suite/test-{i}.elf') for i in range(1,10)]:
            r.input_hashes[str(LEGACY/rel)]=sha(LEGACY/rel)
            case,text=r.run(name,'/work/'+rel)
            assert case['exit_code']==0 and case['fault'] is None
            assert 'runtime error:' not in text
        r.baseline(trace=True)
        tests=[('irq_priority_reset','lr r0,[0x200]\n cmp r0,0\n bne fail\n',0,'S33_AUX_ARCH_RESET index=512'),
               ('irq_priority_mask','mov r1,0xffffffff\n sr r1,[0x200]\n lr r0,[0x200]\n cmp r0,0xfffffff8\n bne fail\n',0,'S33_IRQ_PRIORITY value=fffffff8'),
               ('irq_priority_bit','mov r1,8\n sr r1,[0x200]\n lr r0,[0x200]\n cmp r0,8\n bne fail\n mov r1,0\n sr r1,[0x200]\n lr r0,[0x200]\n cmp r0,0\n bne fail\n',0,'S33_IRQ_PRIORITY value=00000008'),
               ('irq_status_reset','lr r0,[0x43]\n cmp r0,0\n bne fail\n',0,'S33_AUX_ARCH_RESET index=67'),
               ('irq_status_w1c','mov r1,3\n sr r1,[0x43]\n lr r0,[0x43]\n cmp r0,0\n bne fail\n mov r1,0\n sr r1,[0x43]\n lr r0,[0x43]\n cmp r0,0\n bne fail\n',0,'S33_IRQ_W1C value=00000003 status=00000000'),
               ('vector_reset','lr r0,[0x94]\n cmp r0,0\n bne fail\n',0,'S33_AUX_LAB_RESET index=148'),
               ('xmac_store','mov r1,0x12345678\n sr r1,[0x45]\n lr r0,[0x45]\n cmp r0,r1\n bne fail\n',0,'S33_AUX_LAB_WRITE index=69'),
               ('last_aux','mov r1,0x89abcdef\n sr r1,[0x7ff]\n lr r0,[0x7ff]\n cmp r0,r1\n bne fail\n',0,'S33_AUX_LAB_WRITE index=2047'),
               ('range_read','lr r0,[0x800]\n',5,'S33_AUX_RANGE index=2048'),
               ('range_write','mov r1,0\n sr r1,[0x800]\n',5,'S33_AUX_RANGE index=2048'),
               ('unknown_read','lr r0,[0x46]\n',5,'S33_AUX_UNKNOWN index=70'),
               ('xmac_unwritten','lr r0,[0x45]\n',5,'S33_AUX_UNKNOWN index=69')]
        for name,code,expected,tag in tests:
            elf=compile_probe(r,name,code+'mov r0,0\n b finish\nfail:\n mov r0,7\nfinish:\n mov r8,1\n trap_s 1\n')
            case,text=r.run(name,f'/result/{elf.name}',trace=True)
            assert case['exit_code']==expected and case['fault'] is None,text
            assert tag in text and 'runtime error:' not in text,text
            case.update(expected_exit=expected,required_diagnostic=tag,ubsan_error=False,
                        test_is_storage_safety_not_physical_aux_semantics=True)
            print('PASS',name,flush=True)
        r.finish();r.results['status']='PASS_AUX_FIXED'
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.results['status'],r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
