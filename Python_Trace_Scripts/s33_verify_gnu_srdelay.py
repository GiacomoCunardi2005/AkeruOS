#!/usr/bin/env python3
"""Differential test of a taken delayed branch with a non-control SR in the slot."""
from pathlib import Path
from types import SimpleNamespace
import json
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe


def main():
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='sr-delay-branch-differential'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();(r.out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        for n in ('s33_verify_gnu_dsp_lab.py','s33_build_gnu_srdelay_fixed.py'):
            (r.out/n).write_bytes((ROOT/'Python_Trace_Scripts'/n).read_bytes())
        differences=0
        for fixed,lab_rel,manifest_rel in [(False,'work/gnu_arc700_aux_fixed_v2','outputs/gnu_arc700_aux/build_v2/verified_evidence.json'),
                                          (True,'work/gnu_arc700_srdelay_fixed_v2','outputs/gnu_arc700_srdelay/build_v2/verified_evidence.json')]:
            lab=ROOT/lab_rel;manifest=ROOT/manifest_rel;j=json.loads(manifest.read_text());binary=lab/'install/bin/arc-elf32-run'
            assert sha(binary)==j['aux_fixed_sha256']
            r.experimental_engine=lab
            for p in (manifest,binary):r.input_hashes[str(p)]=sha(p)
            for label,slot in [('nop','nop_s'),('sr67','sr r0,[0x43]'),('sr65','sr r0,[0x41]'),
                               ('sr5','sr r0,[5]'),('sr_reg65','sr r0,[r3]'),('lr67','lr r0,[0x43]'),('store','st r0,[sp]')]:
                for branch,taken in [('beq.d',False),('beq.d',True),('b.d',True)]:
                    name=f'{"fixed" if fixed else "old"}_{label}_{branch[:1]}{int(taken)}'
                    if branch=='b.d':name+='_unconditional'
                    asm=f' mov r0,0\n mov r2,1\n mov r3,0x41\n cmp r0,{0 if taken else 1}\n {branch} yes\n {slot}\n mov r2,9\nyes:\n cmp r2,{1 if taken else 9}\n bne fail\n mov r0,0\n b finish\nfail:\n mov r0,7\nfinish:\n mov r8,1\n trap_s 1\n'
                    elf=compile_probe(r,name,asm);case,log=r.run(name,f'/result/{elf.name}',trace=True,extract=True)
                    defect=label.startswith('sr') and taken
                    expected=0 if fixed or not defect else 7
                    assert case['exit_code']==expected and case['fault'] is None,(name,case,log)
                    assert 'runtime error:' not in log
                    case.update(fixed=fixed,branch=branch,taken=taken,slot=slot,expected_exit=expected,
                                expected_marker=1 if taken else 9,physical_aux_semantics_tested=False)
                    if not fixed and defect:differences+=1
                    print('PASS',name,flush=True)
            if fixed:
                for name,rel in [('smoke','tests/smoke-fixed.elf'),('alias','tests/alias.elf')]+[(f'cpu_{i}',f'tests/arc700-suite/test-{i}.elf') for i in range(1,10)]:
                    r.input_hashes[str(LEGACY/rel)]=sha(LEGACY/rel)
                    case,log=r.run(name,'/work/'+rel)
                    assert case['exit_code']==0 and case['fault'] is None and 'runtime error:' not in log
                r.baseline(trace=True)
        assert differences==8
        r.finish();r.results.update(status='PASS_SR_DELAY_FIX',old_discrepancies=differences,new_discrepancies=0,
            limits=['Three SR addressing formats and ordinary AUX destinations tested',
                    'Special AUX writes that flush scache, alter loops/timers or deliver interrupts remain separate',
                    'Full ISA/interrupt correctness and hardware firmware boot not established'])
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.results['status'],r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
