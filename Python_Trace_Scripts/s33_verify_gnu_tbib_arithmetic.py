#!/usr/bin/env python3
"""Execute the original TBIB unsigned-division routine with the unmodified GNU engine."""
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import argparse
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--multiply',action='store_true',help='Test original Nikon product helper using the provisional separate DSP model')
    args=ap.parse_args()
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,
                            action='tbib-multiply-provisional' if args.multiply else 'tbib-arithmetic-original'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare()
        if args.multiply:
            lab=ROOT/'work/gnu_arc700_dsp_lab_v6'
            build=ROOT/'outputs/gnu_arc700_dsp/build_v6/verified_evidence.json'
            j=json.loads(build.read_text());assert sha(lab/'install/bin/arc-elf32-run')==j['experimental_sha256']
            r.experimental_engine=lab
            r.input_hashes[str(build)]=sha(build)
            r.input_hashes[str(lab/'install/bin/arc-elf32-run')]=j['experimental_sha256']
            r.results.update(aux_bounds_fixed=True,dsp_model_inferred=True,
                             independent_complete_semantics_proven=False,
                             actual_engine_sha256=j['experimental_sha256'])
        (r.out/'arithmetic_verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        (r.out/'probe_builder_snapshot.py').write_bytes((ROOT/'Python_Trace_Scripts/s33_verify_gnu_dsp_lab.py').read_bytes())
        body=(LEGACY/'tests/nikon-tbib/tbib.bin').read_bytes()
        mapped=r.out/'tbib_body_mmap.bin';mapped.write_bytes(body)
        initial=sha(mapped)
        assert struct.unpack_from('<I',body,0x9ae8)[0]==0x10412c4
        assert struct.unpack_from('<I',body,0x412c4)[0]==12000000
        r.results['software_reference_word']=dict(address='0x010412c4',value=12000000,physical_frequency_proven=False)
        p=r.command('tbib_clock_disasm',[TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',
                    '--start-address=0x1009b60','--stop-address=0x1009bde',r.out/'tbib.elf'])
        assert p.returncode==0
        p=r.command('tbib_arithmetic_disasm',[TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',
                    '--start-address=0x103ecbc','--stop-address=0x103ef20',r.out/'tbib.elf'])
        assert p.returncode==0
        pairs=[(a,b) for a in [0,1,15,12000000,0x7fffffff,0x80000000,0xffffffff]
                     for b in [1,3,16,1024,8192,0x80000000,0xffffffff]]
        if args.multiply:
            # Both MULUDW instructions also evaluate cross products after ROR16.
            pairs=[(a,b) for a,b in pairs if max(x*y for x in [a&65535,a>>16] for y in [b&65535,b>>16])<=0x7fffffff]
        for i,(a,b) in enumerate(pairs):
            q,rem=divmod(a,b);name=f'{"umul" if args.multiply else "udiv"}_{i:02d}'
            target=0x103ecbc if args.multiply else 0x103ede4
            expected=(a*b)&0xffffffff if args.multiply else q
            check_remainder='' if args.multiply else f' mov r2,{rem:#x}\n cmp r1,r2\n bne fail\n'
            asm=(f' mov r0,{a:#x}\n mov r1,{b:#x}\n mov r12,{target:#x}\n jl [r12]\n'
                 f' mov r2,{expected:#x}\n cmp r0,r2\n bne fail\n'+check_remainder+
                 ' mov r0,0\n b finish\nfail:\n mov r0,7\nfinish:\n mov r8,1\n trap_s 1\n')
            elf=compile_probe(r,name,asm)
            case,text=r.run(name,f'/result/{elf.name}',
                ['--memory-mapfile','/result/tbib_body_mmap.bin','--memory-region','0x1000000,0x44bbc'],trace=True)
            assert case['exit_code']==0 and case['fault'] is None,text
            trace=(r.out/f'{name}.trace').read_text()
            assert f'0x{target:x}' in trace and 'runtime error:' not in text
            if args.multiply:
                assert text.count('S33_DSP_LAB pc=')==2 and 'S33_DSP_GUARD' not in text
                case.update(left=a,right=b,expected_product_mod32=expected,
                            original_routine=hex(target),provisional_cpu=True)
            else:
                assert 'S33_DSP_LAB' not in text
                case.update(dividend=a,divisor=b,expected_quotient=q,expected_remainder=rem,
                            original_routine='0x0103ede4',provisional_cpu=False)
            print('PASS',name,hex(a),hex(b),flush=True)
        assert mapped.read_bytes()==body and sha(mapped)==initial
        r.results['multiplication_cases' if args.multiply else 'division_cases']=len(pairs)
        r.results['limits'].append('Product tests validate the conditional model, not physical DSP semantics' if args.multiply else 'Division-by-zero and signed entry 0103edf4 not tested')
        r.finish();r.results['status']='PASS_EXPERIMENT_ONLY' if args.multiply else 'PASS'
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS:',r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
