#!/usr/bin/env python3
"""Check TBIB halfword initialization with storage-only cells, not a Nikon device model."""
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import re
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe

VALUES={4:0x4321,8:0xffff,12:0xffff,16:0xffff,24:0,28:0,32:0,36:0,40:2,44:0x100,48:0,52:0}
POOLS={0x91f0:0xfe40004,0x91f4:0x4321,0x9204:0xfe40008,0x9208:0xffff,
       0x9214:0xfe4000c,0x9220:0xfe40010,0x9230:0xfe40018,0x923c:0xfe4001c,
       0x9248:0xfe40020,0x9254:0xfe40024,0x9264:0xfe40028,0x9274:0xfe4002c,
       0x9280:0xfe40030,0x928c:0xfe40034,0x92c8:0xfe40008,0x9304:0xfe4000c}
WINDOWS=[(0xc18,0xc3a),(0x91e4,0x91f0),(0x91f8,0x9204),(0x920c,0x9214),
         (0x9218,0x9220),(0x9224,0x922e),(0x9234,0x923c),(0x9240,0x9248),
         (0x924c,0x9254),(0x9258,0x9262),(0x9268,0x9274),(0x9278,0x9280),
         (0x9284,0x928c),(0x9290,0x929c),(0x929c,0x92c8),(0x92cc,0x9304),(0x9308,0x9314)]


def main():
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='tbib-device-storage-writes'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare()
        (r.out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        (r.out/'probe_builder_snapshot.py').write_bytes((ROOT/'Python_Trace_Scripts/s33_verify_gnu_dsp_lab.py').read_bytes())
        body=(LEGACY/'tests/nikon-tbib/tbib.bin').read_bytes()
        for off,value in POOLS.items():assert struct.unpack_from('<I',body,off)[0]==value,hex(off)
        # Explicit pcl align-to-four plus byte offsets for these short loads.
        assert (0x10091e8&~3)+8==0x10091f0
        assert (0x10091ea&~3)+12==0x10091f4
        for i,(a,b) in enumerate(WINDOWS):
            p=r.command(f'gnu_{i:02d}',[TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',
                f'--start-address={0x1000000+a:#x}',f'--stop-address={0x1000000+b:#x}',r.out/'tbib.elf'])
            assert p.returncode==0
        mapped=r.out/'tbib_body_mmap.bin';mapped.write_bytes(body)
        lab=ROOT/'work/gnu_arc700_aux_fixed_v2'
        manifest=ROOT/'outputs/gnu_arc700_aux/build_v2/verified_evidence.json'
        build=json.loads(manifest.read_text());assert sha(lab/'install/bin/arc-elf32-run')==build['aux_fixed_sha256']
        r.experimental_engine=lab
        for p in (manifest,lab/'install/bin/arc-elf32-run'):r.input_hashes[str(p)]=sha(p)
        for name,target,fill,wrapper in [('init_zero',0x10091e4,0,False),('init_poison',0x10091e4,0xa5,False),
                                         ('wrapper_poison',0x1000c18,0xa5,True)]:
            expected=dict(VALUES)
            if wrapper:expected.update({8:0x4321,12:0xeca2})
            asm=f' mov r13,0x3333\n mov r20,sp\n mov r12,{target:#x}\n jl [r12]\n cmp r0,0\n bne fail\n cmp r13,0x3333\n bne fail\n cmp sp,r20\n bne fail\n'
            for offset,value in expected.items():
                asm+=f' mov r1,{0xfe40000+offset:#x}\n ldh.di r0,[r1]\n cmp r0,{value:#x}\n bne fail\n'
            asm+=' mov r0,0\n b finish\nfail:\n mov r0,7\nfinish:\n mov r8,1\n trap_s 1\n'
            elf=compile_probe(r,name,asm)
            opts=['--memory-mapfile','/result/tbib_body_mmap.bin','--memory-region','0x1000000,0x44bbc',
                  '--memory-fill',str(fill)]
            for offset in VALUES:opts+=['--memory-region',f'{0xfe40000+offset:#x},2']
            case,log=r.run(name,f'/result/{elf.name}',opts,trace=True,extract=True)
            assert case['exit_code']==0 and case['fault'] is None,log
            assert 'runtime error:' not in log and 'S33_DSP_LAB' not in log
            trace=(r.out/f'{name}.trace').read_text()
            assert '0x10091f8 ' in trace and '0x1009294 ' in trace
            # No MMIO reads occur in the Nikon init/wrapper; verification reads
            # are deliberately added only to the synthetic caller after return.
            guest_records=[line for line in trace.splitlines() if re.match(r'^0x[0-9a-f]+ ',line) and 0x1000000<=int(line.split()[0],16)<0x1044bbc]
            assert not any(re.search(r'\bld\w*\.di\b',line) for line in guest_records)
            assert sum(bool(re.search(r'\bst\w*\.di\b',line)) for line in guest_records)==(14 if wrapper else 12)
            case.update(target=hex(target),initial_cell_byte=fill,expected_cells={hex(0xfe40000+k):v for k,v in expected.items()},
                        guest_mmio_reads_before_return=0,physical_device_effects_proven=False,synthetic_caller=True)
            print('PASS',name,flush=True)
        # Limited boot: only the twelve statically verified write locations are
        # added as storage, initialized to poison rather than read responses.
        dsp=ROOT/'work/gnu_arc700_dsp_lab_v6'
        dsp_manifest=ROOT/'outputs/gnu_arc700_dsp/build_v6/verified_evidence.json'
        dsp_build=json.loads(dsp_manifest.read_text())
        assert sha(dsp/'install/bin/arc-elf32-run')==dsp_build['experimental_sha256']
        for p in (dsp_manifest,dsp/'install/bin/arc-elf32-run'):r.input_hashes[str(p)]=sha(p)
        r.experimental_engine=dsp
        options=['--memory-fill','0']
        for address in ('0xfe800f8','0xfe80064','0xfe80108','0xfe80100'):
            options+=['--memory-region',address+',2']
        options+=['--memory-fill','165']
        for offset in VALUES:options+=['--memory-region',f'{0xfe40000+offset:#x},2']
        case,log=r.run('tbib_after_device_stores','/result/tbib.elf',options,trace=True,extract=True)
        assert case['exit_code']==11 and case['fault']==dict(size=2,operation='read',address='0xfe80070',pc='0x1009324'),log
        assert 'runtime error:' not in log and 'S33_DSP_GUARD' not in log and 'S33_AUX_UNKNOWN' not in log
        trace=(r.out/'tbib_after_device_stores.trace').read_text()
        records=[line for line in trace.splitlines() if re.match(r'^0x[0-9a-f]+ ',line) and 0x10091e4<=int(line.split()[0],16)<0x1009314]
        assert not any(re.search(r'\bld\w*\.di\b',line) for line in records)
        assert sum(bool(re.search(r'\bst\w*\.di\b',line)) for line in records)==14
        case.update(provisional_dsp=True,clock_cells_synthetic_zero=True,device_cells_storage_only=True,
                    initial_device_byte=165,device_writes=14,physical_device_effects_proven=False)
        print('PASS limited boot to FE80070',flush=True)
        assert mapped.read_bytes()==body
        r.results.update(status='PASS_STORAGE_ONLY',pools={hex(0x1000000+k):hex(v) for k,v in POOLS.items()},
                         original_instructions_preserved=True,device_identity_known=False,
                         limits=['Only stores retained; no physical device semantics','No interrupt/DMA or hardware timing modeled',
                                 'No complete boot; verification reads are synthetic caller code'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.results['status'],r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
