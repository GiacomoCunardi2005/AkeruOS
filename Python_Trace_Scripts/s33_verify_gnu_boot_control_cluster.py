#!/usr/bin/env python3
"""Conditional read/write-cell experiment for TBIB controls; not physical MMIO semantics."""
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import re
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
from s33_verify_gnu_boot_device_writes import VALUES

REGS=[0xfe80070,0xfe8009c,0xfe800a8,0xfe800b4,0xfe800bc,0xfe800c0,0xfe800c8,0xfe800cc,
      0xfed2800,0xfed2804,0xfed3000]
POOLS={0x9320:0xfe80070,0x9344:0xfe8009c,0x9364:0xfe800a8,0x9378:0xfe800b4,
       0x9388:0xfe800bc,0x93b4:0xfe800c0,0x93e0:0xfe800c8,0x9414:0xfe800cc,
       0x9418:0xbff8,0x9428:0xfed2800,0x9438:0xfed2804,0x943c:0x2311,
       0x944c:0xfed3000,0x9450:0x5140,0x9460:0xfed3800,0x94a0:0x2c00030,0x12138:0x1040400}
WINDOWS=[(0x9314,0x9320),(0x9324,0x9342),(0x9348,0x9362),(0x9368,0x9376),
         (0x937c,0x9388),(0x938c,0x93b4),(0x93b8,0x93de),(0x93e4,0x9414),
         (0x941c,0x9428),(0x942c,0x9436),(0x9440,0x944c),(0x9454,0x9460),(0x9464,0x94a0),(0x120,0x12c),(0x12104,0x12120),(0x12138,0x1213c)]


def expected(v):
    return {0xfe80070:v&0x4fff,0xfe8009c:v&0xdc7f,0xfe800a8:0,0xfe800b4:0,
            0xfe800bc:0xf300,0xfe800c0:v&0x10ff,0xfe800c8:(v&0xcff)|0xf000,
            0xfe800cc:0xbff8,0xfed2800:0x300,0xfed2804:0x2311,0xfed3000:0}


def cells(r,name,v):
    opts=[];paths={}
    for addr in REGS:
        p=r.out/f'{name}_{addr:08x}.bin'
        data=bytearray(b'\xa5'*8)
        # sim-memopt.c offsets the mapped file buffer by addr % sizeof(unsigned64).
        struct.pack_into('<H',data,addr%8,v);p.write_bytes(data)
        opts+=['--memory-mapfile',f'/result/{p.name}','--memory-region',f'{addr:#x},2']
        paths[addr]=p
    return opts,paths


def check_cells(paths,v):
    for addr,want in expected(v).items():
        data=paths[addr].read_bytes()
        expect=bytearray(b'\xa5'*8);struct.pack_into('<H',expect,addr%8,want)
        assert data==expect,(hex(addr),data.hex(),hex(want))


def engine(r,dsp=False):
    lab=ROOT/('work/gnu_arc700_dsp_lab_v6' if dsp else 'work/gnu_arc700_srdelay_fixed_v2')
    manifest=ROOT/('outputs/gnu_arc700_dsp/build_v6/verified_evidence.json' if dsp else 'outputs/gnu_arc700_srdelay/build_v2/verified_evidence.json')
    build=json.loads(manifest.read_text());binary=lab/'install/bin/arc-elf32-run'
    assert sha(binary)==build['experimental_sha256' if dsp else 'aux_fixed_sha256']
    for p in (manifest,binary):r.input_hashes[str(p)]=sha(p)
    r.experimental_engine=lab


def main():
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='tbib-control-cluster-conditional'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare()
        core=LEGACY/'source/gnu-arc700-sim-src/sim/common/sim-memopt.c'
        r.input_hashes[str(core)]=sha(core)
        assert 'int padding = (addr % sizeof (unsigned64));' in core.read_text()
        assert 'aligned_buffer = (char*) free_buffer + padding;' in core.read_text()
        (r.out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        for name in ('s33_verify_gnu_boot_device_writes.py','s33_verify_gnu_dsp_lab.py'):
            (r.out/name).write_bytes((ROOT/'Python_Trace_Scripts'/name).read_bytes())
        body=(LEGACY/'tests/nikon-tbib/tbib.bin').read_bytes()
        for off,value in POOLS.items():assert struct.unpack_from('<I',body,off)[0]==value,hex(off)
        for i,(a,b) in enumerate(WINDOWS):
            p=r.command(f'gnu_{i:02d}',[TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',
                f'--start-address={0x1000000+a:#x}',f'--stop-address={0x1000000+b:#x}',r.out/'tbib.elf'])
            assert p.returncode==0
        mapped=r.out/'tbib_body_mmap.bin';mapped.write_bytes(body)
        prefix=compile_probe(r,'control_prefix',' mov r0,0\n mov r12,0x1009314\n jl [r12]\n mov r0,9\n mov r8,1\n trap_s 1\n')
        for full in (False,True):
            engine(r,dsp=full)
            for v in (0,0xffff,0xa5a5,0x5a5a):
                name=f'{"boot" if full else "isolated"}_{v:04x}'
                maps,paths=cells(r,name,v)
                # Map files before any memory-fill, preserving their exact initial bytes.
                options=maps
                if full:
                    options+=['--memory-fill','0']
                    for a in ('0xfe800f8','0xfe80064','0xfe80108','0xfe80100'):
                        options+=['--memory-region',a+',2']
                    options+=['--memory-fill','165']
                    for off in VALUES:options+=['--memory-region',f'{0xfe40000+off:#x},2']
                    elf='/result/tbib.elf'
                else:
                    options+=['--memory-mapfile','/result/tbib_body_mmap.bin','--memory-region','0x1000000,0x44bbc']
                    elf=f'/result/{prefix.name}'
                case,log=r.run(name,elf,options,trace=True,extract=True)
                assert case['exit_code']==11 and case['fault']==dict(size=2,operation='read',address='0xfed3800',pc='0x1009464'),log
                assert 'runtime error:' not in log and 'S33_DSP_GUARD' not in log and 'S33_AUX_UNKNOWN' not in log
                check_cells(paths,v)
                trace=(r.out/f'{name}.trace').read_text()
                records=[line for line in trace.splitlines() if re.match(r'^0x[0-9a-f]+ ',line) and 0x1009324<=int(line.split()[0],16)<0x1009464]
                # Actual data read back from first writes remains a laboratory R/W-cell assumption.
                assert sum(bool(re.search(r'\bst\w*\.di\b',line)) for line in records)==18
                assert sum(bool(re.search(r'\bld\w*\.di\b',line)) for line in records)==8
                branch=0x5700 if v&0xc00 else 0x5300
                bc=[line for line in records if line.startswith('0x10093a4 ')]
                assert len(bc)==1 and f'memory <- {branch:#x}' in bc[0],bc
                case.update(initial_halfword=v,conditional_rw_cell_model=True,provisional_dsp=full,
                            original_instructions_preserved=True,physical_device_semantics_proven=False,
                            expected_final_cells={hex(k):x for k,x in expected(v).items()},first_bc_write=branch)
                print('PASS',name,case['instructions'],flush=True)
        # The status is not assumed universally zero. Check both branches,
        # including the nonzero return produced by the zero-status hypothesis.
        for full in (False,True):
            engine(r,dsp=full)
            for status in (0,1):
                name=f'{"boot" if full else "isolated"}_status{status}'
                options,paths=cells(r,name,0xa5a5)
                status_file=r.out/f'{name}_status.bin'
                status_initial=struct.pack('<H',status)+b'\xa5'*6
                status_file.write_bytes(status_initial)
                options+=['--memory-mapfile',f'/result/{status_file.name}','--memory-region','0xfed3800,2']
                if full:
                    options+=['--memory-fill','0']
                    for a in ('0xfe800f8','0xfe80064','0xfe80108','0xfe80100'):
                        options+=['--memory-region',a+',2']
                    options+=['--memory-fill','165']
                    for off in VALUES:options+=['--memory-region',f'{0xfe40000+off:#x},2']
                    elf='/result/tbib.elf'
                else:
                    asm=(' mov r13,0x1313\n mov r14,0x1414\n mov r15,0x1515\n mov r16,0x1616\n'
                         ' mov r20,sp\n mov r0,0\n mov r12,0x1009314\n jl [r12]\n'
                         ' mov r2,0x2c00030\n cmp r0,r2\n bne fail\n cmp sp,r20\n bne fail\n')
                    for reg,val in [(13,0x1313),(14,0x1414),(15,0x1515),(16,0x1616)]:
                        asm+=f' cmp r{reg},{val:#x}\n bne fail\n'
                    asm+=' mov r0,0\n b finish\nfail:\n mov r0,7\nfinish:\n mov r8,1\n trap_s 1\n'
                    elf_path=compile_probe(r,name,asm)
                    options+=['--memory-mapfile','/result/tbib_body_mmap.bin','--memory-region','0x1000000,0x44bbc']
                    elf=f'/result/{elf_path.name}'
                case,log=r.run(name,elf,options,trace=True,extract=True)
                if not full and status==0:
                    assert case['exit_code']==0 and case['fault'] is None,log
                    case.update(expected_return=0x2c00030,sp_and_r13_to_r16_preserved=True)
                else:
                    fault=dict(size=2,operation='read',address='0xfef0020',pc='0x1011f68') if status else dict(size=2,operation='read',address='0xfed2040',pc='0x1003318')
                    assert case['exit_code']==11 and case['fault']==fault,log
                assert 'runtime error:' not in log and 'S33_DSP_GUARD' not in log and 'S33_AUX_UNKNOWN' not in log
                check_cells(paths,0xa5a5);assert status_file.read_bytes()==status_initial
                trace=(r.out/f'{name}.trace').read_text()
                if full and status==0:
                    assert re.search(r'^0x100946c .*cr16 <- 0x2c00030$',trace,re.M)
                    assert re.search(r'^0x1000128 .*0x00000000010030f4',trace,re.M)
                case.update(status_initial_halfword=status,conditional_rw_cell_model=True,provisional_dsp=full,
                            original_instructions_preserved=True,physical_device_semantics_proven=False)
                print('PASS',name,case['instructions'],flush=True)
        assert mapped.read_bytes()==body
        r.finish();r.results.update(status='PASS_CONDITIONAL_MODEL',controlled_registers=[hex(x) for x in REGS],
            pools={hex(0x1000000+k):hex(v) for k,v in POOLS.items()},
            limits=['Initial values are four explicit hypotheses, not physical reset values',
                    'Read-after-write assumes ordinary R/W cells; W1C, side effects, timing and IRQ unmodeled',
                    'DSP mapping inferred on boot cases; isolated cases do not use DSP',
                    'Status0 returns 02C00030; boot ignores immediate return and reaches FED2040',
                    'Status1 enters 01012104/01011FF4 and stops at FEF0020; neither profile is hardware truth',
                    'No boot/UI/photo completeness claim'])
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.results['status'],r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
