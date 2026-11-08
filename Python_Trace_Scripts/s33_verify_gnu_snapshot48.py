#!/usr/bin/env python3
"""Verify the original 48-bit reader and continue Main with explicit static MMIO inputs; GNU trees stay read-only."""
from pathlib import Path
from types import SimpleNamespace
import json
import re
import shutil
import struct
import sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import DefinedRunner,known_sections,LAB,BUILD,MAIN
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import PS,u32,disasm

CONTROL=0xfed2018
PARTS=(0xfed2024,0xfed2020,0xfed201c)


def cells(r,name,control,parts):
    options=[];paths={}
    for address,value in [(CONTROL,control),*zip(PARTS,parts)]:
        path=r.out/f'{name}_{address:08x}.bin'
        data=bytearray(b'\xa5'*8);struct.pack_into('<H',data,address%8,value);path.write_bytes(data)
        options+=['--memory-mapfile',f'/result/{path.name}','--memory-region',f'{address:#x},2']
        paths[address]=path
    return options,paths


def check_cells(paths,control,parts):
    for address,value in [(CONTROL,control&0xfffe),*zip(PARTS,parts)]:
        expected=bytearray(b'\xa5'*8);struct.pack_into('<H',expected,address%8,value)
        assert paths[address].read_bytes()==expected,(hex(address),paths[address].read_bytes().hex())


def main():
    r=DefinedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='main-snapshot48-conditional'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();build=json.loads(BUILD.read_text());engine=LAB/'install/bin/arc-elf32-run'
        assert sha(engine)==build['engine_sha256'];r.experimental_engine=LAB
        for path in (BUILD,engine,ROOT/'Python_Trace_Scripts/s33_verify_gnu_defined_memory.py',ROOT/'Python_Trace_Scripts/s33_verify_gnu_dsp_lab.py'):
            r.input_hashes[str(path)]=sha(path)
        (r.out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        pools={0x169a80:CONTROL,0x169a94:PARTS[0],0x169aa4:PARTS[1],0x169ab4:PARTS[2]}
        for address,value in pools.items():assert u32(address)==value
        windows=[(0x169a74,0x169a80),(0x169a84,0x169a94),(0x169a98,0x169aa4),(0x169aa8,0x169ab4),
            (0x169ab8,0x169ae8),(0x334e9c,0x334ec4),(0x138be4,0x138c02)]
        (r.out/'gnu_verified.txt').write_text('\n'.join(disasm(a,b) for a,b in windows))
        main_map=r.out/'main_mmap.bin';main_map.write_bytes(PS[0]);original_main_hash=sha(main_map)
        # Verify the simulator budget on a synthetic loop before relying on it for boot.
        loop=compile_probe(r,'budget_check','again:\n b again\n')
        case,log=r.run('budget_check',f'/result/{loop.name}',['--watch-cycles-breakpoint','1000'],trace=True,ram='128-zero')
        assert case['exit_code']==2 and case['fault'] is None and 900<=case['instructions']<=1200,log
        assert 'S33_UNDEFINED' not in log and 'runtime error:' not in log
        triples=[(0,0,0),(1,0x2345,0x6789),(0xffff,0xffff,0xffff),(0x8000,0,0),
                 (0,0x8000,0),(0,0,0x8000),(0xffff,1,0),(0,0xffff,0xffff)]
        for index,parts in enumerate(triples):
            high,middle,low=parts;value=(high<<32)|(middle<<16)|low
            source=' mov r20,sp\n'+''.join(f' mov r{reg},{0xd000+reg:#x}\n' for reg in range(13,18))
            source+=' mov r12,0x169a74\n jl [r12]\n'
            source+=f' mov r2,{value&0xffffffff:#x}\n cmp r0,r2\n bne fail\n cmp r1,{high:#x}\n bne fail\n cmp sp,r20\n bne fail\n'
            source+=''.join(f' cmp r{reg},{0xd000+reg:#x}\n bne fail\n' for reg in range(13,18))
            source+=' mov r0,0\n b finish\nfail:\n mov r0,7\nfinish:\n mov r8,1\n trap_s 1\n'
            elf=compile_probe(r,f'snapshot_probe_{index}',source)
            for control in (0,1,0xa5a5,0xffff):
                name=f'snapshot_{index}_{control:04x}';options,paths=cells(r,name,control,parts)
                options+=['--memory-mapfile','/result/main_mmap.bin','--memory-region','0xad800,0x2ae400']
                r.range_override=known_sections(elf,False)+',0xad800:0x2ae400'
                case,log=r.run(name,f'/result/{elf.name}',options,trace=True,ram='128-zero')
                assert case['exit_code']==0 and case['fault'] is None and 'runtime error:' not in log and 'S33_UNDEFINED' not in log,log
                trace=(r.out/(name+'.trace')).read_text()
                target=[line for line in trace.splitlines() if re.match(r'^0x[0-9a-f]+ ',line) and 0x169a74<=int(line.split()[0],16)<0x169ae8]
                assert sum(bool(re.search(r'\bld[w|h]\.di\b',line)) for line in target)==5
                writes=[line for line in target if re.search(r'\bst[w|h]\.di\b',line)]
                assert len(writes)==2 and f'memory <- {control|1:#x}' in writes[0] and f'memory <- {control&0xfffe:#x}' in writes[1],writes
                check_cells(paths,control,parts);assert sha(main_map)==original_main_hash
                case.update(snapshot_parts=list(parts),expected_value_48bit=hex(value),control_initial=control,control_final=control&0xfffe,
                    r13_to_r17_and_sp_preserved=True,reads=5,writes=2,static_mmio_model=True)
            print('PASS isolated triplet',index,flush=True)
        del r.range_override
        source=json.loads((MAIN/'verified_evidence.json').read_text());assert sha(MAIN/'main.elf')==source['files']['main.elf']
        shutil.copyfile(MAIN/'main.elf',r.out/'main.elf')
        for name,parts in [('main_snapshot_zero',(0,0,0)),('main_snapshot_nonzero',(0x1234,0x5678,0x9abc))]:
            options,paths=cells(r,name,0xa5a5,parts)
            options+=['--memory-fill','0']
            for address in ('0xfe800f8','0xfe80064','0xfe80108','0xfe80100'):options+=['--memory-region',address+',2']
            options+=['--watch-cycles-breakpoint','800000']
            case,log=r.run(name,'/result/main.elf',options,trace=True,ram='128-zero')
            assert 'runtime error:' not in log and 'S33_UNDEFINED' not in log and 'S33_DSP_GUARD' not in log,log
            assert case['exit_code'] in (2,5,11),log
            check_cells(paths,0xa5a5,parts)
            trace=(r.out/(name+'.trace')).read_text();assert '0x169ae4 ' in trace
            case.update(snapshot_parts=list(parts),static_mmio_model=True,budget_stop=case['exit_code']==2,
                unsupported_aux=[line for line in log.splitlines() if line.startswith('S33_AUX_UNKNOWN')])
            print('BOOT',name,case['instructions'],case['fault'],case['exit_code'],flush=True)
        r.results.update(status='PASS_CONDITIONAL_SNAPSHOT48',isolated_cases=32,boot_cases=2,budget_probe_cases=1,
            pools={hex(k):hex(v) for k,v in pools.items()},gnu_windows=len(windows),gnu_trees_written=False,
            limits=['Static R/W control and fixed 48-bit value are laboratory assumptions, not a measured timer',
                'No latch semantics, W1C behavior, peripheral time advance, rollover or interrupt-driven device model',
                'Existing DSPv7 provisional and CPU/AUX lab contexts retained; RAM guard covers selected CGEN paths',
                'A budget stop is not proof of a Nikon hang; full boot/UI/photo/SD and recovery remain unverified'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.results['status'],r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
