#!/usr/bin/env python3
"""Verify byte-level read-before-write detection and run the two existing boot prefixes."""
from pathlib import Path
from types import SimpleNamespace
import json
import shutil
import struct
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha, elf_loads
from s33_verify_gnu_dsp_lab import compile_probe

LAB=ROOT/'work/gnu_arc700_defined_memory_v2'
BUILD=ROOT/'outputs/gnu_arc700_defined_memory/build_v2/verified_evidence.json'
MAIN=ROOT/'outputs/gnu_arc700/20261020T115305Z_b0bb8232'


def known_sections(path, c_abi):
    data=path.read_bytes();header=struct.unpack_from('<16sHHIIIIIHHHHHH',data)
    assert data[:7]==b'\x7fELF\x01\x01\x01' and header[11]==40
    _,segments=elf_loads(path);assert all(s['physical']==s['address'] for s in segments)
    ranges=[]
    for index in range(header[12]):
        _,kind,flags,address,offset,size,*_=struct.unpack_from('<10I',data,header[6]+index*header[11])
        if not flags&2 or not size or kind==8 and not c_abi:continue
        if kind!=8:
            assert offset+size<=len(data)
            assert any(s['address']<=address and address+size<=s['address']+s['file_size'] and
                s['data'][address-s['address']:address-s['address']+size]==data[offset:offset+size] for s in segments)
        ranges.append(f'{address:#x}:{size:#x}')
    assert ranges
    return ','.join(ranges)


class DefinedRunner(Runner):
    def command(self,name,cmd,timeout=30):
        if list(cmd[:2])==['podman','run']:
            cmd=list(cmd[:2])+['--env','S33_DEFINED_RANGES='+self.known_ranges]+list(cmd[2:])
        return super().command(name,cmd,timeout)

    def run(self,name,elf,options=(),**kwargs):
        path=self.out/elf.removeprefix('/result/') if elf.startswith('/result/') else LEGACY/elf.removeprefix('/work/')
        c_abi=getattr(self,'c_abi_nobits',False)
        self.known_ranges=known_sections(path,c_abi)
        if hasattr(self,'range_override'):self.known_ranges=self.range_override
        self.results.setdefault('initial_known_ranges',{})[name]=self.known_ranges
        return super().run(name,elf,options,**kwargs)


def main():
    r=DefinedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='defined-memory-verification'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256']
        r.experimental_engine=LAB
        for path in (BUILD,LAB/'install/bin/arc-elf32-run',ROOT/'S33-sections/analysis_codex/s33_gnu_defined_memory.c'):
            r.input_hashes[str(path)]=sha(path)
        (r.out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        success='mov r0,0\n mov r8,1\n trap_s 1\n'
        tests=[('unknown_byte','ldb r1,[r2]\n',5,'first=07000000 operation=data_read'),
               ('unknown_half','ldw r1,[r2]\n',5,'size=2 first=07000000 operation=data_read'),
               ('unknown_word','ld r1,[r2]\n',5,'size=4 first=07000000 operation=data_read'),
               ('partial_byte','mov r1,0\n stb r1,[r2]\n ld r1,[r2]\n',5,'size=4 first=07000001 operation=data_read'),
               ('partial_half','mov r1,0\n stw r1,[r2]\n ld r1,[r2]\n',5,'size=4 first=07000002 operation=data_read'),
               ('byte_store_read','mov r1,0\n stb r1,[r2]\n ldb r1,[r2]\n',0,None),
               ('half_store_read','mov r1,0\n stw r1,[r2]\n ldw r1,[r2]\n',0,None),
               ('word_store_read','mov r1,0x12345678\n st r1,[r2]\n ld r3,[r2]\n cmp r1,r3\n bne fail\n',0,None),
               ('elf_header_not_loaded','mov r2,0x800\n ld r1,[r2]\n',5,'first=00000800 operation=data_read'),
               ('nobits_stack_unwritten','ld r1,[sp,-4]\n',5,'operation=data_read'),
               ('fetch_unknown','j [r2]\n',5,'operation=decoder_fetch')]
        for name,code,expected,tag in tests:
            elf=compile_probe(r,name,'mov r2,0x07000000\n'+code+success+'fail:\nmov r0,7\nmov r8,1\ntrap_s 1\n')
            case,log=r.run(name,f'/result/{elf.name}',trace=True,ram='128-zero')
            assert case['exit_code']==expected and 'runtime error:' not in log,log
            assert 'S33_PROVENANCE bank_bytes=134217728' in log
            if tag:assert 'S33_UNDEFINED' in log and tag in log,log
            else:assert 'S33_UNDEFINED' not in log,log
            print('PASS',name,flush=True)
        for index,spec in enumerate(('', '0:0', '0x8000000:1', '0x1000:4,', '-1:4')):
            r.range_override=spec
            elf=compile_probe(r,'bad_config_'+str(index),success)
            case,log=r.run('bad_config_'+str(index),f'/result/{elf.name}',ram='128-zero')
            assert case['exit_code']==5 and 'S33_PROVENANCE_CONFIG' in log and 'bad long jump' not in log,log
        del r.range_override
        for name,rel in [('smoke','tests/smoke-fixed.elf'),('alias','tests/alias.elf')]+[(f'cpu_{i}',f'tests/arc700-suite/test-{i}.elf') for i in range(1,10)]:
            r.c_abi_nobits=True  # C regression ABI explicitly supplies zeroed BSS; firmware profiles do not.
            case,log=r.run(name,'/work/'+rel,ram='128-zero')
            assert case['exit_code']==0 and 'S33_UNDEFINED' not in log and 'runtime error:' not in log,log
        r.c_abi_nobits=False
        r.baseline(trace=True,ram='128-zero')
        source=json.loads((MAIN/'verified_evidence.json').read_text())
        assert sha(MAIN/'main.elf')==source['files']['main.elf']
        shutil.copyfile(MAIN/'main.elf',r.out/'main.elf')
        options=['--memory-fill','0']
        for address in ('0xfe800f8','0xfe80064','0xfe80108','0xfe80100'):options+=['--memory-region',address+',2']
        case,log=r.run('main_strict','/result/main.elf',options,trace=True,ram='128-zero')
        assert case['exit_code']==11 and case['instructions']==583306 and case['fault']==source['cases'][0]['fault'],log
        assert 'runtime error:' not in log and 'S33_UNDEFINED' not in log,log
        assert sha(r.out/'main_strict.trace')==source['files']['main_boot.trace']
        r.results.update(status='PASS_TRACKER_TESTS',bank_bytes=128*1024*1024,
            elf_allocated_file_sections_declared=True,firmware_NOBITS_and_host_stack_setup_declared=False,
            c_regression_tests_only_explicit_zero_NOBITS=True,
            boot_main_case=case,boot_main_undefined=[line for line in log.splitlines() if line.startswith('S33_UNDEFINED')],
            limits=['Only CGEN data read/store and decoder-fetch paths hooked; no DMA or all host callbacks',
                'Decoder fetch may include lookahead; not an executed-instruction oracle',
                'Core/AUX register initial zeros, MMIO outside bank and provisional DSP remain separate limits',
                'Declared ELF file bytes are lab inputs, not evidence of reset/loading chain',
                'Single CPU/process, no physical memory geometry or complete boot/recovery'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.results['status'],r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
