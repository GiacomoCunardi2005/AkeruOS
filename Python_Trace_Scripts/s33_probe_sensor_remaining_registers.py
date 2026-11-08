#!/usr/bin/env python3
"""Exercise two original sensor routines with an explicitly synthetic RAM flag.

0x681145 is read by original code before a conditional MMIO update block. The
caller sets that RAM byte to 1 to inspect this software path; this is not an
observed Nikon state, a firmware patch, or a model of device-side behavior.
"""
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import argparse
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import DefinedRunner,LAB,BUILD,known_sections
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--entries',default='0x6123f8,0x6101ec')
    parser.add_argument('--extra-cells',default='',help='Only cells justified by separately recorded original-code accesses')
    args=parser.parse_args();entries=[int(value,0)for value in args.entries.split(',')]
    extra_cells={int(value,0)for value in args.extra_cells.split(',')if value}
    r=DefinedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,
                                   action='sensor-remaining-registers-explicit-ram-flag'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();build=json.loads(BUILD.read_text())
        (r.out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256']
        r.experimental_engine=LAB
        for p in [BUILD,LAB/'install/bin/arc-elf32-run',Path(__file__)]:r.input_hashes[str(p)]=sha(p)
        blocks,payloads,block_dir=verified_payloads(ROOT);info={b['index']:b for b in blocks}
        firmware=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()
        payload_info={};ranges=[]
        for index in [0,1,2,3,4]:
            data=payloads[index];offset=firmware.find(data)
            assert offset>=0 and firmware.find(data,offset+1)<0
            payload_info[index]=dict(path=str(r.out/f'payload{index}_mmap.bin'),sha256=sha(block_dir/info[index]['file']),
                                     base=info[index]['load_address_candidate'],size=len(data),firmware_offset=offset)
            r.input_hashes[str(block_dir/info[index]['file'])]=sha(block_dir/info[index]['file'])
            ranges.append(f"{info[index]['load_address_candidate']:#x}:{len(data):#x}")
        atlas=ROOT/'Risultati/Processor_Registers/20261024T161825Z/register_map.json'
        addresses=sorted({row['number']for row in json.loads(atlas.read_text())['records']
                          if row['space']=='soc_mmio'and row['subsystem']=='sensor_afe_runtime'}
                         |{0x0ff98118,0x0ff980b4,0x0ff980c4}|extra_cells)
        for entry in entries:
            name=f'sensor_ram_flag1_{entry:08x}';options=[];fixtures={}
            for index,payload in payload_info.items():
                path=Path(payload['path']);path.write_bytes(payloads[index])
                options+=['--memory-mapfile','/result/'+path.name,'--memory-region',f"{payload['base']:#x},{payload['size']:#x}"]
            for i,address in enumerate(addresses):
                path=r.out/f'{name}_{address:08x}.bin';data=bytearray(b'\xa5'*8)
                struct.pack_into('<H',data,address%8,(0x1100+37*i)&0xffff);path.write_bytes(data)
                fixtures[hex(address)]=dict(file=path.name,before=data.hex(),value=struct.unpack_from('<H',data,address%8)[0])
                options+=['--memory-mapfile','/result/'+path.name,'--memory-region',f'{address:#x},2']
            asm=('mov r20,sp\nmov r0,1\nmov r1,0x681145\nstb r0,[r1]\n'
                 'mov r0,0x111\nmov r1,0x222\nmov r2,0x333\nmov r3,0x444\nmov r4,0x555\nmov r5,0x666\n'
                 f'mov r12,{entry:#x}\njl [r12]\ncmp sp,r20\nbne fail\nmov r0,0\nb finish\n'
                 'fail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n')
            elf=compile_probe(r,name,asm);r.range_override=known_sections(elf,False)+','+','.join(ranges)
            case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True)
            for fixture in fixtures.values():fixture['after']=(r.out/fixture['file']).read_bytes().hex()
            case.update(entry=hex(entry),fixtures=fixtures,synthetic_ram_flag=dict(address='0x681145',value=1),
                        original_firmware_instruction_bytes_unchanged=True)
            assert case['exit_code']==0 and case['fault']is None,log[-1800:]
            for index in [0,2,4]:assert Path(payload_info[index]['path']).read_bytes()==payloads[index]
            print(name,'PASS',case['instructions'],flush=True)
        r.results.update(status='PASS_ORIGINAL_SENSOR_WITH_SYNTHETIC_RAM_FLAG',payloads=payload_info,
                         explicit_extra_storage_cells=[hex(a)for a in sorted(extra_cells)],
                         physical_device_semantics_proven=False,
                         limits=['RAM flag and register storage values are explicit synthetic inputs, not hardware observations.',
                                 'Payload1/3 data are mutable laboratory RAM; original source files and all code bytes remain unchanged.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
