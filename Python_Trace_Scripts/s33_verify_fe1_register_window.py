#!/usr/bin/env python3
"""Execute original FE1 writers with tagged arguments and storage-only MMIO.

No device name, DMA behavior, physical register layout or asynchronous core
extension state is inferred from this isolated execution.
"""
from pathlib import Path
from types import SimpleNamespace
import json
import struct
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import DefinedRunner,LAB,BUILD,known_sections
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads,run


def main():
    r=DefinedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,
                                   action='fe1-original-register-window-writers'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256']
        r.experimental_engine=LAB
        for path in [BUILD,LAB/'install/bin/arc-elf32-run',Path(__file__)]:r.input_hashes[str(path)]=sha(path)
        (r.out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        blocks,payloads,bd=verified_payloads(ROOT);info={b['index']:b for b in blocks};main=info[0]
        body=payloads[0];firmware=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=firmware.find(body)
        assert offset>=0 and firmware.find(body,offset+1)<0
        path=r.out/'payload0_mmap.bin';path.write_bytes(body);r.input_hashes[str(bd/main['file'])]=sha(bd/main['file'])
        bank_offsets=[0,4,8,12,16,20,24,28,32,36,40,60]
        addresses=[0xfe10000,0xfe10004]+[base+off for base in [0xfe10040,0xfe10080]for off in bank_offsets]
        cases=[('init',0x2931f0,None,None),('bank80_mode4',0x293210,0xfe10080,0x14),
               ('bank80_mode8',0x2932b0,0xfe10080,0x18),('bank40_mode4',0x2933bc,0xfe10040,0x14),
               ('core46_pack',0x293350,None,None),('custom_address_pack',0x2931bc,None,None)]
        for name,entry,base,control in cases:
            args=[0x1234abcd,0x1234,0x2345,0x3456,0x4567,0x5678,0x6789,0x789a,0x89ab]
            if name=='custom_address_pack':args[:2]=[0x01000240,0x01000100]
            options=['--memory-mapfile','/result/payload0_mmap.bin','--memory-region',f"{main['load_address_candidate']:#x},{len(body):#x}"]
            fixtures={};expected={}
            for i,address in enumerate(addresses):
                cell=r.out/f'{name}_{address:08x}.bin';raw=bytearray(b'\xa5'*8)
                struct.pack_into('<H',raw,address%8,0x4100+37*i);cell.write_bytes(raw)
                fixtures[hex(address)]=dict(file=cell.name,before=raw.hex(),value=0x4100+37*i)
                expected[address]=0x4100+37*i
                options+=['--memory-mapfile','/result/'+cell.name,'--memory-region',f'{address:#x},2']
            if name=='init':expected.update({0xfe10000:1,0xfe10004:0x1405})
            if base is not None:
                expected.update({base:0,base+4:args[0]&0xffff,base+8:(args[0]>>16)&0xfff,
                                 base+32:args[1],base+40:args[2],base+20:args[3],base+12:args[4],
                                 base+16:args[5],base+24:args[6],base+28:args[7],base+36:args[8],base+60:control})
            setup='mov r20,sp\nmov r13,0x1337\nmov r8,0x89ab\nst.a r8,[sp,-4]\n'
            if name=='custom_address_pack':
                setup+='mov r0,0x1000000\nsr r0,[0x18]\nmov r55,0x55667788\n'
            setup+=''.join(f'mov r{i},{value:#x}\n'for i,value in enumerate(args[:8]))
            asm=setup+f'mov r12,{entry:#x}\njl [r12]\nadd sp,sp,4\ncmp sp,r20\nbne fail\ncmp r13,0x1337\nbne fail\n'
            if name=='custom_address_pack':
                asm+='cmp r51,0xe0400240\nbne fail\ncmp r59,0xeb8bd\nbne fail\ncmp r0,0x55667788\nbne fail\n'
            packed=None
            if name=='core46_pack':
                packed=((args[0]&0xfff)>>2)|0x8000|(((((args[1]&0x1ff)>>1)|((args[2]&0x1f)<<8)))<<16)|0x80000000
                asm+=f'cmp r46,{packed:#x}\nbne fail\n'
            asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n'
            elf=compile_probe(r,name,asm);r.range_override=known_sections(elf,False)+f",{main['load_address_candidate']:#x}:{len(body):#x}"
            case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True)
            case.update(entry=hex(entry),fixtures=fixtures,arguments=[hex(v)for v in args],
                        expected_cells={hex(a):v for a,v in expected.items()},core46_expected=hex(packed)if packed is not None else None)
            if name=='custom_address_pack':
                case.update(synthetic_aux18_initial=0x1000000,synthetic_core55_initial=0x55667788,
                            expected_core51=0xe0400240,expected_core59=0xeb8bd,
                            actual_hardware_operation_tested=False)
            assert case['exit_code']==0 and case['fault']is None,log[-2000:]
            for address in addresses:
                fixture=fixtures[hex(address)];after=(r.out/fixture['file']).read_bytes();before=bytes.fromhex(fixture['before']);fixture['after']=after.hex()
                assert struct.unpack_from('<H',after,address%8)[0]==expected[address],(name,hex(address))
                assert all(after[i]==before[i]for i in range(8)if i not in [address%8,address%8+1])
            assert path.read_bytes()==body
            print(name,'PASS',case['instructions'],flush=True)
        objcopy=TOOLCHAIN/'arc-elf32-objcopy';r.input_hashes[str(objcopy)]=sha(objcopy)
        source_elf=r.out/'main_source.elf';roundtrip=r.out/'source_roundtrip.bin'
        run([objcopy,'-I','binary','-O','elf32-littlearc','-B','arc',
             '--rename-section','.data=.text,alloc,load,readonly,code,contents',
             '--change-section-vma',f".data={main['load_address_candidate']:#x}",path,source_elf])
        run([objcopy,'--dump-section','.text='+str(roundtrip),source_elf]);assert roundtrip.read_bytes()==body
        windows=[]
        for name,start,end in [('init',0x2931f0,0x293210),('bank80_mode4',0x293210,0x2932b0),
                               ('bank80_mode8',0x2932b0,0x293350),('bank40',0x2933bc,0x29345c),('core46',0x293350,0x293390),
                               ('custom_address_pack',0x2931bc,0x2931f0)]:
            text=run([TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',f'--start-address={start:#x}',f'--stop-address={end:#x}',source_elf])
            assert '.word'not in text and 'out of bounds'not in text.lower()
            (r.out/(name+'_source_disassembly.txt')).write_text(text)
            windows.append(dict(name=name,start=hex(start),end=hex(end),sha256=sha(r.out/(name+'_source_disassembly.txt'))))
        r.results.update(status='PASS_FE1_STORAGE_WRITERS_AND_CORE46_PACK',
                         payloads={'0':dict(path=str(path),base=main['load_address_candidate'],size=len(body),firmware_offset=offset,sha256=sha(path))},
                         addresses=[hex(a)for a in addresses],physical_semantics_proven=False,
                         aligned_source_windows=windows,
                         limits=['Isolated synthetic caller; global runtime reachability not proved.',
                                 'MMIO has plain storage semantics; no transfer/DMA/IRQ completion modeled.',
                                 'R46 read/write is an emulated core slot; physical extension semantics unknown.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
