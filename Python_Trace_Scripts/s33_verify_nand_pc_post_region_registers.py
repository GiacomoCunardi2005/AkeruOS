#!/usr/bin/env python3
"""Run the post-region register setup with explicit cached revision and RAM-backed MMIO."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
from s33_verify_nand_pc_ram_regions import PS, BS, EXTENSION, OBJECT, TABLE, reference, disasm

STATE, MMIO = 0x2100000, 0xfe60000


def main():
    out=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('post_region_cpu_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='original-post-region-register-setup'))
    r.prepare()
    try:
        r.input_hashes[str(Path(__file__))]=sha(Path(__file__))
        records,_,lowest,_,intervals=reference()
        proof=ROOT/json.loads((out.parent/'container_latest.json').read_text())['evidence']
        candidate=json.loads(proof.read_text());artifact=ROOT/candidate['artifact']
        assert sha(artifact)==candidate['sha256']=='0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9'
        sys.path.insert(0,str(ROOT/'coolpix-s33-re'))
        from s33_extract import parse_firmware
        package=artifact.read_bytes();sections,_=parse_firmware(package)
        tbm=package[sections[1].data_start:sections[1].data_end]
        extension_record=next(b for b in candidate['blocks']if b['index']==17)
        extension_bytes=tbm[extension_record['offset']:extension_record['offset']+extension_record['bytes']]
        assert len(extension_bytes)==EXTENSION[1]-EXTENSION[0]
        r.input_hashes.update({str(p):sha(p)for p in [proof,artifact,ROOT/'Python_Trace_Scripts/s33_verify_nand_pc_ram_regions.py']})
        shared=[]
        def mmap(options,name,address,data):
            p=out/name;p.write_bytes(bytes(address%8)+data)
            options.extend(['--memory-mapfile','/result/'+name,'--memory-region',f'{address:#x},{len(data)}'])
            return p
        def binary(name,source):
            elf=compile_probe(r,name,source);p=out/(name+'.bin')
            v=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p])
            assert v.returncode==0,v.stdout
            return p.read_bytes()
        fixture=binary('configuration_boundary',f''' mov r10,{STATE:#x}
 ld r6,[r10,8]
 asl r7,r6,4
 add r7,r7,r10
 st r0,[r7,32]
 st r1,[r7,36]
 st r2,[r7,40]
 add r6,r6,1
 st r6,[r10,8]
 mov r0,0
 j_s [blink]
''')
        mmap(shared,'configuration_boundary.bin',0x2030000,fixture+bytes(16))
        jump=binary('configuration_jump',' mov_s r12,0x2030000\n j_s [r12]\n');assert len(jump)==8
        main0=bytearray(PS[0]);offset=0x177fa8-BS[0]['load_address_candidate'];old=main0[offset:offset+8].hex();main0[offset:offset+8]=jump
        rows=[]
        for revision in [0,1,2]:
            for extra in [0,1]:
                for fill in [0,0xa5]:
                    name=f'revision_{revision}_extra_{extra}_fill_{fill:02x}'
                    options=list(shared)
                    p0=mmap(options,name+'_main0_LAB.bin',BS[0]['load_address_candidate'],main0)
                    data=bytearray(PS[1]);at=0x423f00-BS[1]['load_address_candidate'];data[at+4]=1;struct.pack_into('<I',data,at+8,revision<<16)
                    p1=mmap(options,name+'_main1.bin',BS[1]['load_address_candidate'],data)
                    state=mmap(options,name+'_state.bin',STATE,bytes(128))
                    mmio=mmap(options,name+'_MMIO_RAM.bin',MMIO,bytes([fill])*0x5000)
                    ext=mmap(options,name+'_extension.bin',EXTENSION[0],b'\xa5'*(EXTENSION[1]-EXTENSION[0]))
                    elf=compile_probe(r,name,f' mov r20,{STATE:#x}\n st sp,[r20,12]\n mov r0,{extra}\n mov r12,0x177488\n jl [r12]\n st r0,[r20]\n st sp,[r20,16]\n mov r0,0\n mov r8,1\n trap_s 1\n')
                    result,log=r.run(name,'/result/'+elf.name,options)
                    assert result['exit_code']==0 and result['fault']is None,log
                    state_data=state.read_bytes();w=struct.unpack_from('<5I',state_data)
                    assert w[0]==0 and w[2]==2+extra and w[3]==w[4]
                    tuples=[struct.unpack_from('<3I',state_data,32+16*i)for i in range(w[2])]
                    assert tuples==[(1,3,12),(1,3,48)]+([(27,3,12)]if extra else[])
                    expected=bytearray(bytes([fill])*0x5000);initial=fill*0x101;writes={}
                    for bank,base in enumerate([0xf794000,0xf798000,0xf7a0000][:2+extra]):
                        if revision==1:
                            writes[0x400+bank*4]=((initial&0xc000)|((base>>14)&0x3fff))&0x7fff
                            writes[0x4f0+bank*4]=initial&0xbf33
                        else:
                            prefix=0x800+bank*0x100;end=base+[0x3800,0x7180,0xd200][bank]
                            writes.update({prefix+0x9c:end>>16,prefix+0x98:end&0xffc0,prefix+0x94:base>>16,prefix+0x90:base&0xffc0})
                            for address in [prefix,prefix+8,prefix+0xc0,[0x4ac0,0x48c0,0x49c0][bank]]:writes[address]=initial&0xfffd
                    for address,value in writes.items():struct.pack_into('<H',expected,address,value)
                    assert mmio.read_bytes()==expected,(name,'register image mismatch')
                    assert p0.read_bytes()==main0 and p1.read_bytes()==data
                    assert ext.read_bytes()==b'\xa5'*(EXTENSION[1]-EXTENSION[0])
                    rows.append(dict(name=name,cached_revision=revision,extra_argument=extra,initial_halfword=hex(initial),status=0,configuration_calls=tuples,expected_register_halfwords={hex(MMIO+a):hex(v)for a,v in writes.items()},all_other_mmio_bytes_preserved=True,images_and_extension_preserved=True,stack_preserved=True))
                    print('PASS',name,flush=True)
        # Join the previously separate region and register stages. Keep the original
        # memset too; only the lower configuration boundary remains replaced.
        integrated=[]
        for revision in [0,1,2]:
            name=f'full_chain_revision_{revision}';options=list(shared)
            mmap(options,name+'_main0_LAB.bin',BS[0]['load_address_candidate'],main0)
            data=bytearray(PS[1]);at=0x423f00-BS[1]['load_address_candidate'];data[at+4]=1;struct.pack_into('<I',data,at+8,revision<<16)
            p1=mmap(options,name+'_main1.bin',BS[1]['load_address_candidate'],data)
            state=mmap(options,name+'_state.bin',STATE,bytes(128))
            obj=mmap(options,name+'_region_object.bin',OBJECT,b'\xa5'*0x500)
            mmio=mmap(options,name+'_MMIO_RAM.bin',MMIO,b'\xa5'*0x5000)
            ext=mmap(options,name+'_candidate_extension.bin',EXTENSION[0],extension_bytes)
            canaries=[(a,b,mmap(options,name+f'_canary_{a:x}.bin',a,b'\xa5'*(b-a)))for a,b in intervals]
            elf=compile_probe(r,name,f' mov r20,{STATE:#x}\n st sp,[r20,12]\n mov r12,0xc768c\n jl [r12]\n mov r12,0xc63d8\n jl [r12]\n st r0,[r20]\n st sp,[r20,16]\n mov r0,0\n mov r8,1\n trap_s 1\n')
            result,log=r.run(name,'/result/'+elf.name,options)
            assert result['exit_code']==0 and result['fault']is None,log
            w=struct.unpack_from('<5I',state.read_bytes());assert w[0]==0 and w[2]==2 and w[3]==w[4]
            wanted=next(row for row in rows if row['cached_revision']==revision and row['extra_argument']==0 and row['initial_halfword']=='0xa5a5')
            expected=bytearray(b'\xa5'*0x5000)
            for address,value in wanted['expected_register_halfwords'].items():struct.pack_into('<H',expected,int(address,16)-MMIO,int(value,16))
            assert mmio.read_bytes()==expected and ext.read_bytes()==extension_bytes
            for n,row in enumerate(records):struct.pack_into('<6I',data,TABLE-BS[1]['load_address_candidate']+24*n,*row)
            data[0x365625-BS[1]['load_address_candidate']]=1
            assert p1.read_bytes()==data
            assert struct.unpack_from('<I',obj.read_bytes(),44)[0]==lowest
            _,_,_,fills,_=reference()
            for start,end,path in canaries:
                expected=bytearray(b'\xa5'*(end-start))
                for address,value,length in fills:
                    left,right=max(start,address),min(end,address+length)
                    if left<right:expected[left-start:right-start]=bytes([value])*(right-left)
                assert path.read_bytes()==expected
            integrated.append(dict(name=name,status=0,cached_revision=revision,all_111_regions_matched=True,original_memset_canaries_matched=True,register_image_matched=True,candidate_extension_bytes_preserved=True,stack_preserved=True))
            print('PASS',name,flush=True)
        windows=[(0x177488,0x1774c8),(0x1f0a6c,0x1f0a90),(0x2696f4,0x269754),(0x269754,0x2697e4),(0x2c57c0,0x2c5894),(0x2c5970,0x2c5b6c)]
        (out/'gnu_verified.txt').write_text('\n'.join(disasm(a,b)for a,b in windows))
        assert all(sha(Path(p))==h for p,h in r.input_hashes.items())
        (out/'register_cases.json').write_text(json.dumps(rows,indent=2)+'\n')
        (out/'integrated_cases.json').write_text(json.dumps(integrated,indent=2)+'\n')
        (out/'laboratory_patches.json').write_text(json.dumps([dict(cpu='0x177fa8',original=old,laboratory_target='0x2030000')],indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ORIGINAL_POST_REGION_REGISTER_SETUP_RAM_MMIO',register_cases=len(rows),integrated_cases=len(integrated),candidate_sha256=candidate['sha256'],input_hashes=r.input_hashes,
                         assumptions=['Original177488/base getter2696F4/revision getter1F0A6C/configurator269754/lower register bodies','Cached423F04/08 explicitly supplied; no hardware revision inferred','Only177FA8 replaced; MMIO is RAM-backed storage with zero/A5 bytes'],
                         limits=['No physical register response, transfer activation, DMA/cache/alias or scheduler proof','No complete boot or handler execution; register destinations do not certify physical memory ownership','No camera, SD/NAND or GNU/source writes'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n')
        (out.parent/'post_region_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
        print('PASS',len(rows),'register cases +',len(integrated),'integrated cases',out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));(out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');raise


if __name__=='__main__':main()
