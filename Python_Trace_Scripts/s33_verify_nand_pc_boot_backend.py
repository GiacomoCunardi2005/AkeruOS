#!/usr/bin/env python3
"""Execute original Boot backend; erase/program affect a local RAM fixture only."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe, LAB, BUILD
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
sys.path.insert(0,str(ROOT/'coolpix-s33-re'))
from static_common import BS, PS, locate, disasm
from s33_extract import parse_firmware

STATE, SOURCE, FLASH = 0x2010000, 0x4000000, 0x6000000


def main():
    out=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('boot_backend_cpu_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='original-Boot-backend-identical-image-erase-program-RAM-only'));r.prepare()
    try:
        engine=LAB/'install/bin/arc-elf32-run'
        assert sha(engine)==json.loads(BUILD.read_text())['experimental_sha256']
        r.input_hashes.update({str(engine):sha(engine),str(BUILD):sha(BUILD)})
        r.experimental_engine=LAB
        proof=ROOT/json.loads((out.parent/'container_latest.json').read_text())['evidence'];p=json.loads(proof.read_text());artifact=ROOT/p['artifact']
        assert sha(artifact)==p['sha256']=='0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9'
        package=artifact.read_bytes();sections,_=parse_firmware(package);boot=package[sections[0].data_start:sections[0].data_end]
        assert len(boot)==0x48000
        nand=ROOT/'DUMPS/NANDP1.dmp';table=nand.read_bytes()[0x231a:0x240e]
        assert struct.unpack_from('<5H',table,8)==(1,2,3,4,5)
        r.input_hashes.update({str(f):sha(f) for f in [Path(__file__),proof,artifact,nand]})
        images={i:bytearray(PS[i]) for i in (0,1)};shared=[];patches=[]
        def mmap(options,name,address,data):
            path=out/name;path.write_bytes(bytes(address%8)+data)
            options.extend(['--memory-mapfile','/result/'+name,'--memory-region',f'{address:#x},{len(data)}']);return path
        def binary(name,asm):
            elf=compile_probe(r,name,asm);dest=out/(name+'.bin')
            v=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,dest]);assert v.returncode==0,v.stdout
            return dest.read_bytes()
        def stub(address,asm):
            target=0x2030000+len(patches)*0x400;data=binary(f'boundary_{address:x}',asm)
            mmap(shared,f'boundary_{address:x}.bin',target,data+bytes(16))
            entry=binary(f'entry_{address:x}',f' mov_s r12,{target:#x}\n j_s [r12]\n');assert len(entry)==8
            b,o=locate(address,8);patches.append(dict(cpu=hex(address),original=images[b['index']][o:o+8].hex(),laboratory_target=hex(target)))
            images[b['index']][o:o+8]=entry
        common=f' mov r10,{STATE:#x}\n'
        def event(kind,descriptor):
            return common+f''' ld r6,[r10,12]
 asl r7,r6,5
 add r7,r7,128
 add r7,r7,r10
 mov r8,{kind}
 st r8,[r7]
 ldb r8,[{descriptor}]
 st r8,[r7,4]
 ldb r8,[{descriptor},1]
 st r8,[r7,8]
 ldh r8,[{descriptor},2]
 st r8,[r7,12]
 add r6,r6,1
 st r6,[r10,12]
'''
        # Spare reads provide erased/good markers, never old payload bytes.
        stub(0x25f6a4,event(1,'r1')+''' push_s blink
 mov r1,0xff
 mov r2,64
 mov r12,0x13a954
 jl [r12]
 pop_s blink
 mov r0,0
 j_s [blink]
''')
        stub(0x25f28c,' mov r0,0\n j_s [blink]\n')
        stub(0x29ddd4,event(2,'r0')+f''' ld r6,[r10,16]
 add r6,r6,1
 st r6,[r10,16]
 ld r6,[r10,24]
 cmp r6,0
 bne erase_fail
 ldh r0,[r0,2]
 asl r0,r0,17
 add r0,r0,{FLASH:#x}
 push_s blink
 mov r1,0xff
 mov r2,0x20000
 mov r12,0x13a954
 jl [r12]
 pop_s blink
 mov r0,0
 j_s [blink]
erase_fail:
 mov r0,0x2345
 j_s [blink]
''')
        stub(0x2606b4,event(3,'r2')+f''' st r0,[r7,16]
 st r3,[r7,20]
 ld r6,[r10,20]
 add r6,r6,1
 st r6,[r10,20]
 ld r6,[r10,28]
 cmp r6,0
 bne program_fail
 mov r5,r0
 ldh r0,[r2,2]
 asl r0,r0,17
 ldb r6,[r2,1]
 asl r6,r6,11
 add r0,r0,r6
 add r0,r0,{FLASH:#x}
 mov r1,r5
 push_s blink
 mov r2,2048
 mov r12,0xad920
 jl [r12]
 pop_s blink
 mov r0,0
 j_s [blink]
program_fail:
 mov r0,0x3456
 j_s [blink]
''')
        stub(0x260c6c,' mov r0,0\n j_s [blink]\n')
        rows=[]
        for name,different,erase_error,program_error in [('identical_old_boot',False,0,0),('different_old_boot',True,0,0),('erase_failure',False,1,0),('program_failure',False,0,1)]:
            options=list(shared)
            for i,data in images.items():mmap(options,name+f'_main{i}_LAB.bin',BS[i]['load_address_candidate'],data)
            mmap(options,name+'_source.bin',SOURCE,boot)
            mmap(options,name+'_partition.bin',0x50f420,table)
            mmap(options,name+'_geometry.bin',0x50f52c,bytes(32))
            mmap(options,name+'_spare.bin',0x50e940,bytes(128))
            mmap(options,name+'_block_metadata.bin',0x50e9c0,bytes(128))
            old=bytearray(b'\xff'*(6*0x20000));old[0x20000:0x20000+len(boot)]=boot
            if different:old[0x20000:0x20000+len(boot)]=b'\xa7'*len(boot)
            flash=mmap(options,name+'_RAM_NAND.bin',FLASH,old)
            state=bytearray(16384);struct.pack_into('<II',state,24,erase_error,program_error)
            state_path=mmap(options,name+'_state.bin',STATE,state)
            def call(a):return f' mov r12,{a:#x}\n jl [r12]\n'
            asm=f''' mov r20,{STATE:#x}
 st sp,[r20,4]
 mov r10,0x36b264
 mov r0,1
 stb r0,[r10]
 mov r0,0xf0
'''+call(0x25d194)+f''' mov r10,{SOURCE:#x}
 ld r0,[r10]
 ld r1,[r10,4]
 ld r2,[r10,8]
 ld r3,[r10,12]
'''+call(0x1ed9cc)+f''' mov r0,0
 mov r1,{len(boot)//2048}
 mov r2,{SOURCE:#x}
 mov r3,0
'''+call(0x1edfdc)+''' st r0,[r20]
 st sp,[r20,8]
 mov r0,0
 mov r8,1
 trap_s 1
'''
            elf=compile_probe(r,name,asm);case,log=r.run(name,'/result/'+elf.name,options,trace=True)
            assert case['exit_code']==0 and case['fault'] is None,log
            result=state_path.read_bytes();w=struct.unpack_from('<8I',result)
            expected=0x2345 if erase_error else 0x1b0000a if program_error else 0
            assert w[0]==expected and w[1]==w[2],(name,w)
            events=[struct.unpack_from('<6I',result,128+32*i) for i in range(w[3])]
            erases=[e for e in events if e[0]==2];programs=[e for e in events if e[0]==3]
            assert erases and erases[0][1:4]==(0,0,1),(name,events[:6])
            if erase_error:assert len(erases)==1 and not programs
            elif program_error:assert len(erases)==len(programs)==1
            else:
                assert [e[3] for e in erases]==[1,2,3] and len(programs)==144
                assert [(e[3],e[2],e[4],e[5]) for e in programs]==[(1+n//64,n%64,SOURCE+n*2048,0) for n in range(144)]
                wanted=bytearray(b'\xff'*(6*0x20000));wanted[0x20000:0x20000+len(boot)]=boot
                assert flash.read_bytes()==wanted
            rows.append(dict(name=name,status=hex(w[0]),old_payload_identical=not different,erases=[dict(chip=e[1],page=e[2],block=e[3]) for e in erases],
                             programs=len(programs),events=[dict(kind=e[0],chip=e[1],page=e[2],block=e[3],source=hex(e[4]) if e[0]==3 else None,mode=e[5] if e[0]==3 else None) for e in events],
                             stack_preserved=True,trace=str((out/(name+'.trace')).relative_to(ROOT))))
            print('PASS',name,flush=True)
        spans=[(0x1ee9c4,0x1eea4c),(0x1edfdc,0x1ee148),(0x29ddd4,0x29de80),(0x2606b4,0x2607b4)]
        (out/'gnu_verified.txt').write_text('\n'.join(disasm(a,b) for a,b in spans))
        assert all(sha(Path(f))==h for f,h in r.input_hashes.items())
        (out/'laboratory_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ORIGINAL_BOOT_BACKEND_ERASE_PROGRAM_REQUESTS_RAM_ONLY',candidate_sha256=p['sha256'],cases_detail=rows,input_hashes=r.input_hashes,
                         assumptions=['Original1EDFDC Boot backend and P1/G getters/traversal; original25D194 F0 configuration and1ED9CC metadata fields',
                                      'Spare-read/ready/check-result are fixtures; erase/program are RAM operations with original memset/memcpy',
                                      'Six physical-numbered RAM blocks; explicit old Boot identical or A7, remaining bytes FF'],
                         limits=['Not selector1EE730 execution, package UI, later1EE148 metadata/commit, full NAND controller, ECC or physical readback',
                                 'Spare data explicitly FF/good; no bad-block, physical-error redundancy or power-loss recovery proof',
                                 'No camera access, canonical firmware changes or GNU modifications'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');print('PASS',out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));(out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');raise


if __name__=='__main__':main()
