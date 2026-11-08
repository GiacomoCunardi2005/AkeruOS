#!/usr/bin/env python3
"""Execute Main update/retry/readback against RAM-backed NAND boundaries only."""
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
import json,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe,LAB,BUILD
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
sys.path.insert(0,str(ROOT/'coolpix-s33-re'))
from static_common import BS,PS,raw,locate,disasm
from s33_extract import parse_firmware

PACKAGE,STATE,FLASH,READBACK=0x4000000,0x2010000,0x6000000,0x8000000


def main():
    out=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('main_update_cpu_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='Main-update-write-readback-compare-retry-RAM-model'));r.prepare()
    try:
        proof=ROOT/json.loads((out.parent/'container_latest.json').read_text())['evidence'];p=json.loads(proof.read_text());artifact=ROOT/p['artifact'];assert sha(artifact)==p['sha256']
        package=artifact.read_bytes();sections,_=parse_firmware(package);tbm=sections[1];source=PACKAGE+tbm.data_start;length=tbm.data_length;tbm_bytes=package[tbm.data_start:tbm.data_end]
        nand_path=ROOT/'DUMPS/NANDP1.dmp';table=nand_path.read_bytes()[0x231a:0x240e];assert struct.unpack_from('<H',table,0xd0)[0]==165 and struct.unpack_from('<H',table,0xde)[0]==147
        r.input_hashes.update({str(f):sha(f)for f in [proof,artifact,nand_path,BUILD,Path(__file__)]})
        engine=LAB/'install/bin/arc-elf32-run';assert sha(engine)==json.loads(BUILD.read_text())['experimental_sha256'];r.input_hashes[str(engine)]=sha(engine);r.experimental_engine=LAB
        command=r.command
        def bounded_command(name,args,timeout=30):
            args=list(args)
            if name.startswith('update_')and'10s'in args:args[args.index('10s')]='45s';timeout=55
            return command(name,args,timeout=timeout)
        r.command=bounded_command
        common=f' mov r10,{STATE:#x}\n'
        images={i:bytearray(PS[i])for i in (0,1)};shared=[];patches=[]
        def mmap(maps,name,address,data):
            path=out/name;path.write_bytes(bytes(address%8)+data);maps.extend(['--memory-mapfile','/result/'+name,'--memory-region',f'{address:#x},{len(data)}']);return path
        def binary(name,asm):
            elf=compile_probe(r,name,asm);path=out/(name+'.bin');v=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path]);assert v.returncode==0,v.stdout;return path.read_bytes()
        def stub(address,asm):
            target=0x2030000+len(patches)*0x400;data=binary(f'boundary_{address:x}',asm);mmap(shared,f'boundary_{address:x}.bin',target,data+bytes(16))
            entry=binary(f'entry_{address:x}',f' mov_s r12,{target:#x}\n j_s [r12]\n');assert len(entry)==8
            b,o=locate(address,8);before=images[b['index']][o:o+8];images[b['index']][o:o+8]=entry;patches.append(dict(cpu=hex(address),original=before.hex(),boundary=hex(target)))
        def counter(offset):return common+f' ld r5,[r10,{offset}]\n add r5,r5,1\n st r5,[r10,{offset}]\n'
        for address,offset in [(0x1593ac,32),(0x1594a4,36),(0x17faf8,28)]:stub(address,counter(offset)+' mov r0,0\n j_s [blink]\n')
        # State: status/SP0..8; tail/core/partial/aligned/flush/lock/unlock/count;
        # +44 mismatch offset, +48/52/56/60 budgets; callback values+128.
        stub(0x1ed11c,counter(20)+f''' st r3,[r4]
 st r0,[r10,112]
 st r2,[r10,116]
 st r3,[r10,120]
 push_s blink
 mov r0,r1
 asl r1,r2,11
 add r1,r1,{FLASH:#x}
 asl r2,r3,11
 mov r12,0x100abc0
 jl [r12]
 pop_s blink
 mov r0,0
 j_s [blink]
''')
        stub(0x1eded8,common+f''' cmp r1,1
 bne core_write
 ld r5,[r10,12]
 add r5,r5,1
 st r5,[r10,12]
 ld r6,[r10,52]
 mov r7,52
 b record_write
core_write:
 ld r5,[r10,16]
 add r5,r5,1
 st r5,[r10,16]
 ld r6,[r10,56]
 mov r7,56
record_write:
 ld r5,[r10,12]
 ld r8,[r10,16]
 add r5,r5,r8
 sub r5,r5,1
 asl r5,r5,4
 add r5,r5,512
 add r5,r5,r10
 st r0,[r5]
 st r1,[r5,4]
 st r2,[r5,8]
 st r3,[r5,12]
 cmp r6,0
 beq commit_write
 sub r6,r6,1
 add r7,r7,r10
 st r6,[r7]
 mov r0,0x2345
 j_s [blink]
commit_write:
 push_s blink
 sub r0,r0,10560
 asl r0,r0,11
 add r0,r0,{FLASH:#x}
 mov r3,r2
 asl r2,r1,11
 mov r1,r3
 mov r12,0x100abc0
 jl [r12]
 pop_s blink
 mov r0,0
 j_s [blink]
''')
        stub(0x1ecd14,counter(24)+f''' st r0,[r10,96]
 st r1,[r10,100]
 st r2,[r10,104]
 st r3,[r10,108]
 ld r5,[r10,60]
 cmp r5,0
 beq perform_readback
 sub r5,r5,1
 st r5,[r10,60]
 mov r0,0x3456
 j_s [blink]
perform_readback:
 push_s blink
 sub r0,r0,10560
 asl r3,r0,11
 add r3,r3,{FLASH:#x}
 mov r0,r2
 asl r2,r1,11
 mov r1,r3
 mov r12,0x100abc0
 jl [r12]
 mov r10,{STATE:#x}
 ld r5,[r10,48]
 cmp r5,0
 beq readback_done
 sub r5,r5,1
 st r5,[r10,48]
 ld r5,[r10,44]
 add r5,r5,{READBACK:#x}
 ldb r6,[r5]
 xor r6,r6,1
 stb r6,[r5]
readback_done:
 pop_s blink
 mov r0,0
 j_s [blink]
''')
        callback=0x2034000;code=binary('progress',counter(40)+' add r6,r10,128\n sub r5,r5,1\n asl r5,r5,2\n add r6,r6,r5\n st r0,[r6]\n mov r0,0\n j_s [blink]\n');mmap(shared,'progress.bin',callback,code+bytes(16))
        for i,data in images.items():mmap(shared,f'block{i}_LAB_IO.bin',BS[i]['load_address_candidate'],data)
        mmap(shared,'partition.bin',0x50f420,table);mmap(shared,'geometry.bin',0x50f52c,bytes(32));mmap(shared,'page.bin',0x511f00,bytes(2048))
        original=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();mmap(shared,'TBIB_memcpy.bin',0x1000000,original[0x7c:0x44c38])
        # Counters and expected events are derived from original first-attempt-only callbacks.
        cases=[dict(name='valid',tail=1,core=1,reads=1,events=[4,5,6]),dict(name='no_callback',tail=1,core=1,reads=1,events=[]),dict(name='tail_fail_all',tail_budget=3,tail=3,core=0,reads=0,events=[4],error=True),dict(name='tail_fail_once',tail_budget=1,tail=2,core=1,reads=1,events=[4]),dict(name='core_fail_all',core_budget=3,tail=3,core=3,reads=0,events=[4],error=True),dict(name='read_fail_all',read_budget=3,tail=3,core=3,reads=3,events=[4,5],error=True),dict(name='read_fail_once',read_budget=1,tail=2,core=2,reads=2,events=[4,5]),dict(name='mismatch_first_all',mismatch_budget=3,tail=3,core=3,reads=3,events=[4,5,6],error=True),dict(name='mismatch_first_once',mismatch_budget=1,tail=2,core=2,reads=2,events=[4,5,6]),dict(name='mismatch_last_once',mismatch_budget=1,mismatch_offset=length-1,tail=2,core=2,reads=2,events=[4,5,6]),dict(name='bad_magic',bad_magic=True,tail=0,core=0,reads=0,events=[],validation_error=0x1c00111),dict(name='too_large',too_large=True,tail=0,core=0,reads=0,events=[],validation_error=0x1c00114)]
        rows=[]
        for c in cases:
            maps=list(shared);prefix=c['name'];state=bytearray(4096)
            for off,key in [(44,'mismatch_offset'),(48,'mismatch_budget'),(52,'tail_budget'),(56,'core_budget'),(60,'read_budget')]:struct.pack_into('<I',state,off,c.get(key,0))
            state_path=mmap(maps,prefix+'_state.bin',STATE,state);source_bytes=bytearray(package)
            if c.get('bad_magic'):source_bytes[tbm.data_start]^=1
            package_path=mmap(maps,prefix+'_package.bin',PACKAGE,source_bytes)
            flash_path=mmap(maps,prefix+'_FLASH_RAM_NOT_NAND.bin',FLASH,b'\xa7'*(19267584+16));read_path=mmap(maps,prefix+'_readback.bin',READBACK,b'\xa5'*(length+16))
            n=19267584+512 if c.get('too_large')else length
            asm=' mov r10,0x36b264\n mov r0,1\n stb r0,[r10]\n mov r0,0xf0\n mov r12,0x25d194\n jl [r12]\n'
            asm+=f' mov r20,{STATE:#x}\n st sp,[r20,4]\n mov r0,{0 if c["name"]=="no_callback" else callback:#x}\n mov r1,{source:#x}\n mov r2,{n}\n mov r3,{READBACK:#x}\n mov r12,0x12ad58\n jl [r12]\n st r0,[r20]\n st sp,[r20,8]\n mov r0,0\n mov r8,1\n trap_s 1\n'
            elf=compile_probe(r,prefix,asm);case,log=r.run('update_'+prefix,'/result/'+elf.name,maps,trace=c['name']=='bad_magic');assert case['exit_code']==0 and case['fault']is None,log
            s=state_path.read_bytes();w=struct.unpack_from('<16I',s);expected=c.get('validation_error',0x1c00112 if c.get('error')else 0)
            assert w[0]==expected and w[1]==w[2],(c,w)
            assert (w[3],w[4],w[6])==(c['tail'],c['core'],c['reads']),(c,w)
            assert w[5]==c['tail']+c['reads'] and w[7]==c['tail'] and w[8]==w[9]==c['tail']+c['reads'],(c,w)
            events=list(struct.unpack_from(f'<{w[10]}I',s,128));assert events==c['events'],(c,events)
            flash=flash_path.read_bytes();back=read_path.read_bytes();assert flash[-16:]==b'\xa7'*16 and back[-16:]==b'\xa5'*16
            if not c.get('error')and not c.get('validation_error'):assert flash[:length]==back[:length]==tbm_bytes
            if c['name']in ['valid','no_callback','tail_fail_once','read_fail_once','mismatch_first_once','mismatch_last_once','read_fail_all','mismatch_first_all']:assert flash[:length]==tbm_bytes
            if c['name']in ['tail_fail_all','bad_magic','too_large']:assert flash==b'\xa7'*(19267584+16)
            if c['name']=='core_fail_all':
                tail_at=8603*2048
                assert flash[:tail_at]==b'\xa7'*tail_at and flash[tail_at:length]==tbm_bytes[tail_at:]
            assert flash[length:]==b'\xa7'*(19267584-length+16)
            assert package_path.read_bytes()==source_bytes
            writes=[struct.unpack_from('<4I',s,512+i*16)for i in range(w[3]+w[4])]
            assert all(a==19163 and b==1 and d==0x511f00 or a==10560 and b==8603 and d==source for a,b,d,_ in writes)
            rows.append(dict(name=c['name'],status=hex(w[0]),tail_write_calls=w[3],body_write_calls=w[4],partial_page_reads=w[5],aligned_readbacks=w[6],flushes=w[7],locks=w[8],unlocks=w[9],progress_events=events,stack_preserved=True,flash_model_matches_candidate=flash[:length]==tbm_bytes))
            print('PASS',prefix,flush=True)
        dump=(ROOT/'DUMPS/MainCode.dmp').read_bytes();spans=[]
        for a,b in [(0x12ad58,0x12adfc),(0x1ecd6c,0x1ece20),(0x260320,0x26048c),(0x32e508,0x32e53c)]:
            block,offset=locate(a,b-a);data=raw(a,b-a);assert data==dump[block['offset']+offset:block['offset']+offset+b-a]
            assert data==tbm_bytes[p['blocks'][block['index']]['offset']+offset:p['blocks'][block['index']]['offset']+offset+b-a]
            (out/f'{a:08x}_gnu.txt').write_text(disasm(a,b));spans.append(dict(cpu=hex(a),bytes=b-a))
        assert all(sha(Path(f))==h for f,h in r.input_hashes.items())
        (out/'update_cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'laboratory_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_MAIN_UPDATE_RETRY_AND_READBACK_RAM_MODEL',candidate=str(artifact.relative_to(ROOT)),candidate_sha256=p['sha256'],update_cases=rows,input_hashes=r.input_hashes,original_spans=spans,assumptions=['Original12AD58, writer/preparers, readback1ECD6C and memcmp32E508 execute','Mutex/flush and lower page read/write boundaries use a file-mapped RAM model','Explicit geometryF0/P1IDSTR dump; provisional DSPv7 restricted multiplication'],limits=['No hardware NAND write/erase/readback or power-loss recovery','Not full package UI/dispatcher; only Main component update','Original V1.1 and supplied dump bodies match; current resident flash not read back','RAM model has no bad-block remapping, ECC wear, controller timing or persistence'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');(out.parent/'main_update_cpu_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n');print('PASS',out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));(out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');raise

if __name__=='__main__':main()
