#!/usr/bin/env python3
"""Run original package registration/dispatch; lower component services are recorders."""
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
import json,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe,LAB,BUILD
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
sys.path.insert(0,str(ROOT/'coolpix-s33-re'))
from static_common import BS,PS,raw,locate,disasm,u32
from s33_extract import parse_firmware
PACKAGE,STATE,REGISTRY=0x4000000,0x2010000,0x42d15c


def main():
    out=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('package_cpu_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='original-package-component-dispatch-and-retry-counter'));r.prepare()
    try:
        proof=ROOT/json.loads((out.parent/'container_latest.json').read_text())['evidence'];p=json.loads(proof.read_text());artifact=ROOT/p['artifact'];assert sha(artifact)==p['sha256']
        package=artifact.read_bytes();sections,_=parse_firmware(package);boot,tbm,resource=sections;rounded=(len(package)//1024+1)*1024;allocation=rounded*2
        nand_path=ROOT/'DUMPS/NANDP1.dmp';table=nand_path.read_bytes()[0x231a:0x240e]
        r.input_hashes.update({str(f):sha(f)for f in [proof,artifact,nand_path,BUILD,Path(__file__)]})
        engine=LAB/'install/bin/arc-elf32-run';assert sha(engine)==json.loads(BUILD.read_text())['experimental_sha256'];r.input_hashes[str(engine)]=sha(engine);r.experimental_engine=LAB
        command=r.command
        def bounded_command(name,args,timeout=30):
            args=list(args)
            if name.startswith('package_')and'10s'in args:args[args.index('10s')]='45s';timeout=55
            return command(name,args,timeout=timeout)
        r.command=bounded_command
        images={i:bytearray(PS[i])for i in (0,1)};shared=[];patches=[]
        def mmap(maps,name,address,data):
            path=out/name;path.write_bytes(bytes(address%8)+data);maps.extend(['--memory-mapfile','/result/'+name,'--memory-region',f'{address:#x},{len(data)}']);return path
        def binary(name,asm):
            elf=compile_probe(r,name,asm);dest=out/(name+'.bin');v=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,dest]);assert v.returncode==0,v.stdout;return dest.read_bytes()
        def stub(address,asm):
            target=0x2030000+len(patches)*0x400;data=binary(f'boundary_{address:x}',asm);mmap(shared,f'boundary_{address:x}.bin',target,data+bytes(16))
            entry=binary(f'entry_{address:x}',f' mov_s r12,{target:#x}\n j_s [r12]\n');assert len(entry)==8
            b,o=locate(address,8);before=images[b['index']][o:o+8];images[b['index']][o:o+8]=entry;patches.append(dict(cpu=hex(address),original=before.hex(),boundary=hex(target)))
        def counter(offset):return f' mov r10,{STATE:#x}\n ld r6,[r10,{offset}]\n add r6,r6,1\n st r6,[r10,{offset}]\n'
        def record(kind):return f''' ld r6,[r10,96]
 asl r7,r6,5
 add r7,r7,128
 add r7,r7,r10
 mov r8,{kind}
 st r8,[r7]
 st r0,[r7,4]
 st r1,[r7,8]
 st r2,[r7,12]
 st r3,[r7,16]
 st r4,[r7,20]
 add r6,r6,1
 st r6,[r10,96]
'''
        # Package loader outputs: buffer, allocation length, file length, rounded file length.
        stub(0x12ab24,f''' mov r10,{STATE:#x}
 ld r6,[r10,40]
 add r6,r6,1
 st r6,[r10,40]
 ld r0,[r10,64]
 cmp r0,0
 bne load_done
 mov r6,{PACKAGE:#x}
 st r6,[r2]
 mov r6,{allocation}
 st r6,[r3]
 mov r6,{len(package)}
 st r6,[r4]
 mov r6,{rounded}
 st r6,[r5]
load_done:
 j_s [blink]
''')
        stub(0x12a738,counter(36)+record(6)+' mov r0,0\n j_s [blink]\n')
        stub(0x1eea4c,counter(16)+record(1)+''' cmp r0,0
 mov r7,44
 beq selected_write
 mov r7,48
selected_write:
 add r7,r7,r10
 ld r6,[r7]
 cmp r6,0
 beq write_ok
 sub r6,r6,1
 st r6,[r7]
 mov r0,0x2345
 j_s [blink]
write_ok:
 mov r0,0
 j_s [blink]
''')
        stub(0x1ed27c,counter(20)+record(2)+f''' ld r6,[r10,56]
 cmp r6,0
 beq read_boot
 sub r6,r6,1
 st r6,[r10,56]
 mov r0,0x3456
 j_s [blink]
read_boot:
 mov r6,{boot.data_length}
 st r6,[r4]
 push_s blink
 mov r0,r1
 mov r1,{PACKAGE+boot.data_start:#x}
 mov r2,{boot.data_length}
 mov r12,0x100abc0
 jl [r12]
 pop_s blink
 mov r0,0
 j_s [blink]
''')
        stub(0x1ecd6c,counter(24)+record(3)+f''' ld r6,[r10,60]
 cmp r6,0
 beq read_main
 sub r6,r6,1
 st r6,[r10,60]
 mov r0,0x3456
 j_s [blink]
read_main:
 push_s blink
 mov r0,r2
 asl r2,r1,9
 mov r1,{PACKAGE+tbm.data_start:#x}
 mov r12,0x100abc0
 jl [r12]
 pop_s blink
 mov r0,0
 j_s [blink]
''')
        stub(0x16f200,counter(28)+record(4)+' mov r0,0\n j_s [blink]\n')
        stub(0x129460,counter(32)+record(5)+' ld r0,[r10,52]\n j_s [blink]\n')
        mmap(shared,'TBIB_memcpy.bin',0x1000000,(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()[0x7c:0x44c38])
        cases=[dict(name='complete'),dict(name='bad_xor',bad_xor=True),dict(name='loader_error',load_error=0x1c00135),dict(name='boot_write_failure',boot_budget=3),dict(name='main_write_failure',main_budget=3),dict(name='boot_read_failure',boot_read_budget=3),dict(name='main_read_failure',main_read_budget=3),dict(name='resource_failure',resource_error=0x4567),dict(name='retry_after_main_failure',main_budget=3,repeat=True),dict(name='retry_after_resource_failure',resource_error=0x4567,repeat=True)]
        rows=[]
        def call(address):return f' mov r12,{address:#x}\n jl [r12]\n'
        for c in cases:
            maps=list(shared);name=c['name'];state=bytearray(4096)
            for off,key in [(44,'boot_budget'),(48,'main_budget'),(52,'resource_error'),(56,'boot_read_budget'),(60,'main_read_budget'),(64,'load_error')]:struct.pack_into('<I',state,off,c.get(key,0))
            state_path=mmap(maps,name+'_state.bin',STATE,state)
            data=bytearray(package)
            if c.get('bad_xor'):data[0]^=1
            input_data=data+b'\xa5'*(allocation-len(data)+16);buffer_path=mmap(maps,name+'_package_and_scratch.bin',PACKAGE,input_data)
            registry_path=mmap(maps,name+'_registry.bin',REGISTRY,bytes(680)+b'\xa5'*16)
            main_paths={}
            for i,image in images.items():main_paths[i]=mmap(maps,name+f'_block{i}_LAB_IO.bin',BS[i]['load_address_candidate'],image)
            mmap(maps,name+'_partition.bin',0x50f420,table);mmap(maps,name+'_geometry.bin',0x50f52c,bytes(32))
            asm=' mov r10,0x36b264\n mov r0,1\n stb r0,[r10]\n mov r0,0xf0\n'+call(0x25d194)
            for getter,callback in [(0xc76c4,0x12a9fc),(0xc76cc,0x12aa3c),(0xc76e4,0x12aaa8)]:asm+=call(getter)+f' mov r1,{callback:#x}\n'+call(0xbc3a0)
            asm+=f' mov r20,{STATE:#x}\n st sp,[r20,4]\n'
            invocation=' mov r0,0\n mov r1,0x377e23\n mov r2,0xbc3f8\n'+call(0x12a794)
            asm+=invocation+' st r0,[r20,68]\n mov r10,0x365410\n ldb r0,[r10]\n st r0,[r20,72]\n'
            if c.get('repeat'):
                asm+=' mov r0,0\n st r0,[r20,52]\n'+invocation
            else:asm+=' ld r0,[r20,68]\n'
            asm+=' st r0,[r20]\n st sp,[r20,8]\n mov r0,0\n mov r8,1\n trap_s 1\n';elf=compile_probe(r,name,asm)
            case,log=r.run('package_'+name,'/result/'+elf.name,maps,trace=c['name']=='loader_error');assert case['exit_code']==0 and case['fault']is None,log
            s=state_path.read_bytes();w=struct.unpack_from('<25I',s);assert w[1]==w[2],(c,w)
            events=[struct.unpack_from('<6I',s,128+j*32)for j in range(w[24])]
            writes=[v for v in events if v[0]==1];selectors=[v[1]for v in writes]
            reg=registry_path.read_bytes()[REGISTRY%8:];assert reg[-16:]==b'\xa5'*16
            for i,(n,a)in enumerate([(b'TBM_SK501.BIN',0x12a9fc),(b'TBIB_SK501.BIN',0x12aa3c),(b'P1RES',0x12aaa8)]):assert reg[i*68:i*68+64].split(b'\0')[0]==n and struct.unpack_from('<I',reg,i*68+64)[0]==a
            buf=buffer_path.read_bytes();assert buf[:len(data)]==data and buf[-16:]==b'\xa5'*16
            counter_after=main_paths[1].read_bytes()[0x365410-BS[1]['load_address_candidate']]
            rows.append(dict(name=name,status=hex(w[0]),first_status=hex(w[17]),counter_after_first=w[18],counter_after_final=counter_after,write_selectors=selectors,boot_read_calls=w[5],main_read_calls=w[6],boot_commit_calls=w[7],resource_calls=w[8],release_calls=w[9],load_calls=w[10],events=[dict(kind=v[0],args=[hex(a)for a in v[1:]])for v in events],stack_preserved=True))
            print(name,hex(w[0]),'first',hex(w[17]),'counter',w[18],counter_after,'writes',selectors,'res',w[8],flush=True)
        # Persist observations before explicit expectations, preserving a diagnostic failure.
        (out/'dispatch_cases.json').write_text(json.dumps(rows,indent=2)+'\n')
        expected=[('complete',0,[0,6],1),('bad_xor',0x1c00141,[],0),('loader_error',0x1c00135,[],0),('boot_write_failure',0x1c00122,[0,0,0],0),('main_write_failure',0x1c00112,[0,6,6,6],0),('boot_read_failure',0x1c00122,[0,0,0],0),('main_read_failure',0x1c00112,[0,6,6,6],0),('resource_failure',0x4567,[0,6],1),('retry_after_main_failure',0,[0,6,6,6,0,6],0),('retry_after_resource_failure',0,[0,6,0],1)]
        for row,(name,status,selectors,resources)in zip(rows,expected):
            assert (row['name'],row['status'],row['write_selectors'],row['resource_calls'])==(name,hex(status),selectors,resources),row
            counter=1 if name in ['main_write_failure','main_read_failure','retry_after_main_failure']else 2 if name in ['resource_failure','retry_after_resource_failure']else 0
            assert row['counter_after_first']==counter
            assert row['counter_after_final']==(0 if name.startswith('retry_')else counter)
            assert row['load_calls']==(2 if name.startswith('retry_')else 1)
            assert row['release_calls']==(0 if name=='loader_error'else row['load_calls'])
        for row in rows:
            for event in row['events']:
                if event['kind']==1:
                    selector,buffer,offset,n,_=map(lambda a:int(a,16),event['args']);section=boot if selector==0 else tbm
                    assert (buffer,offset,n)==(PACKAGE+section.data_start,0,section.data_length)
                if event['kind']==3:
                    start,sectors,destination,_,_=map(lambda a:int(a,16),event['args'])
                    assert (start,sectors,destination)==(0,(tbm.data_length+511)//512,PACKAGE+tbm.data_start+rounded)
                if event['kind']==5:
                    assert list(map(lambda a:int(a,16),event['args']))==[0x494d5245,0x1200000,PACKAGE+resource.data_start,resource.data_length,PACKAGE+resource.data_start+rounded]
        assert all(sha(Path(f))==h for f,h in r.input_hashes.items())
        windows=[(0xbc3a0,0xbc3f4),(0xbc3f8,0xbc470),(0xbc478,0xbc4b8),(0x12a794,0x12a8bc),(0x12aa3c,0x12aaa4),(0x12ae00,0x12ae9c)]
        for a,b in windows:(out/f'{a:08x}_gnu.txt').write_text(disasm(a,b))
        (out/'laboratory_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ORIGINAL_PACKAGE_DISPATCH_RECORDER_BOUNDARIES',candidate=str(artifact.relative_to(ROOT)),candidate_sha256=p['sha256'],dispatch_cases=rows,input_hashes=r.input_hashes,assumptions=['Original name registration, package XOR/parser/dispatcher and component callbacks','File loader provides actual candidate and scratch buffers; no filesystem','Component write/read/resource/commit services are recorders or copy fixtures; not physical storage','Explicit initialized registry and F0/P1IDSTR profile; provisional DSPv7'],limits=['No camera writes, installation, physical recovery or power-loss test','Resource129460 internals and physical Boot/Main write/readback/commit are not executed','Stale-counter cases are two requests in one lab lifetime, not full UI/operator sequence','Current resident flash, scheduler, cache and extension lifetime remain unproven'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');(out.parent/'package_cpu_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n');print('PASS',out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));(out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');raise

if __name__=='__main__':main()
