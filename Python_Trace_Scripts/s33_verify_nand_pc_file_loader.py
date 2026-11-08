#!/usr/bin/env python3
"""Execute original TBIB RHIR file loader with local read/seek fixtures only."""
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
import json,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'coolpix-s33-re'))
from s33_extract import parse_firmware
TBM,STATE=0x4000000,0x2010000


def main():
    out=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('file_loader_cpu_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='original-TBIB-file-loader-candidate-and-I/O-failure-contract'));r.prepare()
    try:
        proof=ROOT/json.loads((out.parent/'container_latest.json').read_text())['evidence'];p=json.loads(proof.read_text());artifact=ROOT/p['artifact'];assert sha(artifact)==p['sha256']
        package=artifact.read_bytes();sections,_=parse_firmware(package);tbm=package[sections[1].data_start:sections[1].data_end]
        original=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()[0x7c:0x44c38]
        # TBIB has its own table, with NAND then SD (Main table order differs).
        assert struct.unpack_from('<I',original,0x8574)[0]==0x10421cc
        namespaces=[]
        for index,(device,manager,prefix)in enumerate([('DEVNAND:','PMNAND:','A:'),('DEVSD:','PMSD:','B:')]):
            address=0x10421cc+index*0x150;record=original[address-0x1000000:address-0x1000000+0x150]
            for offset,wanted in [(8,device),(19,manager),(30,prefix)]:
                assert record[offset:].split(b'\0')[0].decode()==wanted
            namespaces.append(dict(index=index,cpu=hex(address),device=device,manager=manager,prefix=prefix,record_hex=record.hex()))
        (out/'tbib_namespace_records.json').write_text(json.dumps(namespaces,indent=2)+'\n')
        blocks=[b for b in p['blocks']if b['type']==1];assert [b['index']for b in blocks]==[0,1,8,17]and tbm[6]==18
        r.input_hashes.update({str(f):sha(f)for f in [proof,artifact,Path(__file__)]})
        def mmap(maps,name,address,data):
            path=out/name;path.write_bytes(bytes(address%8)+data);maps.extend(['--memory-mapfile','/result/'+name,'--memory-region',f'{address:#x},{len(data)}']);return path
        def binary(name,asm):
            elf=compile_probe(r,name,asm);path=out/(name+'.bin');v=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path]);assert v.returncode==0,v.stdout;return path.read_bytes()
        body=bytearray(original);shared=[];patches=[]
        def stub(address,asm):
            target=0x2030000+len(patches)*0x400;data=binary(f'fs_{address:x}',asm);mmap(shared,f'fs_{address:x}.bin',target,data+bytes(16))
            entry=binary(f'entry_{address:x}',f' mov_s r12,{target:#x}\n j_s [r12]\n');assert len(entry)==8;at=address-0x1000000
            patches.append(dict(cpu=hex(address),original=body[at:at+8].hex(),lab=hex(target)));body[at:at+8]=entry
        def counter(offset):return f' mov r10,{STATE:#x}\n ld r6,[r10,{offset}]\n add r6,r6,1\n st r6,[r10,{offset}]\n'
        stub(0x10038c8,' mov r0,0\n j_s [blink]\n')
        stub(0x1008394,counter(36)+' ld r0,[r10,52]\n j_s [blink]\n')
        stub(0x100858c,counter(28)+' mov r6,0x1234\n st r6,[r2]\n ld r0,[r10,48]\n j_s [blink]\n')
        stub(0x1008718,counter(32)+' ld r0,[r10,56]\n j_s [blink]\n')
        stub(0x100b1f0,counter(40)+' ld r0,[r10,60]\n j_s [blink]\n')
        stub(0x100ad64,counter(44)+''' ld r6,[r10,24]
 cmp r1,1
 bne relative_seek
 mov r6,r2
 b position_ready
relative_seek:
 add r6,r6,r2
position_ready:
 st r6,[r10,24]
 st r6,[r4]
 ld r0,[r10,64]
 j_s [blink]
''')
        stub(0x100b0c4,counter(12)+f''' sub r6,r6,1
 asl r12,r6,5
 add r12,r12,128
 add r12,r12,r10
 ld r6,[r10,24]
 st r6,[r12]
 st r2,[r12,4]
 st r1,[r12,8]
 mov r7,r2
 mov r8,0
 ld r5,[r10,12]
 ld r9,[r10,16]
 cmp r5,r9
 bne actual_ready
 ld r5,[r10,20]
 cmp r5,1
 beq short_read
 cmp r5,2
 beq no_read
 cmp r5,3
 bne actual_ready
 mov r8,0x1234
 b actual_ready
short_read:
 sub r7,r7,1
 b actual_ready
no_read:
 mov r7,0
 mov r8,0x1234
actual_ready:
 st r7,[r4]
 st r7,[r12,12]
 st r8,[r12,16]
 add r5,r6,r7
 st r5,[r10,24]
 push_s blink
 st.aw r8,[sp,-4]
 mov r0,r1
 add r1,r6,{TBM:#x}
 mov r2,r7
 mov r12,0x100abc0
 jl [r12]
 ld.ab r0,[sp,4]
 pop_s blink
 j_s [blink]
''')
        cases=[dict(name='valid',status=0,reads=23),dict(name='public_package',status=11,reads=1),dict(name='bad_checksum0',status=13,reads=3),dict(name='bad_extension_checksum',status=13,reads=23),dict(name='mount_failure',status=8,reads=0,mount_error=1),dict(name='open_failure',status=9,reads=0,open_error=1),dict(name='short_header',status=10,reads=1,target=1,mode=1),dict(name='short_descriptor',status=10,reads=2,target=2,mode=1),dict(name='missing_payload0',status=13,reads=3,target=3,mode=2),dict(name='short_payload0',status=13,reads=3,target=3,mode=1),dict(name='missing_extension',status=13,reads=23,target=23,mode=2),dict(name='error_with_full_payload0',status=0,reads=23,target=3,mode=3),dict(name='missing_payload0_valid_RAM',status=0,reads=23,target=3,mode=2,preload=True),dict(name='close_failure',status=0,reads=23,close_error=0x2345),dict(name='unmount_failure',status=0,reads=23,unmount_error=0x3456)]
        cases.extend([
            dict(name='valid_A_namespace',status=0,reads=23,drive_A=True),
            dict(name='short_extension',status=13,reads=23,target=23,mode=1),
            dict(name='missing_extension_valid_RAM',status=0,reads=23,target=23,mode=2,preload_all=True),
            dict(name='short_extension_valid_RAM',status=0,reads=23,target=23,mode=1,preload_all=True),
            dict(name='error_with_full_header',status=0,reads=23,target=1,mode=3),
            dict(name='error_with_full_extension',status=0,reads=23,target=23,mode=3),
            dict(name='seek_reports_error_position_updated',status=0,reads=23,seek_error=0x4567),
        ])
        rows=[]
        for c in cases:
            maps=list(shared);name=c['name'];tbib=mmap(maps,name+'_tbib_LAB_FS.bin',0x1000000,body);source=bytearray(package if name=='public_package'else tbm)
            if name=='bad_checksum0':source[0x1c]^=1
            if name=='bad_extension_checksum':source[0x12c]^=1
            source_path=mmap(maps,name+'_source.bin',TBM,source);state=bytearray(1024)
            for off,key in [(16,'target'),(20,'mode'),(48,'open_error'),(52,'mount_error'),(56,'close_error'),(60,'unmount_error'),(64,'seek_error')]:struct.pack_into('<I',state,off,c.get(key,0))
            state_path=mmap(maps,name+'_state.bin',STATE,state);loaded=[];first=None
            for b in blocks:
                address=int(b['cpu'],16);n=b['bytes']
                if b['index']==17:loaded.append((b,first,blocks[0]['bytes']));continue
                extra=blocks[-1]['bytes']if b['index']==0 else 0;initial=bytearray(b'\xa5'*(n+extra+16))
                if c.get('preload')and b['index']==0:initial[:n]=tbm[b['offset']:b['offset']+n]
                if c.get('preload_all'):
                    initial[:n]=tbm[b['offset']:b['offset']+n]
                    if b['index']==0:
                        ext=blocks[-1];initial[n:n+extra]=tbm[ext['offset']:ext['offset']+extra]
                path=mmap(maps,name+f'_payload{b["index"]}.bin',address,initial)
                if b['index']==0:first=path
                loaded.append((b,path,0))
            drive=struct.unpack_from('<I',original,0x1454 if c.get('drive_A')else 0x144c)[0];filename=struct.unpack_from('<I',original,0x1458 if c.get('drive_A')else 0x1450)[0]
            asm=f' mov r20,{STATE:#x}\n st sp,[r20,4]\n mov r0,{drive:#x}\n mov r1,{filename:#x}\n mov r12,0x100125c\n jl [r12]\n st r0,[r20]\n st sp,[r20,8]\n mov r0,0\n mov r8,1\n trap_s 1\n'
            elf=compile_probe(r,name,asm);case,log=r.run(name,'/result/'+elf.name,maps,trace=name=='public_package');assert case['exit_code']==0 and case['fault']is None,log
            data=state_path.read_bytes();w=struct.unpack_from('<16I',data);assert w[0]==c['status']and w[1]==w[2]and w[3]==c['reads'],(c,w)
            reads=[struct.unpack_from('<5I',data,128+j*32)for j in range(w[3])]
            assert w[9]==1 and w[7]==(0 if c.get('mount_error')else 1)and w[8]==(0 if c.get('mount_error')or c.get('open_error')else 1)and w[10]==(0 if c.get('mount_error')else 1),(c,w)
            assert all(a+actual<=len(source)and actual<=requested for a,requested,dest,actual,status in reads)
            full=c['status']==0 or name=='bad_extension_checksum'
            for b,path,offset in loaded:
                mapped=path.read_bytes();n=b['bytes'];actual=mapped[offset:offset+n];wanted=b'\xa5'*n
                if full or (name=='bad_checksum0'and b['index']==0)or(name in ('missing_extension','short_extension')and b['index']!=17):wanted=tbm[b['offset']:b['offset']+n]
                if name=='short_payload0'and b['index']==0:wanted=tbm[b['offset']:b['offset']+n-1]+b'\xa5'
                if name=='short_extension'and b['index']==17:wanted=tbm[b['offset']:b['offset']+n-1]+b'\xa5'
                assert actual==wanted and mapped[-16:]==b'\xa5'*16,(name,b['index'])
            if full or name in ('missing_extension','short_extension'):
                wanted=[(0,16)]
                for index in range(18):
                    wanted.append((16+index*16,16));block=next((b for b in blocks if b['index']==index),None)
                    if block:wanted.append((block['offset'],block['bytes']))
                assert [(a,n)for a,n,_,_,_ in reads]==wanted
                assert struct.unpack_from('<I',tbib.read_bytes(),0x41100)[0]==0xbb540
            assert source_path.read_bytes()==source
            rows.append(dict(name=name,status=w[0],reads=[dict(offset=a,requested=n,destination=hex(d),actual=actual,io_status=hex(status))for a,n,d,actual,status in reads],mount_calls=w[9],open_calls=w[7],close_calls=w[8],unmount_calls=w[10],seek_calls=w[11],entry_word=hex(struct.unpack_from('<I',tbib.read_bytes(),0x41100)[0]),seek_fixture_status=hex(c.get('seek_error',0)),namespace='A:'if c.get('drive_A')else'B:',all_payloads_preloaded=bool(c.get('preload_all')),valid_payload0_preloaded=bool(c.get('preload')),stack_preserved=True))
            print('PASS',name,flush=True)
        for a,b in [(0x100125c,0x1001358),(0x10011bc,0x100125a),(0x1001764,0x10017c4),(0x1008394,0x100858c)]:
            v=r.command(f'gnu_{a:x}',[TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',out/'tbib.elf']);assert v.returncode==0 and'out of bounds'not in v.stdout
        assert all(sha(Path(f))==h for f,h in r.input_hashes.items())
        (out/'file_loader_cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'laboratory_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ORIGINAL_TBIB_FILE_LOADER_LOCAL_FS_ONLY',candidate=str(artifact.relative_to(ROOT)),candidate_sha256=p['sha256'],static_namespace_records=namespaces,file_loader_cases=rows,input_hashes=r.input_hashes,assumptions=['Original0100125C/010011BC/checksum and memcpy; seven FS/delay entries are local fixtures','Explicit A5 RAM and one case with valid payload0 preloaded','B: and filename are original strings; no physical namespace inference'],limits=['No SD, FAT, driver, physical file read, BootTask scheduling or handoff','Read status/count and cleanup fixtures test local control flow, not physical integrity','No camera writes/commands; no recovery or installable-ready image'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');(out.parent/'file_loader_cpu_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n');print('PASS',out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));(out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');raise

if __name__=='__main__':main()
