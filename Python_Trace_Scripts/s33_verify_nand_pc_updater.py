#!/usr/bin/env python3
"""Execute original updater checks/rounding with lower NAND writes recorded only."""
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
import json,re,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe,LAB,BUILD
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
sys.path.insert(0,str(ROOT/'coolpix-s33-re'))
from static_common import BS,PS,raw,locate,disasm,u32
from s33_extract import parse_firmware
PACKAGE,CURRENT,STATES=0x4000000,0x2010000,0x2100000


def main():
    out=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('updater_cpu_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='original-updater-extended-Main-boundaries'));r.prepare()
    try:
        proof=ROOT/json.loads((out.parent/'container_latest.json').read_text())['evidence'];p=json.loads(proof.read_text());artifact=ROOT/p['artifact'];assert sha(artifact)==p['sha256']
        package=artifact.read_bytes();sections,_=parse_firmware(package);tbm=sections[1];tbm_pointer=PACKAGE+tbm.data_start;length=tbm.data_length
        nand_path=ROOT/'DUMPS/NANDP1.dmp';nand=nand_path.read_bytes();table=nand[0x231a:0x240e];assert table[:8]==table[-8:]==b'P1IDSTR\0'
        assert struct.unpack_from('<HH',table,0xd0)==(165,3)and struct.unpack_from('<H',table,0xde)[0]==147
        r.input_hashes.update({str(f):sha(f)for f in [proof,artifact,nand_path,BUILD]})
        build=json.loads(BUILD.read_text());engine=LAB/'install/bin/arc-elf32-run';assert sha(engine)==build['experimental_sha256'];r.input_hashes[str(engine)]=sha(engine);r.experimental_engine=LAB
        # A full29MB XOR requires a longer bounded execution than a small probe.
        command=r.command
        def bounded_command(name,args,timeout=30):
            args=list(args)
            if name=='package_xor'and '10s'in args:args[args.index('10s')]='45s';timeout=55
            return command(name,args,timeout=timeout)
        r.command=bounded_command
        images={i:bytearray(PS[i])for i in (0,1)};maps=[];patches=[]
        def mmap(name,address,data):
            (out/name).write_bytes(bytes(address%8)+data);maps.extend(['--memory-mapfile','/result/'+name,'--memory-region',f'{address:#x},{len(data)}'])
        def binary(name,asm):
            elf=compile_probe(r,name,asm);dest=out/(name+'.bin');v=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,dest]);assert v.returncode==0,v.stdout
            return dest.read_bytes()
        def stub(address,asm):
            target=0x2030000+len(patches)*0x400;data=binary(f'recorder_{address:x}',asm);mmap(f'recorder_{address:x}.bin',target,data+bytes(16))
            entry=binary(f'entry_{address:x}',f' mov_s r12,{target:#x}\n j_s [r12]\n');assert len(entry)==8
            b,o=locate(address,8);before=images[b['index']][o:o+8];images[b['index']][o:o+8]=entry;patches.append(dict(cpu=hex(address),original=before.hex(),recorder=hex(target)))
        common=f' mov r10,{CURRENT:#x}\n ld r10,[r10]\n'
        # State0status/4,8SP;12writecount/16readcount/20flushcount;
        # 24backenderror/28readerror/32lockerror/36releaseerror/40,44lockcounts.
        stub(0x1593ac,common+' ld r0,[r10,40]\n add r0,r0,1\n st r0,[r10,40]\n ld r0,[r10,32]\n j_s [blink]\n')
        stub(0x1594a4,common+' ld r0,[r10,44]\n add r0,r0,1\n st r0,[r10,44]\n ld r0,[r10,36]\n j_s [blink]\n')
        stub(0x17faf8,common+' ld r0,[r10,20]\n add r0,r0,1\n st r0,[r10,20]\n mov r0,0\n j_s [blink]\n')
        stub(0x1ed11c,common+''' ld r5,[r10,16]
 add r5,r5,1
 st r5,[r10,16]
 st r0,[r10,64]
 st r2,[r10,68]
 st r3,[r10,72]
 st r3,[r4]
 ld r0,[r10,28]
 cmp r0,0
 bne read_done
 mov r5,2048
 mov r6,0xa7
fill_old:
 stb r6,[r1]
 add r1,r1,1
 sub.f r5,r5,1
 bne fill_old
read_done:
 j_s [blink]
''')
        stub(0x1eded8,common+''' ld r5,[r10,12]
 asl r6,r5,5
 add r6,r6,128
 add r6,r6,r10
 st r0,[r6]
 st r1,[r6,4]
 st r2,[r6,8]
 st r3,[r6,12]
 add r5,r5,1
 st r5,[r10,12]
 cmp r1,1
 bne write_done
 add r5,r10,512
 mov r6,512
copy_page:
 ld.ab r7,[r2,4]
 st.ab r7,[r5,4]
 sub.f r6,r6,1
 bne copy_page
write_done:
 ld r0,[r10,24]
 j_s [blink]
''')
        for i,data in images.items():mmap(f'block{i}_LAB_IO.bin',BS[i]['load_address_candidate'],data)
        mmap('package.bin',PACKAGE,package);mmap('current.bin',CURRENT,bytes(8));mmap('states.bin',STATES,bytes(32*4096));mmap('partition.bin',0x50f420,table);mmap('geometry.bin',0x50f52c,bytes(32));mmap('page.bin',0x511f00,bytes(2048))
        def call(a):return f' mov r12,{a:#x}\n jl [r12]\n'
        setup=' mov r10,0x36b264\n mov r0,1\n stb r0,[r10]\n mov r0,0xf0\n'+call(0x25d194)
        # Full package XOR and relocated outer descriptor traversal, original code.
        asm=setup+f' mov r20,{STATES:#x}\n st sp,[r20,4]\n mov r0,{PACKAGE+4:#x}\n mov r1,{len(package)-4}\n'+call(0x12b060)+' st r0,[r20]\n st sp,[r20,8]\n'
        for i,section in enumerate(sections):
            a=STATES+(i+1)*4096
            asm+=f' mov r20,{a:#x}\n mov r10,{CURRENT:#x}\n st r20,[r10]\n st sp,[r20,4]\n mov r0,{PACKAGE:#x}\n st r0,[r20,64]\n add r0,r20,64\n mov r1,{i+1}\n add r2,r20,128\n'+call(0x12aff0)+' st r0,[r20]\n st sp,[r20,8]\n'
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n';elf=compile_probe(r,'package_xor',asm);case,log=r.run('package_xor','/result/'+elf.name,maps,trace=False);assert case['exit_code']==0 and case['fault']is None,log
        data=(out/'states.bin').read_bytes();w=struct.unpack_from('<3I',data);assert w[0]==struct.unpack_from('<I',package)[0]and w[1]==w[2],w
        for i,section in enumerate(sections):
            a=(i+1)*4096;w=struct.unpack_from('<3I',data,a);assert w[0]==0 and w[1]==w[2]and data[a+128:a+204]==package[section.marker_offset:section.marker_offset+76],(i,w)
        # Check actual Main validation: resident size getter and checksum original.
        validations=[('candidate_valid',length,None,0),('too_large',19267584+512,None,0x1c00114),('bad_magic',length,0,0x1c00111),('bad_payload0',length,512,0x1c00111),('bad_payload1',length,p['blocks'][1]['offset'],0x1c00111),('type0_not_checked',length,p['blocks'][4]['offset'],0),('later_type1_not_checked',length,p['blocks'][8]['offset'],0)]
        asm=setup
        for i,(name,n,mutate,expected)in enumerate(validations):
            a=STATES+(i+4)*4096;asm+=f' mov r20,{a:#x}\n st sp,[r20,4]\n'
            if mutate is not None:asm+=f' mov r10,{tbm_pointer+mutate:#x}\n ldb r0,[r10]\n xor r0,r0,1\n stb r0,[r10]\n'
            asm+=f' mov r0,{tbm_pointer:#x}\n mov r1,{n}\n'+call(0x12aea0)+' st r0,[r20]\n st sp,[r20,8]\n'
            if mutate is not None:asm+=f' mov r10,{tbm_pointer+mutate:#x}\n ldb r0,[r10]\n xor r0,r0,1\n stb r0,[r10]\n'
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n';elf=compile_probe(r,'main_validation',asm);case,log=r.run('main_validation','/result/'+elf.name,maps,trace=False);assert case['exit_code']==0 and case['fault']is None,log
        data=(out/'states.bin').read_bytes();validation_rows=[]
        for i,(name,n,mutate,expected)in enumerate(validations):
            w=struct.unpack_from('<3I',data,(i+4)*4096);assert w[0]==expected and w[1]==w[2],(name,w,hex(expected));validation_rows.append(dict(name=name,status=hex(w[0]),stack_preserved=True))
        # Main writer path, with real rounding/preparer/partition bounds. The
        # backend recorder never erases/programs NAND, and partial read is fixture.
        writes=[dict(name='extended_Main',length=length),dict(name='original_length',length=17615360),dict(name='full_partition',length=19267584),dict(name='over_capacity',length=19267584+2048),dict(name='read_error',length=length,read_error=0x1234),dict(name='backend_error',length=length,backend_error=0x2345),dict(name='lock_error',length=length,lock_error=0x3456),dict(name='release_error',length=length,release_error=0x4567),dict(name='aligned_small',length=2048),dict(name='partial_small',length=512),dict(name='zero_length',length=0)]
        asm=setup
        for i,c in enumerate(writes):
            a=STATES+(i+12)*4096;asm+=f' mov r20,{a:#x}\n mov r10,{CURRENT:#x}\n st r20,[r10]\n st sp,[r20,4]\n'
            for off,key in [(24,'backend_error'),(28,'read_error'),(32,'lock_error'),(36,'release_error')]:asm+=f' mov r0,{c.get(key,0)}\n st r0,[r20,{off}]\n'
            asm+=f' mov r0,6\n mov r1,{tbm_pointer:#x}\n mov r2,0\n mov r3,{c["length"]}\n'+call(0x1eea4c)+' st r0,[r20]\n st sp,[r20,8]\n'
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n';elf=compile_probe(r,'writer_bounds',asm);case,log=r.run('writer_bounds','/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault']is None,log
        data=(out/'states.bin').read_bytes();write_rows=[]
        for i,c in enumerate(writes):
            s=data[(i+12)*4096:(i+13)*4096];w=struct.unpack_from('<12I',s)
            expected=c.get('lock_error')or c.get('read_error')or c.get('backend_error')or(0x1b00116 if c['name']=='over_capacity'else c.get('release_error',0));assert w[0]==expected and w[1]==w[2],(c,w,expected)
            assert w[10]==1 and w[11]==(0 if c.get('lock_error')else 1),(c,w)
            rows=[struct.unpack_from('<4I',s,128+j*32)for j in range(w[3])]
            if c['name']in ['extended_Main','original_length','partial_small']:
                count,tail=divmod(c['length'],2048)
                assert w[4]==1 and rows[0]==(10560+count,1,0x511f00,0),(c,rows)
                assert s[512:512+tail]==package[tbm.data_start+count*2048:tbm.data_start+c['length']]
                assert s[512+tail:2560]==b'\xa7'*(2048-tail),c
                if count:assert rows[1]==(10560,count,tbm_pointer,0),(c,rows)
            if c['name']=='over_capacity':assert not rows and w[4]==0
            write_rows.append(dict(name=c['name'],bytes=c['length'],status=hex(w[0]),writes=[dict(page=a,pages=b,buffer=hex(d),mode=mode)for a,b,d,mode in rows],partial_reads=w[4],flushes=w[5],stack_preserved=True))
        assert (out/'package.bin').read_bytes()==package and(out/'partition.bin').read_bytes()==table
        assert all(sha(Path(f))==h for f,h in r.input_hashes.items())
        trace=(out/'writer_bounds.trace').read_text();pcs={int(m[1],16)for m in re.finditer(r'^0x([0-9a-f]+)\s',trace,re.M)};assert {0x1eea4c,0x260fe4,0x261166,0x1ee730,0x1ee974}.issubset(pcs)
        spans=[];dump=(ROOT/'DUMPS/MainCode.dmp').read_bytes()
        for a,b in [(0x12aea0,0x12af3a),(0x12aff0,0x12b05a),(0x1eea4c,0x1eeabe),(0x260fe4,0x2611ba),(0x1ee730,0x1ee77a),(0x1ee874,0x1ee88e),(0x1ee958,0x1ee994)]:
            block,offset=locate(a,b-a);assert raw(a,b-a)==dump[block['offset']+offset:block['offset']+offset+b-a];spans.append(dict(cpu=hex(a),bytes=b-a));(out/f'{a:08x}_gnu.txt').write_text(disasm(a,b))
        (out/'validation_cases.json').write_text(json.dumps(validation_rows,indent=2)+'\n');(out/'writer_cases.json').write_text(json.dumps(write_rows,indent=2)+'\n');(out/'patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ORIGINAL_UPDATER_BOUNDS_ONLY',candidate=str(artifact.relative_to(ROOT)),candidate_sha256=p['sha256'],package_xor=True,descriptors=3,validation_cases=len(validations),writer_cases=len(writes),tool_inputs=r.input_hashes,original_spans=spans,assumptions=['P1IDSTR supplied NAND dump; G initialized by original decoder with explicit F0 input','DSPv7 provisional narrow non-saturating positive multiplication, not full CPU certification','NAND write/read/flush and mutex recorder boundaries only'],limits=['No hardware, NAND write/erase/readback or actual updater installation','Main validator tests only its observed subset; it does not validate all16 payloads','Partition bounds are logical pages before remapping; physical recovery and code residence remain open'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');(out.parent/'updater_cpu_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n');print('PASS',out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));(out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');raise
if __name__=='__main__':main()
