#!/usr/bin/env python3
"""Read-only source verification and bounded original SCSI dispatch in GNU RAM.

Only result-local copies receive a transfer recorder; no hardware or GNU build.
"""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import re
import struct
import sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, u32, locate, disasm

GLOBAL=0x89ab7c
CURRENT=0x2000000
STATES=0x2001000
CDB=0x2020000
RECORDER=0x2040000
WINDOWS=[(0x1392cc,0x139444),(0x13959c,0x139650),(0x139690,0x139730),
 (0x81dc38,0x81dcb8),(0x81f7c8,0x81f7d0),(0x81f89c,0x81f8f0),
 (0x81f94c,0x81fa28),(0x81fa90,0x81faa4),(0x81fb4c,0x81fc5c),
 (0x81ff1c,0x82002c),(0x820304,0x820470),(0x820528,0x82060c),
 (0x82060c,0x8207ec),(0x820c00,0x820c9c),
 (0x820d04,0x820fcc),(0x81f538,0x81f5f8),(0x190bf0,0x190c08),
 (0x16964c,0x16967c),(0x25c020,0x25c028),(0x25caec,0x25caf4),
 (0x25d194,0x25d1e2),(0x25d1f8,0x25d230),(0x25d2fa,0x25d328),
 (0x25d370,0x25d3ba),(0x261478,0x2614a8),(0x2614b2,0x261524),
 (0x261524,0x261586),(0x261590,0x2615f8),(0x2616ac,0x2618c4),
 (0x3342a8,0x3342cc),(0x168f24,0x168f90),(0x168eac,0x168f24),
 (0x260320,0x260488),(0x168cec,0x168db0),(0x168db0,0x168eac),
 (0x168bbc,0x168c68),(0x25eddc,0x25ef24)]


def main():
    out=ROOT/'Risultati/USB_SCSI'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='original-scsi-callback-dispatch'))
    print('Evidence:',out,flush=True)
    try:
        r.prepare()
        for tool in (ROOT/'work/build-arc/binutils/objcopy',ROOT/'work/build-arc/binutils/objdump',TOOLCHAIN/'arc-elf32-objcopy'):
            r.input_hashes[str(tool)]=sha(tool)
        originals=[ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin',ROOT/'DUMPS/MainCode.dmp',ROOT/'Risultati/Disassemblati/Firmware1.1.asm',ROOT/'DUMPS/NANDP1.dmp',ROOT/'Risultati/Hardware/MSDC_Default/20261020T212724Z/observation.json']
        inputs={str(p.relative_to(ROOT)):sha(p) for p in originals}
        dump=originals[1].read_bytes()
        firmware=originals[0].read_bytes()
        tbm=struct.unpack_from('<I',firmware,0x480ac)[0]
        assert tbm==0x480b8
        spans=[]
        def check(a,n):
            b,o=locate(a,n)
            f=tbm+b['offset']+o
            assert firmware[f:f+n]==raw(a,n)==dump[b['offset']+o:b['offset']+o+n]
            spans.append(dict(cpu=hex(a),firmware_offset=hex(f),size=n,sha256=hashlib.sha256(raw(a,n)).hexdigest()))
        texts=[]
        for a,b in WINDOWS:
            check(a,b-a);texts.append(disasm(a,b))
        (out/'gnu_verified.txt').write_text('\n'.join(texts))
        pools=[0x81f8f0,0x81fd1c,0x820510,0x8208d0]
        for a in pools:check(a,4);assert u32(a)==GLOBAL
        check(0x9a33d4,18*8)
        table=[dict(opcode=raw(0x9a33d4+i*8,1)[0],handler=hex(u32(0x9a33d8+i*8))) for i in range(18)]
        assert {x['opcode']:x['handler'] for x in table if x['opcode'] in (0,3,0x12,0x1a,0x25,0x28)}=={0:'0x81faa4',3:'0x81fad8',0x12:'0x81fb4c',0x1a:'0x81fc5c',0x25:'0x81ff1c',0x28:'0x820304'}
        refs=[]
        for line in originals[2].open():
            m=re.match(r'F([0-9A-F]+) V([0-9A-F]+) \| ([0-9a-f ]+) \| (ld(?:_s|\.as)?)\s+(r\d+),\[pcl,([^\]]+)\]',line)
            if not m or not re.fullmatch(r'-?(?:0x[0-9a-f]+|[0-9]+)',m[6]):continue
            pc=int(m[2],16);disp=int(m[6],0);pool=(pc&~3)+disp*(4 if m[4]=='ld.as' else 1)
            if pool in pools:refs.append(dict(cpu=hex(pc),firmware_offset=hex(int(m[1],16)),pool=hex(pool),register=m[5],instruction=line.strip()))
        assert any(x['cpu']=='0x81fbf0' and x['pool']=='0x81fd1c' for x in refs)
        # Raw literal candidates are bounded searches, not an exhaustive alias analysis.
        candidates={}
        for value in [GLOBAL,GLOBAL+0x40,0x1392cc,0x81f89c]:
            pattern=struct.pack('<I',value)
            candidates[hex(value)]=[hex(m.start()) for m in re.finditer(re.escape(pattern),firmware)]
        assert candidates[hex(GLOBAL)]==['0x5cc7a8','0x5ccbd4','0x5cd3c8','0x5cd788']
        (out/'static_evidence.json').write_text(json.dumps(dict(spans=spans,pool_consumers=refs,literal_candidates=candidates,scsi_table=table),indent=2)+'\n')
        nand=originals[3].read_bytes()
        offsets=[m.start() for m in re.finditer(b'P1IDSTR',nand)]
        records=[a for a in offsets if a+244<=len(nand) and nand[a+236:a+243]==b'P1IDSTR']
        assert len(records)==24 and records[0]==0x231a
        p1=nand[records[0]:records[0]+244]
        assert all(nand[a:a+244]==p1 for a in records)
        e4=struct.unpack_from('<H',p1,0xe4)[0];assert e4==324
        assert 0x25d1e2+2*raw(0x25d1e2+(0xf0-220),1)[0]==0x25d208
        assert 0x25d230+2*raw(0x25d230+8-3,1)[0]==0x25d2fa
        assert 0x2614a8+2*raw(0x2614a8+8-3,1)[0]==0x2614de
        assert 500*8*32-e4*64*4==45056==0xb000
        assert (500-e4)*64*4==45056 and 45056*512==22*1024**2
        (out/'storage_formula.json').write_text(json.dumps(dict(p1_offsets=[hex(a) for a in records],p1_sha256=hashlib.sha256(p1).hexdigest(),p1_e4=e4,nand_id_is_fixture='0xf0',class8=dict(chs=[500,8,32],pages_per_block=64,sectors_per_page=4,software_total_sectors=128000,exposed_sectors=45056,last_lba=0xafff),fat_lut='0x50fdc0',p1_lut_is_distinct='0x50e9c0',limit='Runtime NAND ID and initialized geometry/LUT have not been observed'),indent=2)+'\n')
        images={i:bytearray(PS[i]) for i in (0,1,4,5)}
        maps=[]
        def mmap(name,a,data):
            (out/name).write_bytes(data)
            maps.extend(['--memory-mapfile','/result/'+name,'--memory-region',f'{a:#x},{len(data)}'])
        def binary(name,asm):
            elf=compile_probe(r,name,asm);p=out/(name+'.bin')
            proc=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert proc.returncode==0
            return p.read_bytes()
        stub=binary('transfer_recorder',f' mov r10,{CURRENT:#x}\n ld r10,[r10]\n st r2,[r10,20]\n st r1,[r10,24]\n ld r9,[r1]\n st r9,[r10,32]\n ld r9,[r1,4]\n st r9,[r10,36]\n ld r9,[r10,28]\n add r9,r9,1\n st r9,[r10,28]\n mov r0,0\n j_s [blink]\n')
        mmap('transfer_recorder.bin',RECORDER,stub+bytes(8+(-len(stub))%8))
        entry=binary('transfer_entry',f' mov_s r12,{RECORDER:#x}\n j_s [r12]\n');assert len(entry)==8
        b,o=locate(0x1908dc,8);before=images[b['index']][o:o+8];images[b['index']][o:o+8]=entry
        (out/'fixture.json').write_text(json.dumps(dict(replaced_service=hex(0x1908dc),geometry_fixture=dict(address='0x2050000',field='global+0x30',values='per-case start,remaining,512-byte block,status',used_only_for_capacity=True),original_bytes=before.hex(),ram_entry=entry.hex(),recorder=hex(RECORDER),purpose='Record USB IN buffer/length, return success; no USB I/O',assumptions=['Original CBW parser820C00 then explicit entry81F89C; no Bulk-Only task/USB transport','Declared global fields and INQUIRY buffer reset per case; remaining fixture RAM persists','Original registration81DC94/81F7C8, dispatcher, INQUIRY and ABI helpers execute','Default GNU zero RAM; no unknown-read tracking']),indent=2)+'\n')
        cases=[(lun,alloc,present,evpd,page) for lun in (0,1,2) for alloc in (0,4,36,255) for present in (False,True) for evpd,page in [(0,0)]]
        cases += [(0,36,True,evpd,page) for evpd,page in [(1,0),(1,128),(1,131),(1,1),(0,1)]]
        states=bytearray(128*len(cases));asm=''
        def call(a):return f' mov r12,{a:#x}\n jl [r12]\n'
        for i,(lun,alloc,present,evpd,page) in enumerate(cases):
            addr=STATES+i*128
            asm+=f' mov r20,{addr:#x}\n mov r10,{CURRENT:#x}\n st r20,[r10]\n st sp,[r20,4]\n'
            asm+=f' mov r0,{0x139690 if present else 0:#x}\n mov r1,0\n'+call(0x81dc94)
            asm+=f' mov r10,{GLOBAL:#x}\n mov r0,{alloc}\n st r0,[r10,0x74]\n mov r0,0\n st r0,[r10,0x44]\n'
            asm+=f' mov r10,0x553cdc\n mov r0,0xa5a5a5a5\n'
            for off in range(0,256,4):asm+=f' st r0,[r10,{off}]\n'
            cdb=bytes([0x12,evpd,page,0,alloc,0])+bytes(10)
            cbw=b'USBC'+struct.pack('<II',0x10203040,alloc)+bytes([0x80,lun,6])+cdb+bytes(1)
            asm+=f' mov r10,{CDB:#x}\n'
            for off in range(0,16,4):asm+=f' mov r0,0xa5a5a5a5\n st r0,[r10,{off}]\n'
            asm+=f' mov r10,{CDB+0x100:#x}\n'
            for off in range(0,32,4):asm+=f' mov r0,{int.from_bytes(cbw[off:off+4],"little"):#x}\n st r0,[r10,{off}]\n'
            asm+=f' mov r0,{CDB+0x100:#x}\n mov r1,31\n mov r2,{CDB:#x}\n add r3,r20,80\n add r4,r20,84\n add r5,r20,88\n add r6,r20,92\n'+call(0x820c00)
            asm+=' st r0,[r20,96]\n'
            asm+=f' mov r10,{CDB:#x}\n'
            for off in range(0,16,4):asm+=f' ld r0,[r10,{off}]\n st r0,[r20,{100+off}]\n'
            asm+=f' mov r0,{CDB:#x}\n ldb r1,[r20,92]\n'+call(0x81f89c)
            asm+=' st r0,[r20]\n st sp,[r20,8]\n'
            asm+=f' mov r10,{GLOBAL:#x}\n ld r0,[r10,0x40]\n st r0,[r20,12]\n ld r0,[r10,0x74]\n st r0,[r20,16]\n'
            asm+=' mov r10,0x553cdc\n'
            for off in range(0,36,4):asm+=f' ld r0,[r10,{off}]\n st r0,[r20,{32+off}]\n'
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i,data in images.items():mmap(f'block{i}_LAB_ONLY.bin',BS[i]['load_address_candidate'],data)
        mmap('states.bin',STATES,states);mmap('current.bin',CURRENT,bytes(8));mmap('cdb.bin',CDB,bytes(512));mmap('response.bin',0x553c00,bytes(1024))
        elf=compile_probe(r,'inquiry_cases',asm)
        result,log=r.run('inquiry_cases','/result/'+elf.name,maps,trace=True)
        assert result['exit_code']==0 and result['fault'] is None,log
        got=(out/'states.bin').read_bytes();rows=[]
        for i,(lun,alloc,present,evpd,page) in enumerate(cases):
            words=struct.unpack_from('<8I',got,i*128);response=got[i*128+32:i*128+68]
            standard=evpd==0 and page==0
            assert struct.unpack_from('<5I',got,i*128+80)==(0x10203040,alloc,1,lun,0),(i,'CBW outputs')
            assert got[i*128+100:i*128+116]==bytes([0x12,evpd,page,0,alloc,0])+b'\xa5'*10,(i,'original parser CDB copy')
            assert words[1]==words[2] and words[3]==(0x139690 if present else 0),(i,words)
            if standard:
                assert words[0]==0 and words[5]==alloc and words[7]==1,(i,words)
                if present:
                    expected=bytes([0,128,4,2,31,0,0,0])+b' '*8+(b'4MP-CAMERA' if lun==2 else b'4MP-CARD  ').ljust(16,b' ')+b'1.00'
                    assert response==expected,(i,response.hex(),expected.hex())
                else:assert response==bytes([0,0,4,2])+bytes(32),(i,response.hex())
            else:assert words[0]==1 and words[7]==0,(i,words)
            rows.append(dict(lun=lun,allocation=alloc,callback=present,evpd=evpd,page=page,return_value=words[0],stack_restored=True,registered=hex(words[3]),residue=words[4],transfer_length=words[5],transfer_buffer=hex(words[6]),transfers=words[7],response=response.hex()))
        (out/'cpu_cases.json').write_text(json.dumps(rows,indent=2)+'\n')
        pcs=sorted({int(m[1],16) for m in re.finditer(r'^0x([0-9a-f]+)\s',(out/'inquiry_cases.trace').read_text(),re.M)})
        for pc in pcs:
            if 0x1908dc<=pc<0x1908e4:continue
            try:locate(pc,8)
            except ValueError:continue
            check(pc,8)
        assert {0x81fbf2,0x81fbfa,0x139690,0x81fa1e}.issubset(pcs)
        # Capacity uses the original formatter and injected geometry, not NAND I/O.
        geometry=binary('geometry_recorder',f' mov r10,{CURRENT:#x}\n ld r10,[r10]\n ld r1,[r10,80]\n st r1,[r0,8]\n ld r1,[r10,84]\n st r1,[r0,12]\n mov r1,512\n sth r1,[r0,16]\n ld r0,[r10,88]\n j_s [blink]\n')
        mmap('geometry_recorder.bin',0x2050000,geometry+bytes(8+(-len(geometry))%8))
        capacity=[(total,start,0,0,0,8) for total in (512,45056,128000) for start in (0,32)]
        capacity += [(45056,32,0x1b00001,0,0,8),(45056,32,0,1,0,8),(45056,32,0,123,1,8),(45056,32,0,0,0,7),(45056,32,0,0,0,9)]
        capasm=''
        for i,(total,start,error,lba,pmi,residue) in enumerate(capacity):
            a=STATES+i*128
            capasm+=f' mov r20,{a:#x}\n mov r10,{CURRENT:#x}\n st r20,[r10]\n st sp,[r20,4]\n'
            for offset,value in [(80,start),(84,total-start),(88,error)]:capasm+=f' mov r0,{value:#x}\n st r0,[r20,{offset}]\n'
            capasm+=f' mov r10,{GLOBAL:#x}\n mov r0,0x2050000\n st r0,[r10,0x30]\n mov r0,{residue}\n st r0,[r10,0x74]\n mov r10,0x9a3480\n mov r0,2\n stb r0,[r10]\n'
            cdb=bytes([0x25,0])+lba.to_bytes(4,'big')+bytes([0,0,pmi,0])+bytes(6)
            capasm+=f' mov r10,{CDB:#x}\n'
            for off in range(0,16,4):capasm+=f' mov r0,{int.from_bytes(cdb[off:off+4],"little"):#x}\n st r0,[r10,{off}]\n'
            capasm+=f' mov r0,{CDB:#x}\n mov r1,2\n'+call(0x81ff1c)
            capasm+=' st r0,[r20]\n st sp,[r20,8]\n'
        mmap('geometry_global.bin',0x50f500,bytes(128))
        for j,nand_id in enumerate((0xf0,0x76)):
            a=STATES+(len(capacity)+j)*128
            capasm+=f' mov r20,{a:#x}\n st sp,[r20,4]\n mov r0,{nand_id:#x}\n'+call(0x25d194)
            capasm+=' st r0,[r20]\n'
            capasm+=f' mov r10,0x50f52c\n'
            for off in range(0,32,4):capasm+=f' ld r0,[r10,{off}]\n st r0,[r20,{32+off}]\n'
            capasm+=' add r0,r20,80\n add r1,r20,82\n add r2,r20,83\n'+call(0x261478)
            capasm+=' st r0,[r20,12]\n st sp,[r20,8]\n'
        capasm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        (out/'states.bin').write_bytes(bytes(len(states)))
        capelf=compile_probe(r,'capacity_cases',capasm)
        result,log=r.run('capacity_cases','/result/'+capelf.name,maps,trace=True)
        assert result['exit_code']==0 and result['fault'] is None,log
        capgot=(out/'states.bin').read_bytes();caprows=[]
        for i,(total,start,error,lba,pmi,residue) in enumerate(capacity):
            words=struct.unpack_from('<8I',capgot,i*128)
            expected_return=1 if error or (lba and not pmi) or residue>8 else 2 if residue<8 else 0
            assert words[0]==expected_return and words[1]==words[2],(i,words)
            sent=expected_return==0
            assert words[7]==int(sent),(i,words)
            response=capgot[i*128+32:i*128+40]
            if sent:assert response==struct.pack('>II',total-1,512),(i,response.hex())
            caprows.append(dict(total=total,start=start,remaining=total-start,error=hex(error),requested_lba=lba,pmi=pmi,cbw_length=residue,return_value=words[0],transfers=words[7],response=response.hex() if sent else None,stack_restored=True))
        profiles=[]
        for j,(nand_id,cls,pages,sectors) in enumerate(((0xf0,8,64,4),(0x76,7,32,1))):
            a=(len(capacity)+j)*128
            g=capgot[a+32:a+64]
            ret,stack,restored,chs_ret=struct.unpack_from('<4I',capgot,a)
            chs=struct.unpack_from('<HBB',capgot,a+80)
            assert ret==1 and chs_ret==0 and stack==restored and chs==(500,8,32),(j,ret,chs_ret,chs)
            assert (g[0],g[5],g[16],struct.unpack_from('<H',g,8)[0])==(cls,pages,sectors,500 if cls==8 else 1000),(j,g.hex())
            profiles.append(dict(nand_id_fixture=hex(nand_id),geometry_bytes=g.hex(),chs=chs,class_number=cls,sectors=500*8*32-e4*pages*sectors,stack_restored=True))
        (out/'geometry_profile_cases.json').write_text(json.dumps(profiles,indent=2)+'\n')
        (out/'capacity_cases.json').write_text(json.dumps(caprows,indent=2)+'\n')
        for pc in sorted({int(m[1],16) for m in re.finditer(r'^0x([0-9a-f]+)\s',(out/'capacity_cases.trace').read_text(),re.M)}):
            if 0x1908dc<=pc<0x1908e4:continue
            try:locate(pc,8)
            except ValueError:continue
            check(pc,8)
        (out/'executed_spans.json').write_text(json.dumps(spans,indent=2)+'\n')
        assert {str(p.relative_to(ROOT)):sha(p) for p in originals}==inputs
        assert all(sha(Path(p))==digest for p,digest in r.input_hashes.items())
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results['assumptions']=['Explicit lab entries and CDB/CBW fixtures, no task scheduling','USB transfer is a recorder; READ CAPACITY geometry is injected','NAND ID F0/76 are test inputs, not observed hardware state','Default GNU zero RAM, without unknown-read tracking']
        r.results.update(status='PASS_ORIGINAL_INQUIRY_CALLBACK_AND_TABLE',inputs=inputs,tool_inputs=r.input_hashes,script_sha256=sha(Path(__file__)),geometry_profile_cases=len(profiles),cpu_cases=len(rows),capacity_cases=len(caprows),original_spans=len(spans),gnu_windows=len(WINDOWS),scsi_table=table,pool_consumers=len(refs),limits=['Original CBW parser, dispatcher and INQUIRY with USB-transfer recorder; capacity formatter with geometry fixture','No real Bulk-Only, USB, SD, NAND or boot; no physical recovery validation','NAND geometry production and READ10 are statically traced; capacity formatter CPU inputs are fixtures','Callback activation during actual boot remains separate from its verified invocation'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n')
        (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
        print('PASS',len(rows),'CBW/INQUIRY +',len(caprows),'capacity +',len(profiles),'geometry profiles;',out)
    except Exception as exc:
        r.results['assumptions']=['Explicit lab entries and CDB/CBW fixtures, no task scheduling','USB transfer is a recorder; READ CAPACITY geometry is injected','NAND ID F0/76 are test inputs, not observed hardware state','Default GNU zero RAM, without unknown-read tracking']
        r.results.update(status='FAIL',error=repr(exc))
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n')
        raise


if __name__=='__main__':main()
