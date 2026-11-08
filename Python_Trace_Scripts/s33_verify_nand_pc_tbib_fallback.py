#!/usr/bin/env python3
"""Execute TBIB source guards, their producer and routing with explicit lab inputs."""
from datetime import datetime,timezone
from itertools import product
from pathlib import Path
from types import SimpleNamespace
import json,struct
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe

BASE,CURRENT,ROWS=0x1000000,0x2010000,0x2100000
GPIO,RXA,RXB=0xfed2068,0xfe70224,0xfe70228
OBJECT=0x1095a3c


def main():
    out=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('tbib_fallback_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='TBIB-fallback-guard-producer-and-source-routing'));r.prepare()
    try:
        firmware=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';body=firmware.read_bytes()[0x7c:0x44c38]
        r.input_hashes[str(Path(__file__))]=sha(Path(__file__))
        def word(address):return struct.unpack_from('<I',body,address-BASE)[0]
        assert [word(a)for a in [0x10033b4,0x1025aa4,0x1025ab4,0x1005a6c]]==[GPIO,RXA,RXB,OBJECT]
        def mmap(maps,name,address,data):
            path=out/name;path.write_bytes(bytes(address%8)+data);maps.extend(['--memory-mapfile','/result/'+name,'--memory-region',f'{address:#x},{len(data)}']);return path
        def binary(name,asm):
            elf=compile_probe(r,name,asm);path=out/(name+'.bin');v=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path]);assert v.returncode==0,v.stdout;return path.read_bytes()
        def call(address):return f' mov r12,{address:#x}\n jl [r12]\n'
        def store(address,value,byte=False):return f' mov r10,{address:#x}\n mov r0,{value:#x}\n '+('stb'if byte else'st')+' r0,[r10]\n'
        def entry(target):
            code=binary('entry_'+hex(target),f' mov_s r12,{target:#x}\n j_s [r12]\n');assert len(code)==8;return code
        # Every possible halfword, through the original read and inversion chain.
        maps=[];mmap(maps,'guard_tbib.bin',BASE,body);mmap(maps,'guard_gpio.bin',GPIO,bytes(2));state=mmap(maps,'guard_state.bin',CURRENT,bytes(16))
        asm=store(0x1041104,0,True)+store(0x1041274,0,True)+f' mov r21,0\n mov r22,{GPIO:#x}\nloop:\n sth r21,[r22]\n'+call(0x1000488)
        asm+=' lsr r1,r21,4\n and r1,r1,1\n xor r1,r1,1\n cmp r0,r1\n bne fail\n add r21,r21,1\n cmp r21,0x10000\n blo loop\n'
        asm+=f' mov r10,{CURRENT:#x}\n st r21,[r10]\n mov r0,0\n b finish\nfail:\n mov r0,7\nfinish:\n mov r8,1\n trap_s 1\n'
        elf=compile_probe(r,'guard_all_halfwords',asm);case,log=r.run('guard_all_halfwords','/result/'+elf.name,maps);assert case['exit_code']==0 and case['fault']is None,log
        assert struct.unpack_from('<I',state.read_bytes())[0]==65536
        # An absent mapping makes an accidental MMIO read fail in the bypass cases.
        maps=[];mmap(maps,'bypass_tbib.bin',BASE,body);state=mmap(maps,'bypass_state.bin',ROWS,bytes(5*16));asm=''
        bypass=[(1,0,1),(2,0,1),(255,255,1),(0,1,0),(0,255,0)]
        for i,(flag,mode,_)in enumerate(bypass):
            asm+=store(0x1041104,flag,True)+store(0x1041274,mode,True)+call(0x1000488)+f' mov r10,{ROWS+i*16:#x}\n st r0,[r10]\n'
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n';elf=compile_probe(r,'guard_no_mmio',asm);case,log=r.run('guard_no_mmio','/result/'+elf.name,maps);assert case['exit_code']==0 and case['fault']is None,log
        assert [struct.unpack_from('<I',state.read_bytes(),i*16)[0]for i in range(5)]==[x[2]for x in bypass]
        # Original two-register producer -> getter -> flag-update fragment.
        producer=bytearray(body);maps=[];patches=[]
        for address,target,code in [(0x1025a40,0x2030000,f' mov r10,{CURRENT:#x}\n ld r6,[r10]\n add r6,r6,1\n st r6,[r10]\n st r0,[r10,8]\n mov r0,0\n j_s [blink]\n'),(0x100135c,0x2030400,f' mov r10,{CURRENT:#x}\n ld r6,[r10,4]\n add r6,r6,1\n st r6,[r10,4]\n mov r0,0\n j_s [blink]\n'),(0x10002c8,0x2030800,' j [r23]\n')]:
            data=binary(f'producer_{address:x}',code);mmap(maps,f'producer_{address:x}.bin',target,data+bytes(16));at=address-BASE;patches.append(dict(cpu=hex(address),original=producer[at:at+8].hex(),lab=hex(target)));producer[at:at+8]=entry(target)
        mmap(maps,'producer_tbib_LAB.bin',BASE,producer);counts=mmap(maps,'producer_counts.bin',CURRENT,bytes(16));object_path=mmap(maps,'producer_object.bin',OBJECT,b'\xa5'*128)
        mmap(maps,'producer_rxa.bin',RXA,bytes(2));mmap(maps,'producer_rxb.bin',RXB,bytes(2));state=mmap(maps,'producer_rows.bin',ROWS,bytes(32*32))
        pairs=[(a,b)for a,b in product([0,1,0x1f,0x20,0x3ff,0x8000,0xffff],[0,1,0x3ff,0x8000])];assert len(pairs)==28
        asm=''
        for i,(a,b)in enumerate(pairs):
            at=ROWS+i*32
            asm+=f' mov r20,{at:#x}\n st sp,[r20,12]\n mov r10,{RXA:#x}\n mov r0,{a}\n sth r0,[r10]\n mov r10,{RXB:#x}\n mov r0,{b}\n sth r0,[r10]\n'
            asm+=call(0x1018390)+call(0x1005a2c)+' st r0,[r20]\n'+store(0x1041104,0,True)+store(0x1041105,1,True)
            asm+=f' mov r17,0\n mov r23,resume_{i}\n mov r12,0x10002a4\n j [r12]\nresume_{i}:\n mov r10,0x104112c\n ld r0,[r10]\n st r0,[r20,4]\n mov r10,0x1041104\n ldh r0,[r10]\n st r0,[r20,8]\n st sp,[r20,16]\n'
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n';elf=compile_probe(r,'producer_flags',asm);case,log=r.run('producer_flags','/result/'+elf.name,maps);assert case['exit_code']==0 and case['fault']is None,log
        produced=[];data=state.read_bytes()
        for i,(a,b)in enumerate(pairs):
            w=struct.unpack_from('<5I',data,i*32);value=(a<<10)|b;early=not bool(value&0x8000);assert w==(value,(~value)&0xffffffff,1 if early else 0x100,w[3],w[3]),(i,w)
            produced.append(dict(register224=hex(a),register228=hex(b),word=hex(w[0]),complement=hex(w[1]),early_B=int(early),fallback_B=int(not early),stack_preserved=True))
        assert struct.unpack_from('<3I',counts.read_bytes())==(28,28,1)
        actual=object_path.read_bytes()[OBJECT%8:];expected=bytearray(b'\xa5'*128);last=(pairs[-1][0]<<10)|pairs[-1][1];struct.pack_into('<HH',expected,0x28,last>>16,last&65535);struct.pack_into('<I',expected,0x30,last);assert actual==expected
        # BootTask source routing: services record outcomes, original guard remains.
        routing=bytearray(body);maps=[];route_patches=[]
        for index,(address,kind,offset)in enumerate([(0x10069e0,1,4),(0x10010c0,2,8),(0x100125c,3,None),(0x10004a4,4,None),(0x1006998,5,None),(0x100b5b0,6,None)]):
            target=0x2040000+index*0x400
            code=f''' mov r10,{CURRENT:#x}
 ld r10,[r10]
 ld r11,[r10]
 asl r12,r11,4
 add r12,r12,r10
 add r12,r12,64
 mov r9,{kind}
 st r9,[r12]
 st r0,[r12,4]
 st r1,[r12,8]
 st r2,[r12,12]
 add r11,r11,1
 st r11,[r10]
'''
            if kind==3:code+=' ldb r0,[r0]\n cmp r0,65\n bne file_b\n ld r0,[r10,12]\n j_s [blink]\nfile_b:\n ld r0,[r10,16]\n j_s [blink]\n'
            else:code+=(f' ld r0,[r10,{offset}]\n'if offset is not None else' mov r0,0\n')+' j_s [blink]\n'
            data=binary(f'routing_{address:x}',code);mmap(maps,f'routing_{address:x}.bin',target,data+bytes(16));at=address-BASE;route_patches.append(dict(cpu=hex(address),original=routing[at:at+8].hex(),lab=hex(target)));routing[at:at+8]=entry(target)
        tbib_path=mmap(maps,'routing_tbib_LAB.bin',BASE,routing);mmap(maps,'routing_current.bin',CURRENT,bytes(8));mmap(maps,'routing_gpio.bin',GPIO,bytes(2))
        specs=list(product(range(2),repeat=8));states=bytearray(len(specs)*256)
        for i,(_,_,_,_,wait,sector,a,b)in enumerate(specs):struct.pack_into('<4I',states,i*256+4,0x101 if wait else 0,7 if sector else 0,9 if a else 0,11 if b else 0)
        state=mmap(maps,'routing_rows.bin',ROWS,states);asm=''
        for i,(early,late,mode,bit,wait,sector,a,b)in enumerate(specs):
            at=ROWS+i*256
            asm+=f' mov r20,{at:#x}\n mov r10,{CURRENT:#x}\n st r20,[r10]\n st sp,[r20,20]\n'
            asm+=store(0x1041104,early,True)+store(0x1041105,late,True)+store(0x1041274,mode,True)+store(0x1041120,0x900)+store(0x928,0x7f,True)
            asm+=f' mov r10,{GPIO:#x}\n mov r0,{bit<<4}\n sth r0,[r10]\n'+call(0x1001384)+' st r0,[r20,28]\n st sp,[r20,24]\n mov r10,0x1041108\n ld r0,[r10]\n st r0,[r20,32]\n mov r10,0x928\n ldb r0,[r10]\n st r0,[r20,36]\n'
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n';elf=compile_probe(r,'source_routing',asm);case,log=r.run('source_routing','/result/'+elf.name,maps);assert case['exit_code']==0 and case['fault']is None,log
        observed=[];data=state.read_bytes()
        for i,spec in enumerate(specs):
            early,late,mode,bit,wait,sector,a,b=spec;w=struct.unpack_from('<10I',data,i*256);assert w[5]==w[6]and w[7]==0,(spec,w)
            records=[struct.unpack_from('<4I',data,i*256+64+j*16)for j in range(w[0])];path=[]
            for kind,x,y,z in records:
                if kind==2:path.append('sectors')
                if kind==3:
                    drive=body[x-BASE:x-BASE+2].decode();filename=body[y-BASE:].split(b'\0')[0].decode();assert filename==drive+'\\TBM_SK501.BIN';path.append(drive)
            status=0x101 if wait else 0;info=0x7f;wanted=[]
            if not wait:
                if early:wanted.append('B:');status=11 if b else 0
                if not early or status:
                    wanted.append('sectors');status=7 if sector else 0
                    if not status:info=0x10
                    else:
                        info=0x20;wanted.append('A:');status=9 if a else 0
                        if status and late and (early or (mode==0 and bit==0)):wanted.append('B:');status=11 if b else 0
                if early and wanted==['B:']and status==0:info=0x20
            assert path==wanted and (w[8],w[9])==(status,info),(spec,path,wanted,w,status,info)
            assert [v[1]for v in records if v[0]==4]==[1,2] and sum(v[0]==5 for v in records)==sum(v[0]==6 for v in records)==1
            observed.append(dict(inputs=dict(zip(['early','fallback','mode','bit4','wait_error','sector_error','A_error','B_error'],spec)),sources=path,status=status,info_mode=hex(info),stack_preserved=True))
        for name,rows in [('producer_cases.json',produced),('routing_cases.json',observed),('producer_patches.json',patches),('routing_patches.json',route_patches)]: (out/name).write_text(json.dumps(rows,indent=2)+'\n')
        windows=[(0x1000488,0x10004a0),(0x1007168,0x1007188),(0x101fcc4,0x101fcd4),(0x10033ac,0x10033c4),(0x1025a9c,0x1025ac4),(0x1018390,0x10183ac),(0x1005a2c,0x1005a34),(0x10002a4,0x10002c8),(0x1001384,0x1001440)]
        for a,b in windows:
            v=r.command(f'gnu_{a:x}',[TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',out/'tbib.elf']);assert v.returncode==0 and'out of bounds'not in v.stdout
        assert all(sha(Path(f))==h for f,h in r.input_hashes.items());(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_TBIB_GUARD_PRODUCER_AND_ROUTING_ONLY',guard_halfwords=65536,guard_bypass_cases=5,producer_cases=28,routing_cases=256,input_hashes=r.input_hashes,assumptions=['Original TBIB bodies; file/sector/event/stage/scheduler services recorded only for routing','MMIO maps are explicit laboratory halfwords, not hardware values','Init fragment begins at010002A4 withr17=0 and stops at010002C8; task creation replaced'],limits=['No physical source namespace A/B, key assignment, card detection or MCU field semantics established','No filesystem/data loading, ROM boot, task concurrency, handoff or recovery test','Candidate unchanged; no writes or commands to camera'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');(out.parent/'tbib_fallback_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n');print('PASS',out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));(out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');raise

if __name__=='__main__':main()
