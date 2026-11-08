#!/usr/bin/env python3
"""Verify V1.1 diagnostic key-command dispatch with event-post fixture."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32, disasm
from catalog_hiddenmenu import parse_lines


def main():
    out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('script_key_events_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-script-key-events'))
    print('Prove:',out,flush=True)
    try:
        r.prepare()
        dump=ROOT/'DUMPS/MainCode.dmp';source=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
        assert u32(0x809f74)==0x9a0d20 and u32(0x809f6c)==0x1274
        table=raw(0x9a0d20,0x1274);position=0;records=[]
        while position<len(table):
            start=position;kind=table[position];position+=1
            end=table.index(0,position);name=table[position:end].decode('ascii');position=end+1
            args=[]
            while position<len(table) and table[position]!=7:args.append(table[position]);position+=1
            assert position<len(table);position+=1
            records.append(dict(index=len(records),name=name,address=hex(0x9a0d20+start),kind=kind,args=args))
        assert position==len(table) and len(records)==234
        definitions=[('KeyUp',58,0x80be84,0x380,255),('KeyDown',38,0x80bc7c,0x400,255),
                     ('KeyLeft',45,0x80bd4c,0x480,255),('KeyRight',54,0x80bde8,0x500,255),
                     ('KeyOK',48,0x80bf9c,0x580,0),('KeyMenu',46,0x80bf34,0x700,0)]
        for name,index,entry,event,arg in definitions:
            assert records[index]['name']==name and records[index]['args']==[0]
        windows=[(0x809f78,0x809fb0),(0x80a2b0,0x80a2c0),(0x80a320,0x80a360),
                 (0x80a3a0,0x80a3b0),(0x80a3dc,0x80a3ec)]
        windows += [(entry,entry+0x2e) for _,_,entry,_,_ in definitions]
        lines=[];spans=[]
        for start,end in windows:
            block,offset=locate(start,end-start);data=raw(start,end-start)
            assert source[block['offset']+offset:block['offset']+offset+len(data)]==data
            text=disasm(start,end);lines.append(text);spans.append(dict(start=hex(start),end=hex(end)))
        (out/'gnu_verified.txt').write_text('\n'.join(lines))
        image=bytearray(PS[0]);maps=[]
        def binary(name,asm):
            elf=compile_probe(r,name,asm);path=out/(name+'.bin')
            result=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path])
            assert result.returncode==0,result.stdout
            data=path.read_bytes();path.write_bytes(data+bytes(8+(-len(data))%8))
            return path
        def mapping(path,address,size):return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{address:#x},{size}']
        recorder=binary('event_recorder',''' mov r10,0x2000000
 ld r10,[r10]
 ld r11,[r10,0]
 asl r12,r11,4
 add r12,r12,16
 add r12,r12,r10
 st r0,[r12]
 st r1,[r12,4]
 st r2,[r12,8]
 add r11,r11,1
 st r11,[r10,0]
 mov r0,0
 j_s [blink]
''')
        maps+=mapping(recorder,0x2030000,recorder.stat().st_size)
        entry=binary('event_entry',' mov_s r12,0x2030000\n j_s [r12]\n').read_bytes()[:8]
        block,offset=locate(0x169eb4,8);assert block['index']==0 and image[offset:offset+8]==raw(0x169eb4,8)
        original=bytes(image[offset:offset+8]);image[offset:offset+8]=entry
        tests=[(name,index,target,event,arg,value) for name,index,target,event,arg in definitions for value in (0,1)]
        state=bytearray(len(tests)*128);asm=' mov r20,0x2000000\n'
        for i,(name,index,target,event,arg,value) in enumerate(tests):
            address=0x2001000+i*128
            struct.pack_into('<2I',state,i*128+64,address+68,value)
            asm+=f' mov r21,{address:#x}\n st r21,[r20]\n st sp,[r21,48]\n mov r0,{address+64:#x}\n mov r1,{index}\n mov r12,0x809f78\n jl [r12]\n st sp,[r21,52]\n'
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i,data in [(0,image),(1,PS[1]),(4,PS[4]),(5,PS[5])]:
            path=out/f'block{i}_LAB_FIXTURE.bin';path.write_bytes(data);maps+=mapping(path,BS[i]['load_address_candidate'],len(data))
        state_file=out/'cases.bin';state_file.write_bytes(state);maps+=mapping(state_file,0x2001000,len(state))
        current=out/'current.bin';current.write_bytes(bytes(8));maps+=mapping(current,0x2000000,8)
        elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
        assert case['exit_code']==0 and case['fault'] is None,log
        got=state_file.read_bytes();results=[]
        for i,(name,index,target,event,arg,value) in enumerate(tests):
            b=i*128;count=struct.unpack_from('<I',got,b)[0]
            first=struct.unpack_from('<3I',got,b+16);second=struct.unpack_from('<3I',got,b+32)
            sp=struct.unpack_from('<2I',got,b+48)
            assert count==2 and first==(0,event,arg) and second==(0,event+1,0) and sp[0]==sp[1],(name,value,count,first,second,sp)
            results.append(dict(name=name,table_index=index,input=value,handler=hex(target),
                                events=[dict(destination=first[0],event=hex(first[1]),argument=first[2]),
                                        dict(destination=second[0],event=hex(second[1]),argument=second[2])],stack_preserved=True))
        (out/'cases.json').write_text(json.dumps(results,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_SCRIPT_KEY_DISPATCH_WITH_EVENT_FIXTURE',scenarios=results,
            original_post_bytes=original.hex(),fixture_post_bytes=entry.hex(),
            assumptions=['Original script dispatcher 809F78 and key handlers; 169EB4 replaced by event recorder.',
                         'Synthetic argument cells and stack; input is not produced by physical keys.'],
            limits=['No parser invocation, WindowMgr routing, real event queues or camera hardware.',
                    'Command names identify diagnostic script records, not physical button labels.',
                    'Only inputs 0 and 1 were used; downstream effects of the posted arguments are untested.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS script key dispatcher with event fixture:',out,flush=True)


if __name__=='__main__':main()
