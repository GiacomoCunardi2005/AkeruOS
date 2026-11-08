#!/usr/bin/env python3
"""Execute the V1.1 CaptureLiveview key-14 callback with explicit service fixtures."""
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
    out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('liveview_key14_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-liveview-key14-callback'))
    print('Prove:',out,flush=True)
    try:
        r.prepare()
        dump=ROOT/'DUMPS/MainCode.dmp';source=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
        assert u32(0x7833ec+9*8)==0x700 and u32(0x7833ec+9*8+4)==0x65426c
        assert u32(0x654328)==0x16f920 and u32(0x65432c)==0xcad30
        spans=[(0x65426c,0x654328),(0x6541e0,0x654214)]
        text=[];rows={}
        for start,end in spans:
            block,offset=locate(start,end-start);data=raw(start,end-start)
            assert source[block['offset']+offset:block['offset']+offset+len(data)]==data
            listing=disasm(start,end);text.append(listing)
            rows.update({x['address']:x for x in parse_lines(listing)})
        for pc,op,fragment in [(0x6542ec,'cmp_s','r0,0x46'),(0x6542f2,'cmp_s','r0,0xa'),
                               (0x6542f6,'mov_s','r0,0x2'),(0x6542fa,'mov_s','r0,0x9b'),
                               (0x6542fe,'bl',';0x1453e4'),(0x654322,'bl',';0x169eb4')]:
            assert rows[pc]['op']==op and fragment in rows[pc]['args'],rows[pc]
        (out/'gnu_verified.txt').write_text('\n'.join(text))
        images={i:bytearray(PS[i]) for i in (0,1,2,3)};maps=[];patches=[]
        def binary(name,asm):
            elf=compile_probe(r,name,asm);path=out/(name+'.bin')
            result=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path])
            assert result.returncode==0,result.stdout
            data=path.read_bytes();path.write_bytes(data+bytes(8+(-len(data))%8))
            return path
        def mapping(path,address,size):
            return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{address:#x},{size}']
        common=' mov r10,0x2000000\n ld r10,[r10]\n'
        services=[
            ('key',0x16f920,common+''' cmp r0,7
 beq key7
 cmp r0,8
 beq key8
 cmp r0,9
 beq key9
 cmp r0,10
 beq key10
 mov r0,0
 j_s [blink]
key7:
 ld r0,[r10]
 j_s [blink]
key8:
 ld r0,[r10,4]
 j_s [blink]
key9:
 ld r0,[r10,8]
 j_s [blink]
key10:
 ld r0,[r10,12]
 j_s [blink]
'''),
            ('guard',0x12845c,common+' ld r0,[r10,16]\n j_s [blink]\n'),
            ('mode',0xcad30,common+' ld r0,[r10,20]\n j_s [blink]\n'),
            ('state',0xcad28,common+' ld r0,[r10,24]\n j_s [blink]\n'),
            ('other_guard',0x657928,common+' ld r0,[r10,28]\n j_s [blink]\n'),
            ('clear',0x6561b4,' mov r0,0\n j_s [blink]\n'),
            ('aux',0xcdaa0,' mov r0,0\n j_s [blink]\n'),
            ('open',0x1453e4,common+' st r0,[r10,32]\n st r1,[r10,36]\n ld r11,[r10,40]\n add r11,r11,1\n st r11,[r10,40]\n mov r0,0\n j_s [blink]\n'),
            ('post',0x169eb4,common+' ld r11,[r10,44]\n add r11,r11,1\n st r11,[r10,44]\n mov r0,0\n j_s [blink]\n'),
        ]
        for i,(name,address,asm) in enumerate(services):
            target=0x2030000+i*0x400;payload=binary(name,asm);maps+=mapping(payload,target,payload.stat().st_size)
            entry_file=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n')
            entry=entry_file.read_bytes()[:8]
            assert len(entry)==8
            block,offset=locate(address,8);before=images[block['index']][offset:offset+8]
            assert before==raw(address,8)
            images[block['index']][offset:offset+8]=entry
            patches.append(dict(name=name,address=hex(address),original=bytes(before).hex(),fixture=entry.hex()))
        tests=[('mode46',(0,0,0,0),0,0x46,0,0,2),('mode0a',(0,0,0,0),0,0x0a,0,0,2),
               ('modeother',(0,0,0,0),0,0x2c,0,0,0x9b),('mode38_allowed',(0,0,0,0),0,0x38,0,0,0x9b),
               ('mode38_block7',(0,0,0,0),0,0x38,7,0,None),('mode38_block8',(0,0,0,0),0,0x38,8,0,None),
               ('guard',(0,0,0,0),1,0x46,0,0,None),('other_guard',(0,0,0,0),0,0x46,0,1,None)]
        tests += [(f'key{k}',tuple(int(i==k) for i in range(4)),0,0x46,0,0,None) for k in range(4)]
        tests = [(route,)+test for route in ('direct','event_table') for test in tests]
        state=bytearray(len(tests)*128);asm=' mov r20,0x2000000\n'
        for i,(route,name,keys,guard,mode,mode_state,other,dest) in enumerate(tests):
            struct.pack_into('<8I',state,i*128,*keys,guard,mode,mode_state,other)
            addr=0x2001000+i*128
            asm+=f' mov r21,{addr:#x}\n st r21,[r20]\n st sp,[r21,48]\n'
            if route=='direct':
                asm+=' mov r0,0\n mov r1,0x700\n mov r2,0\n mov r12,0x65426c\n jl [r12]\n'
            else:
                asm+=' mov r0,0\n mov r1,0x7833ec\n mov r2,0\n mov r3,0x700\n mov r4,0\n mov r12,0x169f60\n jl [r12]\n'
            asm+=' st sp,[r21,52]\n'
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i,data in images.items():
            path=out/f'block{i}_LAB_FIXTURE.bin';path.write_bytes(data);maps+=mapping(path,BS[i]['load_address_candidate'],len(data))
        state_path=out/'cases.bin';state_path.write_bytes(state);maps+=mapping(state_path,0x2001000,len(state))
        current=out/'current.bin';current.write_bytes(bytes(8));maps+=mapping(current,0x2000000,8)
        elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
        assert case['exit_code']==0 and case['fault'] is None,log
        got=state_path.read_bytes();results=[]
        for i,(route,name,keys,guard,mode,mode_state,other,dest) in enumerate(tests):
            words=struct.unpack_from('<14I',got,i*128)
            assert words[12]==words[13],(name,words)
            assert words[10]==int(dest is not None) and words[8]==(dest or 0) and words[9]==0,(name,words)
            assert words[11]==0,(name,words)
            results.append(dict(route=route,case=name,key_states=keys,guard=guard,mode=hex(mode),mode_state=mode_state,
                                other_guard=other,open_count=words[10],destination=hex(dest) if dest is not None else None,
                                argument=words[9],stack_preserved=True))
        (out/'cases.json').write_text(json.dumps(results,indent=2)+'\n')
        (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_LIVEVIEW_KEY14_BOUNDED_CALLBACK',scenarios=results,
            assumptions=['Original 65426C callback, shared epilogue and optional 169F60 table dispatch; explicit fixtures for nine services.',
                         'Injected key event and synthetic caller, keys, mode and RAM; open manager is a recorder.'],
            limits=['No key hardware, WindowMgr event routing, 6524F4 wrapper filter, real UI manager, display or camera execution.',
                    'Conditional branches for auxiliary service returning nonzero and later key transitions are not exercised.',
                    'Key14 physical label and mode values 46/0A have not been identified.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS liveview key14 callback, bounded fixtures:',out,flush=True)


if __name__=='__main__':main()
