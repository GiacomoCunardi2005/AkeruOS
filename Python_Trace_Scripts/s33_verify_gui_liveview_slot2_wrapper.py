#!/usr/bin/env python3
"""Compare events 2180 and 700 through the original CaptureLiveview wrapper."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import shutil
import struct
import sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32, disasm
from catalog_hiddenmenu import parse_lines


def main():
    previous=ROOT/'Risultati/GUI_S33/liveview_key14_20261027T112823Z'
    out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('liveview_slot2_wrapper_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-liveview-slot2-event'))
    print('Prove:',out,flush=True)
    try:
        r.prepare();evidence=previous/'verified_evidence.json'
        assert json.loads(evidence.read_text())['status']=='PASS_LIVEVIEW_KEY14_BOUNDED_CALLBACK'
        patches=json.loads((previous/'fixture_patches.json').read_text())
        assert len(patches)==9 and patches[0]['name']=='key'
        for p in (evidence,previous/'fixture_patches.json'):
            r.input_hashes[str(p)]=sha(p)
        dump=ROOT/'DUMPS/MainCode.dmp';source=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
        assert u32(0x65273c)==0x681e74 and u32(0x65274c)==0x681f09
        assert u32(0x652750)==0x681e80 and u32(0x652754)==0x7833ec
        assert u32(0x78349c)==0x2180 and u32(0x7834a0)==0x655f34
        assert u32(0x783434)==0x700 and u32(0x783438)==0x65426c
        assert b'ShootingMode\0' in raw(u32(0x3f5900+7*4), 64)
        for address, size in [(0x7833ec, 0x140), (0x3f591c, 4), (u32(0x3f591c), 64)]:
            block, offset = locate(address, size)
            assert source[block['offset'] + offset:block['offset'] + offset + size] == raw(address, size)
        windows=[(0x6524f4,0x6526c0),(0x6526c0,0x65273c),(0x169f60,0x169fb4),(0x655f34,0x655f74),(0x65426c,0x654328)]
        rows={};listings=[]
        for start,end in windows:
            block,offset=locate(start,end-start);data=raw(start,end-start)
            assert source[block['offset']+offset:block['offset']+offset+len(data)]==data
            text=disasm(start,end);listings.append(text)
            rows.update({x['address']:x for x in parse_lines(text)})
        for pc,op,arg in [(0x6525f0,'cmp_s','r14,0xe'),(0x652702,'cmp_s','r14,0xe'),
                          (0x65272a,'bl',';0x169f60'),(0x169fac,'jl_s.d','[r3]'), (0x655f4c,'cmp_s','r0,0x38'), (0x655f68,'mov_s','r0,0x7'), (0x655f6c,'bl',';0x1453e4')]:
            assert rows[pc]['op']==op and arg in rows[pc]['args'],rows[pc]
        (out/'gnu_verified.txt').write_text('\n'.join(listings))
        images={i:bytearray(PS[i]) for i in (0,1,2,3)};maps=[]
        def binary(name,asm):
            elf=compile_probe(r,name,asm);p=out/(name+'.bin')
            result=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p])
            assert result.returncode==0,result.stdout
            data=p.read_bytes();p.write_bytes(data+bytes(8+(-len(data))%8))
            return p
        def mapping(p,address,size):return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{address:#x},{size}']
        key=binary('key_with_s1',''' mov r10,0x2000000
 ld r10,[r10]
 cmp r0,1
 beq key1
 cmp r0,7
 beq key7
 cmp r0,8
 beq key8
 cmp r0,9
 beq key9
 cmp r0,10
 beq key10
 mov r0,0
 j_s [blink]
key1:
 ld r0,[r10,60]
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
''')
        for i,p in enumerate(patches):
            address=int(p['address'],16);block,offset=locate(address,8)
            before=bytes(images[block['index']][offset:offset+8])
            assert before.hex()==p['original'] and before==raw(address,8)
            images[block['index']][offset:offset+8]=bytes.fromhex(p['fixture'])
            old=previous/(p['name']+'.bin');r.input_hashes[str(old)]=sha(old)
            if i==0:fixture=key
            else:
                fixture=out/(p['name']+'.bin');shutil.copyfile(old,fixture)
            maps+=mapping(fixture,0x2030000+i*0x400,fixture.stat().st_size)
        common=' mov r10,0x2000000\n ld r10,[r10]\n'
        added=[]
        for i,(name,address,asm) in enumerate([
            ('wrapper_precheck',0xcfdec,' mov r0,0\n j_s [blink]\n'),
            ('wrapper_guard',0xd0270,common+' ld r0,[r10,56]\n j_s [blink]\n')]):
            target=0x2040000+i*0x400;fixture=binary(name,asm);maps+=mapping(fixture,target,fixture.stat().st_size)
            entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
            block,offset=locate(address,8);before=bytes(images[block['index']][offset:offset+8])
            assert before==raw(address,8);images[block['index']][offset:offset+8]=entry
            added.append(dict(name=name,address=hex(address),original=before.hex(),fixture=entry.hex()))
        # Synthetic context bytes are reset each case; no physical state inferred.
        tests=[
            dict(name='normal_0a',mode=0x0a,expected=7),
            dict(name='normal_46',mode=0x46,expected=7),
            dict(name='mode38_state7_blocks',mode=0x38,mode_state=7,expected=None),
            dict(name='mode38_state8_blocks',mode=0x38,mode_state=8,expected=None),
            dict(name='mode38_state0_passes',mode=0x38,mode_state=0,expected=7),
            dict(name='mode39_state7_passes',mode=0x39,mode_state=7,expected=7),
            dict(name='handler_guard_blocks',mode=0x0a,other_guard=1,expected=None),
            dict(name='filter_event_blocks',mode=0x0a,filter_event=0x2180,expected=None),
            dict(name='filter_other_passes',mode=0x0a,filter_event=0x4004,expected=7),
            dict(name='event700_mode0a',event=0x700,mode=0x0a,expected=2),
            dict(name='event700_mode46',event=0x700,mode=0x46,expected=2),
            dict(name='event700_mode38_state7',event=0x700,mode=0x38,mode_state=7,expected=None),
            dict(name='event700_filter_blocks',event=0x700,mode=0x0a,filter_event=0x700,expected=None),
        ]
        state=bytearray(len(tests)*128);asm=' mov r20,0x2000000\n'
        def write8(address,value):return f' mov r1,{address:#x}\n mov r0,{value}\n stb r0,[r1]\n'
        for i,t in enumerate(tests):
            addr=0x2001000+i*128
            struct.pack_into('<I',state,i*128,t.get('key7',0))
            struct.pack_into('<I',state,i*128+8,t.get('key9',0))
            struct.pack_into('<I',state,i*128+20,t['mode'])
            struct.pack_into('<I',state,i*128+24,t.get('mode_state',0))
            struct.pack_into('<I',state,i*128+28,t.get('other_guard',0))
            struct.pack_into('<I',state,i*128+56,t.get('guard',0))
            struct.pack_into('<I',state,i*128+60,t.get('key1',0))
            asm+=f' mov r21,{addr:#x}\n st r21,[r20]\n st sp,[r21,48]\n'
            for address,value in [(0x681e74+143,t.get('ctx143',0)),(0x681e74+144,t.get('ctx144',0)),
                                  (0x681e74+117,0),(0x681e74+0x1c,0),(0x681e74+0x14,0),
                                  (0x681f09,t.get('selector',0))]:asm+=write8(address,value)
            asm+=f' mov r1,0x681e80\n mov r0,{t.get("filter_event",0x4004)}\n sth r0,[r1]\n mov r0,0\n sth r0,[r1,2]\n'
            asm+=f' mov r0,0\n mov r1,{t.get("event",0x2180):#x}\n mov r2,0\n mov r12,0x6524f4\n jl [r12]\n st sp,[r21,52]\n'
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i,data in images.items():
            p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(data);maps+=mapping(p,BS[i]['load_address_candidate'],len(data))
        state_path=out/'cases.bin';state_path.write_bytes(state);maps+=mapping(state_path,0x2001000,len(state))
        p=out/'current.bin';p.write_bytes(bytes(8));maps+=mapping(p,0x2000000,8)
        elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
        assert case['exit_code']==0 and case['fault'] is None,log
        got=state_path.read_bytes();results=[]
        for i,t in enumerate(tests):
            w=struct.unpack_from('<16I',got,i*128);expected=t['expected']
            assert w[12]==w[13] and w[10]==int(expected is not None) and w[8]==(expected or 0) and w[9]==0,(t,w)
            results.append(dict(**t, input_event=hex(t.get("event",0x2180)), open_count=w[10],destination=hex(w[8]) if w[10] else None,stack_preserved=True))
        trace=(out/'cases.trace').read_text()
        assert any(line.startswith('0x65426c ') for line in trace.splitlines())
        assert any(line.startswith('0x655f34 ') for line in trace.splitlines())
        (out/'cases.json').write_text(json.dumps(results,indent=2)+'\n')
        (out/'fixture_patches.json').write_text(json.dumps(dict(inherited=patches,added=added,key_fixture='key_with_s1'),indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_WRAPPER_EVENTS_2180_700_BOUNDED',scenarios=results,
            assumptions=['Original wrapper 6524F4, 169F60 dispatch, callbacks 655F34 and 65426C, and shared epilogues.',
                         'Original table plus synthetic per-case context/filter; eleven external service fixtures.',
                         'Opening 1453E4 is a recorder, not the real window manager.'],
            limits=['Input event is injected at wrapper; no physical key or event queue/scheduler.',
                    'Only tested events 2180 and 700 and stated guard values; other modes/events/branches remain open.',
                    'No screen rendering or physical camera execution.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS wrapper and events 2180/700:',out,flush=True)


if __name__=='__main__':main()
