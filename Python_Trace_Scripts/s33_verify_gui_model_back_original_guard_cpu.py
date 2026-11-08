#!/usr/bin/env python3
"""Execute the original CaptureMenu Left route with controlled service fixtures."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32, disasm


def main():
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('model_back_original_guard_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='model-back-original-guard'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        dump = ROOT / 'DUMPS/MainCode.dmp'; data = dump.read_bytes(); r.input_hashes[str(dump)] = sha(dump)
        sources=[ROOT/'AkeruOS/ui/menu.c',ROOT/'AkeruOS/ui/menu.h',Path(__file__)]
        for p in sources:r.input_hashes[str(p)]=sha(p)
        spans = [(0x7cafe8, 0x7cb020), (0x7cb0f8, 0x7cb118), (0x20e814, 0x20e848),
                 (0x20e940, 0x20ea5c), (0x169f60, 0x169fb4), (0x16e41c, 0x16e440),
                 (0x982384, 0x9823b4), (0x3e8bb4, 0x3e8c58), (0x9802ac, 0x9802c4), (0x783ae8, 0x783b00),
                 (0x3f5908,0x3f590c),(0x3f5b1c,0x3f5b20)]
        for start, end in spans:
            b, o = locate(start, end-start)
            assert raw(start, end-start) == data[b['offset']+o:b['offset']+o+end-start]
        assert u32(0x3f5900+2*4) == 0x9802ac and u32(0x3f5900+0x87*4) == 0x783ae8
        assert u32(0x7cb018) == 0x899858 and u32(0x7cb01c) == 0x982384
        assert u32(0x9823a4) == 0x480 and u32(0x9823a8) == 0x7cb0f8
        assert u32(0x3e8c4c) == 0x2180 and u32(0x3e8c50) == 0x20e940
        (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in [(0x7cafe8,0x7cb018),(0x7cb0f8,0x7cb118),(0x20e814,0x20e844),(0x20e940,0x20ea50),(0x169f60,0x169fb4),(0x16e41c,0x16e440)]))
        images = {i: bytearray(PS[i]) for i in range(7)}; maps=[]; patches=[]
        def binary(name, asm):
            elf = compile_probe(r, name, asm); path = out/(name+'.bin')
            res = r.command(name+'_extract', [TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path])
            assert res.returncode == 0, res.stdout
            b = path.read_bytes(); path.write_bytes(b + bytes(8+(-len(b))%8)); return path
        def mapping(path, address):
            return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{address:#x},{path.stat().st_size}']
        prefix = ' mov r10,0x2000000\n ld r10,[r10]\n'
        services = [
            ('guard_cb',0xcb4a8,prefix+' ld r0,[r10,0]\n j_s [blink]\n'),
            ('guard_cad',0xcad5c,prefix+' ld r0,[r10,4]\n j_s [blink]\n'),
            ('guard_queue',0x17be18,prefix+' ld r0,[r10,8]\n j_s [blink]\n'),
            ('guard_input',0x16f920,prefix+' ld r0,[r10,12]\n j_s [blink]\n'),
            ('pre_open',0x1564c0,prefix+' ld r11,[r10,64]\n add r11,r11,1\n st r11,[r10,64]\n mov r0,0\n j_s [blink]\n'),
            ('current_gui',0x1453fc,prefix+''' ld r11,[r10,68]
 add r11,r11,1
 st r11,[r10,68]
 cmp r11,1
 bne second
 ld r0,[r10,16]
 j_s [blink]
second:
 ld r0,[r10,20]
 j_s [blink]
'''),
            ('event_service',0x17c074,prefix+''' ld r11,[r10,36]
 asl r12,r11,2
 add r12,r10,r12
 st r1,[r12,40]
 add r11,r11,1
 st r11,[r10,36]
 ld r12,[r10,72]
 or r11,r0,r2
 or r11,r11,r12
 st r11,[r10,72]
 mov r0,0
 j_s [blink]
'''),
            ('open',0x1453e4,prefix+''' st r0,[r10,24]
 st r1,[r10,28]
 ld r11,[r10,32]
 add r11,r11,1
 st r11,[r10,32]
 mov r0,0
 j_s [blink]
'''),
        ]
        for i,(name,address,asm) in enumerate(services):
            target=0x2030000+i*0x400; stub=binary(name,asm); maps+=mapping(stub,target)
            entry=binary('entry_'+name, f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
            b,o=locate(address,8); before=bytes(images[b['index']][o:o+8]); assert before==raw(address,8)
            images[b['index']][o:o+8]=entry
            patches.append(dict(name=name,address=hex(address),original=before.hex(),fixture=entry.hex()))
        tests = [
            dict(name='unfiltered_pass',want=1),
            dict(name='event_filtered',filt=0x480,want=0),
            dict(name='guard_cb_2',cb=2,want=0),
            dict(name='guard_cad_3',cad=3,want=0),
            dict(name='guard_queue_nonzero',queue=1,want=0),
            dict(name='guard_input_2a',inp=42,want=0),
            dict(name='first_gui_1',gui1=1,want=0),
            dict(name='second_gui_7e',gui2=126,want=0),
            dict(name='model_exposure',screen=1,want=0),
            dict(name='model_color',screen=2,want=0),
        ]
        state=bytearray(len(tests)*128); asm=' mov r20,0x2000000\n'
        for i,t in enumerate(tests):
            base=i*128; address=0x2001000+base
            struct.pack_into('<6I',state,base,*[t.get(k,0) for k in ('cb','cad','queue','inp','gui1','gui2')])
            struct.pack_into('<I',state,base+80,t.get('screen',0))
            asm+=f''' mov r21,{address:#x}
 st r21,[r20]
 mov r1,0x899858
 mov r0,{t.get('filt',0x4004):#x}
 sth r0,[r1]
 mov r0,0
 sth r0,[r1,2]
 st sp,[r21,56]
 add r0,r21,80
 mov r1,0x480
 add r2,r21,84
 bl akeru_menu_event
 st r0,[r21,88]
 ld r0,[r21,84]
 cmp r0,9
 bne skip_route_{i}
 mov r0,0x1234
 mov r1,0x480
 mov r2,0x5678
 mov r12,0x7cafe8
 jl [r12]
skip_route_{i}:
 st sp,[r21,60]
'''
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i,image in images.items():
            p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(image);maps+=mapping(p,BS[i]['load_address_candidate'])
        path=out/'cases.bin';path.write_bytes(state);maps+=mapping(path,0x2001000)
        p=out/'current.bin';p.write_bytes(bytes(8));maps+=mapping(p,0x2000000)
        def run(name,args):
            v=r.command(name,args); assert v.returncode==0,v.stdout; return v.stdout
        run('compile_menu',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-O2','-ffreestanding','-fno-builtin','-c',sources[0],'-o',out/'menu.o'])
        (out/'cases.s').write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n'+asm+'\n.section .stack,"aw",@nobits\n.align 16\n.space 16384\n')
        run('assemble',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',out/'cases.o',out/'cases.s'])
        run('link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',LEGACY/'tests/smoke.ld','-o',out/'cases.elf',out/'cases.o',out/'menu.o'])
        assert not run('undefined',['arc-snps-elf-nm','-u',out/'cases.elf']).strip()
        case,log=r.run('cases','/result/cases.elf',maps,trace=True)
        assert case['exit_code']==0 and case['fault'] is None,log
        got=path.read_bytes(); result=[]
        for i,t in enumerate(tests):
            w=struct.unpack_from('<19I',got,i*128); expected=t['want']
            assert w[14]==w[15] and w[8]==expected,(t,w)
            screen,action,handled=struct.unpack_from('<3I',got,i*128+80)
            assert (screen,action,handled)==(0,1 if t.get('screen',0) else 9,1),(t,screen,action,handled)
            if expected:
                assert w[6:8]==(0x87,0) and w[9]==4 and w[10:14]==(0x81,0x80,0x101,0x100) and w[18]==0,(t,w)
            else: assert w[9]==0,(t,w)
            result.append(dict(**t,open_calls=w[8],destination=hex(w[6]) if w[8] else None,
                argument=w[7] if w[8] else None, event_calls=w[9],events=[hex(x) for x in w[10:14]] if w[9] else [],
                pre_open_calls=w[16],current_gui_calls=w[17],model_action=action,model_screen=screen,stack_preserved=True))
        assert all(sha(p)==r.input_hashes[str(p)] for p in sources+[dump])
        (out/'cases.json').write_text(json.dumps(result,indent=2)+'\n')
        (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_MODEL_BACK_ORIGINAL_GUARDS_SYNTHETIC', scenarios=result,
            assumptions=['Model C consumes 480; harness conditionally calls original wrapper 7CAFE8 on RETURN_LIVEVIEW; original dispatcher 169F60, 7CB0F8, 20E814 and 20E940.',
                         'Synthetic filter and return values; eight external service fixtures; open is a recorder.'],
            limits=['Injected event 480, no physical key, scheduler, queue or display.',
                    'Fixed same values for repeated CAD and input fixture calls.',
                    'Does not exercise CAD second call equal 2 or demonstrate real transition.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc)); raise
    finally: r.save()
    print('PASS: model back original guards;',out,flush=True)

if __name__=='__main__': main()
