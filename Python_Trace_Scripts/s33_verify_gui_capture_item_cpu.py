#!/usr/bin/env python3
"""Execute V1.1 CaptureMenu item handler with explicit laboratory fixtures."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32, disasm


def main():
    out = ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('capture_item_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='gui-capture-item-handler'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        dump = ROOT/'DUMPS/MainCode.dmp'; data = dump.read_bytes(); r.input_hashes[str(dump)] = sha(dump)
        for address, size in [(0x631878, 0xe4), (0x98016c, 84), (0x9801f8, 112), (0x77f664, 0x60)]:
            block, offset = locate(address, size)
            assert raw(address, size) == data[block['offset']+offset:block['offset']+offset+size]
        assert (u32(0x631860), u32(0x631950), u32(0x631954), u32(0x631958)) == (0x681b68, 0x681b6b, 0x186a0, 0x681b6d)
        assert any(u32(0x77f664+i) == 0x580 and u32(0x77f668+i) == 0x631878 for i in range(0,0x60,8))
        (out/'handler_disassembly.txt').write_text(disasm(0x631878, 0x631950))
        images = {i:bytearray(PS[i]) for i in (0,1,2,3,4,5)}; maps = []; patches = []
        def binary(name, asm):
            elf = compile_probe(r, name, asm); p = out/(name+'.bin')
            result = r.command(name+'_extract', [TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p])
            assert result.returncode == 0, result.stdout
            b = p.read_bytes(); p.write_bytes(b+bytes(8+(-len(b))%8)); return p
        def mapping(p, a, n): return ['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},{n}']
        current = ' mov r10,0x2000000\n ld r10,[r10]\n'
        count = lambda ofs: f' ld r11,[r10,{ofs}]\n add r11,r11,1\n st r11,[r10,{ofs}]\n'
        services = [
            ('item_select',0x631e00,current+' st r1,[r10,20]\n'+count(16)+' mov r0,0\n j_s [blink]\n'),
            ('state_change',0x14503c,current+count(44)+' mov r0,0\n j_s [blink]\n'),
            ('refresh',0x145150,current+count(24)+' mov r0,0\n j_s [blink]\n'),
            ('condition',0x817ba8,current+' ld r0,[r10,28]\n j_s [blink]\n'),
            ('conditional_action',0x171c30,current+count(48)+' mov r0,0\n j_s [blink]\n'),
            ('delay',0x145c3c,current+' st r0,[r10,52]\n'+count(56)+' mov r0,0\n j_s [blink]\n'),
            ('attributes',0x1450d8,current+' st r1,[r10,60]\n ld r0,[r10,0]\n j_s [blink]\n'),
            ('open',0x1453e4,current+' st r0,[r10,8]\n st r1,[r10,12]\n'+count(4)+' mov r0,0\n j_s [blink]\n')]
        for i,(name,address,asm) in enumerate(services):
            target=0x2030000+i*0x400; p=binary(name,asm); maps+=mapping(p,target,p.stat().st_size)
            entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
            block,offset=locate(address,8); old=bytes(images[block['index']][offset:offset+8]); assert old==raw(address,8)
            images[block['index']][offset:offset+8]=entry
            patches.append({'service':name,'address':hex(address),'original':old.hex(),'fixture':entry.hex()})
        # Count zero and modified flag/ID records are synthetic. Other records copy original payload bytes.
        tests=[(f'list4800_item{i}',0x98016c+i*28,1,None,2,0,None,None) for i in range(3)]
        tests += [(f'list4801_item{i}',0x9801f8+i*28,1,None,2,0,None,None) for i in range(4)]
        tests += [('no_items',0x980188,0,0,2,0,None,None),('flag0',0x980188,1,1,2,0,None,None),
                  ('flag1',0x980188,1,2,2,0,None,None),('attributes_zero',0x980188,1,0,0,0,None,None),
                  ('attributes_bit0',0x980188,1,0,1,0,None,None),('flag10',0x980188,1,0x400,2,0,None,None),
                  ('zero_target',0x980188,1,0,2,0,0,None),('negative_target',0x980188,1,0,2,1,-1,0x12345678)]
        state=bytearray(len(tests)*128); contexts=bytearray(len(tests)*128); asm=' mov r20,0x2000000\n'
        for i,(name,source,n,flags,attrs,cond,target,arg) in enumerate(tests):
            s=0x2001000+i*128; c=0x2100000+i*128
            struct.pack_into('<I',state,i*128,attrs); struct.pack_into('<I',state,i*128+28,cond)
            contexts[i*128+64:i*128+92]=raw(source,28)
            struct.pack_into('<I',contexts,i*128+0x30,c+64); contexts[i*128+0x34]=n; contexts[i*128+0x2f]=1
            if flags is not None: struct.pack_into('<I',contexts,i*128+64+24,flags)
            if target is not None: struct.pack_into('<h',contexts,i*128+64+20,target)
            if arg is not None: struct.pack_into('<I',contexts,i*128+64+16,arg)
            asm+=f''' mov r21,{s:#x}
 st r21,[r20]
 st sp,[r21,36]
 mov r0,{c:#x}
 mov r1,0x580
 mov r2,0
 mov r12,0x631878
 jl [r12]
 st r0,[r21,32]
 st sp,[r21,40]
'''
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i,image in images.items():
            p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(image);maps+=mapping(p,BS[i]['load_address_candidate'],len(image))
        sf=out/'cases.bin';sf.write_bytes(state);maps+=mapping(sf,0x2001000,len(state))
        cf=out/'contexts.bin';cf.write_bytes(contexts);maps+=mapping(cf,0x2100000,len(contexts))
        p=out/'current.bin';p.write_bytes(bytes(8));maps+=mapping(p,0x2000000,8)
        elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
        assert case['exit_code']==0 and case['fault'] is None,log
        got=sf.read_bytes(); results=[]
        for i,(name,source,n,flags,attrs,cond,target,arg) in enumerate(tests):
            w=struct.unpack_from('<16I',got,i*128)
            flags = u32(source+24) if flags is None else flags
            source_target=struct.unpack('<h',raw(source+20,2))[0] if target is None else target
            source_arg=u32(source+16) if arg is None else arg
            accepted=n>0 and (flags&3)==0; opens=bool(accepted and attrs&2 and source_target)
            expected_return=1 if not accepted or opens else 0
            assert (w[8],w[1],w[4],w[6],w[11],w[12],w[14])==(expected_return,int(opens),int(accepted),int(accepted and not flags&0x400),int(accepted and not flags&0x400),int(accepted and not flags&0x400 and cond),int(accepted and not flags&0x400)),(name,w)
            assert w[9]==w[10],(name,w)
            if accepted: assert w[5]==0 and w[15]==0x14,(name,w)
            if accepted and not flags&0x400: assert w[13]==0x186a0,(name,w)
            if opens: assert (w[2],w[3])==(source_target&0xffffffff,source_arg),(name,w)
            results.append({'case':name,'source_record':hex(source),'count':n,'flags':hex(flags),'attributes':hex(attrs),
                 'index':0,'return':w[8],'select_calls':w[4],'open_calls':w[1],
                 'open_id':hex(w[2]) if opens else None,'open_argument':hex(w[3]) if opens else None,
                 'refresh_calls':w[6],'delay_calls':w[14],'conditional_action_calls':w[12],'stack_preserved':True})
        (out/'cases.json').write_text(json.dumps(results,indent=2)+'\n')
        (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_CAPTURE_ITEM_BOUNDED',scenarios=results,
           assumptions=['Original handler 0x631878 and compiler prologue/epilogue; eight named service fixtures.',
             'Synthetic contexts with byte +47=1, count and per-case copied record at +48; original record flags changed for cases.',
             'Each original record is made element zero to examine its fields, not a claim about real list selection.'],
           limits=['No dispatcher, real selection/paging, initialization, scheduler, renderer or physical camera.',
             'The +47=0 pagination path contains MULUDW, unsupported by the pinned GNU simulator; not exercised.',
             'Fixture effects and returns are synthetic and do not prove service semantics or UI reachability.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS: bounded CaptureMenu item handler cases;',out,flush=True)
if __name__=='__main__':main()
