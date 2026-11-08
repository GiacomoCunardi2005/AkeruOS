#!/usr/bin/env python3
"""Execute original GUI index routine and reader with explicit bounded services."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32

def main():
    out=ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('jpeg_reader_cpu_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='gui-jpeg-reader-shared-context'))
    print('Prove:',out,flush=True)
    try:
        r.prepare()
        dump=ROOT/'DUMPS/MainCode.dmp'; data=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
        for addr,n in [(0x7c9e38,0xa0),(0x7c9a5c,16),(0x159550,0x13c),(0x981734,160)]:
            b,o=locate(addr,n);assert raw(addr,n)==data[b['offset']+o:b['offset']+o+n]
        assert u32(0x159688)==0x3672a4 and u32(0x7c9ecc)==0x981734
        images={i:bytearray(PS[i]) for i in (0,1,4,5)}; maps=[]; patches=[]
        def binary(name,asm):
            elf=compile_probe(r,name,asm);path=out/(name+'.bin')
            res=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path])
            assert res.returncode==0,res.stdout
            b=path.read_bytes();path.write_bytes(b+bytes(8+(-len(b))%8));return path
        def mapping(path,addr,size):return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{size}']
        current=' mov r10,0x2000000\n ld r10,[r10]\n'
        services=[('pre',0x302634,' mov r0,0\n j_s [blink]\n'),
          ('lock',0x1593ac,current+' ld r11,[r10,8]\n add r11,r11,1\n st r11,[r10,8]\n ld r0,[r10]\n j_s [blink]\n'),
          ('unlock',0x1594a4,current+' ld r11,[r10,12]\n add r11,r11,1\n st r11,[r10,12]\n mov r0,0\n j_s [blink]\n'),
          ('backend',0x23f08c,current+' st r0,[r10,20]\n st r1,[r10,24]\n st r2,[r10,28]\n st r3,[r10,32]\n ld r11,[r10,16]\n add r11,r11,1\n st r11,[r10,16]\n ld r0,[r10,4]\n j_s [blink]\n')]
        for i,(name,addr,asm) in enumerate(services):
            target=0x2030000+i*0x400;stub=binary(name,asm);maps+=mapping(stub,target,stub.stat().st_size)
            entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
            b,o=locate(addr,8);before=bytes(images[b['index']][o:o+8]);assert before==raw(addr,8)
            images[b['index']][o:o+8]=entry;patches.append({'service':name,'address':hex(addr),'original':before.hex(),'fixture':entry.hex()})
        # Base, index, lock return, backend return, expected result/lock/unlock/backend/status/length.
        tests=[('base_zero_index1',0,1,0,0,0,1,1,0,1,2688),
          ('image_base_index1',0x35c918,1,0,0,1,1,1,1,0,2688),
          ('image_base_index14',0x35c918,14,0,0,1,1,1,1,0,2715),
          ('other_base_index14',0xd03000,14,0,0,1,1,1,1,0,2715),
          ('backend_failure',0x35c918,14,0,9,0,1,1,1,9,2715),
          ('lock_failure',0x35c918,14,7,0,0,1,0,0,0,2715),
          ('empty_index0',0x35c918,0,0,0,0,1,1,0,1,0)]
        state=bytearray(len(tests)*128);asm=' mov r20,0x2000000\n'
        for i,(name,base,index,lock,backend,*_) in enumerate(tests):
            addr=0x2001000+i*128;struct.pack_into('<II',state,i*128,lock,backend)
            asm+=f''' mov r21,{addr:#x}
 st r21,[r20]
 mov r0,0
 mov r1,{base:#x}
 mov r12,0x159550
 jl [r12]
 st sp,[r21,52]
 mov r0,{index}
 add r1,r21,36
 add r2,r21,80
 mov r12,0x7c9e38
 jl [r12]
 st r0,[r21,40]
 mov r12,0x3672a4
 ld r0,[r12,8]
 st r0,[r21,44]
 ld r0,[r12,4]
 st r0,[r21,48]
 st sp,[r21,56]
'''
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i,image in images.items():
            path=out/f'block{i}_LAB_FIXTURE.bin';path.write_bytes(image);maps+=mapping(path,BS[i]['load_address_candidate'],len(image))
        statefile=out/'cases.bin';statefile.write_bytes(state);maps+=mapping(statefile,0x2001000,len(state))
        currentfile=out/'current.bin';currentfile.write_bytes(bytes(8));maps+=mapping(currentfile,0x2000000,8)
        elf=compile_probe(r,'cases',asm);case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
        assert case['exit_code']==0 and case['fault'] is None,log
        got=statefile.read_bytes();results=[]
        for i,(name,base,index,lock,backend,ret,lc,uc,bc,status,length) in enumerate(tests):
            w=struct.unpack_from('<15I',got,i*128)
            assert (w[10],w[2],w[3],w[4],w[9])==(ret,lc,uc,bc,length),(name,w)
            assert w[12]==base and w[13]==w[14],(name,w)
            if name=='lock_failure':assert w[11]==9,(name,w)  # Preserved from the preceding backend failure.
            else:assert w[11]==status,(name,w)
            if bc:assert (w[5],w[6],w[7],w[8])==(6,base+u32(0x981734+index*8),length,0x2001000+i*128+80),(name,w)
            results.append({'case':name,'base':hex(base),'index':index,'result':w[10],'length':w[9],
                'lock_calls':w[2],'unlock_calls':w[3],'backend_calls':w[4],
                'backend_offset':hex(w[6]) if bc else None,'backend_length':w[7] if bc else None,
                'reader_status':w[11], 'context_base_after':hex(w[12]),'stack_preserved':True})
        (out/'cases.json').write_text(json.dumps(results,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_GUI_JPEG_READER_BOUNDED',scenarios=results,
            assumptions=['Original 159550, 159558, 7c9e38 and epilogue; 4 explicit service fixtures.',
            'Null path selects fixture backend; index, base and service outcomes are synthetic.'],
            limits=['No real lock, release, backend bytes, filesystem, scheduler, JPEG parser or display.',
            'No proof any test base or order occurs on camera.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS: bounded GUI JPEG reader CPU cases:',out,flush=True)
if __name__=='__main__':main()
