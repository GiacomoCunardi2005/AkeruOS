#!/usr/bin/env python3
"""Execute the original TBIB status gate and separately its indirect entry wrapper."""
from datetime import datetime, timezone
from itertools import product
from pathlib import Path
from types import SimpleNamespace
import json, struct
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe

BASE, STATE = 0x1000000, 0x2100000


def main():
    out=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('boot_status_gate_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='original-TBIB-loader-status-to-initializer-gate'))
    r.prepare()
    try:
        body=bytearray((ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()[0x7c:0x44c38])
        r.input_hashes[str(Path(__file__))]=sha(Path(__file__))
        maps=[];patches=[]
        def mmap(name,address,data):
            p=out/name;p.write_bytes(bytes(address%8)+data)
            maps.extend(['--memory-mapfile','/result/'+name,'--memory-region',f'{address:#x},{len(data)}'])
            return p
        def binary(name,asm):
            elf=compile_probe(r,name,asm);p=out/(name+'.bin')
            v=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert v.returncode==0,v.stdout
            return p.read_bytes()
        def stub(address,asm):
            target=0x2030000+len(patches)*0x400
            mmap(f'boundary_{address:x}.bin',target,binary(f'boundary_{address:x}',asm)+bytes(16))
            entry=binary(f'jump_{address:x}',f' mov_s r12,{target:#x}\n j_s [r12]\n');assert len(entry)==8
            at=address-BASE;patches.append(dict(cpu=hex(address),original=body[at:at+8].hex(),laboratory_target=hex(target)))
            body[at:at+8]=entry
        stub(0x10069e0,f''' mov r10,{STATE:#x}
 st r0,[r10,24]
 st r1,[r10,28]
 st r2,[r10,32]
 st r3,[r10,36]
 ld r6,[r10,8]
 add r6,r6,1
 st r6,[r10,8]
 ld r0,[r10]
 j_s [blink]
''')
        stub(0x1000610,f' mov r10,{STATE:#x}\n ld r6,[r10,12]\n add r6,r6,1\n st r6,[r10,12]\n ld r0,[r10,4]\n j_s [blink]\n')
        for address,marker in [(0x10003d2,1),(0x100042a,2)]:
            stub(address,f' mov r10,{STATE:#x}\n mov r0,{marker}\n st r0,[r10,16]\n st r18,[r10,20]\n j [r23]\n')
        tbib=mmap('tbib_LAB_boundaries.bin',BASE,body)
        state=mmap('gate_state.bin',STATE,bytes(64))
        results=[]
        for earlier,wait,load,late in product([0,0x303],[0,0x101],[0,13],[0,5]):
            name=f'gate_{earlier:x}_{wait:x}_{load:x}_{late:x}'
            data=bytearray(64);struct.pack_into('<2I',data,0,wait,late);state.write_bytes(data)
            image=bytearray(body);struct.pack_into('<I',image,0x41108,load)
            # Entry is already published, including in deliberate loader-error cases.
            struct.pack_into('<I',image,0x41100,0xbb540);tbib.write_bytes(image)
            asm=f''' mov r20,{STATE:#x}
 st sp,[r20,40]
 mov r18,{earlier}
 mov r17,0
 mov r23,finished
 mov r12,0x1000390
 j [r12]
finished:
 st sp,[r20,44]
 mov r0,0
 mov r8,1
 trap_s 1
'''
            elf=compile_probe(r,name,asm);case,log=r.run(name,'/result/'+elf.name,maps)
            assert case['exit_code']==0 and case['fault']is None,log
            w=struct.unpack('<16I',state.read_bytes());expected=next((e for e in [earlier,wait,load,late]if e),0)
            assert (w[2],w[3],w[4],w[5])==(1,1,2 if expected else 1,expected),(name,w)
            event=struct.unpack_from('<I',body,0x474)[0]
            assert w[6:10]==(event,2,1,0) and w[10]==w[11]
            assert struct.unpack_from('<I',tbib.read_bytes(),0x41100)[0]==0xbb540
            results.append(dict(earlier=hex(earlier),event_status=hex(wait),loader_status=hex(load),late_status=hex(late),selected_status=hex(expected),branch='error'if expected else'continue',entry_already_published=True,stack_preserved=True))
        # Independent entry wrapper test. No scheduler or gate-to-wrapper connection is assumed.
        entry=binary('entry_recorder',f' mov r10,{STATE:#x}\n st r0,[r10,48]\n mov r0,0x55aa\n j_s [blink]\n')
        mmap('entry_recorder.bin',0x2040000,entry+bytes(16))
        image=bytearray(body);struct.pack_into('<I',image,0x41100,0x2040000);tbib.write_bytes(image);state.write_bytes(bytes(64))
        elf=compile_probe(r,'entry_wrapper',f' mov r20,{STATE:#x}\n st sp,[r20,40]\n mov r12,0x1000c10\n jl [r12]\n st r0,[r20,52]\n st sp,[r20,44]\n mov r0,0\n mov r8,1\n trap_s 1\n')
        case,log=r.run('entry_wrapper','/result/'+elf.name,maps);assert case['exit_code']==0 and case['fault']is None,log
        w=struct.unpack('<16I',state.read_bytes());assert w[10]==w[11]and(w[12],w[13])==(0x1041100,0x55aa),w
        for a,b in [(0x1000390,0x10003d2),(0x10000c4,0x10000e8),(0x1000c10,0x1000c18)]:
            p=r.command(f'gnu_{a:x}',[TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',out/'tbib.elf']);assert p.returncode==0 and'out of bounds'not in p.stdout
        assert all(sha(Path(p))==h for p,h in r.input_hashes.items())
        (out/'gate_cases.json').write_text(json.dumps(results,indent=2)+'\n')
        (out/'laboratory_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ORIGINAL_TBIB_STATUS_GATE_LOCAL_ONLY',gate_cases=len(results),independent_entry_wrapper_cases=1,input_hashes=r.input_hashes,
                         assumptions=['Fragment01000390 with r17=0 and r18 supplied; no full initializer or task scheduling','Event wait and late-info service return fixtures; stop at beginnings of success/error branches','Separate original01000C10/010000C4 wrapper with laboratory callback'],
                         limits=['Gate error avoids local continue branch, not proof no later handoff after error/poweroff failure','No physical loader, kernel teardown, SD recovery or full boot; candidate unchanged'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n')
        (out.parent/'boot_status_gate_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
        print('PASS',len(results),'gate cases +1 independent wrapper',out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));(out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');raise


if __name__=='__main__':main()
