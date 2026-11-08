#!/usr/bin/env python3
"""Execute an original context-switch prefix with explicitly seeded AUX/RAM.

Stops at an intentionally undefined decoder boundary; never runs hardware or
claims a complete scheduler switch. All original instruction bytes unchanged.
"""
import json
import re
import struct
import shutil
from types import SimpleNamespace
from pathlib import Path
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_integrate_ffc7000_table_tail import load,save

PARENT=ROOT/'Risultati/Processor_Registers/20261025T201031Z'
REUSED=ROOT/'outputs/gnu_arc700/20261025T201510Z_5b6c70a4'
SITES={0xb3334:('read',47),0xb3348:('read',50),0xb3350:('read',51),0xb337c:('write',47),0xb3390:('write',50),0xb3398:('write',51)}


def main():
    ledger=load(PARENT/'sha256.json');assert all(sha(PARENT/k)==v for k,v in ledger.items())
    r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='kernel-aux-context-prefix'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();r.known_ranges='';r.experimental_engine=LAB;r.observe=False
        assert sha(REUSED/'observer')==load(REUSED/'verified_evidence.json')['files']['observer']
        shutil.copy2(REUSED/'observer',r.out/'observer')
        assert sha(LAB/'install/bin/arc-elf32-run')==load(BUILD)['engine_sha256']
        for q in [Path(__file__),PARENT/'sha256.json',BUILD,LAB/'install/bin/arc-elf32-run',ROOT/'work/binutils-2.45/opcodes/arc-regs.h',REUSED/'observer',REUSED/'verified_evidence.json']:
            r.input_hashes[str(q)]=sha(q)
        for name in ['s33_run_gnu_arc700','s33_verify_gnu_defined_memory','s33_verify_ff7_transfer_windows','s33_verify_gnu_dsp_lab',
            's33_trace_state_dispatch','s33_verify_sensor_mmio_dialog','s33_integrate_ffc7000_table_tail']:
            q=Path(__file__).with_name(name+'.py');r.input_hashes[str(q)]=sha(q)
        shutil.copy2(Path(__file__),r.out/Path(__file__).name)
        blocks,payloads,directory=verified_payloads(ROOT);body=payloads[0];base=blocks[0]['load_address_candidate']
        r.input_hashes[str(directory/blocks[0]['file'])]=sha(directory/blocks[0]['file'])
        fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';r.input_hashes[str(fw)]=sha(fw)
        assert fw.read_bytes().find(body)>=0
        # Map original selectors and tail prefix, not a patched return/trap.
        chunks=[(0xb2e10,0x20),(0xb3318,0xa0)]
        for a,n in chunks:(r.out/f'original_{a:x}.bin').write_bytes(body[a-base:a-base+n])
        (r.out/'original_windows.txt').write_text('\n\n'.join(aligned_window(body,base,a,a+n) for a,n in chunks))
        decoded={}
        for pc,(op,index) in SITES.items():
            text=aligned_window(body,base,pc,pc+12);line=next(x for x in text.splitlines() if re.match(r'\s*'+f'{pc:x}:',x))
            m=re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
            raw=b''.join(bytes.fromhex(w)[::-1] for w in m[1].split());assert raw==body[pc-base:pc-base+len(raw)]
            assert m[2]==('lr' if op=='read' else 'sr') and f'[{hex(index)}]' in m[3]
            decoded[hex(pc)]=dict(opcode=m[2],operands=m[3].strip(),bytes_hex=raw.hex(),index=index)
        specs=[('different_save_one',1,False,False,False,True),('different_save_restore_all',1,True,True,True,True),
            ('different_save_restore_one',1,False,True,False,True),('different_save3_restore1',1,True,True,False,True),
            ('null_restore_all',0,False,True,True,True),('null_no_restore',0,False,False,False,True),
            ('same_context_skip',2,True,True,True,True),('gate8_clear_skip',1,True,True,True,False)]
        for pattern in range(2):
            seed=[(0x12345678,0x87654321,0xfedcba98),(0xffffffff,0,0x80000001)][pattern]
            restore=[(0x13579bdf,0x2468ace0,0xdeadbeef),(0,0xffffffff,0x7ffffffe)][pattern]
            for name,old_kind,old_ext,do_restore,new_ext,gate in specs:
                scenario=f'{name}_{pattern}';ram=bytearray(b'\xa5'*0x800);start=0x700000
                current=start+0x200 if old_kind==1 else start+0x400 if old_kind==2 else 0
                incoming=start+0x400;old_buffer=start+0x600;new_buffer=start+0x700
                def w(a,v):struct.pack_into('<I',ram,a-start,v)
                old_flags=0x42|(0x20000 if old_ext else 0)
                new_flags=0x40|(8 if gate else 0)|(0x100 if do_restore else 0)|(0x20000 if new_ext else 0)
                w(start+36,current);w(incoming+108,new_flags);w(incoming+200,new_buffer)
                if old_kind==1:w(current+108,old_flags);w(current+200,old_buffer)
                for i,v in enumerate(restore):w(new_buffer+4*i,v)
                before=bytes(ram);expected=bytearray(before);events=[]
                def eword(a,v):struct.pack_into('<I',expected,a-start,v)
                active=gate and old_kind!=2
                if active:
                    if old_kind==1:
                        for i,index in enumerate([47,50,51][:3 if old_ext else 1]):
                            events.append((list(SITES)[i],'read',index,seed[i]));eword(old_buffer+4*i,seed[i])
                        eword(current+108,old_flags|0x100)
                    eword(start+36,incoming)
                    if do_restore:
                        for i,index in enumerate([47,50,51][:3 if new_ext else 1]):events.append(([0xb337c,0xb3390,0xb3398][i],'write',index,restore[i]))
                    eword(incoming+108,new_flags&~0x100)
                fixture=r.out/(scenario+'_ram.bin');fixture.write_bytes(before)
                asm=''.join(f'mov r0,{v:#x}\nsr r0,[{index:#x}]\n' for index,v in zip([47,50,51],seed))
                if old_kind==0:
                    asm+=f'mov r0,{0xdead0000|pattern:#x}\nmov r4,0xc8\nst r0,[r4]\n'
                asm+=f'mov r2,{start:#x}\nmov r3,{incoming:#x}\nmov r12,0xb2e12\nj [r12]\n'
                elf=compile_probe(r,scenario,asm)
                options=['--memory-mapfile','/result/'+fixture.name,'--memory-region',f'{start:#x},{len(before):#x}']
                for a,n in chunks:options+=['--memory-mapfile',f'/result/original_{a:x}.bin','--memory-region',f'{a:#x},{n:#x}']
                # Boundary2E22 is declared unknown even though its original bytes
                # exist in the mapfile; decoder lookahead may stop before2E1E.
                r.range_override=known_sections(elf,False)+f',0xb2e10:0x12,0xb3318:0xa0,{start:#x}:{len(before):#x}'
                case,log=r.run(scenario,'/result/'+elf.name,options,trace=True,extract=True)
                assert case['exit_code']==5 and case['fault'] is None,(scenario,log[-3000:])
                assert re.search(r'S33_UNDEFINED .*first=000b2e22 .*operation=decoder_fetch',log),log[-2500:]
                assert not any(s in log for s in ['S33_AUX_UNKNOWN','S33_AUX_RANGE','runtime error:'])
                actual=[];trace=(r.out/(scenario+'.trace')).read_text()
                for line in trace.splitlines():
                    m=re.match(r'0x([0-9a-f]+)\s+(lr|sr)\s+.*?<- (0x[0-9a-f]+)',line)
                    if m and int(m[1],16) in SITES:
                        pc=int(m[1],16);op,index=SITES[pc];actual.append((pc,op,index,int(m[3],16)))
                assert actual==events,(scenario,actual,events)
                assert fixture.read_bytes()==expected,(scenario,'RAM comparison failed')
                if old_kind==0:
                    assert re.search(r'0x0*b3324\s+ld\s+.*?<- '+hex(0xdead0000|pattern)+r'\b',trace)
                assert all((r.out/f'original_{a:x}.bin').read_bytes()==body[a-base:a-base+n] for a,n in chunks)
                case.update(pattern=pattern,spec=name,seed_aux_values=seed,incoming_aux_values=restore,expected_aux_events=events,
                    actual_aux_events=actual,fixture=fixture.name,fixture_before=before.hex(),fixture_after=expected.hex(),
                    boundary='0xb2e22',stop_is_declared_fixture_boundary=True,complete_scheduler_switch=False,
                    old_kind=old_kind,old_extended=old_ext,incoming_restore=do_restore,incoming_extended=new_ext,gate8=gate)
                case.update(null_delay_input_kind='declared_guest_harness_store' if old_kind==0 else None,
                    null_delay_read_address='0xc8' if old_kind==0 else None,null_delay_value=(0xdead0000|pattern) if old_kind==0 else None)
                print(scenario,'PASS',len(actual),'originalAUXevents',flush=True)
        assert all(sha(PARENT/k)==v for k,v in ledger.items())
        r.results.update(status='PASS_ORIGINAL_KERNEL_AUX_CONTEXT_PREFIX',parent_atlas=str(PARENT),sites=decoded,
            original_chunks=[dict(base=a,size=n,sha256=sha(r.out/f'original_{a:x}.bin')) for a,n in chunks],
            hardware_access=False,gnu_modified=False,new_aux_indices=[47,50,51],physical_semantics_proven=False,
            limits=['Seed AUXwrites in harness and RAMstructures are fixtures,not Nikon reset state orhardwaremeasurements.',
                'CPU executes only originalswitch prefix andstops atdeclared decoderboundary;not complete scheduler orinterruptdelivery.',
                'Width32 issoftware LR/SR andRAMstore width;physicalregistername/width/permissions/sideeffects unknown.',
                'GNU ARC600/NONE aliases at these indices are not evidence of Nikon CRC/FBF implementation.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
