#!/usr/bin/env python3
"""Verify a second original callback registration and its software context."""
import json,re,struct
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import DefinedRunner,LAB,BUILD,known_sections
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window


def main():
    r=DefinedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='register-dual-callback'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256'];r.experimental_engine=LAB
        for p in [BUILD,LAB/'install/bin/arc-elf32-run',Path(__file__)]:r.input_hashes[str(p)]=sha(p)
        (r.out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        blocks,payloads,directory=verified_payloads(ROOT);info={b['index']:b for b in blocks};body=payloads[0];data=payloads[1]
        base=info[0]['load_address_candidate'];dbase=info[1]['load_address_candidate']
        main=r.out/'payload0_mmap.bin';main.write_bytes(body)
        for i in [0,1]:r.input_hashes[str(directory/info[i]['file'])]=sha(directory/info[i]['file'])
        assert struct.unpack_from('<I',body,0x342980-base)[0]==0x3428b8
        assert struct.unpack_from('<I',body,0x342f1c-base)[0]==0x360ae0
        assert struct.unpack_from('<I',body,0x342984-base)[0]==0x360ad0
        specs=[('register_original',0x342868,0,0x360ae0,0x3428b8,False),
               ('set_user_callback',0x3428b0,0x11223344,0x360ad0,0x11223344,False),
               ('register_then_invoke',0x342868,0,0x360ae0,0x3428b8,True)]
        for name,entry,arg,slot,expected_pointer,invoke in specs:
            fixture=r.out/(name+'_payload1_mmap.bin');fixture.write_bytes(data)
            options=['--memory-mapfile','/result/'+main.name,'--memory-region',f'{base:#x},{len(body):#x}',
                     '--memory-mapfile','/result/'+fixture.name,'--memory-region',f'{dbase:#x},{len(data):#x}']
            asm=f'mov r9,sp\nmov r7,0x77665544\nmov r13,0x13371337\nmov r0,{arg:#x}\nmov r3,{entry:#x}\njl [r3]\n'
            if invoke:asm+=f'mov r2,{slot:#x}\nld r0,[r2]\njl [r0]\nmov r0,9\nb finish\n'
            else:
                asm+=f'cmp sp,r9\nbne fail\ncmp r7,0x77665544\nbne fail\ncmp r13,0x13371337\nbne fail\nmov r2,{slot:#x}\nld r2,[r2]\ncmp r2,{expected_pointer:#x}\nbne fail\nmov r0,0\nb finish\n'
            asm+='fail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n'
            elf=compile_probe(r,name,asm);r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x},{dbase:#x}:{len(data):#x}'
            case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True)
            assert case['fault']is None
            if invoke:
                assert case['exit_code']==5 and 'S33_AUX_RANGE index=65809'in log,log[-2000:]
                trace=(r.out/(name+'.trace')).read_text();assert 'pc <- 0x3428b8'in trace
                assert re.search(r'Extract: 0x0*3428ba:',trace)
                assert not any('cr <-'in line for line in trace.splitlines()if re.match(r'0x0*3428ba\s+lr\b',line))
            else:assert case['exit_code']==0 and 'S33_AUX_RANGE'not in log,log[-2000:]
            expected=bytearray(data);struct.pack_into('<I',expected,slot-dbase,expected_pointer)
            assert fixture.read_bytes()==expected and main.read_bytes()==body
            case.update(original_entry=hex(entry),slot=hex(slot),pointer=hex(expected_pointer),
                        full_routine_completed=not invoke,custom_aux_semantic_result_observed=False,
                        expected_guard_index='0x10111'if invoke else None,all_other_payload1_bytes_unchanged=True)
            print(name,'PASS',case['exit_code'],case['instructions'],flush=True)
        for name,a,z in [('register',0x342868,0x342878),('user_callback_setter',0x3428b0,0x3428b8),
                          ('handler',0x3428b8,0x34294c),('dispatcher_slot',0x342eb0,0x342ece)]:
            (r.out/(name+'_source_disassembly.txt')).write_text(aligned_window(body,base,a,z)+'\n')
        r.results.update(status='PASS_REGISTER_DUAL_CALLBACK_AND_MODEL_BOUNDARY',original_main_sha256=sha(directory/info[0]['file']),
                         confirmed_targets=[dict(pc=0x34286e,target=0x3428b8,pool=0x342980,slot=0x360ae0,
                                                 anchor_kind='registered_pointer_cpu_bound',case='register_then_invoke')],
                         user_callback_slot=0x360ad0,completed_cases=2,expected_custom_aux_guard_cases=1,
                         hardware_access=False,gnu_modified=False,
                         limits=['Two complete registrations and one expected stop before unsupported AUX10111 read; AUX10110 access remains static.',
                                 'Synthetic callers and payload1 candidate mapping do not prove hardware reset, IRQ delivery or global startup reachability.',
                                 'Original shared code and all input files unchanged; no device values injected.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
