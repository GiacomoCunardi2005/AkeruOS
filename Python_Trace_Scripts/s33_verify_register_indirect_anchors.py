#!/usr/bin/env python3
"""Bind original callback registration/indirect targets without modeling custom AUX."""
import json
import re
import struct
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import DefinedRunner,LAB,BUILD,known_sections
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window


def main():
    r=DefinedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='register-indirect-anchors'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256']
        r.experimental_engine=LAB
        for p in [BUILD,LAB/'install/bin/arc-elf32-run',Path(__file__)]:r.input_hashes[str(p)]=sha(p)
        (r.out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        blocks,payloads,directory=verified_payloads(ROOT);info={b['index']:b for b in blocks}
        body=payloads[0];data=payloads[1];base=info[0]['load_address_candidate'];data_base=info[1]['load_address_candidate']
        main=r.out/'payload0_mmap.bin';main.write_bytes(body)
        for i in [0,1]:r.input_hashes[str(directory/info[i]['file'])]=sha(directory/info[i]['file'])
        slot=0x360ad8;assert struct.unpack_from('<I',body,0x342f20-base)[0]==slot
        assert struct.unpack_from('<I',body,0x33975c-base)[0]==0x339cdc
        assert struct.unpack_from('<I',body,0x33bba0-base)[0]==0x342d20
        assert struct.unpack_from('<I',body,0x342e74-base)[0]==0x342de4
        specs=[('register_constructor',0x339404,0,None,None,'register',0x339cdc),
               ('register_helper_tag',0x342e88,0x11223344,None,None,'register',0x11223344),
               ('register_then_invoke',0x339404,0,0x10802,0x339cde,'callback',0x339cdc),
               ('original_clear_caller',0x342e34,0,0x10037,0x342dfa,'plain',None),
               ('original_set_caller',0x33b7f6,0,0x10036,0x342d36,'plain',None)]
        specs += [(f'set_selector{i}',0x342d20,i,0x10036,pc,'plain',None)for i,pc in [(1,0x342d5a),(2,0x342d8a),(3,0x342dba)]]
        specs += [('set_selector4_return',0x342d20,4,None,None,'plain',None)]
        specs += [(f'clear_selector{i}',0x342de4,i,0x10037,pc,'plain',None)for i,pc in [(1,0x342e06),(2,0x342e12),(3,0x342e1e)]]
        specs += [('clear_selector4_return',0x342de4,4,None,None,'plain',None)]
        for name,entry,arg,guard,pc,kind,expected_pointer in specs:
            options=['--memory-mapfile','/result/'+main.name,'--memory-region',f'{base:#x},{len(body):#x}']
            extra='';model_data=None
            if kind in ['register','callback']:
                model_data=r.out/(name+'_payload1_mmap.bin');model_data.write_bytes(data)
                options+=['--memory-mapfile','/result/'+model_data.name,'--memory-region',f'{data_base:#x},{len(data):#x}']
                extra=f',{data_base:#x}:{len(data):#x}'
            asm=f'mov r9,sp\nmov r7,0x77665544\nmov r13,0x13371337\nmov r0,{arg:#x}\nmov r1,0x80\nmov r3,{entry:#x}\njl [r3]\n'
            if kind=='callback':asm+=f'mov r2,{slot:#x}\nld r0,[r2]\njl [r0]\n'
            if guard is None:
                asm+='cmp sp,r9\nbne fail\ncmp r7,0x77665544\nbne fail\ncmp r13,0x13371337\nbne fail\n'
                if kind=='register':asm+=f'mov r2,{slot:#x}\nld r2,[r2]\ncmp r2,{expected_pointer:#x}\nbne fail\n'
                else:asm+=f'cmp r0,{arg:#x}\nbne fail\n'
                asm+='mov r0,0\nb finish\n'
            else:asm+='mov r0,9\nb finish\n'
            asm+='fail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n'
            elf=compile_probe(r,name,asm);r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}'+extra
            case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True)
            trace=(r.out/(name+'.trace')).read_text()
            assert case['fault']is None,log[-2000:]
            if guard is None:
                assert case['exit_code']==0 and 'S33_AUX_RANGE'not in log,log[-2000:]
            else:
                assert case['exit_code']==5 and f'S33_AUX_RANGE index={guard}'in log,log[-2000:]
                assert re.search(rf'Extract: 0x0*{pc:x}:',trace),(name,hex(pc),trace[-2000:])
                # A decoded/attempted LR stopped by the model is not a successful
                # guest read; no custom value or synthetic device is supplied.
                result_lines=[line for line in trace.splitlines()if re.match(rf'0x0*{pc:x}\s+lr\b',line)]
                assert all('cr <-'not in line and 'auxr <-'not in line for line in result_lines)
            if model_data:
                expected=bytearray(data);struct.pack_into('<I',expected,slot-data_base,expected_pointer)
                assert model_data.read_bytes()==expected
            if name=='register_then_invoke':assert 'pc <- 0x339cdc'in trace
            if name=='original_clear_caller':assert 'pc <- 0x342de4'in trace
            if name=='original_set_caller':assert 'pc <- 0x342d20'in trace
            if guard is not None and name!='register_then_invoke':assert f'pc <- {pc:#x}'in trace
            assert main.read_bytes()==body
            case.update(original_entry=hex(entry),argument0=hex(arg),case_kind=kind,
                        expected_model_guard_index=hex(guard)if guard is not None else None,
                        decoded_original_lr_site=hex(pc)if pc is not None else None,
                        custom_aux_semantic_result_observed=False,full_routine_completed=guard is None,
                        callback_slot=hex(slot)if model_data else None,callback_pointer=hex(expected_pointer)if model_data else None,
                        data_payload_input_sha256=sha(directory/info[1]['file'])if model_data else None,
                        all_data_payload_other_bytes_unchanged=True if model_data else None)
            print(name,'PASS',case['exit_code'],case['instructions'],flush=True)
        windows=[('register',0x339404,0x33941c),('register_helper',0x342e88,0x342e90),
                 ('dispatcher_slot',0x342ece,0x342eea),('set_original_caller',0x33b7f6,0x33b812),
                 ('clear_original_caller',0x342e34,0x342e4c),('set_dispatch',0x342d20,0x342de4),('clear_dispatch',0x342de4,0x342e34)]
        for name,a,z in windows:(r.out/(name+'_source_disassembly.txt')).write_text(aligned_window(body,base,a,z)+'\n')
        r.results.update(status='PASS_REGISTER_INDIRECT_ANCHORS_AND_MODEL_BOUNDARY',
                         confirmed_targets=[dict(pc=0x33940a,target=0x339cdc,anchor_kind='registered_pointer_cpu_bound',case='register_then_invoke',pool=0x33975c,slot=slot),
                                            dict(pc=0x33b7fc,target=0x342d20,anchor_kind='original_indirect_call_guest_target',case='original_set_caller',pool=0x33bba0),
                                            dict(pc=0x342e38,target=0x342de4,anchor_kind='original_indirect_call_guest_target',case='original_clear_caller',pool=0x342e74)],
                         original_main_sha256=sha(directory/info[0]['file']),payload1_input_sha256=sha(directory/info[1]['file']),
                         completed_cases=4,expected_custom_aux_guard_cases=9,hardware_access=False,gnu_modified=False,
                         limits=['Four complete cases and nine expected stops before unsupported custom AUX reads; no custom LR result or SR operation observed.',
                                 'Synthetic callers and selected original caller prefixes do not prove global startup reachability or physical IRQ delivery.',
                                 'Payload1 is mapped by its candidate load address; original bytes are fixture provenance, not hardware RAM/reset measurements.',
                                 'No GNU bank/config/source/build change and no custom device values supplied.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
