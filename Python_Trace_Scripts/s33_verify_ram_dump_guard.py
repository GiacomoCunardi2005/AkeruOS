#!/usr/bin/env python3
"""Execute the resident CRC/one-shot guard before any Resource module call."""
from types import SimpleNamespace
import json
import re
import struct
import zlib

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe

GUARD, FLAG, MODULE, STATE = 0x35BB20, 0x35BBEC, 0xE99E00, 0x2010000


def main():
    r = Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,
        output=None,action='ram-dump-resident-module-guard'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare()
        source = ROOT/'AkeruOS/ram_dump_guard.s'
        r.input_hashes[str(source)]=sha(source)
        (r.out/source.name).write_bytes(source.read_bytes())

        def binary(name, asm):
            elf=compile_probe(r,name,asm)
            out=r.out/(name+'.bin')
            p=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,out])
            assert p.returncode==0,p.stdout
            return out.read_bytes()

        module_code=binary('module_callback',f' mov r1,{STATE:#x}\n ld r0,[r1]\n add r0,r0,1\n st r0,[r1]\n mov r0,0x777\n j_s [blink]\n')
        module=module_code+bytes((i*13+5)&255 for i in range(256-len(module_code)))
        crc=zlib.crc32(module)
        obj=r.out/'guard.o';elf=r.out/'guard.elf';link=r.out/'guard.ld'
        link.write_text(f'SECTIONS {{ . = {GUARD:#x}; .text : {{ *(.text) }} }}\n'
            f'akeru_ram_dump_guard_state = {FLAG:#x};\nakeru_ram_dump_module_base = {MODULE:#x};\n'
            f'akeru_ram_dump_module_bytes = {len(module)};\nakeru_ram_dump_module_crc = {crc:#x};\n'
            f'akeru_ram_dump_module_entry = {MODULE:#x};\n'
            'nikon_after_resource_original = 0x159128;\nnikon_enter_critical = 0x1786e8;\nnikon_leave_critical = 0x179354;\n')
        for name,cmd in [('guard_assemble',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',obj,source]),
                         ('guard_link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',link,'-o',elf,obj])]:
            p=r.command(name,cmd);assert p.returncode==0,p.stdout
        raw=r.out/'guard_text.bin'
        p=r.command('guard_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,raw]);assert p.returncode==0,p.stdout
        code=raw.read_bytes();assert len(code)<=FLAG-GUARD,(len(code),FLAG-GUARD)
        p=r.command('guard_disassembly',[TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',elf]);assert p.returncode==0
        guard=code+bytes(FLAG-GUARD-len(code))+bytes(4)
        assert len(guard)==0xD0
        original=binary('original_callback',f' mov r1,{STATE:#x}\n ld r0,[r1,4]\n add r0,r0,1\n st r0,[r1,4]\n mov r0,0x1234\n j_s [blink]\n')
        lock=binary('lock_callback',f' mov r1,{STATE:#x}\n ld r0,[r1,8]\n add r0,r0,1\n st r0,[r1,8]\n j_s [blink]\n')
        unlock=binary('unlock_callback',f' mov r1,{STATE:#x}\n ld r0,[r1,12]\n add r0,r0,1\n st r0,[r1,12]\n j_s [blink]\n')
        for name, data, initial_flag, expected_calls, repeats in [
            ('valid',module,0,1,1),('repeat',module,0,1,3),
            ('zero_module',bytes(len(module)),0,0,1),
            ('corrupt_tail',module[:-1]+bytes([module[-1]^1]),0,0,1),
            ('already_launched',module,1,0,1)]:
            options=[]
            for label,address,data in [('guard',GUARD,guard[:-4]+struct.pack('<I',initial_flag)),
                    ('module',MODULE,data),('state',STATE,bytes(32)),
                    ('original',0x159128,original),('lock',0x1786E8,lock),('unlock',0x179354,unlock)]:
                path=r.out/f'{name}_{label}.bin'
                # sim-memopt uses address modulo eight as padding.
                path.write_bytes(bytes(address%8)+data+bytes(16))
                options+=['--memory-mapfile','/result/'+path.name,'--memory-region',f'{address:#x},{len(data)+16}']
            caller=' mov r13,0x1313\n mov r14,0x1414\n mov r15,0x1515\n mov r20,sp\n'
            for _ in range(repeats):
                caller+=f' mov r12,{GUARD:#x}\n jl [r12]\n mov r1,0x1234\n cmp r0,r1\n bne fail\n'
            caller+=' cmp r13,0x1313\n bne fail\n cmp r14,0x1414\n bne fail\n cmp r15,0x1515\n bne fail\n cmp sp,r20\n bne fail\n mov r0,0\n b finish\nfail:\n mov r0,7\nfinish:\n mov r8,1\n trap_s 1\n'
            test=compile_probe(r,'caller_'+name,caller)
            case,log=r.run(name,'/result/'+test.name,options)
            assert case['exit_code']==0 and case['fault'] is None,log
            state=struct.unpack_from('<4I',(r.out/f'{name}_state.bin').read_bytes())
            assert state==(expected_calls,repeats,expected_calls,expected_calls),state
            got=(r.out/f'{name}_guard.bin').read_bytes()
            assert got[:len(code)]==code
            assert struct.unpack_from('<I',got,FLAG-GUARD)[0]==int(initial_flag!=0 or expected_calls!=0)
            case.update(module_calls=expected_calls,original_calls=repeats,
                        callee_saved_and_stack_preserved=True)
            print('PASS guard',name,flush=True)
        r.finish()
        r.results.update(status='PASS_RESIDENT_CRC_ONESHOT_GUARD',guard_code_bytes=len(code),
            proposed_guard_range=[hex(GUARD),hex(FLAG+4)],module_crc=hex(crc),
            assumptions=['Original helper, lock and module entry are declared counting stubs',
                         'Module bytes and guard flag are initialized in laboratory mappings'],
            limits=['Does not prove hardware Resource residency, cache coherence, original lock or SD behavior',
                    'Placement requires separate reference/lifetime audit; no firmware packaged here'])
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    latest=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper/guard_latest.json'
    latest.write_text(json.dumps(dict(evidence=str((r.out/'verified_evidence.json').relative_to(ROOT)),status=r.results['status']),indent=2)+'\n')
    print(r.results['status'],r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
