#!/usr/bin/env python3
"""Probe original FDA28 through its first calculation call with synthetic context."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe, LAB, BUILD
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32


def main():
    # mode, ISO index, old time, 0x21, gate at context +0x478, expected argument
    cases = [(1,0,0), (1,1,0), (7,0,125), (7,1,125)]
    which = int(sys.argv[1]); selection, update_operational, expected_iso = cases[which]
    confirmed_iso = 0 if selection==1 else 125
    old_time, adjustment, cap, expected, comparison, expected_decision = 42000, 0, 1000000, 42000, 1, 1
    mode, index, b21, gate = 4, 6, 1, 1
    out = ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime(f'gui_iso_mode_wrapper_calc_probe_{which}_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='exposure-calc-input-probe'))
    print('Prove:', out, flush=True)
    try:
        r.prepare(); sim=LAB/'install/bin/arc-elf32-run'; assert sha(sim)==json.loads(BUILD.read_text())['experimental_sha256']; r.experimental_engine=LAB; dump = ROOT/'DUMPS/MainCode.dmp'; data = dump.read_bytes(); r.input_hashes[str(dump)] = sha(dump)
        for addr, size in ((0xfda28, 0x1dc), (0xf6f54, 0x34), (0xfde08, 8), (0x18c99c, 8), (0x128c20, 8)):
            b, off = locate(addr, size); assert raw(addr, size) == data[b['offset']+off:b['offset']+off+size]
        assert u32(0xf6f10) == 0x37fbd0 and u32(0xfdcf8) == 0x345718
        images = {i:bytearray(PS[i]) for i in (0,1,2,4,5)}; maps = []; patches = []
        def mapping(p, addr):
            return ['--memory-mapfile', '/result/'+p.name, '--memory-region', f'{addr:#x},{p.stat().st_size}']
        def binary(name, asm):
            elf = compile_probe(r, name, asm); p = out/(name+'.bin')
            result = r.command(name+'_extract', [TOOLCHAIN/'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, p]); assert result.returncode == 0, result.stdout
            content = p.read_bytes(); p.write_bytes(content+bytes(8+(-len(content))%8)); return p
        fixtures = [
            ('copy', 0x128c20, ''' mov r3,0
copy_loop:
 cmp r3,r2
 beq copy_end
 add r4,r1,r3
 ldb r5,[r4]
 add r4,r0,r3
 stb r5,[r4]
 add r3,r3,1
 b copy_loop
copy_end:
 j_s [blink]
'''),
            ('observe', 0xd8e22, ''' st.aw r3,[sp,-4]
 st.aw r10,[sp,-4]
 mov r10,0x2001000
 st r0,[r10,12]
 ld r3,[fp,-148]
 st r3,[r10]
 ldh r3,[fp,-136]
 st r3,[r10,4]
 ldb r3,[fp,-120]
 st r3,[r10,8]
 ld.ab r10,[sp,4]
 ld.ab r3,[sp,4]
 cmp r16,1
 beq continue_equal
 mov r12,0xd8e9a
 j_s [r12]
continue_equal:
 mov r12,0xd8e28
 j_s [r12]
'''),
            ('dispatch', 0x18c634, ' mov r0,0\n j_s [blink]\n'),
            ('open', 0x1453e4, ' mov r10,0x2001000\n st r0,[r10,40]\n st r1,[r10,44]\n ld r11,[r10,48]\n add r11,r11,1\n st r11,[r10,48]\n mov r0,0\n j_s [blink]\n'),
            ('control', 0x145790, ' mov r0,0x2200000\n j_s [blink]\n')]
        for i, (name, addr, code) in enumerate(fixtures):
            target = 0x2030000+i*0x400; p = binary(name, code); maps += mapping(p,target)
            entry = binary('entry_'+name, f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
            b, off = locate(addr, 8); before = bytes(images[b['index']][off:off+8]); assert before == raw(addr,8)
            images[b['index']][off:off+8] = entry; patches.append(dict(address=hex(addr), original=before.hex(), fixture=entry.hex(), name=name))
        noop=binary('restore_noop', ' mov r0,0\n j_s [blink]\n'); maps += mapping(noop,0x2031800)
        entry=binary('entry_restore_noop', ' mov_s r12,0x2031800\n j_s [r12]\n').read_bytes()[:8]
        for addr in (0xde23c,0xde3a4,0xde664,0xdee04,0x17c5e4,0xde5f0,0xd0428,0x17c448,0x17e468,0x17e124,0xdeb78,0xdebcc,0xdebf0):
            b,off=locate(addr,8); before=bytes(images[b['index']][off:off+8]); assert before==raw(addr,8)
            images[b['index']][off:off+8]=entry; patches.append(dict(address=hex(addr),original=before.hex(),fixture=entry.hex(),name='restore_noop'))
        helper_fixtures = [
            ('restore_capture',0x17e36c, ' mov r10,0x2001000\n ldh r11,[r13,8]\n st r11,[r10,72]\n ld r11,[r13,24]\n st r11,[r10,76]\n mov r0,0\n j_s [blink]\n'),
            ('snapshot_one',0x17c528,' mov r0,1\n j_s [blink]\n'),
            ('snapshot_time',0x17c480,' mov r0,90000\n j_s [blink]\n'),
            ('config',0xcdc80,' mov r0,0\n stb r0,[r1]\n j_s [blink]\n')]
        helper_fixtures += [(f'snapshot_{addr:x}',addr,' mov r0,0\n j_s [blink]\n') for addr in (0xde254,0xde3e4,0xde6d0,0xdee20,0xde398,0xde60c,0x17c420,0x17e510,0x17e238,0xdeba0,0xdebe8,0xdec0c,0x17e460,0xca38c,0xce4c8,0x14a1f8)]
        helper_fixtures += [(f'wrapper_{addr:x}',addr,' mov r0,0\n j_s [blink]\n') for addr in (0xdd078,0x14941c,0xde574)]
        for i,(name,addr,code) in enumerate(helper_fixtures):
            target=0x2032000+i*0x400; p=binary(name,code); maps+=mapping(p,target)
            entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
            b,off=locate(addr,8); before=bytes(images[b['index']][off:off+8]); assert before==raw(addr,8)
            images[b['index']][off:off+8]=entry; patches.append(dict(address=hex(addr),original=before.hex(),fixture=entry.hex(),name=name))
        callback=binary('indirect', ' mov r0,0\n j_s [blink]\n'); maps += mapping(callback,0x2031400)
        for i,img in images.items():
            p=out/f'block{i}_fixture.bin';p.write_bytes(img);maps += mapping(p, BS[i]['load_address_candidate'])
        for name, addr, content in [('observation',0x2001000,bytes(80)), ('snapshot',0x2002000,bytes(64)), ('result',0x2003000,bytes(128)), ('restore_record',0x2100000,bytes(8)+struct.pack('<H',19)+bytes(2)+bytes([1])+bytes(11)+struct.pack('<I',90000)+bytes(36)), ('input1',0x2005000,struct.pack('<I',4)+bytes(60)), ('input2',0x2006000,bytes([1])+bytes(63)), ('control_data',0x2200000,bytes(37)+bytes([24,selection])+bytes(25)+struct.pack('<I',0x989da4)+bytes(188)), ('mode',0x681000,bytes(4096)), ('context',0x43b000,bytes(8192)), ('table',0x436000,bytes(4096)), ('limit',0x2004000,struct.pack('<II',1,1000000)+bytes(24))]:
            p=out/(name+'.bin');p.write_bytes(content);maps+=mapping(p,addr)
        asm=f''' sr 0,[0x48]
 mov r1,0x3663a0
 mov r0,0x2031400
 st r0,[r1]
 mov r1,0x3663c0
 st r0,[r1]
 mov r1,0x436a41
 mov r0,1
 stb r0,[r1]
 mov r1,0x436df0
 mov r0,1
 sth r0,[r1]
 mov r1,0x436df2
 mov r0,0x8000
 sth r0,[r1]
 mov r1,0x436dec
 mov r0,{comparison}
 st r0,[r1]
 mov r1,0x3663a4
 mov r0,0x2004000
 st r0,[r1]
 mov r1,0x3826a4
 mov r0,{cap}
 st r0,[r1]
 mov r1,0x43bb68
 mov r0,16
 sth r0,[r1]
 mov r1,0x380044
 mov r0,1
 sth r0,[r1]
 mov r1,0x37fbd0
 mov r0,0
 mov r2,0
zero_loop:
 add r3,r1,r2
 stb r0,[r3]
 add r2,r2,1
 cmp r2,64
 blt zero_loop
 mov r0,{mode}
 sth r0,[r1]
 mov r0,{adjustment}
 sth r0,[r1,14]
 mov r0,{b21}
 stb r0,[r1,33]
 mov r0,777
 st r0,[r1,56]
 mov r0,{gate}
 mov r3,0x380048
 sth r0,[r3]
 mov r0,19
 mov r12,0xd03b8
 jl [r12]
 mov r0,0
 mov r1,0x4801
 mov r2,0
 mov r12,0x7d25b0
 jl [r12]
 mov r10,0x2001000
 mov r1,0x37fbf2
 ldh r0,[r1]
 st r0,[r10,56]
 mov r1,0x365787
 ldb r0,[r1]
 st r0,[r10,60]
 mov r1,0x899ad0
 mov r0,{old_time//1000}
 st r0,[r1]
 mov r0,0
 mov r1,0x580
 mov r2,0
 mov r12,0x7d2394
 jl [r12]
 mov r0,{update_operational}
 cmp r0,0
 beq skip_update
 mov r0,19
 mov r12,0x17c320
 jl [r12]
skip_update:
 mov r1,0x681fc0
 mov r0,4
 stb r0,[r1]
 mov r12,0x65ba94
 jl [r12]
 mov r10,0x2001000
 mov r1,0x37fbf2
 ldh r0,[r1]
 st r0,[r10,64]
 mov r0,0
 mov r1,0x2005000
 mov r2,0x2006000
 mov r3,0
 mov r4,0
 mov r10,0x2001000
 st sp,[r10,16]
 mov r12,0xd8ca4
 jl [r12]
 mov r10,0x2001000
 st sp,[r10,20]
 st r0,[r10,24]
 mov r1,0x380844
 ld r0,[r1,52]
 st r0,[r10,28]
 ldh r0,[r1,64]
 st r0,[r10,32]
 ldb r0,[r1,80]
 st r0,[r10,36]
 mov r0,0
 mov r8,1
 trap_s 1
'''
        elf=compile_probe(r,'cases',asm); case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
        assert case['exit_code']==0 and case['fault'] is None,log
        observation=(out/'observation.bin').read_bytes(); value,iso,flag=struct.unpack_from('<3I',observation)
        print('CALLER OUTPUT',value,iso,flag,'FINAL',struct.unpack_from('<3I',observation,28),flush=True)
        print('ISO AFTER',struct.unpack_from('<2I',observation,56),flush=True)
        expected_flag = 0 if expected_iso==0 else 1
        expected_index = {0:19,1:0,7:6,20:19}[selection]
        assert struct.unpack_from('<2I',observation,56)==(confirmed_iso,expected_index)
        assert struct.unpack_from('<I',observation,64)[0]==expected_iso
        assert (value,iso,flag)==(42000,expected_iso,expected_flag)
        assert struct.unpack_from('<I',observation,12)[0]==0
        assert struct.unpack_from('<I',observation,16)[0]==struct.unpack_from('<I',observation,20)[0]
        assert struct.unpack_from('<3I',observation,28)==(42000,expected_iso,expected_flag)
        assert struct.unpack_from('<3I',observation,40)==(0x36,0,2)
        trace=(out/'cases.trace').read_text()
        for addr in ('0x7d25b0','0x6410f4','0x0d03b8','0x7d2394','0x0d03e0','0x0d8ca4','0x0d8d06','0x0f6f54','0x0d8e1e','0x0fda28','0x0d8e22','0x0d9072'):
            assert any(line.startswith(addr+' ') for line in trace.splitlines()),addr
        expected_record = 0 if selection==1 else 6
        assert struct.unpack_from('<2I',observation,72)==(expected_record,42000),struct.unpack_from('<2I',observation,72)
        assert any(line.startswith('0x65db56 ') and '0x4' in line for line in trace.splitlines())
        initial_record = 19 if update_operational else (0 if selection==1 else 6)
        assert any(line.startswith('0x0ca616 ') and f'0x{initial_record:x}' in line for line in trace.splitlines())
        assert any(line.startswith('0x65bcdc ') and '0x0' in line for line in trace.splitlines())
        for addr in ('0x65ba94','0x65db54','0x65bc60','0x0ca5dc','0x17c3f0','0x0ca654'):
            assert any(line.startswith(addr+' ') for line in trace.splitlines()),addr
        calls=sum(line.startswith('0x0fda28 ') for line in trace.splitlines())
        assert calls == (2 if expected_iso==0 else 1),(selection,calls)
        if expected_iso==0: assert any(line.startswith('0x0d8f64 ') for line in trace.splitlines())
        (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ISO_MODE_WRAPPER_OPERATIONAL_INDEX',case=which,result_flag=flag,result_time=value,comparison=comparison,final_time=struct.unpack_from('<I',observation,28)[0],final_iso=struct.unpack_from('<I',observation,32)[0],final_flag=struct.unpack_from('<I',observation,36)[0],selection=selection,update_operational=bool(update_operational),confirmed_iso=confirmed_iso,record_iso=expected_record,calculation_calls=calls,assumptions=['Injected ISO/time confirmation callbacks with synthetic control and explicit 65BA94 wrapper reads synthetic mode 4 and calls 65BC60; CA5DC record from original 17C3F0 getter, optional synthetic 17C320 update; other getters/setters replaced with fixtures and later explicit D8CA4 call, synthetic input and RAM; open, copy, 18C634 and callback fixtures; recorder replaces the compare and branch at D8E22 and reproduces the selected path.'],limits=['One synthetic path, not all D8CA4 inputs; no AE, physical capture, sensor or timing.'],hardware_tested=False,installable=False)
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS prefix:',which,'observed:',value,out,flush=True)

if __name__=='__main__': main()
