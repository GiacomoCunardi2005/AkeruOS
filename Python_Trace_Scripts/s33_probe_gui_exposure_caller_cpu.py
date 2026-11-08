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
    cases = [(42000,0,1000000,42000,1,1), (84000,0,1000000,84000,1,1), (42000,0,20000,20000,1,1), (42000,100,1000000,44941,1,1), (42000,0,1000000,42000,42000,0), (42000,0,1000000,42000,50000,0)]
    which = int(sys.argv[1]); old_time, adjustment, cap, expected, comparison, expected_decision = cases[which]
    mode, index, b21, gate = 4, 6, 1, 1
    out = ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime(f'exposure_caller_probe_{which}_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='exposure-calc-input-probe'))
    print('Prove:', out, flush=True)
    try:
        r.prepare(); sim=LAB/'install/bin/arc-elf32-run'; assert sha(sim)==json.loads(BUILD.read_text())['experimental_sha256']; r.experimental_engine=LAB; dump = ROOT/'DUMPS/MainCode.dmp'; data = dump.read_bytes(); r.input_hashes[str(dump)] = sha(dump)
        for addr, size in ((0xfda28, 0x1dc), (0xf6f54, 0x34), (0xfde08, 8), (0x18c99c, 8), (0x128c20, 8)):
            b, off = locate(addr, size); assert raw(addr, size) == data[b['offset']+off:b['offset']+off+size]
        assert u32(0xf6f10) == 0x37fbd0 and u32(0xfdcf8) == 0x345718
        images = {i:bytearray(PS[i]) for i in (0,1)}; maps = []; patches = []
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
            ('observe', 0xd8e22, ''' mov r10,0x2001000
 st r0,[r10,12]
 ld r3,[fp,-148]
 st r3,[r10]
 ldh r3,[fp,-136]
 st r3,[r10,4]
 ldb r3,[fp,-120]
 st r3,[r10,8]
 mov r0,0
 mov r8,1
 trap_s 1
'''),
            ('dispatch', 0x18c634, ' mov r0,0\n j_s [blink]\n')]
        for i, (name, addr, code) in enumerate(fixtures):
            target = 0x2030000+i*0x400; p = binary(name, code); maps += mapping(p,target)
            entry = binary('entry_'+name, f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
            b, off = locate(addr, 8); before = bytes(images[b['index']][off:off+8]); assert before == raw(addr,8)
            images[b['index']][off:off+8] = entry; patches.append(dict(address=hex(addr), original=before.hex(), fixture=entry.hex(), name=name))
        callback=binary('indirect', ' mov r0,0\n j_s [blink]\n'); maps += mapping(callback,0x2030c00)
        for i,img in images.items():
            p=out/f'block{i}_fixture.bin';p.write_bytes(img);maps += mapping(p, BS[i]['load_address_candidate'])
        for name, addr, content in [('observation',0x2001000,bytes([0xa5])*32), ('snapshot',0x2002000,bytes(64)), ('result',0x2003000,bytes(128)), ('input1',0x2005000,struct.pack('<I',4)+bytes(60)), ('input2',0x2006000,bytes([1])+bytes(63)), ('context',0x43b000,bytes(8192)), ('table',0x436000,bytes(4096)), ('limit',0x2004000,struct.pack('<II',1,1000000)+bytes(24))]:
            p=out/(name+'.bin');p.write_bytes(content);maps+=mapping(p,addr)
        asm=f''' sr 0,[0x48]
 mov r1,0x3663a0
 mov r0,0x2030c00
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
 mov r0,{index}
 mov r12,0xd03b8
 jl [r12]
 mov r0,{old_time}
 mov r12,0xd03e0
 jl [r12]
 mov r0,0
 mov r1,0x2005000
 mov r2,0x2006000
 mov r3,0
 mov r4,0
 mov r12,0xd8ca4
 jl [r12]
 mov r0,1
 mov r8,1
 trap_s 1
'''
        elf=compile_probe(r,'cases',asm); case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
        assert case['exit_code']==0 and case['fault'] is None,log
        observation=(out/'observation.bin').read_bytes(); value,iso,flag=struct.unpack_from('<3I',observation)
        print('CALLER OUTPUT',value,iso,flag,flush=True)
        assert (value,iso,flag)==(expected,125,expected_decision),(value,iso,flag,expected,expected_decision)
        assert struct.unpack_from('<I',observation,12)[0]==0
        trace=(out/'cases.trace').read_text()
        for addr in ('0x0d8ca4','0x0d8d06','0x0f6f54','0x0d8e1e','0x0fda28','0x0d8e22'):
            assert any(line.startswith(addr+' ') for line in trace.splitlines()),addr
        (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ORIGINAL_CALLER_FIRST_FDA28_RETURN',case=which,result_flag=flag,result_time=value,comparison=comparison,hardware_tested=False,installable=False)
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS prefix:',which,'observed:',value,out,flush=True)

if __name__=='__main__': main()
