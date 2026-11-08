#!/usr/bin/env python3
"""Run the original diagnostic dispatcher, iris panel and setter together in synthetic conditions."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe, LAB, BUILD
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, disasm, u32


def main():
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('callback_iris_no_exit_probe_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='model-iris-panel'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        sim=LAB/'install/bin/arc-elf32-run'; assert sha(sim)==json.loads(BUILD.read_text())['experimental_sha256']; r.experimental_engine=LAB
        for source in (ROOT/'AkeruOS/ui/menu.c',ROOT/'AkeruOS/ui/menu.h',Path(__file__)): r.input_hashes[str(source)]=sha(source)
        dump = ROOT / 'DUMPS/MainCode.dmp'
        data = dump.read_bytes()
        r.input_hashes[str(dump)] = sha(dump)
        for a, n in [(0x2c4fac,0x9c), (0x406c68,47*8), (0x2c5074,0x13c), (0x406e05,43), (0x406e89,16), (0x406e9a,18), (0x149530, 0x16), (0x18b85c, 0x74), (0x18b788, 4), (0x149362, 0x10), (0x169e1c, 0x80), (0x169d78, 0x124), (0x1453f4, 0x10), (0x235b0c, 0xb4), (0x2358f4, 0x5c), (0x235950, 0x60)]:
            block, offset = locate(a, n)
            assert raw(a, n) == data[block['offset'] + offset:block['offset'] + offset + n]
        assert (u32(0x406cf0),u32(0x406cf4))==(0x50,0x2c5074)
        (out / 'gnu_windows.txt').write_text('\n'.join(disasm(a, b) for a, b in [(0x149530, 0x149546), (0x18b85c, 0x18b8d0), (0x149362, 0x149372)]))
        images = {i: bytearray(PS[i]) for i in (0, 1, 2, 3, 4, 5)}
        maps, patches = [], []
        def binary(name, asm):
            elf = compile_probe(r, name, asm)
            path = out / (name + '.bin')
            result = r.command(name + '_extract', [TOOLCHAIN / 'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, path])
            assert result.returncode == 0, result.stdout
            data = path.read_bytes()
            path.write_bytes(data + bytes(8 + (-len(data)) % 8))
            return path
        def mapping(path, addr):
            return ['--memory-mapfile', '/result/' + path.name, '--memory-region', f'{addr:#x},{path.stat().st_size}']
        common = ' mov r10,0x2000000\n ld r10,[r10]\n'
        services = [
            ('acquire', 0x235a1c, common + ' ld r11,[r10,32]\n add r11,r11,1\n st r11,[r10,32]\n mov r11,0x1234\n sth r11,[r1]\n ld r0,[r10,8]\n j_s [blink]\n'),
            ('guard', 0x235da0, common + ' ld r11,[r10,36]\n add r11,r11,1\n st r11,[r10,36]\n ld r0,[r10,12]\n j_s [blink]\n'),
            ('release', 0x23524c, common + ' ld r11,[r10,44]\n add r11,r11,1\n st r11,[r10,44]\n mov r0,0\n j_s [blink]\n'),
            ('cleanup', 0x18b9d4, common + ' ld r11,[r10,64]\n add r11,r11,1\n st r11,[r10,64]\n mov r0,0\n j_s [blink]\n'),
        ]
        services += [
            ('request_lock',0x1786e8,' mov r0,0\n j_s [blink]\n'),
            ('request_unlock',0x179354,' mov r0,0\n j_s [blink]\n'),
            ('request_busy',0x234f1c,common+' ld r0,[r10,16]\n mov r11,1\n sub r0,r11,r0\n j_s [blink]\n'),
            ('request_event',0x158ce0,' mov r0,0\n j_s [blink]\n'),
            ('request_mailbox',0x145f28,' mov r0,0\n j_s [blink]\n'),
            ('request_wait',0x158d04,' mov r0,0\n j_s [blink]\n')]
        services += [(f'queue_{addr:x}',addr,' mov r0,0\n j_s [blink]\n') for addr in (0x1593ac,0x1594a4,0x158cbc,0x17c150)]
        # shortcut: key getter replays a bounded sequence, not real electrical input.
        services += [
            ('key', 0x16f920, common + " cmp r0,4\n bne key_other\n ld r0,[r10,72]\n add r11,r0,1\n st r11,[r10,72]\n cmp r11,6\n beq test_stop\n mov r0,0\n j_s [blink]\n test_stop: mov r0,42\n mov r8,1\n trap_s 1\n key_other: ld r11,[r10,68]\n cmp r0,r11\n bne key_zero\n ld r0,[r10,76]\n add r11,r0,1\n st r11,[r10,76]\n cmp r0,0\n mov r0,0\n bne key_done\n mov r0,1\n key_done: j_s [blink]\n key_zero: mov r0,0\n j_s [blink]\n"),
            ('draw_text',0x1567f8,common+' st r2,[r10,80]\n mov r0,0\n j_s [blink]\n'),
        ] + [(name,addr,' mov r0,0\n j_s [blink]\n') for name,addr in
             [('dispatch_init1',0xca404),('dispatch_init2',0xdecd4),('dispatch_init3',0x12df54),('dispatch_init5',0x1490fc),('dispatch_init6',0x1487e8),('dispatch_init7',0x148e14),('init',0x14a7b0),('delay',0x145c3c),('setup',0x149f80),('clear',0x1564c0),('paint',0x1564a8)]]
        for i, (name, addr, asm) in enumerate(services):
            target = 0x2030000 + i * 0x400
            path = binary(name, asm)
            maps += mapping(path, target)
            entry = binary('entry_' + name, f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
            block, off = locate(addr, 8)
            before = bytes(images[block['index']][off:off + 8])
            assert before == raw(addr, 8)
            images[block['index']][off:off + 8] = entry
            patches.append({'name': name, 'address': hex(addr), 'original': before.hex(), 'fixture': entry.hex()})
        tests = [(9,1,9,1,0x2180), (1,9,10,1,0x2180), (9,1,9,0,0x2180), (1,9,10,0,0x2180), (9,1,9,1,0x700)]
        asm = ' sr 0,[0x48]\n mov r20,0x2000000\n'
        for i, (initial, requested, key, accepted, event) in enumerate(tests):
            a = 0x2001000 + i * 128
            asm += f''' mov r21,{a:#x}
 st r21,[r20]
 mov r1,0x36a480
 mov r0,0x1234
 sth r0,[r1]
 mov r1,0x36a482
 mov r0,0
 stb r0,[r1]
 mov r1,0x3ebd3c
 mov r0,0x2003000
 st r0,[r1]
 mov r1,0xfef0388
 mov r0,0xa5a7
 sth r0,[r1]
 mov r1,0xff04024
 mov r0,0xa5b8
 sth r0,[r1]
 mov r1,0x367fea
 mov r0,{initial}
 stb r0,[r1]
 mov r0,{accepted}
 st r0,[r21,16]
 mov r0,{key}
 st r0,[r21,68]
 st sp,[r21,24]
 mov r0,0
 mov r1,0x681b6b
 stb r0,[r1]
 mov r1,0x367bbc
 st r0,[r1]
 mov r1,0x3678f9
 mov r0,1
 stb r0,[r1]
 mov r1,{0x446808+(67 if event==0x2180 else 14)*4+2:#x}
 sth r0,[r1]
 mov r0,255
 mov r1,{67 if event==0x2180 else 14}
 mov r2,1
 mov r3,1
 mov r12,0x16f72c
 jl [r12]
 add r0,r21,112
 mov r12,0x17bd4c
 jl [r12]
 st r0,[r21,124]
 mov r0,1
 st r0,[r21,84]
 mov r1,0x366e94
 mov r0,0x77f728
 st r0,[r1]
 mov r0,22
 sth r0,[r1,4]
 mov r0,0x9802ac
 st r0,[r1,16]
 mov r0,0
 st r0,[r1,24]
 mov r1,0x367814
 mov r0,1
 stb r0,[r1]
 ld r0,[r21,112]
 ldh.x r1,[r21,116]
 ld r2,[r21,120]
 mov r12,0x169e1c
 jl [r12]
 st r0,[r21,92]
 mov r1,0x367fea
 ldb r0,[r1]
 st r0,[r21,4]
 mov r1,0xfef0388
 ldh r0,[r1]
 st r0,[r21,96]
 mov r1,0xff04024
 ldh r0,[r1]
 st r0,[r21,100]
 mov r1,0x36a482
 ldb r0,[r1]
 st r0,[r21,104]
 st sp,[r21,28]
'''
        asm += """ mov r0,0
 mov r8,1
 trap_s 1
menu_callback:
 push_s blink
 push_s r13
 mov r13,0x2000000
 ld r13,[r13]
 add r0,r13,84
 add r2,r0,4
 bl akeru_menu_event
 ld r1,[r13,88]
 cmp r1,3
 bne callback_done
 mov r0,0x50
 mov r1,0
 mov r2,0
 mov r3,0
 mov r4,0
 mov r5,0
 mov r6,0
 mov r12,0x2c4fac
 jl [r12]
 st r0,[r13]
callback_done:
 mov r0,1
 pop_s r13
 pop_s blink
 j_s [blink]
"""
        statefile = out / 'cases.bin'; statefile.write_bytes(bytes(len(tests) * 128)); maps += mapping(statefile, 0x2001000)
        current = out / 'current.bin'; current.write_bytes(bytes(8)); maps += mapping(current, 0x2000000)
        for name,addr in [('mmio_fef',0xfef0300),('mmio_gpio',0xff04000),('fake_device',0x2003000),('key_state',0x446000),('queue',0x47a000)]:
            p=out/(name+'.bin');p.write_bytes(bytes(8192 if name in ('key_state','queue') else 512));maps+=mapping(p,addr)
        (out/'cases.s').write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n'+asm+'\n.section .stack,"aw",@nobits\n.align 16\n.space 16384\n')
        for name, cmd in [('compile_menu',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-O2','-ffreestanding','-fno-builtin','-c',ROOT/'AkeruOS/ui/menu.c','-o',out/'menu.o']),('assemble',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',out/'cases.o',out/'cases.s']),('link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',LEGACY/'tests/smoke.ld','-o',out/'cases.elf',out/'cases.o',out/'menu.o'])]:
            result = r.command(name,cmd); assert result.returncode == 0, result.stdout
        symbols=r.command('symbols',['arc-snps-elf-nm',out/'cases.elf']); assert symbols.returncode==0,symbols.stdout
        entries=[int(line.split()[0],16) for line in symbols.stdout.splitlines() if line.endswith(' t menu_callback')]; assert len(entries)==1
        entry=binary('entry_menu_callback',f' mov_s r12,{entries[0]:#x}\n j_s [r12]\n').read_bytes()[:8]
        block,off=locate(0x7cafe8,8); before=bytes(images[block['index']][off:off+8]); assert before==raw(0x7cafe8,8)
        images[block['index']][off:off+8]=entry; patches.append(dict(name='menu_callback',address='0x7cafe8',original=before.hex(),fixture=entry.hex()))
        for i, image in images.items():
            path = out / f'block{i}_LAB_FIXTURE.bin'
            path.write_bytes(image)
            maps += mapping(path, BS[i]['load_address_candidate'])
        result, log = r.run('cases', '/result/cases.elf', maps, trace=True)
        assert result['exit_code']==42 and result['fault'] is None,log
        w=struct.unpack_from('<32I',statefile.read_bytes(),0)
        assert w[18]==6 and w[19]==6 and w[22]==3 and w[23]==0,w
        assert w[0]==0 and w[1]==0,w
        trace=(out/'cases.trace').read_text()
        for addr in ('0x169e1c','0x169d78','0x7cafe8','0x2c4fac','0x2c5074','0x235b0c'):
            assert any(line.startswith(addr+' ') for line in trace.splitlines()),addr
        assert sum(line.startswith('0x16f920 ') for line in trace.splitlines())>=6
        rows=[dict(exit_polls=w[18],key_reads=w[19],action=w[22],manager_return_recorded=w[23],stop_code=42)]
        (out / 'fixture_patches.json').write_text(json.dumps(patches, indent=2) + '\n')
        (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_EXPECTED_NO_EXIT_PREFIX', scenarios=rows,
            assumptions=['Original logical key producer and queue; harness explicitly dequeues and calls original manager with an artificially current descriptor and a callback replaced in a laboratory copy to route to C model; experimental callback itself synchronously routes the model aperture action to original diagnostic dispatcher, panel, setter, request and Big/Small GPIO paths; input, memory and services synthetic.'],
            limits=['DSP GNU model experimental; MMIO regions are inert mapfiles, not physical hardware; lock, busy, handle, events, mailbox, wait and cleanup are fixtures. Synchronous diagnostic panel runs inside manager callback, with no proof it is safe for scheduling or locks; no real descriptor lifecycle or firmware integration, real keys, sensor, optical movement or concurrency verified.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        r.save()
    print('PASS: expected bounded stop while exit remains absent;', out, flush=True)

if __name__ == '__main__':
    main()
