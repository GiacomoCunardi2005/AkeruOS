#!/usr/bin/env python3
"""Execute original cancel callback with explicit service stubs; no camera I/O."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import re
import struct
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, disasm, locate, sha


def main():
    out = ROOT / 'Risultati/HiddenMenu_Uscita' / ('CPU_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='bounded-hiddenmenu-cancel'))
    try:
        r.prepare()
        r.results['assumptions'] = ['Original806CD4 callback and original strcat32DE00; five explicit recording stubs',
            'Synthetic caller, stack and state records; UI manager is a recorder, not a working UI']
        r.results['limits'] = ['No hardware, physical button mapping, UI lifecycle or persistence test',
            'MSDC preserved only across this callback with declared stubs; other settings not tested']
        main = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
        r.input_hashes[str(ROOT / 'DUMPS/MainCode.dmp')] = sha(main)
        origin = BS[0]['load_address_candidate']
        image = bytearray(PS[0]); patches = []; maps = []
        header = ' mov r10,0x2000000\n ld r10,[r10]\n'
        services = [
            ('prefix', 0x12b0dc, header + ' mov r11,0x3a42\n st r11,[r0]\n ld r0,[r10]\n j_s [blink]\n'),
            ('attributes', 0x12bbb8, header + ' ld r11,[r10,16]\n add r11,r11,1\n st r11,[r10,16]\n'
             ' ld r11,[r10,4]\n stb r11,[r2]\n add r12,r10,64\n'
             'copy_path:\n ldb r11,[r0]\n stb r11,[r12]\n add r0,r0,1\n add r12,r12,1\n cmp r11,0\n bne copy_path\n'
             ' mov r0,0\n j_s [blink]\n'),
            ('key', 0x16f920, header + ' ld r11,[r10,20]\n add r11,r11,1\n st r11,[r10,20]\n st r0,[r10,44]\n ld r0,[r10,8]\n j_s [blink]\n'),
            ('open_menu', 0x1453e4, header + ' st r0,[r10,12]\n mov r0,0\n j_s [blink]\n'),
            ('reset_guard', 0xc9d84, header + ' ld r11,[r10,24]\n add r11,r11,1\n st r11,[r10,24]\n mov r0,0\n j_s [blink]\n')]
        def binary(name, source):
            elf = compile_probe(r, name, source); p = out / (name + '.bin')
            result = r.command(name + '_extract', [TOOLCHAIN / 'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, p])
            assert result.returncode == 0
            return p
        def mapping(name, address, size):
            return ['--memory-mapfile', '/result/' + name, '--memory-region', f'{address:#x},{size}']
        for i, (name, target, source) in enumerate(services):
            address = 0x2010000 + i * 0x200
            p = binary(name, source); data = p.read_bytes(); p.write_bytes(data + bytes(8 + (-len(data)) % 8))
            assert len(p.read_bytes()) < 0x200
            maps += mapping(p.name, address, p.stat().st_size)
            entry = binary('entry_' + name, f' mov_s r12,{address:#x}\n j_s [r12]\n').read_bytes()
            assert len(entry) == 8
            offset = target - origin
            patches.append(dict(name=name, address=hex(target), original=image[offset:offset+8].hex(), fixture=entry.hex()))
            image[offset:offset+8] = entry
        specs = [(status, attr, key, msdc) for status in (0, 1, 0xffffffff) for attr in (0, 1) for key in (0, 1) for msdc in (1, 2)]
        assert len(specs) == 24
        states = bytearray(128 * len(specs)); asm = ' mov r20,0x2000000\n'
        for i, (status, attr, key, msdc) in enumerate(specs):
            struct.pack_into('<3I', states, 128*i, status, attr, key)
            address = 0x2001000 + 128*i
            asm += (f' mov r21,{address:#x}\n st r21,[r20]\n mov r0,{msdc}\n mov r1,0x366b9d\n stb r0,[r1]\n'
                    ' st sp,[r21,32]\n mov r0,0\n mov r1,0x2700\n mov r2,0\n'
                    ' mov r12,0x806cd4\n jl [r12]\n st r0,[r21,40]\n st sp,[r21,36]\n'
                    ' mov r1,0x366b9d\n ldb r0,[r1]\n st r0,[r21,28]\n')
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        for name, data in [('main0_fixture_NOT_FIRMWARE.bin', image), ('main1.bin', PS[1]), ('main4.bin', PS[4]), ('main5.bin', PS[5]),
                           ('states.bin', states), ('current.bin', bytes(8))]:
            (out / name).write_bytes(data)
        maps += mapping('main0_fixture_NOT_FIRMWARE.bin', origin, len(image))
        maps += mapping('main1.bin', BS[1]['load_address_candidate'], len(PS[1]))
        maps += mapping('main4.bin', BS[4]['load_address_candidate'], len(PS[4]))
        maps += mapping('main5.bin', BS[5]['load_address_candidate'], len(PS[5]))
        maps += mapping('states.bin', 0x2001000, len(states)) + mapping('current.bin', 0x2000000, 8)
        elf = compile_probe(r, 'cancel_cases', asm)
        case, log = r.run('cancel_cases', '/result/' + elf.name, maps, trace=True)
        assert case['exit_code'] == 0 and case['fault'] is None, log
        got = (out / 'states.bin').read_bytes(); results = []
        for i, (status, attr, key, msdc) in enumerate(specs):
            words = struct.unpack_from('<12I', got, i*128)
            target = 0x20 if status == 0 and attr == 1 and key else 0x78
            assert words[3] == target and words[4] == int(status == 0)
            assert words[5] == int(status == 0 and attr == 1)
            assert words[6] == 0 and words[7] == msdc and words[8] == words[9]
            if status == 0:
                assert got[i*128+64:i*128+64+14] == b'B:\\HiddenMenu\0'
            if words[5]: assert words[11] == 8
            results.append(dict(prefix_status=hex(status), attribute_byte=attr, logical_key8=key, msdc_before=msdc,
                                requested_menu=hex(words[3]), msdc_after=words[7], reset_calls=words[6], sp_restored=True))
        pcs = sorted({int(m[1],16) for m in re.finditer(r'^0x([0-9a-f]+)\s', (out / 'cancel_cases.trace').read_text(), re.M)})
        verified = []
        for pc in pcs:
            if any(a <= pc < a+8 for _, a, _ in services): continue
            try: block, offset = locate(pc, 8)
            except ValueError: continue
            assert main[block['offset']+offset:block['offset']+offset+8] == raw(pc,8)
            verified.append(hex(pc))
        (out / 'gnu_verified.txt').write_text(disasm(0x806cd4,0x806d48))
        (out / 'protocol_cases.json').write_text(json.dumps(results,indent=2)+'\n')
        (out / 'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        (out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_CANCEL_CALLBACK_WITH_EXPLICIT_STUBS', protocol_cases=len(results),
                         five_services_simulated=True, ui_lifecycle_executed=False,
                         original_unique_pcs_verified=verified, msdc_preserved_in_all_cases=True)
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc)); raise
    finally:
        r.save()
    (out.parent / 'latest_cpu.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n')
    print('PASS 24 original cancel cases, five stubs, no reset calls; MSDC and SP preserved:',out)


if __name__ == '__main__':
    main()
