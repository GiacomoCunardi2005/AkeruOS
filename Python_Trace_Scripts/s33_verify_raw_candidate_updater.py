#!/usr/bin/env python3
"""Exercise original updater validation on the retained RAW candidate, offline."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe, LAB, BUILD
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
sys.path.insert(0, str(ROOT/'coolpix-s33-re'))
from static_common import BS, PS
from s33_extract import parse_firmware


def main():
    source = ROOT/'Risultati/HiddenMenu_RAW_Firmware/20261027T110219Z/firmware_RAW_FORZATO_OFFLINE_NON_INSTALLARE.bin'
    out = ROOT/'Risultati/HiddenMenu_RAW_Firmware'/datetime.now(timezone.utc).strftime('updater_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='raw-original-updater-validation'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        assert sha(source) == '56c9457646be23bde6e1bda47c6cefaada5bf52657ba299f83339306debf4cbf'
        package = source.read_bytes()
        sections, _ = parse_firmware(package)
        nand_path = ROOT/'DUMPS/NANDP1.dmp'
        table = nand_path.read_bytes()[0x231a:0x240e]
        assert table[:8] == table[-8:] == b'P1IDSTR\0'
        assert struct.unpack_from('<HH', table, 0xd0) == (165,3)
        assert struct.unpack_from('<H', table, 0xde)[0] == 147
        build = json.loads(BUILD.read_text())
        engine = LAB/'install/bin/arc-elf32-run'
        assert sha(engine) == build['experimental_sha256']
        r.experimental_engine = LAB
        for path in (source, nand_path, BUILD, engine):
            r.input_hashes[str(path)] = sha(path)
        command = r.command
        def bounded_command(name, args, timeout=30):
            args = list(args)
            if name in ('checksum','main_validation') and '10s' in args:
                args[args.index('10s')] = '45s'
                timeout = 55
            return command(name, args, timeout=timeout)
        r.command = bounded_command
        maps = []
        def mmap(name, address, data):
            (out/name).write_bytes(bytes(address%8)+data)
            maps.extend(['--memory-mapfile','/result/'+name,'--memory-region',f'{address:#x},{len(data)}'])
        mmap('block0.bin',BS[0]['load_address_candidate'],PS[0])
        mmap('block1.bin',BS[1]['load_address_candidate'],PS[1])
        mmap('package.bin',0x4000000,package)
        mmap('states.bin',0x2100000,bytes(8*4096))
        mmap('partition.bin',0x50f420,table)
        mmap('geometry.bin',0x50f52c,bytes(32))
        mmap('page.bin',0x511f00,bytes(2048))
        def call(address):
            return f' mov r12,{address:#x}\n jl [r12]\n'
        setup = ' mov r10,0x36b264\n mov r0,1\n stb r0,[r10]\n mov r0,0xf0\n'+call(0x25d194)
        asm = setup+' mov r20,0x2100000\n st sp,[r20,4]\n mov r0,0x4000004\n'
        asm += f' mov r1,{len(package)-4}\n'+call(0x12b060)
        asm += ' st r0,[r20]\n st sp,[r20,8]\n mov r0,0\n mov r8,1\n trap_s 1\n'
        elf = compile_probe(r,'checksum',asm)
        case, log = r.run('checksum','/result/'+elf.name,maps)
        assert case['exit_code'] == 0 and case['fault'] is None, log
        state = (out/'states.bin').read_bytes()
        words = struct.unpack_from('<3I',state)
        assert words[0] == struct.unpack_from('<I',package)[0] and words[1] == words[2]
        length = sections[1].data_length
        tbm = 0x4000000 + sections[1].data_start
        tests = [('valid',length,None,0),('too_large',19267584+512,None,0x1c00114),
                 ('bad_magic',length,0,0x1c00111),('bad_payload0',length,512,0x1c00111),
                 ('bad_payload1',length,BS[1]['offset'],0x1c00111)]
        asm = setup
        for i,(name,n,mutate,expected) in enumerate(tests):
            addr = 0x2100000+(i+1)*4096
            asm += f' mov r20,{addr:#x}\n st sp,[r20,4]\n'
            if mutate is not None:
                asm += f' mov r10,{tbm+mutate:#x}\n ldb r0,[r10]\n xor r0,r0,1\n stb r0,[r10]\n'
            asm += f' mov r0,{tbm:#x}\n mov r1,{n}\n'+call(0x12aea0)+' st r0,[r20]\n st sp,[r20,8]\n'
            if mutate is not None:
                asm += f' mov r10,{tbm+mutate:#x}\n ldb r0,[r10]\n xor r0,r0,1\n stb r0,[r10]\n'
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        elf = compile_probe(r,'main_validation',asm)
        case, log = r.run('main_validation','/result/'+elf.name,maps)
        assert case['exit_code'] == 0 and case['fault'] is None, log
        state = (out/'states.bin').read_bytes()
        rows = []
        for i,(name,n,mutate,expected) in enumerate(tests):
            words = struct.unpack_from('<3I',state,(i+1)*4096)
            assert words[0] == expected and words[1] == words[2], (name,words,hex(expected))
            rows.append(dict(name=name,status=hex(words[0]),stack_preserved=True))
        assert (out/'package.bin').read_bytes() == package
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ORIGINAL_UPDATER_VALIDATOR_ON_RAW_CANDIDATE',
            artifact=str(source.relative_to(ROOT)), candidate_sha256=sha(source),
            package_xor=hex(struct.unpack_from('<I',package)[0]), main_validation=rows,
            assumptions=['Original V1.1 updater checksum and Main validation code; NAND partition and RAM fixture.',
                         'DSPv7 lab simulator for supported multiplication; no NAND controller or updater UI.'],
            limits=['Not a full updater sequence, erase/write/readback, actual resident updater or physical recovery.',
                    'Passing validation is not proof the camera can boot or save images.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc))
        raise
    finally:
        r.save()
    print('PASS original updater validation on RAW candidate:',out,flush=True)


if __name__ == '__main__':
    main()
