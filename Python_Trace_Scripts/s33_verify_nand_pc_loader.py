#!/usr/bin/env python3
"""Run the original TBIB sector loader on the candidate; record file-backed I/O."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe, LAB, BUILD
sys.path.insert(0, str(ROOT/'coolpix-s33-re'))
from s33_extract import parse_firmware

TBM, STATE, RECORDER, STOP = 0x4000000, 0x2010000, 0x2030000, 0x2031000


def main():
    out = ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('loader_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='original-TBIB-candidate-loader-and-bounded-startup'))
    r.prepare()
    try:
        proof = ROOT/json.loads((out.parent/'container_latest.json').read_text())['evidence']
        p = json.loads(proof.read_text()); artifact = ROOT/p['artifact']
        assert sha(artifact) == p['sha256']
        package = artifact.read_bytes(); sections, _ = parse_firmware(package)
        tbm = package[sections[1].data_start:sections[1].data_start+sections[1].data_length]
        firmware = ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin'
        original_tbib = firmware.read_bytes()[0x7c:0x44c38]
        blocks = [b for b in p['blocks'] if b['type'] == 1]
        assert p['extension_layout']=='additional_type1_record17' and p['rhir_record_count']==18
        assert [b['index'] for b in blocks] == [0, 1, 8, 17]
        r.input_hashes.update({str(f):sha(f) for f in [proof, artifact, Path(__file__), BUILD]})
        build = json.loads(BUILD.read_text()); engine = LAB/'install/bin/arc-elf32-run'
        assert sha(engine) == build['experimental_sha256']
        r.input_hashes[str(engine)] = sha(engine); r.experimental_engine = LAB
        command = r.command
        def bounded_command(name, args, timeout=30):
            args = list(args)
            if name.startswith('loader_') and '10s' in args:
                args[args.index('10s')] = '45s'; timeout = 55
            return command(name, args, timeout=timeout)
        r.command = bounded_command
        def binary(name, asm):
            elf = compile_probe(r, name, asm); dest = out/(name+'.bin')
            v = r.command(name+'_extract', [TOOLCHAIN/'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, dest])
            assert v.returncode == 0, v.stdout
            return dest.read_bytes()
        def jump(target):
            data = binary('entry_'+hex(target), f' mov_s r12,{target:#x}\n j_s [r12]\n')
            assert len(data) == 8
            return data
        def call(a): return f' mov r12,{a:#x}\n jl [r12]\n'
        recorder = binary('sector_recorder', f''' push_s blink
 mov r10,{STATE:#x}
 ld r5,[r10,12]
 asl r6,r5,4
 add r6,r6,64
 add r6,r6,r10
 st r0,[r6]
 st r1,[r6,4]
 st r2,[r6,8]
 add r5,r5,1
 st r5,[r10,12]
 ld r6,[r10,16]
 cmp r5,r6
 beq read_fail
 asl r0,r0,9
 add r0,r0,{TBM:#x}
 asl r1,r1,9
 mov r3,r2
 mov r2,r1
 mov r1,r0
 mov r0,r3
 mov r12,0x100abc0
 jl [r12]
 mov r0,0
 pop_s blink
 j_s [blink]
read_fail:
 mov r0,1
 pop_s blink
 j_s [blink]
''')
        stop = binary('kernel_stop', f' mov r10,{STATE:#x}\n st sp,[r10,24]\n st gp,[r10,28]\n mov r0,0x51\n st r0,[r10,20]\n mov r0,0\n mov r8,1\n trap_s 1\n')
        cpu_return = binary('cpu_configuration_return', ' mov r0,0\n j_s [blink]\n')
        assert len(cpu_return) <= 8
        stop_entry = jump(STOP)
        cases = []
        for name, expected, reads, startup in [('valid',0,5,False), ('bad_magic',11,1,False), ('bad_checksum',13,2,False), ('read_failure',7,2,False), ('bad_extension_checksum',13,5,False), ('extension_read_failure',7,5,False), ('startup_clear',0,5,True)]:
            maps = []
            def mmap(label, address, data):
                filename = name+'_'+label+'.bin'
                (out/filename).write_bytes(bytes(address%8)+data)
                maps.extend(['--memory-mapfile', '/result/'+filename, '--memory-region', f'{address:#x},{len(data)}'])
                return out/filename
            tbib = bytearray(original_tbib); tbib[0xa120:0xa128] = jump(RECORDER)
            mmap('tbib_LAB_IO', 0x1000000, tbib)
            source = bytearray(tbm)
            if name == 'bad_magic': source[0] ^= 1
            if name == 'bad_checksum': source[0x1c] ^= 1
            if name == 'bad_extension_checksum': source[0x12c] ^= 1
            source_path = mmap('TBM', TBM, source)
            state = bytearray(512)
            if name == 'read_failure': struct.pack_into('<I', state, 16, 2)
            if name == 'extension_read_failure': struct.pack_into('<I', state, 16, 5)
            state_path = mmap('state', STATE, state)
            mmap('recorder', RECORDER, recorder+bytes(16))
            mmap('kernel_stop', STOP, stop+bytes(16))
            loaded = []; first_path = None
            for b in blocks:
                address = int(b['cpu'],16); size = b['bytes']
                if b['index']==17:
                    assert int(b['cpu'],16)==int(blocks[0]['cpu'],16)+blocks[0]['bytes']
                    loaded.append((b,first_path,blocks[0]['bytes']))
                else:
                    extra=blocks[-1]['bytes'] if b['index']==0 else 0
                    path=mmap('payload'+str(b['index']), address, b'\xa5'*(size+extra+16))
                    if b['index']==0:first_path=path
                    loaded.append((b,path,0))
            if startup: bss_path = mmap('BSS_stack', 0x42d140, b'\xa5'*(0x5daddc-0x42d140+16))
            asm = f' mov r20,{STATE:#x}\n st sp,[r20,4]\n'+call(0x10010c0)+' st r0,[r20]\n st sp,[r20,8]\n'
            if startup:
                # shortcut: CPU setup and kernel are explicit lab boundaries; this stops before scheduling.
                asm += ' cmp r0,0\n bne finish\n'
                for address, data in [(0x330a78,cpu_return),(0x333d7c,stop_entry)]:
                    for offset, value in enumerate(data):
                        asm += f' mov r10,{address+offset:#x}\n mov r0,{value}\n stb r0,[r10]\n'
                asm += ' mov r12,0xbb540\n j [r12]\n'
            asm += 'finish:\n mov r0,0\n mov r8,1\n trap_s 1\n'
            elf = compile_probe(r, name, asm)
            case, log = r.run('loader_'+name, '/result/'+elf.name, maps, trace=name=='bad_magic')
            assert case['exit_code'] == 0 and case['fault'] is None, log
            w = struct.unpack_from('<8I', state_path.read_bytes())
            assert w[0] == expected and w[1] == w[2] and w[3] == reads, (name,w)
            rows = [struct.unpack_from('<3I',state_path.read_bytes(),64+i*16) for i in range(reads)]
            assert rows[0][0:2] == (0,1), rows
            for b, path, offset in loaded:
                mapped = path.read_bytes(); size = b['bytes']; data=mapped[offset:offset+size]
                assert mapped[-16:] == b'\xa5'*16, (name,b['index'],'canary')
                should_load = name in ('valid','startup_clear','bad_extension_checksum') or (name=='bad_checksum' and b['index']==0) or (name=='extension_read_failure' and b['index']!=17)
                wanted = tbm[b['offset']:b['offset']+size] if should_load else b'\xa5'*size
                if startup and b['index']==0:
                    wanted = bytearray(wanted)
                    for a, patch in [(0x330a78,cpu_return),(0x333d7c,stop_entry)]: wanted[a-int(b['cpu'],16):a-int(b['cpu'],16)+len(patch)] = patch
                assert data[:size] == wanted, (name,b['index'],'payload')
            if expected == 0:
                assert rows[1:] == [(b['offset']//512,b['bytes']//512,int(b['cpu'],16)) for b in blocks], rows
                tbib_after = (out/(name+'_tbib_LAB_IO.bin')).read_bytes()
                assert struct.unpack_from('<I',tbib_after,0x41100)[0] == 0xbb540
            if startup:
                assert w[5] == 0x51 and w[6:8] == (0x5dadc4,0x423844), w
                bss = bss_path.read_bytes(); length = 0x5da5dc-0x42d140
                assert bss[:length] == bytes(length) and bss[-16:] == b'\xa5'*16
            assert source_path.read_bytes() == source
            cases.append(dict(name=name,status=expected,reads=[dict(sector=a,count=b,destination=hex(c)) for a,b,c in rows],stack_preserved=True,startup_clear=startup))
        for a,b in [(0x1001048,0x10010ba),(0x10010c0,0x10011b4),(0x1001764,0x10017c4)]:
            v = r.command(f'gnu_{a:x}', [TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',out/'tbib.elf'])
            assert v.returncode == 0 and 'out of bounds' not in v.stdout
        assert all(sha(Path(f))==h for f,h in r.input_hashes.items())
        (out/'loader_cases.json').write_text(json.dumps(cases,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ORIGINAL_TBIB_LOADER_AND_BOUNDED_CLEAR',candidate=str(artifact.relative_to(ROOT)),candidate_sha256=p['sha256'],loader_cases=cases,input_hashes=r.input_hashes,assumptions=['File-backed sector recorder replaces only TBIB0100A120; original descriptor/checksum/memcpy code executes','Explicit A5 destinations and lab caller/stack; no NAND controller or ROM','DSPv7 restricted positive multiplication with mode0 for sector-count helper, not full CPU certification','Startup case stubs CPU configuration330A78 and stops at kernel333D7C after original clear'],limits=['No hardware or installation; NAND physical mapping/ECC/write/readback/recovery not executed','No scheduler, cache coherence, overlays or lifetime proof after bounded startup','Extension survives only the tested loader and runtime clear; no RAM ownership claim'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n')
        (out.parent/'loader_cpu_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
        print('PASS',out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc)); (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n'); raise

if __name__ == '__main__': main()
