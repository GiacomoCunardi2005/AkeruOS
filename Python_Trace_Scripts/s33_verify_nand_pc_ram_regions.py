#!/usr/bin/env python3
"""Run original application-region initialization; no hardware or GNU changes."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib, json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, disasm

STATE, TABLE, OBJECT, INDEX = 0x2010000, 0x3766f4, 0x441f68, 0x441fa0
EXTENSION = (0x35bc00, 0x35ce00)


def reference():
    records = []
    for n in range(232):
        row = list(struct.unpack('<6I', raw(TABLE+24*n, 24)))
        if row[0] == row[1] == 0:
            break
        records.append(row)
    assert len(records) == 111 and all(row[5] == 4 for row in records)
    lookup = {row[0]: n for n, row in enumerate(records)}
    lowest, canaries = 0x10000000, []
    for row in records:
        parent = 0x10000000 if row[1] == 233 else records[lookup[row[1]]][3]
        assert parent and parent >= row[4]
        row[3] = (parent-row[4]) & ~(row[5]-1)
        lowest = min(lowest, row[3])
        if row[3] < parent-256:
            canaries.append((parent-256, 0x5a, 256))
    assert lowest == 0x1bf9800 and lookup[0x2f] == 45
    intervals = []
    for address, _, length in sorted(canaries):
        start, end = address-16, address+length+16
        if intervals and start <= intervals[-1][1]:
            intervals[-1][1] = max(end, intervals[-1][1])
        else:
            intervals.append([start, end])
    return records, lookup, lowest, canaries, intervals


def main():
    out = ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('ram_regions_cpu_%Y%m%dT%H%M%SZ')
    runner = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out,
                                    action='original-application-region-layout-and-extension-separation'))
    runner.prepare()
    try:
        records, lookup, lowest, canaries, intervals = reference()
        proof = ROOT/json.loads((out.parent/'container_latest.json').read_text())['evidence']
        candidate = json.loads(proof.read_text()); artifact = ROOT/candidate['artifact']
        assert sha(artifact) == candidate['sha256'] == '0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9'
        runner.input_hashes.update({str(p): sha(p) for p in [Path(__file__), proof, artifact]})
        images = {index: bytearray(PS[index]) for index in (0, 1)}
        shared, patches = [], []

        def mmap(options, name, address, data):
            path = out/name; path.write_bytes(bytes(address % 8)+data)
            options.extend(['--memory-mapfile', '/result/'+name, '--memory-region', f'{address:#x},{len(data)}'])
            return path

        def binary(name, assembly):
            elf = compile_probe(runner, name, assembly); dest = out/(name+'.bin')
            result = runner.command(name+'_extract', [TOOLCHAIN/'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, dest])
            assert result.returncode == 0, result.stdout
            return dest.read_bytes()

        def stub(address, assembly):
            target = 0x2030000+len(patches)*0x400
            data = binary(f'boundary_{address:x}', assembly)
            mmap(shared, f'boundary_{address:x}.bin', target, data+bytes(16))
            entry = binary(f'entry_{address:x}', f' mov_s r12,{target:#x}\n j_s [r12]\n')
            assert len(entry) == 8
            block, offset = locate(address, 8)
            patches.append(dict(cpu=hex(address), original=images[block['index']][offset:offset+8].hex(), laboratory_target=hex(target)))
            images[block['index']][offset:offset+8] = entry

        stub(0x13a954, f''' mov r10,{STATE:#x}
 ld r6,[r10,16]
 asl r7,r6,4
 add r7,r7,128
 add r7,r7,r10
 st r0,[r7]
 st r1,[r7,4]
 st r2,[r7,8]
 add r6,r6,1
 st r6,[r10,16]
 mov r5,r0
 mov r6,r2
fill_byte:
 cmp r6,0
 beq fill_done
 stb r1,[r5]
 add r5,r5,1
 sub r6,r6,1
 b fill_byte
fill_done:
 j_s [blink]
''')
        stub(0x177488, f''' mov r10,{STATE:#x}
 st r0,[r10,24]
 ld r6,[r10,20]
 add r6,r6,1
 st r6,[r10,20]
 ld r0,[r10,28]
 j_s [blink]
''')
        rows = []
        for name, direct, backend_error in [('boot_chain', False, 0), ('direct_same_layout', True, 0), ('post_init_error', False, 0x12345678)]:
            options = list(shared); mapped_images = {}
            for index, data in images.items():
                mapped_images[index] = mmap(options, name+f'_main{index}_LAB.bin', BS[index]['load_address_candidate'], data)
            state = bytearray(4096); struct.pack_into('<I', state, 28, backend_error)
            state_path = mmap(options, name+'_state.bin', STATE, state)
            region_path = mmap(options, name+'_region_object.bin', OBJECT, b'\xa5'*0x500)
            extension_path = mmap(options, name+'_extension_sentinel.bin', EXTENSION[0], b'\xa5'*(EXTENSION[1]-EXTENSION[0]))
            canary_paths = [(start, end, mmap(options, name+f'_canary_{start:x}.bin', start, b'\xa5'*(end-start))) for start, end in intervals]
            call = (' mov r0,0x10000000\n mov r1,0x3766f4\n add r2,r20,32\n mov r12,0x12a6e4\n jl [r12]\n' if direct else
                    ' mov r12,0xc768c\n jl [r12]\n st r0,[r20,32]\n mov r12,0xc63d8\n jl [r12]\n')
            assembly = f' mov r20,{STATE:#x}\n st sp,[r20,4]\n'+call+' st r0,[r20]\n st sp,[r20,8]\n mov r0,0\n mov r8,1\n trap_s 1\n'
            elf = compile_probe(runner, name, assembly)
            case, log = runner.run(name, '/result/'+elf.name, options, trace=True)
            assert case['exit_code'] == 0 and case['fault'] is None, log
            state = state_path.read_bytes(); words = struct.unpack_from('<9I', state)
            assert words[0] == backend_error and words[1] == words[2]
            assert words[4] == len(canaries) and words[5] == (0 if direct else 1) and words[6] == 0
            assert words[8] == (lowest if direct else 0x10000000)
            observed_canaries = [struct.unpack_from('<3I', state, 128+16*n) for n in range(words[4])]
            assert observed_canaries == canaries
            result = region_path.read_bytes(); result = result[OBJECT % 8:]
            assert struct.unpack_from('<I', result, 12)[0] == 111
            assert struct.unpack_from('<I', result, 44)[0] == lowest and result[40] == 1
            assert list(struct.unpack_from('<232I', result, INDEX-OBJECT)) == [lookup.get(n, 0xffffffff) for n in range(232)]
            block1 = mapped_images[1].read_bytes(); base1 = BS[1]['load_address_candidate']
            for n, row in enumerate(records):
                actual = struct.unpack_from('<6I', block1, TABLE-base1+24*n)
                assert tuple(row) == actual, (name, n, row, actual)
            if not direct:
                assert block1[0x365625-base1] == (0 if backend_error else 1)
            assert extension_path.read_bytes() == b'\xa5'*(EXTENSION[1]-EXTENSION[0])
            for start, end, path in canary_paths:
                expected = bytearray(b'\xa5'*(end-start))
                for address, value, length in canaries:
                    left, right = max(start, address), min(end, address+length)
                    if left < right: expected[left-start:right-start] = bytes([value])*(right-left)
                assert path.read_bytes()[start % 8:] == expected
            rows.append(dict(name=name, entry='0x12a6e4' if direct else '0xc768c -> 0xc63d8', status=hex(words[0]), region_count=111,
                             lowest=hex(lowest), every_region_and_lookup_matched=True, canary_calls=len(canaries),
                             canary_ranges_and_guards_matched=True, extension_preserved=True, stack_preserved=True, trace=str((out/(name+'.trace')).relative_to(ROOT))))
            print('PASS', name, flush=True)
        windows = [(0xc768c,0xc7694),(0xc63d8,0xc6440),(0x12a6e4,0x12a71c),(0x1ef688,0x1ef7f8),(0x1ef7f8,0x1ef960)]
        (out/'gnu_verified.txt').write_text('\n'.join(disasm(a,b) for a,b in windows))
        assert all(sha(Path(path)) == digest for path,digest in runner.input_hashes.items())
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        (out/'laboratory_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        runner.results.update(status='PASS_ORIGINAL_APPLICATION_REGION_INITIALIZATION', candidate_sha256=candidate['sha256'],
                              cases_detail=rows, regions=[dict(index=n,id=hex(row[0]),parent=hex(row[1]),base=hex(row[3]),bytes=row[4],alignment=row[5]) for n,row in enumerate(records)],
                              region_table_cpu=hex(TABLE), table_with_terminator_sha256=hashlib.sha256(raw(TABLE,112*24)).hexdigest(),
                              canaries=[dict(address=hex(a),value=v,bytes=n) for a,v,n in canaries], input_hashes=runner.input_hashes,
                              assumptions=['Original Main0/Main1, region initializer and resolver executed; 13A954 uses local recorder/byte-fill loop; 177488 is status fixture',
                                           'Explicit A5 state and extension sentinels; original table, fixed software top10000000; no physical RAM-size inference'],
                              limits=['No all-writer, DMA, cache, alias, physical memory or scheduler proof',
                                      'Only application-region manager and shown open/close bodies, not all allocator APIs',
                                      'Candidate extension is sentinel here, not new-handler execution or installable-ready proof',
                                      'No camera access, NAND/SD writes or GNU/canonical firmware changes'])
        (out/'verified_evidence.json').write_text(json.dumps(runner.results,indent=2)+'\n')
        print('PASS',out)
    except Exception as exc:
        runner.results.update(status='FAIL',error=repr(exc))
        (out/'verified_evidence.json').write_text(json.dumps(runner.results,indent=2)+'\n')
        raise


if __name__ == '__main__':
    main()
