#!/usr/bin/env python3
"""Run original TBIB device creation/SD dispatch, with allocation and SD fixtures."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe

BASE, STATE, HEAP = 0x1000000, 0x2100000, 0x2200000
TABLE, SD = 0x10421cc, 0x104231c


def main():
    out = ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('tbib_sd_init_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out,
                              action='original-TBIB-device-creation-and-SD-callback-dispatch'))
    r.prepare()
    try:
        original = (ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()[0x7c:0x44c38]
        r.input_hashes[str(Path(__file__))] = sha(Path(__file__))
        body, maps, patches = bytearray(original), [], []

        def mmap(name, address, data):
            p = out/name
            p.write_bytes(bytes(address % 8)+data)
            maps.extend(['--memory-mapfile', '/result/'+name, '--memory-region', f'{address:#x},{len(data)}'])
            return p

        def binary(name, source):
            elf = compile_probe(r, name, source)
            p = out/(name+'.bin')
            v = r.command(name+'_extract', [TOOLCHAIN/'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, p])
            assert v.returncode == 0, v.stdout
            return p.read_bytes()

        def stub(address, source):
            target = 0x2300000+len(patches)*0x400
            mmap(f'fixture_{address:x}.bin', target, binary(f'fixture_{address:x}', source)+bytes(16))
            jump = binary(f'jump_{address:x}', f' mov_s r12,{target:#x}\n j_s [r12]\n')
            assert len(jump) == 8
            at = address-BASE
            patches.append(dict(cpu=hex(address), original=body[at:at+8].hex(), laboratory_target=hex(target)))
            body[at:at+8] = jump

        # Three allocation requests are separate objects; failed allocation has no object.
        stub(0x1018438, f''' mov r10,{STATE:#x}
 ld r6,[r10]
 add r6,r6,1
 st r6,[r10]
 asl r7,r6,2
 add r7,r7,r10
 st r0,[r7,64]
 ld r7,[r10,4]
 cmp r6,r7
 beq allocation_failed
 sub r6,r6,1
 asl r6,r6,8
 add r0,r6,{HEAP:#x}
 j_s [blink]
allocation_failed:
 mov r0,0
 j_s [blink]
''')
        stub(0x100c1d8, f''' mov r10,{STATE:#x}
 ld r6,[r10,8]
 asl r7,r6,2
 add r7,r7,r10
 st r0,[r7,96]
 add r6,r6,1
 st r6,[r10,8]
 mov r0,0
 j_s [blink]
''')
        # Keep 0102EE24 -> table callback01002E74 -> 01002BE4 intact up to this boundary.
        stub(0x1002be4, f''' mov r10,{STATE:#x}
 ld r6,[r10,12]
 add r6,r6,1
 st r6,[r10,12]
 st r0,[r10,16]
 st r1,[r10,20]
 ld r6,[r10,24]
 st r6,[r1]
 ld r6,[r10,28]
 st r6,[r1,4]
 ld r0,[r10,32]
 j_s [blink]
''')
        tbib = mmap('tbib_LAB_boundaries.bin', BASE, body)
        current = mmap('state.bin', STATE, bytes(128))
        heap = mmap('heap.bin', HEAP, bytes(0x400))
        specs = [dict(name='success'), dict(name='already_created', existing=True)]
        specs += [dict(name=f'allocation_{i}_fails', allocation_failure=i) for i in range(1, 4)]
        specs += [dict(name='SD_backend_error', backend_error=0x1234)]
        specs += [dict(name=f'SD_status_byte_{i}', status_bytes=1 << (i*8)) for i in range(5)]
        specs += [dict(name='SD_status_byte_3_precedes_others', status_bytes=0x01010101)]
        rows = []
        for c in specs:
            data = bytearray(128)
            struct.pack_into('<I', data, 4, c.get('allocation_failure', 0))
            value = c.get('status_bytes', 0)
            struct.pack_into('<3I', data, 24, value & 0xffffffff, value >> 32, c.get('backend_error', 0))
            current.write_bytes(data)
            heap.write_bytes(bytes(0x400))
            fresh = bytearray(body)
            if c.get('existing'):
                struct.pack_into('<I', fresh, SD-BASE+0x50, HEAP+0x200)
            tbib.write_bytes(fresh)
            # Resolve B: first: 0102EE24 selects its callback using the resolver's global index.
            source = f''' mov r20,{STATE:#x}
 st sp,[r20,36]
 mov r0,{SD+30:#x}
 add r1,r20,40
 mov r12,0x102007c
 jl [r12]
 st r0,[r20,44]
 ld r0,[r20,40]
 mov r12,0x10203f0
 jl [r12]
 st r0,[r20,48]
'''
            successful = not c.get('existing') and not c.get('allocation_failure') and not c.get('backend_error')
            if successful:
                source += ''' mov r0,1
 mov r12,0x1020108
 jl [r12]
 st r0,[r20,52]
'''
            source += ' st sp,[r20,56]\n mov r0,0\n mov r8,1\n trap_s 1\n'
            elf = compile_probe(r, c['name'], source)
            result, log = r.run(c['name'], '/result/'+elf.name, maps)
            assert result['exit_code'] == 0 and result['fault'] is None, log
            w = struct.unpack('<32I', current.read_bytes())
            alloc = 0 if c.get('existing') else c.get('allocation_failure', 3)
            free = [] if successful or c.get('existing') else [HEAP+i*0x100 for i in range(c['allocation_failure']-1)] if c.get('allocation_failure') else [HEAP+0x200, HEAP, HEAP+0x100]
            expected_status = 0x1a00010 if c.get('existing') else 0x1a00006 if c.get('allocation_failure') else c.get('backend_error', 0)
            assert w[0] == alloc and w[2] == len(free) and list(w[24:24+len(free)]) == free, (c,w)
            assert w[10] == 1 and w[11] == (0x1a00035 if c.get('existing') else 0x1a00030) and w[12] == expected_status
            assert w[9] == w[14], (c,w)
            backend_calls = int(alloc == 3 and not c.get('allocation_failure'))
            assert w[3] == backend_calls
            if backend_calls:
                assert (w[4],w[5]) == (0, HEAP), (c,w)
            published = struct.unpack_from('<I', tbib.read_bytes(), SD-BASE+0x50)[0]
            assert published == (HEAP+0x200 if successful or c.get('existing') else 0)
            if successful:
                expected_query = next((0x1a00041+i for i in [3,4,2,1,0] if value & (255 << (8*i))), 0)
                assert w[13] == expected_query, (c,w,hex(expected_query))
                objects = heap.read_bytes()
                assert struct.unpack_from('<I', objects, 0x200)[0] == HEAP+0x100
                assert struct.unpack_from('<I', objects, 0x124)[0] == HEAP
                assert struct.unpack_from('<I', objects, 0x108)[0] == SD+8
            rows.append(dict(**c, resolved_index=w[10], resolver_status=hex(w[11]), creation_status=hex(w[12]), query_status=hex(w[13]) if successful else None, allocations=list(w[17:17+alloc]), freed=[hex(x) for x in free], backend_calls=w[3], backend_device_argument=w[4] if backend_calls else None, published=hex(published), stack_preserved=True))
            print('PASS', c['name'], flush=True)
        for a,b in [(0x10203f0,0x10204a4),(0x102ee24,0x102ee44),(0x1002e74,0x1002e7c),(0x10200d0,0x1020180)]:
            v = r.command(f'gnu_{a:x}', [TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',out/'tbib.elf'])
            assert v.returncode == 0 and 'out of bounds' not in v.stdout
        assert all(sha(Path(p)) == digest for p,digest in r.input_hashes.items())
        for name,value in [('sd_init_cases.json',rows),('laboratory_patches.json',patches)]:
            (out/name).write_text(json.dumps(value,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_TBIB_SD_CREATION_DISPATCH_RECORDER_BOUNDARIES', sd_init_cases=len(rows), input_hashes=r.input_hashes,
                         assumptions=['Original resolver, device creator, callback dispatcher, SD wrapper and status query', 'Allocation/free and SD backend01002BE4 replaced; three distinct zeroed laboratory objects', 'No scheduler, SD controller or physical card state'],
                         limits=['Creation status0 is not filesystem readiness or recovery', 'No full mount, handoff, extension lifetime, flash or camera I/O tested'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n')
        (out.parent/'tbib_sd_init_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
        print('PASS', len(rows), out)
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc))
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n')
        raise


if __name__ == '__main__':
    main()
