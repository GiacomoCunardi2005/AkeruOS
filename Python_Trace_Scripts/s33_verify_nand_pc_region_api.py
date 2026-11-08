#!/usr/bin/env python3
"""Exercise original region query/open/close against a verified initialized snapshot."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
from s33_verify_nand_pc_ram_regions import PS, BS, TABLE, OBJECT, EXTENSION, reference, disasm

STATE = 0x2100000


def main():
    out = ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('region_api_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='original-region-query-open-close-without-relocation'))
    r.prepare()
    try:
        prior = out.parent/'ram_regions_cpu_20261021T135003Z'
        proof = prior/'verified_evidence.json'
        verified = json.loads(proof.read_text())
        assert verified['status'] == 'PASS_ORIGINAL_APPLICATION_REGION_INITIALIZATION'
        records, lookup, _, _, _ = reference()
        inputs = [Path(__file__), ROOT/'Python_Trace_Scripts/s33_verify_nand_pc_ram_regions.py', proof,
                  prior/'boot_chain_main1_LAB.bin', prior/'boot_chain_region_object.bin']
        r.input_hashes.update({str(p): sha(p) for p in inputs})
        image = (prior/'boot_chain_main1_LAB.bin').read_bytes()
        for n, row in enumerate(records):
            assert struct.unpack_from('<6I', image, TABLE-BS[1]['load_address_candidate']+n*24) == tuple(row)
        maps = []

        def mmap(name, address, data):
            p = out/name
            p.write_bytes(bytes(address % 8)+data)
            maps.extend(['--memory-mapfile', '/result/'+name, '--memory-region', f'{address:#x},{len(data)}'])
            return p

        mmap('main0_original.bin', BS[0]['load_address_candidate'], PS[0])
        main1 = mmap('main1_initialized.bin', BS[1]['load_address_candidate'], image)
        obj = mmap('region_object.bin', OBJECT, (prior/'boot_chain_region_object.bin').read_bytes())
        extension = mmap('extension_sentinel.bin', EXTENSION[0], b'\xa5'*(EXTENSION[1]-EXTENSION[0]))
        states = mmap('api_rows.bin', STATE, b'\xa5'*(128*(len(records)+4)))
        asm = ''

        def call(address):
            return f' mov r12,{address:#x}\n jl [r12]\n'

        def open_region(identifier, at):
            return f' mov r0,{identifier}\n add r1,r20,8\n add r2,r20,12\n'+call(0x12a71c)+f' st r0,[r20,{at}]\n'

        def close_region(identifier, at):
            return f' mov r0,{identifier}\n'+call(0x12a738)+f' st r0,[r20,{at}]\n'

        # These callback fields were A5 in the narrow initialization fixture.
        # The original setters provide the explicit null-callback context here.
        asm += ' mov r0,0\n'+call(0x12a764)+' mov r0,0\n'+call(0x12a76c)
        for n,row in enumerate(records):
            identifier = row[0]
            asm += f' mov r20,{STATE+n*128:#x}\n st sp,[r20]\n mov r0,{identifier}\n add r1,r20,32\n'+call(0x12a748)+' st r0,[r20,4]\n'
            asm += open_region(identifier,16)+open_region(identifier,20)+close_region(identifier,24)+close_region(identifier,28)
            asm += f' st sp,[r20,56]\n mov r0,{identifier}\n add r1,r20,64\n'+call(0x12a748)+' st r0,[r20,60]\n'
        # Deliberately overlapping real table regions; closing one permits the other.
        at = STATE+len(records)*128
        asm += f' mov r20,{at:#x}\n st sp,[r20]\n'+open_region(0x13,16)+open_region(0x1a,20)+close_region(0x13,24)+open_region(0x1a,28)+close_region(0x1a,60)+' st sp,[r20,56]\n'
        # Both errors must leave caller outputs and region bytes untouched.
        for n,identifier in enumerate([0xe8,0xe7],len(records)+1):
            asm += f' mov r20,{STATE+n*128:#x}\n st sp,[r20]\n'+open_region(identifier,16)+close_region(identifier,24)+f' mov r0,{identifier}\n add r1,r20,32\n'+call(0x12a748)+' st r0,[r20,4]\n st sp,[r20,56]\n'
        # Uninitialized object rejects all three APIs before selecting a record.
        asm += f' mov r10,{OBJECT+40:#x}\n mov r0,0\n stb r0,[r10]\n mov r20,{STATE+(len(records)+3)*128:#x}\n st sp,[r20]\n'
        asm += open_region(0,16)+close_region(0,24)+' mov r0,0\n add r1,r20,32\n'+call(0x12a748)+' st r0,[r20,4]\n st sp,[r20,56]\n'
        asm += f' mov r10,{OBJECT+40:#x}\n mov r0,1\n stb r0,[r10]\n mov r0,0\n mov r8,1\n trap_s 1\n'
        elf = compile_probe(r,'region_api',asm)
        result, log = r.run('region_api','/result/'+elf.name,maps)
        assert result['exit_code'] == 0 and result['fault'] is None, log
        data = states.read_bytes()
        rows = []
        for n,row in enumerate(records):
            w = struct.unpack_from('<32I',data,n*128)
            wanted = tuple(records[lookup[row[0]]])
            assert (w[1],w[4],w[5],w[6],w[7],w[15]) == (0,0,0x1d00002,0,0x1d00008,0), (n,w)
            assert (w[2],w[3]) == (wanted[3],wanted[4]) and w[0] == w[14]
            assert w[8:14] == w[16:22] == wanted
            rows.append(dict(record=n,id=hex(row[0]),resolved_record=lookup[row[0]],base=hex(w[2]),bytes=w[3],query_open_reopen_close_reclose_query=[hex(w[i]) for i in [1,4,5,6,7,15]],stack_preserved=True))
        w = struct.unpack_from('<32I',data,len(records)*128)
        assert (w[4],w[5],w[6],w[7],w[15]) == (0,0x1d00003,0,0,0) and w[0] == w[14]
        for n,status in enumerate([0x1d00004,0x1d00005,0x1d00001],len(records)+1):
            w = struct.unpack_from('<32I',data,n*128)
            assert w[1] == w[4] == w[6] == status and w[0] == w[14] and w[2] == w[3] == 0xa5a5a5a5
        assert main1.read_bytes() == image
        expected_obj = bytearray((prior/'boot_chain_region_object.bin').read_bytes())
        struct.pack_into('<2I',expected_obj,32,0,0)
        struct.pack_into('<2I',expected_obj,48,0x1a,0x13)
        assert obj.read_bytes() == expected_obj
        assert extension.read_bytes() == b'\xa5'*(EXTENSION[1]-EXTENSION[0])
        assert all(sha(Path(p)) == digest for p,digest in r.input_hashes.items())
        (out/'api_cases.json').write_text(json.dumps(rows,indent=2)+'\n')
        (out/'gnu_verified.txt').write_text(disasm(0x12a71c,0x12a774)+disasm(0x1ef7f8,0x1ef960))
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ORIGINAL_REGION_API_NO_RELOCATION',region_sequences=111,additional_scenarios=4,
                         initialized_source=str(proof.relative_to(ROOT)),input_hashes=r.input_hashes,
                         assumptions=['Verified initialized Main1/object snapshot; original Main0 routines without entry replacements',
                                      'Null callbacks set through original APIs; object-ready bit explicitly cleared/restored in one scenario'],
                         limits=['No callbacks with nonzero pointers, table-reinitialization callers, other pools, DMA/cache/alias or full boot',
                                 'Extension is sentinel, not handler execution; no physical camera access or installation readiness'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n')
        (out.parent/'region_api_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
        print('PASS',len(rows),'region sequences +4 scenarios',out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc))
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n')
        raise


if __name__ == '__main__':
    main()
