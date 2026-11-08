#!/usr/bin/env python3
"""Version the register atlas with existing FE1 CPU/observer evidence, read-only inputs."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct

from s33_verify_sensor_mmio_dialog import aligned_window, ROOT


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load(p):
    return json.loads(p.read_text())


def save(p, obj):
    p.write_text(json.dumps(obj, indent=2)+'\n')


def static_argument_proof(out, payload, firmware_offset):
    """Bound a software domain without inventing runtime table contents."""
    evidence=out/'evidence'
    manifest=ROOT/'S33-sections/TBM_blocks/manifest.json'
    manual=ROOT/'outputs/gnu_arc700_aux/sources/ARCompact_5115-029.txt'
    inputs={str(manifest):sha(manifest),str(manual):sha(manual)}
    windows=[]
    for name,start,end in [('caller',0x33c976,0x33c99e),('leaf',0x342c08,0x342c2c)]:
        listing=aligned_window(payload,0xad800,start,end)
        path=evidence/f'aux10010_{name}_disassembly.txt';path.write_text(listing+'\n')
        insns={int(m[1],16):(m[2],m[3].strip()) for line in listing.splitlines()
               if (m:=re.match(r'\s*([0-9a-f]+):\s+(?:[0-9a-f]{4} )*\s*\t([a-z0-9._]+)\t(.*)',line))}
        windows.append(dict(name=name,start=hex(start),end=hex(end),source_file=str(path),
                            firmware_offset=firmware_offset+start-0xad800,
                            bytes_hex=payload[start-0xad800:end-0xad800].hex(),
                            instructions={hex(k):dict(opcode=v[0],operands=v[1])for k,v in insns.items()}))
    caller=windows[0]['instructions'];leaf=windows[1]['instructions']
    for pc,opcode,args in [(0x33c976,'ldb','r0,[r14,156]'),(0x33c982,'add3_s','r0,r0,r0'),
                           (0x33c986,'add_s','r0,r0,r13'),(0x33c98a,'ldb','r0,[r0,0x2938]'),
                           (0x33c99c,'add_s','r2,r2,r1')]:
        assert caller[hex(pc)]==dict(opcode=opcode,operands=args)
    assert caller['0x33c998']['opcode']=='bl.d' and ';0x342c08' in caller['0x33c998']['operands']
    assert leaf['0x342c10']==dict(opcode='add_s',operands='r0,r0,0x10010')
    assert leaf['0x342c16']==dict(opcode='lr',operands='r1,[r0]')
    assert leaf['0x342c24']==dict(opcode='sr',operands='r1,[r0]')
    pools=[]
    for pc,address,expected in [(0x33c97a,0x33cb7c,0x360914),(0x33c97c,0x33cba0,0x42a69a),
                                 (0x33c984,0x33cba4,0x363694)]:
        value=struct.unpack_from('<I',payload,address-0xad800)[0];assert value==expected
        assert f';{hex(address)}' in caller[hex(pc)]['operands']
        pools.append(dict(load_pc=hex(pc),pool=hex(address),value=hex(value),
                          firmware_offset=firmware_offset+address-0xad800))
    manual_lines=manual.read_text().splitlines()
    add3=next((i+1,line)for i,line in enumerate(manual_lines)
              if '0x16' in line and 'ADD3_S' in line and '(c << 3)' in line)
    table_base=0x42a69a+0x2938
    table_addresses=[table_base+9*i for i in range(256)]
    ranges=[]
    for entry in load(manifest):
        if not entry.get('within_file') or 'file' not in entry:
            continue
        p=manifest.parent/entry['file'];assert sha(p)==entry['sha256'];inputs[str(p)]=sha(p)
        lo=entry['load_address_candidate'];hi=lo+entry['size']
        ranges.append(dict(index=entry['index'],start=hex(lo),end_exclusive=hex(hi)))
        assert all(not lo<=a<hi for a in table_addresses)
    assert len(ranges)==16
    result=dict(status='PASS_STATIC_AUX10010_ARGUMENT_BOUND',date='2026-10-25',
                windows=windows,pools=pools,primary_add3_semantics=dict(file=str(manual),line=add3[0],text=add3[1]),
                selector='u8(memory[r14+156])',table_address='0x42cfd2+9*selector',
                table_address_min=hex(min(table_addresses)),table_address_max=hex(max(table_addresses)),
                aux_expression='0x10010+u8(memory[0x42cfd2+9*u8(memory[r14+156])])',
                software_upper_domain=dict(min='0x10010',max='0x1010f',concrete_indices_derived=0),
                table_addresses_covered_by_manifest_payloads=0,manifest_candidate_ranges=ranges,
                input_sha256=inputs,hardware_access=False,
                limits=['Static provenance only; original caller not executed.',
                        'Table bytes require runtime producer/provenance; absent file-backed payload coverage does not imply zero, BSS, or free RAM.',
                        '256 possible byte values do not prove 256 implemented or observed AUX registers.',
                        'ADD3_S with identical operands produces nine times the input; call delay slot changes r2, not r0.'])
    assert all(sha(Path(p))==h for p,h in inputs.items())
    save(evidence/'aux10010_argument_proof.json',result)
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--parent',type=Path,required=True)
    ap.add_argument('--source',type=Path,required=True)
    ap.add_argument('--observer',type=Path,required=True)
    ap.add_argument('--output',type=Path)
    args=ap.parse_args()
    parent=args.parent.resolve();src=args.source.resolve();obsdir=args.observer.resolve()
    ledger=load(parent/'sha256.json')
    assert all(sha(parent/p)==h for p,h in ledger.items()),'parent ledger mismatch'
    source=load(src/'verified_evidence.json');observer=load(obsdir/'verified_evidence.json')
    assert source['status']=='PASS_FE1_STORAGE_WRITERS_AND_CORE46_PACK'
    assert observer['status']=='PASS_DELEGATING_MEMORY_OBSERVER'
    assert all(sha(Path(p))==h for p,h in source['input_hashes'].items())
    assert all(sha(src/p)==h for p,h in source['files'].items())
    assert all(sha(Path(p))==h for p,h in observer['input_sha256'].items())
    assert all(c['exit_code']==0 and c['fault'] is None for c in source['cases'])
    assert len(source['cases'])==len(observer['cases'])==6
    assert all(c['trace_identical'] and c['exit_code']==0 and not c['attempts_without_result'] for c in observer['cases'])
    utc=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out=args.output.resolve() if args.output else parent.parent/utc
    assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink()
    ev=out/'evidence'
    for source_file,name in [(src/'verified_evidence.json','fe1_register_window.json'),
                              (obsdir/'verified_evidence.json','observer_fe1.json'),
                              (Path(__file__),'s33_integrate_fe1_register_evidence.py'),
                              (src/'verifier_snapshot.py','s33_verify_fe1_register_window.py')]:
        shutil.copy2(source_file,ev/name)
    payload_info=source['payloads']['0'];payload=Path(payload_info['path']).read_bytes()
    fwpath=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';firmware=fwpath.read_bytes()
    assert payload==firmware[payload_info['firmware_offset']:payload_info['firmware_offset']+len(payload)]
    argument=static_argument_proof(out,payload,payload_info['firmware_offset'])
    mmio=load(ev/'mmio_documented.json');by_address=defaultdict(list)
    for case in observer['cases']:
        for event in case['completed']:
            assert event['width_bytes']==2 and event['operation']=='write'
            by_address[event['address']].append(dict(case=case['name'],**event))
    assert len(by_address)==26 and sum(map(len,by_address.values()))==41
    assert not set(by_address)&{int(r['address'],16)for r in mmio['records']}
    field_map={0:'write1 then write0',4:'argument0 bits15:0',8:'argument0 bits27:16',
               0x20:'argument1 bits15:0',0x28:'argument2 bits15:0',0x14:'argument3 bits15:0',
               0xc:'argument4 bits15:0',0x10:'argument5 bits15:0',0x18:'argument6 bits15:0',
               0x1c:'argument7 bits15:0',0x24:'argument8 stack bits15:0',0x3c:'fixed0x14 or0x18 according to selected original routine'}
    for address,events in sorted(by_address.items()):
        meaning=('fixed1' if address==0xfe10000 else 'fixed0x1405') if address<0xfe10040 else field_map[(address-0xfe10000)&0x3f]
        mmio['records'].append(dict(address=f'0x{address:08X}',namespace='soc_mmio',subsystem='fe1_register_window_unknown_function',
                                   width_bits=16,access='write_halfword_di_observed',confidence='original_firmware_guest_write_external_observer',
                                   fields=[dict(meaning=meaning,evidence_type='software_operand_mapping',physical_meaning='unknown')],
                                   observed_accesses=events,firmware='Nikon S33 V1.1',hardware_verified=False,
                                   sources=[dict(file=str(ev/'fe1_register_window.json'),line=1),dict(file=str(ev/'observer_fe1.json'),line=1)],
                                   evidence=['byte_identical_original_code','isolated_guest_execution','external_delegating_memory_observer'],
                                   unknown=['Peripheral identity, physical reset, access permissions, completion and IRQ behavior unknown.',
                                            'Fixture is storage; software write1/write0 does not establish a hardware trigger.']))
    mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']))
    save(ev/'mmio_documented.json',mmio)
    extended=load(ev/'cpu_aux_extended.json')
    assert not any(r['number']==0x18 for r in extended['records'])
    extended['records'].append(dict(space='aux',number=24,number_hex='0x18',name='UNKNOWN_AUX_18',width_bits=32,
                                    access='read_by_original_guest_seeded_test',classification='original_guest_read_synthetic_initial_state',
                                    hardware_verified=False,bit_fields=[],sources=[dict(file=str(ev/'fe1_register_window.json'),line=1)],
                                    notes=['Synthetic caller seeds AUX18=0x01000000; not Nikon reset or physical value.',
                                           'Read by original firmware at0x2931BC, result feeds r51 address packing; physical purpose unknown.']))
    save(ev/'cpu_aux_extended.json',extended)
    architecture=load(ev/'cpu_aux_catalog.json')
    usages={46:dict(entry='0x293350',operation='write',software_result='0x851a82f3',
                   formula='0x80000000 | 0x8000 | ((arg0&0xfff)>>2) | ((((arg1&0x1ff)>>1) | ((arg2&0x1f)<<8))<<16)'),
            51:dict(entry='0x2931bc',operation='write',software_result='0xe0400240',
                    formula='uint32((arg0-aux18) | ((arg1-aux18)<<14) | 0xe0000000)'),
            55:dict(entry='0x2931bc',operation='read',software_result='0x55667788',synthetic_initial=True),
            59:dict(entry='0x2931bc',operation='write',software_result='0x000eb8bd')}
    for r in architecture['records']:
        if r['space']=='core' and r['number'] in usages:
            r.setdefault('firmware_guest_usage',[]).append(dict(**usages[r['number']],
                source_file=str(ev/'fe1_register_window.json'),physical_extension_semantics_verified=False))
            r['sources'].append(dict(file=str(ev/'fe1_register_window.json'),line=1))
    save(ev/'cpu_aux_catalog.json',architecture)
    trace=load(ev/'firmware_aux_trace.json');pc=0x2931bc
    lines=(src/'custom_address_pack.trace').read_text().splitlines()
    trace_line,text=next((i+1,line)for i,line in enumerate(lines)if line.startswith('0x2931bc  lr'))
    assert 'cr <- 0x1000000' in text
    offset=payload_info['firmware_offset']+pc-payload_info['base']
    event=dict(trace_line=trace_line,pc=pc,pc_hex=hex(pc),operation='read',aux_index=24,aux_hex='0x18',
               trace_text=text,semantic_result_observed=True,retirement_proven_by_this_record=False,
               firmware_offset=offset,firmware_offset_hex=hex(offset),original_firmware_bytes_next8=firmware[offset:offset+8].hex(),
               trace_value=0x1000000,trace_value_hex='0x1000000',value_meaning='Explicit synthetic initial AUX state read by original guest instruction')
    trace['runs'].append(dict(name='fe1_custom_address_pack_seeded',path=str(src/'custom_address_pack.trace'),
                              sha256=sha(src/'custom_address_pack.trace'),run_manifest=str(src/'verified_evidence.json'),
                              run_manifest_sha256=sha(src/'verified_evidence.json'),
                              elf=str(src/'main_source.elf'),elf_sha256=sha(src/'main_source.elf'),
                              elf_role='source_mmap_ELF_for_static_verification',
                              actual_runtime_harness_elf=str(src/'custom_address_pack.elf'),
                              actual_runtime_harness_sha256=sha(src/'custom_address_pack.elf'),
                              runtime_original_code_mmap=payload_info,synthetic_initial_aux18='0x01000000',
                              synthetic_initial_core55='0x55667788',semantic_result_observed_records=[event]))
    trace['distinct_aux_indices']=sorted({e['aux_index']for r in trace['runs']for e in r['semantic_result_observed_records']})
    trace['distinct_aux_hex']=list(map(hex,trace['distinct_aux_indices']))
    trace['limits']=[x for x in trace['limits']if not x.startswith('Observed subset is 20')]
    trace['limits'].append('21 AUX indices:20 in boot prefixes,1 additional in explicitly seeded isolated caller; no physical values established.')
    trace['date']='2026-10-25';save(ev/'firmware_aux_trace.json',trace)
    static=load(ev/'aux_firmware_expansion.json')
    family=next(f for f in static['custom_families']if f['expression']=='0x10010+argument_r0')
    family.update(argument_expression=argument['aux_expression'],software_domain=argument['software_upper_domain'],
                  source_file=str(ev/'aux10010_argument_proof.json'),
                  unknown='Exact argument is a runtime table byte at0x42CFD2+9*u8(context+156), outside16manifest payload ranges; no concrete index derived.')
    save(ev/'aux_firmware_expansion.json',static)
    metadata=load(out/'atlas_metadata.json')
    metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),
                    parent_ledger_files_verified=len(ledger),fe1_source=str(src/'verified_evidence.json'),
                    fe1_observer=str(obsdir/'verified_evidence.json'),fe1_observed_addresses=26,fe1_observer_events=41,
                    fe1_cases=6,aux_guest_indices=21,whole_physical_map_complete=False)
    save(out/'atlas_metadata.json',metadata)
    audit=load(out/'completion_audit.json')
    audit['requirements'][2]['limits'][1]='195software-level addresses do not establish physical semantics/reset/IRQ/DMA/timing'
    audit['next_work'][0]='Resolve remaining custom AUX callers and runtime table producers;10010 domain bounded, values unknown'
    save(out/'completion_audit.json',audit)
    assert all(sha(parent/p)==h for p,h in ledger.items()),'parent changed'
    print(out)


if __name__=='__main__':
    main()
