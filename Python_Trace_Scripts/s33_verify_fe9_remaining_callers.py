#!/usr/bin/env python3
"""Qualify seven previously unresolved FE9 index setups, without hardware access.

Exact original instruction paths are checked, including branch destinations and
delay slots. These are local witnesses, not a proof of global reachability.
Table selections are static candidates until their new indices are CPU-tested.
"""
import json
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT, load, save, sha
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_custom_aux_cfg import call_at

PARENT = ROOT/'Risultati/Processor_Registers/20261025T193115Z'


def main():
    ledger = load(PARENT/'sha256.json')
    assert all(sha(PARENT/k) == v for k, v in ledger.items())
    prior = load(PARENT/'evidence/fe9_indexed_callers_audit.json')
    blocks, payloads, directory = verified_payloads(ROOT)
    body = payloads[0]; base = blocks[0]['load_address_candidate']
    out = ROOT/'Risultati/Processor_Register_FE9_Remaining'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    inputs = {str(q): sha(q) for q in [Path(__file__), PARENT/'sha256.json',
        ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin',
        ROOT/'work/build-arc/binutils/objdump', ROOT/'work/build-arc/binutils/objcopy']}
    for name in ['s33_trace_state_dispatch','s33_verify_sensor_mmio_dialog','s33_verify_custom_aux_cfg','s33_integrate_ffc7000_table_tail']:
        q = Path(__file__).with_name(name+'.py'); inputs[str(q)] = sha(q)
    for b in blocks: inputs[str(directory/b['file'])] = sha(directory/b['file'])
    decoded = {}

    def decode(pc):
        if pc not in decoded:
            text = aligned_window(body, base, pc, pc+12)
            line = next(x for x in text.splitlines() if re.match(r'\s*'+f'{pc:x}:', x))
            m = re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)', line)
            raw = b''.join(bytes.fromhex(w)[::-1] for w in m[1].split())
            assert raw == body[pc-base:pc-base+len(raw)]
            decoded[pc] = dict(opcode=m[2], operands=m[3].strip(), size=len(raw), bytes_hex=raw.hex())
        return decoded[pc]

    def exact(pc, op, operands):
        ins = decode(pc)
        assert (ins['opcode'], ins['operands']) == (op, operands), (hex(pc), ins)

    def word(address):
        owners = [b for b in blocks if b['load_address_candidate'] <= address and address+4 <= b['load_address_candidate']+len(payloads[b['index']])]
        assert len(owners) == 1
        b = owners[0]
        return struct.unpack_from('<I', payloads[b['index']], address-b['load_address_candidate'])[0]

    def branch_target(pc):
        return int(re.search(r';(?:0x)?([0-9a-f]+)', decode(pc)['operands'])[1],16)

    # Every segment includes all intervening instructions. Register copies are
    # tracked explicitly, rather than widening an arbitrary backward scan.
    paths = [
        (0x295408,0x2ee760,3,[(0x295402,'mov_s','r0,0x3'),(0x295404,'sub_s','r1,r1,0x1'),(0x295406,'extw_s','r1,r1')]),
        (0x295f92,0x2ee850,6,[(0x295f8a,'mov_s','r0,0x6'),(0x295f8c,'mov_s','r1,0'),(0x295f8e,'ld','r14,[pcl,-92]\t;0x295f30')]),
        (0x2ed642,0x2ee760,0,[(0x2ed63e,'mov_s','r14,0'),(0x2ed640,'mov_s','r0,r14')]),
        (0x2ed650,0x2ee760,1,[(0x2ed64a,'mov_s','r0,0x1'),(0x2ed64c,'sub_s','r1,r1,0x1'),(0x2ed64e,'extw_s','r1,r1')]),
        (0x2ed774,0x2ee8f0,0,[(0x2ed76e,'mov_s','r13,0'),(0x2ed770,'mov_s','r0,r13'),(0x2ed772,'mov_s','r1,r3')]),
        (0x2edf9e,0x2ee8f0,8,[(0x2edf98,'mov_s','r0,0x8'),(0x2edf9a,'mov','r1,-1')]),
    ]
    witnesses = []
    for pc, target, index, path in paths:
        registers = {}
        for j,(at,op,operands) in enumerate(path):
            exact(at,op,operands)
            assert at+decode(at)['size'] == (path[j+1][0] if j+1<len(path) else pc)
            dest, source = operands.split(',',1)
            if op == 'mov_s': registers[dest] = registers.get(source) if source.startswith('r') else int(source,0)
            else: registers.pop(dest,None)
        assert registers['r0'] == index
        call = call_at(body,pc-base,base)
        assert call and call['target'] == target and decode(pc)['opcode'] == 'bl.d'
        exact(pc+4,'mov_s', {0x295408:'r2,r18',0x295f92:'r2,r1',0x2ed642:'r2,r16',0x2ed650:'r2,r16',0x2ed774:'r2,r4',0x2edf9e:'r2,r13'}[pc])
        witnesses.append(dict(call_pc=hex(pc),target=hex(target),index=index,path=list(map(hex,[x[0] for x in path])),delay_slot=hex(pc+4)))

    # The seventh caller has three local paths; all select index 6.
    for at,op,operands in [(0x2ed674,'beq_s','22\t;0x2ed68a'),(0x2ed676,'cmp_s','r1,0'),
        (0x2ed678,'mov_s','r0,0x6'),(0x2ed67a,'beq_s','14\t;0x2ed686'),
        (0x2ed67c,'mov_s','r1,0x1'),(0x2ed686,'mov_s','r1,0x2'),
        (0x2ed688,'b_s','-10\t;0x2ed67e'),(0x2ed68a,'mov_s','r0,0x6'),
        (0x2ed68c,'mov_s','r1,0'),(0x2ed68e,'b_s','-14\t;0x2ed67e')]: exact(at,op,operands)
    assert decode(0x2ed67e)['opcode'] == 'bl' and branch_target(0x2ed67e) == 0x2ee850
    assert call_at(body,0x2ed67e-base,base)['target'] == 0x2ee850
    witnesses.append(dict(call_pc='0x2ed67e',target='0x2ee850',index=6,paths=[
        ['0x2ed674:fallthrough','0x2ed676','0x2ed678','0x2ed67a:fallthrough','0x2ed67c'],
        ['0x2ed674:fallthrough','0x2ed676','0x2ed678','0x2ed67a:taken','0x2ed686','0x2ed688'],
        ['0x2ed674:taken','0x2ed68a','0x2ed68c','0x2ed68e']],value_arguments=[1,2,0],delay_slot=None))
    census = load(PARENT/'evidence/fe9_indexed_witnesses.json')
    unresolved = {c['pc'] for c in census['qualified_BL_candidates']}-{int(w['call_pc'],0) for rows in census['local_constant_index_witnesses'].values() for w in rows}
    assert unresolved == {int(w['call_pc'],0) for w in witnesses} and len(unresolved) == 7

    # r14 is loaded before BL, preserved by the original wrapper/helpers, and
    # consumed by an indirect JL after another explicit constant index setup.
    # Preservation across the call is a dependency, not assumed proven here.
    for at,op,operands in [(0x295f98,'mov_s','r0,0x6'),(0x295f9a,'mov_s','r1,0'),
        (0x295f9c,'mov_s','r2,0x1'),(0x295f9e,'jl_s','[r14]')]: exact(at,op,operands)
    assert word(0x295f30) == 0x2ee850
    indirect = dict(call_pc='0x295f9e',loaded_register='r14',pool='0x295f30',target='0x2ee850',index=6,
        path=['0x295f8e','0x295f92:call','0x295f98','0x295f9a','0x295f9c','0x295f9e'],
        dependency='r14 preservation through original2EE850 call;not executed by this static pass')

    known = {r['number'] for r in load(PARENT/'register_map.json')['records'] if r['space']=='soc_mmio'}
    pools = {0x2ee760:0x2eea08,0x2ee850:0x2eea38,0x2ee8f0:0x2eea58}
    selections = []
    for target,index in sorted({(int(w['target'],0),w['index']) for w in witnesses}):
        if index in prior['tested_indices'][hex(target)]: continue
        pool = pools[target]
        for bank in [0,1]:
            pointer = word(pool+bank*8); masks = word(pool+bank*8+4)
            address, mask = word(pointer+index*4), word(masks+index*4)
            assert 0xfe00000 <= address < 0x10000000 and 0 < mask <= 0xffff
            selections.append(dict(wrapper=hex(target),index=index,bank=bank,table_word=hex(pointer+index*4),
                mask_word=hex(masks+index*4),address=hex(address),mask=hex(mask),already_cataloged=address in known,
                evidence_type='static_original_table_selection_not_new_CPU_evidence'))
    new = sorted({int(x['address'],0) for x in selections if not x['already_cataloged']})
    assert len(selections) == 8 and new == [0xfe90000,0xfe90004,0xfe90014,0xfe98000,0xfe98004,0xfe98014]
    assert all(sha(Path(k)) == v for k,v in inputs.items()) and all(sha(PARENT/k) == v for k,v in ledger.items())
    save(out/'verified_evidence.json',dict(status='PASS_FE9_SEVEN_LOCAL_CALLER_WITNESSES_STATIC',date='2026-10-25',
        parent_atlas=str(PARENT),parent_ledger_files_verified=len(ledger),witnesses=witnesses,indirect_candidate=indirect,
        new_index_table_selections=selections,new_scalar_candidates=list(map(hex,new)),
        independently_redecoded_instructions={hex(k):v for k,v in decoded.items()},input_sha256=inputs,
        global_reachability_proven=False,complete_index_domains_proven=False,new_CPU_runs=0,atlas_modified=False,
        hardware_access=False,gnu_modified=False,
        limits=['Seven BL local setup paths only;external branches entering inside segments are not enumerated.',
            'Six new MMIO table candidates require full original wrapper/helper CPU execution before admission.',
            'No new evidence for2EE924/974,physical semantics,BCR,AUX code/data orDSP arithmetic.']))
    save(out/'sha256.json',{'verified_evidence.json':sha(out/'verified_evidence.json')})
    print('PASS:7localBL witnesses;8table selections;6new scalar candidates;atlas unchanged')
    print(out)


if __name__ == '__main__': main()
