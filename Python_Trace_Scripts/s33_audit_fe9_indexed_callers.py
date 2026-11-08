#!/usr/bin/env python3
"""Independently check original FE9 table selections, local index witnesses and sampled exclusions."""
import argparse, json, re, struct
from collections import Counter, defaultdict
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT, sha, load, save
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_custom_aux_cfg import call_at


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('source', type=Path); ap.add_argument('output', type=Path)
    args = ap.parse_args(); src = args.source.resolve(); d = load(src/'verified_evidence.json')
    assert d['status'] == 'PASS_FE9_ORIGINAL_INDEXED_CALLERS' and d['capture_streams_separate']
    assert all(sha(Path(k)) == v for k, v in d['input_hashes'].items()) and all(sha(src/k) == v for k, v in d['files'].items())
    parent = ROOT/'Risultati/Processor_Registers/20261025T192207Z'; ledger = load(parent/'sha256.json')
    assert all(sha(parent/k) == v for k, v in ledger.items())
    prior = load(parent/'evidence/fe9_dispatch_and_mask_helpers_audit.json')
    assert prior['status'] == 'PASS_FE9_SELECTORS_UNBOUND_MASK_HELPERS_AUDIT'
    blocks, payloads, directory = verified_payloads(ROOT); body = payloads[0]; base = blocks[0]['load_address_candidate']
    fw = ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin'; firmware = fw.read_bytes(); decoded = {}
    inputs = {str(q): sha(q) for q in [Path(__file__), fw, src/'verified_evidence.json', src/'caller_index_witnesses.json',
        parent/'sha256.json', parent/'evidence/fe9_dispatch_and_mask_helpers_audit.json',
        ROOT/'work/build-arc/binutils/objdump', ROOT/'work/build-arc/binutils/objcopy']}
    for name in ['s33_trace_state_dispatch', 's33_verify_sensor_mmio_dialog', 's33_verify_custom_aux_cfg', 's33_integrate_ffc7000_table_tail']:
        q = Path(__file__).with_name(name+'.py'); inputs[str(q)] = sha(q)
    for m in d['payloads']:
        q = Path(m['path']); inputs[str(q)] = sha(q)
        assert q.read_bytes() == payloads[m['index']] == firmware[m['firmware_offset']:m['firmware_offset']+m['size']]
        assert m['sha256'] == sha(q) and m['base'] == blocks[m['index']]['load_address_candidate']
    assert [m['index'] for m in d['payloads']] == [0, 1]

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
        ins = decode(pc); assert (ins['opcode'], ins['operands']) == (op, operands), (hex(pc), ins)

    def target(pc):
        ins = decode(pc); c = call_at(body, pc-base, base)
        assert ins['opcode'] in ['bl', 'bl.d'] and c and c['target'] == int(re.search(r';(?:0x)?([0-9a-f]+)', ins['operands'])[1], 16)
        return c['target']

    def word(address):
        owners = [b for b in blocks[:2] if b['load_address_candidate'] <= address and address+4 <= b['load_address_candidate']+len(payloads[b['index']])]
        assert len(owners) == 1; owner = owners[0]
        return struct.unpack_from('<I', payloads[owner['index']], address-owner['load_address_candidate'])[0]

    # Own wrapper-to-pool and wrapper-to-helper mapping, checked at each original call site.
    specs = {0x2ee760:(0x2eea08,0x3098b8,0x309ad0,'masked'), 0x2ee7b0:(0x2eea18,0x3098e4,0x309afc,'flag'),
        0x2ee800:(0x2eea28,0x309918,0x309b30,'masked'), 0x2ee850:(0x2eea38,0x309944,0x309b88,'masked'),
        0x2ee8a0:(0x2eea48,0x3099e4,0x309b5c,'masked'), 0x2ee8f0:(0x2eea58,0x3099c8,0x309c0c,'split'),
        0x2ee924:(0x2eea60,0x309970,0x309bb4,'masked'), 0x2ee974:(0x2eea70,0x30999c,0x309be0,'masked'),
        0x2ee9c4:(0x2eea80,0x309a2c,0x309c44,'selector')}
    for e, (pool, ha, hb, kind) in specs.items():
        assert target(e+10) == 0x2ed448; exact(e+14, 'mov_s', 'r0,r2'); exact(e+16, 'cmp_s', 'r0,0')
        assert decode(e+18)['opcode'] == 'bne_s'
        special = kind in ['split', 'selector']; ca, cb = (26, 40) if special else (32, 52)
        assert target(e+ca) == ha and target(e+cb) == hb
        for pc, pp in [(e+20, pool), (e+(34 if special else 40), pool+(4 if special else 8))]:
            ins = decode(pc); assert ins['opcode'] == 'ld_s' and int(re.search(r';(?:0x)?([0-9a-f]+)', ins['operands'])[1],16) == pp
        for pc in [e+(22 if special else 26), e+(36 if special else 46)]:
            assert decode(pc)['opcode'] == 'add2_s'
    exact(0x2ed448,'cmp_s','r0,0'); exact(0x2ed44a,'mov.ne','r0,0x1'); exact(0x2ed44e,'j_s','[blink]')
    exact(0x2ee9f2,'cmp_s','r13,0x1'); exact(0x2ee9fe,'and_s','r0,r0,r1'); exact(0x2eea00,'extw_s','r1,r0')
    assert int(re.search(r';(?:0x)?([0-9a-f]+)',decode(0x2ee9f8)['operands'])[1],16) == 0x2eea84
    census = load(src/'caller_index_witnesses.json'); candidates = []
    for b in blocks:
        blob = payloads[b['index']]; inputs[str(directory/b['file'])] = sha(directory/b['file'])
        for off in range(0,len(blob)-7,2):
            c = call_at(blob, off, b['load_address_candidate'])
            if c and c['target'] in specs:
                assert b['index'] == 0 and target(c['pc']) == c['target']; candidates.append(dict(payload=0, **c))
    assert candidates == census['qualified_BL_candidates'] and len(candidates) == 75
    indices = {}; witness_count = 0
    for e in specs:
        indices[e] = set()
        for w in census['local_constant_index_witnesses'][hex(e)]:
            pc, start = int(w['call_pc'],0), int(w['setup_pc'],0); assert target(pc) == e
            exact(start,'mov_s',f"r0,{hex(w['index']) if w['index'] else '0'}")
            path = [start]; cur = start+decode(start)['size']
            if start < pc:
                while cur < pc:
                    ins = decode(cur); assert ins['opcode'] in ['mov_s','extw_s','ld_s'] and ins['operands'].split(',')[0] != 'r0'
                    path.append(cur); cur += ins['size']
                assert cur == pc
                if w['delay_slot']:
                    delay = decode(int(w['delay_slot'],0)); assert delay['opcode'] in ['mov_s','extw_s','ld_s'] and delay['operands'].split(',')[0] != 'r0'
            else: assert decode(pc)['opcode'] == 'bl.d' and start == pc+4
            assert path == [int(x,0) for x in w['setup_path']]; indices[e].add(w['index']); witness_count += 1
        assert sorted(indices[e] or {0}) == census['tested_indices'][hex(e)]
    assert not indices[0x2ee924] and not indices[0x2ee974]
    checks = []; counts = Counter(); admissions = set(); samples = set(); addr_ops = defaultdict(dict); table_checks = 0; equivalences = 0; mode1_extra_bit_cases = 0; groups = {}
    for case in d['cases']:
        if not case['observer_enabled']: continue
        trace_path = src/(case['name']+'.trace'); trace = trace_path.read_text(); inputs[str(trace_path)] = sha(trace_path)
        assert trace_path.read_bytes() == (src/(case['name'].replace('_observed','_reference')+'.trace')).read_bytes()
        state = {int(k,0):struct.unpack_from('<H',bytes.fromhex(f['before']),int(k,0)%8)[0] for k,f in case['fixtures'].items()}
        expected = []; expected_loads = []; entries = []; channel = case['channel']; bank = int(channel != 0)
        assert bank == case['normalized_bank']; assembly = (src/(case['scenario']+'.s')).read_text()
        harness = re.findall(r'mov r0,(0x[0-9a-f]+)\nmov r1,(0x[0-9a-f]+)\nmov r2,(0x[0-9a-f]+)\nmov r12,(0x[0-9a-f]+)\njl \[r12\]',assembly)
        assert [(int(e,0),[int(a,0),int(b,0),int(c,0)]) for a,b,c,e in harness] == [(int(c['entry'],0),[int(x,0) for x in c['arguments']]) for c in case['original_calls']]
        for call in case['original_calls']:
            e = int(call['entry'],0); index, value, chan = [int(x,0) for x in call['arguments']]; assert chan == channel
            pool, ha, hb, kind = specs[e]; h = hb if bank else ha; special = kind in ['selector','split']; p = word(pool+bank*(4 if special else 8)); a = word(p+4*index)
            witnessed = index in indices[e]; assert call['original_index_witness'] == witnessed and int(call['helper'],0) == h and call['kind'] == kind
            expected_loads.append((e+((38 if bank else 24) if special else (48 if bank else 28)),a)); words = [(p+4*index,a)]; ret = None
            if kind == 'selector':
                aa = 0xfe9813c if bank else 0xfe9013c; bb = aa+4; m = 2047 if bank else 1023; delta = h-0x309a2c
                if value == 0: ev = [(0x309a58+delta,'read',aa,state[aa]),(0x309a66+delta,'write',aa,state[aa]//(m+1)*(m+1)+(a&m))]; ret = 0
                elif value == 1:
                    mask = word(word(0x2eea84)+4*index); raw = state[aa]; ret = raw&mask; ev = [(0x309aa4+delta,'read',aa,raw)]
                    expected_loads.append((0x2ee9fc,mask)); words.append((word(0x2eea84)+4*index,mask)); mode1_extra_bit_cases += int(not bank and index == 11 and ret != (raw&1023))
                elif value == 2: ev = [(0x309a78+delta,'read',bb,state[bb]),(0x309a66+delta,'write',bb,state[bb]//(m+1)*(m+1)+(a&m))]; ret = 0
                elif value == 3: ev = [(0x309a90+delta,'read',bb,state[bb]),(0x309a66+delta,'write',bb,state[bb]^(state[bb]&a))]; ret = 0
                else: ev = []; ret = 0x55aa
                op = dict(entry=hex(e),index=index,helper=hex(h),selector=value,operation='original_fixed_selector_with_wrapper_read_AND',table_value=hex(a),low_field_width=11 if bank else 10)
            elif kind == 'split':
                ev = [(h+12,'write',a,value%65536),(h+20,'write',a+4,value//65536)]
                op = dict(entry=hex(e),index=index,helper=hex(h),operation='low16_at_dest_then_high16_at_dest_plus4')
            else:
                mp = word(pool+bank*8+4); mask = word(mp+4*index); assert 0 < mask < 65536
                expected_loads.append((e+(56 if bank else 36),mask)); words.append((mp+4*index,mask)); bit = next(i for i in range(16) if mask&(1<<i)); old = state[a]
                if kind == 'flag': rd,wr = (16,24) if value == 0 else (36,44); new = (old&~(1<<bit))|((1<<bit) if value != 0 else 0)
                else: rd,wr = 12,34; new = sum(((((value >> (i-bit))&1) if mask&(1<<i) else ((old>>i)&1))<<i) for i in range(16))
                ev = [(h+rd,'read',a,old),(h+wr,'write',a,new)]
                op = dict(entry=hex(e),index=index,helper=hex(h),operation=kind,mask=hex(mask),first_low16_mask_bit=bit)
            assert call['expected_return'] == ret and [(int(x['address'],0),int(x['value'],0)) for x in call['table_words']] == words
            assert [(x['pc'],x['operation'],x['address'],x['value']) for x in call['events']] == ev
            for pc, operation, address, val in ev:
                assert 0 <= val <= 65535; counts[('witnessed' if witnessed else 'sample')+'_'+operation] += 1
                if operation == 'write': state[address] = val
                (admissions if witnessed else samples).add(address)
                if witnessed:
                    detail = dict(op,table_word_addresses=list(map(hex,[x[0] for x in words])))
                    if kind == 'split': detail.update(destination=hex(a),halfword_lane='low16' if address == a else 'high16')
                    addr_ops[address][json.dumps(detail,sort_keys=True)] = detail
                assert decode(pc)['opcode'] == ('ldh.di' if operation == 'read' else 'sth.di')
                prior_ins = prior['independently_redecoded_instructions'][hex(pc)]; assert prior_ins['bytes_hex'] == decode(pc)['bytes_hex']
            expected.extend(ev); entries.append(e)
        stderr_path = src/(case['name']+'.stderr.log'); inputs[str(stderr_path)] = sha(stderr_path)
        raw_events = [json.loads(line.removeprefix('S33_MEM ')) for line in stderr_path.read_text().splitlines() if line.startswith('S33_MEM ')]
        events = case['completed_memory_events']; assert [x for x in raw_events if x['stage'] == 'result'] == events and len(raw_events) == 2*len(events)
        for b,r in zip(raw_events[::2],raw_events[1::2]):
            assert b['stage'] == 'begin' and r['stage'] == 'result' and b['width_bytes'] == r['width_bytes'] == 2
            assert all(b[k] == r[k] for k in ['id','pc','operation','address'])
        assert [(x['pc'],x['operation'],x['address'],x['value']) for x in events] == expected
        load_pcs = {pc for pc,_ in expected_loads}; memory_pcs = {pc for pc,_,_,_ in expected}; actual_loads = []; actual_mmio = []; actual_entries = []
        for line in trace.splitlines():
            m = re.match(r'0x([0-9a-f]+)\s+(\S+)\s+(.*)',line)
            if not m: continue
            pc = int(m[1],16); opcode = m[2]
            if pc in specs: actual_entries.append(pc)
            if pc in load_pcs:
                assert opcode == 'ld_s'; v = int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16); actual_loads.append((pc,v))
            if pc in memory_pcs:
                assert opcode in ['ldw.di','stw.di']; v = int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16)&65535; actual_mmio.append((pc,'read' if opcode == 'ldw.di' else 'write',v))
            assert opcode not in ['lr','sr']
        assert actual_entries == entries and actual_loads == expected_loads
        assert actual_mmio == [(pc,op,v) for pc,op,_,v in expected]; table_checks += len(actual_loads)
        for key,f in case['fixtures'].items():
            address = int(key,0); before = bytes.fromhex(f['before']); after = (src/f['file']).read_bytes(); off = address%8
            assert len(after) == 8 and struct.unpack_from('<H',after,off)[0] == state[address]
            assert all(before[i] == after[i] for i in range(8) if i not in [off,off+1])
        assert case['exit_code'] == 0 and case['fault'] is None and case['full_original_calls_completed']
        key = (case['pattern'],bank)
        if key in groups: assert groups[key] == expected; equivalences += 1
        else: groups[key] = expected
        checks.append(dict(case=case['name'],calls=len(entries),events=len(events),table_loads=len(actual_loads)))
    assert len(checks) == 12 and sum(counts.values()) == 1080 and len(admissions) == 70
    assert samples == {0xfe90200,0xfe90400,0xfe98200,0xfe98400} and not samples&admissions
    assert sum(v for k,v in counts.items() if k.startswith('sample')) == 48 and equivalences == 6 and mode1_extra_bit_cases == 2
    assert admissions == {int(x,0) for x in d['witnessed_index_addresses']} and samples == {int(x,0) for x in d['unproven_index_sample_addresses']}
    assert len(d['pairs']) == 12 and all(p['trace_identical'] for p in d['pairs'])
    assert all(sha(Path(k)) == v for k,v in inputs.items())
    save(args.output,dict(status='PASS_FE9_ORIGINAL_INDEXED_CALLERS_AUDIT',date='2026-10-25',checks=checks,operation_counts=dict(counts),
        selected_addresses=list(map(hex,sorted(admissions))),sample_addresses_excluded=list(map(hex,sorted(samples))),
        address_software_operations={hex(k):list(v.values()) for k,v in addr_ops.items()},
        independently_redecoded_instructions={hex(k):v for k,v in decoded.items()},original_table_load_checks=table_checks,
        local_constant_index_witnesses=witness_count,qualified_BL_candidates=75,tested_indices={hex(k):sorted(v) for k,v in indices.items()},
        channel_equivalences=6,channel_equivalence_scope='Only channel argument varies1→2/FFFFFFFF withvalues,seeds,indices,modes unchanged',
        mode1_A_index11_extra_bit_cases=2,all_caller_argument_domains_closed=False,global_reachability_proven=False,
        input_sha256=inputs,hardware_access=False,gnu_modified=False,limits=d['limits']))
    print('PASS70selected addresses/4excluded/1080events;',table_checks,'originaltableloads;',witness_count,'localindexwitnesses')


if __name__ == '__main__': main()
