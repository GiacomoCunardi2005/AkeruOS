#!/usr/bin/env python3
"""Exercise original FE9 index wrappers against payload1 tables and local constant-index witnesses."""
import json, re, shutil, struct
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, sha
from s33_verify_gnu_defined_memory import LAB, BUILD, known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_custom_aux_cfg import call_at

REUSED = ROOT/'outputs/gnu_arc700/20261025T104108Z_2704fcf9'
SPECS = [
    (0x2ee760, 0x2eea08, 0x3098b8, 0x309ad0, 'masked'),
    (0x2ee7b0, 0x2eea18, 0x3098e4, 0x309afc, 'flag'),
    (0x2ee800, 0x2eea28, 0x309918, 0x309b30, 'masked'),
    (0x2ee850, 0x2eea38, 0x309944, 0x309b88, 'masked'),
    (0x2ee8a0, 0x2eea48, 0x3099e4, 0x309b5c, 'masked'),
    (0x2ee8f0, 0x2eea58, 0x3099c8, 0x309c0c, 'split'),
    (0x2ee924, 0x2eea60, 0x309970, 0x309bb4, 'masked'),
    (0x2ee974, 0x2eea70, 0x30999c, 0x309be0, 'masked'),
    (0x2ee9c4, 0x2eea80, 0x309a2c, 0x309c44, 'selector')]


def main():
    r = SeparatedRunner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=None, action='fe9-original-indexed-callers'))
    print('Evidence:', r.out, flush=True)
    try:
        r.prepare(); r.known_ranges = ''; r.experimental_engine = LAB
        assert sha(LAB/'install/bin/arc-elf32-run') == json.loads(BUILD.read_text())['engine_sha256']
        assert sha(REUSED/'observer') == json.loads((REUSED/'verified_evidence.json').read_text())['files']['observer']
        shutil.copy2(REUSED/'observer', r.out/'observer'); shutil.copy2(Path(__file__), r.out/Path(__file__).name)
        for p in [Path(__file__), BUILD, LAB/'install/bin/arc-elf32-run', REUSED/'observer', REUSED/'verified_evidence.json'] + [
                Path(__file__).with_name(x+'.py') for x in ['s33_verify_ff7_transfer_windows', 's33_verify_gnu_defined_memory',
                's33_verify_gnu_dsp_lab', 's33_trace_state_dispatch', 's33_verify_sensor_mmio_dialog', 's33_verify_custom_aux_cfg', 's33_run_gnu_arc700']]:
            r.input_hashes[str(p)] = sha(p)
        blocks, payloads, directory = verified_payloads(ROOT)
        base = blocks[0]['load_address_candidate']; data_base = blocks[1]['load_address_candidate']
        body, data = payloads[0], payloads[1]; decoded = {}

        def decode(pc):
            if pc not in decoded:
                text = aligned_window(body, base, pc, pc+12)
                line = next(x for x in text.splitlines() if re.match(r'\s*'+f'{pc:x}:', x))
                m = re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)', line)
                raw = b''.join(bytes.fromhex(w)[::-1] for w in m[1].split())
                assert raw == body[pc-base:pc-base+len(raw)]
                decoded[pc] = dict(opcode=m[2], operands=m[3].strip(), size=len(raw), bytes_hex=raw.hex())
            return decoded[pc]

        def word(address):
            blob, start = (body, base) if base <= address < base+len(body) else (data, data_base)
            assert start <= address and address+4 <= start+len(blob)
            return struct.unpack_from('<I', blob, address-start)[0]

        witnesses = {s[0]: [] for s in SPECS}; candidates = []
        for b in blocks:
            blob = payloads[b['index']]; r.input_hashes[str(directory/b['file'])] = sha(directory/b['file'])
            for off in range(0, len(blob)-7, 2):
                call = call_at(blob, off, b['load_address_candidate'])
                if not call or call['target'] not in witnesses:
                    continue
                assert b['index'] == 0
                op = decode(call['pc']); assert op['opcode'] in ['bl', 'bl.d']
                assert int(re.search(r';(?:0x)?([0-9a-f]+)', op['operands'])[1], 16) == call['target']
                candidates.append(dict(payload=0, **call))
                delay = decode(call['pc']+call['size']) if op['opcode'] == 'bl.d' else None
                starts = ([call['pc']+call['size']] if delay else []) + [call['pc']-dist for dist in [2, 4, 6, 8]]
                for start in starts:
                    setup = decode(start); m = re.fullmatch(r'r0,(0x[0-9a-f]+|[0-9]+)', setup['operands'])
                    if setup['opcode'] != 'mov_s' or not m:
                        continue
                    path = [start]; pc = start+setup['size']; valid = True
                    if start < call['pc']:
                        while pc < call['pc']:
                            ins = decode(pc)
                            if ins['opcode'] not in ['mov_s', 'extw_s', 'ld_s'] or ins['operands'].split(',')[0] == 'r0':
                                valid = False; break
                            path.append(pc); pc += ins['size']
                        valid &= pc == call['pc']
                        if delay:
                            valid &= delay['opcode'] in ['mov_s', 'extw_s', 'ld_s'] and delay['operands'].split(',')[0] != 'r0'
                    if valid:
                        witnesses[call['target']].append(dict(call_pc=hex(call['pc']), setup_pc=hex(start),
                            index=int(m[1], 0), setup_path=list(map(hex, path)), delay_slot=hex(call['pc']+call['size']) if delay else None))
                        break
        indices = {entry: sorted({w['index'] for w in rows}) for entry, rows in witnesses.items()}
        assert all(indices[s[0]] for s in SPECS if s[0] not in [0x2ee924, 0x2ee974])
        assert indices[0x2ee924] == indices[0x2ee974] == []
        census = dict(qualified_BL_candidates=candidates, local_constant_index_witnesses={hex(k): v for k, v in witnesses.items()},
            tested_indices={hex(k): v if v else [0] for k, v in indices.items()},
            unproven_index_sample_wrappers=['0x2ee924', '0x2ee974'],
            all_caller_argument_domains_closed=False, global_reachability_proven=False,
            independently_decoded_local_instructions={hex(k): v for k, v in decoded.items()})
        (r.out/'caller_index_witnesses.json').write_text(json.dumps(census, indent=2)+'\n')
        print('Witnessed indices:', {hex(k): v for k, v in indices.items()}, flush=True)
        mappings = []
        firmware = (ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()
        for i in [0, 1]:
            blob = payloads[i]; q = r.out/f'payload{i}_mmap.bin'; q.write_bytes(blob)
            offset = firmware.find(blob); assert offset >= 0 and firmware.find(blob, offset+1) < 0
            mappings.append(dict(index=i, base=blocks[i]['load_address_candidate'], size=len(blob), path=str(q),
                                 sha256=sha(q), firmware_offset=offset))
        (r.out/'linear_navigation_only.txt').write_text(aligned_window(body, base, 0x2ee760, 0x2eea08))
        sentinels = {i: i*0x01100110 for i in range(13, 20)}; pairs = []; admissions = set(); sampled = set()
        for pattern, (seed, value) in enumerate([(0, 0), (0xffff, 0xffffffff), (0xa55a, 0x12345678)]):
            for channel in [0, 1, 2, 0xffffffff]:
                scenario = f'indexed_{pattern}_{channel:x}'; bank = int(channel != 0)
                calls = []; events = []; loads = []; state = {}; asm = 'mov r20,sp\n'+''.join(f'mov r{i},{v:#x}\n' for i, v in sentinels.items())

                def initial(address):
                    if address not in state: state[address] = (seed ^ (address >> 2)) & 65535
                    return state[address]

                for entry, pool, helper_a, helper_b, kind in SPECS:
                    for index in indices[entry] or [0]:
                        witnessed = bool(indices[entry]); helper = [helper_a, helper_b][bank]
                        pool_offset = bank*(4 if kind in ['split', 'selector'] else 8)
                        pointer = word(pool+pool_offset); item = pointer+4*index; a = word(item)
                        mask = None if kind in ['split', 'selector'] else word(word(pool+pool_offset+4)+4*index)
                        modes = [0, 1, 2, 3, 4, 0xffffffff] if kind == 'selector' else [None]
                        for mode in modes:
                            ev = []; ret = None; call_loads = [(item, a)]
                            if kind == 'selector':
                                delta = helper-0x309a2c; aa = [0xfe9013c, 0xfe9813c][bank]; bb = aa+4; low = [1023, 2047][bank]
                                if mode == 0: ev = [(0x309a58+delta, 'read', aa, initial(aa)), (0x309a66+delta, 'write', aa, (initial(aa)&~low)|(a&low))]; ret = 0
                                elif mode == 1:
                                    ev = [(0x309aa4+delta, 'read', aa, initial(aa))]; extra = word(word(0x2eea84)+4*index)
                                    call_loads.append((word(0x2eea84)+4*index, extra)); ret = initial(aa)&extra
                                elif mode == 2: ev = [(0x309a78+delta, 'read', bb, initial(bb)), (0x309a66+delta, 'write', bb, (initial(bb)&~low)|(a&low))]; ret = 0
                                elif mode == 3: ev = [(0x309a90+delta, 'read', bb, initial(bb)), (0x309a66+delta, 'write', bb, initial(bb)&(~a&65535))]; ret = 0
                                else: ret = 0x55aa
                            elif kind == 'split': ev = [(helper+12, 'write', a, value&65535), (helper+20, 'write', a+4, value>>16)]
                            else:
                                assert mask and mask < 65536; shift = (mask&-mask).bit_length()-1
                                call_loads.append((word(pool+pool_offset+4)+4*index, mask)); old = initial(a)
                                if kind == 'flag':
                                    rd, wr = (16, 24) if value == 0 else (36, 44)
                                    new = old&~(1<<shift) if value == 0 else old|(1<<shift)
                                else: rd, wr = 12, 34; new = ((old&~mask)|((value<<shift)&mask))&65535
                                ev = [(helper+rd, 'read', a, old), (helper+wr, 'write', a, new)]
                            for _, op, address, v in ev:
                                initial(address)
                                if op == 'write': state[address] = v
                            (admissions if witnessed else sampled).update(address for _, _, address, _ in ev)
                            args = [index, mode if kind == 'selector' else value, channel]
                            asm += ''.join(f'mov r{i},{v:#x}\n' for i, v in enumerate(args))+f'mov r12,{entry:#x}\njl [r12]\n'
                            if ret is not None: asm += f'cmp r0,{ret:#x}\nbne fail\n'
                            asm += 'cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{v:#x}\nbne fail\n' for i, v in sentinels.items())
                            calls.append(dict(entry=hex(entry), helper=hex(helper), kind=kind, arguments=list(map(hex, args)),
                                original_index_witness=witnessed, expected_return=ret, table_words=[dict(address=hex(k), value=hex(v)) for k, v in call_loads],
                                events=[dict(pc=pc, operation=op, address=address, value=v) for pc, op, address, v in ev]))
                            events.extend(ev); loads.extend(call_loads)
                asm += 'mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n'
                elf = compile_probe(r, scenario, asm); traces = []
                for enabled in [False, True]:
                    name = scenario+('_observed' if enabled else '_reference'); r.observe = enabled; options = []; fixtures = {}
                    for m in mappings: options += ['--memory-mapfile', '/result/'+Path(m['path']).name, '--memory-region', f"{m['base']:#x},{m['size']:#x}"]
                    for address in sorted(state):
                        before = bytearray(b'\xa5'*8); struct.pack_into('<H', before, address%8, (seed^(address>>2))&65535)
                        q = r.out/f'{name}_{address:x}.bin'; q.write_bytes(before); fixtures[hex(address)] = dict(file=q.name, before=before.hex())
                        options += ['--memory-mapfile', '/result/'+q.name, '--memory-region', f'{address:#x},2']
                    r.range_override = known_sections(elf, False)+''.join(f",{m['base']:#x}:{m['size']:#x}" for m in mappings)
                    case, log = r.run(name, '/result/'+elf.name, options, trace=True, extract=True)
                    assert case['exit_code'] == 0 and case['fault'] is None, log[-5000:]
                    assert not any(x in log for x in ['S33_UNDEFINED', 'S33_AUX_UNKNOWN', 'runtime error:'])
                    observed = [json.loads(line.removeprefix('S33_MEM ')) for line in (r.out/(name+'.stderr.log')).read_text().splitlines() if line.startswith('S33_MEM ')]
                    completed = [e for e in observed if e['stage'] == 'result']
                    assert len(observed) == 2*len(completed) and all(e['width_bytes'] == 2 for e in observed)
                    assert [(e['pc'], e['operation'], e['address'], e['value']) for e in completed] == (events if enabled else [])
                    for key, f in fixtures.items():
                        address = int(key, 0); off = address%8; after = (r.out/f['file']).read_bytes(); before = bytes.fromhex(f['before'])
                        assert struct.unpack_from('<H', after, off)[0] == state[address]
                        assert all(before[j] == after[j] for j in range(8) if j not in [off, off+1])
                        f['after'] = after.hex()
                    assert all(Path(m['path']).read_bytes() == payloads[m['index']] for m in mappings)
                    case.update(scenario=scenario, channel=channel, normalized_bank=bank, pattern=pattern, seed=seed, value=value,
                        observer_enabled=enabled, original_calls=calls, completed_memory_events=completed, fixtures=fixtures,
                        full_original_calls_completed=True, original_table_words_expected=loads)
                    traces.append((r.out/(name+'.trace')).read_bytes()); print(name, 'PASS', len(completed), 'events', flush=True)
                assert traces[0] == traces[1]; pairs.append(dict(scenario=scenario, events=len(events), trace_identical=True))
        r.results.update(status='PASS_FE9_ORIGINAL_INDEXED_CALLERS', pairs=pairs, payloads=mappings, specs=SPECS,
            witness_file='caller_index_witnesses.json', witnessed_index_addresses=list(map(hex, sorted(admissions))),
            unproven_index_sample_addresses=list(map(hex, sorted(sampled))), all_caller_argument_domains_closed=False,
            capture_streams_separate=True, hardware_access=False, gnu_modified=False,
            limits=['Only local constant-index witnesses qualify index selections;global reachability andcompletecaller domains are not established.',
                    'Wrappers2EE924/974 index0is synthetic anddoesnot justify anycatalog admission.',
                    'Original payload1 tables are mapped unchanged;adjacent pointer distances do not establish legal index ranges.',
                    'MMIO seeds/backing,stack,values andchannel arguments are fixtures;physical function/reset/permissions/IRQ/timing unknown.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc)); raise
    finally: r.save()
    print(r.out/'verified_evidence.json', flush=True)


if __name__ == '__main__': main()
