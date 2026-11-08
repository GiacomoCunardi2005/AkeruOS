#!/usr/bin/env python3
"""Audit saved AutoScene Ghidra blocks against V1.1 bytes and GNU decoding."""
from pathlib import Path
from collections import defaultdict
import hashlib
import json
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import raw, u32

out = ROOT / 'Risultati/GUI_S33/autoscene_handler_20261031'
payload = ROOT / 'S33-sections/TBM_blocks/block_02_type0_load_005fe800.bin'
elf = out / 'block2_exec.elf'
roundtrip = out / 'block2_roundtrip.bin'
assert payload.read_bytes() == roundtrip.read_bytes()
rel = json.loads((out / 'entry_block2.elf.json').read_text())
exe = json.loads((out / 'entry_block2_exec.elf.json').read_text())
assert rel['image_base'] == 'ram:00010000' and rel['bytes'] == raw(0x64959c, 8).hex()
assert exe['bytes'] == raw(0x65959c, 8).hex() and rel['bytes'] != exe['bytes']
assert u32(0x65993c) == 0xcad30
flow = json.loads((out / 'flow.json').read_text())
blocks = {b['start']: b for b in flow['blocks']}
owner = {i['address']: b['start'] for b in flow['blocks'] for i in b['instructions']}
instructions = sorted({int(i['address'].split(':')[1], 16): i for b in flow['blocks'] for i in b['instructions']}.items())
for address, ins in instructions:
    assert raw(address, ins['length']).hex() == ins['bytes']
groups = []
for address, ins in instructions:
    if not groups or address != groups[-1][-1][0] + groups[-1][-1][1]['length']:
        groups.append([])
    groups[-1].append((address, ins))
objdump = ROOT / 'work/build-arc/binutils/objdump'
gnu = {}
for group in groups:
    text = subprocess.check_output([str(objdump), '-d', '-m', 'arc:ARC700', '-EL',
        f'--start-address={group[0][0]:#x}',
        f'--stop-address={group[-1][0]+group[-1][1]["length"]:#x}', str(elf)], text=True, stderr=subprocess.STDOUT)
    for line in text.splitlines():
        fields = line.split('\t')
        if len(fields) < 3 or not re.fullmatch(r'\s*[0-9a-f]+:', fields[0]):
            continue
        words = fields[1].split()
        if words and all(re.fullmatch(r'[0-9a-f]{4}', w) for w in words):
            gnu[int(fields[0].strip()[:-1], 16)] = (sum(len(w)//2 for w in words), fields[2].strip().lower())
diff = [{'address': hex(a), 'ghidra': ins['mnemonic'], 'gnu': gnu.get(a)} for a, ins in instructions
        if gnu.get(a) != (ins['length'], ins['mnemonic'].lstrip('_').lower())]
edges, reverse, unknown = defaultdict(set), defaultdict(set), []
for b in flow['blocks']:
    for edge in b['edges']:
        if 'CALL' in edge['flow']:
            continue
        target = owner.get(edge['destination'], edge['destination'])
        if target in blocks:
            edges[b['start']].add(target)
            reverse[target].add(b['start'])
        else:
            unknown.append({'from': b['start'], **edge})

def reachable(start, graph):
    seen, todo = set(), [start]
    while todo:
        item = todo.pop()
        if item not in seen:
            seen.add(item)
            todo.extend(graph[item] - seen)
    return seen

entry, load, target, overwrite = (owner[f'ram:{x:08x}'] for x in (0x65959c, 0x659696, 0x659c08, 0x65999c))
assert target in reachable(entry, edges) and target in reachable(load, edges)
on_paths = reachable(load, edges) & reachable(target, reverse)
assert overwrite not in on_paths
writes = [i for b in flow['blocks'] if b['start'] in on_paths for i in b['instructions']
          if 'r14' in i['outputs']]
assert [i['address'] for i in writes] == ['ram:00659696']
evidence = {'status': 'PASS_BYTES_CFG' if not diff else 'DECODE_DIFFERENCES',
    'instruction_count': len(instructions), 'blocks': len(blocks), 'gnu_differences': diff,
    'path_block_count': len(on_paths), 'r14_explicit_writes_on_paths': writes,
    'r14_overwrite_65999c_reaches_target': target in reachable(overwrite, edges),
    'unresolved_noncall_edges': unknown,
    'sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (payload, elf, out/'flow.json', out/'autoscene.c')},
    'limits': ['Ghidra inferred CFG and paths can omit indirect control flow; GNU comparison checks mnemonic/length only.',
               'Callee effects, flags, live runtime reachability, hardware and physical buttons are not established.']}
(out / 'flow_audit.json').write_text(json.dumps(evidence, indent=2) + '\n')
print(f"{evidence['status']}: {len(instructions)} instructions, {len(diff)} GNU differences, {len(on_paths)} path blocks")
sys.exit(0 if not diff else 1)
