#!/usr/bin/env python3
"""Offline register evidence census; linear decoding is NOT a code-validity proof.

Preserves payload identity, overlapping overlay namespaces and undecidable AUX
operands. Never accesses hardware, rewrites firmware or changes the GNU tools.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct

from s33_trace_state_dispatch import verified_payloads, objdump_text

ROOT = Path(__file__).resolve().parents[1]
INSN = re.compile(r'^\s*([0-9a-fA-F]+):\s+[^\t]+\t([^\s]+)\s*(.*)$')
DEF = re.compile(r'^DEF\s*\(\s*(0x[0-9a-f]+|\d+),\s*(ARC_OPCODE_\w+),\s*\w+,\s*(\w+)\)')
NUM = re.compile(r'^(?:0x[0-9a-fA-F]+|\d+)$')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def aux_names():
    """ARCv1 names only; ARCALL may include optional/custom implementations."""
    path = ROOT / 'work/binutils-2.45/opcodes/arc-regs.h'
    names = {}
    rows = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        match = DEF.match(line)
        if not match or match[2] not in {'ARC_OPCODE_ARCALL', 'ARC_OPCODE_ARCV1', 'ARC_OPCODE_ARC700'}:
            continue
        value = int(match[1], 0)
        names[match[3]] = value
        rows.append(dict(index=value, index_hex=hex(value), name=match[3],
                         applicability=match[2], source=str(path.relative_to(ROOT)), line=number,
                         evidence='toolchain_definition_not_nikon_presence'))
    return names, rows, path


def scan_listing(text, namespace, names):
    accesses, references = [], []
    decoded = 0
    for line in text.splitlines():
        match = INSN.match(line)
        if not match:
            continue
        decoded += 1
        pc, mnemonic, operands = int(match[1], 16), match[2], match[3]
        base = mnemonic.split('.')[0]
        if base in {'lr', 'sr'}:
            operand_match = re.search(r'\[([^\]]+)\]', operands)
            operand = operand_match[1].strip() if operand_match else None
            index = int(operand, 0) if operand and NUM.fullmatch(operand) else names.get(operand)
            accesses.append(dict(namespace=namespace, pc=hex(pc), mnemonic=mnemonic,
                                 operation='read' if base == 'lr' else 'write',
                                 operand=operand, index=index,
                                 index_hex=hex(index) if index is not None else None,
                                 classification='linear_decode_candidate', listing=line.strip()))
        # Explicit instruction constants are candidates, not proven MMIO accesses.
        if base.startswith(('mov', 'ld', 'st', 'add', 'sub', 'or', 'and')):
            body = operands.split(';', 1)[0]
            values = sorted({int(v, 16) for v in re.findall(r'0x([0-9a-fA-F]+)', body)
                             if 0x0F000000 <= int(v, 16) < 0x10000000})
            for value in values:
                references.append(dict(namespace=namespace, pc=hex(pc), constant=hex(value),
                                       mnemonic=mnemonic, listing=line.strip(),
                                       classification='instruction_constant_candidate_not_mmio_proof'))
    return accesses, references, decoded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = args.output or ROOT / 'Risultati/Processor_Registers' / stamp
    out.mkdir(parents=True, exist_ok=False)
    blocks, payloads, block_dir = verified_payloads(ROOT)
    names, definitions, definitions_path = aux_names()
    inputs = {str(definitions_path): digest(definitions_path)}
    for path in [ROOT/'work/build-arc/binutils/objdump', ROOT/'work/build-arc/binutils/objcopy',
                 block_dir/'manifest.json', Path(__file__)]:
        inputs[str(path)] = digest(path)
    all_accesses, all_references, census, summaries = [], [], {}, []
    scan_sources = [(b, payloads[b['index']], block_dir, f"block_{b['index']:02d}") for b in blocks]
    # Separate TBIB payload in original container, not confused with overlays.
    fw = ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin'
    raw = fw.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39'
    base, size, checksum, entry = struct.unpack_from('<4I', raw, 0x6c)
    tbib = raw[0x7c:0x7c+size]
    assert len(tbib) == size and sum(x[0] for x in struct.iter_unpack('<I', tbib)) & 0xffffffff == checksum
    tbib_path = out/'tbib_original.bin';tbib_path.write_bytes(tbib)
    scan_sources.append((dict(index='tbib', file=tbib_path.name, load_address_candidate=base,
                              size=size), tbib, out, 'tbib'))
    inputs[str(fw)] = digest(fw)
    for block, payload, directory, namespace in scan_sources:
        path = directory/block['file']; inputs[str(path)] = digest(path)
        disassembly_error = None
        try:
            listing = objdump_text(ROOT, directory, block, payload)
        except ValueError as exc:
            if 'Objdump reported OOB' not in str(exc):
                raise
            # Preserve a failed decoding boundary rather than padding firmware,
            # silently trimming its tail, or publishing a rejected listing.
            listing = ''
            disassembly_error = str(exc)
        accesses, references, decoded = scan_listing(listing, namespace, names)
        all_accesses.extend(accesses);all_references.extend(references)
        # All aligned words in this numeric range: candidates include data and
        # instruction encodings. Never label them registers or dereferences.
        constants = defaultdict(list)
        for offset in range(0, len(payload)-3, 4):
            value = struct.unpack_from('<I', payload, offset)[0]
            if 0x0F000000 <= value < 0x10000000:
                constants[hex(value)].append(hex(block['load_address_candidate']+offset))
        census[namespace] = dict(classification='aligned_word_value_census_not_mmio_proof',
                                 words=dict(constants))
        (out/(namespace+'_register_candidates.txt')).write_text('\n'.join(
            row['listing'] for row in accesses+references)+'\n')
        summary = dict(namespace=namespace, base=hex(block['load_address_candidate']),
                       size=len(payload), sha256=hashlib.sha256(payload).hexdigest(),
                       linear_decoded_lines=decoded, aux_candidates=len(accesses),
                       disassembly_error=disassembly_error,
                       explicit_address_constants=len(references),
                       aligned_word_candidates=sum(map(len, constants.values())))
        summaries.append(summary);print(json.dumps(summary), flush=True)
    aux_groups = defaultdict(list)
    for row in all_accesses:
        aux_groups[row['index_hex'] or 'unresolved:'+str(row['operand'])].append(row)
    report = dict(schema_version=1, generated_utc=stamp,
                  status='CENSUS_WITH_DISASSEMBLY_GAPS' if any(s['disassembly_error'] for s in summaries)
                  else 'CANDIDATE_CENSUS_COMPLETE',
                  physical_register_map_complete=False, hardware_access=False,
                  scope='16 hash-verified V1.1 TBM payloads plus original TBIB',
                  input_sha256=inputs, payloads=summaries, aux_definitions=definitions,
                  aux_candidate_groups=dict(aux_groups), instruction_constants=all_references,
                  limits=['Linear decode can turn pools/data into plausible instructions.',
                          'All AUX instruction candidates require CFG or executed-trace confirmation.',
                          'Overlays at the same address retain distinct block namespaces.',
                          'Numeric word or instruction constants do not prove MMIO or a physical register.',
                          'Dynamic AUX indices remain unresolved; absent accesses do not prove absent registers.',
                          'Optional CPU units, reset values, widths and reserved bits require separate evidence.'])
    (out/'inventory.json').write_text(json.dumps(report, indent=2)+'\n')
    (out/'address_word_census.json').write_text(json.dumps(census, indent=2)+'\n')
    for name, expected in inputs.items():
        assert digest(Path(name)) == expected, 'Input changed: '+name
    print('Evidence:',out/'inventory.json',flush=True)


if __name__ == '__main__':
    main()
