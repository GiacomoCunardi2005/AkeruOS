#!/usr/bin/env python3
"""Audit bounded traces from failed scanner/manager experiments; no CPU run."""
from pathlib import Path
import json

from s33_run_gnu_arc700 import ROOT, elf_loads
from s33_trace_state_dispatch import verified_payloads


def inspect(elf, trace, address, required):
    _, segments = elf_loads(elf)
    covered = [s for s in segments if s['address'] <= address < s['address'] + s['size']]
    if covered:
        offset = address - covered[0]['address']
        assert covered[0]['data'][offset:offset+4] == bytes(4)
    prefix = []
    with trace.open() as source:
        for line in source:
            if line.startswith(f'{address:#x} '):
                assert 'b 0x' in line and f'pc <- {address:#x}' in line
                break
            prefix.append(line)
        else:
            raise AssertionError(f'loop not seen: {address:#x}')
    for fragment in required:
        assert any(fragment in line for line in prefix), fragment
    return {'loop': hex(address), 'elf': str(elf.relative_to(ROOT)),
            'trace': str(trace.relative_to(ROOT)),
            'elf_mapping': 'zero-filled' if covered else 'unmapped',
            'prefix_lines': len(prefix), 'required_trace_fragments': required}


def main():
    base = ROOT / 'Risultati/GUI_S33'
    runs = [
        ('key_scanner_manager700_cpu_20261104T105837794514Z/explore_unblocked.elf',
         'manager700_timeout_trace_20261104/trace.txt', 0x7D252C,
         ['0x145092  ld_s r0,[r1,0x0]     - cr16 <- 0x989fcc',
          '0x169e12  mov_s r1,r13         - cr16 <- 0x4403']),
        ('key_scanner_lifecycle700_cpu_20261104T110049403082Z/iso_stub_explore.elf',
         'manager700_iso_stub_trace_20261104/trace.txt', 0x16A05C,
         ['0x145092  ld_s r0,[r1,0x0]     - cr16 <- 0x7833cc',
          '0x169e12  mov_s r1,r13         - cr16 <- 0x4401']),
        ('key_scanner_lifecycle700_cpu_20261104T110159720669Z/lifecycle_fixtures_explore.elf',
         'manager700_lifecycle_trace_20261104/trace.txt', 0x16A1FC,
         ['0x169e12  mov_s r1,r13         - cr16 <- 0x4406'])]
    blocks, payloads, _ = verified_payloads(ROOT)
    rows = []
    for elf, trace, address, required in runs:
        row = inspect(base / elf, base / trace, address, required)
        source = next(b for b in blocks if 0 <= address - b['load_address_candidate']
                      and address - b['load_address_candidate'] + 4 <= len(payloads[b['index']]))
        offset = address - source['load_address_candidate']
        raw = payloads[source['index']][offset:offset+4]
        assert raw != bytes(4)
        row['original_payload_bytes'] = raw.hex()
        rows.append(row)
    out = base / 'manager700_timeout_audit_20261104.json'
    out.write_text(json.dumps({'status': 'PASS', 'cases': rows,
                               'limits': 'bounded traces, offline ELF analysis, no hardware'}, indent=2) + '\n')
    print('PASS', len(rows), out)


if __name__ == '__main__':
    main()
