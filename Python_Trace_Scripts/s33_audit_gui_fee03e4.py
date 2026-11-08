#!/usr/bin/env python3
"""Audit the controlled FEE03E4 continuation; GUI completion is not implied."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1] / 'Risultati/GUI_S33'
for seed, middle in ((0x2525, 0x2525), (0xe525, 0xa525)):
    run = root / f'exposure_return_fee03e4_combined_{seed:04x}_20261028T144423Z'
    manifest = json.loads((run / 'verified_evidence.json').read_text())
    for name in ('cases.trace', 'seed.json', 'fee03c0_03e4.bin', 'verifier_snapshot.py'):
        assert hashlib.sha256((run / name).read_bytes()).hexdigest() == manifest['files'][name]
    assert json.loads((run / 'seed.json').read_text())['fee03e4_initial'] == seed
    assert manifest['status'] == 'FAIL'
    assert manifest['cases'][0]['fault'] == {
        'size': 2, 'operation': 'read', 'address': '0xfee0638', 'pc': '0x20d2b0'}
    trace = (run / 'cases.trace').read_text().splitlines()
    def at(pc):
        return [line for line in trace if line.startswith(f'{pc:#x} ')]
    for pc, value in ((0x20a7a4, seed), (0x20a7a8, middle),
                      (0x20a7b2, middle), (0x20a7b6, 0x2525)):
        assert len(at(pc)) == 1 and f'cr <- {value:#x}' in at(pc)[0]
    assert len(at(0x20a7ac)) == len(at(0x20a7ba)) == 1
    assert (run / 'fee03c0_03e4.bin').read_bytes()[36:38] == b'\x25\x25'
print('PASS: controlled FEE03E4 reads, writes and hashes; GUI runs remain FAIL')
