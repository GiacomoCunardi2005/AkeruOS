#!/usr/bin/env python3
"""Check the two incomplete GUI runs and their FEE04B0 operations."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1] / 'Risultati/GUI_S33'
for seed in (0xa5a0, 0xa5a4):
    run = root / f'exposure_return_fee04b0_{seed:04x}_20261028T144248Z'
    manifest = json.loads((run / 'verified_evidence.json').read_text())
    for name in ('cases.trace', 'seed.json', 'fee04b0.bin', 'verifier_snapshot.py'):
        assert hashlib.sha256((run / name).read_bytes()).hexdigest() == manifest['files'][name]
    assert json.loads((run / 'seed.json').read_text()) == {
        'feb0000_initial': 0xa5a0, 'fee03c0_initial': 0xa5a1, 'fee04b0_initial': seed}
    assert manifest['status'] == 'FAIL'
    assert manifest['cases'][0]['fault'] == {
        'size': 2, 'operation': 'read', 'address': '0xfee03e4', 'pc': '0x20a7a4'}
    trace = (run / 'cases.trace').read_text().splitlines()
    def at(pc):
        return [line for line in trace if line.startswith(f'{pc:#x} ')]
    assert len(at(0x20a78c)) == 1 and f'cr <- {seed:#x}' in at(0x20a78c)[0]
    assert len(at(0x20a790)) == 1 and 'cr <- 0xa5a0' in at(0x20a790)[0]
    assert len(at(0x20a794)) == 1 and 'memory <- 0xffffa5a0' in at(0x20a794)[0]
    assert (run / 'fee04b0.bin').read_bytes()[:2] == b'\xa0\xa5'
    assert len(at(0x20a7a4)) == 1
print('PASS: controlled FEE04B0 traces; GUI runs remain FAIL')
