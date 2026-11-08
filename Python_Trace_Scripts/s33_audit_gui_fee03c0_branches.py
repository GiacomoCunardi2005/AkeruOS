#!/usr/bin/env python3
"""Audit the two bounded GUI return traces, including their recorded hashes."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1] / 'Risultati/GUI_S33'
for seed in (0xa5a0, 0xa5a1):
    run = root / f'exposure_return_fee03c0_{seed:04x}_20261028T144136Z'
    manifest = json.loads((run / 'verified_evidence.json').read_text())
    for name in ('cases.trace', 'seed.json', 'fee03c0.bin', 'verifier_snapshot.py'):
        assert hashlib.sha256((run / name).read_bytes()).hexdigest() == manifest['files'][name]
    assert json.loads((run / 'seed.json').read_text()) == {
        'feb0000_initial': 0xa5a0, 'fee03c0_initial': seed}
    assert manifest['status'] == 'FAIL'
    assert manifest['cases'][0]['fault'] == {
        'size': 2, 'operation': 'read', 'address': '0xfee04b0', 'pc': '0x20a78c'}
    lines = (run / 'cases.trace').read_text().splitlines()
    def at(pc):
        return [line for line in lines if line.startswith(f'{pc:#x} ')]
    assert len(at(0x20a2dc)) == 1 and f'cr <- {seed:#x}' in at(0x20a2dc)[0]
    assert len(at(0x20a2fc)) == (1 if seed == 0xa5a0 else 0)
    assert len(at(0x20a2e8)) == (0 if seed == 0xa5a0 else 1)
    if seed == 0xa5a1:
        assert '0x1e03710' in at(0x20a2e8)[0]
    assert (run / 'fee03c0.bin').read_bytes()[:2] == b'\xa1\xa5'
    assert len(at(0x20a78c)) == 1
print('PASS: both synthetic branch traces and manifest hashes; GUI runs remain FAIL')
