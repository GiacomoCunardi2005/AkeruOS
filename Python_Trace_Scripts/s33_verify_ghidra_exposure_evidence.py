#!/usr/bin/env python3
"""Cross-check the saved Ghidra exposure export against its bounded GNU trace."""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import locate, raw

out = ROOT / 'Risultati/GUI_S33/ghidra_monitor_20261031'
initial = out / 'exposure.c'
revised = out / 'exposure_revised.c'
helper = out / 'helper_original.txt'
trace = ROOT / 'Risultati/GUI_S33/exposure_caller_complete_probe_0_20261030T102137Z/cases.trace'
dump = ROOT / 'DUMPS/MainCode.dmp'
files = (initial, revised, helper, trace, dump)
before, after, state, run = (p.read_text() for p in files[:4])
assert 'no_return=True' in state
assert '/* entry=ram:000d8ca4' in before and 'Subroutine does not return' in before
assert 'ram:000d90d9' in after and 'FUN_ram_000f6f54' in after and 'FUN_ram_000fda28' in after
assert '0x0d8cfe  bl 0x00000000000ad920' in run
assert 'pc <- 0xd8d02' in run and '0x0d8d06  bl 0x00000000000f6f54' in run
data = dump.read_bytes()
windows = ((0xad920, 0x122), (0xd8ca4, 0x436), (0xca654, 0xa6))
for address, size in windows:
    block, offset = locate(address, size)
    assert raw(address, size) == data[block['offset'] + offset:block['offset'] + offset + size]
evidence = {'status': 'PASS_BOUNDED', 'windows': [{'address': hex(a), 'bytes': n} for a, n in windows],
            'sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
            'limits': ['GNU trace uses fixtures and synthetic context; Ghidra revised no-return is an experiment.',
                       'String and byte checks do not validate decompiler semantics or physical behavior.']}
(out / 'exposure_crosscheck.json').write_text(json.dumps(evidence, indent=2) + '\n')
print('PASS: Ghidra baseline, revised output, GNU trace and three dump windows')
