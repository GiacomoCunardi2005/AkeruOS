#!/usr/bin/env python3
"""Audit diagnostic selector 0x50 versus WindowMgr object 0x50."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'S33-sections/analysis_codex'))
from static_common import raw, locate, u16, u32, cstring

dump = (root / 'DUMPS/MainCode.dmp').read_bytes()
for address, size in ((0x406cf0, 8), (0x3f5a40, 4), (0x99c924, 28), (0x99c990, 13)):
    block, offset = locate(address, size)
    assert raw(address, size) == dump[block['offset'] + offset:block['offset'] + offset + size]
assert (u32(0x406cf0), u32(0x406cf4)) == (0x50, 0x2c5074)
assert u32(0x3f5900 + 0x50 * 4) == 0x99c924
assert u16(0x99c924 + 4) == 0x50
assert u32(0x99c924 + 20) == 0x99c990
assert cstring(0x99c990) == 'CardUnusable'
run = root / 'Risultati/GUI_S33/iris_selector_namespace_cpu_20261028T144749Z'
manifest = json.loads((run / 'verified_evidence.json').read_text())
for name in ('cases.json', 'cases.trace', 'verifier_snapshot.py'):
    assert hashlib.sha256((run / name).read_bytes()).hexdigest() == manifest['files'][name]
assert manifest['status'] == 'PASS_IRIS_SELECTOR_NAMESPACE_LAB'
rows = json.loads((run / 'cases.json').read_text())
assert rows[2]['event'] == '0x2180' and rows[2]['destination'] == '0x50' and rows[2]['open_calls'] == 1
previous = root / 'Risultati/GUI_S33/iris_diagnostic_dispatch_cpu_20261028T144635Z'
previous_manifest = json.loads((previous / 'verified_evidence.json').read_text())
trace_bytes = (previous / 'cases.trace').read_bytes()
assert hashlib.sha256(trace_bytes).hexdigest() == previous_manifest['files']['cases.trace']
trace = trace_bytes.decode().splitlines()
assert any(x.startswith('0x2032024 ') and 'cr <- 0x0' in x for x in trace)
assert any(x.startswith('0x2c5036 ') and 'cr16 <- 0x1' in x for x in trace)
print('PASS: separate selector namespaces, fixture route and dispatcher return behavior')
