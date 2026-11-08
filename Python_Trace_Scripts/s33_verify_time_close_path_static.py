#!/usr/bin/env python3
"""Cross-check the V1.1 AutoSceneLiveView close-to-request path."""
from datetime import datetime, timezone
from pathlib import Path
import json, sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'S33-sections/analysis_codex'))
from static_common import ROOT, disasm, locate, raw, u32


def main():
    spans = [(0x783b10, 8), (0x659b24, 0x24), (0x14a1fc, 0x24)]
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    for addr, length in spans:
        block, offset = locate(addr, length)
        assert raw(addr, length) == dump[block['offset'] + offset:block['offset'] + offset + length]
    assert (u32(0x783b10), u32(0x783b14)) == (0x4405, 0x65959c)
    handler = disasm(0x659b24, 0x659b48)
    wrapper = disasm(0x14a1fc, 0x14a220)
    assert ';0x14504c' in handler and 'cmp_s\tr0,0x55' in handler and ';0x659b74' in handler
    assert ';0x14a1fc' in handler and ';0x14a968' in wrapper
    old = ROOT / 'Risultati/GUI_S33/aslv_close_handler_cpu_20261101T182145395518Z/verified_evidence.json'
    data = json.loads(old.read_text())
    case = next(c for c in data['cpu_cases'] if c['name'] == 'close_ptr')
    assert data['status'] == 'PASS_ASLV_CLOSE_HANDLER_4405' and case['success'] == '0xdeadb00d'
    assert data['stub_map']['0x14a1fc'] == 64
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('time_close_path_static_%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    (out / 'handler.txt').write_text(handler)
    (out / 'wrapper.txt').write_text(wrapper)
    (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
    (out / 'evidence.json').write_text(json.dumps({'event': '0x4405', 'handler': '0x65959c', 'call_site': '0x659b40', 'target': '0x14a1fc', 'previous_cpu_evidence': str(old), 'previous_case': case, 'limits': ['Static caller and prior CPU case are separate; prior target was stubbed. Other callers and physical shutter behavior remain unresolved.']}, indent=2) + '\n')
    print('PASS:', out)


if __name__ == '__main__':
    main()
