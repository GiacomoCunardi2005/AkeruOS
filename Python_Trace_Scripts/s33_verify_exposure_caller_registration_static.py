#!/usr/bin/env python3
"""Check a V1.1 caller pointer and its conditional registration statically."""
from datetime import datetime, timezone
from pathlib import Path
import json, sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'S33-sections/analysis_codex'))
from static_common import ROOT, disasm, locate, raw, u32


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    windows = {'registration_call': (0x14a0e4, 0x14a0fe), 'registration_helper': (0x14a714, 0x14a758), 'pointer': (0x14a1a0, 0x14a1a4)}
    for start, end in windows.values():
        block, offset = locate(start, end - start)
        assert raw(start, end - start) == dump[block['offset'] + offset:block['offset'] + offset + end - start]
    assert u32(0x14a1a0) == 0xdb138
    call = disasm(*windows['registration_call'])
    helper = disasm(*windows['registration_helper'])
    assert 'ld_s\tr2,[pcl,0xbc]' in call and ';0x14a1a0' in call and ';0x14a714' in call
    for part in ('mov_s\tr22,r2', ';0x1593ac', 'bne_s', 'st\tr22,[r13,16]'):
        assert part in helper, part
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('exposure_caller_registration_static_%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    (out / 'registration_call.txt').write_text(call)
    (out / 'registration_helper.txt').write_text(helper)
    (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
    (out / 'evidence.json').write_text(json.dumps({'pointer_address': '0x14a1a0', 'pointer': '0xdb138', 'registration_call': '0x14a0fa', 'helper': '0x14a714', 'limits': ['Static byte and instruction checks only; no registration, scheduler, physical event or sensor execution observed.']}, indent=2) + '\n')
    print('PASS:', out)


if __name__ == '__main__':
    main()
