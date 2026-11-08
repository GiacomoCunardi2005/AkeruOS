#!/usr/bin/env python3
"""Bounded static checks of the normal format dialog and IQ action; no device I/O."""
from datetime import datetime, timezone
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, ORIGINAL, EXPECTED, raw, u32, cstring, sha, locate, disasm
from catalog_hiddenmenu import parse_lines

WINDOWS = [(0x7cf828, 0x7cf884), (0x1695d0, 0x169638),
           (0x135a84, 0x135a8a), (0x7feda0, 0x7fedce),
           (0x7ff350, 0x7ff39e), (0x8069b4, 0x806a1c)]


def main():
    out = ROOT / 'Risultati/HiddenMenu_Formattazione' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    firmware = ORIGINAL.read_bytes()
    dump_path = ROOT / 'DUMPS/MainCode.dmp'
    dump = dump_path.read_bytes()
    assert sha(firmware) == EXPECTED
    tools = {p: sha(p.read_bytes()) for p in
             (ROOT / 'work/build-arc/binutils' / n for n in ('objcopy', 'objdump'))}
    spans, listings, rows = [], [], {}

    def check_bytes(a, n):
        block, offset = locate(a, n)
        data = raw(a, n)
        assert dump[block['offset'] + offset:block['offset'] + offset + n] == data
        spans.append(dict(address=hex(a), bytes=n, sha256=sha(data)))

    for a, b in WINDOWS:
        check_bytes(a, b-a)
        text = disasm(a, b)
        listings.append(text)
        rows.update({r['address']: r for r in parse_lines(text)})
    checks = [(0x7cf836, 'sub', 'sp,sp,512'),
              (0x7cf844, 'mov_s', 'r1,0xd'), (0x7cf856, 'mov_s', 'r2,fp'),
              (0x7cf858, 'sub', 'r2,r2,512'), (0x7cf85c, 'mov_s', 'r0,0'),
              (0x7cf85e, 'mov_s', 'r1,0x1'), (0x7cf860, 'mov_s', 'r3,r0'),
              (0x7cf862, 'bl', ';0x1695d0'),
              (0x1695fc, 'bl.d', ';0x260fe4'), (0x169600, 'mov', 'r5,0x7'),
              (0x16961e, 'bl_s', ';0x169564'),
              (0x135a86, 'ldb_s', 'r0,[r0,0]'),
              (0x7fedb6, 'bl', ';0x135a84'), (0x7fedbe, 'stb_s', 'r0,[r13,0x8]'),
              (0x7fedc2, 'bl', ';0x137774'), (0x7fedc6, 'stb_s', 'r0,[r13,0x9]'),
              (0x7ff380, 'ldb_s', 'r0,[r1,0x9]'), (0x7ff386, 'ldb_s', 'r0,[r1,0x8]'),
              (0x7ff388, 'btst_s', 'r0,0x3'), (0x7ff38c, 'mov_s', 'r0,0x7b'),
              (0x7ff396, 'bl', ';0x1453e4'),
              (0x806a0e, 'mov_s', 'r0,0x4e'), (0x806a14, 'mov_s', 'r0,0x4e')]
    for a, op, fragment in checks:
        assert rows[a]['op'] == op and fragment in rows[a]['args'], rows[a]
    values = {0x9870a0: 0x500d, 0x9870a4: 0x7cf828,
              0x376168+0x38: 0x1695d0, 0x376018+0x38: 0x1684b4,
              0x135a8c: 0x366aeb, 0x7fefd0: 0x89a480,
              (0x7ff364 & ~3)-116*4: 0x89a480}
    for a, v in values.items():
        check_bytes(a, 4)
        assert u32(a) == v, (hex(a), hex(u32(a)))
    strings = {0x9871ab: 'Switch Require formating', 0x376168+8: 'DEVNAND:',
               0x376018+8: 'DEVSD:'}
    for a, text in strings.items():
        check_bytes(a, len(text)+1)
        assert cstring(a) == text
    assert ORIGINAL.read_bytes() == firmware and dump_path.read_bytes() == dump
    assert all(sha(p.read_bytes()) == h for p, h in tools.items())
    result = dict(status='PASS_BOUNDED_FORMAT_PROMPT_CHECKS', firmware_sha256=EXPECTED,
        main_dump_sha256=sha(dump), payloads_verified=len(BS), windows=len(WINDOWS),
        instruction_checks=len(checks), checked_spans=spans,
        tools_unchanged={str(p.relative_to(ROOT)): h for p,h in tools.items()},
        user_observation={'prompt':'Normal camera format request; refusal permits shutdown',
                          'iq_switch_selected':False, 'exact_text_and_runtime_state':'not supplied'},
        iq_action={'event':'0x500d', 'callback':'0x7cf828',
                   'request':'1695D0(0,1,fp-512,0)',
                   'classification':'Calls initial DEVNAND raw write backend, not a proven RAM-only toggle',
                   'buffer':'512-byte local frame; callback does not initialize contents before call'},
        normal_ui={'context':'0x89a480', 'status_byte':'0x366aeb via135A84',
                   'status_snapshot':'7FEDBE -> context+8;137774(0) -> context+9',
                   'conditional_format_confirmation':'7FF350/2180 can request7B when guards,context+9 and status bit3 pass',
                   'format_action':'7B/2180 ->8069B4 can request Formatting4E'},
        limits=['Static instructions only; no callback executed or physical format operation observed',
                'Normal UI identity on camera still candidate without exact message/photo',
                'No runtime RAM, card filesystem, card health or USB exclusion state checked',
                'No causal link to patch, MSDC or IQ action established',
                'No hardware, SD, firmware or GNU-tree writes'])
    (out/'gnu_verified.txt').write_text('\n'.join(listings))
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    (out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n')
    print(result['status'], len(WINDOWS), 'windows;', len(checks), 'instruction checks;', out)


if __name__ == '__main__':
    main()
