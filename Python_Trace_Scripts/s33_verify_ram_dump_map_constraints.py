#!/usr/bin/env python3
"""Reconcile original CPU map constraints, without guessing a physical bank.

Read-only analysis of supplied Nikon images. No emulator or camera access.
The output is deliberately NOT a full-map manifest accepted by the dumper.
"""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import raw, disasm, ORIGINAL, EXPECTED


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    assert sha(ORIGINAL) == EXPECTED
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = ROOT / 'Risultati/Runtime_Kernel/RAM_Map_Constraints' / stamp
    out.mkdir(parents=True)
    boot = ROOT / 'DUMPS/BootNANDBase.dmp'
    assert sha(boot) == '44c849a4ab69d9e9e010602887293eda1fb19dfcfa22d1f7f4bcfba7a166bd65'
    # Cross-check first region directly in Nikon payload, not only old reports.
    table = raw(0x3766F4, 112 * 24)
    assert hashlib.sha256(table).hexdigest() == 'e86ae222280be8621ba8033688618a8694182e4ae08b69985743fb8eb14d8993'
    first = struct.unpack_from('<6I', table)
    assert first == (0x6B, 0xE9, 0, 0, 0x900000, 4), first
    top = 0x10000000
    reservation_start = (top - first[4]) & ~(first[5] - 1)
    assert reservation_start == 0x0F700000
    # Pin original arithmetic: hardcoded software top, not measured RAM size.
    assert raw(0xC768C, 6).hex() == '00d89cb8e07e'
    windows = [(0xC768C, 0xC7692), (0x2696F4, 0x269710),
               (0x269730, 0x269752), (0x26E610, 0x26E654)]
    listing = '\n'.join(disasm(a, b) for a, b in windows)
    (out / 'gnu_verified.txt').write_text(listing)
    bases = struct.unpack('<4I', raw(0x269828, 16))
    assert bases == (0x0F794000, 0x0F798000, 0x0F7A0000, 0x0F7B0000)
    # Exact bytes of three size-return branches, including delay-slot shifts.
    for pc, expected in [(0x269734, '07d8e07f0bb8'),
                         (0x26973E, 'e3d8e07f07b8'),
                         (0x269748, 'd2d8e07f08b8')]:
        assert raw(pc, 6).hex() == expected
    sizes = [7 << 11, 0xE3 << 7, 0xD2 << 8]
    software_windows = [dict(selector=i, base=hex(b), bytes=n,
                             end_exclusive=hex(b+n), physical_kind='unknown')
                        for i, (b, n) in enumerate(zip(bases, sizes))]
    assert bases[1] + sizes[1] == 0x0F79F180
    assert all(reservation_start <= w < top for w in bases)
    page = (ROOT / 'DUMPS/NANDP1.dmp').read_bytes()[0x2100:0x2300]
    ddr_id = struct.unpack_from('<I', page, 0xC4)[0]
    assert ddr_id == 0x120 and (ddr_id & 255) << 23 == top
    evidence = dict(
        status='PASS_STATIC_RAM_MAP_CONSTRAINTS_NOT_FULL_PHYSICAL_MAP', utc=stamp,
        physical_map_complete=False, executable_dumper_manifest=False,
        original_sha256=EXPECTED, boot_sha256=sha(boot),
        table_sha256=hashlib.sha256(table).hexdigest(),
        first_record=dict(id=hex(first[0]), parent=hex(first[1]), bytes=first[4],
                          alignment=first[5], software_base=hex(reservation_start)),
        configured_ddr_id=hex(ddr_id), software_top=hex(top),
        software_windows=software_windows,
        fourth_base_with_zero_default_size=hex(bases[3]),
        important_intersections=[
            dict(kind='known software workspace', start='0x0f79b180', end='0x0f79f180'),
            dict(kind='candidate BootNAND code', start='0x0f800000', end='0x0f802000'),
            dict(kind='MMIO area excluded by existing dumper', start='0x0fe00000', end='0x10000000')],
        conclusions=[
            'First application reservation starts exactly at final sparse BootNAND probe.',
            'Reserved region [0x0f700000,0x10000000) mixes software windows and MMIO.',
            'Neither application reservation nor configured DDR top proves physical RAM.',
            'Normal pointer reads see current CPU/cache view; physical DDR identity and alias map remain unproved.',
            'No range has been promoted to a complete physical bank or free allocation.'])
    (out / 'verified_evidence.json').write_text(json.dumps(evidence, indent=2)+'\n')
    (out / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(status=evidence['status'], evidence=str(out.relative_to(ROOT) / 'verified_evidence.json'))))


if __name__ == '__main__':
    main()
