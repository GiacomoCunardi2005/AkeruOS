#!/usr/bin/env python3
"""Static verification of the lens aperture (iris) dialogue in the original V1.1.

The iris is a two-position mechanism (Big/Small) driven through the lens MCU:
this script verifies the iris vocabulary and semantics (AE iris index 0/1,
Big/Small bounds, EFA per-iris calibration, the two checksummed LENS IRIS
calibration tables), the documented BCIP_Aperture command (0x9208, Set/Get,
1:Big 9:Small) of the optical-module protocol, and re-asserts the runtime
transport evidence (MCU port transaction 0x25F338 with its 35 Main callers and
RAM descriptor-table literals).

Read-only: firmware, blocks and tools are never modified.
"""
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads, objdump_text, he
from s33_run_gnu_arc700 import ROOT, sha
from s33_verify_sensor_mmio_dialog import aligned_window, mmio_literal_sites

FIRMWARE = ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin'
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Iris'
CALL_TRX = re.compile(r'\tbl(?:\.d|_s)?\t-?\d+\t;0x25f338')
LD_PCL_R0 = re.compile(r'\tld[a-z._]*\s+r0,\[pcl,(0x[0-9a-f]+)\]\s*;0x([0-9a-f]+)')

# (text, container offset). The BCIP blob indents with a leading space; the
# search accepts the string at offset or one byte after (leading space).
STRINGS = {
    'Iris : %d (0:Big 1:Small)': 0x3B3A64,          # payload2: iris is binary
    ' Set Iris:%d': 0x31BC40,                        # payload1: AE applies iris
    ' Get Iris:%d': 0x31BC4D,
    'ExpTime:%d Iris:%d Zoom:%d AdGain_LV@%d:%d': 0x31B082,
    'ucIrisIndex : %d': 0x34FB7D,
    'Small Iris Upper Bound:%d': 0x3273EE,
    'Big   Iris Upper Bound:%d': 0x327427,
    'EFAIRISBIG = %d': 0x350595,
    'EFAIRISSMALL = %d': 0x3505A5,
    'IRIS 1': 0x730716,                              # calibration menu items
    'IRIS 2': 0x73071D,
    'LENS IRIS 1 DATA': 0x730C10,                    # checksummed lens tables
    'LENS IRIS 2 DATA': 0x730FB0,
    'Iris Switch': 0x53F6CE,                         # tuning menu
    'Big Iris': 0x54042E,
    'Small Iris': 0x540437,
    'Iris status: Big': 0x39CD41,
    'Iris status: Small': 0x39CD52,
    'ImgCap_SetAperture': 0x3B2AA1,                  # debug script commands
    'SetIrisIndex': 0x74D67C,
    'Command Name=BCIP_Aperture': 0x380134,
    'Operation Code=0x9208': 0x380150,
    'SP1=0:Set 1:Get': 0x3801AC,
    'SP2=1:Big 9:Small': 0x3801BD,
    'DP1= Value': 0x3801CF,
    'Aperture[%d],Lens NG in AdjustADGain. 0x%x': 0x327696,
    'Aperture[%d] Adjust ADGain. NG': 0x3276C4,
}
# Transaction callers in Main with their command-descriptor pool literals.
TRX_CALLER_LITERAL = {0x29E2BC: 0x50E140, 0x29E74C: 0x50E340}


def main() -> None:
    out = EVIDENCE / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'script_snapshot.py').write_bytes(Path(__file__).read_bytes())
    firmware = FIRMWARE.read_bytes()
    assert sha(FIRMWARE) == '1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39'
    blocks, payloads, block_dir = verified_payloads(ROOT)
    info = {b['index']: b for b in blocks}
    base0 = info[0]['load_address_candidate']
    p0 = payloads[0]

    # Strings at fixed container offsets (leading-space tolerant).
    found = {}
    for text, offset in STRINGS.items():
        needle = text.encode()
        hi = offset + 0x60 + len(needle)
        at = firmware.find(needle, offset - 0x20, hi)
        at_sp = firmware.find(b' ' + needle, offset - 0x20, hi)
        ok = at == offset or (at_sp is not None and at_sp >= 0 and at_sp + 1 == offset) or at == offset + 1
        assert ok, (text, hex(at), hex(at_sp))
        found[text] = at if at == offset else offset

    # BCIP_Aperture container sizes: operation 20, response 16.
    assert firmware.find(b'Operation Container Size=20', 0x380160, 0x380200) > 0
    assert firmware.find(b'Response Container Size=16', 0x380180, 0x380200) > 0

    # Runtime transport: the transaction function 0x25F338 and its callers.
    listing0 = objdump_text(ROOT, block_dir, info[0], p0)
    callers = []
    for line in listing0.splitlines():
        m = re.match(r'\s*([0-9a-f]+):', line)
        if m and CALL_TRX.search(line):
            callers.append(int(m.group(1), 16))
    assert len(callers) == 35, len(callers)
    # Command descriptor literals: RAM tables (not payload data) parameterize
    # the transaction; verify the two pool words read from the payload.
    for lit_va, expected in TRX_CALLER_LITERAL.items():
        off = lit_va - base0
        assert 0 <= off <= len(p0) - 4
        assert struct.unpack_from('<I', p0, off)[0] == expected, (hex(lit_va),)
    # The port block still belongs to the lens dialogue (see lens session).
    sites = mmio_literal_sites(listing0, base0, p0)
    assert sum(1 for _, v in sites if v == 0x0FF05000) >= 4

    # Aligned window: one iris-relevant stepped-move transaction loop that
    # applies command descriptors and repeats until the target is reached.
    window = aligned_window(p0, base0, 0x29E0A4, 0x29E0DC)
    (out / 'gnu_windows.txt').write_text(
        '=== iris_family_transaction_29E0A4 ===\n' + window + '\n')
    assert re.search(r'\tld_s\tr0,\[pcl,', window)
    assert re.search(r'\tmov_s\tr2,r14\b', window)
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25f338', window)
    assert re.search(r'\tmov_s\tr3,0\b', window)

    result = {
        'analysis': 'STATIC iris/aperture dialogue: vocabulary, documented OM command and shared transport',
        'firmware_reference': 'Nikon S33 V1.1 (camera observed V1.0; offsets not portable without proof)',
        'iris_interface': {
            'mechanism': 'two-position iris: Big/Small (strings "Iris : %d (0:Big 1:Small)", "Iris status: Big/Small"); '
                         'ND appears only in factory tuning ratios ("Tele small+ND"), not in runtime options',
            'ae_integration': 'iris index 0/1 flows through the 3A logs (ExpTime/Iris/Zoom/AdGain, Set/Get Iris, '
                              'ucIrisIndex) and debug commands (SetIrisIndex, ImgCap_SetAperture)',
            'documented_command': 'BCIP_Aperture operation code 0x9208 (SP1=0:Set 1:Get; SP2=1:Big 9:Small; '
                                  'DP1=Value; operation container 20, response 16) of the OM protocol '
                                  'over the lens MCU port 0x0FF05000',
            'transport': 'shared lens command transaction 0x25F338 (35 Main callers), command descriptors in '
                         'RAM tables (e.g. 0x50E140, 0x50E340 loaded from PC-relative pools)',
            'calibration': 'two checksummed lens tables "LENS IRIS 1/2 DATA" (calibration menu items IRIS 1/2) '
                           'plus per-position data "EFAIRISBIG/EFAIRISSMALL" and shutter-calibration '
                           '"Big/Small Iris Upper/Lower Bound" bounds',
            'no_direct_gpio': 'no iris-specific MMIO outside the lens MCU port cluster was found; '
                              'the iris travels the OM command path like zoom/focus/shutter',
        },
        'transaction_callers': [he(c) for c in sorted(set(callers))],
        'descriptor_literals': {he(k): he(v) for k, v in TRX_CALLER_LITERAL.items()},
        'strings_verified': {t: hex(o) for t, o in found.items()},
        'limits': [
            'Static only: no MMIO, lens MCU or camera hardware accessed; no firmware executed; NON_INSTALLARE',
            'The runtime iris wrapper function is not pinpointed: which of the 35 transaction callers is the '
            'aperture one remains open, as does the byte encoding of the command on the wire',
            'Whether the two 256-byte block reads (0x25F2B8) carry the LENS IRIS calibration tables is '
            'suggested by checksum strings, not proven',
            'BCIP_Aperture is documentation data; the runtime byte protocol over 0x0FF05000 is not decoded',
            'Iris index-to-physical-position mapping and timing are not measured',
        ],
        'sources': {str(p): sha(p) for p in [Path(__file__), FIRMWARE,
                                             ROOT / 'S33-sections/TBM_blocks/manifest.json']},
    }
    (out / 'verified_evidence.json').write_text(
        __import__('json').dumps(result, indent=2, ensure_ascii=False) + '\n')
    (EVIDENCE / 'latest.json').write_text(__import__('json').dumps(
        dict(evidence=str((out / 'verified_evidence.json').relative_to(ROOT)))) + '\n')
    print('PASS', out)
    print('strings:', len(found), 'transaction callers:', len(callers))


if __name__ == '__main__':
    main()
