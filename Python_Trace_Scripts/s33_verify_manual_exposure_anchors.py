#!/usr/bin/env python3
"""Static anchors for an AkeruOS manual exposure selector (Av/Tv/M, ISO).

Verifies, at fixed container offsets, the firmware-side evidence a manual
aperture/ISO/shutter selector plus Av/Tv priority modes would hook into:
the 3A scene/mode enum (e_Program, e_Aperture_Priority, e_Shutter_Priority),
the CAPCTRL gain API, the documented BCIP override commands (exposure time,
ISO gain, clamp level, aperture), the AE telemetry getter, the debug script
commands that already impose iris/gain/ISO, manual focus and the AE program
curve marker.

Read-only: firmware, blocks and tools are never modified. Design study only:
nothing here is executed on hardware.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_run_gnu_arc700 import ROOT, sha

FIRMWARE = ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin'
EVIDENCE = ROOT / 'Risultati/AkeruOS_Esposizione_Manuale'

STRINGS = {
    # 3A scene/mode enum (payload1): Av and Tv already exist as AE modes.
    'e_Action': 0x31A9CE,
    'e_Aperture_Priority': 0x31AA06,
    'e_Program': 0x31ACC1,
    'e_Shutter_Priority': 0x31ACFB,
    'e_HighISO': 0x31AB40,
    # CAPCTRL API (payload1): gain and AE/AWB telemetry.
    'Error : CAPCTRL_AFE_SetADGain(), error code=0X%X.': 0x31A736,
    'CAPCTRL_3AGetAEAWBData Fail': 0x327460,
    # AE controller loop and report (payload1).
    'AE ConLop:%d, Exp:%d,Gain:%d,Iris:%s,Zoom:%d': 0x3270FD,
    'FillPara  Iris:%d,Aper:%d,ExpTime=%d,ISO:%d,BV:%d,Gain:%d': 0x326EEF,
    'ucSceneMode=%d': 0x310F28,
    '========P CURVE========': 0x31AD57,
    # Documented override commands of the OM/BCIP table (payload2).
    'Command Name=BCIP_SET_EXPOSURE_TIME': 0x37FE72,
    'Operation Code=0x9210': 0x37FE97,
    'SP1=micro second': 0x37FEEF,
    'SP2=0:LV 1:FR': 0x37FF08,
    'Command Name=BCIP_SET_ISO_GAIN': 0x37FF20,
    'Operation Code=0x9212': 0x37FF40,
    'SP1=ISO_Gain': 0x37FFA2,
    'Command Name=BCIP_SET_CLAMP_LEVEL': 0x37FFB8,
    'Operation Code=0x9213': 0x37FFDA,
    'SP1=Clamp_Level 0_255': 0x380041,
    'Command Name=BCIP_Aperture': 0x380134,
    'Operation Code=0x9208': 0x380150,
    'SP2=1:Big 9:Small': 0x3801BD,
    # Debug script commands that already impose the controls.
    'ImgCap_SetISO100Gain': 0x3B2B03,
    'ImgCap_SetISOSpeed': 0x3B2B1B,
    'SetAdGain': 0x74D630,
    'SetIrisIndex': 0x74D67C,
    'SetIsoSpeed': 0x74D68D,
    'SetIsoStartDigiGain': 0x74DC44,
    'Manual Focus': 0x733D1B,
    'Focus mode: MF/AF': 0x73923E,
    # Tuning menu entries that impose time/rate at application level.
    'Exposure Time': 0x53F672,
    'Frame Rate': 0x53F667,
}


def main() -> None:
    out = EVIDENCE / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'script_snapshot.py').write_bytes(Path(__file__).read_bytes())
    firmware = FIRMWARE.read_bytes()
    assert sha(FIRMWARE) == '1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39'

    found = {}
    for text, offset in STRINGS.items():
        needle = text.encode()
        hi = offset + 0x40 + len(needle)
        at = firmware.find(needle, offset - 0x20, hi)
        at_sp = firmware.find(b' ' + needle, offset - 0x20, hi)
        ok = at == offset or (at_sp >= 0 and at_sp + 1 == offset) or at == offset + 1
        assert ok, (text, hex(at), hex(at_sp))
        found[text] = at if at == offset else offset

    # Container sizes of the override commands (exposure 20/16, ISO 16/12).
    assert firmware.find(b'Operation Container Size=20', 0x37FE96, 0x37FF00) > 0
    assert firmware.find(b'Response Container Size=16', 0x37FEC0, 0x37FF00) > 0
    assert firmware.find(b'Operation Container Size=16', 0x37FF50, 0x37FFB0) > 0
    assert firmware.find(b'Response Container Size=12', 0x37FF70, 0x37FFB0) > 0
    # P1 default of both override commands is 240 (0xF0 units).
    assert firmware.count(b'P1=240') >= 3

    result = {
        'analysis': 'STATIC anchors for an AkeruOS manual exposure selector; design study, no execution',
        'firmware_reference': 'Nikon S33 V1.1 (camera observed V1.0; offsets not portable without proof)',
        'anchors': {
            'ae_mode_enum': 'payload1 names e_Program / e_Aperture_Priority / e_Shutter_Priority among the '
                            'AE scene types (with e_Action, e_HighISO, e_Sunset, ...): Av and Tv already '
                            'exist inside the 3A, adjacent to a P CURVE (program AE curve) block',
            'gain_api': 'CAPCTRL_AFE_SetADGain (error string) and debug commands SetAdGain / '
                        'SetIsoSpeed / ImgCap_SetISO100Gain / ImgCap_SetISOSpeed',
            'time_api': 'BCIP_SET_EXPOSURE_TIME 0x9210 (P1 micro second, P2 0:LV 1:FR, container 20/16) '
                        'documents an internal impose-exposure-time service; tuning menu has '
                        'Exposure Time / Frame Rate entries',
            'aperture_api': 'BCIP_Aperture 0x9208 (Set/Get; 1:Big 9:Small) over the lens MCU port; '
                            'SetIrisIndex debug command; iris is binary (see iris session)',
            'telemetry': 'CAPCTRL_3AGetAEAWBData, AE ConLop / FillPara reports (Iris, Aper, ExpTime, '
                         'ISO, BV, Gain), ucSceneMode variable',
            'manual_focus': '"Manual Focus" and "Focus mode: MF/AF" already exist as debug-level controls',
        },
        'strings_verified': {t: hex(o) for t, o in found.items()},
        'design_gaps': [
            'The internal functions behind BCIP_SET_EXPOSURE_TIME / BCIP_SET_ISO_GAIN are not located yet',
            'How a scene/mode (e_Aperture_Priority / e_Shutter_Priority) is selected at runtime is open',
            'How to freeze the AE loop against manual overrides is open (no AE-disable service verified)',
            'No hardware validation; all static',
        ],
        'limits': [
            'Static string/anchor verification only: no code executed, no MMIO or camera touched',
            'Presence of a documented command does not prove the runtime call path for the application',
            'Iris has only two runtime positions (Big/Small); ND is factory-only',
            'Version separation V1.1 analyzed / V1.0 observed still applies',
        ],
        'sources': {str(p): sha(p) for p in [Path(__file__), FIRMWARE]},
    }
    (out / 'verified_evidence.json').write_text(
        __import__('json').dumps(result, indent=2, ensure_ascii=False) + '\n')
    (EVIDENCE / 'latest.json').write_text(__import__('json').dumps(
        dict(evidence=str((out / 'verified_evidence.json').relative_to(ROOT)))) + '\n')
    print('PASS', out)
    print('anchors verified:', len(found))


if __name__ == '__main__':
    main()
