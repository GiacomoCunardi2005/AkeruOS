#!/usr/bin/env python3
"""Static verification of the lens/zoom (MCU) dialogue in the original V1.1 Main.

How the CPU talks to the lens unit (zoom/focus/iris/shutter motors driven by the
lens MCU): inventories the MMIO literal-pool sites of the lens port block
(0x0FF05xxx in block0/Main), re-disassembles aligned windows of the low-level
port accessors, of the send/wait handshake and of the command transaction, and
verifies the BCIP optical-module command documentation strings (zoom/focus/
aperture/shutter operation codes) in block2.

Read-only: firmware, blocks and tools are never modified. Linear GNU listings
are candidate decodings; asserted windows are re-disassembled from verified
function entry offsets.
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
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface'
MMIO_LO, MMIO_HI = 0x0FE00000, 0x10000000

# Verified function entries/windows (Main = block0, base 0x0AD800).
W_PORT = (0x25E00C, 0x25E120)      # low-level port accessors (0x0FF05000/0x0FF05xxx)
W_SEND = (0x25CB0C, 0x25CB54)     # 0xFF attention + ready-wait; send-byte wrapper
W_BLOCKREAD = (0x25F2B8, 0x25F31C) # 256-byte block reads from the lens port
W_TRANSACTION = (0x25F338, 0x25F398) # one command transaction (opcode, flag, delay)
PORT_CONSTS = {0x0FF05000: 4, 0x0FF05108: 1, 0x0FF0510C: 1, 0x0FF05110: 1, 0x0FF04024: 1}
STRINGS = {
    'MCUCTRL_Task': 0x4264B,
    'Lens Zoom Stop': 0x306D38,
    'Tele button Press': 0x306944,
    'Wide button press': 0x306956,
    'Lens Watchdog Time out': 0x325D94,
    'Lens start': 0x325085,
    '[BCIP]': 0x37FB37,
    'NAME=OM': 0x37FB3F,
    'Command Name=BCIP_Get_OM_Property': 0x37FB4F,
    'Command Name=BCIP_ZOOM_MOVE': 0x38005F,
    'Operation Code=0x9204': 0x38007C,
    'SP1=Physical Pos.': 0x3800CC,
    'Command Name=BCIP_FOCUS_MOVE': 0x38028D,
    'Operation Code=0x9205': 0x3802AB,
    'Command Name=BCIP_FOCUS_Status': 0x38032B,
    'Operation Code=0x9206': 0x38034B,
    'Command Name=BCIP_FOCUS_Reset': 0x3803BE,
    'Operation Code=0x9207': 0x3803DD,
    'Command Name=BCIP_Aperture': 0x380134,
    'Operation Code=0x9208': 0x380150,
    'SP2=1:Big 9:Small': 0x3801BD,
    'Command Name=BCIP_Shutter': 0x3801E3,
    'Operation Code=0x9209': 0x3801FE,
    'Command Name=BCIP_LensInitial': 0x380559,
    'Operation Code=0x920a': 0x380578,
    'Command Name=BCIP_Lens_Off': 0x3805EC,
    'Operation Code=0x9203': 0x380608,
    'Command Name=BCIP_GET_OM_CONFIGURATION': 0x37FDF3,
    'Operation Code=0x9211': 0x37FE1B,
    'DP1=Lens ID': 0x37FD9C,
    'DP2=Zoom UML': 0x37FDA9,
    'DP3=Zoom LML': 0x37FDB7,
    'DP4=Zoom Position': 0x37FDC5,
    'DP5=Aperture Range': 0x37FDD8,
}


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
    assert base0 == 0x0AD800

    listing0 = objdump_text(ROOT, block_dir, info[0], p0)
    sites = mmio_literal_sites(listing0, base0, p0)
    by_value = {}
    for pc, value in sites:
        by_value.setdefault(value, []).append(pc)
    for const, min_sites in PORT_CONSTS.items():
        pcs = by_value.get(const, [])
        assert len(pcs) >= min_sites, (hex(const), len(pcs))
    # The port block lives in Main only: no other scanned payload loads it.
    for idx in (2, 4):
        other = objdump_text(ROOT, block_dir, info[idx], payloads[idx])
        assert all(v not in (0x0FF05000,) for _, v in mmio_literal_sites(other, info[idx]['load_address_candidate'], payloads[idx]))

    windows = {
        'port_accessors_25E00C': aligned_window(p0, base0, *W_PORT),
        'send_wait_25CB0C': aligned_window(p0, base0, *W_SEND),
        'block_read_25F2B8': aligned_window(p0, base0, *W_BLOCKREAD),
        'transaction_25F338': aligned_window(p0, base0, *W_TRANSACTION),
    }
    (out / 'gnu_windows.txt').write_text(
        '\n\n'.join(f'=== {name} ===\n{text}' for name, text in windows.items()))
    for name, text in windows.items():
        assert text.strip(), name

    def window_bytes(start, end):
        return p0[start - base0:end - base0 + 8]

    # Port accessors: data port 0x0FF05000 written/read in halfword .di,
    # status bit 7 of 0x0FF04024, position from 0x0FF05108/0x0FF0510C,
    # reset pulse bit0 on 0x0FF05110, RMW on 0x0FFCA008.
    port_text = windows['port_accessors_25E00C']
    wb = window_bytes(*W_PORT)
    for const in (0x0FF05000, 0x0FF05108, 0x0FF0510C, 0x0FF05110, 0x0FFCA008, 0x0FF04024):
        assert struct.pack('<I', const) in wb, hex(const)
    for token in ('ldh.di', 'sth.di', 'bset', 'bclr', 'bmsk'):
        assert token in port_text, token
    assert re.search(r'\tlsr_s\tr0,r0,0x7\b', port_text), 'status bit7 shift missing'
    assert re.search(r'\tbmsk_s\tr0,r0,0\b', port_text), 'status bit mask missing'
    assert re.search(r'\tasl\tr13,r0,0x10\b', port_text), 'position compose shift missing'
    assert re.search(r'\tor_s\tr0,r0,r13\b', port_text), 'position compose OR missing'

    # Send/wait: attention 0xFF, ready poll with timeout 0xF4240 (1000000).
    send_text = windows['send_wait_25CB0C']
    assert re.search(r'\tmov_s\tr0,0xff\b', send_text), 'attention byte 0xFF missing'
    assert re.search(r'\tcmp_s\tr13,0xf4240\b', send_text), 'timeout bound missing'
    assert re.search(r'\tbl(\.d)?\t\d+\t;0x25e0b8', send_text), 'status call missing'
    assert re.search(r'\tbl(\.d)?\t\d+\t;0x25e064', send_text), 'port write call missing'
    assert re.search(r'\tbhs_s\b', send_text), 'timeout branch missing'

    # Block read: 256-byte reads from the port, stored byte-wise.
    block_text = windows['block_read_25F2B8']
    assert block_text.count('mov\tr14,256') >= 2, block_text.count('mov\tr14,256')
    assert block_text.count('stb.ab\tr0,[r13,1]') >= 2
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25e08c', block_text), 'port read call missing'
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25e038', block_text), 'position getter call missing'
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25cbbc', block_text), '3-byte pack call missing'

    # Transaction: opcode send, bit 0xA flag, optional 0x30, delay 1000,
    # attention (0x25CB0C) on non-zero status.
    trx_text = windows['transaction_25F338']
    assert re.search(r'\tbtst_s\tr0,0xa\b', trx_text), 'flag bit 0xA missing'
    assert re.search(r'\tmov_s\tr0,0x30\b', trx_text), '0x30 suffix missing'
    assert re.search(r'\tmov\tr0,1000\b', trx_text), 'delay 1000 missing'
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25cb0c', trx_text), 'attention call missing'
    assert re.search(r'\tbl(\.d)?\t-?\d+\t;0x25cb54', trx_text), 'command sender call missing'

    # Strings at fixed container offsets (the BCIP blob indents entries with a
    # leading space, so each documented string may start at offset or offset+1
    # when captured with the leading space included).
    found = {}
    for text, offset in STRINGS.items():
        lo, hi = offset - 0x40, offset + 0x80
        at = firmware.find(text.encode(), lo, hi)
        at_sp = firmware.find(b' ' + text.encode(), lo, hi)
        if at == offset:
            found[text] = at
        elif at_sp == offset - 1 or at_sp + 1 == at:
            found[text] = at
        else:
            raise AssertionError((text, hex(at), hex(at_sp)))

    result = {
        'analysis': 'STATIC lens/zoom MCU dialogue: port inventory plus aligned GNU windows plus BCIP OM command table',
        'firmware_reference': 'Nikon S33 V1.1 (camera observed V1.0; offsets not portable without proof)',
        'lens_interface': {
            'data_port': '0x0FF05000 (halfword ldh.di/sth.di; byte-oriented protocol above it)',
            'position_inputs': '0x0FF05108 (bmsk 5 bits) << 16 | 0x0FF0510C (bmsk 5 bits)',
            'reset_pulse': '0x0FF05110 bit0 bset/bclr pulse at 0x25E00C',
            'status_bit': '0x0FF04024 bit 7 (ready), read via 0x25E0B8',
            'aux_rmw': '0x0FFCA008 bit write at 0x25E0D4',
            'attention': 'send 0xFF to the port then poll ready up to 0xF4240 iterations (0x25CB0C)',
            'send_byte': '0x25CB3C wrapper; command sender with arithmetic at 0x25CB54',
            'block_read': '256-byte lens data blocks read from the port (0x25F2B8)',
            'transaction': 'opcode send, bit0xA flag, optional 0x30, delay 1000, 0xFF attention on retry (0x25F338)',
            'three_byte_pack': '0x25CBBC: b0=v, b1=v>>8, b2=(v>>14)|3',
            'bcip_om_table': 'BCIP optical-module commands documented in block2 strings: '
                             'Get_OM_Property 0x9200, Lens_Off 0x9203, ZOOM_MOVE 0x9204 (P1 physical pos; '
                             'response zoom time hi/lo, PI value, ErrCode), FOCUS_MOVE 0x9205, FOCUS_Status 0x9206, '
                             'FOCUS_Reset 0x9207, Aperture 0x9208 (Set/Get, 1:Big 9:Small iris), Shutter 0x9209 '
                             '(Close/Open), LensInitial 0x920A, GET_OM_CONFIGURATION 0x9211 (Lens ID, Zoom UML/LML, '
                             'Zoom Position, Aperture Range)',
            'note': 'No 0x92xx immediates appear in Main code: the BCIP table is the documented command set; '
                    'the byte protocol above it is what Main runs over 0x0FF05000',
        },
        'blocks_scanned': [0],
        'mmio_pool_site_counts': {'0': len(sites)},
        'lens_port_sites': {he(v): [he(pc) for pc in by_value[v]] for v in PORT_CONSTS},
        'windows_verified': [hex(w[0]) for w in (W_PORT, W_SEND, W_BLOCKREAD, W_TRANSACTION)],
        'strings_verified': {t: hex(o) for t, o in found.items()},
        'limits': [
            'GNU listings are linear candidate decodings; only the four asserted windows are aligned at verified entries',
            'Pool literal loads are candidates: no CFG/dataflow proof that every site is executed',
            'The wire format of the byte protocol (opcodes, checksums) over 0x0FF05000 is not yet decoded',
            'MCUCTRL_Task entry, queue and the mapping UI Tele/Wide -> command bytes remain open',
            'No MMIO, lens MCU or camera hardware was accessed; no firmware executed; no candidate install',
            'BCIP table is documentation data in block2; not proven to be the runtime protocol',
        ],
        'sources': {str(p): sha(p) for p in [Path(__file__), FIRMWARE,
                                             ROOT / 'S33-sections/TBM_blocks/manifest.json',
                                             ROOT / 'work/build-arc/binutils/objcopy',
                                             ROOT / 'work/build-arc/binutils/objdump']},
    }
    (out / 'verified_evidence.json').write_text(
        __import__('json').dumps(result, indent=2, ensure_ascii=False) + '\n')
    (EVIDENCE / 'latest.json').write_text(__import__('json').dumps(
        dict(evidence=str((out / 'verified_evidence.json').relative_to(ROOT)))) + '\n')
    print('PASS', out)
    print('port sites:', {hex(k): len(by_value[k]) for k in PORT_CONSTS})
    print('bcip strings:', sum(1 for t in found if t.startswith(('Command', 'Operation'))))


if __name__ == '__main__':
    main()
