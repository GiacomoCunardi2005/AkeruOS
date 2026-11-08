#!/usr/bin/env python3
"""Static verification of the sensor/AFE MMIO dialogue in the original V1.1 payload set.

Finds how the CPU-side firmware addresses the image sensor: inventories the MMIO
constants (0x0FE00000-0x0FFFFFFF) actually loaded from PC-relative literal pools
in blocks 0/2/4, then re-disassembles aligned windows around the runtime sensor
register file (block2, bank 0x0FF98xxx), the tuning register file (block4, bank
0x0FF90xxx) and the sensor clock-gate configuration (0xFE800F4 / 0xFEF014C).

Read-only: firmware, blocks and tools are never modified. Linear GNU listings are
candidate decodings; the asserted windows are re-disassembled from verified
function entry offsets so that alignment is controlled.
"""
import re
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads, objdump_text, he
from s33_run_gnu_arc700 import ROOT, sha

FIRMWARE = ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin'
EVIDENCE = ROOT / 'Risultati/Sensore_Interface_MMIO'
TOOLCOPY = ROOT / 'work/build-arc/binutils/objcopy'
TOOLDUMP = ROOT / 'work/build-arc/binutils/objdump'
MMIO_LO, MMIO_HI = 0x0FE00000, 0x10000000

# Verified function entries/windows (addresses in the block-2/4 VA spaces).
W_RESET = (0x60EDEC, 0x60EED0)     # block2: pulse/reset sequence on 0x0FF98074 + 0x0FF98000
W_INIT = (0x60EED0, 0x60EFA0)      # block2: initial bit setup on the same registers
W_MODE = (0x60FA40, 0x60FD90)      # block2: table-driven bitfield writer into 0x0FF98xxx
W_CLOCK = (0x6515A2, 0x651626)     # block2: sensor clock gate 0xFE800F4 / 0xFEF014C
W_TUNING = (0x796800, 0x7968B8)    # block4: tuning AFE writer on 0x0FF90xxx
RESET_BITS = [8, 3, 6, 7]          # bset/bclr pulse bits on 0x0FF98074, in order
INIT_BITS_74 = {8, 3, 6, 7}        # bset-only setup on 0x0FF98074
STRINGS = {
    'IO_SetRegisterBitField(0xFEF014C,0x0003,%d)': 0x540AD1,
    'IO_SetRegisterBitField(0xFE800F4,0x000f,%d)': 0x540AFD,
    'GPIO Mode(0x30): 0x%x': 0x53FFA9,
    'Input Buffer(0x21): 0x%x': 0x53FFBF,
    'DeepSleep(0x00): 0x%x': 0x53FFD8,
    'g_uwAFE_0x74_Steps=%d': 0x540B29,
    'CMOS Fine Tune Script': 0x540669,
    'CCD_Tune_DVT.c': 0x5409D4,
    'By COMS Sensor': 0x3273DD,
    'Sensor  CLK: %d, En: %d': 0x34FA97,
}
LD_PCL = re.compile(r'^\s*([0-9a-f]+):.*\tld[a-z._]*\s+(r[0-9]+),\[pcl,(0x[0-9a-f]+)\]\s*;0x([0-9a-f]+)')
INSN = re.compile(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2,8} )+\s*\t?([a-z._]+)\s*(.*)$')


def mmio_literal_sites(listing: str, base: int, payload: bytes):
    """(pc, literal_word) for every PC-relative pool load whose word is MMIO."""
    sites = []
    for line in listing.splitlines():
        m = LD_PCL.search(line)
        if not m:
            continue
        pc, lit = int(m.group(1), 16), int(m.group(4), 16)
        off = lit - base
        if 0 <= off <= len(payload) - 4:
            value = struct.unpack_from('<I', payload, off)[0]
            if MMIO_LO <= value < MMIO_HI:
                sites.append((pc, value))
    return sites


def aligned_window(payload: bytes, base: int, start: int, end: int) -> str:
    """Disassemble payload[start:end) with the stream aligned at `start`."""
    data = payload[start - base:end - base]
    with tempfile.TemporaryDirectory(prefix='s33-sensor-') as td:
        raw = Path(td) / 'window.bin'
        elf = Path(td) / 'window.elf'
        raw.write_bytes(data)
        for cmd in ([TOOLCOPY, '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc',
                     '--rename-section', '.data=.text,alloc,load,readonly,code,contents',
                     '--change-section-vma', f'.data={start:#x}', '--strip-all', raw, elf],
                    [TOOLDUMP, '-d', '-m', 'arc:ARC700', '-EL', elf]):
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                raise RuntimeError(f'tool failed: {cmd[0]}: {proc.stderr}')
        text = proc.stdout
        lines = [ln for ln in text.splitlines()
                 if not re.search(rf'Address {end:#x} is out of bounds', ln)]
        assert not any('out of bounds' in ln for ln in lines), lines[-3:]
        return '\n'.join(lines)


def bit_sequence(window_text: str, lo: int, hi: int):
    """bset/bclr bit numbers in address order within [lo,hi).

    Bit numbers are usually held in a register set by a preceding mov reg,imm,
    so a tiny register map is tracked while scanning in address order.
    """
    regs = {}
    bits = []
    for line in window_text.splitlines():
        m = INSN.search(line)
        if not m:
            continue
        pc, op, args = int(m.group(1), 16), m.group(2), m.group(3)
        if not (lo <= pc < hi):
            continue
        if op in ('mov', 'mov_s'):
            m2 = re.match(r'(r\d+),(0x[0-9a-f]+|\d+)$', args.strip())
            if m2:
                regs[m2.group(1)] = int(m2.group(2), 0)
        elif op in ('bset', 'bset_s', 'bclr', 'bclr_s'):
            m2 = re.search(r',(r\d+|0x[0-9a-f]+|\d+)$', args.strip())
            if m2:
                tok = m2.group(1)
                bit = int(tok, 0) if not tok.startswith('r') else regs.get(tok)
                if bit is not None:
                    bits.append(('set' if op.startswith('bset') else 'clr', bit))
    return bits


def main() -> None:
    out = EVIDENCE / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'script_snapshot.py').write_bytes(Path(__file__).read_bytes())
    firmware = FIRMWARE.read_bytes()
    assert sha(FIRMWARE) == '1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39'
    blocks, payloads, block_dir = verified_payloads(ROOT)
    info = {b['index']: b for b in blocks}
    listings, sites = {}, {}
    for idx in (0, 2, 4):
        listings[idx] = objdump_text(ROOT, block_dir, info[idx], payloads[idx])
        sites[idx] = mmio_literal_sites(listings[idx], info[idx]['load_address_candidate'], payloads[idx])
    by_value = {idx: {} for idx in (0, 2, 4)}
    for idx in (0, 2, 4):
        for pc, value in sites[idx]:
            by_value[idx].setdefault(value, []).append(pc)

    # --- core assertions on the runtime dialogue (block 2) -------------------
    base2 = info[2]['load_address_candidate']
    p2 = payloads[2]
    for const, min_sites in [(0x0FF98074, 8), (0x0FF98000, 4), (0x0FF98020, 8),
                             (0x0FF98034, 8), (0x0FF98124, 4),
                             (0x0FE800F4, 1), (0x0FEF014C, 2)]:
        pcs = by_value[2].get(const, [])
        assert len(pcs) >= min_sites, (hex(const), len(pcs))
    bank_ff98 = sorted(v for v in by_value[2] if 0x0FF98000 <= v <= 0x0FF98200)
    assert len(bank_ff98) >= 40, len(bank_ff98)
    bank_ff90 = sorted(v for v in by_value[4] if 0x0FF90000 <= v <= 0x0FF90100)
    assert len(bank_ff90) >= 30, len(bank_ff90)

    # --- aligned windows ------------------------------------------------------
    windows = {}
    windows['reset_pulse_60EDEC'] = aligned_window(p2, base2, *W_RESET)
    windows['init_bits_60EED0'] = aligned_window(p2, base2, *W_INIT)
    windows['mode_writer_60FA40'] = aligned_window(p2, base2, *W_MODE)
    windows['sensor_clock_6515A2'] = aligned_window(p2, base2, *W_CLOCK)
    base4 = info[4]['load_address_candidate']
    windows['tuning_afe_796800'] = aligned_window(payloads[4], base4, *W_TUNING)
    (out / 'gnu_windows.txt').write_text(
        '\n\n'.join(f'=== {name} ===\n{text}' for name, text in windows.items()))
    for name, text in windows.items():
        assert text.strip(), name

    # Reset/pulse window: sequence of bset/bclr pairs on the register loaded
    # from the pool literal 0x0FF98074, in the order 8,3,6,7.
    lit_74 = struct.pack('<I', 0x0FF98074)
    lo = W_RESET[0] - base2
    assert p2.find(lit_74, lo, W_RESET[1] - base2 + 8) >= 0, '0x0FF98074 pool literal missing'
    seq = bit_sequence(windows['reset_pulse_60EDEC'], *W_RESET)
    bits = [b for _, b in seq]
    assert bits[:8] == [b for b in RESET_BITS for _ in (0, 1)], (bits,)
    assert [k for k, _ in seq[:8]] == ['set', 'clr'] * 4, seq[:8]
    for token in ('ldh.di', 'sth.di', 'bset', 'bclr'):
        assert token in windows['reset_pulse_60EDEC'], token
    # Command writes to 0x0FF98000: 256 and 512 then bit11 and bit12.
    reset_text = windows['reset_pulse_60EDEC']
    for value in (256, 512):
        assert re.search(rf'\tmov(_s)?\tr0,{value}\b', reset_text), value
    tail = bit_sequence(windows['reset_pulse_60EDEC'], W_RESET[1] - 0x20, W_RESET[1])
    assert ('set', 11) in tail and ('set', 12) in tail, tail

    # Init window: bset-only on 0x0FF98074 (bits 0,3,6,7) plus setup on 0x0FF98000.
    init_bits = {b for _, b in bit_sequence(windows['init_bits_60EED0'], 0x60EED0, 0x60EF30)}
    assert INIT_BITS_74 <= init_bits, init_bits

    # Clock window: writes to 0xFEF014C and sensor clock divider bits of 0xFE800F4.
    clock_text = windows['sensor_clock_6515A2']
    lo_clk = W_CLOCK[0] - base2
    p2off = p2[lo_clk:W_CLOCK[1] - base2 + 8]
    assert struct.pack('<I', 0x0FEF014C) in p2off
    assert struct.pack('<I', 0x0FE800F4) in p2off
    for token in ('ldh.di', 'sth.di', 'bclr', 'bmsk'):
        assert token in clock_text, token
    assert re.search(r'\tand\s+r0,r0,-16', clock_text), 'low-4-bit clear of the divider'

    # Tuning window: RMW on 0x0FF90000 with a bit0 strobe.
    tuning_text = windows['tuning_afe_796800']
    assert struct.pack('<I', 0x0FF90000) in payloads[4][W_TUNING[0] - base4:W_TUNING[1] - base4 + 8]
    for token in ('ldh.di', 'sth.di', 'bclr_s', 'bset_s'):
        assert token in tuning_text, token

    # --- AFE/sensor naming strings at fixed container offsets -----------------
    found = {}
    for text, offset in STRINGS.items():
        at = firmware.find(text.encode(), offset - 0x40, offset + 0x80)
        assert at == offset, (text, hex(at))
        found[text] = at

    # --- inventories -----------------------------------------------------------
    def bank_counts(idx):
        counts = {}
        for _, value in sites[idx]:
            counts[(value >> 16) & 0xFFFF] = counts.get((value >> 16) & 0xFFFF, 0) + 1
        return {f'0x{bank:04x}': n for bank, n in sorted(counts.items())}

    result = {
        'analysis': 'STATIC sensor/AFE MMIO dialogue: literal-pool inventory plus aligned GNU windows',
        'firmware_reference': 'Nikon S33 V1.1 (camera observed V1.0; offsets not portable without proof)',
        'sensor_interface': {
            'runtime_register_file': '0x0FF98000-0x0FF981xx (block2, halfword .di RMW bitfields)',
            'reset_pulse_register': '0x0FF98074 (bset/bclr bit pulses 8,3,6,7 at 0x60EDEC)',
            'init_bits_register': '0x0FF98074 bset-only bits 0,3,6,7 then 0x0FF98000 setup at 0x60EED0',
            'command_register': '0x0FF98000 (writes 256,512 and bset bits 11,12)',
            'tuning_register_file': '0x0FF90000-0x0FF900E0 (block4 tuning module, .di RMW)',
            'sensor_clock_divider': '0xFE800F4 low 4 bits via IO_SetRegisterBitField(0xFE800F4,0x000f,n)',
            'sensor_clock_gate': '0xFEF014C bits 0-1 via IO_SetRegisterBitField(0xFEF014C,0x0003,n)',
            'api_layer_strings': 'CAPCTRL_EnableAndWaitFieldChange / CAPCTRL_AFE_SetADGain in block1 data',
            'tuning_tables': 'SETDLL_*.CON / DLL timing files (H1/H3,H2/H4,SHP,SHD,RG,MCKOUT,DCLK,ADCCK)',
        },
        'blocks_scanned': [0, 2, 4],
        'mmio_pool_site_counts': {str(i): len(sites[i]) for i in (0, 2, 4)},
        'mmio_bank_counts': {str(i): bank_counts(i) for i in (0, 2, 4)},
        'block2_bank_0xFF980_constants': [he(v) for v in bank_ff98],
        'block2_bank_0xFF980_sites': {he(v): [he(pc) for pc in by_value[2][v]] for v in bank_ff98},
        'block4_bank_0xFF900_constants': [he(v) for v in bank_ff90],
        'reset_pulse_bits': RESET_BITS,
        'clock_windows_verified': ['0x60EDEC', '0x60EED0', '0x60FA40', '0x6515A2', '0x796800'],
        'strings_verified': {t: hex(o) for t, o in found.items()},
        'limits': [
            'GNU listings are linear candidate decodings; only the five asserted windows are aligned at verified entries',
            'Pool literal loads are candidates: no CFG/dataflow proof that every site is executed',
            'No MMIO, sensor or camera hardware was accessed; no firmware executed; no candidate install',
            'Block1 (CAPCTRL strings, DLL tables, ME data) was not MMIO-scanned: its code/struct role stays open',
            'Bit-to-pin mapping (SIO clock/data/reset) is inferred from pulse shape, not from a datasheet',
            'Runtime callers, sequencing vs DSP/payload6, DMA and the pixel data path remain open',
        ],
        'sources': {str(p): sha(p) for p in [Path(__file__), FIRMWARE,
                                             ROOT / 'S33-sections/TBM_blocks/manifest.json',
                                             TOOLCOPY, TOOLDUMP]},
    }
    (out / 'verified_evidence.json').write_text(
        __import__('json').dumps(result, indent=2, ensure_ascii=False) + '\n')
    (EVIDENCE / 'latest.json').write_text(__import__('json').dumps(
        dict(evidence=str((out / 'verified_evidence.json').relative_to(ROOT)))) + '\n')
    print('PASS', out)
    print('runtime 0x0FF98 constants:', len(bank_ff98), ' tuning 0x0FF90 constants:', len(bank_ff90))
    print('reset bits:', bits, ' strings:', len(found))


if __name__ == '__main__':
    main()
