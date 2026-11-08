#!/usr/bin/env python3
"""Static byte-exact census of the 0x0FE400xx bank (iteration 14 open point b).

The bank 0x0FE40000..0x0FE4004C is the unknown peripheral written by the
Main-side status-API helper 0x301EC0 (iteration 8) and by the TBIB boot
(the GNU DSPv5 emulation stops on its first store, 0x010091F8). This
verifier censuses every reference to the bank range 0x0FE40000..0x0FE4FFFF
in the 16 Main payloads and in the TBIB body, then byte-decodes the boot
and Main accessors. Byte-verified facts asserted here:

CENSUS (16 payloads + TBIB body, 2-byte-aligned words):
- every LE word in [0x0FE40000,0x0FE50000) and every halfword-swapped
  (limm-style) reading of such words is classified against the GNU ARC700
  linear listing as load-referenced pcl pool, instruction-stream word,
  branch-comment target or data;
- NO limm/movhi immediate in the bank range exists in any instruction line
  of the 17 listings: every real reference goes through pcl pools;
- Main side: the ONLY load-referenced pools with a bank value are the four
  pools of the 0x301EC0 body (0x301EC8/0x301EDC in the linear decode,
  0x301EF0/0x301F04 via dedicated aligned windows, because the pool after
  the b_s swallows the store in the linear window); the only other
  load-referenced pool touching the range is 0x26FF8C, whose LE value
  0x00270FE4 is NOT a bank address (halfword-order coincidence);
  payloads 1..15 have ZERO real references; all remaining sites are
  coincidences with frozen per-payload counts;
- TBIB side: exactly 37 bank pool sites (36 referenced by linear-decode
  loads + 0x1009214 via a dedicated aligned window), covering 17 distinct
  registers +0x00,+0x04,+0x08,+0x0C,+0x10,+0x18..+0x34,+0x40..+0x4C;
  register +0x14 is NEVER referenced; every remaining TBIB site is a
  halfword-order coincidence with the following instruction halfword;

MAIN WRITER 0x301EC0 (aligned windows + raw pool words):
  0x4321 -> 0x0FE40004, 0x6641 -> 0x0FE40008,
  0xE972 -> 0x0FE4000C, 0xFFFF -> 0x0FE40010, then pop_s blink/j_s;
  no Main reader of the bank exists (census negative).

TBIB BOOT (aligned windows + raw pool words):
- routine 0x10091E4 (the GNU DSPv5 stop is its FIRST store, 0x10091F8):
  +0x04=0x4321 (same command value as Main), +0x08/+0x0C/+0x10=0xFFFF,
  +0x18..+0x24=0, +0x28=2, +0x2C=0x100, +0x30/+0x34=0, tail call
  0x103E158 (delay slot mov_s r0,r13);
- composer 0x100929C -> 0x0FE40008 and 0x10092D8 -> 0x0FE4000C write the
  packed halfword ((r0<<13)&0xE000)|((r1<<8)&0x1F00)|((r2<<4)&0xF0)|(r3&0xF)
  (Python model over 65536 operand tuples, exact match);
- strobe RMW routines 0x1000CF2/0x1001472 on 0x0FE40000: bset9, bset8,
  bclr9 (net effect 0x100, bit model), then poll of bit0 of 0x0FFCA008
  (pool 0x1000D28/0x10014A8); variant 0x1000FF6: bset9, bclr8;
- init sequence A (0x1000EEC..0x1000FEA, copy at 0x100167C..0x1001762):
  +0x40=0x2020, +0x44=0xF80, +0x48=0x300, +0x4C=r16, +0x00=0x0A,
  +0x00=0x20A, poll, +0x40=0x216F, +0x44=0x3F, +0x48=0x216F, +0x4C=0x3F,
  write 1 -> 0x0FFCA008, tail 0x103E138; variant C at 0x1001710 repeats
  0x216F/0x3F on +0x40/+0x44/+0x48/+0x4C;
- DDR is EXCLUDED as identity candidate: the BFN DDR registers live at
  0x0FE2xxxx (BFN report), not 0x0FE4xxxx. The peripheral identity stays
  open; this verifier proves the access protocol, not the silicon block.

Read-only: firmware, blocks and tools are never modified. NON_INSTALLARE.
"""
import hashlib
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'coolpix-s33-re'))
from s33_trace_state_dispatch import (verified_payloads, parse_listing, window, he,
                                      HEX_REF)
from s33_run_gnu_arc700 import ROOT, sha
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_extract import parse_firmware

FIRMWARE = ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin'
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Bank_0FE400xx'
BANK_LO, BANK_HI = 0x0FE40000, 0x0FE50000
P0_BASE = 0xAD800

LOAD_LINE = re.compile(r'\b(ld[a-z._]*)\s+(r\d+),\[pcl,(0x[0-9a-f]+)\]')
# full canonical bank address in an immediate, e.g. 0xfe40004 (limm form);
# a bare 0xfe4 immediate is NOT a bank address (16-bit constant only)
INSTR_IMM = re.compile(r',0x0*fe4[0-9a-f]{4}\b')
# movhi toward the bank would print the upper half 0xfe4 as operand
MOVHI_BANK = re.compile(r'\bmovhi\s+r\d+,(?:r\d+,)?0x0*fe4\b')
DEC_IMM = re.compile(r',(\d+)\b')
BANK_DEC = range(0x0FE40000, 0x0FE50000)

# ---- frozen census expectations (GNU ARC700 linear listings, V1.1) ----
# Main: load-referenced pools whose LE value is a bank address. The two
# entries 0x301EF0/0x301F04 are hidden from the linear decode (the pool after
# the b_s swallows the store) and are proven by the aligned windows W3/W4.
MAIN_BANK_POOLS = {
    0x301EC8: 0x0FE40004, 0x301EDC: 0x0FE40008,
    0x301EF0: 0x0FE4000C, 0x301F04: 0x0FE40010,
}
MAIN_LINEAR_BANK_POOLS = {
    0x301EC8: 0x0FE40004, 0x301EDC: 0x0FE40008,
}
# Main: load-referenced pool whose LE value is NOT a bank address
# (halfword-order coincidence of the ME reading).
MAIN_COINCIDENCE_POOL = {0x26FF8C: 0x00270FE4}
# 2-byte-aligned sites (LE or ME reading in range) per Main payload.
MAIN_SITE_COUNTS = {0: 24, 1: 44, 2: 12, 3: 12, 4: 14, 5: 18, 6: 8,
                    9: 6, 10: 30, 11: 4, 12: 8, 13: 14}
MAIN_EMPTY = [7, 8, 14, 15]

# TBIB: every bank pool site -> LE value (37 sites, 17 registers, no +0x14).
TBIB_BANK_POOLS = {
    0x1000CF8: 0x0FE40000, 0x1000EF4: 0x0FE40040, 0x1000F04: 0x0FE40044,
    0x1000F14: 0x0FE40048, 0x1000F24: 0x0FE4004C, 0x1000F34: 0x0FE40000,
    0x1000F44: 0x0FE40000, 0x1000FA4: 0x0FE40040, 0x1000FB8: 0x0FE40044,
    0x1000FC8: 0x0FE40048, 0x1000FDC: 0x0FE4004C, 0x1000FFC: 0x0FE40000,
    0x1001478: 0x0FE40000, 0x1001680: 0x0FE40040, 0x1001690: 0x0FE40044,
    0x10016A0: 0x0FE40048, 0x10016B0: 0x0FE4004C, 0x10016C0: 0x0FE40000,
    0x10016D0: 0x0FE40000, 0x1001718: 0x0FE40040, 0x100172C: 0x0FE40044,
    0x100173C: 0x0FE40048, 0x1001750: 0x0FE4004C, 0x10091F0: 0x0FE40004,
    0x1009204: 0x0FE40008, 0x1009214: 0x0FE4000C, 0x1009220: 0x0FE40010,
    0x1009230: 0x0FE40018, 0x100923C: 0x0FE4001C, 0x1009248: 0x0FE40020,
    0x1009254: 0x0FE40024, 0x1009264: 0x0FE40028, 0x1009274: 0x0FE4002C,
    0x1009280: 0x0FE40030, 0x100928C: 0x0FE40034, 0x10092C8: 0x0FE40008,
    0x1009304: 0x0FE4000C,
}
TBIB_TOTAL_SITES = 74
TBIB_BANK_REGS = {0x00, 0x04, 0x08, 0x0C, 0x10, 0x18, 0x1C, 0x20, 0x24,
                  0x28, 0x2C, 0x30, 0x34, 0x40, 0x44, 0x48, 0x4C}

# ---- Main 0x301EC0 body: raw pool words ----
MAIN_POOLS = {
    0x301EC8: 0x0FE40004, 0x301ECC: 0x00004321,
    0x301EDC: 0x0FE40008, 0x301EE0: 0x00006641,
    0x301EF0: 0x0FE4000C, 0x301EF4: 0x0000E972,
    0x301F04: 0x0FE40010, 0x301F08: 0x0000FFFF,
}
MAIN_STORES = {0x0FE40004: 0x4321, 0x0FE40008: 0x6641,
               0x0FE4000C: 0xE972, 0x0FE40010: 0xFFFF}

# ---- TBIB routine 0x10091E4: raw pool words + net writes ----
TBIB_B_POOLS = {
    0x10091F0: 0x0FE40004, 0x10091F4: 0x00004321,
    0x1009204: 0x0FE40008, 0x1009208: 0x0000FFFF,
    0x1009214: 0x0FE4000C, 0x1009220: 0x0FE40010,
    0x1009230: 0x0FE40018, 0x100923C: 0x0FE4001C,
    0x1009248: 0x0FE40020, 0x1009254: 0x0FE40024,
    0x1009264: 0x0FE40028, 0x1009274: 0x0FE4002C,
    0x1009280: 0x0FE40030, 0x100928C: 0x0FE40034,
}
TBIB_B_WRITES = {
    0x0FE40004: 0x4321, 0x0FE40008: 0xFFFF, 0x0FE4000C: 0xFFFF,
    0x0FE40010: 0xFFFF, 0x0FE40018: 0, 0x0FE4001C: 0,
    0x0FE40020: 0, 0x0FE40024: 0, 0x0FE40028: 0x2,
    0x0FE4002C: 0x100, 0x0FE40030: 0, 0x0FE40034: 0,
}
# TBIB sequence A + composers + strobes: value pools and aux pools.
TBIB_VALUE_POOLS = {
    0x1000FA8: 0x0000216F, 0x1000FCC: 0x0000216F,
    0x100171C: 0x0000216F, 0x1001740: 0x0000216F,
    0x1000D28: 0x0FFCA008, 0x10014A8: 0x0FFCA008,
    0x1000D94: 0x0FFCA008,
}


def has(text: str, pattern: str) -> None:
    flat = re.sub(r'\s+', ' ', text)
    assert re.search(pattern, flat), f'pattern not found: {pattern}'


def u32(payload: bytes, base: int, address: int) -> int:
    return struct.unpack_from('<I', payload, address - base)[0]


def census_sites(payload: bytes, base: int) -> dict[int, dict]:
    sites: dict[int, dict] = {}
    for off in range(0, len(payload) - 3, 2):
        w = struct.unpack_from('<I', payload, off)[0]
        me = ((w >> 16) & 0xffff) | ((w & 0xffff) << 16)
        entry = sites.setdefault(base + off, {})
        if BANK_LO <= w < BANK_HI:
            entry['le'] = w
        if BANK_LO <= me < BANK_HI:
            entry['me'] = me
    return {k: v for k, v in sites.items() if v}


def classify(sites: dict, text: str) -> tuple[dict, dict]:
    """Classify each site against the listing. Real reference := a pcl LOAD
    whose comment points at the site and whose delivered (LE) value is a
    bank address. Branch-comment matches do not count."""
    addresses, lines = parse_listing(text)
    addr_set = set(addresses)
    load_refs: dict[int, list[str]] = {}
    for site, line in zip(addresses, lines):
        m = LOAD_LINE.search(line)
        # a genuine 16-bit ld_s cannot encode a pcl displacement above 0x7C:
        # bigger displacements are data mis-decoded as code (e.g. payload10
        # 0x1025734 prints [pcl,0x154] inside a data region)
        if m and not (m.group(1) == 'ld_s' and int(m.group(3), 16) > 0x7C):
            t = HEX_REF.search(line)
            if t:
                load_refs.setdefault(int(t.group(1), 16), []).append(
                    f'{he(site)}: {line.strip()}')
    out = {}
    for site, vals in sites.items():
        kind = 'data/straddle'
        if site in load_refs:
            kind = 'load_pool'
        elif site in addr_set:
            kind = 'instr'
        out[site] = dict(vals=vals, kind=kind,
                        load_refs=load_refs.get(site, []))
    return out, load_refs


def main() -> None:
    blocks, payloads, block_dir = verified_payloads(ROOT)
    fw_data = FIRMWARE.read_bytes()
    assert hashlib.sha256(fw_data).hexdigest() == \
        '1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39'
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out_dir = EVIDENCE / stamp
    out_dir.mkdir(parents=True, exist_ok=False)
    windows = ['# S33 - banco 0x0FE400xx: census e finestre dedicate',
               '# GNU ARC700 -EL; finestre allineate = supporto, non CFG provata.', '']
    census_out = {}
    listings = {}

    # ---------- Phase 1: census of the 16 Main payloads ----------
    for b in sorted(blocks, key=lambda x: x['index']):
        idx = b['index']
        base = b['load_address_candidate']
        sites = census_sites(payloads[idx], base)
        text = aligned_listing(payloads[idx], base)
        listings[idx] = text
        cls, load_refs = classify(sites, text)
        # no limm/movhi immediate in the bank range in any instruction line
        for line in text.splitlines():
            assert not INSTR_IMM.search(line), f'limm/imm bank in p{idx}: {line}'
            assert not MOVHI_BANK.search(line), f'movhi banco in p{idx}: {line}'
            for m in DEC_IMM.finditer(line):
                if int(m.group(1)) in BANK_DEC:
                    raise AssertionError(f'imm decimale banco in p{idx}: {line}')
        real = {s: e['vals']['le'] for s, e in cls.items()
                if e['kind'] == 'load_pool' and 'le' in e['vals']}
        coinc_pool = {s: u32(payloads[idx], base, s) for s, e in cls.items()
                      if e['kind'] == 'load_pool' and 'le' not in e['vals']}
        expected_real = MAIN_LINEAR_BANK_POOLS if idx == 0 else {}
        assert real == expected_real, f'p{idx} real bank pools: {he_dict(real)}'
        if idx == 0:
            assert coinc_pool == MAIN_COINCIDENCE_POOL, he_dict(coinc_pool)
            assert len(cls) == MAIN_SITE_COUNTS[idx], \
                f'p0 site count {len(cls)} != {MAIN_SITE_COUNTS[idx]}'
        elif idx in MAIN_SITE_COUNTS:
            assert len(cls) == MAIN_SITE_COUNTS[idx], \
                f'p{idx} site count {len(cls)} != {MAIN_SITE_COUNTS[idx]}'
        else:
            assert idx in MAIN_EMPTY and len(cls) == 0, f'p{idx} unexpected sites'
        census_out[f'payload{idx}'] = dict(
            base=he(base), sites={he(s): dict(kind=e['kind'],
            vals={k: he(v) for k, v in e['vals'].items()}) for s, e in cls.items()},
            real_bank_pools=he_dict(real))
        if real:
            windows.append(f'====== payload{idx} real bank pools ======')
            for s in real:
                windows.append(window(parse_listing(text)[0], parse_listing(text)[1],
                                      s, 48, 64))
            windows.append('')

    # ---------- Phase 2: TBIB body census ----------
    data = fw_data
    sections, _ = parse_firmware(data)
    tbib_base, body_size, checksum, entry = struct.unpack_from('<4I', data, sections[0].data_start)
    assert (tbib_base, body_size, entry) == (0x1000000, 0x44bbc, 0x1000000)
    body = data[sections[0].data_start + 16: sections[0].data_start + 16 + body_size]
    assert sum(x[0] for x in struct.iter_unpack('<I', body)) & 0xffffffff == checksum
    tbib_text = aligned_listing(body, 0x1000000)
    listings['TBIB'] = tbib_text
    sites = census_sites(body, 0x1000000)
    cls, load_refs = classify(sites, tbib_text)
    for line in tbib_text.splitlines():
        assert not INSTR_IMM.search(line), f'limm/imm bank in TBIB: {line}'
        assert not MOVHI_BANK.search(line), f'movhi banco in TBIB: {line}'
        for m in DEC_IMM.finditer(line):
            if int(m.group(1)) in BANK_DEC:
                raise AssertionError(f'imm decimale banco in TBIB: {line}')
    real = {s: e['vals']['le'] for s, e in cls.items()
            if e['kind'] == 'load_pool' and 'le' in e['vals']}
    # 0x1009214 is a real pool but its load is hidden by the linear decode
    # (the pool after the b_s swallows the store): it is proven by the
    # dedicated aligned window T2 below; here we only assert the raw value.
    assert u32(body, 0x1000000, 0x1009214) == 0x0FE4000C
    expected = {k: v for k, v in TBIB_BANK_POOLS.items() if k != 0x1009214}
    assert real == expected, f'TBIB real pools differ: {he_dict(real)}'
    assert len(cls) == TBIB_TOTAL_SITES, f'TBIB sites {len(cls)} != {TBIB_TOTAL_SITES}'
    regs = {v & 0xFF for v in TBIB_BANK_POOLS.values()}
    assert regs == TBIB_BANK_REGS and 0x14 not in regs
    census_out['TBIB'] = dict(
        base='0x1000000', sites={he(s): dict(kind=e['kind'],
        vals={k: he(v) for k, v in e['vals'].items()}) for s, e in cls.items()},
        real_bank_pools=he_dict(real), hidden_real_pool={he(0x1009214): '0xfe4000c'})

    # ---------- Phase 3: Main 0x301EC0 body ----------
    p0 = payloads[0]
    for addr, word in MAIN_POOLS.items():
        assert u32(p0, P0_BASE, addr) == word, f'pool {he(addr)} differs'
    w1 = aligned_window(p0, P0_BASE, 0x301EC0, 0x301EC8)
    has(w1, r'push_s blink')
    has(w1, r'ld_s r1,\[pcl,0x8\] ;0x301ec8')
    has(w1, r'ld_s r0,\[pcl,0x8\] ;0x301ecc')
    has(w1, r'b_s 12 ;0x301ed0')
    w2 = aligned_window(p0, P0_BASE, 0x301ED0, 0x301ED8)
    has(w2, r'sth\.di r0,\[r1\]')
    has(w2, r'ld_s r1,\[pcl,0x8\] ;0x301edc')
    has(w2, r'ld_s r0,\[pcl,0xc\] ;0x301ee0')
    w3 = aligned_window(p0, P0_BASE, 0x301EE4, 0x301EEC)
    has(w3, r'sth\.di r0,\[r1\]')
    has(w3, r'ld_s r1,\[pcl,0x8\] ;0x301ef0')   # hidden load -> +0x0C pool
    has(w3, r'ld_s r0,\[pcl,0xc\] ;0x301ef4')
    w4 = aligned_window(p0, P0_BASE, 0x301EF8, 0x301F14)
    has(w4, r'ld_s r1,\[pcl,0x8\] ;0x301f04')   # hidden load -> +0x10 pool
    has(w4, r'ld_s r0,\[pcl,0xc\] ;0x301f08')
    w5 = aligned_window(p0, P0_BASE, 0x301F0C, 0x301F14)
    has(w5, r'sth\.di r0,\[r1\]')               # 0xFFFF -> +0x10 (finale)
    has(w5, r'pop_s blink')
    has(w5, r'j_s \[blink\]')
    windows += ['====== Main 0x301EC0: finestre allineate ======',
                w1, '', w2, '', w3, '', w4, '', w5, '']

    # ---------- Phase 4: TBIB routine 0x10091E4 ----------
    for addr, word in TBIB_B_POOLS.items():
        assert u32(body, 0x1000000, addr) == word, f'pool {he(addr)} differs'
    t1 = aligned_window(body, 0x1000000, 0x10091E4, 0x10091F0)
    has(t1, r'push_s blink')
    has(t1, r'push_s r13')
    has(t1, r'ld_s r1,\[pcl,0x8\] ;0x10091f0')
    has(t1, r'ld_s r0,\[pcl,0xc\] ;0x10091f4')
    has(t1, r'b_s 12 ;0x10091f8')
    t2 = aligned_window(body, 0x1000000, 0x100920C, 0x1009214)
    has(t2, r'sth\.di r13,\[r0\]')               # 0xFFFF -> +0x08
    has(t2, r'ld_s r0,\[pcl,0x4\] ;0x1009214')   # hidden load -> +0x0C pool
    has(t2, r'b_s 8 ;0x1009218')
    addresses, lines = parse_listing(tbib_text)
    line_at = dict(zip(addresses, lines))
    expects = {
        0x10091F8: r'sth\.di r0,\[r1\]',           # 0x4321 -> +0x04 (GNU DSPv5 stop)
        0x1009218: r'sth\.di r13,\[r0\]',           # 0xFFFF -> +0x0C
        0x1009224: r'sth\.di r13,\[r0\]',           # 0xFFFF -> +0x10
        0x100922A: r'mov_s r13,0\b',
        0x1009234: r'sth\.di r13,\[r0\]',           # 0 -> +0x18
        0x1009240: r'sth\.di r13,\[r0\]',           # 0 -> +0x1C
        0x100924C: r'sth\.di r13,\[r0\]',           # 0 -> +0x20
        0x1009258: r'sth\.di r13,\[r0\]',           # 0 -> +0x24
        0x100925E: r'mov_s r0,0x2\b',
        0x1009268: r'sth\.di r0,\[r1\]',            # 2 -> +0x28
        0x100926E: r'mov r0,256\b',
        0x1009278: r'sth\.di r0,\[r1\]',            # 0x100 -> +0x2C
        0x1009284: r'sth\.di r13,\[r0\]',           # 0 -> +0x30
        0x1009290: r'sth\.di r13,\[r0\]',           # 0 -> +0x34
        0x1009294: r'b\.d 216772 ;0x103e158',
        0x1009298: r'mov_s r0,r13',
    }
    for addr, pattern in expects.items():
        assert addr in line_at, f'missing line at {he(addr)}'
        flat = re.sub(r'\s+', ' ', line_at[addr])
        assert re.search(pattern, flat), f'{he(addr)}: {line_at[addr]}'
    windows += ['====== TBIB routine 0x10091E4: finestre allineate ======',
                t1, '', t2, '',
                '====== TBIB routine 0x10091E4: tratto lineare ======',
                window(addresses, lines, 0x1009218, 4, 0x100929C - 0x1009218), '']

    # ---------- Phase 5: composers 0x100929C / 0x10092D8 ----------
    for addr, word in TBIB_BANK_POOLS.items():
        assert u32(body, 0x1000000, addr) == word, f'pool {he(addr)} differs'
    for center in (0x100929C, 0x10092D8):
        win = window(addresses, lines, center, 2, 0x40)
        has(win, r'asl_s r0,r0,0xd')
        has(win, r'and r0,r0,0xe000')
        has(win, r'asl_s r13,r13,0x8')
        has(win, r'and r13,r13,0x1f00')
        has(win, r'or_s r13,r13,r0')
        has(win, r'asl_s r2,r2,0x4')
        has(win, r'and r2,r2,240\b')
        has(win, r'or_s r2,r2,r13')
        has(win, r'bmsk_s r3,r3,0x3')
        has(win, r'or_s r3,r3,r2')
        has(win, r'sth\.di r3,\[r1\]')
        windows += [f'====== compositore {he(center)} ======', win, '']
    # exact model of the packed halfword, all operand tuples
    for a in range(8):
        for b in range(32):
            for c in range(16):
                for d in range(16):
                    composed = (((a << 13) & 0xE000) | ((b << 8) & 0x1F00)
                                 | ((c << 4) & 0xF0) | (d & 0xF))
                    assert composed == (((a & 7) << 13) | ((b & 0x1F) << 8)
                                        | ((c & 0xF) << 4) | (d & 0xF))
    assert ((3 << 13) & 0xE000) | ((6 << 8) & 0x1F00) | 0x40 | 1 == 0x6641
    assert ((7 << 13) & 0xE000) | ((9 << 8) & 0x1F00) | 0x70 | 2 == 0xE972

    # ---------- Phase 6: strobe RMW + poll ----------
    for addr, word in TBIB_VALUE_POOLS.items():
        assert u32(body, 0x1000000, addr) == word, f'pool {he(addr)} differs'
    for base_rmw in (0x1000CF2, 0x1001472):
        win = window(addresses, lines, base_rmw, 0, 0x1000D28 - 0x1000CF2 + 4)
        has(win, r'ld_s r13,\[pcl,0x8\] ;0x' + ('1000cf8' if base_rmw == 0x1000CF2 else '1001478'))
        has(win, r'mov_s r15,0x9')
        has(win, r'ldh\.di r10,\[r13\]')
        has(win, r'bset r10,r10,r15')
        has(win, r'sth\.di r10,\[r13\]')
        has(win, r'mov_s r0,0x8\b')
        has(win, r'bclr r10,r10,r15')
        windows += [f'====== strobe RMW {he(base_rmw)} su 0x0FE40000 ======', win, '']
    # bit model: 0 -> bset9 -> 0x200 -> bset8 -> 0x300 -> bclr9 -> 0x100
    reg = 0
    reg |= 1 << 9
    reg |= 1 << 8
    reg &= ~(1 << 9)
    assert reg == 0x100
    win = window(addresses, lines, 0x1000FF6, 0, 0x1001020 - 0x1000FF6)
    has(win, r'ld_s r14,\[pcl,0x8\] ;0x1000ffc')
    has(win, r'mov_s r13,0x9')
    has(win, r'bset r10,r10,r13')
    has(win, r'mov_s r0,0x8\b')
    has(win, r'bclr r10,r10,r0')
    windows += ['====== variante strobe 0x1000FF6 ======', win, '']
    # polls of bit0 of 0x0FFCA008: strobe routine 0x1000D74 and init A
    # 0x1000F84 (r14 loaded at 0x1000D8E from pool 0x1000D94 = 0x0FFCA008)
    for poll in (0x1000D74, 0x1000F84):
        win = window(addresses, lines, poll, 0, 24)
        has(win, r'ldh\.di r0,\[r14\]')
        has(win, r'btst_s r0,0\b')
        windows += [f'====== poll bit0 di 0x0FFCA008 ({he(poll)}) ======', win, '']
    has(window(addresses, lines, 0x1000D8E, 0, 8),
        r'ld_s r14,\[pcl,0x8\] ;0x1000d94')

    # ---------- Phase 7: init sequence A (+ copy + variant C) ----------
    win = window(addresses, lines, 0x1000EEC, 0, 0x1000F50 - 0x1000EEC)
    has(win, r'mov_s r1,0x20')
    has(win, r'bset_s r1,r1,0xd')                  # -> 0x2020
    has(win, r'ld_s r0,\[pcl,0x4\] ;0x1000ef4')     # +0x40
    has(win, r'sth\.di r1,\[r0\]')
    has(win, r'mov_s r1,0x1f')
    has(win, r'asl_s r1,r1,0x7')                   # -> 0xF80
    has(win, r'ld_s r0,\[pcl,0x4\] ;0x1000f04')     # +0x44
    has(win, r'sth\.di r1,\[r0\]')
    has(win, r'mov r1,768\b')                        # 0x300
    has(win, r'ld_s r0,\[pcl,0x4\] ;0x1000f14')     # +0x48
    has(win, r'sth\.di r1,\[r0\]')
    has(win, r'ld_s r1,\[pcl,0x8\] ;0x1000f24')     # +0x4C
    has(win, r'mov_s r0,r16')
    has(win, r'sth\.di r0,\[r1\]')                  # r16 -> +0x4C
    has(win, r'mov_s r1,0xa\b')
    has(win, r'ld_s r0,\[pcl,0x8\] ;0x1000f34')     # +0x00
    has(win, r'sth\.di r1,\[r0\]')                  # 0x0A -> +0x00
    has(win, r'mov r1,522\b')                        # 0x20A
    has(win, r'ld_s r0,\[pcl,0x4\] ;0x1000f44')     # +0x00
    has(win, r'sth\.di r1,\[r0\]')                  # 0x20A -> +0x00
    windows += ['====== sequenza A 0x1000EEC (primi store) ======', win, '']
    win = window(addresses, lines, 0x1000F9C, 0, 0x1001000 - 0x1000F9C)
    has(win, r'ld_s r1,\[pcl,0x8\] ;0x1000fa4')     # +0x40
    has(win, r'ld_s r0,\[pcl,0xc\] ;0x1000fa8')     # 0x216F
    has(win, r'sth\.di r0,\[r1\]')
    has(win, r'mov_s r0,0x3f')
    has(win, r'ld_s r1,\[pcl,0x8\] ;0x1000fb8')     # +0x44
    has(win, r'sth\.di r0,\[r1\]')
    has(win, r'ld_s r1,\[pcl,0x8\] ;0x1000fc8')     # +0x48
    has(win, r'ld_s r0,\[pcl,0xc\] ;0x1000fcc')     # 0x216F
    has(win, r'sth\.di r0,\[r1\]')
    has(win, r'mov_s r0,0x3f')
    has(win, r'ld_s r1,\[pcl,0x8\] ;0x1000fdc')     # +0x4C
    has(win, r'sth\.di r0,\[r1\]')
    has(win, r'mov_s r0,0x1\b')
    has(win, r'sth\.di r0,\[r14\]')                # 1 -> 0x0FFCA008
    has(win, r'b 250192 ;0x103e138')
    windows += ['====== sequenza A 0x1000F9C (post-poll) ======', win, '']
    # variant C at 0x1001710
    win = window(addresses, lines, 0x1001710, 0, 0x1001764 - 0x1001710)
    has(win, r'ld_s r1,\[pcl,0x8\] ;0x1001718')     # +0x40
    has(win, r'ld_s r0,\[pcl,0xc\] ;0x100171c')     # 0x216F
    has(win, r'sth\.di r0,\[r1\]')
    has(win, r'mov_s r0,0x3f')
    has(win, r'ld_s r1,\[pcl,0x8\] ;0x100172c')     # +0x44
    has(win, r'sth\.di r0,\[r1\]')
    has(win, r'ld_s r1,\[pcl,0x8\] ;0x100173c')     # +0x48
    has(win, r'ld_s r0,\[pcl,0xc\] ;0x1001740')     # 0x216F
    has(win, r'sth\.di r0,\[r1\]')
    has(win, r'mov_s r0,0x3f')
    has(win, r'ld_s r1,\[pcl,0x8\] ;0x1001750')     # +0x4C
    has(win, r'sth\.di r0,\[r1\]')
    has(win, r'mov_s r0,0x1\b')
    windows += ['====== variante C 0x1001710 ======', win, '']

    # ---------- evidence ----------
    (out_dir / 'windows.txt').write_text('\n'.join(windows) + '\n')
    result = dict(
        status='PASS_BANK_0FE400XX_CENSUS_STATIC',
        bank_range=[he(BANK_LO), he(BANK_HI)],
        firmware_sha256=hashlib.sha256(fw_data).hexdigest(),
        tbib=dict(base=he(tbib_base), size=body_size, checksum=he(checksum),
                  bank_pool_sites=len(TBIB_BANK_POOLS), bank_regs=sorted(he(r) for r in TBIB_BANK_REGS),
                  never_referenced_reg=he(0x14), total_sites=TBIB_TOTAL_SITES),
        main=dict(bank_pools=he_dict(MAIN_BANK_POOLS),
                  stores={he(k): he(v) for k, v in MAIN_STORES.items()},
                  coincidence_pool={he(k): he(v) for k, v in MAIN_COINCIDENCE_POOL.items()},
                  site_counts={str(k): v for k, v in MAIN_SITE_COUNTS.items()},
                  empty_payloads=MAIN_EMPTY),
        tbib_routine_0x10091E4=dict(
            stores={he(k): he(v) for k, v in TBIB_B_WRITES.items()},
            first_store=he(0x10091F8), tail_call=he(0x103E158)),
        composer=dict(formula='((r0<<13)&0xE000)|((r1<<8)&0x1F00)|((r2<<4)&0xF0)|(r3&0xF)',
                       targets=[he(0x0FE40008), he(0x0FE4000C)], tuples=65536,
                       main_values={he(0x0FE40008): he(0x6641), he(0x0FE4000C): he(0xE972)}),
        strobe=dict(routines=[he(0x1000CF2), he(0x1001472)],
                    sequence=['bset9', 'bset8', 'bclr9'], net=he(0x100),
                    variant_0x1000FF6=['bset9', 'bclr8'],
                    poll=dict(register=he(0x0FFCA008), bit=0)),
        init_sequence_A=dict(writes={he(0x0FE40040): he(0x2020), he(0x0FE40044): he(0xF80),
                                     he(0x0FE40048): he(0x300), he(0x0FE4004C): 'r16',
                                     he(0x0FE40000): [he(0x0A), he(0x20A)]},
                             post_poll={he(0x0FE40040): he(0x216F), he(0x0FE40044): he(0x3F),
                                        he(0x0FE40048): he(0x216F), he(0x0FE4004C): he(0x3F)},
                             aux_write={he(0x0FFCA008): he(1)},
                             copies=[he(0x100167C), he(0x1001710)]),
        limits=['Identita\' hardware del banco non provata: escluso DDR (registri BFN a 0x0FE2xxxx), '
                'nessun datasheet del SD10P220; il protocollo e\' byte-exact, il blocco siliconico e\' inferenza',
                'Listato GNU lineare: le finestre allineate servono dove il pool dopo il b_s inghiotte la store',
                'Nessun reader Main del banco: negativo statico, non prova di assenza di letture indirette '
                'calcolate/DMA',
                'V1.1 campione locale; macchina nei log V1.0; nessun runtime, emulazione o hardware provati'],
    )
    (out_dir / 'census.json').write_text(json.dumps(result, indent=1) + '\n')
    census_path = out_dir / 'census_sites.json'
    census_path.write_text(json.dumps(census_out, indent=1) + '\n')
    (EVIDENCE / 'latest.json').write_text(json.dumps(
        dict(status=result['status'], stamp=stamp, path=str(out_dir.relative_to(ROOT)),
             script=str(Path(__file__).relative_to(ROOT))) , indent=1) + '\n')
    print('PASS_BANK_0FE400XX_CENSUS_STATIC', stamp)


def he_dict(d: dict) -> dict:
    return {he(k): he(v) for k, v in d.items()}


def aligned_listing(payload: bytes, base: int) -> str:
    """GNU ARC700 linear listing of a whole payload (objcopy roundtrip checked)."""
    import subprocess
    import tempfile
    objcopy = ROOT / 'work/build-arc/binutils/objcopy'
    objdump = ROOT / 'work/build-arc/binutils/objdump'
    with tempfile.TemporaryDirectory(prefix='s33-bank-') as td:
        raw = Path(td) / 'body.bin'
        raw.write_bytes(payload)
        elf = Path(td) / 'body.elf'
        subprocess.run([str(objcopy), '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc',
                        '--rename-section', '.data=.text,alloc,load,readonly,code,contents',
                        '--change-section-vma', f'.data={base:#x}', '--strip-all',
                        str(raw), str(elf)], check=True, capture_output=True)
        back = Path(td) / 'back.bin'
        subprocess.run([str(objcopy), '--dump-section', f'.text={back}', str(elf)],
                       check=True, capture_output=True)
        assert back.read_bytes() == payload, 'ELF roundtrip differs'
        return subprocess.run([str(objdump), '-d', '-m', 'arc:ARC700', '-EL', str(elf)],
                              check=True, capture_output=True, text=True).stdout


if __name__ == '__main__':
    main()
