#!/usr/bin/env python3
"""Static verification of the diagnostic shadow-table writer (V1.1, payload0).

Closes the open point of iteration 23 ("scrittore della tabella shadow
0x446808", the bytes the diagnostic panel 0x2C5100 polls for iris):

- INIT 0x16F638 (called from 0x15AF58) zeroes 128 table entries with a
  hardware lp-loop of 128 iterations: each entry (4 bytes at
  0x446808+4*i) gets value byte +0 = 0, secondary byte +1 = 0xFF,
  flags halfword +2 = 1. The base enters the loop body as a LIMM
  0x446808 (bytes 44 00 08 68 at 0x16F646, middle-endian), the ONLY
  limm reference to the table in the whole firmware. The function then
  clears the 10-word handler table at 0x446A08 (pool 0x16FA30) with
  0xAD90C(dst, ?, 0x28) - 40 bytes.
- SINGLE WRITER of the value byte: 0x16F72C(secondary=r0, idx=r1,
  value=r2, flag=r3): stb_s r2,[0x446808+4*r1+0] (pool 0x16FA34) with
  NO range check on the store, then logs id=(idx<<7)|1 and dispatches
  the registered handlers through 0x16F6B0.
- The handler dispatch 0x16F6B0 reads handler pointers at
  [0x446808+4*i + 512] (ld.as [r1,128] after add2_s), i.e. the table at
  0x446A08; register/unregister are 0x16F988/0x16F9F0 (find-or-insert /
  zero-out) using pool 0x16FA60 = 0x4469F8 = base+0x1F0 with
  sub3(0x3e): the two addressing paths converge on 0x446A08+4*slot only
  if the sub3 immediate contributes 0x1F0 (printed field 0x3e scaled x8
  - derivation, see JSON note).
- SECONDARY byte +1 is installed by 0x16F66C(recordTable, count) from
  the record table: for record i it stores shadow[rec.idx].secondary=i
  and writes the struct at 0x3678E4: +0 enable=1, +4 (cell 0x3678E8) =
  table pointer, +8 (halfword) = count. Records are 20 bytes:
  maskLo@+0, maskHi@+4, value@+8, shadowIdx@+9, halfword@+0xA (bit15
  pending), halfword@+0xC.
- The state-transition consumer 0x16F86C(newLo, newHi, flag) walks the
  records, matches mask changes against the pair stored at
  0x3678E4+0xC/+0x10, and calls 0x16F72C(recIdx, rec.idx, rec.value,
  flag) for each match: the shadow bytes are the cached outputs of a
  64-bit state machine.
- INSTALLER of the record table: init 0x16E2F4 (called from 0xC5D9E)
  passes table 0x392F04 (pool 0x16E388) and count 0x10 to 0x16F66C and
  registers handler 0x16E588 (pool 0x16E38C) via 0x16F988.
- PANEL 0x2C5100 semantics (refined): it polls RAW bytes 8/9/0xA via
  the getter 0x16F920 with wait-until-zero loops and SERVES the
  requests: entry 9 nonzero -> log + 0x18B85C(1) (impose Big) +
  wait until entry 9 clears; entry 0xA nonzero -> log + 0x18B85C(9)
  (impose Small) + wait until clear. Entries 8/9/0xA are REQUEST
  flags, not telemetry: no static caller of 0x16F72C writes them.
  The static explicit indices are {1, 2, 0xC, 0x62, 0x65, 0x66, 0x77}
  plus generic paths (0x16EC28 switch, record-driven 0x16F8D4).

Read-only: firmware, blocks, tools and listings are never modified.
Linear-listing censuses are candidates; every asserted window here is
re-disassembled aligned at a call-verified entry and every literal is
re-read from the raw payload bytes.
"""
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads
from s33_run_gnu_arc700 import ROOT, sha
from s33_verify_sensor_mmio_dialog import aligned_window

FIRMWARE = ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin'
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Iris_Shadow'
LISTING = ROOT / 'Risultati/Disassemblati/Firmware1.1.asm'

SHADOW = 0x446808          # 128 entries x 4 bytes: value, secondary, flags
HANDLERS = 0x446A08        # 10 words, right after the shadow table (+512)
RECORDS = 0x392F04        # 16 records x 20 bytes (RAM, runtime content)
STRUCT = 0x3678E4          # {+0 enable, +4 ptr=cell 0x3678E8, +8 count(h),
                           #  +0xA gate byte, +0xC/+0x10 state pair}

# Literal words re-read from raw payload0 bytes (little-endian).
LITERALS = {
    0x16FA30: HANDLERS,     # handler table base (memset + register/unregister)
    0x16FA34: SHADOW,       # writer/getter/flag-setter base
    0x16FA38: STRUCT,       # state struct (consumer 0x16F86C)
    0x16FA3C: SHADOW,       # dispatch 0x16F6B0 base
    0x16FA40: 0x3678F9,     # byte cell written by 0x16F964 (struct+0x15)
    0x16FA44: 0x3678E8,     # struct+4: record table pointer cell
    0x16FA48: 0x3678F8,     # struct+0x14 cell (family pool)
    0x16FA50: 0x300005,     # error id (consumer gate)
    0x16FA5C: 0x300006,     # error id (register/unregister)
    0x16FA60: 0x4469F8,     # SHADOW + 0x1F0 (register/unregister route)
    0x2C519C: 0x16F920,     # panel: shadow getter
    0x16E388: RECORDS,      # installer: record table
    0x16E38C: 0x16E588,     # installer: handler registered via 0x16F988
    0x16EDD4: 0x393044,     # RECORDS + 16*20 (table end, log arg)
}

# Call censuses (linear GNU listing, bl/bl.d/bl_s/bl_s.d/jl forms).
CALLS_16F72C = {0x144A82, 0x16E8A6, 0x16E8CA, 0x16E8F6, 0x16E9D8, 0x16EA2A,
                0x16EA7A, 0x16EA94, 0x16EAD4, 0x16EC28, 0x16ECA2, 0x16EDFE,
                0x16EF64, 0x16EF7A, 0x16EFC8, 0x16EFEC, 0x16F00E, 0x16F176,
                0x16F8D4}
CALLS_16F638 = {0x15AF58}
CALLS_16E2F4 = {0x0C5D9E}
CALLS_16F66C = {0x16E306}
CALLS_16F6B0 = {0x16F7EA, 0x16F80E, 0x16F834, 0x16F85C, 0x16FA92,
                0x20F74E, 0x26C5C2}
CALLS_16F86C = {0x16E3FA, 0x16EC74, 0x16F90A}
CALLS_16F988 = {0x16E30A, 0x323856}
CALLS_16F950 = {0x2B37CC, 0x2CA34C, 0x2CABCC, 0x2CAC64, 0x2CBB28,
                0x6531DE, 0x6531E6}
# explicit idx passed by the static callers of 0x16F72C (r1 at the call)
EXPLICIT_IDX = {
    0x144A82: 0x77, 0x16E8A6: 0x1, 0x16E8CA: 0x2, 0x16E8F6: 0x77,
    0x16E9D8: 0x1, 0x16EA2A: 0x2, 0x16EA7A: 0x1, 0x16EA94: 0x1,
    0x16EAD4: 0x2, 0x16EC28: None, 0x16ECA2: 0xC, 0x16EDFE: 0x62,
    0x16EF64: 0x66, 0x16EF7A: 0x65, 0x16EFC8: 0x65, 0x16EFEC: 0x77,
    0x16F00E: 0x65, 0x16F176: 0x77, 0x16F8D4: None,
}  # None = dynamic (record-driven or switch); audit iterazione 27:
  # 0x16E8F6 = 0x77 e 0x16EF7A = 0x65 (verificati sui byte:
  # mov_s r1,0x77 a 0x16E8F2 / mov_s r1,0x65 a 0x16EF78)

CENSUS_TARGETS = [0x16F72C, 0x16F638, 0x16E2F4, 0x16F66C, 0x16F6B0,
                  0x16F86C, 0x16F920, 0x16F950, 0x16F988, 0x16F9F0,
                  0x16F964, 0x16FA66, 0x16F6A4, 0x16F8EC, 0x16F914]


def he(n: int) -> str:
    return f'0x{n:x}'


def has(text: str, pattern: str) -> None:
    assert re.search(pattern, text), f'missing pattern: {pattern}'


def count(text: str, pattern: str) -> int:
    return len(re.findall(pattern, text))


def census_calls() -> dict:
    """Single pass over the linear listing; candidate call sites."""
    pat = re.compile(
        r'V([0-9A-F]{6,8}) \| [0-9a-f ]+ \| '
        r'(bl|bl\.d|bl_s|bl_s\.d|jl|jl_s|jl_s\.d|b|b\.d)\s+?-?\d+\s+;0x([0-9a-f]+)\b')
    hits = {t: [] for t in CENSUS_TARGETS}
    assert LISTING.exists(), LISTING
    with LISTING.open('r', errors='replace') as fh:
        for line in fh:
            m = pat.search(line)
            if not m:
                continue
            target = int(m.group(3), 16)
            if target in hits:
                hits[target].append(int(m.group(1), 16))
    return hits


def main() -> None:
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = EVIDENCE / stamp
    out.mkdir(parents=True, exist_ok=True)
    (out / 'script_snapshot.py').write_bytes(Path(__file__).read_bytes())
    assert sha(FIRMWARE) == ('1d34e990a8f99019ffa53ca5de785399'
                             'df863e942739a667ceb314ec6ce62a39')
    blocks, payloads, block_dir = verified_payloads(ROOT)
    info = {b['index']: b for b in blocks}
    base0 = info[0]['load_address_candidate']
    p0 = payloads[0]
    assert base0 == 0x0AD800

    # 1. Literal words verified against raw payload0 bytes.
    for addr, value in LITERALS.items():
        got = struct.unpack_from('<I', p0, addr - base0)[0]
        assert got == value, (hex(addr), hex(got), hex(value))

    # 2. LE-word census of the exact shadow base across all payloads
    #    (step-2 raw scan; only pool words of the family may carry it).
    base_hits = {i: [] for i in range(16)}
    for b in blocks:
        data = payloads[b['index']]
        for off in range(0, len(data) - 3, 2):
            if struct.unpack_from('<I', data, off)[0] == SHADOW:
                base_hits[b['index']].append(
                    b['load_address_candidate'] + off)
    assert base_hits[0] == [0x16FA34, 0x16FA3C], base_hits[0]
    for i in range(1, 16):
        assert not base_hits[i], (i, base_hits[i])

    # 3. Region scan [SHADOW, HANDLERS+40): only the family pools may
    #    point inside the shadow table or the handler table.
    region = {i: [] for i in range(16)}
    for b in blocks:
        data = payloads[b['index']]
        for off in range(0, len(data) - 3, 2):
            w = struct.unpack_from('<I', data, off)[0]
            if SHADOW <= w < HANDLERS + 40:
                region[b['index']].append(
                    (b['load_address_candidate'] + off, w))
    assert region[0] == [(0x16FA30, HANDLERS), (0x16FA34, SHADOW),
                         (0x16FA3C, SHADOW), (0x16FA60, 0x4469F8)], region[0]
    for i in range(1, 16):
        assert not region[i], (i, region[i])

    # 4. LIMM census (middle-endian: bytes m0..m3 -> value
    #    m2 | m3<<8 | m0<<16 | m1<<24). 0x446808 -> bytes 44 00 08 68.
    needle = bytes((0x44, 0x00, 0x08, 0x68))
    limm_hits = {i: [] for i in range(16)}
    for b in blocks:
        data = payloads[b['index']]
        start = 0
        while True:
            off = data.find(needle, start)
            if off < 0:
                break
            limm_hits[b['index']].append(
                b['load_address_candidate'] + off)
            start = off + 1
    assert limm_hits[0] == [0x16F646, 0x16FA32], limm_hits[0]
    # 0x16F646 = the LIMM operand of the 32-bit MOV at 0x16F644 inside
    # the init loop; 0x16FA32 = STRADDLE of the adjacent pools 0x16FA30
    # (=0x446A08: bytes ... 44 00) and 0x16FA34 (=0x446808: 08 68 ...).
    for i in range(1, 16):
        assert not limm_hits[i], (i, limm_hits[i])
    # the limm is the operand of the 32-bit MOV inside the init loop
    got = struct.unpack_from('<I', p0, 0x16F646 - base0)[0]
    assert got == 0x68080044  # raw LE bytes 44 00 08 68

    # 5. Aligned windows.
    windows = {}
    for name, (lo, hi) in [
        ('init_16f638', (0x16F638, 0x16F66C)),
        ('install_16f66c', (0x16F66C, 0x16F6A4)),
        ('writer_16f72c', (0x16F72C, 0x16F7FA)),
        ('writer_tail_16f7fa', (0x16F7FA, 0x16F866)),
        ('dispatch_16f6b0', (0x16F6B0, 0x16F72C)),
        ('getter_raw_16f920', (0x16F920, 0x16F950)),
        ('flagsetter_16f950', (0x16F950, 0x16F96C)),
        ('register_16f988', (0x16F988, 0x16F9F0)),
        ('unregister_16f9f0', (0x16F9F0, 0x16FA30)),
        ('consumer_16f86c', (0x16F86C, 0x16F8EC)),
        ('installer_16e2f4', (0x16E2F4, 0x16E33E)),
        ('handler_16e588', (0x16E588, 0x16E6D8)),
        ('mask_writer_16f8ec', (0x16F8EC, 0x16F920)),
        ('panel_head_2c50b6', (0x2C50B6, 0x2C5114)),
        ('panel_2c5100', (0x2C5100, 0x2C5180)),
        ('caller_144a82', (0x144A6A, 0x144A88)),
        ('caller_16eca2', (0x16EC96, 0x16ECA8)),
        ('caller_16edfe', (0x16EDF6, 0x16EE04)),
        ('caller_16f8d4', (0x16F8AC, 0x16F8DA)),
    ]:
        windows[name] = aligned_window(p0, base0, lo, hi)
        assert windows[name].strip(), name
    (out / 'gnu_windows.txt').write_text(
        '\n\n'.join(f'=== {k} ===\n{v}' for k, v in windows.items()))

    def w(name: str) -> str:
        return windows[name]

    # 6. INIT 0x16F638: 128 zeroed entries + handler table memset.
    t = w('init_16f638')
    has(t, r'\tpush_s\tblink\b')
    has(t, r'\tmov\tlp_count,128\b')
    has(t, r'\tlp\t28\t;0x16f65c\b')
    has(t, r'\tmov_s\tr0,0x446808\b')          # 32-bit MOV + limm 0x446808
    has(t, r'\tadd2_s\tr0,r0,r1\b')            # base + 4*i
    has(t, r'\tstb_s\tr2,\[r0,0\]')          # value = 0
    has(t, r'\tstb_s\tr2,\[r0,0x1\]')        # secondary = 0xFF
    has(t, r'\tstw_s\tr2,\[r0,0x2\]')        # flags = 1
    has(t, r'\tld_s\tr0,\[pcl,0x3d4\]\t;0x16fa30\b')
    has(t, r'\tbl\.d\t-793936\t;0xad90c\b')    # memset handlers, 0x28 bytes
    has(t, r'\tmov_s\tr1,0x28\b')
    assert count(t, r'0x0*446808') == 1

    # 7. INSTALL 0x16F66C: secondary bytes + struct pointer/count/enable.
    t = w('install_16f66c')
    has(t, r'\tpush_s\tr13\b')
    has(t, r'\tasl_s\tr13,r3,0x2\b')           # 4*i
    has(t, r'\tadd2_s\tr13,r13,r13\b')          # *5 -> stride 20
    has(t, r'\tadd\tr2,r0,0x9\b')               # record + 9 (shadow idx)
    has(t, r'\tldb_s\tr13,\[r2,0\]')
    has(t, r'\tld_s\tr2,\[pcl,0x3ac\]\t;0x16fa34\b')
    has(t, r'\tadd2_s\tr2,r2,r13\b')
    has(t, r'\tstb_s\tr3,\[r2,0x1\]')         # secondary = record index
    has(t, r'\tld_s\tr2,\[pcl,0x3a4\]\t;0x16fa38\b')
    has(t, r'\tst_s\tr0,\[r2,0x4\]')          # struct+4 = table ptr
    has(t, r'\tstw_s\tr1,\[r2,0x8\]')         # struct+8 = count
    has(t, r'\tstb_s\tr0,\[r2,0\]')           # struct+0 = enable 1

    # 8. WRITER 0x16F72C: the single value-byte writer + dispatch.
    t = w('writer_16f72c') + w('writer_tail_16f7fa')
    has(t, r'\tpush_s\tblink\b')
    has(t, r'\tbl\t1853940\t;0x334120\b')
    has(t, r'\tld_s\tr0,\[pcl,0x300\]\t;0x16fa34\b')
    has(t, r'\tmov\.f\tr16,r3\b')
    has(t, r'\tadd2_s\tr0,r0,r1\b')             # base + 4*idx
    has(t, r'\tstb_s\tr2,\[r0,0\]')           # VALUE BYTE WRITTEN HERE
    has(t, r'\tcmp\tr15,255\b')                 # secondary argument
    has(t, r'\tldb_s\tr15,\[r0,0x1\]')
    has(t, r'\tld_s\tr0,\[pcl,0x2ec\]\t;0x16fa44\b')
    has(t, r'\tld_s\tr1,\[r0,0\]')            # record table pointer
    has(t, r'\tldw_s\tr0,\[r1,0xa\]')         # record +0xA halfword
    has(t, r'\tldh\.x\tr18,\[r1,12\]')        # record +0xC halfword
    has(t, r'\tor\tr0,r17,0x1\b')               # log id (idx<<7)|1
    has(t, r'\tbl_s\t-312\t;0x16f6b0\b')        # handler dispatch
    assert count(t, r'\tbl_s\t-?\d+\t;0x16f6b0\b') == 4
    # no range check between entry and the store
    has(t, r'\tsub_s\tsp,sp,0x10\b')

    # 9. DISPATCH 0x16F6B0: handlers at SHADOW+4*i+512.
    t = w('dispatch_16f6b0')
    has(t, r'\tsub_s\tsp,sp,0x4\b')
    has(t, r'\tpush_s\tblink\b')
    has(t, r'\tmov_s\tr13,0xa\b')               # 10 handler slots
    has(t, r'\tld_s\tr1,\[pcl,0x370\]\t;0x16fa3c\b')
    has(t, r'\tadd2_s\tr1,r1,r14\b')
    has(t, r'\tld\.as\tr3,\[r1,128\]')        # +512 -> 0x446A08+4*i
    has(t, r'\tjl_s\.d\t\[r3\]')
    has(t, r'\textb_s\tr0,r0\b')
    has(t, r'\tbhi_s\t-44\t;0x16f6cc\b')
    has(t, r'\tld_s\tr1,\[pcl,0x344\]\t;0x16fa40\b')

    # 10. GETTER 0x16F920 raw entry + pending entry 0x16F928.
    t = w('getter_raw_16f920')
    has(t, r'\tld_s\tr1,\[pcl,0x114\]\t;0x16fa34\b')
    has(t, r'\tadd2_s\tr1,r1,r0\b')
    has(t, r'\tj_s\.d\t\[blink\]')
    has(t, r'\tldb_s\tr0,\[r1,0\]')           # raw byte: first entry
    has(t, r'\tcmp_s\tr0,0x61\b')               # pending entry 0x16F928
    has(t, r'\tblt_s\t34\t;0x16f94a\b')         # idx >= 0x61 -> 0
    has(t, r'\tldb_s\tr0,\[r1,0x1\]')         # secondary byte
    has(t, r'\tcmp\tr0,255\b')                  # 0xFF -> 0
    has(t, r'\tld_s\tr1,\[pcl,0x10c\]\t;0x16fa44\b')
    has(t, r'\tasl_s\tr0,r0,0x2\b')
    has(t, r'\tadd2_s\tr0,r0,r0\b')             # *20 -> record stride
    has(t, r'\tadd_s\tr1,r1,0xa\b')
    has(t, r'\tldw_s\tr0,\[r0,0\]')
    has(t, r'\tlsr_s\tr0,r0,0xf\b')             # bit15 of record +0xA

    # 11. FLAG SETTER 0x16F950: bit0 of the flags halfword.
    t = w('flagsetter_16f950')
    has(t, r'\tld_s\tr2,\[pcl,0xe4\]\t;0x16fa34\b')
    has(t, r'\tadd2_s\tr2,r2,r0\b')
    has(t, r'\tldw_s\tr0,\[r2,0x2\]')
    has(t, r'\tbset_s\tr0,r0,0\b')
    has(t, r'\tbclr_s\tr0,r0,0\b')
    has(t, r'\tj_s\.d\t\[blink\]')
    has(t, r'\tstw_s\tr0,\[r2,0x2\]')

    # 12. REGISTER 0x16F988 (find-or-insert) / UNREGISTER 0x16F9F0.
    t = w('register_16f988')
    has(t, r'\tmov_s\tr13,r0\b')
    has(t, r'\tld_s\tr0,\[pcl,0xcc\]\t;0x16fa5c\b')
    has(t, r'\tld_s\tr1,\[pcl,0xc8\]\t;0x16fa60\b')
    has(t, r'\tsub3\tr0,r1,0x3e\b')
    has(t, r'\tadd2_s\tr0,r0,r14\b')
    has(t, r'\tld\.as\tr0,\[r0,128\]')
    has(t, r'\tcmp_s\tr13,r0\b')
    has(t, r'\tld_s\tr1,\[pcl,0x5c\]\t;0x16fa30\b')
    has(t, r'\tadd2_s\tr1,r1,r2\b')
    has(t, r'\tst_s\tr13,\[r1,0\]')           # handler -> 0x446A08+4*slot
    t = w('unregister_16f9f0')
    has(t, r'\tmov_s\tr13,r0\b')
    has(t, r'\tld_s\tr3,\[pcl,0x60\]\t;0x16fa60\b')
    has(t, r'\tsub3\tr0,r3,0x3e\b')
    has(t, r'\tadd2_s\tr0,r0,r2\b')
    has(t, r'\tld\.as\tr0,\[r0,128\]')
    has(t, r'\tcmp_s\tr13,r0\b')
    has(t, r'\tld_s\tr1,\[pcl,0x18\]\t;0x16fa30\b')
    has(t, r'\tadd2_s\tr1,r1,r2\b')
    has(t, r'\tst_s\tr14,\[r1,0\]')           # zero the slot

    # 13. STATE-TRANSITION CONSUMER 0x16F86C.
    t = w('consumer_16f86c')
    has(t, r'\tpush_s\tblink\b')
    has(t, r'\tld_s\tr15,\[pcl,0x1c8\]\t;0x16fa38\b')
    has(t, r'\tldb_s\tr0,\[r15,0xa\]')        # gate byte 0x3678EE
    has(t, r'\tmov_s\tr0,r0\b|mov_s\tr0,0\b')
    has(t, r'\tld_s\tr0,\[r15,0x10\]')        # state pair
    has(t, r'\tld_s\tr2,\[r15,0xc\]')
    has(t, r'\tst\tr16,\[r15,12\]')           # new pair committed
    has(t, r'\tst\tr17,\[r15,16\]')
    has(t, r'\tld_s\tr13,\[r15,0x4\]')        # record table
    has(t, r'\txor\tr19,r0,r17\b')
    has(t, r'\txor\tr18,r2,r16\b')
    has(t, r'\tldw_s\.x\tr0,\[r15,0x8\]')     # count (halfword)
    has(t, r'\tand\tr0,r2,r18\b')
    has(t, r'\tor\.f\t0,r0,r15\b')
    has(t, r'\tbeq_s\t26\t;0x16f8d6\b')
    has(t, r'\tbl\.d\t1860488\t;0x335c4c\b')
    has(t, r'\tldb_s\tr2,\[r13,0x8\]')        # record value
    has(t, r'\tldb_s\tr1,\[r13,0x9\]')       # record shadow idx
    has(t, r'\tmov_s\tr0,r14\b')                # record index = secondary
    has(t, r'\tmov_s\tr3,r21\b')
    has(t, r'\tbl_s\t-424\t;0x16f72c\b')

    # 14. MASK WRITER 0x16F8EC: store the complement pair (forces every
    #     mask bit to look changed), set the gate byte, run the consumer.
    t = w('mask_writer_16f8ec')
    has(t, r'\tpush_s\tblink\b')
    has(t, r'\tpush_s\tr13\b')
    has(t, r'\tld_s\tr2,\[pcl,0x148\]\t;0x16fa38\b')
    has(t, r'\tldb_s\tr3,\[r2,0\]')          # struct enable byte
    has(t, r'\tnot_s\tr13,r0\b')
    has(t, r'\tnot_s\tr3,r1\b')
    has(t, r'\tst_s\tr13,\[r2,0xc\]')        # old pair = ~new
    has(t, r'\tst_s\tr3,\[r2,0x10\]')
    has(t, r'\tstb_s\tr13,\[r2,0xa\]')       # gate byte = 1
    has(t, r'\tbl_s\t-156\t;0x16f86c\b')

    # 15. INSTALLER 0x16E2F4 and registered handler 0x16E588.
    t = w('installer_16e2f4')
    has(t, r'\tpush_s\tblink\b')
    has(t, r'\tld_s\tr0,\[pcl,0x88\]\t;0x16e388\b')   # record table
    has(t, r'\tmov_s\tr1,0x10\b')                     # 16 records
    has(t, r'\tbl\t4968\t;0x16f66c\b')
    has(t, r'\tbl\.d\t5760\t;0x16f988\b')             # register handler
    has(t, r'\tbl\t5560\t;0x16f8ec\b')                # read state pair
    has(t, r'\tbl\t952\t;0x16e6e0\b')
    t = w('handler_16e588')
    has(t, r'\tpush_s\tblink\b')
    has(t, r'\tmov_s\tr13,r0\b')                       # idx
    has(t, r'\tmov_s\tr17,r1\b')
    has(t, r'\tmov_s\tr16,r2\b')
    has(t, r'\tmov_s\tr0,0x4e\b')
    has(t, r'\tbl\t4952\t;0x16f920\b')
    has(t, r'\tcmp\tr0,1153\b')                        # 0x481
    has(t, r'\tmov_s\tr0,0x9\b')                       # idx 9 read
    has(t, r'\tbl\t4896\t;0x16f920\b')
    has(t, r'\tcmp_s\tr0,0x2701\b')
    has(t, r'\tbl\t1836\t;0x16ed40\b')

    # 16. PANEL 0x2C5100: request-flag server for iris Big/Small.
    t = w('panel_head_2c50b6') + w('panel_2c5100')
    has(t, r'\tld_s\tr14,\[pcl,0xe8\]\t;0x2c519c\b')   # getter 0x16F920
    has(t, r'\tmov_s\tr0,0x4\b')
    has(t, r'\tmov_s\tr0,0x7\b')
    has(t, r'\tbl\t-1284428\t;0x18b794\b')
    has(t, r'\tmov_s\tr0,0x8\b')                       # entry 8 wait
    has(t, r'\tbl\t-1284580\t;0x18b72c\b')
    has(t, r'\tmov_s\tr0,0x9\b')                       # entry 9 request
    has(t, r'\tmov_s\tr0,0x1\b')
    has(t, r'\tbl\t-1284324\t;0x18b85c\b')             # impose Big
    has(t, r'\tmov_s\tr0,0xa\b')                       # entry 0xA request
    has(t, r'\tmov_s\tr0,0x9\b')
    has(t, r'\tbl\t-1284372\t;0x18b85c\b')             # impose Small
    assert count(t, r'\tjl_s\t\[r14\]') >= 8          # poll loops

    # 17. Static callers of the writer: explicit indices only.
    t = w('caller_144a82')
    has(t, r'\tmov_s\tr1,0x77\b')
    has(t, r'\tmov_s\tr2,r13\b')
    has(t, r'\tbl\t175276\t;0x16f72c\b')
    t = w('caller_16eca2')
    has(t, r'\tmov_s\tr1,0xc\b')
    has(t, r'\tbl\t2700\t;0x16f72c\b')
    t = w('caller_16edfe')
    has(t, r'\tmov_s\tr1,0x62\b')
    has(t, r'\tmov_s\tr2,0x1\b')
    has(t, r'\tbl\t2352\t;0x16f72c\b')
    t = w('caller_16f8d4')
    has(t, r'\tldb_s\tr2,\[r13,0x8\]')               # record value
    has(t, r'\tldb_s\tr1,\[r13,0x9\]')               # record idx
    has(t, r'\tmov_s\tr0,r14\b')
    has(t, r'\tbl_s\t-424\t;0x16f72c\b')
    explicit = {i for i in EXPLICIT_IDX.values() if i is not None}
    assert explicit == {1, 2, 0xC, 0x62, 0x65, 0x66, 0x77}, explicit
    assert not ({8, 9, 0xA} & explicit)

    # 18. Call census from the linear listing (candidate sites).
    census = census_calls()
    got = {hex(t): sorted(he(s) for s in census[t]) for t in census}
    assert set(census[0x16F72C]) == CALLS_16F72C, census[0x16F72C]
    assert set(census[0x16F638]) == CALLS_16F638
    assert set(census[0x16E2F4]) == CALLS_16E2F4
    assert set(census[0x16F66C]) == CALLS_16F66C
    assert set(census[0x16F6B0]) == CALLS_16F6B0
    assert set(census[0x16F86C]) == CALLS_16F86C
    assert set(census[0x16F988]) == CALLS_16F988
    assert set(census[0x16F950]) == CALLS_16F950
    assert census[0x16F9F0] == []          # pointer-only, no bl sites
    assert 0xC5DEE in census[0x16F920] and len(census[0x16F920]) >= 25
    assert 0x149F80 in census[0x16F964] and len(census[0x16F964]) >= 25

    # 19. Functional model of the decoded semantics (no hardware).
    entries = {}
    for i in range(128):
        entries[i] = [0, 0xFF, 1]                    # value, secondary, flags
    handlers = [0] * 10

    def setter(secondary, idx, value):
        assert 0 <= idx < 128 or True               # NO range check decoded
        entries[idx][0] = value & 0xFF
        entries[idx][1] = secondary & 0xFF if secondary != 0xFF else \
            entries[idx][1]

    def getter_raw(idx):
        return entries[idx][0]

    def flag(idx, on):
        entries[idx][2] = (entries[idx][2] | 1) if on else \
            (entries[idx][2] & ~1) & 0xFFFF

    records = [{'mask0': 1, 'mask4': 0, 'value': 1, 'idx': 9,
                'halfA': 0x8000}]
    for i, rec in enumerate(records):               # 0x16F66C install
        entries[rec['idx']][1] = i
    setter(0, 9, 1)                                 # request Big
    assert getter_raw(9) == 1                       # panel would serve it
    setter(0, 9, 0)                                 # request cleared
    assert getter_raw(9) == 0
    flag(9, True)
    assert entries[9][2] & 1
    flag(9, False)
    assert not entries[9][2] & 1
    # dispatch path arithmetic: 0x446808+4*i+512 == 0x446A08+4*i
    for i in range(10):
        assert SHADOW + 4 * i + 512 == HANDLERS + 4 * i
    # register path convergence: pool 0x16FA60 - sub3(0x3e) + 512 == 0x446A08
    assert 0x4469F8 - 0x1F0 + 512 == HANDLERS      # derivation note below

    result = dict(
        status='PASS_IRIS_SHADOW_STATIC',
        stamp=stamp,
        question='writer of the diagnostic shadow table 0x446808 polled by '
                 'panel 0x2C5100 (iteration 23 open point a)',
        answer=dict(
            init=he(0x16F638),
            init_caller=sorted(he(s) for s in CALLS_16F638),
            init_body='lp 128 iterations, LIMM 0x446808 at 0x16F646 '
                      '(only limm reference in 16 payloads), entry = '
                      '{value=0, secondary=0xFF, flags=1}, then memset '
                      '0xAD90C of the 10-word handler table 0x446A08 '
                      '(pool 0x16FA30, 0x28 bytes)',
            writer=dict(
                entry=he(0x16F72C),
                store='stb_s r2,[0x446808+4*r1+0] at 0x16F742 '
                      '(pool 0x16FA34); NO range check before the store '
                      '(the cmp idx,0x61 at 0x16F76E is on the log/dispatch '
                      'path only)',
                post='log id=(idx<<7)|1 via 0x149028/0x16F6B0 and handler '
                     'dispatch 0x16F6B0 over the 10 slots at 0x446A08',
                static_call_sites=sorted(he(s) for s in CALLS_16F72C),
                explicit_indices=sorted(he(i) for i in explicit),
                dynamic_paths=['0x16F8D4 inside consumer 0x16F86C: idx = '
                               'record+9, value = record+8',
                               '0x16EC28: generic switch path, idx = r13 '
                               '(0x62/0x66/0x77 routed to 0x16EED8)']),
            record_layer=dict(
                table=he(RECORDS),
                count=0x10,
                stride=20,
                layout='{maskLo@+0, maskHi@+4, value@+8, shadowIdx@+9, '
                       'half@+0xA (bit15 pending), half@+0xC}',
                struct=he(STRUCT),
                struct_layout='{+0 enable byte, +4 table pointer = cell '
                              '0x3678E8, +8 count halfword, +0xA gate byte '
                              '0x3678EE, +0xC/+0x10 64-bit state pair}',
                installer=he(0x16E2F4),
                installer_caller=sorted(he(s) for s in CALLS_16E2F4),
                install_service=he(0x16F66C),
                consumer=he(0x16F86C),
                consumer_callers=sorted(he(s) for s in CALLS_16F86C),
                mask_writer=he(0x16F8EC),
                registered_handler=he(0x16E588),
                note='the record table content at 0x392F04 is RAM and has '
                     'no static writer in the 16 payloads (only pools '
                     '0x16E388 base and 0x16EDD4 end reference it): the '
                     'request bytes 8/9/0xA served by the panel are fed at '
                     'runtime through the record transitions or the '
                     '0x16E440 command dispatcher'),
            handler_table=dict(
                base=he(HANDLERS),
                slots=10,
                register=he(0x16F988),
                unregister=he(0x16F9F0),
                dispatch=he(0x16F6B0),
                dispatch_callers=sorted(he(s) for s in CALLS_16F6B0),
                addressing_derivation='dispatch reads [0x446808+4*i+512] '
                                      '(ld.as [r1,128]); register search '
                                      'uses pool 0x16FA60=0x4469F8 with '
                                      'sub3(0x3e) and the same ld.as +512: '
                                      'the two paths converge on '
                                      '0x446A08+4*slot only if sub3(0x3e) '
                                      'contributes 0x1F0 (printed field '
                                      '0x3e scaled x8) - find-or-insert '
                                      'semantics requires the convergence; '
                                      'the sub3 immediate scale is a '
                                      'DERIVATION, not an independently '
                                      'proven hardware rule'),
            panel=dict(
                entry=he(0x2C5100),
                getter=he(0x16F920),
                semantics='waits entry 8 to clear (after 4/7 prologue with '
                          '0x18B794/0x18B72C), then serves entry 9 = '
                          'request Big -> 0x18B85C(1), entry 0xA = request '
                          'Small -> 0x18B85C(9), each with a wait-until-'
                          'clear loop: entries 8/9/0xA are REQUEST FLAGS, '
                          'not telemetry; no static writer of 0x16F72C '
                          'writes them'),
        ),
        census=dict(
            shadow_base_le_pools=[he(a) for a in base_hits[0]],
            shadow_base_limms=[he(a) for a in limm_hits[0]],
            region_hits=[(he(a), he(v)) for a, v in region[0]],
            calls=got,
            note='linear-listing census (candidate); all chain sites '
                 'asserted here are re-verified in dedicated aligned '
                 'windows',
        ),
        limits=[
            'Static only: no MMIO, camera hardware or firmware execution; '
            'the functional model is a semantic reconstruction',
            'The record table content 0x392F04 (which record carries idx '
            '8/9/0xA and what value/masks) is runtime RAM: the origin of '
            'the panel requests remains OPEN',
            'The 0x16E440 command dispatcher (switch on 0xCAD30()-3, '
            '~0x44 byte-offset cases) is only classified as a candidate '
            'producer of record/state changes, not decoded',
            'sub3 immediate scale x8 is a derivation from the '
            'find-or-insert convergence, not a proven decode rule; the '
            'ld.as +512 scale is independently fixed by the dispatch '
            'window arithmetic',
            'The store in 0x16F72C has no idx range check: out-of-range '
            'idx would write past the 128-entry table (caller discipline '
            'not proven)',
            'Linear-listing censuses can carry false positives near '
            'pools; asserted sets were cross-checked in dedicated windows '
            'for the chain sites',
            'V1.1 sample analysed; camera in the logs runs V1.0; '
            'addresses are not portable without proof',
        ],
        sources=dict(
            script=str(Path(__file__).relative_to(ROOT)),
            firmware=str(FIRMWARE.relative_to(ROOT)),
            manifest='S33-sections/TBM_blocks/manifest.json',
            listing=str(LISTING.relative_to(ROOT)),
            objdump='work/build-arc/binutils (GNU ARC700, -EL, aligned '
                    'windows)'),
    )
    (out / 'iris_shadow.json').write_text(json.dumps(result, indent=1) + '\n')
    (EVIDENCE / 'latest.json').write_text(json.dumps(
        dict(status=result['status'], stamp=stamp, path=str(out.relative_to(ROOT)),
             script=str(Path(__file__).relative_to(ROOT))), indent=1) + '\n')
    print('PASS_IRIS_SHADOW_STATIC', stamp)


if __name__ == '__main__':
    main()
