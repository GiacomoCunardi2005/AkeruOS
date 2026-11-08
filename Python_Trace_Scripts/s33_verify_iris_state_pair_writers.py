#!/usr/bin/env python3
"""Static verification of the writers of the 64-bit iris state pair (V1.1).

Closes the open point of iteration 27(b) / iteration 29 next step: WHO
writes the state pair consumed by 0x16F86C (the shadow transition
consumer).  The pair lives in the struct 0x3678E4 (+0xC/+0x10) and its
bits 16/21/15 ARE the panel request bytes shadow[8/9/0xA].

Chain asserted here (payload0, byte-exact windows + raw pools):

- SETTER 0x16E3A2(secondary, value): loops over the 16 records at
  0x392F04 (stride 20, pool 0x16E388), matches rec.idx == secondary,
  reads the current pair through 0x16F914(-1,-1) (full mask), clears
  rec.maskLo/rec.maskHi, ORs value << rec[+8] (bit position, via
  __ashldi3 0x334E9C) and commits via 0x16F86C(newLo,newHi,1).
  NO static caller exists (no bl/b, no LE word, no middle-endian limm
  in any of the 16 payloads): computed dispatch, honest negative.
- COMMIT 0x16EC38(newLo,newHi): builds the pair, runs the
  normalizer/validator 0x16E6E0(&pair) and, if it returns 1, commits
  via 0x16F86C(pair,1).  Installed as a FUNCTION POINTER in cell
  [0x366DE8] by the installer 0x16E2F4 through 0x140634 (pool 0x16E390).
- COMPLEMENT 0x16F8EC(pair) (bl_s 0x16F86C at 0x16F90A inside its own
  body): only static caller is the installer 0x16E336 (boot init).

NORMALIZER 0x16E6E0(&pair) (struct 0x367898, pools 0x16E834/0x16E830):
gate byte [0x367898+0xA], mirror halfword [0x367898+4]; lo is masked
with 0xFE31B188 (~0x01CE4E77); gate==1 clears the gate and forces
bit0=1, gate!=1 clears bit0; magic bypass (lo,hi)==(0xFE003000,0);
otherwise at most ONE set bit among {7,8,12,13,15,16,20,21} of lo
is accepted (sampled through __lshrdi3 0x335C4C with shifts
5/10/15/20 and masks 0xC/0xC/3/3 - bmsk_s with n masks n+1 bits,
audit iris-pair-audit-31 - then a 4x5 bit-count loop); on success
the normalized pair is written back through the pointer and 1
returned, on failure 0 returned WITHOUT writing.  The gate==1 branch
skips both the magic bypass and the validation.

INVOKERS (registered by the setup 0x140568, called from 0xC5D88 - the
same parent function that installs the record table through 0x16E2F4
at 0xC5D9E):
- 0x1406D0(x): [0x366DE8](~x, 0)  -> commit the COMPLEMENT of x.
- 0x140704(bits): bit2 -> [0x366DE0] (0x16ECB4, id-4 cell), bit1 ->
  [0x366DE4] (0x16EC88, id-2 cell), bit0 -> [0x366DDC] (id-1 cell,
  nobody registers it in payload0; the ld.as pool is 0x140628 =
  (0x14073C&~3)+(-69*4); the id-2/id-4 cell naming follows the
  0x1405F8 case that WRITES each cell - audit iris-pair-audit-31).
- registration services: 0x140634 -> [0x366DE8]=r0;
  0x1405F8(1/2/4,ptr) -> [0x366DDC]/[0x366DE4]/[0x366DE0]=ptr;
  0x148F64(ptr) -> [0x366F78]=ptr; 0x22C3BC stores its r0 at
  [pool 0x22C474 struct +0x18] and raises event 0x158CBC(0x3200002,
  1<<10) when r1!=0; 0x16ACDC(7,2,ptr) stores halfword 7 at +0x14
  (bmsk_s ,0x2 = &7), 2 at +0x16 and the pointer at +0x1C of the
  struct 0x392AC0 (audit iris-pair-audit-31).

CONSEQUENCE for the iris request bits 16/21/15 (shadow 8/9/0xA):
the normalize mask 0xFE31B188 does NOT clear bits 16/21 (cleared set
= 0x01CE4E77 = {0,1,2,4,5,6,9,10,11,14,17,18,19,22,23,24}); bit 15 is
NOT cleared either.  All three bits are nonetheless SAMPLED by the
one-bit validation (bmsk_s ,0x1 masks two bits: sampled set
{7,8,12,13,15,16,20,21} - audit iris-pair-audit-31): each single
request can be born from the setter 0x16E3A2, from the commit path
0x16EC38/0x1406D0 or from the boot complement commit, but a commit
carrying TWO simultaneous requests among the sampled set is REJECTED
without writing.  The setter does not pass through the normalizer and
is not constrained.

Read-only: firmware, blocks, tools and listings are never modified.
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
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Iris_State_Pair'
LISTING = ROOT / 'Risultati/Disassemblati/Firmware1.1.asm'

RECORDS = 0x392F04          # 16 records x 20 bytes, static in payload1
STRUCT = 0x3678E4            # {+0xC/+0x10 pair} (consumer side)
STRUCT2 = 0x367898           # normalizer struct {+4 mirror(h), +0xA gate(b)}

# Literal words re-read from raw payload0 bytes (little-endian).
LITERALS = {
    0x16E388: 0x392F04,     # record table (setter + installer)
    0x16E38C: 0x16E588,     # notification handler (installer)
    0x16E390: 0x16EC38,     # pair-commit function pointer (installer)
    0x16E394: 0x16ECB4,     # registered with id 4
    0x16E398: 0x16EC88,     # registered with id 2
    0x16E39C: 0x16EE7C,     # registered through 0x148F64
    0x16E830: 0xFE31B188,   # normalize mask constant (~0x01CE4E77)
    0x16E834: STRUCT2,       # normalizer struct
    0x16E6D8: STRUCT2,       # handler 0x16E588 struct
    0x16E6DC: 0x36726B,     # byte flag read by the handler
    0x1405E8: 0x1406D0,     # complement invoker (function pointer)
    0x1405EC: 0x140704,     # bit invoker (function pointer)
    0x1405F0: 0x140700,     # gate reader tail (function pointer)
    0x1405F4: 0x366DF0,     # gate byte cell
    0x140628: 0x366DDC,     # callback cell case 1
    0x14062C: 0x366DE0,     # callback cell case 2
    0x140630: 0x366DE4,     # callback cell case 4
    0x14064C: 0x366DE8,     # callback cell (pair commit)
    0x148FC4: 0x366F78,     # callback cell (0x148F64 route)
    0x22C474: 0x5545F8,     # 0x22C3BC registration struct
    0x22C484: 0x3200002,    # event id raised by 0x22C3BC
    0x16ADC0: 0x392AC0,     # 0x16ACDC registration struct
}

CENSUS_TARGETS = [0x16F86C, 0x16F8EC, 0x16E6E0, 0x16E3A2, 0x16EC38,
                  0x140568, 0x22C3BC, 0x16ACDC, 0x1406D0, 0x140704,
                  0x14066C, 0x148F64, 0x1405F8, 0x140634]

# Expected call censuses (linear GNU listing, bl/bl.d/bl_s/bl_s.d forms;
# candidate sites, the chain ones are re-asserted in aligned windows).
EXPECT_CALLS = {
    0x16F86C: {0x16E3FA, 0x16EC74, 0x16F90A},
    0x16F8EC: {0x16E336},
    0x16E6E0: {0x16E32A, 0x16EC64},
    0x16E3A2: set(),
    0x16EC38: set(),
    0x140568: {0xC5D88},
    0x22C3BC: {0x1405B2},
    0x16ACDC: {0x1405BC},
    0x1406D0: set(),
    0x140704: set(),
    0x14066C: {0x16B7CE, 0x16E31A, 0x174E72},   # shared getter
    0x148F64: {0x16E376},
    0x1405F8: {0x16E344, 0x16E34C},
    0x140634: {0x16E33A},
}

MASK = 0xFE31B188


def he(n: int) -> str:
    return f'0x{n:x}'


def has(text: str, pattern: str) -> None:
    assert re.search(pattern, text), f'missing pattern: {pattern}'


def census_calls() -> dict:
    pat = re.compile(
        r'V([0-9A-F]{6,8}) \|[0-9a-f ]+\| '
        r'(bl|bl\.d|bl_s|bl_s\.d)\s+?-?\d+\s+;0x([0-9a-f]+)\b')
    hits = {t: [] for t in CENSUS_TARGETS}
    with LISTING.open('r', errors='replace') as fh:
        for line in fh:
            m = pat.search(line)
            if not m:
                continue
            target = int(m.group(3), 16)
            if target in hits:
                hits[target].append(int(m.group(1), 16))
    return hits


def norm_model(lo: int, hi: int, gate: int):
    """Semantics of 0x16E6E0 (gate/mirror are the struct cells)."""
    mirror_out = None
    if gate == 1:
        if not (lo & 1):
            lo |= 1
        new = (lo & MASK) | (lo & 1)
        gate = 0
    else:
        new = lo & MASK
    if (new, hi) == (0xFE003000, 0):
        return (new, hi, gate, 0, True)      # magic bypass, accepted
    sampled = ((new >> 5) & 0xC, (new >> 10) & 0xC,
               (new >> 15) & 3, (new >> 20) & 3)   # bmsk_s ,0x1 = 2 bits
    total = 0
    for byte in sampled:
        for b in range(5):
            total += (byte >> b) & 1
            if total > 1:
                return (new, hi, gate, None, False)   # rejected
    mirror_out = new & 1
    return (new, hi, gate, mirror_out, True)


def setter_model(records, pair, secondary, value):
    """Semantics of 0x16E3A2 over the record list."""
    lo, hi = pair
    fired = []
    for (maskLo, maskHi, bitpos, idx) in records:
        if idx != secondary:
            continue
        shifted = (value << bitpos) & 0xFFFFFFFFFFFFFFFF
        sLo, sHi = shifted & 0xFFFFFFFF, shifted >> 32
        lo = (lo & ~maskLo & 0xFFFFFFFF) | sLo
        hi = (hi & ~maskHi & 0xFFFFFFFF) | sHi
        fired.append(idx)
    return (lo, hi), fired


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
    base1 = info[1]['load_address_candidate']
    p1 = payloads[1]

    # 1. Literal words verified against raw payload0 bytes.
    for addr, value in LITERALS.items():
        got = struct.unpack_from('<I', p0, addr - base0)[0]
        assert got == value, (hex(addr), hex(got), hex(value))

    # 2. Static record table from payload1: 16 records, single-bit
    #    masks, bitpos == mask bit position (32+bit for the high half).
    rec_off = RECORDS - base1
    records = []
    for i in range(16):
        raw = p1[rec_off + 20 * i: rec_off + 20 * i + 20]
        maskLo, maskHi = struct.unpack_from('<II', raw, 0)
        bitpos, idx = raw[8], raw[9]
        assert maskLo & maskHi == 0
        if maskLo:
            assert maskLo & (maskLo - 1) == 0            # single bit
            assert bitpos == (maskLo.bit_length() - 1)
        if maskHi:
            assert maskHi & (maskHi - 1) == 0
            assert bitpos == 32 + (maskHi.bit_length() - 1)
        assert struct.unpack_from('<H', raw, 0xA)[0] & 0x7FFF == 0
        records.append((maskLo, maskHi, bitpos, idx))
    assert records[1] == (0x00010000, 0, 0x10, 0x08)     # bit 16 -> 8
    assert records[2] == (0x00200000, 0, 0x15, 0x09)     # bit 21 -> 9
    assert records[3] == (0x00008000, 0, 0x0F, 0x0A)     # bit 15 -> 0xA

    # 3. Call censuses.
    got = census_calls()
    for target, expect in EXPECT_CALLS.items():
        assert set(got[target]) == expect, (
            he(target), sorted(map(he, got[target])),
            sorted(map(he, expect)))

    # 4. No static reference to the setter / commit entries anywhere:
    #    LE word and middle-endian limm scans over all 16 payloads.
    for needle, name in ((0x16E3A2, 'setter'), (0x16EC38, 'commit')):
        for b in blocks:
            data = payloads[b['index']]
            for off in range(0, len(data) - 3):
                if struct.unpack_from('<I', data, off)[0] == needle:
                    # the installer pool 0x16E390 carries the commit
                    # pointer; nothing may carry the setter.
                    if name == 'commit' and \
                            b['index'] == 0 and off == 0x16E390 - base0:
                        continue
                    raise AssertionError(
                        f'{name} referenced at payload{b["index"]}'
                        f' {he(b["load_address_candidate"] + off)}')
    # ... and no branch of any form to the setter in the linear listing.
    with LISTING.open('r', errors='replace') as fh:
        for line in fh:
            if ';0x16e3a2' in line:
                raise AssertionError('branch to setter: ' + line.strip())

    # 5. Aligned windows.
    windows = {}
    for name, (lo, hi) in [
        ('setter_16e3a2', (0x16E3A2, 0x16E41C)),
        ('commit_16ec38', (0x16EC38, 0x16EC88)),
        ('normalize_16e6e0', (0x16E6E0, 0x16E830)),
        ('installer_16e2f4', (0x16E2F4, 0x16E388)),
        ('reg_case_1405f8', (0x1405F8, 0x140634)),
        ('reg_single_140634', (0x140634, 0x14064C)),
        ('reg_148f64', (0x148F64, 0x148F6C)),
        ('invoker_complement_1406d0', (0x1406D0, 0x140704)),
        ('invoker_bits_140704', (0x140704, 0x14074E)),
        ('setup_140568', (0x140568, 0x1405E8)),
        ('getter_14066c', (0x14066C, 0x140678)),
        ('svc_22c3bc', (0x22C3BC, 0x22C434)),
        ('svc_16acdc', (0x16ACDC, 0x16AD38)),
    ]:
        windows[name] = aligned_window(p0, base0, lo, hi)
        assert windows[name].strip(), name
    (out / 'gnu_windows.txt').write_text(
        '\n\n'.join(f'=== {k} ===\n{v}' for k, v in windows.items()))

    def w(name: str) -> str:
        return windows[name]

    # 6. SETTER 0x16E3A2.
    t = w('setter_16e3a2')
    has(t, r'\tbl\t1858944\t;0x334120\b')            # save r13-r18
    has(t, r'\tmov_s\tr18,r0\b')                     # secondary
    has(t, r'\tmov_s\tr17,r1\b')                     # value
    has(t, r'\tmov_s\tr14,0\b')
    has(t, r'\tld\tr12,\[pcl,-52\]\t;0x16e388\b')    # record table
    has(t, r'\tasl_s\tr13,r14,0x2\b')
    has(t, r'\tadd2_s\tr13,r13,r13\b')                # x5 -> stride 20
    has(t, r'\tadd_s\tr13,r13,r12\b')
    has(t, r'\tldb_s\tr1,\[r13,0x9\]')              # rec.idx
    has(t, r'\tcmp_s\tr1,r18\b')
    has(t, r'\tmov\tr0,-1\b')
    has(t, r'\tmov_s\tr1,r0\b')
    has(t, r'\tbl\t5440\t;0x16f914\b')               # full-mask read
    has(t, r'\tld_s\tr2,\[r13,0x4\]')              # rec.maskHi
    has(t, r'\tld_s\tr3,\[r13,0\]')                # rec.maskLo
    has(t, r'\tbic\tr16,r1,r2\b')
    has(t, r'\tldb_s\tr2,\[r13,0x8\]')             # bit position
    has(t, r'\tbic\tr15,r0,r3\b')
    has(t, r'\tmov_s\tr0,r17\b')
    has(t, r'\tmov_s\tr1,0\b')
    has(t, r'\tbl\t1862324\t;0x334e9c\b')            # value << bitpos
    has(t, r'\tor_s\tr15,r15,r0\b')
    has(t, r'\tor\tr1,r1,r16\b')
    has(t, r'\tmov_s\tr16,r1\b')
    has(t, r'\tmov_s\tr0,r15\b')
    has(t, r'\tmov_s\tr2,0x1\b')                     # flag = 1
    has(t, r'\tbl\t5236\t;0x16f86c\b')                # consumer
    has(t, r'\tcmp_s\tr14,0x10\b')                   # 16 records
    has(t, r'\tbc\t-66\t;0x16e3be\b')

    # 7. COMMIT 0x16EC38.
    t = w('commit_16ec38')
    has(t, r'\tst\tr0,\[fp,8\]')
    has(t, r'\tst\tr1,\[fp,12\]')
    has(t, r'\tmov_s\tr2,0\b')
    has(t, r'\tst\tr2,\[fp,-8\]')
    has(t, r'\tst\tr2,\[fp,-4\]')
    has(t, r'\tst\tr0,\[fp,-8\]')
    has(t, r'\tst\tr1,\[fp,-4\]')
    has(t, r'\tsub\tr0,fp,0x8\b')
    has(t, r'\tbl_s\t-1412\t;0x16e6e0\b')             # normalize/validate
    has(t, r'\tcmp_s\tr0,0x1\b')
    has(t, r'\tld\tr0,\[fp,-8\]')
    has(t, r'\tld\tr1,\[fp,-4\]')
    has(t, r'\tmov_s\tr2,0x1\b')
    has(t, r'\tbl\t3064\t;0x16f86c\b')

    # 8. NORMALIZER 0x16E6E0.
    t = w('normalize_16e6e0')
    has(t, r'\tmov_s\tr18,r0\b')                      # &pair
    has(t, r'\tld_s\tr1,\[r0,0\]')
    has(t, r'\tld_s\tr0,\[r0,0x4\]')
    has(t, r'\tld_s\tr13,\[pcl,0x11c\]\t;0x16e830\b')  # mask constant
    has(t, r'\tbmsk\tr5,r1,0\b')                      # bit0 of lo
    has(t, r'\tldb\tr4,\[r0,10\]')                  # gate
    has(t, r'\tcmp\tr4,0x1\b')
    has(t, r'\tstb_s\tr2,\[r0,0xa\]')               # gate clear
    has(t, r'\tbset_s\tr1,r1,0\b')                    # force bit0
    has(t, r'\tand\tr1,r1,0xfe31b188\b')
    has(t, r'\tor\tr17,r2,r1\b')
    has(t, r'\tst_s\tr2,\[r0,0x4\]')               # mirror halfword
    has(t, r'\tbmsk_s\tr0,r0,0\b')                   # mirror bit0
    has(t, r'\tand\tr17,r1,0xfe31b188\b')
    has(t, r'\tand\tr0,r17,0x8\b')                   # extra bit3 byte
    has(t, r'\tmov_s\tr2,0x5\b')
    has(t, r'\tbl\t1864884\t;0x335c4c\b')             # lshr 5
    has(t, r'\tand\tr0,r0,0xc\b')
    has(t, r'\tmov_s\tr2,0xa\b')
    has(t, r'\tbl\t1864868\t;0x335c4c\b')             # lshr 10
    has(t, r'\tmov_s\tr2,0xf\b')
    has(t, r'\tbl\t1864848\t;0x335c4c\b')             # lshr 15
    has(t, r'\tbmsk_s\tr0,r0,0x1\b')
    has(t, r'\tmov_s\tr2,0x14\b')
    has(t, r'\tbl\t1864832\t;0x335c4c\b')             # lshr 20
    has(t, r'\tcmp\tr17,0xfe003000\b')               # magic bypass
    has(t, r'\tcmp\.eq\tr16,0\b')
    has(t, r'\tble_s\t6\t;0x16e806\b')               # reject when >1 bit
    has(t, r'\tmov_s\tr0,0\b')
    has(t, r'\tst\tr17,\[r0\]')                    # write-back
    has(t, r'\tst\tr16,\[r0,4\]')
    has(t, r'\tmov_s\tr0,0x1\b')                     # accepted

    # 9. INSTALLER 0x16E2F4: record table, handler, init commit,
    #    callback registrations.
    t = w('installer_16e2f4')
    has(t, r'\tld_s\tr0,\[pcl,0x88\]\t;0x16e388\b')  # records
    has(t, r'\tmov_s\tr1,0x10\b')                   # count 16
    has(t, r'\tbl\t4968\t;0x16f66c\b')               # install
    has(t, r'\tbl\.d\t5760\t;0x16f988\b')             # register handler
    has(t, r'\tld_s\tr0,\[pcl,0x80\]\t;0x16e38c\b')
    has(t, r'\tbl\t-187564\t;0x14066c\b')             # init pair getter
    has(t, r'\tsub\tr0,fp,0x8\b')
    has(t, r'\tbl\t952\t;0x16e6e0\b')                 # normalize init
    has(t, r'\tbl\t5560\t;0x16f8ec\b')               # complement commit
    has(t, r'\tbl\.d\t-187652\t;0x140634\b')          # [0x366DE8]=commit
    has(t, r'\tld_s\tr0,\[pcl,0x54\]\t;0x16e390\b')
    has(t, r'\tld_s\tr1,\[pcl,0x54\]\t;0x16e394\b')
    has(t, r'\tmov_s\tr0,0x4\b')
    has(t, r'\tbl\t-187724\t;0x1405f8\b')             # case 4
    has(t, r'\tld_s\tr1,\[pcl,0x50\]\t;0x16e398\b')
    has(t, r'\tmov_s\tr0,0x2\b')
    has(t, r'\tbl\t-187732\t;0x1405f8\b')             # case 2
    has(t, r'\tbl\.d\t-152592\t;0x148f64\b')          # 0x366F78 route
    has(t, r'\tld_s\tr0,\[pcl,0x24\]\t;0x16e39c\b')

    # 10. Registration services.
    t = w('reg_case_1405f8')
    has(t, r'\tcmp_s\tr0,0x1\b')
    has(t, r'\tcmp_s\tr0,0x2\b')
    has(t, r'\tcmp_s\tr0,0x4\b')
    has(t, r'\tst_s\tr1,\[r2,0\]')
    t = w('reg_single_140634')
    has(t, r'\tld_s\tr1,\[pcl,0x10\]\t;0x14064c\b')
    has(t, r'\tst_s\tr0,\[r1,0\]')
    t = w('reg_148f64')
    has(t, r'\tld_s\tr1,\[pcl,0x60\]\t;0x148fc4\b')
    has(t, r'\tst_s\tr0,\[r1,0\]')

    # 11. INVOKERS.
    t = w('invoker_complement_1406d0')
    has(t, r'\tmov_s\tr14,r0\b')
    has(t, r'\tld\tr0,\[pcl,-148\]\t;0x14064c\b')     # cell 0x366DE8
    has(t, r'\tld_s\tr2,\[r0,0\]')
    has(t, r'\tcmp_s\tr2,0\b')
    has(t, r'\tnot_s\tr13,r14\b')                    # complement
    has(t, r'\tmov_s\tr0,r13\b')
    has(t, r'\tmov_s\tr1,0\b')                       # hi = 0
    has(t, r'\tjl_s\t\[r2\]')
    t = w('invoker_bits_140704')
    has(t, r'\tbtst_s\tr0,0x2\b')
    has(t, r'\tld\tr0,\[pcl,-236\]\t;0x14062c\b')     # id-4 cell 0x366DE0
    has(t, r'\tjl_s\t\[r1\]')
    has(t, r'\tbtst_s\tr13,0x1\b')
    has(t, r'\tld\tr0,\[pcl,-252\]\t;0x140630\b')     # id-2 cell 0x366DE4
    has(t, r'\tbtst_s\tr13,0\b')
    has(t, r'\tld\.as\tr0,\[pcl,-69\]\t;0x1406f7\b')  # id-1 cell
    # byte-proven: (0x14073C & ~3) + (-69 * 4) = 0x140628 = 0x366DDC
    assert (0x14073E & ~3) + (-69 * 4) == 0x140628
    assert struct.unpack_from('<I', p0, 0x140628 - base0)[0] == 0x366DDC

    # 12. SETUP 0x140568 and the registration services it drives.
    t = w('setup_140568')
    has(t, r'\tmov_s\tr0,0\b')
    has(t, r'\tbl\t173184\t;0x16a9f8\b')
    has(t, r'\tbl\t-601208\t;0xad90c\b')
    has(t, r'\tbl\t-500212\t;0xc6398\b')
    has(t, r'\tbl\t-500192\t;0xc63b8\b')
    has(t, r'\tbl\t107480\t;0x15a978\b')
    has(t, r'\tld_s\tr0,\[pcl,0x44\]\t;0x1405e8\b')   # 0x1406D0
    has(t, r'\tld\tr3,\[fp,-4\]')
    has(t, r'\tmov\tr4,0x14\b')
    has(t, r'\tbl\t966156\t;0x22c3bc\b')
    has(t, r'\tld_s\tr2,\[pcl,0x38\]\t;0x1405ec\b')   # 0x140704
    has(t, r'\tmov_s\tr0,0x7\b')
    has(t, r'\tmov_s\tr1,0x2\b')
    has(t, r'\tbl\t173856\t;0x16acdc\b')
    has(t, r'\tbl\.d\t180456\t;0x16c6ac\b')
    has(t, r'\tld_s\tr0,\[pcl,0x28\]\t;0x1405f0\b')   # 0x140700
    has(t, r'\tld_s\tr0,\[pcl,0x24\]\t;0x1405f4\b')   # 0x366DF0
    has(t, r'\tstb_s\tr1,\[r0,0\]')
    t = w('svc_22c3bc')
    has(t, r'\tld_s\tr14,\[pcl,0xb0\]\t;0x22c474\b')
    has(t, r'\tstw_s\tr1,\[r14,0x8\]')
    has(t, r'\tcmp\tr2,800\b')
    has(t, r'\tst_s\tr2,\[r14,0xc\]')
    has(t, r'\tst_s\tr3,\[r14,0x10\]')
    has(t, r'\tst_s\tr0,\[r14,0x14\]')
    has(t, r'\tst_s\tr13,\[r14,0x18\]')            # the callback ptr
    has(t, r'\tbl\.d\t-866144\t;0x158cbc\b')          # event SET
    has(t, r'\tmov\tr1,1024\b')                      # 1<<10
    t = w('svc_16acdc')
    has(t, r'\tld_s\tr13,\[pcl,0xe0\]\t;0x16adc0\b')
    has(t, r'\tbmsk_s\tr0,r0,0x2\b')
    has(t, r'\tst_s\tr2,\[r13,0x1c\]')             # the callback ptr
    has(t, r'\tstw_s\tr0,\[r13,0x14\]')
    has(t, r'\tstw_s\tr1,\[r13,0x16\]')
    has(t, r'\tbl\.d\t881212\t;0x241f40\b')

    # 13. getter 0x14066C (init pair source).
    t = w('getter_14066c')
    has(t, r'\tbl\t966088\t;0x22c434\b')
    has(t, r'\tnot_s\tr0,r0\b')

    # 14. Functional models.
    # 14a. mask semantics: cleared set = ~MASK.
    cleared = {b for b in range(32) if not (MASK >> b) & 1}
    assert cleared == {0, 1, 2, 4, 5, 6, 9, 10, 11, 14,
                       17, 18, 19, 22, 23, 24}, sorted(cleared)
    assert 16 not in cleared and 21 not in cleared and 15 not in cleared
    # no record bit (3,7,8,12,13,15,16,20,21,30,31 lo; hi bits) is
    # cleared by the normalize mask: the mask preserves exactly the
    # state-machine bits defined by the record table.
    rec_bits = {bp for (_, _, bp, _) in records}
    assert not (rec_bits & cleared)
    # 14b. setter model on the real records.
    pair = (0, 0)
    pair, fired = setter_model(records, pair, 0x08, 1)
    assert pair == (1 << 16, 0) and fired == [0x08]
    pair, fired = setter_model(records, pair, 0x09, 1)
    assert pair == (1 << 16 | 1 << 21, 0) and fired == [0x09]
    pair, fired = setter_model(records, pair, 0x0A, 1)
    assert pair == (1 << 16 | 1 << 21 | 1 << 15, 0) and fired == [0x0A]
    pair, fired = setter_model(records, pair, 0x08, 0)
    assert pair == (1 << 21 | 1 << 15, 0) and fired == [0x08]
    # one setter call touches only the records with that idx (here 0x62
    # is the only duplicated secondary in the table).
    pair, fired = setter_model(records, (0, 0), 0x62, 1)
    assert pair == (0x80000000, 0) and fired == [0x62]
    # 14c. normalize model.
    out5 = norm_model(1 << 16, 0, 0)
    assert out5[4] is True and out5[0] == (1 << 16)      # bit16 survives
    out5 = norm_model(1 << 21, 0, 0)
    assert out5[4] is True and out5[0] == (1 << 21)      # bit21 survives
    out5 = norm_model(1 << 15, 0, 0)
    assert out5[4] is True and out5[0] == (1 << 15)      # bit15 survives
    out5 = norm_model((1 << 15) | (1 << 20), 0, 0)       # two sampled
    assert out5[4] is False and out5[3] is None          # rejected
    # audit iris-pair-audit-31: bits 16 and 21 are sampled too
    # (bmsk_s ,0x1 masks TWO bits), so a commit carrying two
    # simultaneous iris requests is rejected without writing.
    out5 = norm_model((1 << 16) | (1 << 21), 0, 0)
    assert out5[4] is False and out5[3] is None          # rejected
    out5 = norm_model((1 << 15) | (1 << 16), 0, 0)
    assert out5[4] is False and out5[3] is None          # rejected
    out5 = norm_model((1 << 16) | (1 << 17), 0, 0)      # bit17 is masked
    assert out5[4] is True and out5[0] == (1 << 16)
    out5 = norm_model(1 << 8, 0, 0)                      # bit8 survives
    assert out5[4] is True and out5[0] == (1 << 8)
    out5 = norm_model(0xFE003000, 0, 0)                  # magic bypass
    assert out5[4] is True and out5[0] == 0xFE003000
    out5 = norm_model(0, 0, 1)                           # gate forces bit0
    assert out5[4] is True and out5[0] == 1 and out5[2] == 0
    out5 = norm_model(1, 0, 0)                           # bit0 masked off
    assert out5[4] is True and out5[0] == 0
    # 14d. full 2^16 sweep of the low half (upper bits of lo random-free):
    #      the accept/reject predicate must depend only on the sampled
    #      bits and the magic constant.
    for v in range(0x10000):
        lo = v << 16                       # exercise bits 16..31 only
        new, hi, gate, mirror, ok = norm_model(lo, 0, 0)
        assert new == (lo & MASK)
        sampled_one = bin((new >> 7) & 1)[2:] == '' or True
        cnt = sum(((new >> b) & 1)
                  for b in (7, 8, 12, 13, 15, 16, 20, 21))
        assert ok == (cnt <= 1) or new == 0xFE003000

    result = dict(
        status='PASS_IRIS_STATE_PAIR_WRITERS_STATIC',
        stamp=stamp,
        firmware_sha256=sha(FIRMWARE),
        question='who writes the 64-bit state pair consumed by '
                 '0x16F86C (bits 16/21/15 = shadow request bytes '
                 '8/9/0xA)',
        answer=dict(
            setter=dict(
                entry=he(0x16E3A2),
                signature='(secondary, value)',
                record_table=he(RECORDS),
                stride=20,
                bit_position_field='+8',
                commit=he(0x16F86C),
                static_callers='NONE (no bl/b, no LE word, no limm in '
                               'the 16 payloads): computed dispatch, '
                               'honest negative',
            ),
            commit=dict(
                entry=he(0x16EC38),
                normalizer=he(0x16E6E0),
                installed_by=he(0x16E2F4),
                install_service=he(0x140634),
                cell=he(0x366DE8),
                invoked_by=he(0x1406D0),
                invoker_semantics='[0x366DE8](~x, 0): commit the '
                                  'complement of the argument with '
                                  'hi=0',
            ),
            complement=dict(
                entry=he(0x16F8EC),
                only_static_caller=he(0x16E336),
                role='boot init: forces every record with a non-null '
                     'mask to fire',
            ),
            normalizer=dict(
                struct=he(STRUCT2),
                gate_byte=he(STRUCT2 + 0xA),
                mirror_halfword=he(STRUCT2 + 4),
                mask=he(MASK),
                cleared_bits=sorted(cleared),
                sampled_bits=[7, 8, 12, 13, 15, 16, 20, 21],
                magic_bypass=[he(0xFE003000), '0'],
                rule='gate==1 clears the gate, forces bit0=1 and '
                     'SKIPS magic and validation; otherwise bit0 is '
                     'cleared and at most ONE sampled bit may be set, '
                     'else return 0 without writing; bits 16/21/15 '
                     'are NOT cleared by the mask but ARE sampled: '
                     'each single iris request can be born from the '
                     'commit path, while a commit carrying two '
                     'simultaneous requests among {7,8,12,13,15,16,'
                     '20,21} is rejected; the setter bypasses the '
                     'normalizer entirely',
            ),
            registration_chain=dict(
                setup=he(0x140568),
                setup_caller=he(0xC5D88),
                parent_note='0xC5D88 and 0xC5D9E (record-table '
                            'installer 0x16E2F4) share the same '
                            'parent function',
                services=[he(0x140634), he(0x1405F8), he(0x148F64),
                          he(0x22C3BC), he(0x16ACDC)],
                cells={'id1': he(0x366DDC),
                       'id2': he(0x366DE4),
                       'id4': he(0x366DE0),
                       'commit': he(0x366DE8),
                       'ev_route': he(0x366F78)},
                event=dict(service=he(0x158CBC), id=he(0x3200002),
                           bit='1<<10'),
                unknowns='the runtime callers that invoke the '
                         'registered pointers (0x1406D0 stored at '
                         '[0x5545F8+0x18], 0x140704 at '
                         '[0x392AC0+0x1C]) are NOT identified here: '
                         'one more layer (task/monitor framework)',
            ),
            records=dict(
                table=he(RECORDS), count=16,
                iris=[dict(rec=1, mask='0x00010000', bit=16, idx=8),
                      dict(rec=2, mask='0x00200000', bit=21, idx=9),
                      dict(rec=3, mask='0x00008000', bit=15, idx=0xA)],
                coherence='16/16: single-bit masks, bitpos == mask '
                           'bit position (32+bit for the high half)',
            ),
        ),
        census={he(t): sorted(he(s) for s in got[t])
                for t in CENSUS_TARGETS},
        limits=[
            'Static only: no MMIO, camera or firmware execution; the '
            'functional models are semantic reconstructions',
            'Audit iris-pair-audit-31 (independent, read-only): '
            'claims 1/2/4/5 CONFIRMED; corrections accepted here: '
            '(a) bmsk_s with n masks n+1 bits, so the shift-15/20 '
            'samples are 2 bits wide and the sampled set is '
            '{7,8,12,13,15,16,20,21}; (b) id-2/id-4 cell naming: '
            '0x1405F8 case 2 writes 0x366DE4 and case 4 writes '
            '0x366DE0; (c) 0x16ACDC stores halfword 7 (bmsk_s ,0x2 = '
            '&7) at +0x14',
            'The dead ld r15/r16 from [fp-8]/[fp-4] at the setter '
            'entry are uninitialized loads (the pair is re-read '
            'through 0x16F914 at each record match): innocuous',
            'The setter 0x16E3A2 has no statically censable caller: '
            'its runtime trigger is a computed dispatch (blind spot '
            'of the linear census); it could also be dead code in '
            'V1.1',
            'The runtime invokers of the registered pointers '
            '([0x5545F8+0x18] and [0x392AC0+0x1C]) are not identified: '
            'the 0x22C3BC/0x16ACDC consumers are one layer deeper',
            'The id-1 cell 0x366DDC has no registrant in the 16 '
            'payloads: the bit0 branch of 0x140704 is a no-op unless '
            'a runtime writer exists',
            'The initial pair at boot comes from 0x14066C (bl '
            '0x22C434 + not r0): its runtime value is not derivable',
            'ld.as/ld pcl bases: (PC&~3)+field*4 for scaled, (PC&~3)'
            '+field for non-scaled - both re-proven here (0x14073E '
            '-> 0x140628, 0x16E3BE -> 0x16E388)',
            'V1.1 sample analysed; the camera in the logs runs V1.0; '
            'addresses are not portable without proof',
        ],
        sources=dict(
            script=str(Path(__file__).relative_to(ROOT)),
            firmware=str(FIRMWARE.relative_to(ROOT)),
            manifest='S33-sections/TBM_blocks/manifest.json',
            listing=str(LISTING.relative_to(ROOT)),
            objdump='work/build-arc/binutils (GNU ARC700, -EL, aligned '
                    'windows)',
        ),
    )
    (out / 'iris_state_pair.json').write_text(
        json.dumps(result, indent=1) + '\n')
    (EVIDENCE / 'latest.json').write_text(json.dumps(
        dict(status=result['status'], stamp=stamp,
             path=str(out.relative_to(ROOT)),
             script=str(Path(__file__).relative_to(ROOT))), indent=1)
        + '\n')
    print('PASS_IRIS_STATE_PAIR_WRITERS_STATIC', stamp)


if __name__ == '__main__':
    main()
