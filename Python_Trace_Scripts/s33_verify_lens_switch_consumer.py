#!/usr/bin/env python3
"""Static decode of the parameter-switch 0x1EE730: the consumer of the ctxB
command fields 0xC4..0xDE, and its callers.

Follows the cmd-intake session (s33_verify_lens_cmd_intake.py, iteration 9)
and answers its open point (a): how the cumulative fields 0xC4..0xD0 and the
parameter fields 0xD2..0xDE written by the intake 0x25C038 into ctxB 0x50F420
are consumed inside the switch 0x1EE730, up to the lens wire transaction.

Byte-verified facts asserted here:

- switch header: guard 0x25BFB8 (fail -> return 0x1B00101, pool 0x1EE9AC),
  ctxA/ctxB resolvers, command byte r2 = ctxA[+5] loaded in the delay slot of
  the jump-table dispatch, bound cmp 0..6 (default -> 0x1B00103, pool 0x1EE9B8);
- phase-1 jump table 04 11 1e 2b 38 70 7d at 0x1EE77A: case c loads
  ctxB halfword[196+2c] (cumulative) and ctxB halfword[210+2c] (parameter),
  r14 = cmd*cumulative, shared tail r13 = cmd*parameter (muludw, sr 0 to
  aux_macmode; both operands < 2^16);
- shared tail: budget check r13 > arg2 -> split path 0x1EE958; bit 0xA of
  ctxA[+2] clear -> return 0x1B00115 (pool 0x1EE9BC); set -> descriptor
  0x36B254 = {byte0=0, byte1=4, word2=0} + transaction 0x25F338(buf512=
  0x54D8A8, rec16=0x50E940, desc) + copy of 244 bytes from 0x54DAB2
  (= buf512+0x20A, the response record) INTO ctxB 0x50F420 (pool 0x1EE9B4):
  the MCU response updates the context;
- phase-2: second jump table 20 2d 3a 47 54 69 76 at 0x1EE852, r1 = cmd,
  r2 = ctxB (post-copy), same 7 field pairs, re-check r13 vs arg2, exit
  0x1B00115;
- split path 0x1EE958: r14 += arg2; chunks = ceil(arg3 / (ctxA[+0x10]<<9))
  via the divide millicode 0x335B34 (quotient r0, remainder r1); accepted
  window arg2 < cmd*param < arg2+chunks, outside -> 0x1B00116 (pool 0x1EE9C0);
  chunks==0 -> return 0; case 0 -> ctxB[0xB4..0xC0] = arg1 words and, via
  0x1EDFDC, ctxB[0xAC] = ceil(ctxB[0xB8]/((cmd<<9)*ctxA[+0x10])) must be
  <= 0x50 (else 0x1B00113, pool 0x1EED6C) then hub 0x1EE148(0,0); cases 1..6
  -> 0x1EDED8(cmd*cumulative+arg2, chunks, arg1, 0);
- millicode: 0x334120 saves r13..r18 (six st.aw + j_s [blink]), 0x334104
  saves r25..r19, 0x33417C is the restore thunk entry; 0x3342A8 is the GCC
  32x32 multiply helper: ror r2,r1,16; muludw; add r2,r56,r57; muludw;
  asl r2,r2,16; add r0,r57,r2 == (r0*r1) mod 2^32 under the documented
  conditional MULUDW hypothesis (r57 = lo16*lo16, r56 = hi16*hi16);
- twin dispatcher 0x1ED11C(case, arg1, arg2, arg3, &out): same guard, same
  jump table shape (raw bytes 04 0d 16 1f 28 38 41 at 0x1ED17C), same 7 field
  pairs on ctxB, output written to [r4], error paths store 0xFF to [arg1];
- callers: 0x29E9C4 (orchestrator module) re-derives the budget from the
  packed record words a1={.,p1}, a2={p2,p3}, a3={p4,p5} as
  3 + p1 + 2*p2 + 2*p3 + p4 + p5 <= ctxA[+8] (error 0x1B00106), checks the
  ctxA[+0] type against {3,4,5}, computes r21 = (ctxA[+5]<<9)*ctxA[+0x10],
  then calls 0x1ED11C seven times (one per case, products via 0x3342A8) and
  the switch 0x1EE730 seven times with arg0 = 0..6, arg2 = 0,
  arg3 = max(sp-slot, param*r21); further callers: 0x1EEA4C (512-block bulk
  wrapper: ceil(arg3/512), 0x260FE4, then the switch) and the 0x261xxx family.

The per-case field products r14/r13 are exact products when the documented
conditional MULUDW hypothesis holds (both operands < 2^16); the hypothesis
itself is not CPU-proven, but the firmware's own multiply millicode 0x3342A8
relies on the same channel mapping.

pcl note: ld_s/ld pool addresses are unscaled annotations; ld.as with a
register base scales the printed offset by the access size (x4 word, x2
halfword). Read-only: firmware, blocks and tools are never modified.
"""
import json
import random
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads, objdump_text, he
from s33_run_gnu_arc700 import ROOT, sha
from s33_verify_sensor_mmio_dialog import aligned_window

FIRMWARE = ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin'
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Switch_Consumer'

JT1 = bytes([0x04, 0x11, 0x1e, 0x2b, 0x38, 0x70, 0x7d])
JT2 = bytes([0x20, 0x2d, 0x3a, 0x47, 0x54, 0x69, 0x76])
JT_TWIN = bytes([0x04, 0x0d, 0x16, 0x1f, 0x28, 0x38, 0x41])

POOLS_1EE = {
    0x1EE994: 0x50E940,   # rec16 buffer
    0x1EE998: 0x54D8A8,   # buf512
    0x1EE99C: 0x50F210,   # template dest of the 0x50Fxxx family (iteration 5)
    0x1EE9A0: 0x36B25C,   # shadow struct
    0x1EE9A4: 0x54DAA8,   # buf512+0x200
    0x1EE9AC: 0x1B00101,  # guard failure
    0x1EE9B0: 0x36B254,   # active descriptor
    0x1EE9B4: 0x54DAB2,   # buf512+0x20A: response record -> copied into ctxB
    0x1EE9B8: 0x1B00103,  # switch default
    0x1EE9BC: 0x1B00115,  # exit value (bit clear and phase-2 normal end)
    0x1EE9C0: 0x1B00116,  # split window violated
    0x1EED6C: 0x1B00113,  # ctxB[0xAC] > 0x50 in the case-0 split path
    0x1EED70: 0x1B00001,  # check id used by 0x1EEA4C
}
POOLS_29E = {
    0x29EB88: 0x1B00101,  # guard failure in 0x29E9C4
    0x29EB8C: 0x1B00106,  # budget violation in 0x29E9C4
    0x29EB90: 0x1B00111,  # ctxB[0xE2]*r21 above the sp-slot limit
    0x29EB94: 0x1ED11C,   # computed-call target (twin dispatcher)
}

SWITCH = 0x1EE730
LOOP_SITES = [0x29ECAC, 0x29ED20, 0x29ED8A, 0x29EDF2,
              0x29EE5A, 0x29EEC2, 0x29EF2A]
TWIN_PRECALL_JL = [0x1ED11C]

SWITCH_CALLERS = [0x1EEAA4, 0x261104, 0x2611A6] + LOOP_SITES


def has(window: str, pattern: str) -> None:
    assert re.search(pattern, window), pattern


def model_muludw_hyp(a: int, b: int) -> tuple[int, int]:
    """Documented conditional hypothesis: r57 = lo16*lo16, r56 = hi16*hi16."""
    return ((a & 0xFFFF) * (b & 0xFFFF)) & 0xFFFFFFFF, \
           ((a >> 16) * (b >> 16)) & 0xFFFFFFFF


def model_millicode_mul(a: int, b: int) -> int:
    """0x3342A8 recombination under the hypothesis == full 32-bit product."""
    r2 = ((b >> 16) | ((b & 0xFFFF) << 16)) & 0xFFFFFFFF     # ror r2,r1,16
    r57a, r56a = model_muludw_hyp(a, r2)
    cross = (r56a + r57a) & 0xFFFFFFFF                      # add r2,r56,r57
    r57b, r56b = model_muludw_hyp(a, b)
    cross = (cross << 16) & 0xFFFFFFFF                      # asl r2,r2,16
    return (r57b + cross) & 0xFFFFFFFF                      # add r0,r57,r2


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

    def lit(addr):
        return struct.unpack_from('<I', p0, addr - base0)[0]

    for table, pools in ((POOLS_1EE, None), (POOLS_29E, None)):
        for addr, value in table.items():
            got = lit(addr)
            assert got == value, (hex(addr), hex(got), hex(value))

    # Jump tables straight from the raw bytes.
    assert p0[0x1EE77A - base0:0x1EE77A - base0 + 7] == JT1
    assert p0[0x1EE852 - base0:0x1EE852 - base0 + 7] == JT2
    assert p0[0x1ED17C - base0:0x1ED17C - base0 + 7] == JT_TWIN
    jt1_targets = [0x1EE77A + 2 * b for b in JT1]
    jt2_targets = [0x1EE852 + 2 * b for b in JT2]
    twin_targets = [0x1ED17C + 2 * b for b in JT_TWIN]
    assert jt1_targets == [0x1EE782, 0x1EE79C, 0x1EE7B6, 0x1EE7D0,
                           0x1EE7EA, 0x1EE85A, 0x1EE874]
    assert jt2_targets == [0x1EE892, 0x1EE8AC, 0x1EE8C6, 0x1EE8E0,
                           0x1EE8FA, 0x1EE924, 0x1EE93E]
    assert twin_targets == [0x1ED184, 0x1ED196, 0x1ED1A8, 0x1ED1BA,
                            0x1ED1CC, 0x1ED1EC, 0x1ED1FE]

    listing = objdump_text(ROOT, block_dir, info[0], p0)
    lines = listing.splitlines()

    # --- Caller census of the switch over payload0. ---
    callers = []
    for ln in lines:
        m = re.match(r'^\s*([0-9a-f]+):.*\tbl(?:\.d|_s)?\t[-0-9]+\t;0x1ee730\b',
                     ln)
        if m:
            callers.append(int(m.group(1), 16))
    assert sorted(set(callers)) == SWITCH_CALLERS, \
        [hex(c) for c in sorted(set(callers))]

    windows = {}

    def win(name, lo, hi):
        windows[name] = aligned_window(p0, base0, lo, hi)
        assert windows[name].strip(), name
        return windows[name]

    # --- Switch header. ---
    t = win('switch_header', 0x1EE730, 0x1EE77A)
    has(t, r'\tpush_s\tblink')
    has(t, r'\tbl\t1333744\t;0x334120\b')
    has(t, r'\tsub_s\tsp,sp,0x8\b')
    has(t, r'\tmov_s\tr16,r0\b') and has(t, r'\tmov_s\tr15,r1\b')
    has(t, r'\tmov_s\tr17,r2\b') and has(t, r'\tmov_s\tr18,r3\b')
    has(t, r'\tbl\.d\t448628\t;0x25bfb8\b')
    has(t, r'\tcmp_s\tr0,0\b')
    has(t, r'\tb\.d\t760\t;0x1eea44\b')
    has(t, r'\tld_s\tr0,\[pcl,0x25c\]\t;0x1ee9ac\b')      # delay: 0x1B00101
    has(t, r'\tbl\.d\t451480\t;0x25caec\b')               # ctxA resolver
    has(t, r'\tbl\.d\t448712\t;0x25c020\b')               # ctxB resolver
    has(t, r'\tcmp_s\tr0,0x6\b')
    has(t, r'\tbhi\t298\t;0x1ee88e\b')
    has(t, r'\tadd\tr12,pcl,0x12\t;0x1ee77a\b')
    has(t, r'\tldb\tr0,\[r12,r0\]')
    has(t, r'\tld_s\tr1,\[sp,0\]')      # ctxA
    has(t, r'\tld_s\tr3,\[sp,0x4\]')    # ctxB
    has(t, r'\tadd1_s\tr12,r12,r0')
    has(t, r'\tj_s\.d\t\[r12\]')
    has(t, r'\tldb_s\tr2,\[r1,0x5\]')   # delay slot: cmd byte from ctxA[+5]

    # --- Phase-1 cases. ---
    for case, target in enumerate(jt1_targets):
        t = win(f'switch_case_{case}', target, target + 0x1A)
        has(t, rf'\tldh\tr0,\[r3,{196 + case * 2}\]')
        has(t, r'\tsr\t0,\[aux_macmode\]')
        has(t, r'\tmuludw\t0,r[02],r[02]')
        has(t, r'\tmov\tr14,r57')
        has(t, rf'\tldh\tr0,\[r3,{210 + case * 2}\]')
        if case != 4:
            has(t, r'\tb_s\t-?\d+\t;0x1ee802\b')
        else:
            # case 4: mov scheduled after the second load, falls through.
            has(t, r'\tmov\tr14,r57')

    # --- Shared tail (bit 0xA set: transaction + ctxB update + phase 2). ---
    t = win('switch_shared', 0x1EE802, 0x1EE85A)
    has(t, r'\tmuludw\t0,r0,r2')
    has(t, r'\tmov\tr13,r57')
    has(t, r'\tcmp_s\tr13,r17\b')
    has(t, r'\tbhi\t332\t;0x1ee958\b')
    has(t, r'\tldw_s\tr0,\[r1,0x2\]')   # ctxA[+2]
    has(t, r'\tbtst_s\tr0,0xa\b')
    has(t, r'\tbeq_s\t268\t;0x1ee920\b')
    has(t, r'\tld_s\tr2,\[pcl,0x19c\]\t;0x1ee9b0\b')   # 0x36B254
    has(t, r'\tld_s\tr1,\[pcl,0x17c\]\t;0x1ee994\b')   # 0x50E940
    has(t, r'\tstb_s\tr0,\[r2,0\]')    # desc byte0 = 0
    has(t, r'\tstw_s\tr0,\[r2,0x2\]')  # desc word2 = 0
    has(t, r'\tmov_s\tr0,0x4\b')
    has(t, r'\tstb_s\tr0,\[r2,0x1\]')  # desc byte1 = 4
    has(t, r'\tld_s\tr0,\[pcl,0x174\]\t;0x1ee998\b')   # 0x54D8A8
    has(t, r'\tbl\.d\t461588\t;0x25f338\b')           # transaction
    has(t, r'\tmov_s\tr3,0')                            # delay slot
    has(t, r'\tld_s\tr0,\[sp,0x4\]')                   # ctxB
    has(t, r'\tld_s\tr1,\[pcl,0x188\]\t;0x1ee9b4\b')   # 0x54DAB2
    has(t, r'\tbl\.d\t-1314576\t;0xad920\b')           # copy helper
    has(t, r'\tmov_s\tr2,0xf4')                        # delay: len 244
    has(t, r'\tcmp\tr16,0x6\b')                        # re-check bound
    has(t, r'\tbhi\t226\t;0x1ee91a\b')
    has(t, r'\tld_s\tr0,\[sp,0\]')                     # ctxA
    has(t, r'\tadd\tr12,pcl,0x12\t;0x1ee852\b')        # second jump table
    has(t, r'\tldb_s\tr1,\[r0,0x5\]')                  # cmd byte again
    has(t, r'\tmov_s\tr0,r16\b')
    has(t, r'\tldb\.x\tr0,\[r12,r0\]')
    has(t, r'\tj_s\.d\t\[r12\]')
    has(t, r'\tld_s\tr2,\[sp,0x4\]')                   # delay: ctxB post-copy

    # --- Phase-2 cases (ctxB after the response copy). ---
    for case, target in enumerate(jt2_targets):
        t = win(f'phase2_case_{case}', target, target + 0x1A)
        has(t, rf'\tldh\tr0,\[r2,{196 + case * 2}\]')
        has(t, r'\tsr\t0,\[aux_macmode\]')
        has(t, r'\tmuludw\t0,r[01],r[01]')
        has(t, r'\tmov\tr14,r57')
        has(t, rf'\tldh\tr0,\[r2,{210 + case * 2}\]')
        if case != 4:
            has(t, r'\tb_s\t-?\d+\t;0x1ee912\b')

    # --- Phase-2 shared tail and bit-clear exit. ---
    t = win('phase2_shared', 0x1EE912, 0x1EE924)
    has(t, r'\tmuludw\t0,r0,r1')
    has(t, r'\tmov\tr13,r57')
    has(t, r'\tcmp_s\tr13,r17\b')
    has(t, r'\tbhi\t60\t;0x1ee958\b')
    t = win('bitchr_exit', 0x1EE920, 0x1EE924)
    has(t, r'\tld_s\tr0,\[pcl,0x9c\]\t;0x1ee9bc\b')    # 0x1B00115
    has(t, r'\tb_s\t292\t;0x1eea44\b')

    # --- Default and exit. ---
    t = win('switch_default', 0x1EE88E, 0x1EE892)
    has(t, r'\tld_s\tr0,\[pcl,0x12c\]\t;0x1ee9b8\b')    # 0x1B00103
    has(t, r'\tb_s\t436\t;0x1eea44\b')
    t = win('switch_exit', 0x1EEA44, 0x1EEA4C)
    has(t, r'\tb\.d\t1333048\t;0x33417c\b')            # restore r13..r18
    has(t, r'\tadd_s\tsp,sp,0x8')

    # --- Split path. ---
    t = win('split_head', 0x1EE958, 0x1EE9C4)
    has(t, r'\tld_s\tr0,\[sp,0\]')                    # ctxA
    has(t, r'\tadd_s\tr14,r14,r17')                   # r14 = cmd*cum + arg2
    has(t, r'\tldb_s\tr1,\[r0,0x10\]')                # ctxA[+0x10] count
    has(t, r'\tasl_s\tr1,r1,0x9')                     # count << 9
    has(t, r'\tbl\.d\t1339860\t;0x335b34\b')          # divide millicode
    has(t, r'\tmov_s\tr0,r18')                        # delay: dividend = arg3
    has(t, r'\tcmp_s\tr1,0\b')                        # remainder
    has(t, r'\tmov_s\tr2,r0\b')                        # quotient
    has(t, r'\tadd_s\tr2,r2,0x1')                     # ceil
    has(t, r'\tadd\tr0,r2,r17')                       # chunks + arg2
    has(t, r'\tcmp_s\tr13,r0\b')
    has(t, r'\tbhs_s\t6\t;0x1ee97a\b')                # accept window
    has(t, r'\tld_s\tr0,\[pcl,0x4c\]\t;0x1ee9c0\b')   # 0x1B00116
    has(t, r'\tcmp_s\tr2,0\b')                         # chunks == 0
    has(t, r'\tmov_s\tr0,0')
    has(t, r'\tcmp\tr16,0\b')                          # case 0?
    has(t, r'\tmov_s\tr0,r14\b')
    has(t, r'\tmov_s\tr1,r2\b')                        # chunks
    has(t, r'\tmov_s\tr2,r15\b')                       # arg1
    has(t, r'\tmov_s\tr3,0')
    has(t, r'\tbl_s\t-2744\t;0x1eded8\b')

    t = win('split_case0', 0x1EE9C4, 0x1EEA44)
    has(t, r'\tcmp\tr17,0\b')                          # arg2 must be 0
    has(t, r'\tbne_s\t-168\t;0x1ee920\b')
    has(t, r'\tld_s\tr0,\[r15,0\]')                    # arg1[0]
    has(t, r'\tld_s\tr1,\[sp,0x4\]')                   # ctxB
    has(t, r'\tst\tr0,\[r1,180\]')                    # ctxB[0xB4]
    has(t, r'\tld_s\tr0,\[r15,0x4\]')
    has(t, r'\tst\tr0,\[r1,184\]')                    # ctxB[0xB8]
    has(t, r'\tld_s\tr0,\[r15,0x8\]')
    has(t, r'\tst\tr0,\[r1,188\]')                    # ctxB[0xBC]
    has(t, r'\tld_s\tr0,\[r15,0xc\]')
    has(t, r'\tst\tr0,\[r1,192\]')                    # ctxB[0xC0]
    has(t, r'\tor\.f\t0,r3,r0')                       # all-zero test
    has(t, r'\tsth\tr0,\[r1,172\]')                   # ctxB[0xAC] = 0
    has(t, r'\tb_s\t-138\t;0x1ee976\b')                # -> 0x1B00116
    has(t, r'\tmov_s\tr1,r2\b')                        # chunks
    has(t, r'\tmov_s\tr2,r15\b')                       # arg1
    has(t, r'\tbl_s\t-2604\t;0x1edfdc\b')
    has(t, r'\tldb_s\tr0,\[r1,0x5\]')                 # cmd (ctxA again)
    has(t, r'\tasl_s\tr0,r0,0x9')
    has(t, r'\tbl\.d\t1333396\t;0x3342a8\b')           # (cmd<<9)*count
    has(t, r'\tldb_s\tr1,\[r1,0x10\]')                # delay: count
    has(t, r'\tbl\.d\t1339672\t;0x335b34\b')          # divide
    has(t, r'\tld\tr0,\[r13,184\]')                   # delay: ctxB[0xB8]
    has(t, r'\tcmp_s\tr0,0x50\b')
    has(t, r'\tsth\tr0,\[r13,172\]')                  # ctxB[0xAC]
    has(t, r'\tld_s\tr0,\[pcl,0x334\]\t;0x1eed6c\b')  # 0x1B00113
    has(t, r'\tmov_s\tr0,0')
    has(t, r'\tmov_s\tr1,r0')
    has(t, r'\tbl_s\t-2296\t;0x1ee148\b')              # hub markers

    # --- Millicode. ---
    t = win('millicode_save_334120', 0x334120, 0x33413A)
    for reg in ('r18', 'r17', 'r16', 'r15', 'r14', 'r13'):
        has(t, rf'\tst\.aw\t{reg},\[sp,-4\]')
    has(t, r'\tj_s\t\[blink\]')
    t = win('millicode_save_334104', 0x334104, 0x334120)
    for reg in ('r25', 'r24', 'r23', 'r22', 'r21', 'r20', 'r19'):
        has(t, rf'\tst\.aw\t{reg},\[sp,-4\]')
    t = win('millicode_restore_33417c', 0x33417C, 0x334184)
    has(t, r'\tmov_s\tr12,0x4\b')
    has(t, r'\tmov_s\tr13,0x18\b')
    has(t, r'\tb_s\t74\t;0x3341ca\b')
    t = win('millicode_mul_3342a8', 0x3342A8, 0x3342CC)
    has(t, r'\tsr\t0,\[aux_macmode\]')
    has(t, r'\tror\tr2,r1,0x10')
    has(t, r'\tmuludw\t0,r0,r2')
    has(t, r'\tadd\tr2,r56,r57')
    has(t, r'\tmuludw\t0,r0,r1')
    has(t, r'\tasl\tr2,r2,0x10')
    has(t, r'\tadd\tr0,r57,r2')
    has(t, r'\tj_s\t\[blink\]')

    # --- Twin dispatcher 0x1ED11C. ---
    t = win('twin_header', 0x1ED11C, 0x1ED17C)
    has(t, r'\tpush_s\tblink')
    has(t, r'\tbl\t1339392\t;0x33411c\b')
    has(t, r'\tsub_s\tsp,sp,0x8\b')
    has(t, r'\tmov_s\tr16,r0\b') and has(t, r'\tmov_s\tr18,r1\b')
    has(t, r'\tmov_s\tr19,r2\b') and has(t, r'\tmov_s\tr17,r3\b')
    has(t, r'\tmov_s\tr15,r4\b')                     # output pointer
    has(t, r'\tbl\.d\t454280\t;0x25bfb8\b')          # same guard
    has(t, r'\tstb\tr1,\[r18\]')                     # 0xFF to arg1 on fail
    has(t, r'\tst_s\tr0,\[r15,0\]')                  # 0 to output
    has(t, r'\tbl\.d\t457120\t;0x25caec\b')
    has(t, r'\tbl\.d\t454352\t;0x25c020\b')
    has(t, r'\tcmp\tr16,0x6\b')
    has(t, r'\tbhi\t180\t;0x1ed210\b')
    has(t, r'\tadd\tr12,pcl,0x10\t;0x1ed17c\b')
    has(t, r'\tmov_s\tr1,r16\b')
    has(t, r'\tldb\.x\tr1,\[r12,r1\]')
    has(t, r'\tj_s\.d\t\[r12\]')
    has(t, r'\tldb_s\tr2,\[r0,0x5\]')                # cmd byte delay slot
    for case, target in enumerate(twin_targets):
        t = win(f'twin_case_{case}', target, target + 0x12)
        has(t, rf'\tldh\tr1,\[r3,{196 + case * 2}\]')
        has(t, r'\tmuludw\t0,r[12],r[12]')
        has(t, r'\tmov\tr13,r57')
        has(t, rf'\tldh\tr1,\[r3,{210 + case * 2}\]')
        if case != 4:
            has(t, r'\tb_s\t-?\d+\t;0x1ed1dc\b')
    t = win('twin_shared', 0x1ED1DC, 0x1ED210)
    has(t, r'\tmuludw\t0,r1,r2')
    has(t, r'\tmov\.f\tr14,r57')
    has(t, r'\tbne_s\t58\t;0x1ed21e\b')
    has(t, r'\tst_s\tr0,\[r15,0\]')                   # output = 0
    t = win('twin_default', 0x1ED210, 0x1ED21E)
    has(t, r'\tmov_s\tr1,0xff\b')
    has(t, r'\tstb\tr1,\[r18\]')
    has(t, r'\tst_s\tr0,\[r15,0\]')
    has(t, r'\tld_s\tr0,\[pcl,0xe8\]\t;0x1ed300\b')

    # --- Orchestrator 0x29E9C4: budget, type check, r21, seven calls. ---
    t = win('orch_entry', 0x29E9C4, 0x29EA06)
    has(t, r'\tsub_s\tsp,sp,0x18\b')
    has(t, r'\tpush_s\tblink')
    has(t, r'\tbl\t612156\t;0x334104\b')
    has(t, r'\tsub\tsp,sp,316\b')
    has(t, r'\tst_s\tr0,\[sp,0\]')
    has(t, r'\tst_s\tr1,\[sp,0x4\]')
    has(t, r'\tst\.as\tr1,\[sp,94\]')                 # spill a1
    has(t, r'\tst_s\tr2,\[sp,0x8\]')
    has(t, r'\tst\.as\tr2,\[sp,95\]')                 # spill a2
    has(t, r'\tst_s\tr3,\[sp,0xc\]')
    has(t, r'\tst\.as\tr3,\[sp,96\]')                 # spill a3
    has(t, r'\tst\tr4,\[sp,16\]')
    has(t, r'\tst\tr5,\[sp,20\]')
    has(t, r'\tmov_s\tr14,r6\b')
    has(t, r'\tmov_s\tr13,r7\b')
    has(t, r'\tbl\.d\t-272956\t;0x25bfb8\b')          # guard -> ctxB
    has(t, r'\tst\.as\tr0,\[sp,70\]')                 # delay: ctxB pointer
    has(t, r'\tcmp_s\tr0,0\b')
    has(t, r'\tld_s\tr0,\[pcl,0x184\]\t;0x29eb88\b')  # 0x1B00101

    t = win('orch_budget', 0x29EA06, 0x29EA52)
    has(t, r'\tbl\.d\t-270104\t;0x25caec\b')           # ctxA resolver
    has(t, r'\tldh\.as\tr0,\[sp,189\]')               # p1 = hi(a1)
    has(t, r'\tldh\.as\tr1,\[sp,190\]')               # p2 = lo(a2)
    has(t, r'\tadd_s\tr0,r0,0x3')
    has(t, r'\tadd1_s\tr0,r0,r1')                      # + 2*p2
    has(t, r'\tldh\.as\tr1,\[sp,191\]')               # p3 = hi(a2)
    has(t, r'\tadd1_s\tr0,r0,r1')                      # + 2*p3
    has(t, r'\tldh\.as\tr1,\[sp,192\]')               # p4 = lo(a3)
    has(t, r'\tldh\.as\tr0,\[sp,193\]')               # p5 = hi(a3)
    has(t, r'\tldb_s\tr1,\[r2,0\]')                    # ctxA[+0] type
    has(t, r'\tcmp_s\tr1,0x3\b')
    has(t, r'\tcmp_s\tr1,0x4\b')
    has(t, r'\tcmp_s\tr1,0x5\b')
    has(t, r'\tldw_s\tr2,\[r2,0x8\]')                  # ctxA[+8] budget
    has(t, r'\tld_s\tr0,\[pcl,0x148\]\t;0x29eb8c\b')  # 0x1B00106

    t = win('orch_r21', 0x29EA52, 0x29EA92)
    has(t, r'\tbl\.d\t-272944\t;0x25c020\b')          # ctxB resolver
    has(t, r'\tldb_s\tr1,\[r0,0x5\]')                 # cmd
    has(t, r'\tasl_s\tr1,r1,0x9')
    has(t, r'\tbl\.d\t612424\t;0x3342a8\b')           # (cmd<<9)*count
    has(t, r'\tldb_s\tr0,\[r0,0x10\]')                # delay: count
    has(t, r'\tmov_s\tr21,r0\b')                       # r21 = time unit
    has(t, r'\tld\.as\tr15,\[sp,70\]')                # ctxB
    has(t, r'\tldh\tr0,\[r15,226\]')                  # ctxB[0xE2]
    has(t, r'\tbl\.d\t612404\t;0x3342a8\b')
    has(t, r'\tmov_s\tr1,r21')                         # delay
    has(t, r'\tld\.as\tr1,\[sp,99\]')
    has(t, r'\tbls_s\t8\t;0x29ea88\b')
    has(t, r'\tld_s\tr0,\[pcl,0x10c\]\t;0x29eb90\b')  # 0x1B00111
    has(t, r'\tadd3\tr0,sp,0x23')
    has(t, r'\tmov_s\tr1,r15\b')
    has(t, r'\tbl\.d\t-2036076\t;0xad920\b')          # mirror copy
    has(t, r'\tmov_s\tr2,0xf4')                        # delay: 244 bytes

    # Seven twin-dispatcher pre-calls (products via 0x3342A8, target 0x1ED11C).
    # The block at 0x29EB5C jumps over an inline pool (0x29EB60..0x29EB98),
    # so the region is split in two windows aligned at real boundaries.
    t = win('orch_twin_precalls_a', 0x29EABA, 0x29EB5E)
    has(t, r'\tld_s\tr15,\[pcl,0xd0\]\t;0x29eb94\b')   # 0x1ED11C
    for case in range(6):
        has(t, rf'\tldh\tr0,\[sp,{232 + case * 2}\]')
        has(t, rf'\tmov_s\tr0,0x{case:x}\b' if case else r'\tmov_s\tr0,0\b')
    has(t, r'\tb_s\t60\t;0x29eb98\b')                  # skip inline pool
    assert len(re.findall(r'\tjl_s\.d\t\[r15\]', t)) == 5
    assert len(re.findall(r'\tbl\.d\t61[12]\d+\t;0x3342a8\b', t)) == 6
    t = win('orch_twin_precalls_b', 0x29EB98, 0x29EBB8)
    has(t, r'\tldh\tr0,\[sp,244\]')
    has(t, r'\tmov_s\tr0,0x6\b')
    has(t, r'\tadd_s\tr1,r0,r14')
    has(t, r'\tadd\tr4,r4,308')                         # delay: output slot
    has(t, r'\tadd3\tr4,sp,0x27')                       # delay: output slot
    assert len(re.findall(r'\tjl_s\.d\t\[r15\]', t)) == 2
    assert len(re.findall(r'\tbl\.d\t61[12]\d+\t;0x3342a8\b', t)) == 1

    # Seven switch calls: arg0 = case index, arg2 = 0, arg3 = max.
    for case, site in enumerate(LOOP_SITES):
        t = win(f'orch_switch_call_{case}', site - 0x40, site + 0x10)
        has(t, rf'\tldh\tr0,\[sp,{232 + case * 2}\]')
        assert len(re.findall(r'\tbl\.d\t61[12]\d+\t;0x3342a8\b', t)) == 2
        has(t, r'\tld\.as\tr0,\[sp,70\]')              # ctxB
        has(t, rf'\tldh\tr0,\[r0,{210 + case * 2}\]')  # live parameter field
        has(t, rf'\tld\.as\tr1,\[sp,{72 + case}\]')
        has(t, r'\tcmp_s\tr1,r0\b')
        has(t, r'\tmov\.c\tr15,r1')
        has(t, r'\tmov\.nc\tr15,r0')
        has(t, r'\tcmp_s\tr15,0\b')
        if case == 0:
            has(t, r'\tldh\tr0,\[sp,208\]')
            has(t, r'\tble\t78\t;0x29ecea\b')
        has(t, r'\tadd\tr\d+,r\d+,r14')
        has(t, rf'\tmov_s\tr0,0x{case:x}\b' if case else r'\tmov_s\tr0,0\b')
        if case == 0:
            # r2 = r0 (which is 0) in the first site; immediate 0 afterwards.
            has(t, r'\tmov_s\tr2,r0')
        else:
            has(t, r'\tmov_s\tr2,0\b')                  # budget arg2 = 0
        has(t, r'\tbl\.d\t-722\d+\t;0x1ee730\b')
        has(t, r'\tmov_s\tr3,r15')                      # delay: arg3 = max
        has(t, r'\tcmp_s\tr13,0\b')                     # caller-side r13 = arg7

    # --- Bulk wrapper 0x1EEA4C (512-block preparation before the switch). ---
    t = win('bulk_wrapper_1eea4c', 0x1EEA4C, 0x1EEABC)
    has(t, r'\tsub_s\tsp,sp,0x4\b')
    has(t, r'\tpush_s\tblink')
    has(t, r'\tbl\t1332948\t;0x334124\b')
    has(t, r'\tadd\tr0,r0,511\b')
    has(t, r'\tlsr\tr16,r0,0x9')                       # ceil(arg3/512)
    has(t, r'\tld_s\tr0,\[pcl,0x30c\]\t;0x1eed70\b')  # 0x1B00001
    has(t, r'\tbl\.d\t-612028\t;0x1593ac\b')
    has(t, r'\tbl\.d\t468324\t;0x260fe4\b')           # size query
    has(t, r'\tmov_s\tr5,r14')                         # delay
    has(t, r'\tld_s\tr3,\[sp,0x4\]')
    has(t, r'\tasl_s\tr3,r3,0xb')
    has(t, r'\tbl_s\t-884\t;0x1ee730\b')
    has(t, r'\tmov_s\tr0,r13\b')
    has(t, r'\tmov_s\tr12,0x8\b')
    has(t, r'\tb\.d\t1332942\t;0x334186\b')

    # --- 0x261xxx family callers. ---
    for site in (0x261104, 0x2611A6):
        t = win(f'caller_261_{site:x}', site - 0x40, site + 0x10)
        has(t, r'\tbl\.d\t-475\d+\t;0x1ed11c\b')
        has(t, r'\tbl\.d\t-923\d+\t;0x17faf8\b')
        has(t, r'\tbl\.d\t-469\d+\t;0x1ee730\b')
        has(t, r'\tbset_s\tr[13],r[13],0xb\b')

    # --- Models (documented conditional MULUDW hypothesis). ---
    rng = random.Random(20261022)
    for _ in range(4096):
        a = rng.randrange(1 << 32)
        b = rng.randrange(1 << 32)
        assert model_millicode_mul(a, b) == (a * b) & 0xFFFFFFFF
    # Edge cases for the recombination.
    for a, b in ((1, 0x10000), (0xFFFFFFFF, 0xFFFFFFFF), (0, 0x12345),
                 (0x10000, 0x10000), (0xFFFF, 0xFFFF)):
        assert model_millicode_mul(a, b) == (a * b) & 0xFFFFFFFF

    # Budget formula from the packed record words: a1={.,p1}, a2={p2,p3},
    # a3={p4,p5}; the spill halfwords read by ldh.as 189..193 are
    # hi(a1), lo(a2), hi(a2), lo(a3), hi(a3) == p1..p5 of the record.
    def packed_budget(a1, a2, a3):
        p1, p2, p3, p4, p5 = ((a1 >> 16) & 0xFFFF, a2 & 0xFFFF,
                              (a2 >> 16) & 0xFFFF, a3 & 0xFFFF,
                              (a3 >> 16) & 0xFFFF)
        return 3 + p1 + 2 * p2 + 2 * p3 + p4 + p5, (p1, p2, p3, p4, p5)

    def intake_bound_core(p1, p2, p3, p4, p5):
        # iteration 9: 4 + p1 + 2*p2 + 2*p3 + p4 + p5 + 10 <= ctxA[+8]
        return p1 + 2 * p2 + 2 * p3 + p4 + p5

    for _ in range(4096):
        a1, a2, a3 = (rng.randrange(1 << 32) for _ in range(3))
        total, (p1, p2, p3, p4, p5) = packed_budget(a1, a2, a3)
        assert total == 3 + intake_bound_core(p1, p2, p3, p4, p5)
        # spill layout: halfwords at sp+378..386 (st.as x4 at 376/380/384)
        assert ((a1 >> 16) & 0xFFFF) == p1
        assert (a2 & 0xFFFF) == p2 and ((a2 >> 16) & 0xFFFF) == p3
        assert (a3 & 0xFFFF) == p4 and ((a3 >> 16) & 0xFFFF) == p5

    # Switch products: both operands < 2^16, so under the hypothesis r13/r14
    # are the exact products cmd*cumulative and cmd*parameter.
    for _ in range(1024):
        cmd = rng.randrange(0x100)
        cum = rng.randrange(0x10000)
        par = rng.randrange(0x10000)
        r57, r56 = model_muludw_hyp(cmd, cum)
        assert r56 == 0 and r57 == cmd * cum
        r57, r56 = model_muludw_hyp(cmd, par)
        assert r56 == 0 and r57 == cmd * par

    # Split arithmetic: chunks = ceil(arg3/(count<<9)); accepted window
    # arg2 < cmd*param < arg2 + chunks.
    for _ in range(1024):
        arg2 = rng.randrange(0x10000)
        arg3 = rng.randrange(1 << 20)
        count = rng.randrange(1, 0x100)
        cmd = rng.randrange(1, 0x100)
        par = rng.randrange(0x10000)
        div = count << 9
        q, rem = divmod(arg3, div)
        chunks = q + (1 if rem else 0)
        r13 = cmd * par
        if r13 <= arg2:
            path = 'normal'
        elif chunks == 0:
            path = 'return0'
        elif r13 < arg2 + chunks:
            path = 'split'
        else:
            path = 'error_0x1B00116'
        assert (path == 'normal') == (r13 <= arg2)
        if r13 > arg2:
            assert (path == 'split') == (0 < chunks and r13 < arg2 + chunks)

    (out / 'gnu_windows.txt').write_text(
        '\n\n'.join(f'=== {k} ===\n{v}' for k, v in windows.items()))

    result = {
        'analysis': 'STATIC decode of switch 0x1EE730 (consumer of ctxB '
                    'command fields 0xC4..0xDE), its split path, its twin '
                    'dispatcher 0x1ED11C and its callers in the orchestrator '
                    'module 0x29E9C4',
        'firmware_reference': 'Nikon S33 V1.1 (camera observed V1.0; offsets '
                              'not portable without proof)',
        'switch_callers_payload0': [he(c) for c in SWITCH_CALLERS],
        'switch_structure': {
            'header': 'guard 0x25BFB8 (fail -> 0x1B00101), ctxA 0x50F52C / '
                      'ctxB 0x50F420 resolvers, cmd byte r2 = ctxA[+5] in '
                      'the delay slot of the dispatch, bound 0..6 '
                      '(default -> 0x1B00103)',
            'phase1_jump_table_0x1ee77a': JT1.hex(' '),
            'phase1_cases': 'case c: r14 = cmd*ctxB[196+2c] (cumulative '
                            '0xC4..0xD0), r13 = cmd*ctxB[210+2c] (parameter '
                            '0xD2..0xDE); sr 0,[aux_macmode] + muludw; both '
                            'operands < 2^16',
            'shared_tail': 'budget r13 > arg2 -> split 0x1EE958; bit0xA of '
                           'ctxA[+2] clear -> return 0x1B00115; set -> '
                           'desc 0x36B254 = {0,4,0} + transaction '
                           '0x25F338(0x54D8A8, 0x50E940, desc) + copy of 244 '
                           'bytes from 0x54DAB2 (buf512+0x20A, response '
                           'record) INTO ctxB 0x50F420',
            'phase2_jump_table_0x1ee852': JT2.hex(' '),
            'phase2': 'same 7 field pairs re-read from the UPDATED ctxB '
                      '(r1 = cmd, r2 = ctxB post-copy), re-check r13 vs '
                      'arg2, exit 0x1B00115',
            'split_path': 'r14 += arg2; chunks = ceil(arg3/(ctxA[+0x10]<<9)); '
                          'accepted window arg2 < cmd*param < arg2+chunks, '
                          'outside -> 0x1B00116; chunks==0 -> return 0; '
                          'case 0 -> ctxB[0xB4..0xC0] = arg1 words, '
                          '0x1EDFDC, ctxB[0xAC] = '
                          'ceil(ctxB[0xB8]/((cmd<<9)*ctxA[+0x10])) <= 0x50 '
                          '(else 0x1B00113), hub 0x1EE148(0,0); cases 1..6 '
                          '-> 0x1EDED8(cmd*cum+arg2, chunks, arg1, 0)',
        },
        'twin_dispatcher_0x1ed11c': {
            'jump_table_0x1ed17c': JT_TWIN.hex(' '),
            'shape': 'same guard, resolvers, cmd byte in delay slot, same 7 '
                     'field pairs (196..222 on ctxB); output written to '
                     '[arg4]; error paths store 0xFF to [arg1] and 0 to '
                     'the output; shared tail 0x1ED1DC: r14 = cmd*param '
                     'with flags, then compare vs arg2',
        },
        'millicode': {
            '0x334120': 'saves r18,r17,r16,r15,r14,r13 (st.aw each) + '
                        'j_s [blink]; 0x33417C is the matching restore entry',
            '0x334104': 'saves r25..r19 (used by 0x29E9C4)',
            '0x3342a8': 'GCC 32x32 multiply helper: under the documented '
                        'conditional MULUDW hypothesis the recombination '
                        'equals (r0*r1) mod 2^32 (modelled and asserted on '
                        '4096 random pairs + edge cases)',
        },
        'orchestrator_0x29e9c4': {
            'budget': 'from the packed record words a1={.,p1}, a2={p2,p3}, '
                      'a3={p4,p5} (spilled by st.as at sp+376/380/384, read '
                      'back by ldh.as at sp+378..386): '
                      '3 + p1 + 2*p2 + 2*p3 + p4 + p5 <= ctxA[+8], error '
                      '0x1B00106; same parametric core as the intake bound '
                      'of iteration 9 (14 + same core <= ctxA[+8])',
            'type_check': 'ctxA[+0] compared against 3, 4, 5',
            'time_unit': 'r21 = (ctxA[+5]<<9) * ctxA[+0x10] via 0x3342A8',
            'pre_calls': 'seven calls to 0x1ED11C (target from pool '
                         '0x29EB94), one per case, products of the local '
                         'halfwords sp[232..244] with r21 via 0x3342A8',
            'switch_calls': 'seven calls to 0x1EE730 at 0x29ECAC/0x29ED20/'
                            '0x29ED8A/0x29EDF2/0x29EE5A/0x29EEC2/0x29EF2A '
                            'with arg0 = 0..6, arg2 = 0, arg3 = max(sp-slot '
                            'word 72+c, ctxB[210+2c]*r21); case 0 has an '
                            'extra guard (sp[208] > 0); after each call the '
                            'caller-side r13 (= arg7) is tested',
            'mirror_copy': '244 bytes copied from ctxB into the local frame '
                           'at 0x29EA8C (sp-relative destination); frame '
                           'layout arithmetic not fully resolved (open)',
        },
        'other_callers': {
            '0x1eea4c': '512-block wrapper: r16 = (arg3+511)>>9, check '
                        '0x1593AC(0x1B00001, 0), size query 0x260FE4, then '
                        'the switch with arg2 = result of the query',
            '0x261xxx': 'family calling 0x1ED11C, 0x17FAF8 and the switch '
                        'with bit 0xB set on the size arguments',
        },
        'byte_verified': {
            'jump_tables': {'0x1ee77a': JT1.hex(' '), '0x1ee852': JT2.hex(' '),
                            '0x1ed17c': JT_TWIN.hex(' ')},
            'pools': {**{he(a): hex(v) for a, v in POOLS_1EE.items()},
                      **{he(a): hex(v) for a, v in POOLS_29E.items()}},
            'return_codes': ['0x1B00101 guard', '0x1B00103 default',
                             '0x1B00111 ctxB[0xE2] limit',
                             '0x1B00113 ctxB[0xAC] > 0x50',
                             '0x1B00115 normal/bit-clear exit',
                             '0x1B00116 split window violated',
                             '0x1B00106 orchestrator budget'],
        },
        'windows_verified': sorted(windows),
        'limits': [
            'static only: no MMIO, lens MCU or camera hardware accessed; no '
            'firmware executed',
            'MULUDW semantics remain the documented conditional hypothesis '
            '(r57 = lo16*lo16, r56 = hi16*hi16), not CPU-proven; the '
            'firmware multiply millicode 0x3342A8 relies on the same '
            'channel mapping, which strengthens but does not prove it',
            'the case products cmd*cumulative and cmd*parameter are exact '
            'only under that hypothesis (both operands < 2^16)',
            'runtime values (cmd byte, ctxA[+8] budget, ctxA[+0x10] count, '
            'bit 0xA of ctxA[+2]) are not determinable statically',
            'frame arithmetic of 0x29E9C4 (add3 scale of the 0x23/0x27 '
            ' immediates, exact location of the 244-byte mirror and of the '
            'sp[232..244] products) is not fully resolved; the budget '
            'interpretation relies on the st.as/ldh.as scale reasoning '
            '(x4 word spill at sp+376/380/384, halfword reads at '
            'sp+378..386)',
            'physical meaning of the cumulative/parameter fields (times, '
            'positions, budgets) is inference from the arithmetic; the '
            'MCU-side semantics of the wire bytes is not re-derived here',
            'the wire transaction layer is cross-referenced from iteration 1 '
            '(0x25F338, sender 0x25CB54) and not re-verified in this run',
            'V1.1 analysed vs camera V1.0: offsets not portable without '
            'proof',
        ],
        'sources': {str(p): sha(p) for p in [
            Path(__file__), FIRMWARE,
            ROOT / 'S33-sections/TBM_blocks/manifest.json',
            ROOT / 'work/build-arc/binutils/objcopy',
            ROOT / 'work/build-arc/binutils/objdump']},
    }
    (out / 'verified_evidence.json').write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    (EVIDENCE / 'latest.json').write_text(json.dumps(
        dict(evidence=str((out / 'verified_evidence.json').relative_to(ROOT))))
        + '\n')
    print('PASS', out)
    print('switch callers:', [hex(c) for c in SWITCH_CALLERS])
    print('jt1 targets:', [hex(t) for t in jt1_targets])
    print('jt2 targets:', [hex(t) for t in jt2_targets])
    print('twin targets:', [hex(t) for t in twin_targets])


if __name__ == '__main__':
    main()
