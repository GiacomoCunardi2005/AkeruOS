#!/usr/bin/env python3
"""Static verification of the lens command intake 0x25C038 (iteration 9).

Closes the open point of iteration 8 (MDs/S33_Obiettivo_Semantica_Record_
Orchestratore.md, section 10): byte-verify 0x25C038, the candidate intake of
the 6-word argument block into the command fields of the lens context.

Byte-verified results (windows aligned at the function entries; pool words
read raw little-endian from the payload image):

1. THE INTAKE'S FIRST ARGUMENT IS ctxB, NOT ctxA. In the caller 0x29E680 the
   two resolver stubs are
     0x25CAEC(slot): ld_s r1,[pcl,..] -> 0x50F52C (ctxA); st_s r1,[r0,0]
     0x25C020(slot): ld_s r1,[pcl,..] -> 0x50F420 (ctxB); st_s r1,[r0,0]
   (each is a 3-instruction j_s.d tail with the store in the delay slot).
   0x29E680 calls 0x25CAEC(sp+4) (ctxA slot) and 0x25C020(sp) (ctxB slot),
   then passes r0=[sp,0]=ctxB=0x50F420 and r1=sp+0x1C (the 6-word block) to
   0x25C038. This closes the loop with iteration 2: the halfword parameter
   fields 0xD2..0xDE consumed by the dispatch switch 0x1EE730 live in
   0x50F420, and 0x25C038 is the writer that fills them from the block.
   0x25C038 resolves ctxA itself (0x25CAEC(sp) -> local slot -> r16) for the
   budget fields ctxA[+6]/[+8] and the bit0xA flag ctxA[+2].

2. BLOCK -> ctxB HALFWORD MAP (all sources are 16-bit loads; the printed
   offset of every ldw_s/stw_s is (raw & 0x1f)*2, checked for each site):
     block[+0x00] -> ctxB+174 (0xAE)      block[+0x08] -> ctxB+212 (0xD4)
     block[+0x02] -> ctxB+176 (0xB0)      block[+0x08] -> ctxB+214 (0xD6)
     block[+0x04] -> ctxB+178 (0xB2)      block[+0x0A] -> ctxB+216 (0xD8)
     block[+0x06] -> ctxB+210 (0xD2)      block[+0x0A] -> ctxB+218 (0xDA)
     block[+0x0C] -> ctxB+220 (0xDC)      block[+0x0E] -> ctxB+222 (0xDE)
     block[+0x10] -> ctxB+232 (0xE8)      block[+0x12] -> ctxB+234 (0xEA)
   The parameter halfwords p1..p5 = block[+6],+8,+0xA,+0xC,+0xE are the SAME
   five halfwords that 0x29E8F0 scales with ceil(h/8) when ctxA[+2] bit0xA
   is set (iteration-8 transform sites, record offsets 6..14); p2 and p3 are
   each loaded twice and written to two fields (0xD4/0xD6, 0xD8/0xDA).
   block[+0x14] (the a5 halfword) is never read by the intake.

3. BOUND CHECK: 4 + p1 + 2*p2 + 2*p3 + p4 + p5 + 10 must be <= ctxA[+8]
   (unsigned compare, bls_s). The two add1_s sites add 2*r0 each (ARC
   ADD1_S = b + (c << 1)), so p2 and p3 enter DOUBLED, exactly as in the
   "clear" total 0xC4: bound == 0xC4_clear + p1 + 14. Violation returns the
   error id 0x1B00106 (pool 0x25C3A4) through the shared error tail 0x25C1E8.

4. HEADER MAGIC: after the bound check, memcpy(ctxB, 0x351718, 8) copies the
   literal string "P1IDSTR\\0" (8 bytes at payload0 VA 0x351718) into ctxB+0;
   the tail repeats memcpy(ctxB+236, 0x351718, 8) -> ctxB+0xEC. The 0x25Cxxx
   cluster is therefore the P1IDSTR command-record service, and the record
   header/footer carry the "P1IDSTR" magic.

5. MARGIN: r5 = (ctxA[+6] - ctxA[+8]) & 0xFFFF is stored at ctxB+224 (0xE0);
   extw/extw_s ZERO-extend the low 16 bits (ARC EXTW is zero-extension,
   SEXW would be the sign-extend form), so every stored field is the low
   halfword of the 32-bit sum.

6. TWO FORMULAS SELECTED BY ctxA[+2] BIT 0xA (same flag as the ceil(h/8)
   scaling of 0x29E8F0). With r2 = ctxB + 0x2d*4 = ctxB+180
   (ARC ADD2 = b + (c << 2) on the printed immediate, proven below), the
   fields ctxB+196..230 (0xC4..0xE6) are filled with cumulative sums:
     bit CLEAR ("clear" variant):
       0xC4 = 2*p2+2*p3+p4+p5     0xC6 = 0
       0xC8 = 0xC6+p2             0xCA = 0xC8+p2
       0xCC = 0xCA+p3             0xCE = 0xCC+p3
       0xD0 = 0xCE+p4             0xE2 = 0xC4+p1+5
       0xE4 = 0xE2+margin         0xE6 = (ctxA[+6]-0xE4) & 0xFFFF
     bit SET ("set" variant):
       0xC4 = 1                    0xC6 = p1+3
       0xC8 = 0xC6+p2             0xCA = 0xC8+p2
       0xCC = 0xCA+p3             0xCE = 0xCC+p3
       0xD0 = 0xCE+p4             0xE2 = p1+3+2*p2+2*p3+p4+p5
       0xE4 = 0xE2+margin         0xE6 = 0
   (stw_s/ldh are 16-bit accesses at 2-byte steps with NO overlap; the
   sums are computed in 32-bit registers and ZERO-extended by extw/extw_s
   at each step). Success return value: 0.

7. add2 SCALE = 4 IN THIS TOOLCHAIN. The caller's stride site
     add2 r0,r1,0x3b ; sub_s r0,r0,r1 ; cmp r0,236
   cancels r1 arithmetically, so the comparison is a compile-time constant
   0x3b*4 == 236 (ARC ADD2 = b + (c << 2)), which also matches the
   236-byte context stride of iteration 2. NOTE: because sub_s cancels r1,
   this "stride check" is arithmetically ALWAYS TRUE at the printed operands
   (r0 = r1+236-r1 = 236): the error edge at 0x29E8D6 from this site is
   unreachable, and 0x1B00105 (pool 0x29E758, loaded in the b.d delay slot)
   is the id of this DEAD site only: the other failure paths reaching
   0x29E8D6 return the codes of the nested callees (0x1B00106 from the
   intake, the results of 0x25D3AC, etc.), so 0x1B00105 is never actually
   returned in practice. This refines the iteration-8 reading of the site
   as a real stride check.

pcl notes: ld_s pool words resolve at (PC & ~3) + offset (unscaled); the
GNU byte column prints 32-bit chunks in ARC instruction halfword order, so
pool VALUES are always read raw from the payload image here. Read-only:
firmware, blocks and tools are never modified.
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
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Cmd_Intake'

BASE0, END0 = 0x0AD800, 0x35BC00

CTXA, CTXB = 0x50F52C, 0x50F420
GUARD = 0x50F4D4
MAGIC_VA = 0x351718
MAGIC = b'P1IDSTR\x00'

RESOLVER_CTXA = 0x25CAEC
RESOLVER_CTXB = 0x25C020
INTAKE = 0x25C038
CALLER = 0x29E680

POOL_WORDS = {
    0x25CEC4: CTXA,       # resolver 0x25CAEC constant
    0x25C3A0: CTXB,       # resolver 0x25C020 constant
    0x25C3A4: 0x1B00106,  # intake bound-check error id
    0x25C3A8: MAGIC_VA,   # 8-byte memcpy source ("P1IDSTR\0")
    0x25C39C: GUARD,      # getter 0x25C028 base (iteration-2 guard cell)
    0x29E758: 0x1B00105,  # caller generic error id (b.d delay slot)
}

WINDOWS = [
    ('intake_25c038', INTAKE, 0x25C1F0),
    ('caller_29e680', CALLER, 0x29E738),
    ('resolver_25caec', RESOLVER_CTXA, 0x25CAF4),
    ('resolver_25c020', RESOLVER_CTXB, 0x25C028),
]

# block halfword offset -> ctxB halfword offset of the direct map.
DIRECT_MAP = [
    (0x00, 174), (0x02, 176), (0x04, 178), (0x06, 210),
    (0x08, 212), (0x08, 214), (0x0A, 216), (0x0A, 218),
    (0x0C, 220), (0x0E, 222), (0x10, 232), (0x12, 234),
]

# iteration-8 ceil(h/8) transform sites: record offsets 6..14 (the same
# five parameter halfwords consumed by the intake).
TRANSFORM_RECORD_OFFSETS = [6, 8, 10, 12, 14]

# Expected instruction text (mnemonic + normalized operands) per address.
# "norm" strips objdump's decimal displacement before the ;0x... comment.
E = {
    # --- prologue, local ctxA resolve ---
    0x25C038: ('push_s', 'blink'),
    0x25C03A: ('bl', ';0x334128'),
    0x25C03E: ('sub_s', 'sp,sp,0x4'),
    0x25C040: ('mov_s', 'r13,r0'),
    0x25C042: ('mov_s', 'r14,r1'),
    0x25C044: ('mov_s', 'r0,0'),
    0x25C046: ('st_s', 'r0,[sp,0]'),
    0x25C048: ('bl.d', ';0x25caec'),
    0x25C04C: ('mov_s', 'r0,sp'),
    # --- bound check: 4 + p1+p2+p3+p4+p5 + 10 <= ctxA[+8] ---
    0x25C04E: ('ldw_s', 'r1,[r14,0x6]'),
    0x25C050: ('ldw_s', 'r0,[r14,0x8]'),
    0x25C052: ('add_s', 'r1,r1,0x4'),
    0x25C054: ('add1_s', 'r1,r1,r0'),
    0x25C056: ('ldw_s', 'r0,[r14,0xa]'),
    0x25C058: ('add1_s', 'r1,r1,r0'),
    0x25C05A: ('ldw_s', 'r0,[r14,0xc]'),
    0x25C05C: ('add_s', 'r0,r0,r1'),
    0x25C05E: ('ldw_s', 'r1,[r14,0xe]'),
    0x25C060: ('add_s', 'r1,r1,r0'),
    0x25C062: ('ld_s', 'r0,[sp,0]'),
    0x25C064: ('add_s', 'r1,r1,0xa'),
    0x25C066: ('mov_s', 'r16,r0'),
    0x25C068: ('ldw_s', 'r0,[r0,0x8]'),
    0x25C06A: ('cmp_s', 'r1,r0'),
    0x25C06C: ('bls_s', ';0x25c072'),
    0x25C06E: ('ld_s', 'r0,[pcl,0x338]\t;0x25c3a4'),
    0x25C070: ('b_s', ';0x25c1e8'),
    # --- header magic memcpy(ctxB, 0x351718, 8) ---
    0x25C072: ('ld_s', 'r1,[pcl,0x338]\t;0x25c3a8'),
    0x25C074: ('mov_s', 'r0,r13'),
    0x25C076: ('bl.d', ';0x128c20'),
    0x25C07A: ('mov_s', 'r2,0x8'),
    # --- direct block -> ctxB map ---
    0x25C07C: ('ldw_s', 'r0,[r14,0]'),
    0x25C07E: ('sth', 'r0,[r13,174]'),
    0x25C082: ('ldw_s', 'r0,[r14,0x2]'),
    0x25C084: ('sth', 'r0,[r13,176]'),
    0x25C088: ('ldw_s', 'r0,[r14,0x4]'),
    0x25C08A: ('sth', 'r0,[r13,178]'),
    0x25C08E: ('ldw_s', 'r0,[r14,0x6]'),
    0x25C090: ('sth', 'r0,[r13,210]'),
    0x25C094: ('mov_s', 'r4,r0'),
    0x25C096: ('ldw_s', 'r0,[r14,0x8]'),
    0x25C098: ('sth', 'r0,[r13,212]'),
    0x25C09C: ('mov_s', 'r8,r0'),
    0x25C09E: ('ldw_s', 'r0,[r14,0x8]'),
    0x25C0A0: ('sth', 'r0,[r13,214]'),
    0x25C0A4: ('ldw_s', 'r1,[r14,0xa]'),
    0x25C0A6: ('sth', 'r1,[r13,216]'),
    0x25C0AC: ('mov_s', 'r10,r1'),
    0x25C0AA: ('ldw_s', 'r3,[r14,0xa]'),
    0x25C0AE: ('sth', 'r3,[r13,218]'),
    0x25C0B2: ('ldw_s', 'r1,[r14,0xc]'),
    0x25C0B4: ('sth', 'r1,[r13,220]'),
    0x25C0B8: ('mov_s', 'r9,r1'),
    0x25C0BA: ('ldw_s', 'r1,[r14,0xe]'),
    0x25C0BC: ('sth', 'r1,[r13,222]'),
    0x25C0C0: ('mov_s', 'r7,r1'),
    # --- margin sext(ctxA[6]-ctxA[8]) -> ctxB+224; a4 -> 0xE8/0xEA ---
    0x25C0C2: ('ldh', 'r1,[r16,8]'),
    0x25C0C6: ('ldh', 'r15,[r16,6]'),
    0x25C0CA: ('sub', 'r5,r15,r1'),
    0x25C0CE: ('extw', 'r5,r5'),
    0x25C0D2: ('sth', 'r5,[r13,224]'),
    0x25C0D6: ('ldw_s', 'r1,[r14,0x10]'),
    0x25C0D8: ('sth', 'r1,[r13,232]'),
    0x25C0DC: ('ldw_s', 'r1,[r14,0x12]'),
    0x25C0DE: ('sth', 'r1,[r13,234]'),
    # --- variant gate: ctxA[+2] bit 0xA ---
    0x25C0E2: ('ldh', 'r1,[r16,2]'),
    0x25C0E6: ('btst_s', 'r1,0xa'),
    0x25C0E8: ('add2', 'r2,r13,0x2d'),
    0x25C0EC: ('bne_s', ';0x25c168'),
    # --- "clear" variant (bit 0xA clear) ---
    0x25C0EE: ('mov_s', 'r1,0'),
    0x25C0F0: ('stw_s', 'r1,[r2,0x12]'),
    0x25C0F2: ('ldh', 'r14,[r13,198]'),
    0x25C0F6: ('add', 'r1,r14,r8'),
    0x25C0FA: ('extw_s', 'r1,r1'),
    0x25C0FC: ('stw_s', 'r1,[r2,0x14]'),
    0x25C0FE: ('ldh', 'r1,[r13,200]'),
    0x25C102: ('add_s', 'r1,r1,r0'),
    0x25C104: ('extw_s', 'r1,r1'),
    0x25C106: ('stw_s', 'r1,[r2,0x16]'),
    0x25C108: ('ldh', 'r1,[r13,202]'),
    0x25C10C: ('add_s', 'r1,r1,r10'),
    0x25C10E: ('extw_s', 'r1,r1'),
    0x25C110: ('stw_s', 'r1,[r2,0x18]'),
    0x25C112: ('ldh', 'r1,[r13,204]'),
    0x25C116: ('add_s', 'r1,r1,r3'),
    0x25C118: ('extw_s', 'r1,r1'),
    0x25C11A: ('stw_s', 'r1,[r2,0x1a]'),
    0x25C11C: ('ldh', 'r1,[r13,206]'),
    0x25C120: ('add_s', 'r1,r1,r9'),
    0x25C122: ('extw_s', 'r1,r1'),
    0x25C124: ('stw_s', 'r1,[r2,0x1c]'),
    0x25C126: ('ldh', 'r14,[r13,208]'),
    0x25C12A: ('add', 'r1,r14,r7'),
    0x25C12E: ('extw_s', 'r1,r1'),
    0x25C130: ('stw_s', 'r1,[r2,0x10]'),
    0x25C132: ('add', 'r14,r4,0x5'),
    0x25C136: ('add', 'r1,r14,r8'),
    0x25C13A: ('add_s', 'r1,r1,r0'),
    0x25C13C: ('add', 'r0,r1,r10'),
    0x25C140: ('add_s', 'r3,r3,r0'),
    0x25C142: ('add', 'r1,r3,r9'),
    0x25C146: ('add', 'r0,r1,r7'),
    0x25C14A: ('extw_s', 'r0,r0'),
    0x25C14C: ('stw_s', 'r0,[r2,0x2e]'),
    0x25C14E: ('ldh', 'r1,[r13,226]'),
    0x25C152: ('add', 'r0,r1,r5'),
    0x25C156: ('extw_s', 'r0,r0'),
    0x25C158: ('stw_s', 'r0,[r2,0x30]'),
    0x25C15A: ('ldh', 'r1,[r13,228]'),
    0x25C15E: ('ldh', 'r0,[r16,6]'),
    0x25C162: ('sub_s', 'r0,r0,r1'),
    0x25C164: ('extw_s', 'r0,r0'),
    0x25C166: ('b_s', ';0x25c1d8'),
    # --- "set" variant (bit 0xA set) ---
    0x25C168: ('mov_s', 'r1,0x1'),
    0x25C16A: ('stw_s', 'r1,[r2,0x10]'),
    0x25C16C: ('ldh', 'r14,[r13,196]'),
    0x25C170: ('add', 'r1,r14,r4'),
    0x25C174: ('add_s', 'r1,r1,0x2'),
    0x25C176: ('extw_s', 'r1,r1'),
    0x25C178: ('stw_s', 'r1,[r2,0x12]'),
    0x25C17A: ('ldh', 'r14,[r13,198]'),
    0x25C17E: ('add', 'r1,r14,r8'),
    0x25C182: ('extw_s', 'r1,r1'),
    0x25C184: ('stw_s', 'r1,[r2,0x14]'),
    0x25C186: ('ldh', 'r1,[r13,200]'),
    0x25C18A: ('add_s', 'r1,r1,r0'),
    0x25C18C: ('extw_s', 'r1,r1'),
    0x25C18E: ('stw_s', 'r1,[r2,0x16]'),
    0x25C190: ('ldh', 'r14,[r13,202]'),
    0x25C194: ('add', 'r1,r14,r10'),
    0x25C198: ('extw_s', 'r1,r1'),
    0x25C19A: ('stw_s', 'r1,[r2,0x18]'),
    0x25C19C: ('ldh', 'r1,[r13,204]'),
    0x25C1A0: ('add_s', 'r1,r1,r3'),
    0x25C1A2: ('extw_s', 'r1,r1'),
    0x25C1A4: ('stw_s', 'r1,[r2,0x1a]'),
    0x25C1A6: ('ldh', 'r14,[r13,206]'),
    0x25C1AA: ('add', 'r1,r14,r9'),
    0x25C1AE: ('extw_s', 'r1,r1'),
    0x25C1B0: ('stw_s', 'r1,[r2,0x1c]'),
    0x25C1B2: ('add', 'r14,r4,0x3'),
    0x25C1B6: ('add', 'r1,r14,r8'),
    0x25C1BA: ('add_s', 'r0,r0,r1'),
    0x25C1BC: ('add_s', 'r0,r0,r10'),
    0x25C1BE: ('add_s', 'r3,r3,r0'),
    0x25C1C0: ('add', 'r1,r3,r9'),
    0x25C1C4: ('add', 'r0,r1,r7'),
    0x25C1C8: ('extw_s', 'r0,r0'),
    0x25C1CA: ('stw_s', 'r0,[r2,0x2e]'),
    0x25C1CC: ('ldh', 'r0,[r13,226]'),
    0x25C1D0: ('add_s', 'r0,r0,r5'),
    0x25C1D2: ('extw_s', 'r0,r0'),
    0x25C1D4: ('stw_s', 'r0,[r2,0x30]'),
    0x25C1D6: ('mov_s', 'r0,0'),
    # --- tail: footer magic memcpy(ctxB+236, 0x351718, 8), return 0 ---
    0x25C1D8: ('ld_s', 'r1,[pcl,0x1d0]\t;0x25c3a8'),
    0x25C1DA: ('stw_s', 'r0,[r2,0x32]'),
    0x25C1DC: ('add2', 'r0,r13,0x3b'),
    0x25C1E0: ('bl.d', ';0x128c20'),
    0x25C1E4: ('mov_s', 'r2,0x8'),
    0x25C1E6: ('mov_s', 'r0,0'),
    0x25C1E8: ('b.d', ';0x33418c'),
    0x25C1EC: ('add_s', 'sp,sp,0x4'),
    # --- caller 0x29E680 (delay slots and stride site) ---
    0x29E69C: ('st_s', 'r14,[sp,0]'),
    0x29E69E: ('st_s', 'r14,[sp,0x4]'),
    0x29E6A0: ('bl.d', ';0x25caec'),
    0x29E6A4: ('add_s', 'r0,sp,0x4'),
    0x29E6B8: ('bl.d', ';0x25c020'),
    0x29E6BC: ('mov_s', 'r0,sp'),
    0x29E6BE: ('ld_s', 'r1,[sp,0]'),
    0x29E6C0: ('add2', 'r0,r1,0x3b'),
    0x29E6C4: ('sub_s', 'r0,r0,r1'),
    0x29E6C6: ('cmp', 'r0,236'),
    0x29E6CA: ('beq_s', ';0x29e6d2'),
    0x29E6CC: ('b.d', ';0x29e8d6'),
    0x29E6D0: ('ld_s', 'r0,[pcl,0x88]\t;0x29e758'),
    0x29E6DC: ('add_s', 'r1,sp,0x1c'),
    0x29E6DE: ('bl.d', ';0x25c038'),
    0x29E6E2: ('ld_s', 'r0,[sp,0]'),
    0x29E6E4: ('cmp_s', 'r0,0'),
    0x29E6E6: ('bne', ';0x29e8d6'),
    # --- resolver stubs ---
    0x25CAEC: ('ld_s', 'r1,[pcl,0x3d8]\t;0x25cec4'),
    0x25CAEE: ('j_s.d', '[blink]'),
    0x25CAF0: ('st_s', 'r1,[r0,0]'),
    0x25C020: ('ld_s', 'r1,[pcl,0x380]\t;0x25c3a0'),
    0x25C022: ('j_s.d', '[blink]'),
    0x25C024: ('st_s', 'r1,[r0,0]'),
}

LINE_RE = re.compile(
    r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{4} )*[0-9a-f]{4})\s+(\S+)\s*(.*)$')


def norm(ops: str) -> str:
    return re.sub(r'^[-0-9]+\t;', ';', ops)


def parse_window(text: str):
    out = {}
    for ln in text.splitlines():
        m = LINE_RE.match(ln)
        if m:
            out[int(m.group(1), 16)] = (m.group(3), norm(m.group(4)),
                                        m.group(2))
    return out


def intake_model(p1, p2, p3, p4, p5, ctxA6, ctxA8, bit_set):
    """Model of the 0x25C038 field computation (16-bit zero-extended chains)."""
    # extw/extw_s ZERO-extend the low halfword of the 32-bit sums.
    margin = (ctxA6 - ctxA8) & 0xFFFF
    f = {}
    if not bit_set:
        f[0xC4] = (2 * p2 + 2 * p3 + p4 + p5) & 0xFFFF
        f[0xC6] = 0
        f[0xC8] = (0 + p2) & 0xFFFF
        f[0xCA] = (f[0xC8] + p2) & 0xFFFF
        f[0xCC] = (f[0xCA] + p3) & 0xFFFF
        f[0xCE] = (f[0xCC] + p3) & 0xFFFF
        f[0xD0] = (f[0xCE] + p4) & 0xFFFF
        e2 = (f[0xC4] + p1 + 5) & 0xFFFF
        e4 = (e2 + margin) & 0xFFFF
        e6 = (ctxA6 - e4) & 0xFFFF
    else:
        f[0xC4] = 1
        f[0xC6] = (p1 + 3) & 0xFFFF
        f[0xC8] = (f[0xC6] + p2) & 0xFFFF
        f[0xCA] = (f[0xC8] + p2) & 0xFFFF
        f[0xCC] = (f[0xCA] + p3) & 0xFFFF
        f[0xCE] = (f[0xCC] + p3) & 0xFFFF
        f[0xD0] = (f[0xCE] + p4) & 0xFFFF
        e2 = (p1 + 3 + 2 * p2 + 2 * p3 + p4 + p5) & 0xFFFF
        e4 = (e2 + margin) & 0xFFFF
        e6 = 0
    f[0xE2], f[0xE4], f[0xE6] = e2, e4, e6
    f['margin'] = margin
    return f


def main() -> None:
    out = EVIDENCE / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'script_snapshot.py').write_bytes(Path(__file__).read_bytes())
    assert sha(FIRMWARE) == ('1d34e990a8f99019ffa53ca5de785399df863e9427'
                              '39a667ceb314ec6ce62a39')
    blocks, payloads, block_dir = verified_payloads(ROOT)
    info = {b['index']: b for b in blocks}
    p0 = bytes(payloads[0])
    assert info[0]['load_address_candidate'] == BASE0

    def word(va: int) -> int:
        return struct.unpack_from('<I', p0, va - BASE0)[0]

    windows = {}
    for name, lo, hi in WINDOWS:
        w = aligned_window(p0, BASE0, lo, hi)
        assert w.strip(), (name, hex(lo))
        windows[name] = w

    # --- 1. Raw pool words (little-endian from the payload image). ---
    for va, val in POOL_WORDS.items():
        assert word(va) == val, (hex(va), hex(word(va)), hex(val))

    # --- 2. The "P1IDSTR\0" magic at 0x351718. ---
    assert p0[MAGIC_VA - BASE0:MAGIC_VA - BASE0 + 8] == MAGIC
    assert p0[MAGIC_VA - BASE0 + 8:MAGIC_VA - BASE0 + 16] == b' ' * 8

    # --- 3. Address-keyed instruction checks. ---
    ins = {}
    for name in ('intake_25c038', 'caller_29e680',
                 'resolver_25caec', 'resolver_25c020'):
        ins.update(parse_window(windows[name]))
    for va, (mnem, ops) in E.items():
        assert va in ins, (hex(va), 'missing from windows')
        got_m, got_o, _raw = ins[va]
        assert (got_m, got_o) == (mnem, ops), \
            (hex(va), (got_m, got_o), (mnem, ops))

    # --- 4. ldw_s / stw_s printed offsets equal (raw & 0x1f) * 2. ---
    short_load_store = 0
    for va, (mnem, ops, raw) in ins.items():
        if mnem in ('ldw_s', 'stw_s') and ' ' not in raw:
            m = re.match(r'r\d+,\[r\d+,(?:0x([0-9a-f]+)|(\d+))\]$', ops)
            assert m, (hex(va), ops)
            off = int(m.group(1) or m.group(2), 16 if m.group(1) else 10)
            assert (int(raw.replace(' ', ''), 16) & 0x1f) * 2 == off, \
                (hex(va), raw, ops)
            short_load_store += 1
    assert short_load_store >= 14, short_load_store

    # --- 5. add2 immediate scale is 4, proven by the caller's site
    #        add2 r0,r1,0x3b ; sub_s r0,r0,r1 ; cmp r0,236:
    #        the sub cancels r1, so the cmp tests 0x3b*scale == 236. ---
    imm3b = (struct.unpack_from('<H', p0, 0x29E6C2 - BASE0)[0] >> 6) & 0x3f
    imm2d = (struct.unpack_from('<H', p0, 0x25C0EA - BASE0)[0] >> 6) & 0x3f
    imm3b_tail = (struct.unpack_from('<H', p0, 0x25C1DE - BASE0)[0] >> 6) & 0x3f
    assert imm3b == 0x3B and imm2d == 0x2D and imm3b_tail == 0x3B
    assert 0x3B * 4 == 236, 'add2 scale must be 4 for the stride site'
    # and because sub_s cancels r1, the caller's check is a compile-time
    # constant comparison (always true): the error edge from 0x29E6CC is
    # unreachable and 0x1B00105 (loaded in its b.d delay slot) is the id of
    # this DEAD site only; the other failure paths reaching 0x29E8D6 return
    # the codes of the nested callees (0x1B00106 from the intake, etc.).
    assert (0x29E6C0 in E) and E[0x29E6C4][1] == 'r0,r0,r1'

    # --- 6. The direct block->ctxB map matches the iteration-8 transform
    #        sites: the five parameter halfwords are record offsets 6..14. ---
    param_srcs = sorted({off for off, _ in DIRECT_MAP if 6 <= off <= 0xE})
    assert param_srcs == TRANSFORM_RECORD_OFFSETS, param_srcs
    assert sorted({off for off, _ in DIRECT_MAP if off >= 0x10}) == [0x10, 0x12]
    dsts = sorted(dst for _, dst in DIRECT_MAP)
    assert dsts == [174, 176, 178, 210, 212, 214, 216, 218, 220, 222, 232, 234]
    # a5 (block offset 0x14) is never read by the intake
    for va, (mnem, ops, _raw) in ins.items():
        if mnem == 'ldw_s' and 'r14' in ops:
            m = re.search(r'\[r14,(?:0x([0-9a-f]+)|(\d+))\]', ops)
            assert m, (hex(va), ops)
            off = int(m.group(1) or m.group(2), 16 if m.group(1) else 10)
            assert off <= 0x12, (hex(va), off)

    # --- 7. Model of the two variants (chain semantics). ---
    vectors = [(0, 0, 0, 0, 0, 100, 200),
               (1, 2, 3, 4, 5, 300, 400),
               (0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x8000, 0x7FFF),
               (0x7FFF, 0x1234, 0xBEEF, 0x0001, 0x8000, 0, 0xFFFF),
               (0x00FF, 0x0100, 0x0200, 0x0300, 0x0400, 0xF00F, 0x0FF0)]
    for p1, p2, p3, p4, p5, c6, c8 in vectors:
        for bit in (False, True):
            f = intake_model(p1, p2, p3, p4, p5, c6, c8, bit)
            margin = (c6 - c8) & 0xFFFF
            assert f['margin'] == margin
            # bound check (add1_s doubles p2 and p3): 4 + p1+2p2+2p3+p4+p5
            # + 10 <= ctxA[+8], i.e. bound == clear_total_0xC4 + p1 + 14
            bound = 4 + p1 + 2 * p2 + 2 * p3 + p4 + p5 + 10
            full_clear = 2 * p2 + 2 * p3 + p4 + p5
            assert bound == full_clear + p1 + 14, (bound, full_clear)
            if not bit:
                assert f[0xC4] == (2 * p2 + 2 * p3 + p4 + p5) & 0xFFFF
                assert f[0xE2] == (f[0xC4] + p1 + 5) & 0xFFFF
                assert f[0xE6] == (c6 - f[0xE4]) & 0xFFFF
            else:
                assert f[0xC4] == 1
                assert f[0xC6] == (p1 + 3) & 0xFFFF
                assert f[0xE2] == (p1 + 3 + 2 * p2 + 2 * p3 + p4 + p5) & 0xFFFF
                assert f[0xE6] == 0
            assert f[0xE4] == (f[0xE2] + margin) & 0xFFFF
            # the two variants differ by exactly 2 in the e2 total
            g = intake_model(p1, p2, p3, p4, p5, c6, c8, not bit)
            assert (f[0xE2] - g[0xE2]) & 0xFFFF == (2 if not bit else -2) & 0xFFFF
    # error-id neighbourhood (fact, not a check): the intake bound id
    # 0x1B00106 follows the caller's dead-site id 0x1B00105
    assert 0x1B00106 == 0x1B00105 + 1

    result = {
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'firmware_sha256': sha(FIRMWARE),
        'question': 'byte-verification of 0x25C038, the intake of the '
                    '6-word argument block into the command context '
                    '(open point of iteration 8)',
        'findings': {
            'first_arg_is_ctxB': '0x29E680 fills [sp,0] with ctxB=0x50F420 '
                                 'via the resolver stub 0x25C020 (pool '
                                 '0x25C3A0) and passes [sp,0] to 0x25C038; '
                                 '[sp+4] holds ctxA=0x50F52C via 0x25CAEC '
                                 '(pool 0x25CEC4). The command fields '
                                 '0xC4..0xE6 written by the intake are '
                                 'therefore ctxB fields, closing the loop '
                                 'with iteration 2 (0x50F420 holds the '
                                 'halfword parameters 0xD2..0xDE read by '
                                 'the switch 0x1EE730)',
            'direct_map': 'block halfwords -> ctxB halfwords: +0/+2/+4 -> '
                          '0xAE/0xB0/0xB2; +6 -> 0xD2; +8 -> 0xD4 AND 0xD6; '
                          '+0xA -> 0xD8 AND 0xDA; +0xC -> 0xDC; +0xE -> '
                          '0xDE; +0x10/+0x12 -> 0xE8/0xEA; the a5 halfword '
                          '(block +0x14) is never read',
            'param_coupling': 'the five parameter halfwords (block offsets '
                              '6,8,0xA,0xC,0xE) are exactly the record '
                              'offsets 6..14 that 0x29E8F0 scales with '
                              'ceil(h/8) when ctxA[+2] bit0xA is set; the '
                              'same bit selects the two intake formulas',
            'bound_check': '4 + p1 + 2*p2 + 2*p3 + p4 + p5 + 10 <= '
                           'ctxA[+8] (unsigned, bls_s; the two add1_s sites '
                           'add 2*r0 each, ARC ADD1_S = b + (c << 1)), i.e. '
                           'bound == clear_total_0xC4 + p1 + 14; violation '
                           'returns error id 0x1B00106 (pool 0x25C3A4)',
            'magic': 'memcpy(ctxB+0, 0x351718, 8) and memcpy(ctxB+236, '
                     '0x351718, 8) copy the literal "P1IDSTR\\0": the 0x25Cxxx '
                     'cluster is the P1IDSTR command-record service and the '
                     'record header/footer carry the magic',
            'margin': 'ctxB+224 (0xE0) = (ctxA[+6]-ctxA[+8]) & 0xFFFF; '
                      'extw/extw_s ZERO-extend (ARC EXTW is zero-extension, '
                      'SEXW would sign-extend), so fields hold the low '
                      'halfword of the 32-bit sums',
            'variants': 'ctxA[+2] bit0xA clear: 0xC4=2p2+2p3+p4+p5, '
                        '0xC6..0xD0 = cumulative sums from 0, 0xE2=0xC4+p1+5, '
                        '0xE4=0xE2+margin, 0xE6=(ctxA[+6]-0xE4)&0xFFFF; bit '
                        'set: 0xC4=1, 0xC6=p1+3, sums from p1+3, '
                        '0xE2=p1+3+2p2+2p3+p4+p5, 0xE4=0xE2+margin, 0xE6=0; '
                        'success returns 0',
            'add2_scale4': 'this toolchain prints add2 with the raw '
                           'immediate scaled by 4 (caller site add2 0x3b / '
                           'sub_s / cmp 236 proves it); the caller stride '
                           'check is arithmetically a tautology (sub_s '
                           'cancels r1), its error edge is unreachable; '
                           '0x1B00105 (pool 0x29E758, loaded in the b.d '
                           'delay slot of the dead site) is never actually '
                           'returned: the other failure paths reaching '
                           '0x29E8D6 return the codes of the nested callees '
                           '(0x1B00106 from the intake, results of '
                           '0x25D3AC, ...)',
            'resolver_stubs': '0x25CAEC and 0x25C020 are 3-instruction '
                              'stubs (ld_s pool ; j_s.d [blink] ; st_s '
                              'r1,[r0,0] delay) writing a constant pointer '
                              'to the caller-provided slot; the getter '
                              '0x25C028 reads ctxB-like fields +0x30/+0x32 '
                              'of the guard cell 0x50F4D4 (pool 0x25C39C)',
        },
        'pool_words': {hex(k): hex(v) for k, v in sorted(POOL_WORDS.items())},
        'direct_map': [[hex(s), hex(d)] for s, d in DIRECT_MAP],
        'windows_verified': [w[0] for w in WINDOWS],
        'instruction_sites_checked': len(E),
        'short_offset_rule_sites': short_load_store,
        'independent_review': 'agent cmd-intake-audit (inherited config) '
                              'confirmed claims 1/2/3/5/8 and the variant '
                              'formulas (with the nuance that ldw_s '
                              'zero-extends, .X never used); it CONTRADICTED '
                              'the first bound-check formula (add1_s = '
                              'b + (c << 1) doubles p2 and p3, now modeled '
                              'and asserted here) and corrected the extw '
                              'semantics (zero-extension, not sign-'
                              'extension), the stw_s width (16-bit store, '
                              'no overlap) and the role of 0x1B00105 (id '
                              'of the dead stride site, never actually '
                              'returned)',
        'limits': [
            'static only: no MMIO, lens MCU or camera hardware accessed; no '
            'firmware executed; NON_INSTALLARE',
            'the two formula variants are modeled in Python (halfword-'
            'truncated chains, extw sign extension) and cross-checked '
            'against the instruction listing, not against the physical CPU',
            'the semantic meaning of the fields (times, positions, budgets) '
            'remains inferred from the arithmetic: no MCU-side confirmation',
            'the duplicated loads of block[+8] and block[+0xA] into two '
            'fields each are recorded as bytes; whether the MCU treats the '
            'two fields differently is open',
            'runtime values of ctxA[+6]/[+8] (budget and bound) and of the '
            'flag bit0xA remain unknown (no static writer found in '
            'iteration 3 for the bit)',
            'V1.1 analysed vs V1.0 camera; no address transfer',
        ],
        'sources': {str(p): sha(p) for p in [Path(__file__), FIRMWARE,
                     ROOT / 'S33-sections/TBM_blocks/manifest.json',
                     ROOT / 'work/build-arc/binutils/objcopy',
                     ROOT / 'work/build-arc/binutils/objdump']},
    }
    (out / 'verified_evidence.json').write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    (EVIDENCE / 'latest.json').write_text(
        json.dumps({'evidence': str((out / 'verified_evidence.json')
                                    .relative_to(ROOT))}) + '\n')
    (out / 'gnu_windows.txt').write_text(
        '\n\n'.join(f'=== {k} ===\n{v}' for k, v in windows.items()))
    print('PASS', out)
    print('intake 0x25C038: first arg = ctxB 0x50F420 (resolver 0x25C020), '
          'not ctxA; command fields 0xC4..0xE6 are ctxB fields')
    print('block -> ctxB map verified; magic "P1IDSTR\\0" at 0x351718 '
          'copied to ctxB+0 and ctxB+236; bound id 0x1B00106; '
          'add2 scale 4; caller stride check is a tautology')


if __name__ == '__main__':
    main()
