#!/usr/bin/env python3
"""Nikon COOLPIX S33 - AutoSceneLiveView handler 0x100 (iteration 37).

Closes the open point left by iteration 36 (report
S33_GUI_AutoSceneLiveView_Helper_D098_CPU_20261101.md): the first caller
of the helper, handler 0x100 = 0x65B1CC (registry p3 record ev 0x0100 at
0x783B50), was decoded only partially (writer sites 0x65B212/0x65B2EA in
the it.25 census). Question: what does handler 0x100 do around the helper
call - does it really re-deliver the ORIGINAL (ev,arg) to 0x65B060 when
the gate byte [0x47BBC8] is > 0, does it really ARM state 6 (with
[ctx+0x1C]:=1, +0x1D:=0, +0x1E:=1) when the gate byte is <= 0 and the
mode/state/guard gates pass, and can the full cycle
0x100 -> helper(state6,guard1 -> state2 + 0x81 -> teardown -> 0)
RE-ARM state 6 within the same invocation?

Static decode (GNU ARC700, original bytes, block 2; see the report):
  65b1cc: push blink; bl 0x334128 (push r16,r15,r14,r13); st.aw fp
          r14=node, r16=ev(r1), r15=arg(r2)
  head:  17083C(1), 1707D8(2), 149028(node,0xA),
         helper 0x65D098(r0=node, r1/r2 leftovers),
         C7DD8(helper_return), 65C720(node)
  gate:  byte[0x47BBB8+0x10] (pool 0x65B388=0x47BBB8), ldb SIGN-extended
   >0 (path A): [ctx+4]:=2 (pool 0x65B38C=0x681F60),
         C5870(2) (r0 is the constant 2 of the state store, NOT the
         gate byte; its return is unused - revision C1),
         CF538(0) ([0x3657BA]:=0 per the agent review),
         65B060(node,ev,arg) ORIGINAL re-delivery,
         re-read gate, word [0x47BBB4+gate*4] (pool 0x65B390=0x47BBB4),
         65E900(word) -> packed (extb=idx, >>16=arg), 1453E4(idx,arg),
         shared tail b 0x659F8C -> pop 0x33418C (r16..r13)
   <=0 (path B): mode getter 0xCAD30 REAL:
     0x7E: CD5AC()==0 -> CD5BC(1), 145D1C(0)->[ctx+0x30],
           D2470(0), 1453E4(0x87,0); !=0: arg==0xFFFFFF80 or D10E8()!=0
           -> 145D1C(0)->[ctx+0x34], 149028(node,9), 143AFC(27/28),
           1439D4(0x26), fall to 0x65b2ae; else 65D590(node,0x86)
     !=0x7E: r13=ctx (pool 0x65B394); C7E04()==1 && [ctx+0xC]==0 ->
           exit; [ctx+4]==2 or D10C4()!=0 -> 136280, DE254(==0x15->0),
           C01EC, guard getter 0xCA310 REAL: ==1 -> [ctx+4]:=6,
           [ctx+0x1C]:=1, +0x1D:=0, +0x1E:=1, 65DB78(), 145150(node),
           14905C(node,4,1000,1000,0), 176828(3,1,0x32),
           145C3C(0x30D40 delay slot), 176828(3,0,0x32); !=1 ->
           17BF60(0,0x80,0x307F), 17BF60(0,0x400C,0x400C),
           12CAD4(0x00B00106 delay slot), mode 0x7D -> D0CE8/D0CF0,
           141CE8(0,0,0), mode 0x15 -> D0CAC, 17083C(2),
           1453E4(4,[ctx+0x2A])

NEW toolchain lesson (proven with the pinned assembler as oracle):
`ld.as r0,[pcl,-240]` at 0x65A09A (bytes 10 17 00 f6, handler 0x440E):
arc-elf32-as -mcpu=arc700 assembles `ld.as r0,[pcl,-240]` to EXACTLY
those bytes; -960 does not encode (limm needed). The raw s9 field is
-240 and the runtime EA is (pc&~3)+(-240)*4 = 0x659CD8, where the pool
word 0x0047BBB4 lives (verified in the payload). GNU objdump displays
the operand -240 and the comment ;0x659fa8 = (pc&~3)+(-240) WITHOUT
the x4 scaling: the COMMENT is wrong for LD.AS (plain LD like
[pcl,-76]/[pcl,-4] is unscaled and GNU is correct there). Consistent
with the it.40 CPU-proven rule (PC&~3)+imm*4.

Gate-byte subsystem census (static, LE scans at aligned offsets):
  pools holding 0x47BBC8: {0x659598 (open 0x4401, writer :=0),
                            0x65A3B0 (0x440E reader, cell direct),
                            0x65C400 (0x180 reader, exits if !=0)}
  pools holding 0x47BBB4: {0x659CD8 (close 0x4405), 0x65B390 (h100),
                           0x65CC28 (open attribution)}
  pools holding 0x47BBB8: {0x659CD4 (close 0x4405), 0x65AC48,
                           0x65B388 (h100), 0x65C914/0x65C924 (65C720),
                           0x65CC24, 0x65D484}
  0x65C720 (ring writer of the gate history, called by h100 at
  0x65B200): 5 bl sites {0x659A80, 0x659C14 (both 0x4405), 0x65A08E
  (0x440E), 0x65B200 (h100), 0x65CAEE}; 0x65E900: 9 bl sites
  {0x659A9A, 0x659C6E (4405), 0x65A0A2 (440E), 0x65B230 (h100),
  0x65CB0C, 0x65D8CA, 0x65D966, 0x65DAEC, 0x65DE3A}.
  bl 0x65B1CC: 0 callers (pure registry callback); LE: only the
  handler field of the p3 record (payload 3, 0x783B54).
  The table at 0x47BBB4 and the byte at 0x47BBC8 are RUNTIME cells in
  the load gap 0x428600..0x5FE800: NOT verifiable from the dump.

CPU cases (original windows; entry 0x65B1CC with r0=NODE, r1=EV,
r2=ARG; head stubs return helper=0x77 so C7DD8 logs the pass-through):
 0 ldas_ea_659cd8   entry 0x65A09A (micro): original ld.as bytes + the
   original pool window 0x659CD4..CDC; gate table fixture
   [0x47BBB8]=0x5151; 65E900 stubbed -> proves in CPU that the EA of
   the ld.as is 0x659CD8 (=0x47BBB4 pool), NOT the GNU comment 0x659FA8
 1 h100_pathA_tbl4  gate=2, table[2]=4: [ctx+4]:=2, re-delivery
   65B060(NODE,EV,ARG), 65E900 REAL -> 149028(0xBEEF,6),
   1453E4(0xA7,1); ret=rettab[1453E4]
 2 h100_pathA_tblB  gate=3, table[3]=0xB -> 1453E4(0x4D,0)
 3 h100_pathA_tbl0  gate=1, table[1]=0 -> 65E900 early return: NO
   149028(saved,6), 1453E4(0,0)
 4 h100_pathB_arm6  gate=0, mode 2B, state 2, C7E04!=1, DE254=0x15,
   guard=1 -> ARM: [ctx+4]:=6, +1C:=1, +1D:=0, +1E:=1, 65DB78(1),
   145150(node), 14905C(node,4,1000), 176828(3,1,0x32),
   145C3C(0x30D40), 176828(3,0,0x32)
 5 h100_pathB_guard0  guard=0 -> 17BF60(0,0x80,0x307F),
   17BF60(0,0x400C,0x400C), 12CAD4(0x00B00106), 141CE8(0,0,0),
   17083C(2), 1453E4(4,[ctx+0x2A]); state stays 2, no state-6 write
 6 h100_pathB_state5  state=5, D10C4==0 -> early exit, nothing written
 7 h100_pathB_mode7e  mode 7E, CD5AC==0 -> CD5BC(1), 145D1C(0)->
   [ctx+0x30]=0x42, D2470(0), 1453E4(0x87,0)
 8 h100_chain_rearm  REAL helper + REAL 0x65B060: state 6 + guard 1 +
   gate 0 + mode 2B + arg18 0x100 + D10C4 ret 1: helper -> state 2 ->
   b060 teardown -> state 0 -> handler path B: D10C4()!=0 -> RE-ARMS
   state 6 in the SAME event (final [ctx+4]==6, +1C==1)
 9 h100_7e_arg80     mode 7E, CD5AC!=0, arg=0xFFFFFF80 -> [ctx+0x34]:=
   145D1C ret, 149028(node,9), 143AFC(0x27), 143AFC(0x28),
   1439D4(0x26), then C7E04 path -> arm 6
10 h100_7e_d10e8     mode 7E, CD5AC!=0, arg!=0x80, D10E8==0 ->
   65D590(node,0x86) -> exit
11 h100_gate10_far   path A with a LARGE ring index: gate byte 0x10,
   table word at 0x47BBF4 (fixture) = 3 -> 1453E4(0xA7,0). NOTE: byte
   loads are UNSIGNED per the ARCompact ISA (zero-extended unless .X),
   so the ble at 0x65B20A means "gate byte == 0"; a sign-extension
   negative control is meaningless (LDB_S = "Load unsigned byte").

Read-only: firmware, blocks, tools and listings are never modified.
No hardware, no USB/SD access; NON_INSTALLARE state unchanged.
"""
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads
from s33_verify_capture_restore_caller_census import le_scan
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, elf_loads

STACK = 0xC8F000
PROBE_AT = 0x300000
COMMON_AT = 0x600
CNT = 0x367000
LOG_ENT = 0x367100
RETTAB = 0x368400
RETCELL = 0x367700

CTX = 0x681F5C               # AutoSceneLiveView context
REG_P3 = 0x783B08            # AutoSceneLiveView notify registry
ENTRY = 0x65B1CC             # handler 0x100
B060 = 0x65B060              # event 0x81 handler
HELPER = 0x65D098            # state6+guard1 helper
E900 = 0x65E900              # ring-value -> packed window mapper
GUARD_CELL = 0x365751        # byte read by 0xCA310 (pool 0xCA30C)
MODE_CELL = 0xC8E80C
GATE_CELL = 0x442734
GATE_P_CELL = 0x3669EC
GATE_TGT = 0x3680F0
SAVED_CELL = 0x681FBC        # ctx+0x60: node saved by open 0x4401
GATE_BYTE = 0x47BBC8         # runtime cell (load gap, fixture-imposed)
TBL_BASE = 0x47BBB4          # runtime table base (load gap)

NODE = 0x1234
EV = 0x100
ARG = 0x5678
SAVED = 0xBEEF

# original windows (payload, lo, hi, section)
W_MILI = (0, 0x334100, 0x3341E4, '.mili')
W_GGET = (0, 0xCA30C, 0xCA318, '.gget')
W_MODEGET = (0, 0xCAD30, 0xCAD38, '.modeget')
W_MODEPOOL = (0, 0xCAAC4, 0xCAAC8, '.modepool')
W_EPI = (2, 0x659588, 0x659594, '.epi')          # helper tail
W_EPI2 = (2, 0x659F8C, 0x659F98, '.epi2')        # handler 0x100 tail
W_POOLCTX = (2, 0x65AFF8, 0x65AFFC, '.poolctx')  # b060 ctx pool
W_POOLG = (2, 0x65B00C, 0x65B010, '.poolg')      # b060 gate pool 0x442644
W_B60 = (2, 0x65B060, 0x65B1CC, '.b60')
W_H100 = (2, 0x65B1CC, 0x65B3A8, '.h100')
W_HELPER = (2, 0x65D098, 0x65D0EC, '.helper')
W_E900 = (2, 0x65E8FC, 0x65E974, '.e900')
W_POOL9 = (2, 0x659CD4, 0x659CDC, '.pool9')      # ld.as pools (0x4405)
W_LDAS = (2, 0x65A09A, 0x65A0A6, '.ldas')        # ld.as sequence (0x440E)

WINS_ISOLATED = [W_MILI, W_EPI2, W_H100, W_E900]
WINS_PATHB = [W_MILI, W_GGET, W_MODEGET, W_MODEPOOL, W_EPI2, W_H100]
WINS_CHAIN = [W_MILI, W_GGET, W_MODEGET, W_MODEPOOL, W_EPI, W_EPI2,
              W_POOLCTX, W_POOLG, W_B60, W_H100, W_HELPER]
WINS_LDAS = [W_LDAS, W_POOL9]

H100_STUBS = [
    0x17083C, 0x1707D8, 0x149028, 0x65D098, 0xC7DD8, 0x65C720,
    0xC5870, 0xCF538, 0x65B060, 0x1453E4,
    0xCD5AC, 0xCD5BC, 0x145D1C, 0xD2470, 0xD10E8, 0x65D590,
    0x143AFC, 0x1439D4, 0xC7E04, 0xD10C4, 0x136280, 0xDE254,
    0xC01EC, 0x65DB78, 0x145150, 0x14905C, 0x176828, 0x145C3C,
    0x17BF60, 0x12CAD4, 0x141CE8]
B60_STUBS = [
    0x148E14, 0x148E68, 0xD103C, 0xD10A8, 0xCB5B0,
    0xCD558, 0x65CDF4, 0x14A228, 0x65BBD8, 0x65DAD0, 0x65DDA8,
    0xCE5C8, 0x2106F4, 0x660C34, 0xAD90C, 0xCD8CC, 0x12845C,
    0x65CF58]

ALL_STUBS = sorted(set(H100_STUBS + B60_STUBS + [E900]))
STUBS = {a: i + 1 for i, a in enumerate(ALL_STUBS)}
S = {a: STUBS[a] for a in ALL_STUBS}


def harness(entry, args):
    text = ('.section .text,"ax",@progbits\n.global _start\n_start:\n'
            f' mov sp,{hex(STACK)}\n'
            + ''.join(f' mov r{k},{hex(v)}\n' for k, v in enumerate(args))
            + f' mov r12,{hex(entry)}\n'
            ' jl_s [r12]\n'
            f' mov r12,{hex(RETCELL)}\n'
            ' st r0,[r12,0]\n'
            f' mov r12,{hex(PROBE_AT)}\n'
            ' j_s [r12]\n'
            '.section .stack,"aw",@nobits\n.align 16\n'
            ' .space 16384\n')
    return text


def probe(asserts, success, case_idx):
    text = []
    n = 0
    for addr, width, expected in asserts:
        text.append(f' mov r4,{hex(addr)}')
        text.append(' ldb r5,[r4,0]' if width == 1 else ' ld r5,[r4,0]')
        text.append(f' mov r6,{hex(expected)}')
        text.append(' cmp r5,r6')
        text.append(f' bne bad{n}')
        n += 1
    text.append(f' mov r5,{hex(success)}')
    text.append(' ldb r0,[r5,0]')
    for k in range(n):
        marker = 0xDEAD0000 + case_idx * 0x40 + k
        text.append(f'bad{k}:')
        text.append(f' mov r5,{hex(marker)}')
        text.append(' ldb r0,[r5,0]')
    return ('.section .probe,"ax",@progbits\n .org 0\n'
            + '\n'.join(text) + '\n')


def stub_body(sid):
    return (' push_s blink\n'
            f' mov_s r12,{hex(sid)}\n'
            f' mov r3,{hex(COMMON_AT)}\n'
            ' jl_s [r3]\n')


def common_logger():
    return (f'.section .common,"ax",@progbits\n .org 0\n'
            f' mov r3,{hex(CNT)}\n'
            ' ld r4,[r3,0]\n'
            ' asl r5,r4,4\n'
            f' mov r3,{hex(LOG_ENT)}\n'
            ' add r3,r3,r5\n'
            ' st r12,[r3,0]\n'
            ' st r0,[r3,4]\n'
            ' st r1,[r3,8]\n'
            ' st r2,[r3,12]\n'
            f' mov r3,{hex(CNT)}\n'
            ' ld r4,[r3,0]\n'
            ' add r4,r4,1\n'
            ' st r4,[r3,0]\n'
            f' mov r3,{hex(RETTAB)}\n'
            ' asl r4,r12,2\n'
            ' add r3,r3,r4\n'
            ' ld r0,[r3,0]\n'
            ' pop_s blink\n'
            ' j_s [blink]\n')


def fixture_sections(fix):
    out = ''
    for name, base, data in fix:
        out += (f'.section {name},"aw",@progbits\n.align 4\n'
                + ''.join(f' .byte {b}\n' for b in data))
    return out


def L(idx, sid, a0, a1, a2):
    a = LOG_ENT + 16 * idx
    out = [(a, 4, sid)]
    for off, v in ((4, a0), (8, a1), (12, a2)):
        if v is not None:
            out.append((a + off, 4, v))
    return out


def ctx_fixture(state, arg18, byte2a=0xA5, saved=SAVED):
    # 0xD0 bytes, sentinel 0xA5
    buf = bytearray(b'\xA5' * 0xD0)
    struct.pack_into('<I', buf, 4, state)          # word state
    buf[8] = 0xFF                                  # open leftover
    buf[9] = 0x5A                                  # open leftover
    struct.pack_into('<I', buf, 0x18, arg18)        # word arg18
    buf[0x2A] = byte2a                              # byte [ctx+0x2A]
    struct.pack_into('<I', buf, 0x60, saved)        # saved node cell
    return bytes(buf)


def guard_fixture(guard=1):
    buf = bytearray([0xA3] * 8)
    buf[1] = guard
    return bytes(buf)


def gate9_fixture(gate, tbl):
    # 0x20 bytes at 0x47BBB0: sentinel, tbl[0..3] at 0x47BBB4..C4,
    # gate byte at 0x47BBC8 (+0x18)
    buf = bytearray(b'\xA5' * 0x20)
    for k in range(4):
        struct.pack_into('<I', buf, 4 + 4 * k, tbl[k])
    buf[0x18] = gate & 0xFF
    return bytes(buf)


def gate9_far_fixture(gate, far_off, far_word):
    # 0x50 bytes at 0x47BBB0: standard layout plus a far table cell
    # (e.g. 0x47BBF4 for gate byte 0x10 -> [0x47BBB4+0x10*4])
    buf = bytearray(b'\xA5' * 0x50)
    for k in range(4):
        struct.pack_into('<I', buf, 4 + 4 * k, 0xA5A5A5A5)
    buf[0x18] = gate & 0xFF
    struct.pack_into('<I', buf, far_off, far_word)
    return bytes(buf)


def base_fix(state, guard, arg18, mode, gate, tbl,
             byte2a=0xA5, saved=SAVED, gate9=None):
    return [('.ctxfix', CTX, ctx_fixture(state, arg18, byte2a, saved)),
            ('.guardfix', GUARD_CELL - 1, guard_fixture(guard)),
            ('.modefix', MODE_CELL, bytes([mode])),
            ('.gate9fix', TBL_BASE - 4,
             gate9 if gate9 is not None else gate9_fixture(gate, tbl)),
            ('.gatefix', GATE_CELL, b'\xA5'),
            ('.gptrfix', GATE_P_CELL,
             struct.pack('<I', 0x368000)),
            ('.tgtfix', GATE_TGT, b'\xA5'),
            ('.logfix', 0x367000, bytes(0x800))]


def ldas_fix():
    # micro case: [0x47BBB8]=0x5151, neighbors sentinel
    tbl = struct.pack('<III', 0xA5A5A5A5, 0x5151, 0xA5A5A5A5)
    return [('.tblfix', TBL_BASE, tbl),
            ('.logfix', 0x367000, bytes(0x800))]


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'aslv_h100_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, _ = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp,
                   action='aslv-h100-cpu',
                   limits=['Static analysis + 11 synthetic CPU cases; '
                           'no hardware',
                           'Deep callees are stubs; originals executed: '
                           'handler 0x100 body, millicode, both shared '
                           'epilogues, guard getter 0xCA310, mode '
                           'getter 0xCAD30, mapper 0x65E900 (path A), '
                           'helper 0x65D098 + handler 0x81 body (chain '
                           'case)',
                           'ctx 0x681F5C, guard byte 0x365751, mode byte '
                           '0xC8E80C, gate cells fixtures; the gate '
                           'table 0x47BBB4 and byte 0x47BBC8 are '
                           'RUNTIME cells in the load gap '
                           '0x428600..0x5FE800: NOT verifiable from '
                           'the dump, fixture-imposed',
                           'Caller->event attribution over sorted '
                           'registry p3 handlers is range-based '
                           '(heuristic)',
                           'No physical button map, no hardware, no '
                           'scheduling; V1.1 dump only; NON_INSTALLARE'])
    try:
        p0, p2, p3 = payloads[0], payloads[2], payloads[3]

        # --- 1. static: registry p3 -------------------------------
        recs = []
        k = 0
        while True:
            a = REG_P3 + 8 * k
            ev, pad, h = struct.unpack_from('<HHI', p3, a - base[3])
            recs.append((ev, h, a))
            if ev == 0:
                break
            k += 1
        assert len(recs) == 40, len(recs)
        m = {ev: (a, h) for (ev, h, a) in recs[:-1]}
        a100, h100 = m[0x100]
        assert h100 == ENTRY, hex(h100)
        assert a100 == 0x783B50, hex(a100)
        a81, h81 = m[0x81]
        assert h81 == B060, hex(h81)
        results['registry_p3'] = dict(
            n_records=len(recs) - 1,
            ev0100_handler=hex(h100),
            ev0100_record=hex(a100),
            ev0081_handler=hex(h81))

        # --- 2. static: pools --------------------------------------
        pools = {
            0x65B388: 0x47BBB8, 0x65B38C: CTX + 4, 0x65B390: TBL_BASE,
            0x65B394: CTX, 0x65B398: CTX + 0x30, 0x65B39C: 0x30D40,
            0x65B3A0: 0x307F, 0x65B3A4: 0x00B00106,
            0x65E8FC: SAVED_CELL, 0x65E970: 0x000300A7,
            0x659CD4: 0x47BBB8, 0x659CD8: TBL_BASE,
            0x659598: GATE_BYTE, 0x65A3B0: GATE_BYTE,
            0x65C400: GATE_BYTE,
            0x65C914: 0x47BBB8, 0x65C924: 0x47BBB8,
            0x65C90C: 0x3181, 0x65C918: 0x4111, 0x65C91C: 0x4110}
        for a, v in pools.items():
            src, bb = (p0, base[0]) if a < base[2] else (p2, base[2])
            got = struct.unpack_from('<I', src, a - bb)[0]
            assert got == v, (hex(a), hex(got), hex(v))
        results['pools'] = {hex(a): hex(v) for a, v in pools.items()}

        # --- 3. static: LE scans -----------------------------------
        hitsE = [(i, a, o) for (i, a, o)
                 in le_scan(payloads, base, ENTRY) if o == 0]
        assert hitsE == [(3, 0x783B54, 0)], hitsE
        hitsB = sorted(a for (i, a, o)
                       in le_scan(payloads, base, GATE_BYTE) if o == 0)
        assert hitsB == [0x659598, 0x65A3B0, 0x65C400], hitsB
        hitsT = sorted(a for (i, a, o)
                       in le_scan(payloads, base, TBL_BASE) if o == 0)
        assert hitsT == [0x659CD8, 0x65B390, 0x65CC28], hitsT
        hitsN = sorted(a for (i, a, o)
                       in le_scan(payloads, base, 0x47BBB8) if o == 0)
        assert hitsN == [0x659CD4, 0x65AC48, 0x65B388, 0x65C914,
                         0x65C924, 0x65CC24, 0x65D484], hitsN
        results['le_scans'] = dict(
            entry_pool_sites=[(i, hex(a)) for (i, a, o) in hitsE],
            gate_byte_pool_sites=[hex(a) for a in hitsB],
            tbl_base_pool_sites=[hex(a) for a in hitsT],
            gate_base_pool_sites=[hex(a) for a in hitsN])

        # --- 4. static: bl censuses --------------------------------
        objcopy = ROOT / 'work/build-arc/binutils/objcopy'
        objdump = ROOT / 'work/build-arc/binutils/objdump'
        assert objcopy.is_file() and objdump.is_file()
        census = {t: [] for t in (ENTRY, 0x65C720, E900)}
        with tempfile.TemporaryDirectory(prefix='it37-census-') as td:
            for b in blocks:
                idx = b['index']
                elf = Path(td) / f'b{idx}.elf'
                subprocess.run([str(objcopy), '-I', 'binary',
                                '-O', 'elf32-littlearc', '-B', 'arc',
                                '--rename-section',
                                '.data=.text,alloc,load,readonly,'
                                'code,contents',
                                '--change-section-vma',
                                f".data={b['load_address_candidate']:#x}",
                                '--strip-all',
                                str(ROOT / 'S33-sections/TBM_blocks'
                                    / b['file']),
                                str(elf)], check=True, timeout=120)
                text = subprocess.run(
                    [str(objdump), '-d', '-m', 'arc:ARC700',
                     '-EL', str(elf)], capture_output=True, text=True,
                    check=True, timeout=280).stdout
                for line in text.splitlines():
                    for t in census:
                        if f';0x{t:x}' in line:
                            parts = [p for p in line.split('\t') if p]
                            addr = int(parts[0].strip().rstrip(':'), 16)
                            mn = parts[2].strip() if len(parts) > 2 else ''
                            assert mn.startswith('bl'), (line, mn)
                            census[t].append((idx, addr))
        assert sorted(census[ENTRY]) == [], census[ENTRY]
        assert sorted(a for _, a in census[0x65C720]) == \
            [0x659A80, 0x659C14, 0x65A08E, 0x65B200, 0x65CAEE], \
            census[0x65C720]
        assert sorted(a for _, a in census[E900]) == \
            [0x659A9A, 0x659C6E, 0x65A0A2, 0x65B230, 0x65CB0C,
             0x65D8CA, 0x65D966, 0x65DAEC, 0x65DE3A], census[E900]
        assert set(i for i, _ in census[0x65C720]) == {2}
        assert set(i for i, _ in census[E900]) == {2}
        results['bl_census'] = {
            'h100_entry': 0,
            '65c720': [(f'b{i}', hex(a)) for i, a in
                       sorted(census[0x65C720])],
            '65e900': [(f'b{i}', hex(a)) for i, a in
                       sorted(census[E900])]}

        # --- 5. static: opcode freezes -------------------------------
        H100_HEX = (
            'f1c05e0f4e6cfc1cc8b60a23003708761a71487701d85e0e8d8a02d8'
            'f20d8d8ac9700ad93a0ecd76c970a60ec000e20b4d36c970220d800'
            '061d0108880e03a000c0060d102d800a15e0e0d3500d8220b0d3ac97'
            '00a71e9728fff59d030885ad035780080d20e800108750f78422d011'
            '4aa090d75a2f0f20acd37fee003f253d531f0620b0d3980e00ff401d'
            '8660b0d3900d8c20a4d754ed200a200d80a0a8d3b87d800d9e6f18c2'
            '73e900bf2720ecd3a80e007f4c97086d90e0b00017ef000d8920a4d7'
            '541d509d90da5c970920dcd7627d862084d7428d85a084d7426d82e0f'
            '0d745a0b4d3681e004f40c8d80e066f2018582e005f2060ecd3a80e0'
            '5ef2ba0f4d6d8a0f4d4195e003f400d802f001d8120f4d3232088d37'
            '81e026f406d801a501d81cad00d81dad01d81ead82084001c970560ec'
            'd74c97004d98a220f0a48734a2400004e0dcd7603d801d932da120d8d'
            '8d22096d751fd003d800d932da020d8d8d2cf000d880d92e0c6d901ad'
            '200d80cd98eb92872220c4d90920fad6817d0e609cd37fde008f49609'
            'cd3a80e004f49609cd3a00d80871087286094d73ca09cd3795e003f43'
            'e09cd3a02d8c60c8d8a2a15811004d85ef109044fffb8bb4700601f68'
            '00b4bb47005c1f68008c1f6800400d03007f3000000601b000')
        E900_HEX = (
            'bc1f6800f1c0e1c5fc1cc8b60a2300370a25009003f400d827f0e8170'
            '0f006d900800e0f0d750b6d8ae03c000d0040278c7333240010147c00'
            '7c130e110b15151515061308004dd80ff0a7d891b80df0a7d892b809f'
            '0a7d890b807f006d005f0a7d803f000d80a24c03604141b343d00ce6a'
            'e078a7000300')
        MILI_HEX = (
            'fc1c88b6fc1c48b6fc1c08b6fc1cc8b5fc1c88b5fc1c48b5fc1c08b5'
            'fc1cc8b4fc1c88b4fc1c48b4fc1c08b4fc1cc8b3fc1c88b3fc1c48b3'
            'e07ee07804dc38dd35f0e07804dc34dd33f0e07804dc30dd31f0e078'
            '04dc2cdd2ff0e07804dc28dd2df0e07804dc24dd2bf0e07804dc20dd'
            '29f0e07804dc1cdd27f0e07804dc18dd25f0e07804dc14dd23f0e0780'
            '4dc10dd21f0e07804dc0cdd1ff0e07804dc08dd1cf0e07804dc04dd19'
            'f034141a30301419302c1418302814173024141630201415301c141430'
            '1814133014141230101411300c14103002c701c6b0244d33b0241f33e0'
            '7e')
        HELPER_HEX = (
            'f1c096088e6bfc1cc8b60a230037087610d5018586e01cf4620a8d368'
            '1e018f4c97004d96e0fcd75c9700fd9660fcd7503d800dfe97132da5a'
            '0f8d8c02d801a5c97081d901da860fcffefcada5040ffe5c1f6800')
        freezes = [
            ('h100_body', 2, 0x65B1CC, H100_HEX),
            ('e900_win', 2, 0x65E8FC, E900_HEX),
            ('epi2', 2, 0x659F8C, '0a24c03604141b34f9010e6d'),
            ('epi', 2, 0x659588, '0a24c03604141b3405044e6d'),
            ('millicode_win', 0, 0x334100, MILI_HEX),
            ('guard_getter', 0, 0xCA30C, '51573600fc1700f00088e07e'),
            ('modeget', 0, 0xCAD30, '651700f60088e07e'),
            ('modepool', 0, 0xCAAC4, '0ce8c800'),
            ('helper_body', 2, 0x65D098, HELPER_HEX),
            ('b60_head', 2, 0x65B060,
             'f1c0c6088e6cfc1cc8b60a23003708753a711a7201d8ca0f8d8af2'
             '0dcd7680e004f401d8920dcd7600dfe970b20fcd3a36080d3b6417'
             '0ef081e005f4018683e08cf2'),
            ('ldas_seq', 2, 0x65A09A, '101700f63578008062084002'),
            ('pool9', 2, 0x659CD4, 'b8bb4700b4bb4700'),
        ]
        for name, idx, addr, hexstr in freezes:
            data = payloads[idx][addr - base[idx]:
                                 addr - base[idx] + len(hexstr) // 2]
            assert data.hex() == hexstr, (name, data.hex())
        results['opcode_freezes'] = 'ok'
        # the ld.as EA lesson: the pool word 0x0047BBB4 lives at
        # 0x659CD8 = (0x65A09A & ~3) + (-240 * 4); GNU's comment
        # ;0x659fa8 is unscaled (assembler round-trip proven).
        assert struct.unpack_from('<I', p2, 0x659CD8 - base[2])[0] \
            == TBL_BASE
        results['ldas_ea_rule'] = dict(
            site=hex(0x65A09A), raw_field=-240,
            ea=hex(0x659CD8), gnu_comment=hex(0x659FA8),
            note='LD.AS displacement is x4-scaled; GNU objdump operand '
                 'and comment show the raw field unscaled')

        # window inventory + non-overlap (chain set: superset)
        wins = {}
        prev = None
        for (pidx, lo, hi, sec) in sorted(
                WINS_CHAIN + [W_E900, W_POOL9, W_LDAS],
                key=lambda w: (w[1], w[2])):
            assert prev is None or lo >= prev, (hex(lo), hex(prev))
            prev = hi
            data = payloads[pidx][lo - base[pidx]:hi - base[pidx]]
            wins[sec] = dict(payload=pidx, lo=hex(lo), hi=hex(hi),
                             size=len(data),
                             sha256=hashlib.sha256(data).hexdigest())
        results['windows'] = wins

        # --- 6. CPU cases -------------------------------------------
        r = Runner(SimpleNamespace(legacy_root=LEGACY,
                                   toolchain=TOOLCHAIN,
                                   output=out,
                                   action='aslv-h100-cpu'))
        r.prepare()
        r.results.update(static_pass=results)

        def build_case(name, asm_text, orig_windows, extra_sections):
            s = out / f'{name}.s'
            s.write_text(asm_text)
            obj = out / f'{name}.o'
            assert r.command(f'{name}_as', [
                TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL',
                '-o', obj, s]).returncode == 0
            bin_objs = []
            for (pidx, wlo, whi, section) in orig_windows:
                data = payloads[pidx][wlo - base[pidx]:
                                      whi - base[pidx]]
                orig = out / f'{name}_{section}.bin'
                orig.write_bytes(data)
                bo = out / f'{name}_{section}_bin.o'
                assert r.command(f'{name}_{section}_oc', [
                    TOOLCHAIN / 'arc-elf32-objcopy', '-I', 'binary',
                    '-O', 'elf32-littlearc', '-B', 'arc',
                    '--rename-section',
                    f'.data={section},alloc,load,readonly,code,'
                    'contents',
                    '--change-section-vma', f'.data={hex(wlo)}',
                    '--strip-all', orig, bo]).returncode == 0
                bin_objs.append(bo)
            elf = out / f'{name}.elf'
            ld = out / f'{name}.ld'
            ld.write_text(
                'ENTRY(_start)\nSECTIONS {\n'
                '  .text 0x1000 : { *(.text .text.*) }\n'
                + ''.join(f'  {section} {hex(wlo)} : {{ *({section}) }}\n'
                          for (_, wlo, _, section) in orig_windows)
                + extra_sections
                + '  .stack 0xC8F000 (NOLOAD) : { *(.stack .stack.*) }\n'
                '} \n')
            cmd = [TOOLCHAIN / 'arc-elf32-ld', '-EL', '-T', ld,
                   '-o', elf, obj] + bin_objs
            assert r.command(f'{name}_ld', cmd).returncode == 0
            ep, segments = elf_loads(elf)
            assert ep == 0x1000, hex(ep)
            for (pidx, wlo, whi, section) in orig_windows:
                want_b = payloads[pidx][wlo - base[pidx]:
                                        whi - base[pidx]]
                by = [seg for seg in segments
                      if seg['address'] <= wlo
                      and wlo + (whi - wlo)
                      <= seg['address'] + seg['size']]
                assert len(by) == 1, (hex(wlo), segments)
                data = by[0]['data'][wlo - by[0]['address']:]
                assert data[:whi - wlo] == bytes(want_b), hex(wlo)
            case, sim_text = r.run(name, '/result/' + f'{name}.elf')
            return case, sim_text

        def spec(name, wins, entry, args, stub_addrs, rets, fix, logs,
                 extra=None, syncret=False):
            asserts = []
            for i, (sid, a0, a1, a2) in enumerate(logs):
                asserts += L(i, sid, a0, a1, a2)
            n = len(logs)
            asserts += [(CNT, 4, n)]
            asserts += L(n, 0, None, None, None)   # no extra calls
            asserts += [(RETCELL, 4, rets.pop('_ret'))]
            if extra:
                asserts += extra
            return (name, wins, entry, args, stub_addrs, rets, fix,
                    asserts, syncret)

        def HEAD(ev=EV, arg=ARG, hret=0x77):
            return [(S[0x17083C], 1, ev, arg),
                    (S[0x1707D8], 2, ev, arg),
                    (S[0x149028], NODE, 0xA, arg),
                    (S[0x65D098], NODE, 0xA, arg),
                    (S[0xC7DD8], hret, 0xA, arg),
                    (S[0x65C720], NODE, 0xA, arg)]

        def ARMTAIL(arg=ARG):
            return [(S[0x65DB78], 1, 0xA, arg),
                    (S[0x145150], NODE, 0xA, arg),
                    (S[0x14905C], NODE, 4, 1000),
                    (S[0x176828], 3, 1, 0x32),
                    (S[0x145C3C], 0x30D40, 1, 0x32),
                    (S[0x176828], 3, 0, 0x32)]

        def MIDB(arg=ARG, state=2):
            # C7E04 ret 0 -> state gate (r0 is RELOADED with the state
            # word at 0x65B2BC, so 136280 receives the state value)
            return [(S[0xC7E04], 0x2B, 0xA, arg),
                    (S[0x136280], state, 0xA, arg),
                    (S[0xDE254], 0x33, 0xA, arg),
                    (S[0xC01EC], 0, 0xA, arg)]

        # b060 teardown log blocks (from the it.34/it.36 verifiers)
        def HEAD_B60():
            return [(S[0x17083C], 1, 0x81, 1),
                    (S[0x148E68], 1, 0x81, 1)]

        def GATE_B60():
            # D103C ret 0; D10C4 rettab is 1 in the chain case
            return [(S[0xD103C], 0, 0x81, 1),
                    (S[0xD10C4], 0, 0x81, 1)]

        def CLEAR_B60():
            return [(S[0xD10A8], 0, 0x81, 1),
                    (S[0xCB5B0], 0x100, 0x81, 1)]

        def TEAR_B60(mode=0x2B):
            log = [(S[0xCD558], 1, 0x442644, 1),
                   (S[0x65CDF4], 1, 0x442644, 1),
                   (S[0x14A228], 0, 0x442644, 1),
                   (S[0x65BBD8], 0, 0x442644, 1),
                   (S[0x65DAD0], 0, 0x442644, 1),
                   (S[0x143AFC], 0x16, 0x442644, 1),
                   (S[0x143AFC], 0x15, 0x442644, 1),
                   (S[0x143AFC], 0x14, 0x442644, 1),
                   (S[0xCE5C8], 0, 0x442644, 1),
                   (S[0x660C34], 0, 0x442644, 1),
                   (S[0xAD90C], 0, 0x110, 1),
                   (S[0x145C3C], 0x7530, 0x110, 1),
                   (S[0x145150], NODE, 0x110, 1),
                   (S[0xCD8CC], mode, 0x110, 1),
                   (S[0x14905C], NODE, 0xB, 0xFA),
                   (S[0x12845C], 0, 0xB, 0xFA),
                   (S[0x65CF58], NODE, 0xB, 0xFA)]
            return log

        BASE_MEM = [(CTX + 8, 1, 0xFF), (CTX + 9, 1, 0x5A),
                    (CTX + 0x24, 1, 0xA5),
                    (GUARD_CELL - 1, 1, 0xA3),
                    (GUARD_CELL + 1, 1, 0xA3)]

        SPECS = []

        # 0 micro: ld.as EA
        SPECS.append(spec(
            'ldas_ea_659cd8', WINS_LDAS, 0x65A09A,
            [0x111, 1, 0x222], [E900],
            {E900: 0x99, '_ret': 0x99}, ldas_fix(),
            [(S[E900], 0x5151, 1, 0x222)],
            extra=[(0x47BBB4, 4, 0xA5A5A5A5),
                   (0x47BBB8, 4, 0x5151),
                   (0x47BBBC, 4, 0xA5A5A5A5),
                   (0x659CD4, 4, 0x0047BBB8),
                   (0x659CD8, 4, 0x0047BBB4)],
            syncret=True))

        # 1 path A, table word 4
        SPECS.append(spec(
            'h100_pathA_tbl4', WINS_ISOLATED, ENTRY,
            [NODE, EV, ARG],
            [a for a in H100_STUBS],
            {0x65D098: 0x77, 0x1453E4: 0x55, '_ret': 0x55},
            base_fix(5, 1, 0x100, 0x2B, 2,
                     [0xA5A5A5A5, 0xA5A5A5A5, 4, 0xA5A5A5A5]),
            HEAD() + [
                (S[0xC5870], 2, 0x681F60, ARG),
                (S[0xCF538], 0, 0x681F60, ARG),
                (S[0x65B060], NODE, EV, ARG),
                (S[0x149028], SAVED, 6, ARG),
                (S[0x1453E4], 0xA7, 1, ARG)],
            extra=BASE_MEM + [
                (CTX + 4, 4, 2), (CTX + 0x18, 4, 0x100),
                (CTX + 0x1C, 1, 0xA5), (CTX + 0x1D, 1, 0xA5),
                (CTX + 0x1E, 1, 0xA5), (CTX + 0x60, 4, SAVED),
                (GATE_BYTE, 1, 2), (0x47BBB4, 4, 0xA5A5A5A5),
                (0x47BBB8, 4, 0xA5A5A5A5), (0x47BBBC, 4, 4),
                (0x47BBC0, 4, 0xA5A5A5A5)]))

        # 2 path A, table word 0xB
        SPECS.append(spec(
            'h100_pathA_tblB', WINS_ISOLATED, ENTRY,
            [NODE, EV, ARG],
            [a for a in H100_STUBS],
            {0x65D098: 0x77, 0x1453E4: 0x55, '_ret': 0x55},
            base_fix(5, 1, 0x100, 0x2B, 3,
                     [0xA5A5A5A5, 0xA5A5A5A5, 0xA5A5A5A5, 0xB]),
            HEAD() + [
                (S[0xC5870], 2, 0x681F60, ARG),
                (S[0xCF538], 0, 0x681F60, ARG),
                (S[0x65B060], NODE, EV, ARG),
                (S[0x149028], SAVED, 6, ARG),
                (S[0x1453E4], 0x4D, 0, ARG)],
            extra=BASE_MEM + [
                (CTX + 4, 4, 2), (GATE_BYTE, 1, 3),
                (0x47BBC0, 4, 0xB)]))

        # 3 path A, table word 0 -> early return, no saved-node close
        SPECS.append(spec(
            'h100_pathA_tbl0', WINS_ISOLATED, ENTRY,
            [NODE, EV, ARG],
            [a for a in H100_STUBS],
            {0x65D098: 0x77, 0x1453E4: 0x55, '_ret': 0x55},
            base_fix(5, 1, 0x100, 0x2B, 1,
                     [0xA5A5A5A5, 0, 0xA5A5A5A5, 0xA5A5A5A5]),
            HEAD() + [
                (S[0xC5870], 2, 0x681F60, ARG),
                (S[0xCF538], 0, 0x681F60, ARG),
                (S[0x65B060], NODE, EV, ARG),
                (S[0x1453E4], 0, 0, ARG)],
            extra=BASE_MEM + [
                (CTX + 4, 4, 2), (GATE_BYTE, 1, 1),
                (0x47BBB8, 4, 0), (CTX + 0x60, 4, SAVED)]))

        # 4 path B arm 6
        SPECS.append(spec(
            'h100_pathB_arm6', WINS_PATHB, ENTRY,
            [NODE, EV, ARG],
            [a for a in H100_STUBS],
            {0x65D098: 0x77, 0x136280: 0x33, 0xDE254: 0x15,
             '_ret': 0},
            base_fix(2, 1, 0x100, 0x2B, 0,
                     [0xA5A5A5A5] * 4),
            HEAD() + MIDB() + ARMTAIL(),
            extra=BASE_MEM + [
                (CTX + 4, 4, 6), (CTX + 0x1C, 1, 1),
                (CTX + 0x1D, 1, 0), (CTX + 0x1E, 1, 1),
                (CTX + 0x18, 4, 0x100), (GATE_BYTE, 1, 0),
                (CTX + 0x30, 4, 0xA5A5A5A5),
                (CTX + 0x34, 4, 0xA5A5A5A5), (CTX + 0x2A, 1, 0xA5),
                (CTX + 0x60, 4, SAVED)]))

        # 5 path B guard 0 -> long tail, no state-6 write
        SPECS.append(spec(
            'h100_pathB_guard0', WINS_PATHB, ENTRY,
            [NODE, EV, ARG],
            [a for a in H100_STUBS],
            {0x65D098: 0x77, 0x136280: 0x33, 0xDE254: 0x15,
             0x1453E4: 0x55, '_ret': 0x55},
            base_fix(2, 0, 0x100, 0x2B, 0,
                     [0xA5A5A5A5] * 4, byte2a=0x37),
            HEAD() + MIDB() + [
                (S[0x17BF60], 0, 0x80, 0x307F),
                (S[0x17BF60], 0, 0x400C, 0x400C),
                (S[0x12CAD4], 0x00B00106, 0x400C, 0x400C),
                (S[0x141CE8], 0, 0, 0),
                (S[0x17083C], 2, 0, 0),
                (S[0x1453E4], 4, 0x37, 0)],
            extra=BASE_MEM + [
                (CTX + 4, 4, 2), (CTX + 0x1C, 1, 0xA5),
                (CTX + 0x1D, 1, 0xA5), (CTX + 0x1E, 1, 0xA5),
                (CTX + 0x2A, 1, 0x37), (GATE_BYTE, 1, 0),
                (GUARD_CELL, 1, 0)]))

        # 6 path B state 5 -> D10C4==0 exit
        SPECS.append(spec(
            'h100_pathB_state5', WINS_PATHB, ENTRY,
            [NODE, EV, ARG],
            [a for a in H100_STUBS],
            {0x65D098: 0x77, '_ret': 0},
            base_fix(5, 1, 0x100, 0x2B, 0,
                     [0xA5A5A5A5] * 4),
            HEAD() + [(S[0xC7E04], 0x2B, 0xA, ARG),
                      # r0 reloaded with the state word (5) at 0x65B2BC
                      (S[0xD10C4], 5, 0xA, ARG)],
            extra=BASE_MEM + [
                (CTX + 4, 4, 5), (CTX + 0x1C, 1, 0xA5),
                (GATE_BYTE, 1, 0)]))

        # 7 path B mode 7E, CD5AC==0
        SPECS.append(spec(
            'h100_pathB_mode7e', WINS_PATHB, ENTRY,
            [NODE, EV, ARG],
            [a for a in H100_STUBS],
            {0x65D098: 0x77, 0x145D1C: 0x42, 0x1453E4: 0x55,
             '_ret': 0x55},
            base_fix(5, 1, 0x100, 0x7E, 0,
                     [0xA5A5A5A5] * 4),
            HEAD() + [
                (S[0xCD5AC], 0x7E, 0xA, ARG),
                (S[0xCD5BC], 1, 0xA, ARG),
                (S[0x145D1C], 0, 0xA, ARG),
                (S[0xD2470], 0, 0xA, 0x681F8C),
                (S[0x1453E4], 0x87, 0, 0x681F8C)],
            extra=BASE_MEM + [
                (CTX + 4, 4, 5), (CTX + 0x30, 4, 0x42),
                (CTX + 0x34, 4, 0xA5A5A5A5), (CTX + 0x1C, 1, 0xA5),
                (GATE_BYTE, 1, 0)]))

        # 8 chain: REAL helper + REAL b060, re-arm state 6
        SPECS.append(spec(
            'h100_chain_rearm', WINS_CHAIN, ENTRY,
            [NODE, EV, ARG],
            [a for a in H100_STUBS + B60_STUBS
             if a not in (0x65D098, 0x65B060)],
            {0x17083C: 1, 0x148E68: 1, 0xCD558: 1, 0x65CF58: 0,
             0xD10C4: 1, 0x136280: 0x33, 0xDE254: 0x15, '_ret': 0},
            base_fix(6, 1, 0x100, 0x2B, 0,
                     [0xA5A5A5A5] * 4),
            [(S[0x17083C], 1, EV, ARG),
             (S[0x1707D8], 2, EV, ARG),
             (S[0x149028], NODE, 0xA, ARG),
             # helper REAL
             (S[0x149028], NODE, 4, ARG),
             (S[0x149028], NODE, 0xF, ARG),
             (S[0x176828], 3, 0, 0x32),
             # b060 REAL (node,0x81,1): teardown state 2, mode 2B
             (S[0x17083C], 1, 0x81, 1),
             (S[0x148E68], 1, 0x81, 1),
             (S[0xD103C], 0, 0x81, 1),
             (S[0xD10C4], 0, 0x81, 1),
             (S[0xD10A8], 0, 0x81, 1),
             (S[0xCB5B0], 0x100, 0x81, 1),
             (S[0xCD558], 1, 0x442644, 1),
             (S[0x65CDF4], 1, 0x442644, 1),
             (S[0x14A228], 0, 0x442644, 1),
             (S[0x65BBD8], 0, 0x442644, 1),
             (S[0x65DAD0], 0, 0x442644, 1),
             (S[0x143AFC], 0x16, 0x442644, 1),
             (S[0x143AFC], 0x15, 0x442644, 1),
             (S[0x143AFC], 0x14, 0x442644, 1),
             (S[0xCE5C8], 0, 0x442644, 1),
             (S[0x660C34], 0, 0x442644, 1),
             (S[0xAD90C], 0, 0x110, 1),
             (S[0x145C3C], 0x7530, 0x110, 1),
             (S[0x145150], NODE, 0x110, 1),
             (S[0xCD8CC], 0x2B, 0x110, 1),
             (S[0x14905C], NODE, 0xB, 0xFA),
             (S[0x12845C], 0, 0xB, 0xFA),
             (S[0x65CF58], NODE, 0xB, 0xFA),
             # handler continues: after the REAL b060 the live
             # leftovers are r1=0xB, r2=0xFA (b060's last stub call
             # was 65CF58(node,0xB,0xFA); millicode does not touch
             # r1/r2)
             (S[0xC7DD8], 0, 0xB, 0xFA),
             (S[0x65C720], NODE, 0xB, 0xFA),
             (S[0xC7E04], 0x2B, 0xB, 0xFA),
             (S[0xD10C4], 0, 0xB, 0xFA),
             (S[0x136280], 1, 0xB, 0xFA),
             (S[0xDE254], 0x33, 0xB, 0xFA),
             (S[0xC01EC], 0, 0xB, 0xFA),
             (S[0x65DB78], 1, 0xB, 0xFA),
             (S[0x145150], NODE, 0xB, 0xFA),
             (S[0x14905C], NODE, 4, 1000),
             (S[0x176828], 3, 1, 0x32),
             (S[0x145C3C], 0x30D40, 1, 0x32),
             (S[0x176828], 3, 0, 0x32)],
            extra=BASE_MEM + [
                (CTX + 4, 4, 6), (CTX + 0x18, 4, 0),
                (CTX + 0x1C, 1, 1), (CTX + 0x1D, 1, 0),
                (CTX + 0x1E, 1, 1), (GATE_CELL, 1, 0),
                (GATE_TGT, 1, 0), (GUARD_CELL, 1, 1),
                (CTX + 0x60, 4, SAVED), (GATE_BYTE, 1, 0),
                (CTX + 0x30, 4, 0xA5A5A5A5),
                (CTX + 0x34, 4, 0xA5A5A5A5)]))

        # 9 path B mode 7E, arg 0xFFFFFF80 -> arm 6
        SPECS.append(spec(
            'h100_7e_arg80', WINS_PATHB, ENTRY,
            [NODE, EV, 0xFFFFFF80],
            [a for a in H100_STUBS],
            {0x65D098: 0x77, 0xCD5AC: 1, 0x145D1C: 0x99,
             0x136280: 0x33, 0xDE254: 0x15, '_ret': 0},
            base_fix(2, 1, 0x100, 0x7E, 0,
                     [0xA5A5A5A5] * 4),
            HEAD(arg=0xFFFFFF80) + [
                (S[0xCD5AC], 0x7E, 0xA, 0xFFFFFF80),
                (S[0x145D1C], 0, 0xA, 0xFFFFFF80),
                (S[0x149028], NODE, 9, 0xFFFFFF80),
                (S[0x143AFC], 0x27, 9, 0xFFFFFF80),
                (S[0x143AFC], 0x28, 9, 0xFFFFFF80),
                (S[0x1439D4], 0x26, 9, 0xFFFFFF80),
                (S[0xC7E04], 0, 9, 0xFFFFFF80),
                (S[0x136280], 2, 9, 0xFFFFFF80),
                (S[0xDE254], 0x33, 9, 0xFFFFFF80),
                (S[0xC01EC], 0, 9, 0xFFFFFF80),
                (S[0x65DB78], 1, 9, 0xFFFFFF80),
                (S[0x145150], NODE, 9, 0xFFFFFF80),
                (S[0x14905C], NODE, 4, 1000),
                (S[0x176828], 3, 1, 0x32),
                (S[0x145C3C], 0x30D40, 1, 0x32),
                (S[0x176828], 3, 0, 0x32)],
            extra=BASE_MEM + [
                (CTX + 4, 4, 6), (CTX + 0x34, 4, 0x99),
                (CTX + 0x1C, 1, 1), (CTX + 0x1D, 1, 0),
                (CTX + 0x1E, 1, 1), (CTX + 0x30, 4, 0xA5A5A5A5),
                (GATE_BYTE, 1, 0)]))

        # 10 path B mode 7E, D10E8==0 -> 65D590(node,0x86)
        SPECS.append(spec(
            'h100_7e_d10e8', WINS_PATHB, ENTRY,
            [NODE, EV, 0x77],
            [a for a in H100_STUBS],
            {0x65D098: 0x77, 0xCD5AC: 1, 0x65D590: 0x66,
             '_ret': 0x66},
            base_fix(5, 1, 0x100, 0x7E, 0,
                     [0xA5A5A5A5] * 4),
            HEAD(arg=0x77) + [
                (S[0xCD5AC], 0x7E, 0xA, 0x77),
                (S[0xD10E8], 1, 0xA, 0x77),
                (S[0x65D590], NODE, 0x86, 0x77)],
            extra=BASE_MEM + [
                (CTX + 4, 4, 5), (CTX + 0x34, 4, 0xA5A5A5A5),
                (CTX + 0x30, 4, 0xA5A5A5A5), (CTX + 0x1C, 1, 0xA5),
                (GATE_BYTE, 1, 0)]))

        # 11 path A with a LARGE ring index: gate byte 0x10 -> table
        # word at 0x47BBB4+0x10*4 = 0x47BBF4 (fixture) = 3 ->
        # 1453E4(0xA7,0). Originally designed as a sign-extension
        # negative control, but the ARCompact ISA manual (5115-029)
        # is explicit: byte/word loads are ZERO-extended unless the
        # .X suffix is used ("Load unsigned byte" for LDB_S); the
        # pinned engine implements ZEXTQISI. So the `ble` at
        # 0x65B20A means "gate byte == 0" and bytes >= 0x80 take
        # path A - the sign-extension control is meaningless.
        SPECS.append(spec(
            'h100_gate10_far', WINS_ISOLATED, ENTRY,
            [NODE, EV, ARG],
            [a for a in H100_STUBS],
            {0x65D098: 0x77, 0x1453E4: 0x55, '_ret': 0x55},
            base_fix(5, 1, 0x100, 0x2B, 0x10, [0xA5A5A5A5] * 4,
                     gate9=gate9_far_fixture(0x10, 0x44, 3)),
            HEAD() + [
                (S[0xC5870], 2, 0x681F60, ARG),
                (S[0xCF538], 0, 0x681F60, ARG),
                (S[0x65B060], NODE, EV, ARG),
                (S[0x149028], SAVED, 6, ARG),
                (S[0x1453E4], 0xA7, 0, ARG)],
            extra=BASE_MEM + [
                (CTX + 4, 4, 2), (GATE_BYTE, 1, 0x10),
                (0x47BBF4, 4, 3), (0x47BBB4, 4, 0xA5A5A5A5),
                (0x47BBB8, 4, 0xA5A5A5A5), (CTX + 0x60, 4, SAVED),
                (CTX + 0x18, 4, 0x100)]))

        cases = []
        for idx, (name, wins, entry, args, stub_addrs, rets, fix,
                  asserts, syncret) in enumerate(SPECS):
            rets = dict(rets)
            success = 0xDEADB001 + idx
            # stubs must not overlap the original windows
            for a in stub_addrs:
                for (_, wlo, whi, _) in wins:
                    assert not (wlo <= a < whi), (hex(a), hex(wlo))
            rettab = bytearray(4 * (max(STUBS.values()) + 1))
            for a, v in rets.items():
                if a == '_ret':
                    continue
                struct.pack_into('<I', rettab, 4 * STUBS[a],
                                 v & 0xFFFFFFFF)
            prev_end = None
            for a in sorted(stub_addrs):
                if prev_end is not None and a < prev_end:
                    raise AssertionError(
                        f'stub overlap at {hex(a)} < {hex(prev_end)}')
                prev_end = a + 10
            stub_sections = (
                f'  .probe {hex(PROBE_AT)} : {{ *(.probe) }}\n'
                f'  .common {hex(COMMON_AT)} : {{ *(.common) }}\n'
                f'  .rettab {hex(RETTAB)} : {{ *(.rettab) }}\n')
            if syncret:
                stub_sections += \
                    f'  .syncret {hex(0x65A0A6)} : {{ *(.syncret) }}\n'
            for a in stub_addrs:
                stub_sections += (
                    f'  .stub_{a:x} {hex(a)} : '
                    f'{{ *(.stub_{a:x}) }}\n')
            for sname, sbase, _ in fix:
                if sname == '.rettab':
                    continue
                stub_sections += \
                    f'  {sname} {hex(sbase)} : {{ *({sname}) }}\n'
            asm = (harness(entry, args)
                   + ''.join(
                       (f'.section .stub_{a:x},"ax",@progbits\n'
                        ' .org 0\n' + stub_body(STUBS[a]))
                       for a in stub_addrs)
                   + common_logger()
                   + probe(asserts, success, idx)
                   + fixture_sections(fix))
            if syncret:
                # the bl at 0x65A0A2 clobbers blink with 0x65A0A6, so
                # the trampoline must jump to the harness landing
                # point directly (0x101E, confirmed by trace: the
                # harness is mov sp/limm + 3x4-byte movs + 8-byte
                # mov r12 + 2-byte jl_s from 0x1000)
                land = 0x1000 + 8 + 4 * 3 + 8 + 2
                assert land == 0x101E, hex(land)
                asm += (f'.section .syncret,"ax",@progbits\n'
                        ' .org 0\n'
                        f' mov r12,{hex(land)}\n'
                        ' j_s [r12]\n')
            asm += (f'.section .rettab,"aw",@progbits\n'
                    + ''.join(f' .byte {b}\n' for b in rettab))
            case, sim_text = build_case(name, asm, wins,
                                        stub_sections)
            assert case['exit_code'] == 11, (name, case)
            fault = case['fault']
            assert fault is not None \
                and fault['operation'] == 'read', (name, fault)
            addr = int(fault['address'], 16)
            assert addr == success, (name, fault, hex(success))
            assert PROBE_AT <= int(fault['pc'], 16) \
                < PROBE_AT + 0x2000, (name, fault)
            cases.append(dict(name=name, entry=hex(entry),
                              success=hex(success),
                              exit_code=case['exit_code'],
                              instructions=case['instructions'],
                              fault=fault))
            print(f'PASS {name} -> {hex(success)}', flush=True)

        results['cpu_cases'] = cases
        results['stub_map'] = {hex(a): STUBS[a] for a in ALL_STUBS}
        results['status'] = 'PASS_ASLV_H100_CPU'
        print('PASS_ASLV_H100_CPU', stamp)
        print('Evidence:', out / 'verified_evidence.json')
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'verified_evidence.json').write_text(
            json.dumps(results, indent=2, default=str) + '\n')


if __name__ == '__main__':
    main()
