#!/usr/bin/env python3
"""Nikon COOLPIX S33 - AutoSceneLiveView close handler 0x4405 (0x65959C).

Iteration 30 (Vibe offline, CPU bench with original windows).

Question: the 0x4405 close handler of the AutoSceneLiveView window
(registry p3 0x783B08, ctx 0x681F5C) is the richest writer of the
window state [ctx+4] (values 0 and 2) and the natural consumer of the
context prepared by the open handler 0x659554 (it.28). Decode and
CPU-prove its structure to close the open -> state -> close cycle.

Static decode (GNU ARC700, original bytes):
  entry 0x65959C(r0=node, r1=arg, r2=arg2):
  - 0xD2554(node); ==1 -> 0xD2544 + 0xD3E6C(1); 0x26C4E8(ret);
  - gate 0x14504C(node,0x12)==0x55 -> [0x442644+0xF0]:=[0x442734]:=0
    AND [[0x3669EC]+0xF0]:=0 (double indirection);
  - 0xCE6F4(1); 0xD10A8(0); 0x143AFC(0);
  - timer cells [ctx+0x64]/[ctx+0x68] (64-bit, pool 0x659924=0x682020):
    both zero -> skip; else 0x145D1C(0)=now, elapsed=now-t0,
    elapsed>=0x16E360 (1500000) -> 0x143AFC(0xC),
    else 0x145C3C(1500000-elapsed);
  - TEARDOWN: 0x1439D4(1); 0x131790(ret); [ctx+4]:=0 (word, 0x65964A),
    [ctx+0x39]:=0, [ctx+0x2C]:=0, [ctx+0x1C]:=0, [ctx+0x26]:=0,
    [ctx+0x1D]:=0, [ctx+0x1E]:=1, [ctx+0x1F]:=0, [ctx+0x23]:=0,
    [ctx+0x28]:=0 (word); 0x15AD44()!=0 -> [ctx+0x38]:=0;
    [ctx+8]/[ctx+9]/[ctx+0x18] NOT touched here;
  - 0x145B08(node,0x4800,0) [9<<11]; 0x8101FC(0);
    0x145654(node,0x480C) (delay slot); 0xD148C(ret,0,0);
  - mode getter ORIGINAL 0xCAD30 (byte 0xC8E80C, pool 0xCAAC4):
    mode==0x2C -> guard getter ORIGINAL 0xCA310:
      guard==7  -> chain A: 0xCE1EC(0), 0x1316F8(2), 0x191B58(0),
                   0x1421AC(0), 0x130E5C(0), 0x192708(0);
      guard!=7  -> chain B: 0xCC410(0x11), 0xCE1EC, 0xCC410(0x13),
                   0x131740, 0x1316F8, 0xD1154, 0x1421AC, 0x1421C8
                   (loop while ret!=0), tail 0x191B58(0)/0x130E5C(0)/
                   0x192708(0);
    mode re-read: ==0x2C -> 0xD0924() gate -> 0x6597c2 block;
    0x2019C0(0); mode!=0x7D -> 0xCC410(9), 0x126F8C(extb),
    0x126F80, 0xCF0C4(x,1), 0xCFE18, 0x1435FC(x);
  - common: 0xCFDD0(0); 0x12845C() gate; 0xCEB0C(1);
    0xCAD38(1) (CaptureMenu state setter, static claim it.23:
    writes [0x365753]:=1); 0xDE1F4(0xC8);
    0xCF554() #1: ==1 -> notify cells [0x366AF1]==1 -> post
      0x169EB4(node,0x80,0)+0x169EB4(node,0x100,0); else [0x366AF0]==1
      -> post 0x169EB4(node,0x80,0) and if cfg[1]==0 (ORIGINAL reader
      0x16F920) post 0x169EB4(node,0x81,0); then BOTH cells :=0;
    0xCF554() #2: ==1 and 0xCE6A0()==0 -> queue queries
      0x17BE18(0,0x80,0x80) / (0,0x100,0x100); either !=0 ->
      0x12CAD4(pool 0x659958=0x00B80035);
  - [ctx+0x18] destiny (three-way):
    ==0x100 (256)  -> COMPLETE: 0x14504C(node,0x12)!=6 ->
      0xCAFBC + 0xCaff8(3); [ctx+0x24]:=1; posts (node,0x80,0) +
      (node,0x100,0); 0x65CFA0; 0x14503C(node,0) -> bclr bit0xA ->
      0x1450C8(node,0,flags); return 0, state stays 0;
    ==0x101 (257)  -> DEFERRED REOPEN: [ctx+0x18]:=0x100;
      0xCAFBC(ctx); 0xCaff8(3); 0x65CFA0(3);
      0x65AC58(node,r1,r2); re-read [ctx+0x18]: ==0 -> return 0;
      queue query 0x17BE18(0,0x100,0x100)!=0 -> return 0 (state 0);
      cfg[2]!=0 (ORIGINAL) -> return 0; cfg[1]!=0 -> return 0;
      else [ctx+0x18]:=0; 0x661780(0); [ctx+4]:=2 (0x6599C2);
      0x65B060(node); purge 0x17BF60(0,0x80,0x307F); return 0;
    other (pointer) -> 0x660C34([ctx+0x18]); [ret+0xF0]>0 ->
      0x660C34 + 0xAD90C(ret,0x110); mode chain {0x6F,0x70,0x6E,0x7A,
      0x7B,0x7C}->0x15A5C8; mode==0x15 -> queue queries; ... long tail
      (covered by case close_ptr), ends 0x809DF4(1,1) -> return 0.
  Return value: r0=0 via shared epilogue 0x65953C (inside wrapper
  window) -> millicode 0x334174.

CPU cases (original windows .mili 0x334100..0x3341E4, .guard
0xCA2F4..0xCA31A, .modeget 0xCAD30..0xCAD38, .modepool 0xCAAC4,
.cfgread 0x16F920..0x16F928 + .cfgpool 0x16FA34, .wrap
0x6593A0..0x659554 [epilogue only], .h4405 0x65959C..0x659EF0):
 1 close_m2c_g7_arg100   mode 2C guard 7 arg18=0x100: teardown, chain
                         A, completion, state 0, [ctx+0x24]:=1
 2 close_m2c_gN_arg100   mode 2C guard 3: chain B, 0x15AD44 ret 1 ->
                         [ctx+0x38]:=0
 3 close_entry55         0x14504C ret 0x55 (mode 2B): [0x442734]:=0
                         and [[0x3669EC]+0xF0]:=0
 4 close_timer_rem       t0=1000, now=2000 -> 0x145C3C(1499000)
 5 close_timer_exp       elapsed>=1500000 -> 0x143AFC(0xC)
 6 close_arg101_deferred arg18=0x101: [ctx+4]:=2, [ctx+0x18]:=0,
                         0x65AC58(node,r1,r2), purge
 7 close_arg101_qblocked queue query ret 1: NO state-2 writer
 8 close_arg101_cfg1     cfg[1]=1 fixture (ORIGINAL reader): blocked
 9 close_arg101_cfg2     cfg[2]=1 fixture: blocked
10 close_notify_f1       [0x366AF1]=1, CF554 ret 1: posts 0x80/0x100,
                         both cells cleared
11 close_notify_f0       [0x366AF0]=1: posts 0x80 and cfg[1]==0 ->
                         0x81; cells cleared
12 close_notify_q80      queue query ret 1 -> 0x12CAD4(0x00B80035)
13 close_ptr             arg18=PTR: pointer path to 0x809DF4(1,1)

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
RETCELL = 0x367700      # NOT near LOG_ENT: entry 34 sid slot
                        # collides with 0x367320
R3CELL = 0x367710      # unused mirrors (kept for reference)
R4CELL = 0x367714

CTX = 0x681F5C               # AutoSceneLiveView context
REG_P3 = 0x783B08            # AutoSceneLiveView notify registry
ENTRY = 0x65959C             # 0x4405 handler
GUARD = 0x365751             # CaptureMenu guard byte
CMSTATE = 0x365753           # CaptureMenu state byte (0xCAD38 setter)
MODE_CELL = 0xC8E80C         # mode byte read by 0xCAD30
CFG_TAB = 0x446808           # runtime cfg byte table (0x16F920)
GATE_CELL = 0x442734         # 0x442644+0xF0
GATE_P_CELL = 0x3669EC       # pointer cell for the second gate target
GATE_TGT = 0x3680F0          # [0x3669EC]+0xF0 fixture target
NT_F0 = 0x366AF0             # notify cell B
NT_F1 = 0x366AF1             # notify cell A
TIMER_LO = CTX + 0xC4       # [0x682020]
TIMER_HI = CTX + 0xC8       # [0x682024]
PTR = 0x369200               # pointer value for case close_ptr

NODE = 0x1234
ARG1 = 0x71
ARG2 = 0x72

# original windows (payload, lo, hi, section)
W_MILI = (0, 0x334100, 0x3341E4, '.mili')
W_GUARD = (0, 0xCA2F4, 0xCA31A, '.guard')
W_MODEGET = (0, 0xCAD30, 0xCAD38, '.modeget')
W_MODEPOOL = (0, 0xCAAC4, 0xCAAC8, '.modepool')
W_CFG = (0, 0x16F920, 0x16F928, '.cfgread')
W_CFG_POOL = (0, 0x16FA34, 0x16FA38, '.cfgpool')
W_WRAP = (2, 0x6593A0, 0x659554, '.wrap')
W_H4405 = (2, 0x65959C, 0x659EF0, '.h4405')

ALL_WINS = [W_MILI, W_GUARD, W_MODEGET, W_MODEPOOL, W_CFG, W_CFG_POOL,
            W_WRAP, W_H4405]

# bl targets actually reached by the 13 CPU cases (from the GNU listing
# of 0x65959C..0x659EF0), minus originals (millicode 0x33411C, guard
# getter 0xCA310, cfg reader 0x16F920) and minus branches never taken
# with the case fixtures (documented in the report; reaching a dropped
# target executes garbage and fails the case probe).
BL_TARGETS = [
    0x26C4E8, 0xC7E04, 0xCAD38, 0xCAFBC, 0xCAFF8, 0xCB5B0, 0xCB634,
    0xCC410, 0xCD558, 0xCD8CC, 0xCE1EC, 0xCE6A0, 0xCE6F4, 0xCEB0C,
    0xCF0C4, 0xCF554, 0xCFBE8, 0xCFDD0, 0xCFE18, 0xD0924, 0xD0B4C,
    0xD0B80, 0xD10A8, 0xD1154, 0xD148C, 0xD1680, 0xD16C8, 0xD1A00,
    0xD2554, 0xDE1F4, 0xE1398, 0xE13A8, 0x126F80, 0x126F8C,
    0x12845C, 0x12CAD4, 0x130E5C, 0x1316F8, 0x131740, 0x131790,
    0x1421AC, 0x1421C8, 0x1435FC, 0x1439D4, 0x143AFC, 0x144CE8,
    0x14503C, 0x14504C, 0x1450C8, 0x145150, 0x145654, 0x145920,
    0x145B08, 0x145C3C, 0x145D1C, 0x14905C, 0x1493D8, 0x14941C,
    0x14949C, 0x149DF4, 0x1314B8, 0x14A1C8, 0x14A1CC, 0x14A1F8,
    0x14A1FC, 0x14A884,
    0x14A8E8, 0x158D04, 0x15AD44, 0x169EB4, 0x175394, 0x177484,
    0x17BE18, 0x17BF60, 0x191B58, 0x192708, 0x2019C0, 0x61E4EC,
    0x65AC58, 0x65B060, 0x65C720, 0x65CE24, 0x65CED4, 0x65CF58,
    0x65CFA0, 0x65D0EC, 0x65D6D0, 0x65D814, 0x65E430, 0x660C34,
    0x661780, 0x809DF4, 0x8101FC]

STUBS = {a: i + 1 for i, a in enumerate(sorted(set(BL_TARGETS)))}

# stub pairs only 4 bytes apart: one shared section with two 4-byte
# entries (mov_s r12,sid + b_s tail) and a common 10-byte tail.
SPECIAL_PAIRS = [(0x14A1C8, 0x14A1CC), (0x14A1F8, 0x14A1FC)]

# readable stub keys (subset used in oracles)
S = {a: STUBS[a] for a in BL_TARGETS}


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
    # 10-byte position-independent stub: the caller's return
    # address (set by bl) is pushed on the stack; sid in r12
    # (caller-saved); common address in r3 via u12 mov; the common
    # logger pops the saved blink and returns directly to caller.
    return (' push_s blink\n'
            f' mov_s r12,{hex(sid)}\n'
            f' mov r3,{hex(COMMON_AT)}\n'
            ' jl_s [r3]\n')


def special_pair_section(lo, hi):
    # two 4-byte entries (lo, hi=lo+4) + shared 10-byte tail at lo+8
    assert hi == lo + 4, (hex(lo), hex(hi))
    return (f'.section .spair_{lo:x},"ax",@progbits\n .org 0\n'
            f' mov_s r12,{hex(STUBS[lo])}\n'
            f' b_s tail_{lo:x}\n'
            ' .org 4\n'
            f' mov_s r12,{hex(STUBS[hi])}\n'
            f' b_s tail_{lo:x}\n'
            ' .org 8\n'
            f'tail_{lo:x}:\n'
            ' push_s blink\n'
            f' mov r3,{hex(COMMON_AT)}\n'
            ' jl_s [r3]\n')


def common_logger():
    # r12 holds the stub id at entry
    # NOTE: no r3/r4 mirror stores - the previous mirror address
    # collided with log entry slots (16*33+4 = 0x367314)
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


def ctx_fixture(state=6, arg18=0x100, timer_lo=0, timer_hi=0):
    # 0xD0 bytes: the timer cells [0x682020]/[0x682024] are at
    # ctx + 0xC4 / ctx + 0xC8 (pool 0x659924 = 0x682020)
    buf = bytearray(b'\xA5' * 0xD0)
    struct.pack_into('<I', buf, 4, state)          # word state
    buf[8] = 0xFF                                  # open handler 0xFF
    buf[9] = 0x5A                                  # guard copy (open)
    buf[0x23] = 3
    buf[0x38] = 0xA5                               # sentinel (15AD44)
    struct.pack_into('<I', buf, 0x18, arg18)        # word arg18
    struct.pack_into('<I', buf, 0xC4, timer_lo)
    struct.pack_into('<I', buf, 0xC8, timer_hi)
    # teardown clears [ctx+0x28] with stw_s (16-bit halfword): keep
    # the high bytes zero so the 32-bit probe assert stays valid
    buf[0x2A] = 0
    buf[0x2B] = 0
    return bytes(buf)


def guard_fixture(guard):
    buf = bytearray(b'\xA5' * 8)          # 0x365750..0x365757
    buf[1] = guard                       # 0x365751
    buf[3] = 0xA5                        # 0x365753 sentinel
    return bytes(buf)


def cfg_fixture(c1=0, c2=0):
    buf = bytearray(b'\x00' * 0x48)      # 0x446808..0x446850
    buf[4 * 1] = c1
    buf[4 * 2] = c2
    return bytes(buf)


def base_fix(mode=0x2B, guard=5, arg18=0x100, c1=0, c2=0,
             f0=0, f1=0, timer_lo=0, timer_hi=0, state=6):
    return [('.ctxfix', CTX, ctx_fixture(state, arg18, timer_lo,
                                         timer_hi)),
            ('.guardfix', 0x365750, guard_fixture(guard)),
            ('.modefix', MODE_CELL, bytes([mode])),
            ('.cfgfix', CFG_TAB, cfg_fixture(c1, c2)),
            ('.gatefix', GATE_CELL, b'\xA5'),
            ('.gptrfix', GATE_P_CELL,
             struct.pack('<I', 0x368000)),
            ('.tgtfix', GATE_TGT, b'\xA5'),
            ('.ntfix', NT_F0, bytes([f0, f1])),
            ('.logfix', 0x367000, bytes(0x800))]


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'aslv_close_handler_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, _ = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp,
                   action='aslv-close-handler-4405',
                   limits=['Static analysis + 13 synthetic CPU cases; '
                           'no hardware',
                           'Deep callees are stubs (~136); only the '
                           'handler, the wrapper epilogue, millicode, '
                           'the ORIGINAL guard getter/setter window '
                           '(getter executed), the ORIGINAL mode getter '
                           '0xCAD30, the ORIGINAL cfg reader 0x16F920 '
                           'and the ORIGINAL guard getter 0xCA310 '
                           'execute',
                           'ctx 0x681F5C, mode byte 0xC8E80C, cfg '
                           'table 0x446808, cells 0x442734/0x3669EC/'
                           '0x366AF0/0x366AF1, timer cells ctx+0x64/'
                           '+0x68 are fixtures; runtime producers not '
                           'proven',
                           '0xCAD38 (CaptureMenu state setter) is a '
                           'STUB: the write to 0x365753 is the static '
                           'claim of iteration 23, not re-proven here',
                           'Semantics of states 0/2, cfg[1]/[2], '
                           '[ctx+0x18] values 0x100/0x101 and the '
                           'pointer path are structural, not '
                           'functionally identified',
                           'No physical button map, no hardware, no '
                           'scheduling; V1.1 dump only; NON_INSTALLARE'])
    try:
        p0, p2, p3 = payloads[0], payloads[2], payloads[3]

        # --- 1. static: registry p3 record for 0x4405 ---------------
        recs = []
        k = 0
        while True:
            a = REG_P3 + 8 * k
            ev, pad, h = struct.unpack_from('<HHI', p3, a - base[3])
            recs.append((a, ev, h))
            if ev == 0:
                break
            k += 1
        m = {ev: (a, h) for (a, ev, h) in recs[:-1]}
        assert len(recs) == 40, len(recs)
        h4405_addr, h4405 = m[0x4405]
        assert h4405 == ENTRY, hex(h4405)
        results['registry_p3'] = dict(n_records=len(recs) - 1,
                                     ev4405_handler=hex(h4405),
                                     handler_field=hex(h4405_addr + 4))

        # --- 2. static: pools ----------------------------------------
        pools = {0x65991C: 0x442644, 0x659920: GATE_P_CELL,
                 0x659924: 0x682020, 0x659928: 0x16E360,
                 0x65992C: CTX, 0x659930: 0x681F94,
                 0x659934: 0x681F78, 0x659938: 0x480C,
                 0x65993C: 0xCAD30, 0x659940: 0x142834,
                 0x659944: 0x192CB4, 0x659948: 0x3101,
                 0x65994C: 0x307F, 0x659950: NT_F1, 0x659954: NT_F0,
                 0x659958: 0x00B80035, 0x659CCC: CTX,
                 0x659CD0: 0x307F, 0x659CD4: 0x47BBB8,
                 0x659CD8: 0x47BBB4, 0x659CDC: 0x00B0000D,
                 0x659CE0: 0x47BB3C, 0x659CE4: 0x02600001,
                 0x659CE8: 0x4111, 0x659EE4: 0x442644,
                 0x659EE8: GATE_P_CELL, 0x659EEC: 0x65E430,
                 0xCAAC4: MODE_CELL, 0x16FA34: CFG_TAB,
                 0xCA30C: GUARD}
        for a, v in pools.items():
            src, bb = (p0, base[0]) if a < base[2] else (p2, base[2])
            got = struct.unpack_from('<I', src, a - bb)[0]
            assert got == v, (hex(a), hex(got), hex(v))
        results['pools'] = {hex(a): hex(v) for a, v in pools.items()}

        # --- 3. static: LE scans --------------------------------------
        # cells shared by many pools: assert handler pools are a
        # subset of the LE hits (full lists recorded); unique
        # references (handler address, notify cell A, packed id)
        # must be exact.
        subset = {0x682020: [(2, 0x659924)],
                  NT_F0: [(2, 0x659954)],
                  GATE_P_CELL: [(2, 0x659920), (2, 0x659EE8)],
                  0x442644: [(2, 0x65991C), (2, 0x659EE4)],
                  0x16E360: [(2, 0x659928)]}
        exact = {ENTRY: [(3, h4405_addr + 4, 0)],
                 NT_F1: [(2, 0x659950, 0)],
                 0x00B80035: [(2, 0x659958, 0)]}
        le = {}
        for t, exp in subset.items():
            hits = [(i, a, o) for (i, a, o) in le_scan(payloads, base, t)
                    if o == 0]
            for (i, a) in exp:
                assert (i, a, 0) in hits, (hex(t), hex(a), hits)
            le[hex(t)] = dict(handler_pools=[(i, hex(a)) for i, a in
                                             exp],
                              total_hits=len(hits))
        for t, exp in exact.items():
            hits = [(i, a, o) for (i, a, o) in le_scan(payloads, base, t)
                    if o == 0]
            assert hits == exp, (hex(t), hits, exp)
            le[hex(t)] = [(i, hex(a), o) for i, a, o in hits]
        results['le_scans'] = le

        # --- 4. static: bl census of ENTRY across all block listings --
        census = 0
        objcopy = ROOT / 'work/build-arc/binutils/objcopy'
        objdump = ROOT / 'work/build-arc/binutils/objdump'
        assert objcopy.is_file() and objdump.is_file()
        with tempfile.TemporaryDirectory(prefix='it30-census-') as td:
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
                     '-EL', str(elf)],
                    capture_output=True, text=True, check=True,
                    timeout=280).stdout
                census += text.count(f';0x{ENTRY:x}')
        assert census == 0, census
        results['bl_census'] = {hex(ENTRY): census,
                                'note': 'pure callback (registry p3 only)'}

        # --- 5. static: opcode freezes --------------------------------
        freezes = [
            ('prologue', 2, 0x65959C,
             'f1c0820b4e6dfc1cc8b60a23003708751a715a724a210020a20f4d3'
             'c81e007f48a0f4d3c01d8ae084d3d260f4e09a97012d9820acd75'),
            ('entry_gate55', 2, 0x6595D4,
             'd5e009f4d1d0f018c203d1d00080f018c203'),
            ('teardown', 2, 0x65963A,
             '01d89a0b0d7552090d6cbad001d9bad6e1a0bad0e1aef0a8b7d0fca8'
             'b8d0eaa8b5d0fda83ea8ffa8b5d0e7a8b2d0f4b0de0e8d8080e002f2e'
             '0ae'),
            ('writer2_deferred', 2, 0x6599B2,
             'c7d0e6a000d8ca0dc003c4d00a714a72c1a0a9709e0e800000d880d9'
             '960d2d91c0d2'),
            ('arg18_read', 2, 0x6598C4,
             '1ad006808c20048048f4a97012d9'),
            ('tail', 2, 0x6599D4, '00d80d050000'),
            ('tail_809df4', 2, 0x659ED4,
             '01d808711e0fc0d7f902cfff5d068fff'),
            ('modeget', 0, 0xCAD30, '651700f60088e07e'),
            ('modepool', 0, 0xCAAC4, '0ce8c800'),
            ('cfg_win', 0, 0x16F920, '45d11579e07f0089'),
            ('cfg_pool', 0, 0x16FA34, '08684400'),
            ('guard_win', 0, 0xCA2F4,
             'fc1cc8b60a23003704d100a90a24c03604141b34e07ee07851573600'
             'fc1700f00088e07ef1c0'),
        ]
        for name, idx, addr, hexstr in freezes:
            data = payloads[idx][addr - base[idx]:
                                 addr - base[idx] + len(hexstr) // 2]
            assert data.hex() == hexstr, (name, data.hex())
        results['opcode_freezes'] = 'ok'

        # window inventory + non-overlap
        wins = {}
        prev = None
        for (pidx, lo, hi, sec) in sorted(ALL_WINS,
                                          key=lambda w: (w[1], w[2])):
            assert prev is None or lo >= prev, (hex(lo), hex(prev))
            prev = hi
            data = payloads[pidx][lo - base[pidx]:hi - base[pidx]]
            wins[sec] = dict(payload=pidx, lo=hex(lo), hi=hex(hi),
                             size=len(data),
                             sha256=hashlib.sha256(data).hexdigest())
        results['windows'] = wins

        # --- 6. CPU cases ----------------------------------------------
        r = Runner(SimpleNamespace(legacy_root=LEGACY,
                                   toolchain=TOOLCHAIN,
                                   output=out,
                                   action='aslv-close-handler'))
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
                '}\n')
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

        def spec(name, fixkw, rets, logs, extra=None):
            asserts = []
            for i, (sid, a0, a1, a2) in enumerate(logs):
                asserts += L(i, sid, a0, a1, a2)
            n = len(logs)
            asserts += [(CNT, 4, n)]
            asserts += L(n, 0, None, None, None)   # no extra calls
            asserts += [(RETCELL, 4, rets.pop('_ret'))]
            if extra:
                asserts += extra
            return (name, (NODE, ARG1, ARG2), rets, fixkw, asserts)

        # shared log fragments
        def P0():
            return [(S[0xD2554], NODE, None, None),
                    (S[0x26C4E8], 0, None, None),
                    (S[0x14504C], NODE, 0x12, None),
                    (S[0xCE6F4], 1, None, None),
                    (S[0xD10A8], 0, None, None),
                    (S[0x143AFC], 0, None, None)]

        def MID():
            return [(S[0x1439D4], 1, None, None),
                    (S[0x131790], 0, None, None),
                    (S[0x15AD44], CTX, None, None),
                    (S[0x145B08], NODE, 0x4800, 0),
                    (S[0x8101FC], 0, None, None),
                    (S[0x145654], NODE, 0x480C, None),
                    (S[0xD148C], 0, 0, 0)]

        CHAIN_A = [(S[0xCE1EC], 0, None, None),
                   (S[0x1316F8], 2, None, None),
                   (S[0x191B58], 0, None, None),
                   (S[0x1421AC], 0, None, None),
                   (S[0x130E5C], 0, None, None),
                   (S[0x192708], 0, None, None)]
        CHAIN_B = [(S[0xCC410], 0x11, None, None),
                   (S[0xCE1EC], 0, None, None),
                   (S[0xCC410], 0x13, None, None),
                   (S[0x131740], 0, None, None),
                   (S[0x1316F8], 0, None, None),
                   (S[0xD1154], 0, None, None),
                   (S[0x1421AC], 0, None, None),
                   (S[0x1421C8], 0, None, None),
                   (S[0x191B58], 0, None, None),
                   (S[0x130E5C], 0, None, None),
                   (S[0x192708], 0, None, None)]

        def MID2():
            return [(S[0x2019C0], 0, None, None),
                    (S[0xCC410], 9, None, None),
                    (S[0x126F8C], 0, None, None),
                    (S[0x126F80], 0, None, None),
                    (S[0xCF0C4], 0, 1, None),
                    (S[0xCFE18], 0, None, None),
                    (S[0x1435FC], 0, None, None),
                    (S[0xCFDD0], 0, None, None),
                    (S[0x12845C], 0, None, None),
                    (S[0xCEB0C], 1, None, None),
                    (S[0xCAD38], 1, None, None),
                    (S[0xDE1F4], 0xC8, 1, None),
                    # CF554 #2 is called ALWAYS (bne_s at 0x659846 goes
                    # to 0x659890); with CF554 #1 ret 0 the branch is
                    # taken directly and r0 = the return value (0)
                    (S[0xCF554], 0, None, None),
                    (S[0xCF554], 0, None, None)]

        def TAIL100(r402c=0):
            # CAFBC receives r0 = the return of the TAIL 0x14504C call
            return [(S[0x14504C], NODE, 0x12, None),
                    (S[0xCAFBC], r402c, None, None),
                    (S[0xCAFF8], 3, None, None),
                    (S[0x169EB4], NODE, 0x80, 0),
                    (S[0x169EB4], NODE, 0x100, 0),
                    (S[0x65CFA0], 0, None, None),
                    (S[0x14503C], NODE, 0, None),
                    (S[0x1450C8], NODE, 0, 0)]

        # final [ctx+4] is asserted per case (0 or 2), not here
        TEARDOWN_MEM = [
            (CTX + 0x1C, 1, 0), (CTX + 0x1D, 1, 0),
            (CTX + 0x1E, 1, 1), (CTX + 0x1F, 1, 0), (CTX + 0x23, 1, 0),
            (CTX + 0x26, 1, 0), (CTX + 0x28, 4, 0), (CTX + 0x2C, 1, 0),
            (CTX + 0x39, 1, 0),
            (CTX + 8, 1, 0xFF), (CTX + 9, 1, 0x5A),   # open leftovers
            (CMSTATE, 1, 0xA5)]   # setter stubbed

        # gate cells NOT zeroed (default: entry stub != 0x55);
        # close_entry55 overrides with 0/0 in its own extras
        GATE_OK = [(GATE_CELL, 1, 0xA5), (GATE_TGT, 1, 0xA5)]

        specs = []

        # 1 mode 2C guard 7, arg18=0x100 -> complete, state 0
        specs.append(spec(
            'close_m2c_g7_arg100',
            dict(mode=0x2C, guard=7),
            {'_ret': 0},
            P0() + MID() + CHAIN_A
            + [(S[0xD0924], 0x2C, None, None)] + MID2() + TAIL100(),
            extra=TEARDOWN_MEM + GATE_OK + [
                (CTX + 4, 4, 0), (CTX + 0x24, 1, 1),
                (CTX + 0x18, 4, 0x100), (CTX + 0x38, 1, 0xA5),
                (GUARD, 1, 7), (NT_F0, 1, 0), (NT_F1, 1, 0)]))

        # 2 mode 2C guard 3 -> chain B, 15AD44 ret 1 -> [ctx+0x38]:=0
        specs.append(spec(
            'close_m2c_gN_arg100',
            dict(mode=0x2C, guard=3),
            {0x15AD44: 1, '_ret': 0},
            P0() + MID() + CHAIN_B
            + [(S[0xD0924], 0x2C, None, None)] + MID2() + TAIL100(),
            extra=TEARDOWN_MEM + GATE_OK + [
                (CTX + 4, 4, 0), (CTX + 0x24, 1, 1),
                (CTX + 0x18, 4, 0x100), (CTX + 0x38, 1, 0),
                (GUARD, 1, 3)]))

        # 3 14504C ret 0x55 -> both gate cells zeroed
        specs.append(spec(
            'close_entry55',
            dict(mode=0x2B, guard=5),
            {0x14504C: 0x55, '_ret': 0},
            P0() + MID() + MID2() + TAIL100(0x55),
            extra=TEARDOWN_MEM + [   # no GATE_OK: gate cells ARE zeroed
                (GATE_CELL, 1, 0), (GATE_TGT, 1, 0),
                (CTX + 4, 4, 0), (CTX + 0x24, 1, 1),
                (CTX + 0x18, 4, 0x100), (CTX + 0x38, 1, 0xA5)]))

        # 4 timer remaining -> 145C3C(1499000)
        specs.append(spec(
            'close_timer_rem',
            dict(mode=0x2B, guard=5, timer_lo=1000),
            {0x145D1C: 2000, '_ret': 0},
            P0() + [(S[0x145D1C], 0, None, None),
                    (S[0x145C3C], 1499000, None, None),
                    # 0x659630 falls through to 0x659634: 143AFC(0xC)
                    # is called in BOTH timer branches
                    (S[0x143AFC], 0xC, None, None)]
            + MID() + MID2() + TAIL100(),
            extra=TEARDOWN_MEM + GATE_OK + [
                (CTX + 4, 4, 0), (CTX + 0x24, 1, 1),
                (CTX + 0x18, 4, 0x100), (CTX + 0xC4, 4, 1000),
                (CTX + 0xC8, 4, 0)]))

        # 5 timer expired -> 143AFC(0xC)
        specs.append(spec(
            'close_timer_exp',
            dict(mode=0x2B, guard=5, timer_lo=100000),
            {0x145D1C: 2000000, '_ret': 0},
            P0() + [(S[0x145D1C], 0, None, None),
                    (S[0x143AFC], 0xC, None, None)]
            + MID() + MID2() + TAIL100(),
            extra=TEARDOWN_MEM + GATE_OK + [
                (CTX + 4, 4, 0), (CTX + 0x24, 1, 1),
                (CTX + 0x18, 4, 0x100), (CTX + 0xC4, 4, 100000),
                (CTX + 0xC8, 4, 0)]))

        # 6 arg18=0x101 -> deferred reopen: state := 2
        specs.append(spec(
            'close_arg101_deferred',
            dict(mode=0x2B, guard=5, arg18=0x101),
            {'_ret': 0},
            P0() + MID() + MID2() + [
                (S[0xCAFBC], CTX, None, None),
                (S[0xCAFF8], 3, None, None),
                (S[0x65CFA0], 0, None, None),   # r0 = ret of CAFF8 stub
                (S[0x65AC58], NODE, ARG1, ARG2),
                (S[0x17BE18], 0, 0x100, 0x100),
                (S[0x661780], 0, None, None),
                (S[0x65B060], NODE, None, None),
                (S[0x17BF60], 0, 0x80, 0x307F)],
            extra=TEARDOWN_MEM + GATE_OK + [
                (CTX + 4, 4, 2), (CTX + 0x18, 4, 0),
                (CTX + 0x24, 1, 0xA5), (CTX + 0x38, 1, 0xA5),
                (NT_F0, 1, 0), (NT_F1, 1, 0)]))

        # 7 arg18=0x101, queue query ret 1 -> blocked, state stays 0
        specs.append(spec(
            'close_arg101_qblocked',
            dict(mode=0x2B, guard=5, arg18=0x101),
            {0x17BE18: 1, '_ret': 0},
            P0() + MID() + MID2() + [
                (S[0xCAFBC], CTX, None, None),
                (S[0xCAFF8], 3, None, None),
                (S[0x65CFA0], 0, None, None),   # r0 = ret of CAFF8 stub
                (S[0x65AC58], NODE, ARG1, ARG2),
                (S[0x17BE18], 0, 0x100, 0x100)],
            extra=TEARDOWN_MEM + GATE_OK + [
                (CTX + 4, 4, 0), (CTX + 0x18, 4, 0x100),
                (CTX + 0x24, 1, 0xA5)]))

        # 8 arg18=0x101, cfg[1]=1 (ORIGINAL reader) -> blocked
        specs.append(spec(
            'close_arg101_cfg1',
            dict(mode=0x2B, guard=5, arg18=0x101, c1=1),
            {'_ret': 0},
            P0() + MID() + MID2() + [
                (S[0xCAFBC], CTX, None, None),
                (S[0xCAFF8], 3, None, None),
                (S[0x65CFA0], 0, None, None),   # r0 = ret of CAFF8 stub
                (S[0x65AC58], NODE, ARG1, ARG2),
                (S[0x17BE18], 0, 0x100, 0x100)],
            extra=TEARDOWN_MEM + GATE_OK + [
                (CTX + 4, 4, 0), (CTX + 0x18, 4, 0x100),
                (CTX + 0x24, 1, 0xA5)]))

        # 9 arg18=0x101, cfg[2]=1 -> blocked before cfg[1]
        specs.append(spec(
            'close_arg101_cfg2',
            dict(mode=0x2B, guard=5, arg18=0x101, c2=1),
            {'_ret': 0},
            P0() + MID() + MID2() + [
                (S[0xCAFBC], CTX, None, None),
                (S[0xCAFF8], 3, None, None),
                (S[0x65CFA0], 0, None, None),   # r0 = ret of CAFF8 stub
                (S[0x65AC58], NODE, ARG1, ARG2),
                (S[0x17BE18], 0, 0x100, 0x100)],
            extra=TEARDOWN_MEM + GATE_OK + [
                (CTX + 4, 4, 0), (CTX + 0x18, 4, 0x100),
                (CTX + 0x24, 1, 0xA5)]))

        # 10 notify cell 0x366AF1=1, CF554 ret 1 -> posts 0x80+0x100
        specs.append(spec(
            'close_notify_f1',
            dict(mode=0x2B, guard=5, f1=1),
            {0xCF554: 1, '_ret': 0},
            P0() + MID() + [
                (S[0x2019C0], 0, None, None),
                (S[0xCC410], 9, None, None),
                (S[0x126F8C], 0, None, None),
                (S[0x126F80], 0, None, None),
                (S[0xCF0C4], 0, 1, None),
                (S[0xCFE18], 0, None, None),
                (S[0x1435FC], 0, None, None),
                (S[0xCFDD0], 0, None, None),
                (S[0x12845C], 0, None, None),
                (S[0xCEB0C], 1, None, None),
                (S[0xCAD38], 1, None, None),
                (S[0xDE1F4], 0xC8, 1, None),
                (S[0xCF554], 0, None, None),
                (S[0x169EB4], NODE, 0x80, 0),
                (S[0x169EB4], NODE, 0x100, 0),
                (S[0xCF554], NT_F1, None, None),
                (S[0xCE6A0], 1, None, None),
                (S[0x17BE18], 0, 0x80, 0x80),
                (S[0x17BE18], 0, 0x100, 0x100)]
            + TAIL100(),
            extra=TEARDOWN_MEM + GATE_OK + [
                (NT_F0, 1, 0), (NT_F1, 1, 0),
                (CTX + 4, 4, 0), (CTX + 0x24, 1, 1),
                (CTX + 0x18, 4, 0x100)]))

        # 11 notify cell 0x366AF0=1 -> posts 0x80 and cfg[1]==0 -> 0x81
        specs.append(spec(
            'close_notify_f0',
            dict(mode=0x2B, guard=5, f0=1),
            {0xCF554: 1, '_ret': 0},
            P0() + MID() + [
                (S[0x2019C0], 0, None, None),
                (S[0xCC410], 9, None, None),
                (S[0x126F8C], 0, None, None),
                (S[0x126F80], 0, None, None),
                (S[0xCF0C4], 0, 1, None),
                (S[0xCFE18], 0, None, None),
                (S[0x1435FC], 0, None, None),
                (S[0xCFDD0], 0, None, None),
                (S[0x12845C], 0, None, None),
                (S[0xCEB0C], 1, None, None),
                (S[0xCAD38], 1, None, None),
                (S[0xDE1F4], 0xC8, 1, None),
                (S[0xCF554], 0, None, None),
                (S[0x169EB4], NODE, 0x80, 0),
                (S[0x169EB4], NODE, 0x81, 0),
                (S[0xCF554], NT_F1, None, None),
                (S[0xCE6A0], 1, None, None),
                (S[0x17BE18], 0, 0x80, 0x80),
                (S[0x17BE18], 0, 0x100, 0x100)]
            + TAIL100(),
            extra=TEARDOWN_MEM + GATE_OK + [
                (NT_F0, 1, 0), (NT_F1, 1, 0),
                (CTX + 4, 4, 0), (CTX + 0x24, 1, 1),
                (CTX + 0x18, 4, 0x100)]))

        # 12 notify f1 + queue query ret 1 -> 12CAD4(0x00B80035)
        specs.append(spec(
            'close_notify_q80',
            dict(mode=0x2B, guard=5, f1=1),
            {0xCF554: 1, 0x17BE18: 1, '_ret': 0},
            P0() + MID() + [
                (S[0x2019C0], 0, None, None),
                (S[0xCC410], 9, None, None),
                (S[0x126F8C], 0, None, None),
                (S[0x126F80], 0, None, None),
                (S[0xCF0C4], 0, 1, None),
                (S[0xCFE18], 0, None, None),
                (S[0x1435FC], 0, None, None),
                (S[0xCFDD0], 0, None, None),
                (S[0x12845C], 0, None, None),
                (S[0xCEB0C], 1, None, None),
                (S[0xCAD38], 1, None, None),
                (S[0xDE1F4], 0xC8, 1, None),
                (S[0xCF554], 0, None, None),
                (S[0x169EB4], NODE, 0x80, 0),
                (S[0x169EB4], NODE, 0x100, 0),
                (S[0xCF554], NT_F1, None, None),
                (S[0xCE6A0], 1, None, None),
                (S[0x17BE18], 0, 0x80, 0x80),
                (S[0x12CAD4], 0x00B80035, None, None)]
            + TAIL100(),
            extra=TEARDOWN_MEM + GATE_OK + [
                (NT_F0, 1, 0), (NT_F1, 1, 0),
                (CTX + 4, 4, 0), (CTX + 0x24, 1, 1),
                (CTX + 0x18, 4, 0x100)]))

        # 13 arg18 = pointer -> full pointer path to 0x809DF4(1,1)
        specs.append(spec(
            'close_ptr',
            dict(mode=0x2B, guard=5, arg18=PTR),
            {'_ret': 0},
            P0() + MID() + MID2() + [
                (S[0x660C34], PTR, None, None),
                (S[0x1493D8], 0x2B, None, None),
                (S[0x14504C], NODE, 0x12, None),
                (S[0x17BE18], 0, 0x3101, 0x3101),
                (S[0xCAFF8], 3, None, None),
                (S[0x14504C], NODE, 0x12, None),
                (S[0x14A884], 0, None, None),
                (S[0xE1398], 0, None, None),
                (S[0x14A1FC], 0, None, None),
                (S[0xE13A8], 0, None, None),
                (S[0x14504C], NODE, 0x12, None),
                (S[0x14504C], NODE, 0x12, None),
                (S[0x65D0EC], NODE, None, None),
                (S[0x65D814], 0, None, None),
                (S[0x144CE8], 0, None, None),
                (S[0xD0B4C], 1, None, None),
                (S[0x14504C], NODE, 0x12, None),
                (S[0x14504C], NODE, 0x12, None),
                (S[0x14504C], NODE, 0x12, None),
                (S[0xCB5B0], 0, None, None),
                (S[0x12CAD4], 0x00B0000D, None, None),
                (S[0x65C720], NODE, None, None),
                (S[0x65D6D0], 0, None, None),
                (S[0x145920], 0, None, None),
                (S[0xD16C8], 0, None, None),
                (S[0xC7E04], 0, None, None),
                (S[0x14905C], NODE, 8, 100),
                (S[0x61E4EC], 1, None, None),
                (S[0x158D04], 0x02600001, 8, 0),
                (S[0x14A8E8], 0, None, None),
                (S[0x14A1CC], 0, None, None),
                (S[0x177484], 0, None, None),
                (S[0xCD558], 1, None, None),
                (S[0x65CE24], 0, None, None),
                (S[0x14949C], 0x65E430, None, None),   # delay slot loads r0
                (S[0x14A1F8], 0, None, None),
                (S[0x14941C], 0, None, None),
                (S[0x65E430], 0, None, None),
                (S[0xD0B80], 0, None, None),
                (S[0xCB634], 0, None, None),
                # CB634() != 4 falls through (beq at 0x659E2E):
                # 177484 then (ret==0) 149DF4 + 1314B8
                (S[0x177484], 0, None, None),
                (S[0x149DF4], 0, None, None),
                (S[0x1314B8], 0, None, None),
                (S[0xCD8CC], 0, None, None),
                (S[0x14905C], NODE, 0xB, 0xFA),
                (S[0xCFBE8], 0, None, None),
                (S[0x65CED4], NODE, None, None),
                (S[0x65CF58], NODE, None, None),
                (S[0x14503C], NODE, 0, None),
                (S[0x1450C8], NODE, 0, 0),
                (S[0x145150], NODE, None, None),
                (S[0x12845C], 0, None, None),
                (S[0xD1680], 0, None, None),
                (S[0xD1A00], 0, None, None),
                (S[0x15AD44], 0, None, None),
                (S[0x175394], 0, None, None),
                (S[0x809DF4], 1, 1, None)],
            extra=TEARDOWN_MEM + GATE_OK + [
                (CTX + 4, 4, 0), (CTX + 0x18, 4, PTR),
                (CTX + 0x24, 1, 0xA5), (CTX + 0x30, 4, 0xA5A5A5A5),
                (CTX + 0x34, 4, 0xA5A5A5A5), (CTX + 0x38, 1, 0xA5),
                (NT_F0, 1, 0), (NT_F1, 1, 0),
                (GATE_CELL, 1, 0xA5), (GATE_TGT, 1, 0xA5)]))

        cases = []
        for idx, (name, args, rets, fixkw, asserts) in \
                enumerate(specs):
            rets = dict(rets)
            success = 0xDEADB001 + idx
            stub_addrs = sorted(STUBS)
            rettab = bytearray(4 * (max(STUBS.values()) + 1))
            for a, v in rets.items():
                if a == '_ret':
                    continue
                struct.pack_into('<I', rettab, 4 * STUBS[a],
                                 v & 0xFFFFFFFF)
            fix = base_fix(**fixkw) + [('.rettab', RETTAB,
                                         bytes(rettab))]
            stub_addrs = sorted(STUBS)
            # stub layout: 12-byte bodies, shared 22-byte sections for
            # the two 4-byte-apart pairs; assert no overlap
            special = {lo: hi for (lo, hi) in SPECIAL_PAIRS}
            for lo, hi in SPECIAL_PAIRS:
                assert STUBS.get(lo) and STUBS.get(hi)
            prev_end = None
            for a in stub_addrs:
                if a in special:
                    size = 16          # 8 entry bytes + 8 tail bytes
                elif a - 4 in special:
                    size = 0           # covered by the pair section
                else:
                    size = 10
                if size:
                    if prev_end is not None and a < prev_end:
                        raise AssertionError(
                            f'stub overlap at {hex(a)} < {hex(prev_end)}')
                    prev_end = a + size
            stub_sections = (
                f'  .probe {hex(PROBE_AT)} : {{ *(.probe) }}\n'
                f'  .common {hex(COMMON_AT)} : {{ *(.common) }}\n'
                f'  .rettab {hex(RETTAB)} : {{ *(.rettab) }}\n')
            for addr in stub_addrs:
                if addr in special:
                    stub_sections += (
                        f'  .spair_{addr:x} {hex(addr)} : '
                        f'{{ *(.spair_{addr:x}) }}\n')
                elif addr - 4 in special:
                    continue          # inside the pair section
                else:
                    stub_sections += (
                        f'  .stub_{addr:x} {hex(addr)} : '
                        f'{{ *(.stub_{addr:x}) }}\n')
            for sname, sbase, _ in fix:
                if sname == '.rettab':
                    continue
                stub_sections += \
                    f'  {sname} {hex(sbase)} : {{ *({sname}) }}\n'
            asm = (harness(ENTRY, list(args))
                   + ''.join(
                       (special_pair_section(lo, hi)
                        if lo in special else
                        (f'.section .stub_{a:x},"ax",@progbits\n'
                         ' .org 0\n' + stub_body(STUBS[a]))
                        if a - 4 not in special else '')
                       for a in stub_addrs
                       for lo, hi in [(a, special.get(a, a))])
                   + common_logger()
                   + probe(asserts, success, idx)
                   + fixture_sections(fix))
            case, sim_text = build_case(name, asm, ALL_WINS,
                                        stub_sections)
            assert case['exit_code'] == 11, (name, case)
            fault = case['fault']
            assert fault is not None \
                and fault['operation'] == 'read', (name, fault)
            addr = int(fault['address'], 16)
            assert addr == success, (name, fault, hex(success))
            assert PROBE_AT <= int(fault['pc'], 16) \
                < PROBE_AT + 0x2000, (name, fault)
            cases.append(dict(name=name, entry=hex(ENTRY),
                              success=hex(success),
                              exit_code=case['exit_code'],
                              instructions=case['instructions'],
                              fault=fault))
            print(f'PASS {name} -> {hex(success)}', flush=True)

        results['cpu_cases'] = cases
        results['stub_map'] = {hex(a): STUBS[a] for a in
                               sorted(STUBS)}
        results['status'] = 'PASS_ASLV_CLOSE_HANDLER_4405'
        print('PASS_ASLV_CLOSE_HANDLER_4405', stamp)
        print('Evidence:', out / 'verified_evidence.json')
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'verified_evidence.json').write_text(
            json.dumps(results, indent=2, default=str) + '\n')


if __name__ == '__main__':
    main()
