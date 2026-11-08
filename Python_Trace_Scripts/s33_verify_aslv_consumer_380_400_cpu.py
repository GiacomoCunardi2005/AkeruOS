#!/usr/bin/env python3
"""Nikon COOLPIX S33 - AutoSceneLiveView consumer handler 0x65B3A8 (it.48).

Closes the open point left by iteration 47 (report
S33_GUI_AutoSceneLiveView_Append_Writers_4110_4111_CPU_20261101.md,
prossimo passo (a)): the handler of events 0x380/0x400 (p3 records
0x783B58/0x783B68), the only direct bl caller of the 0x4111 writer
0x65CCC8 and the first DECREMENTER of the gate byte, was decoded only
statically and never executed. Question: does it really consume the
ring (read gate, read word[0x47BBB4+4*gate], decrement the gate when
the word == 0xA), does it really call the 0x4111 handler with
(node, 0, 0) when the queue is still non-empty after the purge, and
does it forward (node, 0x4111, arg) to the p1 wrapper in both cases?

Static decode (GNU ARC700, original bytes, block 2; window
0x65B3A8..0x65B5D4, internal pools 0x65B5BC..0x65B5D0, external
h100 pools 0x65B388/0x65B390 via ld.as [pcl,-97/-98]):

handler 0x65B3A8 @ entry (r0=node, r1=ev, r2=arg):
  push_s blink; bl 0x334124 (millicode push r17,r16,r15,r14,r13);
  st.aw fp,[sp,-4]; mov fp,sp;
  r14=node, r17=ev, r16=arg, r13=0;
  r0=4; bl 0x1707D8(4, ev, arg); bl 0xC9BF8 -> ==1 EXIT;
  bl 0xCAD30 (mode) -> ==0x7E EXIT; r0=1; bl 0xCF060(1);
  r0 = ctx (pool 0x65B5BC = 0x681F5C); r1 = [ctx+4] (state);
  state==8 -> [ctx+4]:=0 (r1:=0) and continue;
  state==0 -> continue; state==3 -> continue; OTHER -> EXIT
  (return value = ctx pointer);
  bl 0x135A84(ctx, state, arg); btst bit1 -> set EXIT (ret 2);
  r15=0; bl 0xC8BA0(0, ...) -> !=0 EXIT;
  if ev == 0x400 (cmp r17,1024; the other branch is
  ELSE, no explicit 0x380 compare): zoom gates 0x1493D8()==1,
    0x149474()==1, 0x14A1F8() > 0x64 (bls -> fail), 0xCD514()==1
    -> [ctx+0x20 (0x681F7C)] := 0 (byte), forward 0x65B71C(node,
    0x400, arg), common tail; gate fail -> 0x14948C()==0 ->
    0x65D008(node)/0x65CE88, r13 := 0x1493A4 (pool 0x65B5C4);
  else (ev 0x380): same gates but 0x14A1F8() >= 0x64 (blo -> fail:
    OPPOSITE polarity at the 0x64 boundary), then 0xCDACC():
    !=0 -> 0x65D008(node)/0x65CE88, then [ctx+0x20] := 1,
    forward 0x65B71C(node, 0x380, arg), common tail; ==0 ->
    common tail directly;
    zoom gate fail -> 0x149474()==0 -> 0x65D008/0x65CE88,
    r13 := 0x14938C (pool 0x65B5C8), then timer arm:
    0x14918C(node,0xC)==0 -> 0x14905C(node,0xC,400,400,0);
  common tail 0x65B4C2: r15 = 0x149028 (pool 0x65B5CC);
    149028(node,k) for k in {1,2,3,4,6} via jl_s [r15];
    0x65D1CC(node); 0x65D8B4(); 0x145920(); 0x145150(node);
    0x177484() queue check:
    ==0 (empty) -> r13!=0: DECD4(0)/DD094/149DF4(1), [ctx+4]:=4,
      jl_s [r13] (LINKED: returns to 0x65B566), then 0x14A1F8()
      > 0x64 -> exit, else 14905C(node,3,1000,1000,0) -> exit;
      r13==0: state {2,3} -> 149474()!=0 exit; [ctx+4]:=5;
      0x14A1F8() > 0x64 -> exit; mode 0xCAD30()==0x2C ->
      14905C(node,1,500,500,0) -> exit;
    !=0 (non-empty) -> purge 0x177460()/0x17743C()/0x177484():
      still !=0 -> bl 0x65CCC8 (REAL 0x4111 handler) with
      (node, 0, 0) -> it APPENDS 0xA to the ring, then
      20E814(node, 0x4111, arg) -> exit;
      ==0 (drained) -> CONSUME: r2 = [0x65B388] = 0x47BBB8;
      r1 = ldb [r2,0x10] (gate 0x47BBC8); gate==0 -> skip
      (ble_s, zero-extended byte); else r0 = [0x65B390] =
      0x47BBB4; r0 += 4*gate (add2_s); r0 = word[r0]; == 0xA ->
      gate := gate-1 (sub_s + stb_s, the ONLY decrementer found
      in the firmware); then 0x65D8B4(); 0x145150(node);
      20E814(node, 0x4111, arg) -> exit;
  exit: b 0x65B1B8 (mov sp,fp; ld.ab fp,[sp,4]; b 0x334184 ->
  millicode pop r17,r16,r15,r14,r13 + blink). The b at 0x65B5B8
  has displacement -1024 (small negative, safe per it.23/it.25);
  the epilogue b at 0x65B1C0 is 32-bit aligned with displacement
  -0x32703C (large negative, executed CORRECTLY by the pinned
  engine per it.36 -3298300 and it.47 trace precedents).

Internal pools (window freeze): 0x65B5BC = 0x681F5C (ctx),
0x65B5C0 = 0x681F7C (ctx+0x20), 0x65B5C4 = 0x1493A4,
0x65B5C8 = 0x14938C, 0x65B5CC = 0x149028, 0x65B5D0 = 0x4111
(the forwarded event id). External pools (loaded via .poolh
window): 0x65B388 = 0x47BBB8 (ring), 0x65B390 = 0x47BBB4
(guard table base).

CPU cases (16, original windows; entry r0=NODE, r1=ev, r2=ARG):
 0 exit_c9bf8          C9BF8 ret 1 -> immediate exit, ret 1
 1 exit_mode_7e        mode getter ret 0x7E -> exit, ret 0x7E
 2 exit_state7         state 7 (not 0/3/8) -> exit, ret ctx
                       pointer 0x681F5C, state unchanged
 3 bit1_exit           135A84 bit1 -> exit, ret 2
 4 c8ba0_exit          C8BA0 ret 1 -> exit, ret 1
 5 ev400_pass          state 3 passes the state gate untouched;
                       zoom gates ok -> [ctx+0x20]:=0,
                       65B71C(node,0x400,arg); queue empty;
                       state 3 -> 149474 ret 1 -> exit, state 3
 6 ev400_zoomfail      14A1F8 ret 0x64 fails bls (0x400 needs
                       > 0x64) -> 14948C==0 -> 65D008/65CE88,
                       r13=0x1493A4; queue empty -> state:=4,
                       jl_s [r13] RETURNS to 0x65B566 (14A1F8
                       2nd ret 0x64) -> 14905C(node,3,1000,
                       1000,0) -> exit; proves the linked
                       continuation
 7 ev380_zoom64_pass   14A1F8 ret 0x64 passes blo (0x380 needs
                       >= 0x64) -> CDACC==0 -> no forward, no
                       [ctx+0x20] write; queue empty; state 0 ->
                       state:=5; 14A1F8 2nd ret 0x64; mode 0x2C
                       -> 14905C(node,1,500,500,0) -> exit
 8 ev380_gatefail      1493D8 ret 0 -> 149474 ret 0 ->
                       65D008/65CE88, r13=0x14938C; timer arm
                       14918C(node,0xC)==0 -> 14905C(node,0xC,
                       400,400,0); queue empty -> state:=4,
                       jl_s [r13] -> 14A1F8 ret 0x65 -> exit
                       (ret 0x65)
 9 consume_decrement   queue: 177484=1 -> purge -> 177484=0
                       (drained) -> consume: gate=2, word[ring
                       slot 1]=0xA -> gate 2->1; 65D8B4/145150
                       then 20E814(node,0x4111,arg); ring words
                       NOT cleared; 65DAD0/14941C never called
10 consume_gate0      gate=0 -> ble_s skips the read/decrement;
                       gate stays 0
11 consume_noA        gate=3, word (ring slot 2) = 9 -> no
                       decrement, gate stays 3
12 consume_gate_ff    gate=0xFF, word at 0x47BBB4+4*0xFF =
                       0x47BFB0 = 0xA -> gate 0xFF->0xFE (far
                       read inside the fixture)
13 append_real_4111   purge leaves the queue non-empty -> the
                       handler calls the REAL 0x65CCC8 (window
                       .h41, original bytes) with (node,0,0):
                       its gates pass, ring[0]=5 != 0xA -> it
                       APPENDS 0xA at ring slot 1, gate 1->2,
                       ctx writes (+0x10=0, +0x14=ring, +0xD=1),
                       its tail forwards the INCOMING (ev,arg) =
                       (0,0) (mov_s r1,r13 / mov_s r2,r15 at
                       0x65CD3C/0x65CD3E): 20E814(node,0,0) and
                       14941C/177460 with r1=0,r2=0 (NEW FINDING:
                       the 0x4111 handler re-notifies the event it
                       was CALLED with, not its own id; it.47 could
                       not distinguish because it always entered
                       with ev=0x4111), then back in 0x65B3A8:
                       20E814(node,0x4111,arg) with arg
                       PRESERVED (r16 survives the real callee,
                       which never touches r16/r17 - statically
                       verified on the window)
14 append_real_guard  same but ring[0]=0xA -> the REAL 0x4111
                       handler's guard blocks the append: gate
                       stays 1, ring slot 1 sentinel intact, the
                       tails still run (65DAD0(0xA,...), ctx
                       writes, 20E814/14941C/177460), then the
                       consumer's own 20E814(node,0x4111,arg)
16 state8_clear_consume state 8 -> [ctx+4]:=0 and the flow
                       CONTINUES (only [ctx+4] write left
                       uncovered); ev 0x380 CDACC!=0 ->
                       65D008/65CE88, [ctx+0x20]:=1, forward
                       65B71C(node,0x380,arg); purge drains ->
                       consume gate=1 ring[0]=9 (no decrement);
                       final [ctx+4]=0 PERSISTS (no rewrite)

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
RETCELL = 0x367700
SCNT = 0x369000              # per-sid call counters (fixture zeroed)
RETSEQ = 0x369800            # 8 return values per sid (fixture)
NSEQ = 8

CTX = 0x681F5C               # AutoSceneLiveView context (pool 0x65B5BC)
CTX20 = 0x681F7C             # ctx+0x20 byte (pool 0x65B5C0)
RING = 0x47BBB8              # ring base (pool 0x65B388 via ld.as)
TBL_BASE = 0x47BBB4          # guard table base (pool 0x65B390)
GATE_BYTE = 0x47BBC8         # RING+0x10
RING_FIX = 0x47BBB0          # fixture base (covers 0x47BBB0..0x47C070)
FF_WORD = 0x47BFB0           # word read at gate=0xFF (TBL+4*0xFF)

H380 = 0x65B3A8              # handler events 0x380/0x400
E4111 = 0x65CCC8             # handler event 0x4111 (real, .h41 window)
EPI = 0x65B1B8               # shared epilogue of H380

NODE = 0x1234
EV380 = 0x380
EV400 = 0x400
ARG = 0x7B
SENT = 0xA5A5A5A5
VALA = 0xA

# original windows (payload, lo, hi, section)
W_H380 = (2, 0x65B3A8, 0x65B5D4, '.h380')
W_POOLH = (2, 0x65B388, 0x65B398, '.poolh')
W_EPI = (2, 0x65B1B8, 0x65B1C4, '.epi')
W_MILI = (0, 0x334100, 0x3341E4, '.mili')
W_H41 = (2, 0x65CC18, 0x65CD54, '.h41')
W_EPI9 = (2, 0x659588, 0x659594, '.epi9')
WINS_MAIN = [W_H380, W_POOLH, W_EPI, W_MILI, W_H41, W_EPI9]

H380_HEX = (
    'f1c07e0d4e6cfc1cc8b60a23003708763a711a7200dd04d81a0c8d8a36084d37'
    '81e0f00101006609cd37fee0e401010001d88a0ccd3978d0218088e103f4a971'
    'a1a080e104f283e1c8010200920e0d6de1b8c001020000dfe970a20f8d3680e0'
    'd8f48c2110a025f4ca0fcd7681e016f45e080d7781e012f4da0d4d77e4e0cef7'
    'ee080d3981e00af464d0e0a8c9702a710a72e60a000043f04e080d7780e03ff4'
    'c970c20bc0003e0ac0005dd537f0860fcd7681e01af41a080d7781e016f4960d'
    '4d77e4e092f7aa080d3981e00ef45a0e0d3980e023f2c9708a0bc000060ac000'
    '4ed001d920a8d4f1e60fcd7680e008f4c970720bc000ee09c0004ad5c9700cd9'
    'e60ccd7680e00bf4c9700cd98a22060448734a240000a20bcd7643d7c97001d9'
    '407fc97002d9407fc97003d9407fc97004d9407fc97006d9407fc970ea0cc000'
    'ce0b0001360c0d75c970620ccd74920fcd8d80e027f2660fcd8d3e0fcd8d820f'
    'cd8d80e014f49f1702f6308a80e1caf69e1700f6357800808ae004f461b930aa'
    '8e0b0001c970260ccd7407f0c97000d900da920f8000c97024d10a72d20a8dd9'
    '38f080e518f200d8860f8d41420bcd4001d89e084d7718d004d921a0407d960c'
    '4d77e4e04c000d00c97003d98a220f0a48731cf010d0018083e004f282e006f4'
    'ee0ecd7680e016f40bd005d921a0660c4d77e4e00ef7960f8d37ace00af4c970'
    '01d98a22070d48734a240000aa0acd760104cfff5c1f68007c1f6800a4931400'
    '8c9314002890140011410000')
POOLH_HEX = 'b8bb4700601f6800b4bb47005c1f6800'
EPI_HEX = '0a24c03604141b34c5074e6c'
MILI_HEX = (
    'fc1c88b6fc1c48b6fc1c08b6fc1cc8b5fc1c88b5fc1c48b5fc1c08b5fc1cc8b4'
    'fc1c88b4fc1c48b4fc1c08b4fc1cc8b3fc1c88b3fc1c48b3e07ee07804dc38dd'
    '35f0e07804dc34dd33f0e07804dc30dd31f0e07804dc2cdd2ff0e07804dc28dd'
    '2df0e07804dc24dd2bf0e07804dc20dd29f0e07804dc1cdd27f0e07804dc18dd'
    '25f0e07804dc14dd23f0e07804dc10dd21f0e07804dc0cdd1ff0e07804dc08dd'
    '1cf0e07804dc04dd19f034141a30301419302c14183028141730241416302014'
    '15301c1414301814133014141230101411300c14103002c701c6b0244d33b024'
    '1f33e07e')
H41_HEX = (
    '3a0d0d749d050fff81310000b8bb4700b4bb47005c1f6800ec69360044264400'
    '881300007f300000f1c0ee0c8e6bfc1cc8b60a230037087528764877320e4d6c'
    'e1b830f406d872fc00d876080d41320c0d4001d88a098d76b41701f009da10898'
    '0e00af280e0cdf6a81703f0157b60838ae307f21521030040a301e010a93e0e40'
    '00a970b60c0d7409d8920b0d8d00d876088d74801702f004a201d825a20daa00d'
    '8c971e9725a0bcdd8c9004ffee078f1c0660c8e6bfc1cc8b60a23003708762875'
    '4877aa0d4d6ce1b832f406d850fc00d8ee0fcd40aa0b0d4001d802098d762c170'
    '1f0508980e209f280e2cdf6241700f0557800808ae007f20adb1521800060a001'
    'e250a9b60d4000c9702e0c0d7400d8f60f4d74001702f004a201d825a20daac97'
    '0a971e972d60acdd8da0e0d7680e004f4160f0d8d39004ffe')
EPI9_HEX = '0a24c03604141b3405044e6d'

# stub ids
(S1707D8, SC9BF8, SCAD30, SCF060, S135A84, SC8BA0) = range(1, 7)
(S1493D8, S149474, S14A1F8, SCD514, SCDACC, S14948C) = range(7, 13)
(S65D008, S65CE88, S14918C, S14905C, S149028, S65D1CC) = range(13, 19)
(S65D8B4, S145920, S145150, S177484, S177460, S17743C) = range(19, 25)
(S20E814, SDECD4, SDD094, S149DF4, S1493A4, S14938C) = range(25, 31)
(S65B71C, S65BE24, S65DAD0, S145D1C, S14941C) = range(31, 36)

STUBS = {
    0x1707D8: S1707D8, 0xC9BF8: SC9BF8, 0xCAD30: SCAD30,
    0xCF060: SCF060, 0x135A84: S135A84, 0xC8BA0: SC8BA0,
    0x1493D8: S1493D8, 0x149474: S149474, 0x14A1F8: S14A1F8,
    0xCD514: SCD514, 0xCDACC: SCDACC, 0x14948C: S14948C,
    0x65D008: S65D008, 0x65CE88: S65CE88, 0x14918C: S14918C,
    0x14905C: S14905C, 0x149028: S149028, 0x65D1CC: S65D1CC,
    0x65D8B4: S65D8B4, 0x145920: S145920, 0x145150: S145150,
    0x177484: S177484, 0x177460: S177460, 0x17743C: S17743C,
    0x20E814: S20E814, 0xDECD4: SDECD4, 0xDD094: SDD094,
    0x149DF4: S149DF4, 0x1493A4: S1493A4, 0x14938C: S14938C,
    0x65B71C: S65B71C, 0x65BE24: S65BE24, 0x65DAD0: S65DAD0,
    0x145D1C: S145D1C, 0x14941C: S14941C,
}
MAXSID = max(STUBS.values())


def harness(calls):
    """calls = [(entry, [r0, r1, r2]), ...]; return value in RETCELL."""
    text = ('.section .text,"ax",@progbits\n.global _start\n_start:\n'
            f' mov sp,{hex(STACK)}\n')
    for i, (entry, args) in enumerate(calls):
        cell = RETCELL
        text += (''.join(f' mov r{k},{hex(v)}\n' for k, v in enumerate(args))
                 + f' mov r12,{hex(entry)}\n'
                 ' jl_s [r12]\n'
                 f' mov r12,{hex(cell)}\n'
                 ' st r0,[r12,0]\n')
    text += (f' mov r12,{hex(PROBE_AT)}\n'
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
        marker = 0xDEAD0000 + case_idx * 0x80 + k
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
            f' mov r3,{hex(SCNT)}\n'
            ' asl r4,r12,2\n'
            ' add r3,r3,r4\n'
            ' ld r5,[r3,0]\n'
            f' mov r3,{hex(RETSEQ)}\n'
            ' asl r4,r12,5\n'
            ' add r3,r3,r4\n'
            ' asl r4,r5,2\n'
            ' add r3,r3,r4\n'
            ' ld r0,[r3,0]\n'
            f' mov r3,{hex(SCNT)}\n'
            ' asl r4,r12,2\n'
            ' add r3,r3,r4\n'
            ' ld r5,[r3,0]\n'
            ' add r5,r5,1\n'
            ' st r5,[r3,0]\n'
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


def ctx_fixture(state):
    buf = bytearray(b'\xA5' * 0xD0)
    struct.pack_into('<I', buf, 4, state)
    return bytes(buf)


def ring_fixture(gate, slots, ffword=None):
    """0x4C0 bytes at 0x47BBB0. slots: {abs_addr: word}."""
    buf = bytearray(b'\xA5' * 0x4C0)
    buf[GATE_BYTE - RING_FIX] = gate & 0xFF
    for addr, w in slots.items():
        struct.pack_into('<I', buf, addr - RING_FIX, w)
    if ffword is not None:
        struct.pack_into('<I', buf, FF_WORD - RING_FIX, ffword)
    return bytes(buf)


def base_fix(state, gate, slots, ffword, retseq):
    return [('.ctxfix', CTX, ctx_fixture(state)),
            ('.ringfix', RING_FIX, ring_fixture(gate, slots, ffword)),
            ('.logfix', CNT, bytes(0x800)),
            ('.scntfix', SCNT, bytes(4 * (MAXSID + 1))),
            ('.retseq', RETSEQ, bytes(retseq))]


def ring_asserts(gate, ring0=SENT, ring1=SENT, ring2=SENT, ring3=SENT):
    return [(GATE_BYTE, 1, gate),
            (0x47BBB0, 4, SENT),
            (TBL_BASE, 4, SENT),      # slot -1: never written
            (0x47BBB8, 4, ring0),
            (0x47BBBC, 4, ring1),
            (0x47BBC0, 4, ring2),
            (0x47BBC4, 4, ring3)]


def ctx_asserts(state, ctx20, w4111=False, ret145d=0):
    out = [(CTX + 4, 4, state),
           (CTX + 0x20, 1, ctx20)]
    if w4111:
        out += [(CTX + 0xC, 1, 0xA5),    # never touched by 0x4111 writer
                (CTX + 0xD, 1, 1),
                (CTX + 0x10, 4, ret145d),
                (CTX + 0x14, 4, RING)]
    else:
        out += [(CTX + 0xC, 1, 0xA5),
                (CTX + 0xD, 1, 0xA5),
                (CTX + 0x10, 4, SENT),
                (CTX + 0x14, 4, SENT)]
    return out


def spec(name, ev, rets, logs, mem, state, gate, slots, ffword=None,
         ctx20=0xA5, w4111=False, ret145d=0):
    seq = {sid: ([v] * NSEQ if not isinstance(v, list) else v)
           for sid, v in rets.items()}
    retseq = bytearray(NSEQ * 4 * (MAXSID + 1))
    for sid in range(MAXSID + 1):
        vals = seq.get(sid, [0] * NSEQ)
        assert len(vals) <= NSEQ
        for k, v in enumerate(vals):
            struct.pack_into('<I', retseq, NSEQ * 4 * sid + 4 * k,
                             v & 0xFFFFFFFF)
    fix = base_fix(state, gate, slots, ffword, bytes(retseq))
    asserts = []
    for i, (sid, a0, a1, a2) in enumerate(logs):
        asserts += L(i, sid, a0, a1, a2)
    n = len(logs)
    asserts += [(CNT, 4, n)]
    asserts += L(n, 0, None, None, None)   # no extra calls
    asserts += [(RETCELL, 4, mem['ret'])]
    asserts += ring_asserts(mem['gate'], mem.get('ring0', SENT),
                            mem.get('ring1', SENT),
                            mem.get('ring2', SENT),
                            mem.get('ring3', SENT))
    if ffword is not None:
        asserts += [(FF_WORD, 4, ffword)]
    asserts += ctx_asserts(mem['state'], mem.get('ctx20', 0xA5),
                           w4111, ret145d)
    return dict(name=name, calls=[(H380, [NODE, ev, ARG])],
                stubs=list(STUBS), fix=fix, asserts=asserts)


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'aslv_consumer_380_400_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, _ = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp,
                   action='aslv-consumer-380-400-cpu',
                   limits=['Static analysis + 16 synthetic CPU cases; '
                           'no hardware',
                           'Deep callees are stubs; originals executed: '
                           'the whole handler body 0x65B3A8, millicode '
                           'push/pop 0x334124/0x334184, shared epilogue '
                           '0x65B1B8, and in cases 13/14 the whole REAL '
                           '0x4111 handler 0x65CCC8 (window .h41) with '
                           'its own epilogue 0x659588 and millicode '
                           '0x33412C/0x334194',
                           'ctx 0x681F5C, ring 0x47BBB0..0x47C070 and '
                           'gate byte 0x47BBC8 are RUNTIME cells in the '
                           'load gap 0x428600..0x5FE800: '
                           'fixture-imposed, NOT verifiable from the '
                           'dump',
                           'The returns of the stubbed callees are '
                           'imposed by the bench; the jl_s [r13] '
                           'continuation at 0x65B566 assumes the '
                           'callee (0x1493A4/0x14938C) RETURNS - the '
                           'real behaviour of those functions is not '
                           'proven here',
                           'No physical button map, no hardware, no '
                           'scheduling; V1.1 dump only; NON_INSTALLARE'])
    try:
        p0, p2, p3 = payloads[0], payloads[2], payloads[3]

        # --- 1. static: pools --------------------------------------
        pools = {0x65B5BC: CTX, 0x65B5C0: CTX20, 0x65B5C4: 0x1493A4,
                 0x65B5C8: 0x14938C, 0x65B5CC: 0x149028,
                 0x65B5D0: 0x4111, 0x65B388: RING, 0x65B38C: 0x681F60,
                 0x65B390: TBL_BASE, 0x65B394: CTX}
        for a, v in pools.items():
            got = struct.unpack_from('<I', p2, a - base[2])[0]
            assert got == v, (hex(a), hex(got), hex(v))
        results['pools'] = {hex(a): hex(v) for a, v in pools.items()}

        # --- 2. static: event registry -----------------------------
        reg = [(0x783B58, EV380), (0x783B5C, H380),
               (0x783B68, EV400), (0x783B6C, H380),
               (0x783C10, 0x4110), (0x783C14, 0x65CC40),
               (0x783C18, 0x4111), (0x783C1C, E4111),
               (0x783C40, 0), (0x783C44, 0x20E814)]
        for a, v in reg:
            got = struct.unpack_from('<I', p3, a - base[3])[0]
            assert got == v, (hex(a), hex(got), hex(v))
        results['registry'] = ('p3 pairs (event,handler): 0x380/0x400 -> '
                              '0x65B3A8 (consumer), 0x4110 -> 0x65CC40, '
                              '0x4111 -> 0x65CCC8, terminator '
                              '(0,0x20E814)')

        # --- 3. static: opcode freezes ------------------------------
        freezes = [('h380', 2, 0x65B3A8, H380_HEX),
                   ('poolh', 2, 0x65B388, POOLH_HEX),
                   ('epi', 2, 0x65B1B8, EPI_HEX),
                   ('millicode_win', 0, 0x334100, MILI_HEX),
                   ('h41_win', 2, 0x65CC18, H41_HEX),
                   ('epi9', 2, 0x659588, EPI9_HEX)]
        for name, idx, addr, hexstr in freezes:
            data = payloads[idx][addr - base[idx]:
                                addr - base[idx] + len(hexstr) // 2]
            assert data.hex() == hexstr, (name, data.hex())
        results['opcode_freezes'] = 'ok'

        # --- 4. static: add2 + ld.as semantics ----------------------
        sem = (LEGACY / 'source/gnu-arc700-sim-src/sim/arc/sem7.c')
        text = sem.read_text()
        i = text.index('SEM_FN_NAME (arc700f,add2_L_r_r__RA__RC)')
        body = text[i:i + 2000]
        assert 'SLLSI (GET_H_CR (FLD (f_op_C)), 2)' in body
        results['add2_engine_semantics'] = dict(
            source=str(sem),
            sha256=hashlib.sha256(text.encode()).hexdigest(),
            rule='add2 rA,rB,rC = rB + (rC << 2)',
            site='sem7.c add2_L_r_r__RA__RC (ld.as EA rule: '
                 '(PC&~3)+imm*4, it.37 lesson)')

        # --- 5. static: LE + bl census -----------------------------
        le_cons = le_scan(payloads, base, H380)
        assert le_cons == [(3, 0x783B5C, 0), (3, 0x783B6C, 0)], le_cons
        results['le_census'] = {
            hex(H380): [(f'p{p}', hex(a), o) for p, a, o in le_cons]}

        objcopy = ROOT / 'work/build-arc/binutils/objcopy'
        objdump = ROOT / 'work/build-arc/binutils/objdump'
        assert objcopy.is_file() and objdump.is_file()
        census = {H380: [], E4111: []}
        with tempfile.TemporaryDirectory(prefix='it48-census-') as td:
            for b in blocks:
                elf = Path(td) / f'b{b["index"]}.elf'
                subprocess.run([str(objcopy), '-I', 'binary',
                                '-O', 'elf32-littlearc', '-B', 'arc',
                                '--rename-section',
                                '.data=.text,alloc,load,readonly,'
                                'code,contents',
                                '--change-section-vma',
                                f".data={b['load_address_candidate']:#x}",
                                '--strip-all',
                                str(ROOT / 'S33-sections/TBM_blocks'
                                    / b['file']), str(elf)],
                               check=True, timeout=120)
                text = subprocess.run(
                    [str(objdump), '-d', '-m', 'arc:ARC700',
                     '-EL', str(elf)], capture_output=True, text=True,
                    check=True, timeout=280).stdout
                for line in text.splitlines():
                    for tgt in (H380, E4111):
                        if f';0x{tgt:x}' in line:
                            parts = [p for p in line.split('\t') if p]
                            addr = int(parts[0].strip().rstrip(':'), 16)
                            mn = (parts[2].strip()
                                  if len(parts) > 2 else '')
                            assert mn.startswith('bl'), (line, mn)
                            census[tgt].append((b['index'], addr))
        assert census[H380] == [], census[H380]
        assert census[E4111] == [(2, 0x65B53A)], census[E4111]
        results['bl_census'] = {
            hex(H380): [],
            hex(E4111): [(f'b{i}', hex(a)) for i, a in census[E4111]]}

        # window inventory + sha256
        wins = {}
        for (pidx, lo, hi, sec) in WINS_MAIN:
            data = payloads[pidx][lo - base[pidx]:hi - base[pidx]]
            wins[sec] = dict(payload=pidx, lo=hex(lo), hi=hex(hi),
                             size=len(data),
                             sha256=hashlib.sha256(data).hexdigest())
        results['windows'] = wins

        # --- 6. CPU cases ------------------------------------------
        r = Runner(SimpleNamespace(legacy_root=LEGACY,
                                   toolchain=TOOLCHAIN,
                                   output=out,
                                   action='aslv-consumer-380-400-cpu'))
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

        # --- log helpers -------------------------------------------
        # (explicit per-case logs below; entry gates derived statically:
        #  135A84 receives (CTX, state, ARG) - r0 is the ctx pointer
        #  loaded at 0x65B3DE, r1 the state word, never reloaded)

        SPECS = []

        # 0 exit at C9BF8()==1
        SPECS.append(spec(
            'exit_c9bf8', EV380,
            {SC9BF8: 1},
            [(S1707D8, 4, EV380, ARG), (SC9BF8, 0, EV380, ARG)],
            dict(ret=1, gate=1, state=0),
            state=0, gate=1, slots={}))

        # 1 exit at mode 0x7E
        SPECS.append(spec(
            'exit_mode_7e', EV380,
            {SCAD30: 0x7E},
            [(S1707D8, 4, EV380, ARG), (SC9BF8, 0, EV380, ARG),
             (SCAD30, 0, EV380, ARG)],
            dict(ret=0x7E, gate=1, state=0),
            state=0, gate=1, slots={}))

        # 2 exit at state 7 (not 0/3/8): ret = ctx pointer
        SPECS.append(spec(
            'exit_state7', EV380,
            {},
            [(S1707D8, 4, EV380, ARG), (SC9BF8, 0, EV380, ARG),
             (SCAD30, 0, EV380, ARG), (SCF060, 1, EV380, ARG)],
            dict(ret=CTX, gate=1, state=7),
            state=7, gate=1, slots={}))

        # 3 exit at 135A84 bit1
        SPECS.append(spec(
            'bit1_exit', EV380,
            {S135A84: 2},
            [(S1707D8, 4, EV380, ARG), (SC9BF8, 0, EV380, ARG),
             (SCAD30, 0, EV380, ARG), (SCF060, 1, EV380, ARG),
             (S135A84, CTX, 0, ARG)],
            dict(ret=2, gate=1, state=0),
            state=0, gate=1, slots={}))

        # 4 exit at C8BA0()!=0
        SPECS.append(spec(
            'c8ba0_exit', EV380,
            {SC8BA0: 1},
            [(S1707D8, 4, EV380, ARG), (SC9BF8, 0, EV380, ARG),
             (SCAD30, 0, EV380, ARG), (SCF060, 1, EV380, ARG),
             (S135A84, CTX, 0, ARG), (SC8BA0, 0, 0, ARG)],
            dict(ret=1, gate=1, state=0),
            state=0, gate=1, slots={}))

        # 5 ev 0x400 full pass, state 3 untouched, ctx20 := 0
        SPECS.append(spec(
            'ev400_pass', EV400,
            {S1493D8: 1, S149474: [1, 1], S14A1F8: 0x65, SCD514: 1},
            [(S1707D8, 4, EV400, ARG), (SC9BF8, 0, EV400, ARG),
             (SCAD30, 0, EV400, ARG), (SCF060, 1, EV400, ARG),
             (S135A84, CTX, 3, ARG), (SC8BA0, 0, 3, ARG),
             (S1493D8, 0, 3, ARG), (S149474, 1, 3, ARG),
             (S14A1F8, 1, 3, ARG), (SCD514, 0x65, 3, ARG),
             (S65B71C, NODE, EV400, ARG),
             (S149028, NODE, 1, ARG), (S149028, NODE, 2, ARG),
             (S149028, NODE, 3, ARG), (S149028, NODE, 4, ARG),
             (S149028, NODE, 6, ARG),
             (S65D1CC, NODE, 6, ARG), (S65D8B4, 0, 6, ARG),
             (S145920, 0, 6, ARG), (S145150, NODE, 6, ARG),
             (S177484, 0, 6, ARG),
             (S149474, 3, 6, ARG)],
            dict(ret=1, gate=1, state=3, ctx20=0),
            state=3, gate=1, slots={}))

        # 6 ev 0x400 zoom fail (0x64 bls) -> r13=0x1493A4 -> state 4,
        #   jl_s [r13] RETURNS -> 2nd 14A1F8 = 0x64 -> timer(node,3,1000)
        SPECS.append(spec(
            'ev400_zoomfail_r13_timer', EV400,
            {S1493D8: 1, S149474: 1, S14A1F8: [0x64, 0x64],
             S14948C: 0, S149DF4: 1, S1493A4: 0x77},
            [(S1707D8, 4, EV400, ARG), (SC9BF8, 0, EV400, ARG),
             (SCAD30, 0, EV400, ARG), (SCF060, 1, EV400, ARG),
             (S135A84, CTX, 0, ARG), (SC8BA0, 0, 0, ARG),
             (S1493D8, 0, 0, ARG), (S149474, 1, 0, ARG),
             (S14A1F8, 1, 0, ARG), (S14948C, 0x64, 0, ARG),
             (S65D008, NODE, 0, ARG), (S65CE88, 0, 0, ARG),
             (S149028, NODE, 1, ARG), (S149028, NODE, 2, ARG),
             (S149028, NODE, 3, ARG), (S149028, NODE, 4, ARG),
             (S149028, NODE, 6, ARG),
             (S65D1CC, NODE, 6, ARG), (S65D8B4, 0, 6, ARG),
             (S145920, 0, 6, ARG), (S145150, NODE, 6, ARG),
             (S177484, 0, 6, ARG),
             (SDECD4, 0, 6, ARG), (SDD094, 0, 6, ARG),
             (S149DF4, 1, 6, ARG), (S1493A4, CTX, 4, ARG),
             (S14A1F8, 0x77, 4, ARG),
             (S14905C, NODE, 3, 1000)],
            dict(ret=0, gate=1, state=4, ctx20=0xA5),
            state=0, gate=1, slots={}))

        # 7 ev 0x380 zoom 0x64 passes blo -> CDACC==0 -> common tail;
        #   state 0 -> 5; mode 0x2C -> timer(node,1,500)
        SPECS.append(spec(
            'ev380_zoom64_pass_state5', EV380,
            {S1493D8: 1, S149474: 1, S14A1F8: [0x64, 0x64],
             SCD514: 1, SCDACC: 0, SCAD30: [0, 0x2C]},
            [(S1707D8, 4, EV380, ARG), (SC9BF8, 0, EV380, ARG),
             (SCAD30, 0, EV380, ARG), (SCF060, 1, EV380, ARG),
             (S135A84, CTX, 0, ARG), (SC8BA0, 0, 0, ARG),
             (S1493D8, 0, 0, ARG), (S149474, 1, 0, ARG),
             (S14A1F8, 1, 0, ARG), (SCD514, 0x64, 0, ARG),
             (SCDACC, 1, 0, ARG),
             (S149028, NODE, 1, ARG), (S149028, NODE, 2, ARG),
             (S149028, NODE, 3, ARG), (S149028, NODE, 4, ARG),
             (S149028, NODE, 6, ARG),
             (S65D1CC, NODE, 6, ARG), (S65D8B4, 0, 6, ARG),
             (S145920, 0, 6, ARG), (S145150, NODE, 6, ARG),
             (S177484, 0, 6, ARG),
             (S14A1F8, CTX, 5, ARG), (SCAD30, 0x64, 5, ARG),
             (S14905C, NODE, 1, 500)],
            dict(ret=0, gate=1, state=5, ctx20=0xA5),
            state=0, gate=1, slots={}))

        # 8 ev 0x380 zoom gate fail -> r13=0x14938C + timer(node,0xC,
        #   400) -> state 4 -> jl_s [r13] -> 2nd 14A1F8 = 0x65 -> exit
        SPECS.append(spec(
            'ev380_gatefail_r13', EV380,
            {S1493D8: 0, S149474: 0, S14A1F8: 0x65,
             S14918C: 0, S149DF4: 1, S14938C: 0x88},
            [(S1707D8, 4, EV380, ARG), (SC9BF8, 0, EV380, ARG),
             (SCAD30, 0, EV380, ARG), (SCF060, 1, EV380, ARG),
             (S135A84, CTX, 0, ARG), (SC8BA0, 0, 0, ARG),
             (S1493D8, 0, 0, ARG), (S149474, 0, 0, ARG),
             (S65D008, NODE, 0, ARG), (S65CE88, 0, 0, ARG),
             (S14918C, NODE, 0xC, ARG), (S14905C, NODE, 0xC, 400),
             (S149028, NODE, 1, 400), (S149028, NODE, 2, 400),
             (S149028, NODE, 3, 400), (S149028, NODE, 4, 400),
             (S149028, NODE, 6, 400),
             (S65D1CC, NODE, 6, 400), (S65D8B4, 0, 6, 400),
             (S145920, 0, 6, 400), (S145150, NODE, 6, 400),
             (S177484, 0, 6, 400),
             (SDECD4, 0, 6, 400), (SDD094, 0, 6, 400),
             (S149DF4, 1, 6, 400), (S14938C, CTX, 4, 400),
             (S14A1F8, 0x88, 4, 400)],
            dict(ret=0x65, gate=1, state=4, ctx20=0xA5),
            state=0, gate=1, slots={}))

        # shared head for the queue cases (ev 0x380, CDACC==0 path)
        def QHEAD():
            return [(S1707D8, 4, EV380, ARG), (SC9BF8, 0, EV380, ARG),
                    (SCAD30, 0, EV380, ARG), (SCF060, 1, EV380, ARG),
                    (S135A84, CTX, 0, ARG), (SC8BA0, 0, 0, ARG),
                    (S1493D8, 0, 0, ARG), (S149474, 1, 0, ARG),
                    (S14A1F8, 1, 0, ARG), (SCD514, 0x64, 0, ARG),
                    (SCDACC, 1, 0, ARG),
                    (S149028, NODE, 1, ARG), (S149028, NODE, 2, ARG),
                    (S149028, NODE, 3, ARG), (S149028, NODE, 4, ARG),
                    (S149028, NODE, 6, ARG),
                    (S65D1CC, NODE, 6, ARG), (S65D8B4, 0, 6, ARG),
                    (S145920, 0, 6, ARG), (S145150, NODE, 6, ARG)]

        def QTAIL():
            return [(S177484, 0, 6, ARG), (S177460, 1, 6, ARG),
                    (S17743C, 0, 6, ARG), (S177484, 0, 6, ARG)]

        # 9 consume with decrement: gate 2, ring slot1 = 0xA -> gate 1
        SPECS.append(spec(
            'consume_decrement', EV380,
            {S1493D8: 1, S149474: 1, S14A1F8: 0x64, SCD514: 1,
             SCDACC: 0, S177484: [1, 0], S65D8B4: [0, 0],
             S145150: [0, 0], S20E814: 0},
            QHEAD() + QTAIL() + [(S65D8B4, VALA, 1, RING),
                                 (S145150, NODE, 1, RING),
                                 (S20E814, NODE, 0x4111, ARG)],
            dict(ret=0, gate=1, state=0, ring0=SENT, ring1=VALA,
                 ctx20=0xA5),
            state=0, gate=2, slots={0x47BBBC: VALA}))

        # 10 consume at gate 0: ble_s skips, no decrement
        SPECS.append(spec(
            'consume_gate0', EV380,
            {S1493D8: 1, S149474: 1, S14A1F8: 0x64, SCD514: 1,
             SCDACC: 0, S177484: [1, 0], S65D8B4: [0, 0],
             S145150: [0, 0], S20E814: 0},
            QHEAD() + QTAIL() + [(S65D8B4, 0, 0, RING),
                                 (S145150, NODE, 0, RING),
                                 (S20E814, NODE, 0x4111, ARG)],
            dict(ret=0, gate=0, state=0, ctx20=0xA5),
            state=0, gate=0, slots={}))

        # 11 consume, last word 9 != 0xA: no decrement, gate stays 3
        SPECS.append(spec(
            'consume_noA', EV380,
            {S1493D8: 1, S149474: 1, S14A1F8: 0x64, SCD514: 1,
             SCDACC: 0, S177484: [1, 0], S65D8B4: [0, 0],
             S145150: [0, 0], S20E814: 0},
            QHEAD() + QTAIL() + [(S65D8B4, 9, 3, RING),
                                 (S145150, NODE, 3, RING),
                                 (S20E814, NODE, 0x4111, ARG)],
            dict(ret=0, gate=3, state=0, ring2=9, ctx20=0xA5),
            state=0, gate=3, slots={0x47BBC0: 9}))

        # 12 consume at gate 0xFF: far word 0xA -> gate 0xFE
        SPECS.append(spec(
            'consume_gate_ff', EV380,
            {S1493D8: 1, S149474: 1, S14A1F8: 0x64, SCD514: 1,
             SCDACC: 0, S177484: [1, 0], S65D8B4: [0, 0],
             S145150: [0, 0], S20E814: 0},
            QHEAD() + QTAIL() + [(S65D8B4, VALA, 0xFE, RING),
                                 (S145150, NODE, 0xFE, RING),
                                 (S20E814, NODE, 0x4111, ARG)],
            dict(ret=0, gate=0xFE, state=0, ctx20=0xA5),
            state=0, gate=0xFF, slots={}, ffword=VALA))

        # 13 append: purge leaves the queue non-empty -> REAL 0x65CCC8
        SPECS.append(spec(
            'append_real_4111', EV380,
            {S1493D8: 1, S149474: 1, S14A1F8: 0x64, SCD514: 1,
             SCDACC: 0, S177484: [1, 1], S177460: [0, 0],
             S145150: [0, 0], S135A84: [0, 0], S20E814: [0, 0],
             S145D1C: 0, S14941C: 0},
            QHEAD() + QTAIL() +
            [(S135A84, NODE, 0, 0), (S65BE24, 6, 0, 0),
             (SDECD4, 0, 0, 0), (SDD094, 0, 0, 0),
             (S149DF4, 1, 0, 0),
             (S65DAD0, 0x47BBBC, RING, 2),
             (S145150, NODE, RING, 2),
             (S145D1C, 0, RING, 2),
             (S20E814, NODE, 0, 0),
             (S14941C, 0, 0, 0),
             (S177460, 0, 0, 0),
             (S20E814, NODE, 0x4111, ARG)],
            dict(ret=0, gate=2, state=0, ring0=5, ring1=VALA,
                 ctx20=0xA5),
            state=0, gate=1, slots={0x47BBB8: 5}, w4111=True,
            ret145d=0))

        # 14 append blocked by the REAL 0x4111 guard (ring[0]=0xA)
        SPECS.append(spec(
            'append_real_guard', EV380,
            {S1493D8: 1, S149474: 1, S14A1F8: 0x64, SCD514: 1,
             SCDACC: 0, S177484: [1, 1], S177460: [0, 0],
             S145150: [0, 0], S135A84: [0, 0], S20E814: [0, 0],
             S145D1C: 0, S14941C: 0},
            QHEAD() + QTAIL() +
            [(S135A84, NODE, 0, 0), (S65BE24, 6, 0, 0),
             (SDECD4, 0, 0, 0), (SDD094, 0, 0, 0),
             (S149DF4, 1, 0, 0),
             (S65DAD0, VALA, RING, 1),
             (S145150, NODE, RING, 1),
             (S145D1C, 0, RING, 1),
             (S20E814, NODE, 0, 0),
             (S14941C, 0, 0, 0),
             (S177460, 0, 0, 0),
             (S20E814, NODE, 0x4111, ARG)],
            dict(ret=0, gate=1, state=0, ring0=VALA, ring1=SENT,
                 ctx20=0xA5),
            state=0, gate=1, slots={0x47BBB8: VALA}, w4111=True,
            ret145d=0))

        # 16 state8_clear_consume: state 8 -> [ctx+4]:=0 (the ONLY
        #     [ctx+4] write not yet covered) and the flow CONTINUES;
        #     ev 0x380 with CDACC!=0 -> 65D008/65CE88, [ctx+0x20]:=1,
        #     forward 65B71C(node,0x380,arg); purge drains the queue
        #     -> consume at gate=1 with ring[0]=9 (!=0xA, no
        #     decrement) -> 20E814(node,0x4111,arg); final
        #     [ctx+4]=0: the cleared state PERSISTS (no rewrite in
        #     this path)
        SPECS.append(spec(
            'state8_clear_consume', EV380,
            {S1493D8: 1, S149474: 1, S14A1F8: 0x65, SCD514: 1,
             SCDACC: 1, S177484: [1, 0], S65D8B4: [0, 0],
             S145150: [0, 0], S20E814: 0},
            [(S1707D8, 4, EV380, ARG), (SC9BF8, 0, EV380, ARG),
             (SCAD30, 0, EV380, ARG), (SCF060, 1, EV380, ARG),
             (S135A84, CTX, 0, ARG), (SC8BA0, 0, 0, ARG),
             (S1493D8, 0, 0, ARG), (S149474, 1, 0, ARG),
             (S14A1F8, 1, 0, ARG), (SCD514, 0x65, 0, ARG),
             (SCDACC, 1, 0, ARG),
             (S65D008, NODE, 0, ARG), (S65CE88, 0, 0, ARG),
             (S65B71C, NODE, EV380, ARG),
             (S149028, NODE, 1, ARG), (S149028, NODE, 2, ARG),
             (S149028, NODE, 3, ARG), (S149028, NODE, 4, ARG),
             (S149028, NODE, 6, ARG),
             (S65D1CC, NODE, 6, ARG), (S65D8B4, 0, 6, ARG),
             (S145920, 0, 6, ARG), (S145150, NODE, 6, ARG),
             (S177484, 0, 6, ARG), (S177460, 1, 6, ARG),
             (S17743C, 0, 6, ARG), (S177484, 0, 6, ARG),
             (S65D8B4, 9, 1, RING),
             (S145150, NODE, 1, RING),
             (S20E814, NODE, 0x4111, ARG)],
            dict(ret=0, gate=1, state=0, ring0=9, ctx20=1),
            state=8, gate=1, slots={0x47BBB8: 9}))

        assert len(SPECS) == 16, len(SPECS)

        cases = []
        for idx, sp in enumerate(SPECS):
            name = sp['name']
            success = 0xDEADB001 + idx
            for a in sp['stubs']:
                for (_, wlo, whi, _) in WINS_MAIN:
                    assert not (wlo <= a < whi), (hex(a), hex(wlo))
            stub_sections = (
                f'  .probe {hex(PROBE_AT)} : {{ *(.probe) }}\n'
                f'  .common {hex(COMMON_AT)} : {{ *(.common) }}\n'
                f'  .retseq {hex(RETSEQ)} : {{ *(.retseq) }}\n')
            prev_end = None
            for a in sorted(sp['stubs']):
                if prev_end is not None and a < prev_end:
                    raise AssertionError(
                        f'stub overlap at {hex(a)} < {hex(prev_end)}')
                prev_end = a + 10
                stub_sections += (f'  .stub_{a:x} {hex(a)} : '
                                  f'{{ *(.stub_{a:x}) }}\n')
            for sname, sbase, _ in sp['fix']:
                stub_sections += \
                    f'  {sname} {hex(sbase)} : {{ *({sname}) }}\n'
            asm = (harness(sp['calls'])
                   + ''.join(
                       (f'.section .stub_{a:x},"ax",@progbits\n'
                        ' .org 0\n' + stub_body(STUBS[a]))
                       for a in sp['stubs'])
                   + common_logger()
                   + probe(sp['asserts'], success, idx)
                   + fixture_sections(sp['fix']))
            case, sim_text = build_case(name, asm, WINS_MAIN,
                                        stub_sections)
            assert case['exit_code'] == 11, (name, case)
            fault = case['fault']
            assert fault is not None \
                and fault['operation'] == 'read', (name, fault)
            addr = int(fault['address'], 16)
            assert addr == success, (name, fault, hex(success))
            assert PROBE_AT <= int(fault['pc'], 16) \
                < PROBE_AT + 0x2000, (name, fault)
            cases.append(dict(name=name,
                              calls=[[hex(e), a] for e, a in sp['calls']],
                              success=hex(success),
                              exit_code=case['exit_code'],
                              instructions=case['instructions'],
                              fault=fault))
            print(f'PASS {name} -> {hex(success)}', flush=True)

        results['cpu_cases'] = cases
        results['stub_map'] = {hex(a): STUBS[a] for a in STUBS}
        results['status'] = 'PASS_ASLV_CONSUMER_380_400_CPU'
        print('PASS_ASLV_CONSUMER_380_400_CPU', stamp)
        print('Evidence:', out / 'verified_evidence.json')
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'verified_evidence.json').write_text(
            json.dumps(results, indent=2, default=str) + '\n')


if __name__ == '__main__':
    main()
