#!/usr/bin/env python3
"""Nikon COOLPIX S33 - AutoSceneLiveView ring writer 0x65C720 (iteration 39).

Closes the open point left by iteration 37 (report
S33_GUI_AutoSceneLiveView_Handler_100_CPU_20261101.md, prossimo passo (a)):
the gate/ring subsystem writer 0x65C720 - called by handler 0x100 at
0x65B200 and by 0x4405/0x440E/0x4006 - was decoded only statically and
never executed. Question: does 0x65C720 really reset [ctx+0xC] and the
gate byte [0x47BBC8], enqueue exactly one "re-opening reason" word into
the ring at [0x47BBB8+4*gate] (add2 scale 4), increment the gate, and
then consult the 0x4111/0x4110/0x177484 service queue before returning
r15?

Static decode (GNU ARC700, original bytes, block 2; window
0x65C720..0x65C920, pools 0x65C90C..0x65C91C):
  prologue: push_s blink; bl 0x334118 (millicode push r20..r13, 8 regs,
            proven here: entry 0x334118 pushes r20,r19,r18,r17,r16,
            r15,r14,r13; epilogue b 0x33416C pops them and restores
            blink from the pushed cell)
  r16=node; r17=0x135A84(); r13=0; r19=0x137774(0); r15=1 (default ret);
  r20=0xDE3E4() (unused in the branches); r18=0
  gate 1: C7E04() == 0 -> return 0 (r13), NOTHING written
  gate 2: 17BE18(0,0x3180,0x3180) != 0 -> return 0; 17BE18(0,0x3181,
          0x3181) != 0 -> return 0 (no reset either)
  reset: ctx=pool 0x65C910 (0x681F5C); ring=pool 0x65C914 (0x47BBB8);
          [ctx+0xC]:=0; [ring+0x10]=[0x47BBC8]:=0; 12B0DC(fp-0xC)
  mode = CAD30() REAL:
    0x7D: zero fp-3..fp-1; 127984(fp-3,fp-2,fp-1) [3 out-bytes];
          b1!=0 or b2!=0 or b3>=0xA -> r18=C7BDC() else r18 stays 0
    else: C7E04()==1 -> r18=127284() else r18=-1
  dispatch (ONE enqueue max per invocation, if/elif chain):
    r19!=0: r17 bit3 -> ENQ 0xB; elif bit2 -> ENQ 0xD; elif bit4 ->
            ENQ 6; elif bit1 -> ENQ 4; else 127278(): ==0 && r18==0 ->
            ENQ 3 (r15=0); !=0 -> ENQ 5 (r15=0); r18!=0 -> ctx write
            ([ctx+0xC]:=1, [ctx+0xD]:=0, r15=0, NO enqueue)
    r19==0: 127278()!=0 -> ENQ 5 (r15=0); else r18==0 -> ENQ 0xC
            (r15=0); else ctx write (r15=0)
    ENQ(v): r0=[ring+0x10] (gate, just reset to 0); add2 r1,ring,r0
            = ring + 4*r0 (sem7.c add2_L_r_r: SLLSI(...,2), scale x4);
            st v,[r1]; gate+1. So the writer ALWAYS restarts the ring
            at slot 0 and leaves gate=1; only the 0x4110/0x4111
            handlers append (9/0xA) without reset.
  service queue section:
    17BE18(0,0x4111,0x4111)!=0: 14941C(); if 0 -> 177460();
            17BF60(0,0x4111,0x4111); r15=1; 20E814(node,0x4111,0)
    elif 17BE18(0,0x4110,0x4110)!=0: 14941C(); if 0 -> 177460();
            17BF60(0,0x4110,0x4110); r15=1 (NO 20E814)
    elif 177484()!=0: 14941C(); if 0 -> 177460(); r15=1
    final: C9750(); ==0 -> r15=0. C975C(1). return r15.
  Epilogue 0x65C900: mov sp,fp; ld.ab fp,[sp,4]; b 0x33416C.

Reader/writer consistency (proven it.37 + here): the h100 reader reads
word [0x47BBB4 + 4*gate]; after this writer gate==1, so the reader
consumes [0x47BBB8] = the reason just written at ring slot 0.

NEW lesson: 16-bit ld_s rN,[pcl,u] EA = (pc&~3) + u (displayed operand
u, encoded field u/4) - pools 0x65C90C/10/14/18/1C are read this way
by 0x65C720 (GNU comments correct).

CPU cases (22, original windows; entry 0x65C720 with r0=NODE, r1/r2
leftovers 0xB/0xFA; sequence-valued stubs because 17BE18/C7E04 are
called multiple times with different semantics):
 0 gate1_c7e040      C7E04()==0 -> ret 0, no writes (sentinels)
 1 gate2_q3180       3180 in queue -> ret 0, no reset (gate sentinel)
 2 gate2_q3181       3181 in queue -> ret 0, no reset
 3 enq_0xB           bit3 -> ring[0]=0xB, gate 0->1, ret 1
 4 enq_0xD           bit2 -> ring[0]=0xD
 5 enq_6             bit4 -> ring[0]=6
 6 enq_4             bit1 -> ring[0]=4
 7 bits_priority     r17=0x1E (bits 1,2,3,4) -> ONLY 0xB, gate=1
 8 enq_3             no bits, 127278==0, r18==0 -> ring[0]=3, ret 0
 9 enq5_7278ne0      r19!=0, 127278!=0 -> ring[0]=5, ret 0
10 enq_0xC_r19eq0    r19==0, 127278==0, r18==0 -> ring[0]=0xC
11 enq5_r19eq0       r19==0, 127278!=0 -> ring[0]=5
12 ctxwrite_r19ne0   r18!=0 -> [ctx+0xC]=1, [ctx+0xD]=0, no enqueue,
                       gate stays 0, ret 0
13 ctxwrite_r19eq0   same via the r19==0 branch
14 mode7d_clean      mode 0x7D, out-bytes 0,0,0 -> no C7BDC, ENQ 3;
                       only ONE C7E04 call (log order proves it)
15 mode7d_c7bdc      out-bytes 0,0,0xA -> C7BDC ret 0x33 -> r18!=0 ->
                       ctx write (r18 propagation)
16 q4111_post        ENQ 0xB then 0x4111 pending -> 14941C/177460/
                       17BF60(0,0x4111,0x4111)/20E814(node,0x4111,0),
                       ret 1
17 q4111_941cne0     14941C()!=0 -> NO 177460, still posts
18 q4110_post        ENQ 3 (r15=0) then 0x4110 pending -> 17BF60
                       (0,0x4110,0x4110), NO 20E814, r15 RESTORED to 1
19 177484_restore    queue empty, 177484()!=0 -> 14941C/177460,
                       r15 restored to 1, no post
20 c9750_zero        C9750()==0 -> ret 0 despite the enqueue
21 add2_micro        entry 0x65C7F0 (original enqueue sequence) with
                       gate fixture 3: word written at 0x47BBC4 =
                       0x47BBB8+4*3 (add2 scale x4 PROVEN), gate=4

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
SCNT = 0x369000          # per-sid call counters (fixture zeroed)
RETSEQ = 0x369800        # 4 return values per sid (fixture)
OUTCELL = 0x369C00       # 3 out-bytes for the 0x127984 writer stub
NSEQ = 4

CTX = 0x681F5C           # AutoSceneLiveView context (pool 0x65C910)
RING = 0x47BBB8          # ring base (pool 0x65C914)
TBL_BASE = 0x47BBB4      # reader table base (it.37)
GATE_BYTE = 0x47BBC8     # RING+0x10
MODE_CELL = 0xC8E80C
ENTRY = 0x65C720         # ring writer
ENQ_SEQ = 0x65C7F0       # first enqueue sequence (add2 micro case)
SENT = 0xA5A5A5A5

NODE = 0x1234
R1L = 0xB                # entry leftovers (h100 lesson 753)
R2L = 0xFA

FP = 0xC8EFD8            # deterministic frame: fp after the prologue
LOCAL3 = FP - 3          # 0xC8EFD5 (mode-0x7D out-bytes)
LOCAL2 = FP - 2          # 0xC8EFD6
LOCAL1 = FP - 1          # 0xC8EFD7
FRAME12 = FP - 0xC       # 0xC8EFCC (12B0DC argument)

# original windows (payload, lo, hi, section)
W_RW = (2, 0x65C720, 0x65C920, '.rw')
W_MILI = (0, 0x334100, 0x3341E4, '.mili')
W_MODEGET = (0, 0xCAD30, 0xCAD38, '.modeget')
W_MODEPOOL = (0, 0xCAAC4, 0xCAAC8, '.modepool')

WINS_MAIN = [W_RW, W_MILI, W_MODEGET, W_MODEPOOL]
WINS_MICRO = [W_RW, W_MILI]

RW_HEX = (
    'f1c0fa09ce6bfc1cc8b60a230037a3c11a70560b8d6c3a7000dda9703a088d6d7a'
    '7001dfa20ccd409a705a75ba0e8d3580e005f4a970ad010000a97063d907b92872'
    'ba0e8d8f80e008f4a97068d12872aa0e8d8f80e004f200d8c4f065d066d6aca842'
    '230033b0ae56094d67a60d0d37fde020f4fd1b42b3fe1b42b3ff1b42b34223c030'
    '4223813042234230da098d65fd1380b080e00af4fe1380b080e006f4ff1380b08a'
    'e090f6160c8d355a700cf0360e8d3581e005f4ae0a4d6503f08a20ff0f5a704c23'
    '00a031f22a70e3b808f2108e0bda1526011040a111f0e2b808f2108e0dda152601'
    '1040a109f0e4b80af2108e06da1526011040a101e010ae32f0e1b808f2108e04da'
    '1526011040a1f7f14a0a4d6580e00ff44c2200a01df4108e03da1526011040a10a'
    'f0320a4d6580e00af2108e05da1526011040a101e010ae00df10f04c2200a007f4'
    '108e0cda1526011040a1f4f127d001d900df2ca8ada800d826d12872960d8d8f80'
    'e013f2920b4d7680e003f4ce0b4d8d00d81fd12872c20e8d8f01df0a701cd100da'
    '6a0fcdd81ff000d81ad12872620d8d8f80e00ef25e0b4d7680e004f49a0b4d8d00'
    'd814d12872920e8d8f0cf0ae0b4d8d80e009f23e0b4d7680e004f47a0b4d8d01df'
    '660e4d3680e002f400df01d8660e4d36e9700a24c03604141b346500ce6b813100'
    '005c1f6800b8bb47001141000010410000')
MILI_HEX = (
    'fc1c88b6fc1c48b6fc1c08b6fc1cc8b5fc1c88b5fc1c48b5fc1c08b5fc1cc8b4'
    'fc1c88b4fc1c48b4fc1c08b4fc1cc8b3fc1c88b3fc1c48b3e07ee07804dc38dd'
    '35f0e07804dc34dd33f0e07804dc30dd31f0e07804dc2cdd2ff0e07804dc28dd'
    '2df0e07804dc24dd2bf0e07804dc20dd29f0e07804dc1cdd27f0e07804dc18dd'
    '25f0e07804dc14dd23f0e07804dc10dd21f0e07804dc0cdd1ff0e07804dc08dd'
    '1cf0e07804dc04dd19f034141a30301419302c14183028141730241416302014'
    '15301c1414301814133014141230101411300c14103002c701c6b0244d33b024'
    '1f33e07e')

# stub ids
S135A84, S137774, SDE3E4, SC7E04, S17BE18, S12B0DC = 1, 2, 3, 4, 5, 6
S127984, SC7BDC, S127284, S127278, S14941C, S177460 = 7, 8, 9, 10, 11, 12
S177484, S17BF60, S20E814, SC9750, SC975C = 13, 14, 15, 16, 17

STUBS = {
    0x135A84: S135A84, 0x137774: S137774, 0xDE3E4: SDE3E4,
    0xC7E04: SC7E04, 0x17BE18: S17BE18, 0x12B0DC: S12B0DC,
    0x127984: S127984, 0xC7BDC: SC7BDC, 0x127284: S127284,
    0x127278: S127278, 0x14941C: S14941C, 0x177460: S177460,
    0x177484: S177484, 0x17BF60: S17BF60, 0x20E814: S20E814,
    0xC9750: SC9750, 0xC975C: SC975C,
}
MAXSID = max(STUBS.values())


BLINK_PLACEHOLDER = 0x51515151


def harness(entry, args, pre=None, push_blink=False):
    # push_blink (micro case only): the ELF entry starts with blink=0,
    # so push_s blink would save 0; instead load blink with a
    # placeholder that the two-pass build replaces with the real
    # harness land address found via objdump.
    text = ('.section .text,"ax",@progbits\n.global _start\n_start:\n'
            f' mov sp,{hex(STACK)}\n'
            + ((f' mov blink,{hex(BLINK_PLACEHOLDER)}\n'
                ' push_s blink\n') if push_blink else '')
            + ''.join(f' mov r{k},{hex(v)}\n' for k, v in enumerate(args))
            + ''.join(f' mov r{k},{hex(v)}\n' for k, v in (pre or []))
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


def stub127984_body():
    # 127984(fp-3,fp-2,fp-1) writes its 3 out-bytes from OUTCELL,
    # then logs (r0,r1,r2 = the pointers) through the common logger.
    return (' push_s blink\n'
            f' mov r3,{hex(OUTCELL)}\n'
            ' ldb r4,[r3,0]\n'
            ' stb r4,[r0,0]\n'
            ' ldb r4,[r3,1]\n'
            ' stb r4,[r1,0]\n'
            ' ldb r4,[r3,2]\n'
            ' stb r4,[r2,0]\n'
            f' mov_s r12,{hex(S127984)}\n'
            f' mov r3,{hex(COMMON_AT)}\n'
            ' jl_s [r3]\n')


def common_logger():
    # same call log as the it.37 bench, plus a per-sid sequence return
    # table (RETSEQ, NSEQ entries per sid) with a per-sid counter in
    # SCNT, so 17BE18/C7E04 can return different values per call.
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
            ' asl r4,r12,4\n'
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


def ctx_fixture():
    # 0xD0 bytes, sentinel 0xA5; +8/+9 open leftovers as in it.37
    buf = bytearray(b'\xA5' * 0xD0)
    buf[8] = 0xFF
    buf[9] = 0x5A
    return bytes(buf)


def gate_fixture(gate):
    # 0x20 bytes at 0x47BBB0: [0] sentinel, reader table[0..3] sentinels
    # (0x47BBB4..C4), ring slots overlap table[1..], gate byte at +0x18.
    buf = bytearray(b'\xA5' * 0x20)
    for k in range(4):
        struct.pack_into('<I', buf, 4 + 4 * k, SENT)
    buf[0x18] = gate & 0xFF
    return bytes(buf)


def base_fix(mode, gate, outbytes=(0, 0, 0)):
    return [('.ctxfix', CTX, ctx_fixture()),
            ('.modefix', MODE_CELL, bytes([mode]) + b'\xA5' * 3),
            ('.gatefix', 0x47BBB0, gate_fixture(gate)),
            ('.logfix', CNT, bytes(0x800)),
            ('.scntfix', SCNT, bytes(4 * (MAXSID + 1))),
            ('.outfix', OUTCELL, bytes(outbytes))]


def ring_asserts(gate, ring0, ring1=SENT, ring2=SENT, ring3=SENT,
                 ctx0C=0, ctx0D=0xA5):
    return [(GATE_BYTE, 1, gate),
            (0x47BBB0, 4, SENT),
            (0x47BBB4, 4, SENT),      # reader slot 0 NEVER written here
            (0x47BBB8, 4, ring0),
            (0x47BBBC, 4, ring1),
            (0x47BBC0, 4, ring2),
            (0x47BBC4, 4, ring3),
            (CTX + 0xC, 1, ctx0C),
            (CTX + 0xD, 1, ctx0D)]


def spec(name, entry, args, rets, logs, mem, mode=0x2B, gate=0x5A,
         outbytes=(0, 0, 0), pre=None, push_blink=False, wins=None):
    seq = {sid: ([v] * NSEQ if not isinstance(v, list) else v)
           for sid, v in rets.items()}
    retseq = bytearray(NSEQ * 4 * (MAXSID + 1))
    for sid in range(MAXSID + 1):
        vals = seq.get(sid, [0] * NSEQ)
        assert len(vals) <= NSEQ
        for k, v in enumerate(vals):
            struct.pack_into('<I', retseq, NSEQ * 4 * sid + 4 * k,
                             v & 0xFFFFFFFF)
    fix = base_fix(mode, gate, outbytes)
    fix.append(('.retseq', RETSEQ, bytes(retseq)))
    asserts = []
    for i, (sid, a0, a1, a2) in enumerate(logs):
        asserts += L(i, sid, a0, a1, a2)
    n = len(logs)
    asserts += [(CNT, 4, n)]
    asserts += L(n, 0, None, None, None)   # no extra calls
    asserts += [(RETCELL, 4, mem.pop('ret'))]
    asserts += ring_asserts(**mem)
    return dict(name=name, entry=entry, args=args, pre=pre,
                push_blink=push_blink, wins=wins or WINS_MAIN,
                stubs=list(STUBS), fix=fix, asserts=asserts)


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'aslv_ring_writer_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, _ = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp,
                   action='aslv-ring-writer-cpu',
                   limits=['Static analysis + 22 synthetic CPU cases; '
                           'no hardware',
                           'Deep callees are stubs; originals executed: '
                           'the whole ring writer body 0x65C720, '
                           'millicode push/pop entries 0x334118/0x33416C, '
                           'mode getter 0xCAD30; the enqueue sequence '
                           '0x65C7F0..0x65C81E runs original bytes in '
                           'every case',
                           'ctx 0x681F5C, mode byte 0xC8E80C, ring '
                           '0x47BBB0..0x47BCD0 and gate byte 0x47BBC8 '
                           'are RUNTIME cells in the load gap '
                           '0x428600..0x5FE800: fixture-imposed, NOT '
                           'verifiable from the dump',
                           'The 0x3180/0x3181/0x4111/0x4110 queue '
                           'contents and the returns of the stubbed '
                           'getters are imposed by the bench',
                           'No physical button map, no hardware, no '
                           'scheduling; V1.1 dump only; NON_INSTALLARE'])
    try:
        p0, p2 = payloads[0], payloads[2]

        # --- 1. static: pools --------------------------------------
        pools = {0x65C90C: 0x3181, 0x65C910: CTX, 0x65C914: RING,
                 0x65C918: 0x4111, 0x65C91C: 0x4110}
        for a, v in pools.items():
            got = struct.unpack_from('<I', p2, a - base[2])[0]
            assert got == v, (hex(a), hex(got), hex(v))
        results['pools'] = {hex(a): hex(v) for a, v in pools.items()}

        # --- 2. static: opcode freezes ------------------------------
        freezes = [
            ('rw_window', 2, 0x65C720, RW_HEX),
            ('millicode_win', 0, 0x334100, MILI_HEX),
            ('modeget', 0, 0xCAD30, '651700f60088e07e'),
            ('modepool', 0, 0xCAAC4, '0ce8c800')]
        for name, idx, addr, hexstr in freezes:
            src = payloads[idx]
            data = src[addr - base[idx]:
                       addr - base[idx] + len(hexstr) // 2]
            assert data.hex() == hexstr, (name, data.hex())
        results['opcode_freezes'] = 'ok'

        # --- 3. static: add2 semantics in the pinned engine ---------
        sem = (LEGACY / 'source/gnu-arc700-sim-src/sim/arc/sem7.c')
        text = sem.read_text()
        assert 'SEM_FN_NAME (arc700f,add2_L_r_r__RA__RC)' in text
        i = text.index('SEM_FN_NAME (arc700f,add2_L_r_r__RA__RC)')
        body = text[i:i + 2000]
        assert 'SLLSI (GET_H_CR (FLD (f_op_C)), 2)' in body, \
            'add2 scale x4 not found in the engine source'
        results['add2_engine_semantics'] = dict(
            source=str(sem),
            sha256=hashlib.sha256(text.encode()).hexdigest(),
            rule='add2 rA,rB,rC = rB + (rC << 2)',
            site='sem7.c add2_L_r_r__RA__RC')

        # --- 4. static: census bl 0x65C720 ---------------------------
        objcopy = ROOT / 'work/build-arc/binutils/objcopy'
        objdump = ROOT / 'work/build-arc/binutils/objdump'
        assert objcopy.is_file() and objdump.is_file()
        census = []
        with tempfile.TemporaryDirectory(prefix='it39-census-') as td:
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
                    if ';0x65c720' in line:
                        parts = [p for p in line.split('\t') if p]
                        addr = int(parts[0].strip().rstrip(':'), 16)
                        mn = parts[2].strip() if len(parts) > 2 else ''
                        assert mn.startswith('bl'), (line, mn)
                        census.append((idx, addr))
        assert sorted(census) == [(2, 0x659A80), (2, 0x659C14),
                                  (2, 0x65A08E), (2, 0x65B200),
                                  (2, 0x65CAEE)], census
        results['bl_census_65c720'] = [(f'b{i}', hex(a))
                                       for i, a in sorted(census)]

        # window inventory + non-overlap
        wins = {}
        prev = None
        for (pidx, lo, hi, sec) in sorted(
                WINS_MAIN, key=lambda w: (w[1], w[2])):
            assert prev is None or lo >= prev, (hex(lo), hex(prev))
            prev = hi
            data = payloads[pidx][lo - base[pidx]:hi - base[pidx]]
            wins[sec] = dict(payload=pidx, lo=hex(lo), hi=hex(hi),
                             size=len(data),
                             sha256=hashlib.sha256(data).hexdigest())
        results['windows'] = wins

        # --- 5. CPU cases -------------------------------------------
        r = Runner(SimpleNamespace(legacy_root=LEGACY,
                                   toolchain=TOOLCHAIN,
                                   output=out,
                                   action='aslv-ring-writer-cpu'))
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

        SPECS = []

        # 0 gate 1: C7E04()==0 -> return 0, nothing written
        SPECS.append(spec(
            'rw_gate1_c7e040', ENTRY, [NODE, R1L, R2L],
            {S135A84: 0x8, S137774: 0x55, SDE3E4: 0xD3, SC7E04: 0},
            [(S135A84, NODE, R1L, R2L), (S137774, 0, R1L, R2L),
             (SDE3E4, 0x55, R1L, R2L), (SC7E04, 0xD3, R1L, R2L)],
            dict(ret=0, gate=0x5A, ring0=SENT, ctx0C=0xA5)))

        # 1 gate 2: 0x3180 pending -> return 0, no reset
        SPECS.append(spec(
            'rw_gate2_q3180', ENTRY, [NODE, R1L, R2L],
            {S135A84: 0x8, S137774: 1, SDE3E4: 0xD3, SC7E04: 1,
             S17BE18: [1, 0, 0, 0]},
            [(S135A84, NODE, R1L, R2L), (S137774, 0, R1L, R2L),
             (SDE3E4, 1, R1L, R2L), (SC7E04, 0xD3, R1L, R2L),
             (S17BE18, 0, 0x3180, 0x3180)],
            dict(ret=0, gate=0x5A, ring0=SENT, ctx0C=0xA5)))

        # 2 gate 2: 0x3181 pending -> return 0, no reset
        SPECS.append(spec(
            'rw_gate2_q3181', ENTRY, [NODE, R1L, R2L],
            {S135A84: 0x8, S137774: 1, SDE3E4: 0xD3, SC7E04: 1,
             S17BE18: [0, 1, 0, 0]},
            [(S135A84, NODE, R1L, R2L), (S137774, 0, R1L, R2L),
             (SDE3E4, 1, R1L, R2L), (SC7E04, 0xD3, R1L, R2L),
             (S17BE18, 0, 0x3180, 0x3180),
             (S17BE18, 0, 0x3181, 0x3181)],
            dict(ret=0, gate=0x5A, ring0=SENT, ctx0C=0xA5)))

        # shared full-path log prefix (gates pass, mode != 0x7D).
        # Live-register lesson: the 0x3180/0x3181 gate-2 queries load
        # r1/r2 with the pool constants, which stay as leftovers until
        # the 0x4111/0x4110 queue section overwrites them.
        def FULLHEAD(ret137=1):
            return [(S135A84, NODE, R1L, R2L),
                    (S137774, 0, R1L, R2L),
                    (SDE3E4, ret137, R1L, R2L),
                    (SC7E04, 0xD3, R1L, R2L),
                    (S17BE18, 0, 0x3180, 0x3180),
                    (S17BE18, 0, 0x3181, 0x3181),
                    (S12B0DC, FRAME12, 0x3181, 0x3181),
                    (SC7E04, 0x2B, 0x3181, 0x3181)]

        def TAIL_EMPTY():
            return [(S17BE18, 0, 0x4111, 0x4111),
                    (S17BE18, 0, 0x4110, 0x4110),
                    (S177484, 0, 0x4110, 0x4110),
                    (SC9750, 0, 0x4110, 0x4110),
                    (SC975C, 1, 0x4110, 0x4110)]

        RETS_BIT = {S135A84: 8, S137774: 1, SDE3E4: 0xD3, SC7E04: [1, 1],
                    S17BE18: [0, 0, 0, 0], S12B0DC: 0x12,
                    S127284: 0x66, S177484: 0, SC9750: 1, SC975C: 0x77}

        # 3-6 bit-path enqueues (r15 stays 1)
        for cname, r17, val in (('enq_0xB', 8, 0xB), ('enq_0xD', 4, 0xD),
                                ('enq_6', 0x10, 6), ('enq_4', 2, 4)):
            SPECS.append(spec(
                f'rw_{cname}', ENTRY, [NODE, R1L, R2L],
                {**RETS_BIT, S135A84:r17},
                FULLHEAD() + [(S127284, 1, 0x3181, 0x3181)]
                + TAIL_EMPTY(),
                dict(ret=1, gate=1, ring0=val)))

        # 7 multiple reasons -> only the highest-priority one (bit3)
        SPECS.append(spec(
            'rw_bits_priority', ENTRY, [NODE, R1L, R2L],
            {**RETS_BIT, S135A84:0x1E},
            FULLHEAD() + [(S127284, 1, 0x3181, 0x3181)] + TAIL_EMPTY(),
            dict(ret=1, gate=1, ring0=0xB, ring1=SENT)))

        RETS_ENQ3 = {S135A84: 0, S137774: 1, SDE3E4: 0xD3,
                     SC7E04: [1, 1], S17BE18: [0, 0, 0, 0],
                     S12B0DC: 0x12, S127284: 0, S127278: 0,
                     S177484: 0, SC9750: 1, SC975C: 0x77}

        # 8 ENQ 3 (r19!=0, no bits, 127278==0, r18==0), r15=0
        SPECS.append(spec(
            'rw_enq_3', ENTRY, [NODE, R1L, R2L], RETS_ENQ3,
            FULLHEAD() + [(S127284, 1, 0x3181, 0x3181),
                          (S127278, 0, 0x3181, 0x3181)] + TAIL_EMPTY(),
            dict(ret=0, gate=1, ring0=3)))

        # 9 ENQ 5 via 127278()!=0 (r19!=0), r15=0
        SPECS.append(spec(
            'rw_enq5_7278ne0', ENTRY, [NODE, R1L, R2L],
            {**RETS_ENQ3, S127278:1},
            FULLHEAD() + [(S127284, 1, 0x3181, 0x3181),
                          (S127278, 0, 0x3181, 0x3181)] + TAIL_EMPTY(),
            dict(ret=0, gate=1, ring0=5)))

        # 10 ENQ 0xC (r19==0, 127278==0, r18==0), r15=0
        SPECS.append(spec(
            'rw_enq_0xC_r19eq0', ENTRY, [NODE, R1L, R2L],
            {**RETS_ENQ3, S137774:0},
            FULLHEAD(ret137=0)
            + [(S127284, 1, 0x3181, 0x3181),
               (S127278, 0, 0x3181, 0x3181)] + TAIL_EMPTY(),
            dict(ret=0, gate=1, ring0=0xC)))

        # 11 ENQ 5 (r19==0, 127278!=0), r15=0
        SPECS.append(spec(
            'rw_enq5_r19eq0', ENTRY, [NODE, R1L, R2L],
            {**RETS_ENQ3, S137774:0, S127278:1},
            FULLHEAD(ret137=0)
            + [(S127284, 1, 0x3181, 0x3181),
               (S127278, 0, 0x3181, 0x3181)] + TAIL_EMPTY(),
            dict(ret=0, gate=1, ring0=5)))

        # 12/13 ctx write (r18!=0): no enqueue, gate stays 0.
        # r19!=0 goes through 65c7ea mov r0,r17 -> s7278 sees r17(0);
        # r19==0 jumps straight to 65c84a and s7278 sees the 127284
        # leftover (0x77) - the two dispatch arms see a different r0.
        SPECS.append(spec(
            'rw_ctxwrite_r19ne0', ENTRY, [NODE, R1L, R2L],
            {**RETS_ENQ3, S137774:1, S127284:0x77},
            FULLHEAD(ret137=1)
            + [(S127284, 1, 0x3181, 0x3181),
               (S127278, 0, 0x3181, 0x3181)] + TAIL_EMPTY(),
            dict(ret=0, gate=0, ring0=SENT, ctx0C=1, ctx0D=0)))
        SPECS.append(spec(
            'rw_ctxwrite_r19eq0', ENTRY, [NODE, R1L, R2L],
            {**RETS_ENQ3, S137774:0, S127284:0x77},
            FULLHEAD(ret137=0)
            + [(S127284, 1, 0x3181, 0x3181),
               (S127278, 0x77, 0x3181, 0x3181)] + TAIL_EMPTY(),
            dict(ret=0, gate=0, ring0=SENT, ctx0C=1, ctx0D=0)))

        # 14 mode 0x7D, clean out-bytes: single C7E04 call, ENQ 3
        SPECS.append(spec(
            'rw_mode7d_clean', ENTRY, [NODE, R1L, R2L],
            {S135A84: 0, S137774: 1, SDE3E4: 0xD3, SC7E04: 1,
             S17BE18: [0, 0, 0, 0], S12B0DC: 0x12, S127278: 0,
             S177484: 0, SC9750: 1, SC975C: 0x77},
            [(S135A84, NODE, R1L, R2L), (S137774, 0, R1L, R2L),
             (SDE3E4, 1, R1L, R2L), (SC7E04, 0xD3, R1L, R2L),
             (S17BE18, 0, 0x3180, 0x3180),
             (S17BE18, 0, 0x3181, 0x3181),
             (S12B0DC, FRAME12, 0x3181, 0x3181),
             (S127984, LOCAL3, LOCAL2, LOCAL1),
             (S127278, 0, LOCAL2, LOCAL1)] + TAIL_EMPTY(),
            dict(ret=0, gate=1, ring0=3), mode=0x7D))

        # 15 mode 0x7D, out-bytes 0,0,0xA -> C7BDC -> r18 -> ctx write
        SPECS.append(spec(
            'rw_mode7d_c7bdc', ENTRY, [NODE, R1L, R2L],
            {S135A84: 0, S137774: 1, SDE3E4: 0xD3, SC7E04: 1,
             S17BE18: [0, 0, 0, 0], S12B0DC: 0x12, SC7BDC: 0x33,
             S127278: 0, S177484: 0, SC9750: 1, SC975C: 0x77},
            [(S135A84, NODE, R1L, R2L), (S137774, 0, R1L, R2L),
             (SDE3E4, 1, R1L, R2L), (SC7E04, 0xD3, R1L, R2L),
             (S17BE18, 0, 0x3180, 0x3180),
             (S17BE18, 0, 0x3181, 0x3181),
             (S12B0DC, FRAME12, 0x3181, 0x3181),
             (S127984, LOCAL3, LOCAL2, LOCAL1),
             (SC7BDC, 0xA, LOCAL2, LOCAL1),
             (S127278, 0, LOCAL2, LOCAL1)] + TAIL_EMPTY(),
            dict(ret=0, gate=0, ring0=SENT, ctx0C=1, ctx0D=0),
            mode=0x7D, outbytes=(0, 0, 0xA)))

        # 16 ENQ 0xB then 0x4111 pending -> post + notify, ret 1
        SPECS.append(spec(
            'rw_q4111_post', ENTRY, [NODE, R1L, R2L],
            {**RETS_BIT, S17BE18:[0, 0, 1, 0], S14941C:0,
                 S177460:0x46, S17BF60:0x57, S20E814:0x21},
            FULLHEAD() + [(S127284, 1, 0x3181, 0x3181),
                          (S17BE18, 0, 0x4111, 0x4111),
                          (S14941C, 1, 0x4111, 0x4111),
                          (S177460, 0, 0x4111, 0x4111),
                          (S17BF60, 0, 0x4111, 0x4111),
                          (S20E814, NODE, 0x4111, 0),
                          (SC9750, 0x21, 0x4111, 0),
                          (SC975C, 1, 0x4111, 0)],
            dict(ret=1, gate=1, ring0=0xB)))

        # 17 same but 14941C()!=0 -> NO 177460
        SPECS.append(spec(
            'rw_q4111_941cne0', ENTRY, [NODE, R1L, R2L],
            {**RETS_BIT, S17BE18:[0, 0, 1, 0], S14941C:5,
                 S17BF60:0x57, S20E814:0x21},
            FULLHEAD() + [(S127284, 1, 0x3181, 0x3181),
                          (S17BE18, 0, 0x4111, 0x4111),
                          (S14941C, 1, 0x4111, 0x4111),
                          (S17BF60, 0, 0x4111, 0x4111),
                          (S20E814, NODE, 0x4111, 0),
                          (SC9750, 0x21, 0x4111, 0),
                          (SC975C, 1, 0x4111, 0)],
            dict(ret=1, gate=1, ring0=0xB)))

        # 18 ENQ 3 (r15=0) then 0x4110 pending -> r15 RESTORED to 1
        SPECS.append(spec(
            'rw_q4110_post', ENTRY, [NODE, R1L, R2L],
            {**RETS_ENQ3, S17BE18:[0, 0, 0, 1], S14941C:0,
                 S177460:0x46, S17BF60:0x57},
            FULLHEAD() + [(S127284, 1, 0x3181, 0x3181),
                          (S127278, 0, 0x3181, 0x3181),
                          (S17BE18, 0, 0x4111, 0x4111),
                          (S17BE18, 0, 0x4110, 0x4110),
                          (S14941C, 1, 0x4110, 0x4110),
                          (S177460, 0, 0x4110, 0x4110),
                          (S17BF60, 0, 0x4110, 0x4110),
                          (SC9750, 0x57, 0x4110, 0x4110),
                          (SC975C, 1, 0x4110, 0x4110)],
            dict(ret=1, gate=1, ring0=3)))

        # 19 queue empty, 177484()!=0 -> r15 restored, no post
        SPECS.append(spec(
            'rw_177484_restore', ENTRY, [NODE, R1L, R2L],
            {**RETS_ENQ3, S177484:1, S14941C:0, S177460:0x46},
            FULLHEAD() + [(S127284, 1, 0x3181, 0x3181),
                          (S127278, 0, 0x3181, 0x3181)]
            + TAIL_EMPTY()[:-2]
            + [(S14941C, 1, 0x4110, 0x4110),
               (S177460, 0, 0x4110, 0x4110),
               (SC9750, 0x46, 0x4110, 0x4110),
               (SC975C, 1, 0x4110, 0x4110)],
            dict(ret=1, gate=1, ring0=3)))

        # 20 C9750()==0 forces ret 0 despite the enqueue
        SPECS.append(spec(
            'rw_c9750_zero', ENTRY, [NODE, R1L, R2L],
            {**RETS_BIT, SC9750:0},
            FULLHEAD() + [(S127284, 1, 0x3181, 0x3181)] + TAIL_EMPTY(),
            dict(ret=0, gate=1, ring0=0xB)))

        # 21 add2 micro: original enqueue sequence, gate=3 ->
        # word at 0x47BBC4 = RING + 4*3 (scale x4 PROVEN), gate=4
        SPECS.append(spec(
            'rw_add2_micro', ENQ_SEQ, [0x111, 0x222, 0x333],
            {S17BE18: [0, 0, 0, 0], S177484: 0, SC9750: 1,
             SC975C: 0x77},
            [(S17BE18, 0, 0x4111, 0x4111),
             (S17BE18, 0, 0x4110, 0x4110),
             (S177484, 0, 0x4110, 0x4110),
             (SC9750, 0, 0x4110, 0x4110),
             (SC975C, 1, 0x4110, 0x4110)],
            dict(ret=0, gate=4, ring0=SENT, ring3=0xB, ctx0C=0xA5),
            gate=3, pre=[(14, RING), (27, FP)], push_blink=True,
            wins=WINS_MICRO))

        cases = []
        for idx, sp in enumerate(SPECS):
            name = sp['name']
            success = 0xDEADB001 + idx
            for a in sp['stubs']:
                for (_, wlo, whi, _) in sp['wins']:
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
                body = (stub127984_body() if a == 0x127984
                        else stub_body(STUBS[a]))
                prev_end = a + 46 if a == 0x127984 else a + 10
                stub_sections += (f'  .stub_{a:x} {hex(a)} : '
                                  f'{{ *(.stub_{a:x}) }}\n')
            for sname, sbase, _ in sp['fix']:
                stub_sections += \
                    f'  {sname} {hex(sbase)} : {{ *({sname}) }}\n'
            asm = (harness(sp['entry'], sp['args'], sp['pre'],
                           sp['push_blink'])
                   + ''.join(
                       (f'.section .stub_{a:x},"ax",@progbits\n'
                        ' .org 0\n' + (stub127984_body()
                                       if a == 0x127984
                                       else stub_body(STUBS[a])))
                       for a in sp['stubs'])
                   + common_logger()
                   + probe(sp['asserts'], success, idx)
                   + fixture_sections(sp['fix']))
            if sp['push_blink']:
                # two-pass: find the harness land address (the first
                # 'mov r12,RETCELL' in .text) and patch blink
                (out / f'{name}.s').write_text(asm)
                obj_path = out / f'{name}_land.o'
                assert r.command(f'{name}_land_as', [
                    TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL',
                    '-o', obj_path,
                    out / f'{name}.s']).returncode == 0
                dtext = subprocess.run(
                    [str(TOOLCHAIN / 'arc-elf32-objdump'), '-d',
                     '-m', 'arc:ARC700', '-EL', str(obj_path)],
                    capture_output=True, text=True,
                    check=True, timeout=120).stdout
                # section-relative -> absolute: .text is linked at
                # 0x1000; restrict the search to the .text section
                # of the relocatable object
                sect = None
                land = None
                for line in dtext.splitlines():
                    if line.startswith('Disassembly of section'):
                        sect = line
                    elif (sect is not None
                          and '.text' in sect
                          and (f'mov\tr12,{hex(RETCELL)}' in line
                               or f'mov\tr12,{RETCELL}' in line)):
                        land = 0x1000 + int(line.split(':')[0].strip(),
                                            16)
                        break
                assert land is not None, name
                patched = asm.replace(
                    f' mov blink,{hex(BLINK_PLACEHOLDER)}\n',
                    f' mov blink,{hex(land)}\n')
                assert patched != asm, name
                # push_s blink stores the patched land value at
                # [0xC8EFFC]: the millicode epilogue reads blink
                # from MEMORY, not from the live register
                (out / f'{name}.s').write_text(patched)
                asm = patched
                results.setdefault('micro_land', {})[name] = hex(land)
            case, sim_text = build_case(name, asm, sp['wins'],
                                        stub_sections)
            assert case['exit_code'] == 11, (name, case)
            fault = case['fault']
            assert fault is not None \
                and fault['operation'] == 'read', (name, fault)
            addr = int(fault['address'], 16)
            assert addr == success, (name, fault, hex(success))
            assert PROBE_AT <= int(fault['pc'], 16) \
                < PROBE_AT + 0x2000, (name, fault)
            cases.append(dict(name=name, entry=hex(sp['entry']),
                              success=hex(success),
                              exit_code=case['exit_code'],
                              instructions=case['instructions'],
                              fault=fault))
            print(f'PASS {name} -> {hex(success)}', flush=True)

        results['cpu_cases'] = cases
        results['stub_map'] = {hex(a): STUBS[a] for a in STUBS}
        results['frame'] = dict(fp=hex(FP), locals321=[
            hex(LOCAL3), hex(LOCAL2), hex(LOCAL1)],
            frame12=hex(FRAME12))
        results['status'] = 'PASS_ASLV_RING_WRITER_CPU'
        print('PASS_ASLV_RING_WRITER_CPU', stamp)
        print('Evidence:', out / 'verified_evidence.json')
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'verified_evidence.json').write_text(
            json.dumps(results, indent=2, default=str) + '\n')


if __name__ == '__main__':
    main()
