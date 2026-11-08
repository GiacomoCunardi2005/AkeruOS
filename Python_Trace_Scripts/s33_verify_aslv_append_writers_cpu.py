#!/usr/bin/env python3
"""Nikon COOLPIX S33 - AutoSceneLiveView append writers 0x4110/0x4111 (it.41).

Closes the open point left by iteration 39 (report
S33_GUI_AutoSceneLiveView_Ring_Writer_65C720_CPU_20261101.md, prossimo
passo (a)): the two remaining writers of the gate/ring subsystem were
decoded only statically (it.37) and never executed. Question: do the
handlers of events 0x4110/0x4111 really APPEND 9/0xA to the ring at
[0x47BBB8+4*gate] WITHOUT resetting the gate byte [0x47BBC8], with the
guard word[0x47BBB4+4*gate] != 0xA, incrementing the gate, and what do
their tails do?

Registry (p3, block_03): 0x783C10 (0x4110) -> 0x65CC40, 0x783C18 (0x4111)
-> 0x65CCC8, terminator (0, 0x20E814) at 0x783C40. LE census: the only
references; 0x65CC40 has ZERO bl callers, 0x65CCC8 has ONE direct bl
caller at 0x65B53A inside the handler of events 0x380/0x400 (0x65B3A8,
which also reads and DECREMENTS the gate when the last word == 0xA).

Static decode (GNU ARC700, original bytes, block 2; window
0x65CC18..0x65CD54, pools 0x65CC20..0x65CC3C):

handler 0x4110 @ 0x65CC40 (r13=node, r14=ev, r15=arg):
  push_s blink; bl 0x33412C (millicode push r15,r14,r13; j_s [blink]);
  st.aw fp,[sp,-4]; mov fp,sp;
  r0 = 0x135A84(node,ev,arg); btst r0,1; bne -> tail;
  if bit1 clear: r0=6; bl 0x65BE24; r0=0; bl 0xDECD4; bl 0xDD094;
  r0=1; bl 0x149DF4;
  r1 = pool 0x65CC24 (0x47BBB8 ring); r2 = 9;
  r0 = ldb [ring+0x10] (gate 0x47BBC8);
  gate==0 -> beq 0x65CC8C unconditional append;
  gate>0  -> ble 0x65CC96 is dead (zero-extended byte, it.37 lesson);
  r3 = word[pool 0x65CC28 + 4*gate] (0x47BBB4+4*gate); == 0xA ->
  NO append; else st 9,[ring+4*gate] (add2, scale x4); gate+1;
  bl 0x65DAD0; bl 0x145150(node); r0=9; bl 0x177030; r0=0;
  bl 0x145D1C; r2 = pool 0x65CC2C (ctx 0x681F5C):
  [ctx+0x10] := ret(0x145D1C); [ctx+0x14] := 0x47BBB8; [ctx+0xD] := 1;
  tail 0x65CCB8: r0=0; r1=r14(0x4110); r2=r15(arg);
  bl 0x20E814(0, 0x4110, arg); b 0x659588 at 0x65CCC2 (PC==2 mod 4,
  displacement -14136). EMPIRICAL TRACE (pinned engine, sim sha256
  7d6ccd1b...): the simulator executes this b CORRECTLY (pc <- 0x659588,
  trace line '0x65ccc2 b 0x659588'); the precautionary syncret
  trampoline placed at 0x65D588 (the it.44 wrap target hypothesis) is
  DEAD CODE, never executed. Same for the aligned b at 0x65CD50.
  The it.44 wrap lesson does NOT reproduce at this site with this
  engine; kept as a documented harmless safeguard.

handler 0x4111 @ 0x65CCC8 (r14=node, r13=ev, r15=arg):
  same prologue/gates; value 0xA (r3); NO 0x177030 call;
  same ctx writes; then 0x20E814(node, 0x4111, arg) with r0=NODE;
  then ALWAYS 0x14941C -> if 0 -> 0x177460; b 0x659588 at 0x65CD50
  (PC==0 mod 4, executed correctly by the sim, RW/h100 precedent);
  bit1-set skip path: only 0x14941C/0x177460, no ring/ctx/20E814.

Epilogue 0x659588 (original): mov sp,fp; ld.ab fp,[sp,4];
b 0x334194 -> millicode pop (r12=4, r13=0xC): ld r15,[sp,8];
ld r14,[sp,4]; ld.ab r13,[sp,0xC]; ld.ab blink,[sp,4]; j_s [blink]
-> returns to the harness with the FULL frame balance proven
(push_s blink + millicode push r15/r14/r13 + fp save/restore).

CPU cases (14, original windows; entry with r0=NODE, r1=ev, r2=ARG):
 0 w4110_append_gate1   gate=1, ring[0]=0xD -> ring[1]=9, gate=2,
                        20E814(0, 0x4110, ARG), ctx+0x10=0x600D
 1 w4110_guard_lastA    gate=1, ring[0]=0xA -> NO append, gate=1,
                        tail calls still run (65DAD0 gets gate_old)
 2 w4110_gate0          gate=0 -> NO guard read, 9 at ring[0], gate=1
 3 w4110_append_gate2   gate=2, ring[1]=9 -> 9 at ring[2], gate=3
                        (consecutive 9s allowed: guard checks 0xA)
 4 w4110_bit1_skip      135A84 bit1 set -> only 20E814(0,0x4110,ARG)
 5 w4110_gate_ff        gate=0xFF, word 0x33 -> 9 at 0x47BFB4,
                        gate byte wraps 0x00, register r0=0x100
 6 w4111_append_gate1   gate=1, ring[0]=5 -> 0xA at ring[1], gate=2,
                        20E814(NODE, 0x4111, ARG), queue 14941C/177460
 7 w4111_guard_lastA    gate=1, ring[0]=0xA -> NO append, gate=1
 8 w4111_gate0          gate=0 -> 0xA at ring[0], gate=1, 65DAD0
                        receives r0=EA=0x47BBB8
 9 w4111_bit1_skip      135A84 bit1 set -> ONLY 14941C(2,...)/177460,
                        no 20E814, no ring/ctx writes
10 w4111_q14941c_ne0    14941C returns 0x55 -> NO 177460, ret 0x55
11 w4111_gate_ff_guard  gate=0xFF, word 0xA -> GUARD BLOCKS, gate
                        stays 0xFF, 0x47BFB4 sentinel intact
12 dbl_4111_twice       two calls: first appends 0xA (gate 1->2),
                        second blocked by guard (ring[1]==0xA),
                        gate stays 2
13 dbl_9_then_A         0x4110 then 0x4111: 9 at slot 1, then 0xA at
                        slot 2, gate 1->2->3 (mixed append chain)

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
RETCELL2 = 0x367708          # second call return (double cases)
SCNT = 0x369000              # per-sid call counters (fixture zeroed)
RETSEQ = 0x369800            # 4 return values per sid (fixture)
NSEQ = 4

CTX = 0x681F5C               # AutoSceneLiveView context (pool 0x65CC2C)
RING = 0x47BBB8              # ring base (pool 0x65CC24)
TBL_BASE = 0x47BBB4          # guard table base (pool 0x65CC28)
GATE_BYTE = 0x47BBC8         # RING+0x10
RING_FIX = 0x47BBB0          # fixture base (covers 0x47BBB0..0x47C010)
FF_WORD = 0x47BFB0           # table[0xFF] (guard read at gate=0xFF)
FF_SLOT = 0x47BFB4           # ring slot 0xFF

E4110 = 0x65CC40             # handler event 0x4110
E4111 = 0x65CCC8             # handler event 0x4111
EPI = 0x659588               # shared ASLV epilogue
SYNCRET_AT = 0x65D588        # sim landing of the 0x65CCC2 b (PC==2 mod 4)

NODE = 0x1234
EV4110 = 0x4110
EV4111 = 0x4111
ARG = 0x7B
SENT = 0xA5A5A5A5
VAL9 = 9
VALA = 0xA

# original windows (payload, lo, hi, section)
W_H41 = (2, 0x65CC18, 0x65CD54, '.h41')
W_EPI = (2, 0x659588, 0x659594, '.epi')
W_MILI = (0, 0x334100, 0x3341E4, '.mili')
WINS_MAIN = [W_H41, W_EPI, W_MILI]

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
EPI_HEX = '0a24c03604141b3405044e6d'
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
(S135A84, S65BE24, SDECD4, SDD094, S149DF4, S65DAD0) = range(1, 7)
(S145150, S177030, S145D1C, S20E814, S14941C, S177460) = range(7, 13)

STUBS = {
    0x135A84: S135A84, 0x65BE24: S65BE24, 0xDECD4: SDECD4,
    0xDD094: SDD094, 0x149DF4: S149DF4, 0x65DAD0: S65DAD0,
    0x145150: S145150, 0x177030: S177030, 0x145D1C: S145D1C,
    0x20E814: S20E814, 0x14941C: S14941C, 0x177460: S177460,
}
MAXSID = max(STUBS.values())


def harness(calls):
    """calls = [(entry, [r0, r1, r2]), ...]; return values stored in
    RETCELL (first call) and RETCELL2 (second call, if any)."""
    text = ('.section .text,"ax",@progbits\n.global _start\n_start:\n'
            f' mov sp,{hex(STACK)}\n')
    for i, (entry, args) in enumerate(calls):
        cell = RETCELL if i == 0 else RETCELL2
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


def syncret_section():
    """Precautionary landing pad at the it.44 wrap target hypothesis
    for the 0x65CCC2 b (PC==2 mod 4, displacement -14136). EMPIRICAL
    TRACE: the pinned engine executes that b correctly (pc <-
    0x659588), so this pad is DEAD CODE, never executed; it is kept
    only as a documented safeguard against engine divergence."""
    return (f'.section .syncret,"ax",@progbits\n .org 0\n'
            f' mov r12,{hex(EPI)}\n'
            ' j_s [r12]\n')


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
    return bytes(b'\xA5' * 0xD0)


def ring_fixture(gate, slots, ffword=None):
    """0x4C0 bytes at 0x47BBB0. slots: {abs_addr: word}."""
    buf = bytearray(b'\xA5' * 0x4C0)
    buf[GATE_BYTE - RING_FIX] = gate & 0xFF
    for addr, w in slots.items():
        struct.pack_into('<I', buf, addr - RING_FIX, w)
    if ffword is not None:
        struct.pack_into('<I', buf, FF_WORD - RING_FIX, ffword)
    return bytes(buf)


def base_fix(gate, slots, ffword=None, retseq=None):
    return [('.ctxfix', CTX, ctx_fixture()),
            ('.ringfix', RING_FIX,
             ring_fixture(gate, slots, ffword)),
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


def ctx_asserts(touched, ret145d=0):
    if touched:
        return [(CTX + 0xC, 1, 0xA5),   # NOT touched (unlike 0x65C720)
                (CTX + 0xD, 1, 1),
                (CTX + 0x10, 4, ret145d),
                (CTX + 0x14, 4, RING)]
    return [(CTX + 0xC, 1, 0xA5),
            (CTX + 0xD, 1, 0xA5),
            (CTX + 0x10, 4, SENT),
            (CTX + 0x14, 4, SENT)]


def spec(name, calls, rets, logs, mem, gate, slots, ffword=None,
         ffslot=SENT, touched=True, ret145d=0, double=False):
    seq = {sid: ([v] * NSEQ if not isinstance(v, list) else v)
           for sid, v in rets.items()}
    retseq = bytearray(NSEQ * 4 * (MAXSID + 1))
    for sid in range(MAXSID + 1):
        vals = seq.get(sid, [0] * NSEQ)
        assert len(vals) <= NSEQ
        for k, v in enumerate(vals):
            struct.pack_into('<I', retseq, NSEQ * 4 * sid + 4 * k,
                             v & 0xFFFFFFFF)
    fix = base_fix(gate, slots, ffword, bytes(retseq))
    asserts = []
    for i, (sid, a0, a1, a2) in enumerate(logs):
        asserts += L(i, sid, a0, a1, a2)
    n = len(logs)
    asserts += [(CNT, 4, n)]
    asserts += L(n, 0, None, None, None)   # no extra calls
    asserts += [(RETCELL, 4, mem['ret'])]
    if double:
        asserts += [(RETCELL2, 4, mem['ret2'])]
    asserts += ring_asserts(mem['gate'], mem.get('ring0', SENT),
                            mem.get('ring1', SENT),
                            mem.get('ring2', SENT),
                            mem.get('ring3', SENT))
    if ffword is not None:
        asserts += [(FF_WORD, 4, ffword), (FF_SLOT, 4, ffslot)]
    asserts += ctx_asserts(touched, ret145d)
    return dict(name=name, calls=calls, stubs=list(STUBS), fix=fix,
                asserts=asserts, double=double)


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'aslv_append_writers_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, _ = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp,
                   action='aslv-append-writers-cpu',
                   limits=['Static analysis + 14 synthetic CPU cases; '
                           'no hardware',
                           'Deep callees are stubs; originals executed: '
                           'the whole handler bodies 0x65CC40/0x65CCC8, '
                           'millicode push/pop 0x33412C/0x334194, shared '
                           'epilogue 0x659588; the final b of handler '
                           '0x4110 (0x65CCC2, PC==2 mod 4) is executed '
                           'CORRECTLY by the pinned engine (traced '
                           'pc <- 0x659588); the syncret trampoline at '
                           '0x65D588 (it.44 wrap hypothesis) is dead '
                           'code, kept as a documented safeguard',
                           'ctx 0x681F5C, ring 0x47BBB0..0x47C010 and '
                           'gate byte 0x47BBC8 are RUNTIME cells in the '
                           'load gap 0x428600..0x5FE800: '
                           'fixture-imposed, NOT verifiable from the '
                           'dump',
                           'The returns of the stubbed callees and the '
                           '135A84 gate bit are imposed by the bench',
                           'No physical button map, no hardware, no '
                           'scheduling; V1.1 dump only; NON_INSTALLARE'])
    try:
        p0, p2, p3 = payloads[0], payloads[2], payloads[3]

        # --- 1. static: pools --------------------------------------
        pools = {0x65CC20: 0x3181, 0x65CC24: RING, 0x65CC28: TBL_BASE,
                 0x65CC2C: CTX, 0x65CC30: 0x3669EC, 0x65CC34: 0x442644,
                 0x65CC38: 0x1388, 0x65CC3C: 0x307F}
        for a, v in pools.items():
            got = struct.unpack_from('<I', p2, a - base[2])[0]
            assert got == v, (hex(a), hex(got), hex(v))
        results['pools'] = {hex(a): hex(v) for a, v in pools.items()}

        # --- 2. static: event registry -----------------------------
        reg = [(0x783C10, EV4110), (0x783C14, E4110),
               (0x783C18, EV4111), (0x783C1C, E4111),
               (0x783C40, 0), (0x783C44, 0x20E814),
               (0x783B58, 0x380), (0x783B5C, 0x65B3A8),
               (0x783B68, 0x400), (0x783B6C, 0x65B3A8)]
        for a, v in reg:
            got = struct.unpack_from('<I', p3, a - base[3])[0]
            assert got == v, (hex(a), hex(got), hex(v))
        results['registry'] = ('p3 pairs (event,handler): 0x4110->'
                               '0x65CC40, 0x4111->0x65CCC8, terminator '
                               '(0,0x20E814); 0x380/0x400->0x65B3A8 '
                               '(direct 0x4111 caller)')

        # --- 3. static: opcode freezes ------------------------------
        freezes = [
            ('handlers_win', 2, 0x65CC18, H41_HEX),
            ('epi', 2, 0x659588, EPI_HEX),
            ('millicode_win', 0, 0x334100, MILI_HEX)]
        for name, idx, addr, hexstr in freezes:
            data = payloads[idx][addr - base[idx]:
                                addr - base[idx] + len(hexstr) // 2]
            assert data.hex() == hexstr, (name, data.hex())
        results['opcode_freezes'] = 'ok'

        # --- 4. static: add2 semantics in the pinned engine ---------
        sem = (LEGACY / 'source/gnu-arc700-sim-src/sim/arc/sem7.c')
        text = sem.read_text()
        i = text.index('SEM_FN_NAME (arc700f,add2_L_r_r__RA__RC)')
        body = text[i:i + 2000]
        assert 'SLLSI (GET_H_CR (FLD (f_op_C)), 2)' in body
        results['add2_engine_semantics'] = dict(
            source=str(sem),
            sha256=hashlib.sha256(text.encode()).hexdigest(),
            rule='add2 rA,rB,rC = rB + (rC << 2)',
            site='sem7.c add2_L_r_r__RA__RC')

        # --- 5. static: LE + bl census -----------------------------
        le4110 = le_scan(payloads, base, E4110)
        le4111 = le_scan(payloads, base, E4111)
        assert le4110 == [(3, 0x783C14, 0)], le4110
        assert le4111 == [(3, 0x783C1C, 0)], le4111
        results['le_census'] = {
            hex(E4110): [tuple(hex(v) for v in t) for t in le4110],
            hex(E4111): [tuple(hex(v) for v in t) for t in le4111]}

        objcopy = ROOT / 'work/build-arc/binutils/objcopy'
        objdump = ROOT / 'work/build-arc/binutils/objdump'
        assert objcopy.is_file() and objdump.is_file()
        census = {E4110: [], E4111: []}
        with tempfile.TemporaryDirectory(prefix='it41-census-') as td:
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
                    for tgt in (E4110, E4111):
                        if f';0x{tgt:x}' in line:
                            parts = [p for p in line.split('\t') if p]
                            addr = int(parts[0].strip().rstrip(':'), 16)
                            mn = (parts[2].strip()
                                  if len(parts) > 2 else '')
                            assert mn.startswith('bl'), (line, mn)
                            census[tgt].append((b['index'], addr))
        assert census[E4110] == [], census[E4110]
        assert census[E4111] == [(2, 0x65B53A)], census[E4111]
        results['bl_census'] = {
            hex(E4110): [], hex(E4111): [(f'b{i}', hex(a))
                                         for i, a in census[E4111]]}

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
                                   action='aslv-append-writers-cpu'))
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
                + f'  .syncret {hex(SYNCRET_AT)} : {{ *(.syncret) }}\n'
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

        # shared head: gates + pre-steps (handler 0x4110)
        def P0(ev, d9140):
            return [(S135A84, NODE, ev, ARG),
                    (S65BE24, 6, ev, ARG),
                    (SDECD4, 0, ev, ARG),
                    (SDD094, 0, ev, ARG),
                    (S149DF4, 1, ev, ARG),
                    (S65DAD0, d9140[0], RING, d9140[1]),
                    (S145150, NODE, RING, d9140[1]),
                    (S177030, VAL9, RING, d9140[1]),
                    (S145D1C, 0, RING, d9140[1]),
                    (S20E814, 0, ev, ARG)]

        # shared head + queue tail (handler 0x4111)
        def P1(ev, dad0, gate_r2, tail=True):
            out = [(S135A84, NODE, ev, ARG),
                   (S65BE24, 6, ev, ARG),
                   (SDECD4, 0, ev, ARG),
                   (SDD094, 0, ev, ARG),
                   (S149DF4, 1, ev, ARG),
                   (S65DAD0, dad0, RING, gate_r2),
                   (S145150, NODE, RING, gate_r2),
                   (S145D1C, 0, RING, gate_r2)]
            if tail:
                out += [(S20E814, NODE, ev, ARG),
                        (S14941C, 0, ev, ARG),
                        (S177460, 0, ev, ARG)]
            return out

        # 0 append 9, gate 1 -> 2, 145D1C propagation 0x600D
        SPECS.append(spec(
            'w4110_append_gate1', [(E4110, [NODE, EV4110, ARG])],
            {S145D1C: 0x600D},
            P0(EV4110, (2, VAL9)),
            dict(ret=0, gate=2, ring0=0xD, ring1=VAL9),
            gate=1, slots={0x47BBB8: 0xD}, ret145d=0x600D))

        # 1 guard: last word 0xA -> NO append, tail still runs
        SPECS.append(spec(
            'w4110_guard_lastA', [(E4110, [NODE, EV4110, ARG])], {},
            P0(EV4110, (1, VAL9)),
            dict(ret=0, gate=1, ring0=VALA),
            gate=1, slots={0x47BBB8: VALA}))

        # 2 gate 0: unconditional append at slot 0
        SPECS.append(spec(
            'w4110_gate0', [(E4110, [NODE, EV4110, ARG])], {},
            P0(EV4110, (1, VAL9)),
            dict(ret=0, gate=1, ring0=VAL9),
            gate=0, slots={}))

        # 3 gate 2, last=9 (slot1): consecutive 9s ALLOWED
        SPECS.append(spec(
            'w4110_append_gate2', [(E4110, [NODE, EV4110, ARG])], {},
            P0(EV4110, (3, VAL9)),
            dict(ret=0, gate=3, ring1=VAL9, ring2=VAL9),
            gate=2, slots={0x47BBBC: VAL9}))

        # 4 bit1 set -> skip everything, only 20E814(0, 0x4110, ARG)
        SPECS.append(spec(
            'w4110_bit1_skip', [(E4110, [NODE, EV4110, ARG])],
            {S135A84: 0x2},
            [(S135A84, NODE, EV4110, ARG),
             (S20E814, 0, EV4110, ARG)],
            dict(ret=0, gate=1, ring0=0xD),
            gate=1, slots={0x47BBB8: 0xD}, touched=False))

        # 5 gate 0xFF: append at 0x47BFB4, gate byte wraps to 0
        SPECS.append(spec(
            'w4110_gate_ff', [(E4110, [NODE, EV4110, ARG])], {},
            P0(EV4110, (0x100, VAL9)),
            dict(ret=0, gate=0),
            gate=0xFF, slots={}, ffword=0x33, ffslot=VAL9))

        # 6 append 0xA, gate 1 -> 2
        SPECS.append(spec(
            'w4111_append_gate1', [(E4111, [NODE, EV4111, ARG])], {},
            P1(EV4111, 0x47BBBC, 2),
            dict(ret=0, gate=2, ring0=5, ring1=VALA),
            gate=1, slots={0x47BBB8: 5}))

        # 7 guard blocks the second 0xA
        SPECS.append(spec(
            'w4111_guard_lastA', [(E4111, [NODE, EV4111, ARG])], {},
            P1(EV4111, VALA, 1),
            dict(ret=0, gate=1, ring0=VALA),
            gate=1, slots={0x47BBB8: VALA}))

        # 8 gate 0: 0xA at slot 0; 65DAD0 receives the EA as r0
        SPECS.append(spec(
            'w4111_gate0', [(E4111, [NODE, EV4111, ARG])], {},
            P1(EV4111, RING, 1),
            dict(ret=0, gate=1, ring0=VALA),
            gate=0, slots={}))

        # 9 bit1 set -> only the queue drain, no ring/ctx/20E814
        SPECS.append(spec(
            'w4111_bit1_skip', [(E4111, [NODE, EV4111, ARG])],
            {S135A84: 0x2},
            [(S135A84, NODE, EV4111, ARG),
             (S14941C, 0x2, EV4111, ARG),
             (S177460, 0, EV4111, ARG)],
            dict(ret=0, gate=1, ring0=5),
            gate=1, slots={0x47BBB8: 5}, touched=False))

        # 10 14941C != 0 -> NO 177460, ret 0x55
        SPECS.append(spec(
            'w4111_q14941c_ne0', [(E4111, [NODE, EV4111, ARG])],
            {S14941C: 0x55},
            P1(EV4111, 0x47BBBC, 2)[:-1],
            dict(ret=0x55, gate=2, ring0=5, ring1=VALA),
            gate=1, slots={0x47BBB8: 5}))

        # 11 gate 0xFF with last word 0xA -> guard blocks, gate stays
        SPECS.append(spec(
            'w4111_gate_ff_guard', [(E4111, [NODE, EV4111, ARG])], {},
            P1(EV4111, VALA, 0xFF),
            dict(ret=0, gate=0xFF),
            gate=0xFF, slots={}, ffword=VALA, ffslot=SENT))

        # 12 double 0x4111: append then guard-blocked second call
        SPECS.append(spec(
            'dbl_4111_twice',
            [(E4111, [NODE, EV4111, ARG]),
             (E4111, [NODE, EV4111, ARG])],
            {S135A84: [0x8, 0x8]},
            P1(EV4111, 0x47BBBC, 2) + P1(EV4111, VALA, 2),
            dict(ret=0, ret2=0, gate=2, ring0=3, ring1=VALA),
            gate=1, slots={0x47BBB8: 3}, double=True))

        # 13 mixed chain: 9 (slot 1) then 0xA (slot 2), gate 1->2->3
        SPECS.append(spec(
            'dbl_9_then_A',
            [(E4110, [NODE, EV4110, ARG]),
             (E4111, [NODE, EV4111, ARG])],
            {S135A84: [0x8, 0x8]},
            P0(EV4110, (2, VAL9)) + P1(EV4111, 0x47BBC0, 3),
            dict(ret=0, ret2=0, gate=3, ring0=3, ring1=VAL9,
                 ring2=VALA),
            gate=1, slots={0x47BBB8: 3}, double=True))

        cases = []
        for idx, sp in enumerate(SPECS):
            name = sp['name']
            success = 0xDEADB001 + idx
            for a in sp['stubs']:
                for (_, wlo, whi, _) in WINS_MAIN:
                    assert not (wlo <= a < whi), (hex(a), hex(wlo))
                assert not (SYNCRET_AT <= a < SYNCRET_AT + 10), hex(a)
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
                   + syncret_section()
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
        results['status'] = 'PASS_ASLV_APPEND_WRITERS_CPU'
        print('PASS_ASLV_APPEND_WRITERS_CPU', stamp)
        print('Evidence:', out / 'verified_evidence.json')
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'verified_evidence.json').write_text(
            json.dumps(results, indent=2, default=str) + '\n')


if __name__ == '__main__':
    main()
