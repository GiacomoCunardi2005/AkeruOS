#!/usr/bin/env python3
"""Static + CPU verification of the AutoSceneLiveView OPEN handler 0x659554
(event 0x4401, first record of the window notify registry p3 0x783B08) of the
Nikon S33 firmware (V1.1).

Closes the open point of iteration 25 (checkpoint 2026-11-01): decode and
CPU-prove the window open/lifecycle handler named by the p3 registry record
{0x4401, 0x659554}, and settle the "second registry p6 0xAF5F08" question.

Facts asserted here (byte-exact on the verified payloads + 10 CPU cases on
the GNU ARC700 simulator executing ORIGINAL firmware bytes):

- REGISTRY p3 0x783B08: the 0x4401 record is the FIRST record of the table
  (39 records + terminator {0, 0x20E814} at 0x783C40); handler 0x659554.
  The window event wrapper 0x6593A0 FILTERS events to [0x80..0x307F]
  (cmp 128 / blt 0x65952a, cmp_s 0x307F / bgt 0x65952a on ORIGINAL bytes):
  0x4401 > 0x307F therefore does NOT reach the registry through the
  wrapper; delivery comes from another path (WM service candidate
  0x16A05C, iteration 24, open).

- OPEN HANDLER 0x659554(node, ev, arg) [window 0x659554..0x65959C,
  pools 0x659594=0x681F5C (context), 0x659598=0x47BBC8 (gap cell)]:
  push_s blink; bl 0x33412C (millicode push r15,r14,r13); r14=node,
  r15=ev (NEVER used), r13=arg;
  1. bl 0x65D6A0(node);
  2. [ctx+8]  := 0xFF;
  3. [0x47BBC8] := 0;
  4. g := 0xCA310() (guard getter, byte 0x365751 via pool 0xCA30C);
  5. [ctx+9]  := g;
  6. bl 0xCA2F4(g) (guard setter writes 0x365751 := g, VALUE-PRESERVING
     write-back, unlike 0x20F414/0x4006 which clears the guard);
  7. [ctx+0x18] := arg;
  tail b 0x334194 (millicode pop).

- HELPER 0x65D6A0 [window 0x65D6A0..0x65D6D0, pool 0x65D6CC=0x681FBC
  (= ctx+0x60)]: [ctx+0x60] := node; bl 0x65C920() (leaf: j_s.d [blink]
  with delay-slot ld_s r0,[pcl,0x4] -> pool 0x65C924 = 0x47BBB8, i.e. it
  returns the CONSTANT POINTER 0x47BBB8, it does NOT dereference it);
  [ctx+0x68] := 0x47BBB8 (constant, not a snapshot); bl 0x189D78(r0
  ignored by callee). 0x47BBC8 = 0x47BBB8+0x10 is the struct cell zeroed
  by the handler; both 0x47BBB8/0x47BBC8 are words in the
  0x428600..0x5FE800 GAP not covered by any payload: runtime cells.

- RESOURCE REQUEST 0x189D78 [window 0x189D78..0x189DD0, pool
  0x189DCC=0x3ABA38 (class-1 resource, ID 0x4A12)]: locals [fp-8]=0(h),
  [fp-4]=0; 0x18AC58(&[fp-4]); v=[fp-4]; if v==1 or v==3 -> id 0x41 else
  0xCB70C(&[fp-8]) computes id; 0x633768(0x3ABA38, id, 0). Called by 33
  sites (p0:15, p2:8, p4:10); 0x65D6A0 and 0x65C920 have exactly ONE bl
  caller each (inside this chain); 0x659554 has ZERO bl callers (pure
  registry callback).

- p6 0xAF5F08 IS NOT A REGISTRY (disproof of the it.25 note): the word
  0x659554 at 0xAF5F08 sits inside a byte3==0 word array (a data/ramp-like
  blob spanning at least 0xAF5708..0xAF6708 verified here); the putative
  {u16 ev, u16 pad, u32 handler} record has pad 0x0065 != 0 and NO payload
  contains an aligned word 0x00AF5F08 (no pointer to the table). The LE
  word 0x659554 appears exactly twice in all 16 payloads: the p3 registry
  field 0x783B0C and the p6 data word 0xAF5F08.

- Context 0x681F5C is shared: 20 aligned LE words across the 0x659xxx..
  0x65Dxxx handler family pools; 0x681FBC (ctx+0x60): 9 pools;
  0x47BBB8: 7 pools; 0x47BBC8: 3 pools (0x659598, 0x65A3B0, 0x65C400).
  Dump initial state: ctx+8 = 0xFF (already open in the dump), ctx+9 = 0,
  ctx+0x18 = 0, ctx+0x60 = 0, ctx+0x68 = 0x00040A04, guard 0x365751 = 0.

CPU cases (original windows: handler 0x659554..0x65959C, helper
0x65D6A0..0x65D6D0, leaf 0x65C920..0x65C928, resource 0x189D78..0x189DD0,
guard getter+setter 0xCA2F4..0xCA318, millicode 0x334114..0x33413A /
0x33417C..0x3341E4; stubs log {id,r0,r1,r2} at 0x367100+16k, counter
0x367000; 0x18AC58/0xCB70C are pointer-store stubs that write their
RETTAB return value through the r0 pointer, word/halfword):
 1 open_basic        guard 0xA5, arg 0x77, [0x47BBB8]=0x11223344,
                     0x18AC58 stores 1 -> 0x633768(0x3ABA38, 0x41, 0)
 2 open_state3       0x18AC58 stores 3 -> same 0x41 branch
 3 open_state0_else  0x18AC58 stores 0 -> 0xCB70C path, id 0x99
 4 open_else_2211    0x18AC58 stores 2 -> 0xCB70C writes 0x2211
 5 open_guard_zero   guard 0 -> ctx+9 = 0, guard rewritten 0
 6 open_guard_seven  guard 7 (the CaptureMenu special guard) snapshot
 7 open_guard_dump   guard struct = dump bytes, all 8 bytes preserved
 8 open_arg_zero     arg 0 -> ctx+0x18 = 0 (write of zero proven)
 9 open_gap_dead0005 [0x47BBB8]=0xDEAD0005 -> ctx+0x68 = 0xDEAD0005
10 open_ev_ignored   ev r1 = 0x5555 -> identical behaviour (r1 dead)

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
PROBE_AT = 0x169800
COMMON_AT = 0x169000
CNT = 0x367000
LOG_ENT = 0x367100
RETTAB = 0x367400

# original windows (payload, lo, hi, section)
W_MILI_PUSH = (0, 0x334114, 0x33413A, '.mcpush')
W_MILI_POP = (0, 0x33417C, 0x3341E4, '.mcpop')
W_OPEN = (2, 0x659554, 0x65959C, '.open')       # handler + pools
W_HELPER = (2, 0x65D6A0, 0x65D6D0, '.helper')   # 0x65D6A0 + pool 0x65D6CC
W_LEAF = (2, 0x65C920, 0x65C928, '.leaf')       # j_s.d + ld_s + pool
W_RES = (0, 0x189D78, 0x189DD0, '.res')         # resource request + pool
W_GUARD = (0, 0xCA2F4, 0xCA318, '.guard')       # setter + pool + getter

ALL_WINS = [W_MILI_PUSH, W_MILI_POP, W_OPEN, W_HELPER, W_LEAF,
            W_RES, W_GUARD]

# stubs: address -> sid (1/2 write through r0 pointer, word/halfword)
STUBS = {0x18AC58: 1, 0xCB70C: 2, 0x633768: 3}

NODE = 0x1234
ARG = 0x77
EV_OPEN = 0x4401

REG_P3 = 0x783B08            # AutoSceneLiveView notify registry
CTX = 0x681F5C               # window context
GUARD = 0x365751             # guard byte
GAP_WORD = 0x47BBB8          # runtime word in the payload gap
GAP_BYTE = 0x47BBC8          # runtime byte in the payload gap
REG_P6 = 0xAF5F08            # data word coincidentally equal to 0x659554

# static freezes (byte-exact, LE)
FR_OPEN = ('f1c0da0b4e6dfc1cc8b60a2300370876287748753a0900020ad0ffd928a8'
           '0ad000d920a89a0d4d3806d109a9760d4d3804d0a6a00a24c03604141b34'
           '05044e6d5c1f6800c8bb4700')
FR_HELPER = ('f1c0920a4e6bfc1cc8b60a230037087507d600a66e0a8fff02a6c20e0'
             'd960a24c03604141b34d9024e6be078bc1f6800')
FR_LEAF = 'e07f01d0b8bb4700'
FR_RES = ('f1c0fc1cc8b60a230037a2c100d8f81b04b0fc1b00b042230031ca0e4000'
          'fc1300b081e003f283e005f441d8f81b04b005f0422300326209cfa007d0f8'
          '1341b100dab209c2540a24c03604141b34d1c0e07ee07838ba3a00')
FR_GUARD = ('fc1cc8b60a23003704d100a90a24c03604141b34e07ee078'
            '51573600fc1700f00088e07e')
FR_MCPUSH = 'fc1c48b5fc1c08b5fc1cc8b4fc1c88b4fc1c48b4fc1c08b4fc1cc8b3fc1c88b3fc1c48b3e07e'
FR_MCPOP = ('04dc18dd25f0e07804dc14dd23f0e07804dc10dd21f0e07804dc0cdd1ff0'
            'e07804dc08dd19f0e07804dc04dd19f034141a30301419302c1418302814'
            '173024141630201415301c1414301814133014141230101411300c141030'
            '02c701c6b0244d33b0241f33e07e')
FR_FILTER = '8c27029056010b00d77700007f304e010900'   # wrapper range filter
FR_WRAPPOOLS = '5c1f6800400d0300083b7800'            # 0x681F5C/0x30D40/p3


def harness(entry, args):
    text = ('.section .text,"ax",@progbits\n.global _start\n_start:\n'
            f' mov sp,{hex(STACK)}\n'
            + ''.join(f' mov r{k},{hex(v)}\n' for k, v in enumerate(args))
            + f' mov r12,{hex(entry)}\n'
            ' jl_s [r12]\n'
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
            f' mov r7,{hex(sid)}\n'
            f' mov r12,{hex(COMMON_AT)}\n'
            ' jl_s [r12]\n'
            ' pop_s blink\n'
            ' j_s [blink]\n')


def ptr_stub_body(sid, half=False):
    """Stub that writes its RETTAB return value through the r0 pointer
    (word for 0x18AC58, halfword for 0xCB70C). r8 is free in the stub
    contract; the common logger clobbers r0..r5,r7,r12 only."""
    return (' push_s blink\n'
            ' mov r8,r0\n'
            f' mov r7,{hex(sid)}\n'
            f' mov r12,{hex(COMMON_AT)}\n'
            ' jl_s [r12]\n'
            + (' sth r0,[r8,0]\n' if half else ' st r0,[r8,0]\n')
            + ' pop_s blink\n'
            ' j_s [blink]\n')


def common_logger():
    return (f'.section .common,"ax",@progbits\n .org 0\n'
            f' mov r3,{hex(CNT)}\n'
            ' ld r4,[r3,0]\n'
            ' asl r5,r4,4\n'
            f' mov r3,{hex(LOG_ENT)}\n'
            ' add r3,r3,r5\n'
            ' st r7,[r3,0]\n'
            ' st r0,[r3,4]\n'
            ' st r1,[r3,8]\n'
            ' st r2,[r3,12]\n'
            f' mov r3,{hex(CNT)}\n'
            ' ld r4,[r3,0]\n'
            ' add r4,r4,1\n'
            ' st r4,[r3,0]\n'
            f' mov r3,{hex(RETTAB)}\n'
            ' asl r4,r7,2\n'
            ' add r3,r3,r4\n'
            ' ld r0,[r3,0]\n'
            ' j_s [blink]\n')


def fixture_sections(fix):
    out = ''
    for name, base_addr, data in fix:
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
    return bytes([0xC5] * 0x70)          # 0x681F5C..0x681FCC sentinel fill


def guard_fixture(guard, dump=False):
    if dump:
        return bytes([0x02, guard, 0x01, 0x00, 0x01, 0xFF, 0x00, 0x00])
    return bytes([0x5A, guard, 0xA7, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F])


def gap_fixture(word):
    buf = bytearray([0xEE] * 0x18)        # 0x47BBB8..0x47BBD0
    struct.pack_into('<I', buf, 0, word)
    return bytes(buf)


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'aslv_open_handler_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, _ = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    size = {b['index']: len(payloads[b['index']]) for b in blocks}
    results = dict(status='RUNNING', utc=stamp, action='aslv-open-handler',
                   limits=['Static analysis + 10 synthetic CPU cases; no hardware',
                           '0x18AC58/0xCB70C/0x633768 are stubs; the open '
                           'handler, 0x65D6A0, the leaf getter 0x65C920, '
                           '0x189D78 and the guard getter/setter execute as '
                           'ORIGINAL bytes',
                           '0x47BBB8/0x47BBC8 are runtime cells in the payload '
                           'gap 0x428600..0x5FE800 (no dump bytes exist); '
                           'context/guard fixture values are imposed',
                           'The 0x4401 delivery path to the registry is NOT '
                           'proven here (wrapper filters it out; WM service '
                           '0x16A05C is the candidate, iteration 24)',
                           'bl/b delay-slot semantics: micro-test '
                           'tmp/it27/bltest shows the sim executes bl WITHOUT '
                           'running the following instruction before the '
                           'callee',
                           'No physical button map, no hardware, no '
                           'scheduling; V1.1 dump only; NON_INSTALLARE'])
    try:
        p2, p3, p6, p1, p0 = (payloads[2], payloads[3], payloads[6],
                              payloads[1], payloads[0])

        # --- 1. static: registry p3, 0x4401 first record ---------------
        recs = []
        k = 0
        while True:
            a = REG_P3 + 8 * k
            ev, pad, h = struct.unpack_from('<HHI', p3, a - base[3])
            recs.append((a, ev, pad, h))
            if ev == 0:
                break
            k += 1
        assert len(recs) == 40, len(recs)
        assert recs[0] == (REG_P3, 0x4401, 0, 0x659554), recs[0]
        assert recs[-1] == (REG_P3 + 8 * 39, 0, 0, 0x20E814), recs[-1]
        m = {ev: h for (_, ev, _, h) in recs[:-1]}
        for ev, h in ((0x580, 0x65C46C), (0x700, 0x65C46C),
                      (0x2180, 0x65C46C), (0x2700, 0x65C46C),
                      (0x581, 0x65C6B4), (0x2701, 0x65C6B4)):
            assert m[ev] == h, (hex(ev), hex(m[ev]))
        results['registry_p3'] = dict(
            n_records=39, first_record=['0x4401', '0', hex(0x659554)],
            open_handler=hex(0x659554))

        # --- 2. static: pools ------------------------------------------
        pools = {0x659594: 0x681F5C, 0x659598: 0x47BBC8,   # open handler
                 0x65D6CC: 0x681FBC,                        # helper
                 0x65C924: 0x47BBB8,                        # leaf getter
                 0x189DCC: 0x3ABA38,                        # resource req
                 0xCA30C: 0x365751,                        # guard set/get
                 0x659548: 0x681F5C, 0x65954C: 0x30D40,    # wrapper
                 0x659550: REG_P3}
        for a, v in pools.items():
            src, bb = (p2, base[2]) if a >= base[2] else (p0, base[0])
            got = struct.unpack_from('<I', src, a - bb)[0]
            assert got == v, (hex(a), hex(got), hex(v))
        results['pools'] = {hex(a): hex(v) for a, v in pools.items()}

        # --- 3. static: opcode freezes ---------------------------------
        freezes = [
            ('open_handler', 2, 0x659554, FR_OPEN),
            ('helper', 2, 0x65D6A0, FR_HELPER),
            ('leaf', 2, 0x65C920, FR_LEAF),
            ('resource', 0, 0x189D78, FR_RES),
            ('guard_setget', 0, 0xCA2F4, FR_GUARD),
            ('millicode_push', 0, 0x334114, FR_MCPUSH),
            ('millicode_pop', 0, 0x33417C, FR_MCPOP),
            ('wrapper_filter', 2, 0x6593D0, FR_FILTER),
            ('wrapper_pools', 2, 0x659548, FR_WRAPPOOLS),
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

        # --- 4. static: LE scans ----------------------------------------
        want = {
            0x659554: [(3, 0x783B0C, 0), (6, 0xAF5F08, 0)],
            0x65D6A0: [],
            0x65C920: [],
            0x189D78: [],
            0x681F5C: [(2, a, 0) for a in (
                0x659548, 0x659594, 0x65992C, 0x659CCC, 0x659F98, 0x65A3B8,
                0x65A704, 0x65AC4C, 0x65AFF8, 0x65B394, 0x65B5BC, 0x65B710,
                0x65B9CC, 0x65BEA0, 0x65C3FC, 0x65C910, 0x65CC2C, 0x65D0E8,
                0x65D58C, 0x65D694)],
            0x681FBC: [(2, a, 0) for a in (
                0x65D6CC, 0x65DB50, 0x65DCB4, 0x65E1B4, 0x65E204, 0x65E280,
                0x65E898, 0x65E8FC, 0x65EB0C)],
            0x47BBB8: [(2, a, 0) for a in (
                0x659CD4, 0x65AC48, 0x65B388, 0x65C914, 0x65C924, 0x65CC24,
                0x65D484)],
            0x47BBC8: [(2, a, 0) for a in (0x659598, 0x65A3B0, 0x65C400)],
        }
        le = {}
        for t, exp in want.items():
            hits = [(i, a, o) for (i, a, o) in le_scan(payloads, base, t)
                    if o == 0]
            assert hits == exp, (hex(t),
                                 [(i, hex(a), o) for i, a, o in hits],
                                 [(i, hex(a), o) for i, a, o in exp])
            le[hex(t)] = [(i, hex(a), o) for i, a, o in hits]
        results['le_scans'] = le

        # --- 5. static: p6 0xAF5F08 is data, not a registry -------------
        assert base[6] <= REG_P6 < base[6] + size[6]
        w = struct.unpack_from('<I', p6, REG_P6 - base[6])[0]
        assert w == 0x659554, hex(w)
        # byte3 == 0 across the verified blob window
        for off in range(0xAF5708 - base[6], 0xAF6708 - base[6], 4):
            assert p6[off + 3] == 0, hex(base[6] + off)
        # putative {u16 ev, u16 pad, u32 h} record: pad != 0
        pad = struct.unpack_from('<H', p6, REG_P6 + 2 - base[6])[0]
        assert pad == 0x0065, hex(pad)
        # no payload contains an aligned word pointing at the table
        ptr = struct.pack('<I', REG_P6)
        for i, pl in payloads.items():
            for off in range(0, len(pl) - 3, 4):
                assert pl[off:off + 4] != ptr, \
                    (i, hex(base[i] + off))
        # dump values of the context and guard (report, not fixture)
        ctx_dump = {
            'ctx+8': hex(p3[CTX + 8 - base[3]]),
            'ctx+9': hex(p3[CTX + 9 - base[3]]),
            'ctx+0x18': hex(p3[CTX + 0x18 - base[3]]),
            'ctx+0x60': hex(struct.unpack_from('<I', p3,
                                               CTX + 0x60 - base[3])[0]),
            'ctx+0x68': hex(struct.unpack_from('<I', p3,
                                               CTX + 0x68 - base[3])[0]),
            'guard 0x365751': hex(p1[0x365751 - base[1]]),
        }
        assert ctx_dump['ctx+8'] == '0xff'
        assert ctx_dump['guard 0x365751'] == '0x0'
        results['dump_initial_state'] = ctx_dump
        # gap cells are not covered by any payload
        for a in (GAP_WORD, GAP_BYTE):
            cov = [i for i in base
                   if base[i] <= a < base[i] + size[i]]
            assert cov == [], (hex(a), cov)
        results['p6_disproof'] = dict(
            word_at=hex(REG_P6), value=hex(0x659554), pad_halfword=hex(pad),
            blob_checked='0xAF5708..0xAF6708 byte3==0',
            pointer_refs=0)
        results['gap_cells'] = [hex(GAP_WORD), hex(GAP_BYTE),
                                'in gap 0x428600..0x5FE800']

        # --- 6. static: bl census on 16 GNU listings --------------------
        census = {0x659554: {}, 0x65D6A0: {}, 0x65C920: {}, 0x189D78: {}}
        objcopy = ROOT / 'work/build-arc/binutils/objcopy'
        objdump = ROOT / 'work/build-arc/binutils/objdump'
        assert objcopy.is_file() and objdump.is_file()
        with tempfile.TemporaryDirectory(prefix='it27-census-') as td:
            for b in blocks:
                idx = b['index']
                elf = Path(td) / f'b{idx}.elf'
                subprocess.run([str(objcopy), '-I', 'binary',
                                '-O', 'elf32-littlearc', '-B', 'arc',
                                '--rename-section',
                                '.data=.text,alloc,load,readonly,code,contents',
                                '--change-section-vma',
                                f".data={b['load_address_candidate']:#x}",
                                '--strip-all',
                                str(ROOT / 'S33-sections/TBM_blocks' / b['file']),
                                str(elf)], check=True, timeout=120)
                text = subprocess.run([str(objdump), '-d', '-m', 'arc:ARC700',
                                       '-EL', str(elf)],
                                      capture_output=True, text=True,
                                      check=True, timeout=280).stdout
                for t in census:
                    n = text.count(f';0x{t:x}')
                    if n:
                        census[t][idx] = n
        total = {t: sum(v.values()) for t, v in census.items()}
        assert total == {0x659554: 0, 0x65D6A0: 1, 0x65C920: 1,
                         0x189D78: 33}, total
        assert census[0x65D6A0] == {2: 1} and census[0x65C920] == {2: 1}
        assert census[0x189D78] == {0: 15, 2: 8, 4: 10}
        results['bl_census'] = {hex(k): {str(i): n for i, n in v.items()}
                                for k, v in census.items()}

        # --- 7. CPU cases ------------------------------------------------
        r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN,
                                   output=out, action='aslv-open-handler'))
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
                data = payloads[pidx][wlo - base[pidx]:whi - base[pidx]]
                orig = out / f'{name}_{section}.bin'
                orig.write_bytes(data)
                bo = out / f'{name}_{section}_bin.o'
                assert r.command(f'{name}_{section}_oc', [
                    TOOLCHAIN / 'arc-elf32-objcopy', '-I', 'binary',
                    '-O', 'elf32-littlearc', '-B', 'arc', '--rename-section',
                    f'.data={section},alloc,load,readonly,code,contents',
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
            cmd = [TOOLCHAIN / 'arc-elf32-ld', '-EL', '-T', ld, '-o', elf,
                   obj] + bin_objs
            assert r.command(f'{name}_ld', cmd).returncode == 0
            ep, segments = elf_loads(elf)
            assert ep == 0x1000, hex(ep)
            for (pidx, wlo, whi, section) in orig_windows:
                want_b = payloads[pidx][wlo - base[pidx]:whi - base[pidx]]
                by = [seg for seg in segments
                      if seg['address'] <= wlo
                      and wlo + (whi - wlo) <= seg['address'] + seg['size']]
                assert len(by) == 1, (hex(wlo), segments)
                data = by[0]['data'][wlo - by[0]['address']:]
                assert data[:whi - wlo] == bytes(want_b), hex(wlo)
            case, sim_text = r.run(name, '/result/' + f'{name}.elf')
            return case, sim_text

        # (name, guard, arg, ev, v47bbb8, rets, logs, dump_guard)
        specs = []

        def spec(name, guard, arg=ARG, ev=EV_OPEN, v47=0x11223344,
                 rets=None, logs=None, dump_guard=False):
            specs.append((name, guard, arg, ev, v47, rets or {},
                          logs or [], dump_guard))

        s_Q, s_H, s_RES = 1, 2, 3
        log_q = (s_Q, None, None, None)             # 0x18AC58 ptr arg
        # 1. basic
        spec('open_basic', 0xA5, rets={0x18AC58: 1},
             logs=[log_q, (s_RES, 0x3ABA38, 0x41, 0)])
        # 2. state 3 -> 0x41 too
        spec('open_state3', 0xA5, rets={0x18AC58: 3},
             logs=[log_q, (s_RES, 0x3ABA38, 0x41, 0)])
        # 3. state 0 -> else branch via 0xCB70C
        spec('open_state0_else', 0xA5, rets={0x18AC58: 0, 0xCB70C: 0x99},
             logs=[log_q, (s_H, None, None, None),
                   (s_RES, 0x3ABA38, 0x99, 0)])
        # 4. state 2 -> else branch, halfword 0x2211
        spec('open_else_2211', 0xA5, rets={0x18AC58: 2, 0xCB70C: 0x2211},
             logs=[log_q, (s_H, None, None, None),
                   (s_RES, 0x3ABA38, 0x2211, 0)])
        # 5. guard 0
        spec('open_guard_zero', 0x00, rets={0x18AC58: 1},
             logs=[log_q, (s_RES, 0x3ABA38, 0x41, 0)])
        # 6. guard 7
        spec('open_guard_seven', 0x07, rets={0x18AC58: 1},
             logs=[log_q, (s_RES, 0x3ABA38, 0x41, 0)])
        # 7. guard struct = dump bytes (all preserved)
        spec('open_guard_dump', 0x00, rets={0x18AC58: 1},
             logs=[log_q, (s_RES, 0x3ABA38, 0x41, 0)], dump_guard=True)
        # 8. arg 0
        spec('open_arg_zero', 0xA5, arg=0x00, rets={0x18AC58: 1},
             logs=[log_q, (s_RES, 0x3ABA38, 0x41, 0)])
        # 9. gap word special value
        spec('open_gap_dead0005', 0xA5, v47=0xDEAD0005, rets={0x18AC58: 1},
             logs=[log_q, (s_RES, 0x3ABA38, 0x41, 0)])
        # 10. ev ignored (r1 = 0x5555)
        spec('open_ev_ignored', 0xA5, ev=0x5555, rets={0x18AC58: 1},
             logs=[log_q, (s_RES, 0x3ABA38, 0x41, 0)])

        cases = []
        for idx, (name, guard, arg, ev, v47, rets, logs,
                  dump_guard) in enumerate(specs):
            success = 0xDEADB001 + idx
            args = (NODE, ev, arg)
            rettab = bytearray(4 * (max(STUBS.values()) + 1))
            for a, v in rets.items():
                struct.pack_into('<I', rettab, 4 * STUBS[a], v & 0xFFFFFFFF)
            fix = [('.ctxfix', CTX, ctx_fixture()),
                   ('.guardfix', 0x365750, guard_fixture(guard, dump_guard)),
                   ('.gapfix', GAP_WORD, gap_fixture(v47)),
                   ('.logfix', CNT, bytes(0x300)),
                   ('.rettab', RETTAB, bytes(rettab))]
            asserts = [
                (CTX + 8, 1, 0xFF),          # window open marker
                (GAP_BYTE, 1, 0),             # global cleared
                (CTX + 9, 1, guard),           # guard snapshot
                (GUARD, 1, guard),             # guard rewritten, same value
                (CTX + 0x18, 4, arg),         # arg stored
                (CTX + 0x60, 4, NODE),         # node stored
                (CTX + 0x68, 4, v47),          # [0x47BBB8] snapshot
                (GAP_WORD, 4, v47),            # gap word read-only
                (GAP_BYTE + 1, 1, 0xEE),       # gap neighbours untouched
                (GAP_BYTE - 1, 1, 0xEE),
            ]
            if dump_guard:
                asserts += [(0x365750 + i, 1, b) for i, b in
                             enumerate(guard_fixture(guard, True))]
            else:
                asserts += [(0x365750, 1, 0x5A), (0x365752, 1, 0xA7)]
            asserts += [(CTX, 4, 0xC5C5C5C5),        # context head untouched
                        (CTX + 0x1C, 4, 0xC5C5C5C5),
                        (CTX + 0x64, 4, 0xC5C5C5C5),
                        (CTX + 0x6C, 4, 0xC5C5C5C5)]
            for i, (sid, a0, a1, a2) in enumerate(logs):
                asserts += L(i, sid, a0, a1, a2)
            n = len(logs)
            asserts += [(CNT, 4, n)]
            asserts += L(n, 0, None, None, None)     # no extra calls

            stub_sections = (f'  .probe {hex(PROBE_AT)} : {{ *(.probe) }}\n'
                             f'  .common {hex(COMMON_AT)} : {{ *(.common) }}\n'
                             f'  .rettab {hex(RETTAB)} : {{ *(.rettab) }}\n')
            for addr in sorted(STUBS):
                stub_sections += (f'  .stub_{addr:x} {hex(addr)} : '
                                  f'{{ *(.stub_{addr:x}) }}\n')
            for sname, sbase, _ in fix:
                if sname == '.rettab':
                    continue
                stub_sections += f'  {sname} {hex(sbase)} : {{ *({sname}) }}\n'
            asm = (harness(0x659554, list(args))
                   + ''.join(
                       f'.section .stub_{a:x},"ax",@progbits\n .org 0\n'
                       + (ptr_stub_body(STUBS[a], half=(a == 0xCB70C))
                          if a in (0x18AC58, 0xCB70C)
                          else stub_body(STUBS[a]))
                       for a in sorted(STUBS))
                   + common_logger()
                   + probe(asserts, success, idx)
                   + fixture_sections(fix))
            case, sim_text = build_case(name, asm, ALL_WINS, stub_sections)
            assert case['exit_code'] == 11, (name, case)
            fault = case['fault']
            assert fault is not None and fault['operation'] == 'read', \
                (name, fault)
            addr = int(fault['address'], 16)
            assert addr == success, (name, fault, hex(success))
            assert PROBE_AT <= int(fault['pc'], 16) < COMMON_AT + 0x2000, \
                (name, fault)
            cases.append(dict(name=name, entry=hex(0x659554),
                              success=hex(success),
                              exit_code=case['exit_code'],
                              instructions=case['instructions'],
                              fault=fault))
            print(f'PASS {name} -> {hex(success)}', flush=True)

        results['cpu_cases'] = cases
        results['status'] = 'PASS_ASLV_OPEN_HANDLER'
        print('PASS_ASLV_OPEN_HANDLER', stamp)
        print('Evidence:', out / 'verified_evidence.json')
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'verified_evidence.json').write_text(
            json.dumps(results, indent=2, default=str) + '\n')


if __name__ == '__main__':
    main()
