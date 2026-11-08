#!/usr/bin/env python3
"""Static + CPU verification of the AutoSceneLiveView OPEN handler 0x659554
(event 0x4401, p3 registry 0x783B08) and of its event WRAPPER 0x6593A0
(descriptor 0x783AE8 -> window notify gate), Nikon S33 firmware V1.1.

Closes the open point of iteration 25 (checkpoint 2026-11-01): decode and
CPU-prove the 0x4401 open handler that links the window lifecycle/state to
the slot chain decoded in iteration 25.

Facts asserted here (byte-exact on the verified payloads + 19 CPU cases on
the GNU ARC700 simulator executing ORIGINAL firmware bytes):

- REGISTRY p3 0x783B08 (re-asserted): 39 records + terminator
  {0, 0x20E814} at 0x783C40; 0x4401 -> 0x659554, 0x4405 -> 0x65959C,
  0x4406 -> 0x659EF0, 0x4409 -> 0x65A4A4, 0x440E -> 0x659FA0,
  0x400C -> 0x65A708, 0x7D40 -> 0x65AB5C.

- OPEN HANDLER 0x659554(node, ev, arg) [p2, pools 0x659594/0x659598]:
  (1) bl 0x65D6A0(node, ev, arg): stores node (WORD) at [0x681FBC]
      (pool 0x65D6CC), calls the 2-instruction ORIGINAL helper 0x65C920
      (j_s.d [blink] + delay slot ld_s r0,[pcl,+4]; pool 0x65C924=0x47BBB8)
      which returns the POINTER 0x47BBB8 (not the byte): the pointer
      (WORD) is stored at [0x681FBC+8], then 0x189D78 (service/yield,
      stubbed) is called with r0 = that same pointer;
  (2) [0x681F5C+8] := 0xFF;
  (3) [0x47BBC8] := 0 (pool 0x659598 = 0x47BBC8);
  (4) r0 := ORIGINAL guard getter 0xCA310 (byte 0x365751);
      [0x681F5C+9] := r0; then ORIGINAL setter 0xCA2F4(r0) re-writes the
      SAME value to 0x365751 (r1=0x681F5C leftover is IGNORED by the
      setter: it reloads its pool first);
  (5) [0x681F5C+0x18] := arg (WORD store);
  (6) epilogue -> millicode pop 0x334194; return value r0 = 0x681F5C.
  The handler does NOT touch the state cell [ctx+4].

- WRAPPER 0x6593A0(node, ev, arg) [p2, pools 0x659548/4C/50]: r14 =
  (ev & 0x3F80) >> 7 for 0 < ev <= 0x3FFF else 0; r13 = ctx 0x681F5C.
  Events outside [0x80..0x307F] bypass every gate and go straight to the
  router 0x169F60(ctx, 0x783B08, node, ev, arg). Inside the range:
  - state [ctx+4] == 6 AND r14 in {1,2,3,0x10,0xC}: special sub-gate at
    0x6593FC (r18 = ev&1); r14==1 press/release both call 0x65D2E8
    (which is 8x 0x17BF60(0, id) for ids 0x380/0x400/0x480/0x500/0x600/
    0x601/0x580/0x581, pool 0x65D384 = 0x17BF60, stubbed here); release
    (r18 != 0) then exits to the router, press continues below;
  - state 6 with any OTHER r14 (the four button slots 0x580/0x700/0x2180/
    0x2700 have r14 = 0xB/0xE/0x43/0x4E) -> RETURN 0, no router (swallow);
  - state 2: cfg[1] != 0 (ORIGINAL table reader 0x16F920, byte at
    0x446808 + 4*id via add2_s) -> RETURN 0; cfg[1] == 0 -> continue;
  - guard == 7 (ORIGINAL getter): 0xD10C4() == 1 AND state in {2,3} AND
    0 < byte[ctx+0x23] <= 6 AND r14 in {3, 0xC} -> RETURN 0;
  - cfg[8] != 0 -> state-clearing sub-gate; cfg[8] == 0: cfg[7] == 0 ->
    router, else state-clearing sub-gate;
  - state in {4,5}: r14 in {9,0xA,3,0xB,0xE,0x43,0x4E,0xF} -> RETURN 0
    (the four button slots are swallowed in states 4 and 5 too);
    r14 in {1,2}: zoom-position sub-gate (0x14A1F8 counter vs 100/400,
    cfg[8], 0x1493D8/0x14941C, cfg[7]) that either routes or returns 0;
    any other r14 -> 0x65951C: [ctx+4] := 0, bl 0x1493BC, bl.d 0x145C3C
    with delay slot r0 = 0x30D40 (pool 0x65954C), THEN router;
  - all other states -> router. Router result returned in r0.

- p6 0xAF5F08 is NOT a second notify registry (closes the it.25 doubt):
  it is one record of an address-PAIRS table at 0xAF4B70..0xAF5F68
  (639 records {u32 a, u32 b}, all pointing into block 2 code
  0x5FE800..0x669800); the record at 0xAF5F08 is (0x659554, 0x659555).

- Census (16 GNU listings): bl callers 0x659554 = 0, 0x6593A0 = 0
  (pure callbacks), 0x65D6A0 = 1 (0x659568), 0x65C920 = 1 (0x65D6B4),
  0x65D2E8 = 3. LE scans: 0x659554 only at p3 0x783B08 (registry) and
  p6 0xAF5F08 (pairs table); 0x6593A0 only at descriptor 0x783AF4;
  0x47BBC8 only at pools 0x659598/0x65A3B0/0x65C400.

CPU cases (original windows .mili 0x334100..0x3341E4, .guard 0xCA2F4..
0xCA31A, .cfgread 0x16F920..0x16F928 + pool 0x16FA34, .wrap 0x6593A0..
0x659554, .open 0x659554..0x65959C, .d6a0 0x65D6A0..0x65D6D0, .c920
0x65C920..0x65C928; stubs log {id, r0, r1, r2} at 0x367100+16k with
counter 0x367000, r3/r3 mirror cells 0x367310/0x367314, return-value cell
0x367320):
 1 wrap_ev_below        ev 0x50  -> router only
 2 wrap_ev_above        ev 0x3100 -> router only
 3 wrap_state6_slot0    state 6, ev 0x580  -> swallow, ret 0
 4 wrap_state6_slot3    state 6, ev 0x2700 -> swallow, ret 0
 5 wrap_state6_slot2rel state 6, ev 0x2181 -> swallow, ret 0
 6 wrap_state6_zoom     state 6, ev 0x80 press -> 0x65D2E8 + router
 7 wrap_state6_zoom_g7  guard 7, 0xD10C4 ret 1 -> 0x65D2E8 + 0xD10C4 + router
 8 wrap_state6_zoomrel  state 6, ev 0x81 release -> 0x65D2E8 + router (no gates)
 9 wrap_state2_cfg1     cfg[1]=1 -> swallow, ret 0
10 wrap_state2_cfg1pass cfg[1]=0, guard 7, 0xD10C4 ret 0 -> 0xD10C4 + router
11 wrap_state5_slot0    state 5, ev 0x580 -> swallow, ret 0
12 wrap_state5_cfg7     cfg[8]=0, cfg[7]=0 -> router
13 wrap_state5_clear    state 5, ev 0xA00 -> [ctx+4]:=0 + 0x1493BC +
                        0x145C3C(0x30D40) + router
14 wrap_state4_zoom     state 4, r14 2, counter 0 -> 0x14A1F8 x2 +
                        0x1493D8, swallow, ret 0
15 wrap_state3_r14c     state 3, guard 7, 0xD10C4 ret 1, [ctx+0x23]=3,
                        ev 0x600 (r14 0xC) -> 0xD10C4 only, ret 0
16 wrap_state0_slot2    state 0, ev 0x2180 -> router (normal live view)
17 open_basic           entry 0x659554, guard 3: [ctx+8]=0xFF,
                        [0x47BBC8]=0, [ctx+9]=3, [ctx+0x18]=arg,
                        [0x681FBC]=node, [0x681FC4]=0x47BBB8 (pointer),
                        guard re-written 3, ret 0x681F5C
18 open_guard7          guard 7: [ctx+9]=7, guard cell 7
19 open_args            node 0x4321, arg 0x99: propagated to ctx+0x18
                        and 0x681FBC

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
R3CELL = 0x367310
R4CELL = 0x367314
RETCELL = 0x367320

CTX = 0x681F5C               # AutoSceneLiveView context
SUBCTX = 0x681FBC            # ctx+0x60 (node / [0x47BBB8] holder)
REG_P3 = 0x783B08            # AutoSceneLiveView notify registry
DESC = 0x783AE8              # descriptor
GUARD = 0x365751             # CaptureMenu guard byte
CFG_TAB = 0x446808           # runtime cfg byte table (0x16F920)
BB8 = 0x47BBB8               # [0x47BBB8] byte cell
BC8 = 0x47BBC8               # [0x47BBC8] byte cell

# original windows (payload, lo, hi, section)
W_MILI = (0, 0x334100, 0x3341E4, '.mili')      # push/pop millicode
W_GUARD = (0, 0xCA2F4, 0xCA31A, '.guard')      # setter+getter+pool 0xCA30C
W_CFG = (0, 0x16F920, 0x16F928, '.cfgread')    # table reader
W_CFG_POOL = (0, 0x16FA34, 0x16FA38, '.cfgpool')
W_WRAP = (2, 0x6593A0, 0x659554, '.wrap')      # wrapper + pools 0x659548..50
W_OPEN = (2, 0x659554, 0x65959C, '.open')     # 0x4401 handler + pools
W_D6A0 = (2, 0x65D6A0, 0x65D6D0, '.d6a0')      # entry helper + pool
W_C920 = (2, 0x65C920, 0x65C928, '.c920')      # [0x47BBB8] getter + pool

ALL_WINS = [W_MILI, W_GUARD, W_CFG, W_CFG_POOL, W_WRAP, W_OPEN, W_D6A0,
            W_C920]

# stubs: address -> sid
STUBS = {0x169F60: 1, 0x65D2E8: 2, 0x145C3C: 3, 0x1493BC: 4, 0x1493D8: 5,
         0x14941C: 6, 0x14A1F8: 7, 0xD10C4: 8, 0x189D78: 9}

s_router, s_d2e8, s_145c3c = 1, 2, 3
s_1493bc, s_1493d8, s_14941c = 4, 5, 6
s_14a1f8, s_d10c4, s_189d78 = 7, 8, 9

NODE = 0x1234
ARG = 0x77


def harness(entry, args):
    text = ('.section .text,\"ax\",@progbits\n.global _start\n_start:\n'
            f' mov sp,{hex(STACK)}\n'
            + ''.join(f' mov r{k},{hex(v)}\n' for k, v in enumerate(args))
            + f' mov r12,{hex(entry)}\n'
            ' jl_s [r12]\n'
            f' mov r12,{hex(RETCELL)}\n'
            ' st r0,[r12,0]\n'
            f' mov r12,{hex(PROBE_AT)}\n'
            ' j_s [r12]\n'
            '.section .stack,\"aw\",@nobits\n.align 16\n'
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
    return ('.section .probe,\"ax\",@progbits\n .org 0\n'
            + '\n'.join(text) + '\n')


def stub_body(sid):
    return (' push_s blink\n'
            f' mov r7,{hex(sid)}\n'
            f' mov r12,{hex(COMMON_AT)}\n'
            ' jl_s [r12]\n'
            ' pop_s blink\n'
            ' j_s [blink]\n')


def common_logger():
    return (f'.section .common,\"ax\",@progbits\n .org 0\n'
            f' mov r6,{hex(R3CELL)}\n'
            ' st r3,[r6,0]\n'
            f' mov r6,{hex(R4CELL)}\n'
            ' st r4,[r6,0]\n'
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
    for name, base, data in fix:
        out += (f'.section {name},\"aw\",@progbits\n.align 4\n'
                + ''.join(f' .byte {b}\n' for b in data))
    return out


def L(idx, sid, a0, a1, a2):
    a = LOG_ENT + 16 * idx
    out = [(a, 4, sid)]
    for off, v in ((4, a0), (8, a1), (12, a2)):
        if v is not None:
            out.append((a + off, 4, v))
    return out


def ctx_fixture(state, sub23):
    buf = bytearray(b'\xA5' * 0x68)
    struct.pack_into('<I', buf, 4, state)     # state is a 32-bit word
    buf[0x23] = sub23
    return bytes(buf)


def guard_fixture(guard):
    buf = bytearray(b'\xA5' * 8)          # 0x365750..0x365757
    buf[1] = guard                        # 0x365751
    return bytes(buf)


def cfg_fixture(c1, c7, c8):
    buf = bytearray(b'\x00' * 0x48)       # 0x446808..0x446850
    buf[4 * 1] = c1
    buf[4 * 7] = c7
    buf[4 * 8] = c8
    return bytes(buf)


def bb_fixture(bb8):
    buf = bytearray(b'\xA5' * 0x20)       # 0x47BBB0..0x47BBCF
    buf[8] = bb8                          # 0x47BBB8
    return bytes(buf)


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'aslv_open_wrapper_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, _ = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp,
                   action='aslv-open-handler-wrapper',
                   limits=['Static analysis + 19 synthetic CPU cases; no '
                           'hardware',
                           'Deep callees are stubs (router 0x169F60, '
                           '0x65D2E8, 0x145C3C, 0x1493BC/D8/41C, 0x14A1F8, '
                           '0xD10C4, 0x189D78); only the wrapper, the open '
                           'handler, 0x65D6A0, 0x65C920, the millicode, the '
                           'ORIGINAL guard getter/setter and the ORIGINAL '
                           'cfg reader execute',
                           'The ctx 0x681F5C, guard 0x365751, cfg table '
                           '0x446808 and cells 0x47BBB8/0x47BBC8 are '
                           'fixtures; runtime producers are not proven',
                           'cfg[1]/[7]/[8] real values unknown (runtime '
                           'RAM); state [ctx+4] producer not proven here',
                           'No physical button map, no hardware, no '
                           'scheduling; V1.1 dump only; NON_INSTALLARE'])
    try:
        p0, p2, p3 = payloads[0], payloads[2], payloads[3]

        # --- 1. static: registry p3 -------------------------------------
        recs = []
        k = 0
        while True:
            a = REG_P3 + 8 * k
            ev, pad, h = struct.unpack_from('<HHI', p3, a - base[3])
            recs.append((a, ev, pad, h))
            if ev == 0:
                break
            k += 1
        m = {ev: h for (_, ev, _, h) in recs[:-1]}
        assert len(recs) == 40, len(recs)
        for ev, h in ((0x4401, 0x659554), (0x4405, 0x65959C),
                      (0x4406, 0x659EF0), (0x4409, 0x65A4A4),
                      (0x440E, 0x659FA0), (0x400C, 0x65A708),
                      (0x7D40, 0x65AB5C), (0x580, 0x65C46C),
                      (0x2700, 0x65C46C)):
            assert m.get(ev) == h, (hex(ev), hex(m.get(ev) or 0), hex(h))
        results['registry_p3'] = dict(
            n_records=len(recs) - 1,
            open_handler=hex(m[0x4401]))

        # --- 2. static: pools --------------------------------------------
        pools = {0x659548: CTX, 0x65954C: 0x30D40, 0x659550: REG_P3,
                 0x659594: CTX, 0x659598: 0x47BBC8, 0x65D6CC: SUBCTX,
                 0x65C924: BB8, 0x65D384: 0x17BF60, 0xCA30C: GUARD,
                 0x16FA34: CFG_TAB}
        for a, v in pools.items():
            src, bb = (p0, base[0]) if a < base[2] else (p2, base[2])
            got = struct.unpack_from('<I', src, a - bb)[0]
            assert got == v, (hex(a), hex(got), hex(v))
        results['pools'] = {hex(a): hex(v) for a, v in pools.items()}

        # --- 3. static: LE scans ----------------------------------------
        want = {0x659554: [(3, REG_P3 + 4, 0), (6, 0xAF5F08, 0)],
                0x6593A0: [(3, DESC + 0xC, 0)],
                0x47BBC8: [(2, 0x659598, 0), (2, 0x65A3B0, 0),
                           (2, 0x65C400, 0)]}
        le = {}
        for t, exp in want.items():
            hits = [(i, a, o) for (i, a, o) in le_scan(payloads, base, t)
                    if o == 0]
            assert hits == exp, (hex(t), hits, exp)
            le[hex(t)] = [(i, hex(a), o) for i, a, o in hits]
        results['le_scans'] = le

        # --- 4. static: bl census on 16 GNU listings --------------------
        census = {t: 0 for t in (0x659554, 0x6593A0, 0x65D6A0, 0x65C920,
                                 0x65D2E8)}
        objcopy = ROOT / 'work/build-arc/binutils/objcopy'
        objdump = ROOT / 'work/build-arc/binutils/objdump'
        assert objcopy.is_file() and objdump.is_file()
        with tempfile.TemporaryDirectory(prefix='it28-census-') as td:
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
                    census[t] += text.count(f';0x{t:x}')
        assert census == {0x659554: 0, 0x6593A0: 0, 0x65D6A0: 1,
                          0x65C920: 1, 0x65D2E8: 3}, census
        results['bl_census'] = {hex(k): v for k, v in census.items()}

        # --- 5. static: p6 pairs table -----------------------------------
        p6, b6 = payloads[6], base[6]

        def pair(a):
            w1, w2 = struct.unpack_from('<II', p6, a - b6)
            return w1, w2
        tlo, thi = 0xAF5F08, 0xAF5F08
        while True:
            w1, w2 = pair(tlo - 8)
            if not (0x5FE800 <= w1 < 0x669800
                    and 0x5FE800 <= w2 < 0x669800):
                break
            tlo -= 8
        while True:
            w1, w2 = pair(thi + 8)
            if not (0x5FE800 <= w1 < 0x669800
                    and 0x5FE800 <= w2 < 0x669800):
                break
            thi += 8
        n_pairs = (thi - tlo) // 8 + 1
        assert (tlo, thi) == (0xAF4B70, 0xAF5F60), (hex(tlo), hex(thi))
        assert pair(0xAF5F08) == (0x659554, 0x659555), pair(0xAF5F08)
        results['p6_pairs_table'] = dict(
            lo=hex(tlo), hi=hex(thi), records=n_pairs,
            record_at_0xAF5F08=[hex(x) for x in pair(0xAF5F08)],
            note='address-range pairs over block-2 code; NOT a notify '
                 'registry (closes it.25 doubt)')

        # --- 6. static: opcode freezes -----------------------------------
        freezes = [
            ('wrap_prologue', 2, 0x6593A0, 'f1c07e0d4e6dfc1c'),
            ('wrap_gate_ctx4', 2, 0x6593E2, '018586e00cf481e6'),
            ('wrap_state_clear', 2, 0x65951C,
             '00d801a59e0ecd771a0f2d7609d0a970'),
            ('wrap_router_call', 2, 0x65952A,
             'a97009d10a72e9730a2440042e0a4d887a700a24'),
            ('wrap_pools', 2, 0x659548, '5c1f6800400d0300083b7800'),
            ('open_prologue', 2, 0x659554, 'f1c0da0b4e6dfc1cc8b60a2300370876'),
            ('open_0xff', 2, 0x65956C, '0ad0ffd928a80ad000d920a8'),
            ('open_guardcopy', 2, 0x659578, '9a0d4d3806d109a9760d4d3804d0a6a0'),
            ('open_argstore', 2, 0x659584, '04d0a6a00a24c03604141b34'),
            ('open_pools', 2, 0x659594, '5c1f6800c8bb4700'),
            ('d6a0_head', 2, 0x65D6A0,
             'f1c0920a4e6bfc1cc8b60a230037087507d600a66e0a8fff02a6c20e0d960a'
             '24c03604141b34d9024e6be078bc1f'),
            ('c920_body', 2, 0x65C920, 'e07f01d0b8bb4700'),
            ('guard_win', 0, 0xCA2F4,
             'fc1cc8b60a23003704d100a90a24c03604141b34e07ee07851573600fc17'
             '00f00088e07ef1c0'),
            ('cfg_win', 0, 0x16F920, '45d11579e07f0089'),
            ('cfg_pool', 0, 0x16FA34, '08684400'),
        ]
        for name, idx, addr, hexstr in freezes:
            data = payloads[idx][addr - base[idx]:addr - base[idx]
                                 + len(hexstr) // 2]
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

        # --- 7. CPU cases ------------------------------------------------
        r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN,
                                   output=out, action='aslv-open-wrapper'))
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

        def base_fix(state=0xA5, sub23=0xA5, guard=5, c1=0, c7=0, c8=1,
                     bb8=0x5A):
            return [('.ctxfix', CTX, ctx_fixture(state, sub23)),
                    ('.guardfix', 0x365750, guard_fixture(guard)),
                    ('.cfgfix', CFG_TAB, cfg_fixture(c1, c7, c8)),
                    ('.bbfix', 0x47BBB0, bb_fixture(bb8)),
                    ('.logfix', 0x367000, bytes(0x400))]

        # (name, entry, ev, fix-kwargs, rets, logs, extra_asserts)
        specs = []

        def spec(name, entry, ev, fixkw, rets, logs, extra=None):
            if entry == 0x6593A0:
                args = (NODE, ev, ARG)
            else:
                node = 0x4321 if name == 'open_args' else NODE
                arg = 0x99 if name == 'open_args' else ARG
                args = (node, ev, arg)
            asserts = []
            for i, (sid, a0, a1, a2) in enumerate(logs):
                asserts += L(i, sid, a0, a1, a2)
            n = len(logs)
            asserts += [(CNT, 4, n)]
            asserts += L(n, 0, None, None, None)     # no extra calls
            asserts += [(RETCELL, 4, rets.pop('_ret'))]
            if extra:
                asserts += extra
            specs.append((name, entry, args, rets, fixkw, asserts))

        ROUTER_RET = 0x5A

        # ---- wrapper cases ----
        spec('wrap_ev_below', 0x6593A0, 0x50, dict(state=0),
             {0x169F60: ROUTER_RET, '_ret': ROUTER_RET},
             [(s_router, CTX, REG_P3, NODE)],
             extra=[(R3CELL, 4, 0x50), (R4CELL, 4, ARG)])
        spec('wrap_ev_above', 0x6593A0, 0x3100, dict(state=0),
             {0x169F60: ROUTER_RET, '_ret': ROUTER_RET},
             [(s_router, CTX, REG_P3, NODE)],
             extra=[(R3CELL, 4, 0x3100), (R4CELL, 4, ARG)])
        spec('wrap_state6_slot0', 0x6593A0, 0x580, dict(state=6),
             {'_ret': 0}, [],
             extra=[(CTX + 4, 4, 6)])
        spec('wrap_state6_slot3', 0x6593A0, 0x2700, dict(state=6),
             {'_ret': 0}, [],
             extra=[(CTX + 4, 4, 6)])
        spec('wrap_state6_slot2rel', 0x6593A0, 0x2181, dict(state=6),
             {'_ret': 0}, [],
             extra=[(CTX + 4, 4, 6)])
        spec('wrap_state6_zoom', 0x6593A0, 0x80, dict(state=6, guard=5),
             {0x169F60: ROUTER_RET, '_ret': ROUTER_RET},
             [(s_d2e8, 0, 0x80, None), (s_router, CTX, REG_P3, NODE)],
             extra=[(R3CELL, 4, 0x80), (R4CELL, 4, ARG)])
        spec('wrap_state6_zoom_g7', 0x6593A0, 0x80,
             dict(state=6, guard=7),
             {0x169F60: ROUTER_RET, 0xD10C4: 1, '_ret': ROUTER_RET},
             [(s_d2e8, 0, 0x80, None), (s_d10c4, None, None, None),
              (s_router, CTX, REG_P3, NODE)],
             extra=[(GUARD, 1, 7), (R3CELL, 4, 0x80)])
        spec('wrap_state6_zoomrel', 0x6593A0, 0x81, dict(state=6, guard=5),
             {0x169F60: ROUTER_RET, '_ret': ROUTER_RET},
             [(s_d2e8, 1, 0x81, None), (s_router, CTX, REG_P3, NODE)],
             extra=[(R3CELL, 4, 0x81), (R4CELL, 4, ARG)])
        spec('wrap_state2_cfg1', 0x6593A0, 0x580, dict(state=2, c1=1),
             {'_ret': 0}, [],
             extra=[(CTX + 4, 4, 2)])
        spec('wrap_state2_cfg1pass', 0x6593A0, 0x580,
             dict(state=2, c1=0, guard=7),
             {0x169F60: ROUTER_RET, 0xD10C4: 0, '_ret': ROUTER_RET},
             [(s_d10c4, None, None, None),
              (s_router, CTX, REG_P3, NODE)],
             extra=[(GUARD, 1, 7), (R3CELL, 4, 0x580)])
        spec('wrap_state5_slot0', 0x6593A0, 0x580, dict(state=5),
             {'_ret': 0}, [],
             extra=[(CTX + 4, 4, 5)])
        spec('wrap_state5_cfg7', 0x6593A0, 0x580,
             dict(state=5, c8=0, c7=0),
             {0x169F60: ROUTER_RET, '_ret': ROUTER_RET},
             [(s_router, CTX, REG_P3, NODE)],
             extra=[(R3CELL, 4, 0x580), (R4CELL, 4, ARG)])
        spec('wrap_state5_clear', 0x6593A0, 0xA00, dict(state=5, guard=5),
             {0x169F60: ROUTER_RET, '_ret': ROUTER_RET},
             [(s_1493bc, None, None, None),
              (s_145c3c, 0x30D40, None, None),
              (s_router, CTX, REG_P3, NODE)],
             extra=[(CTX + 4, 4, 0), (R3CELL, 4, 0xA00),
                    (R4CELL, 4, ARG)])
        spec('wrap_state4_zoom', 0x6593A0, 0x100,
             dict(state=4, guard=5, c8=1),
             {0x14A1F8: 0, 0x1493D8: 0, '_ret': 0},
             [(s_14a1f8, None, None, None), (s_1493d8, None, None, None),
              (s_14a1f8, None, None, None)],
             extra=[(CTX + 4, 4, 4)])
        spec('wrap_state3_r14c', 0x6593A0, 0x600,
             dict(state=3, sub23=3, guard=7),
             {0xD10C4: 1, '_ret': 0},
             [(s_d10c4, None, None, None)],
             extra=[(CTX + 4, 4, 3), (GUARD, 1, 7)])
        spec('wrap_state0_slot2', 0x6593A0, 0x2180, dict(state=0),
             {0x169F60: ROUTER_RET, '_ret': ROUTER_RET},
             [(s_router, CTX, REG_P3, NODE)],
             extra=[(R3CELL, 4, 0x2180), (R4CELL, 4, ARG)])
        # ---- open handler cases ----
        spec('open_basic', 0x659554, 0x4401, dict(guard=3),
             {0x189D78: 0, '_ret': CTX},
             [(s_189d78, 0x47BBB8, None, None)],
             extra=[(CTX + 8, 1, 0xFF), (BC8, 1, 0), (CTX + 9, 1, 3),
                    (CTX + 0x18, 4, ARG), (SUBCTX, 4, NODE),
                    (SUBCTX + 8, 4, 0x47BBB8), (GUARD, 1, 3),
                    (CTX + 4, 4, 0xA5), (BB8, 1, 0x5A),
                    (0x47BBC7, 1, 0xA5), (0x47BBC9, 1, 0xA5),
                    (CTX, 4, 0xA5A5A5A5)])
        spec('open_guard7', 0x659554, 0x4401, dict(guard=7),
             {0x189D78: 0, '_ret': CTX},
             [(s_189d78, 0x47BBB8, None, None)],
             extra=[(CTX + 9, 1, 7), (GUARD, 1, 7), (CTX + 8, 1, 0xFF),
                    (BC8, 1, 0), (CTX + 0x18, 4, ARG),
                    (SUBCTX, 4, NODE), (SUBCTX + 8, 4, 0x47BBB8)])
        spec('open_args', 0x659554, 0x4401, dict(guard=3),
             {0x189D78: 0, '_ret': CTX},
             [(s_189d78, 0x47BBB8, None, None)],
             extra=[(CTX + 0x18, 4, 0x99), (SUBCTX, 4, 0x4321),
                    (CTX + 9, 1, 3), (CTX + 8, 1, 0xFF), (BC8, 1, 0),
                    (GUARD, 1, 3)])

        cases = []
        for idx, (name, entry, args, rets, fixkw, asserts) in \
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
            fix = base_fix(**fixkw) + [('.rettab', RETTAB, bytes(rettab))]
            stub_sections = (f'  .probe {hex(PROBE_AT)} : {{ *(.probe) }}\n'
                             f'  .common {hex(COMMON_AT)} : {{ *(.common) }}\n'
                             f'  .rettab {hex(RETTAB)} : {{ *(.rettab) }}\n')
            for addr in stub_addrs:
                stub_sections += (f'  .stub_{addr:x} {hex(addr)} : '
                                  f'{{ *(.stub_{addr:x}) }}\n')
            for sname, sbase, _ in fix:
                if sname == '.rettab':
                    continue
                stub_sections += f'  {sname} {hex(sbase)} : {{ *({sname}) }}\n'
            asm = (harness(entry, list(args))
                   + ''.join(f'.section .stub_{a:x},\"ax\",@progbits\n .org 0\n'
                             + stub_body(STUBS[a])
                             for a in stub_addrs)
                   + common_logger()
                   + probe(asserts, success, idx)
                   + fixture_sections(fix))
            case, sim_text = build_case(name, asm, ALL_WINS,
                                        stub_sections)
            assert case['exit_code'] == 11, (name, case)
            fault = case['fault']
            assert fault is not None and fault['operation'] == 'read', \
                (name, fault)
            addr = int(fault['address'], 16)
            assert addr == success, (name, fault, hex(success))
            assert PROBE_AT <= int(fault['pc'], 16) < COMMON_AT + 0x2000, \
                (name, fault)
            cases.append(dict(name=name, entry=hex(entry),
                              success=hex(success),
                              exit_code=case['exit_code'],
                              instructions=case['instructions'],
                              fault=fault))
            print(f'PASS {name} -> {hex(success)}', flush=True)

        results['cpu_cases'] = cases
        results['status'] = 'PASS_ASLV_OPEN_WRAPPER'
        print('PASS_ASLV_OPEN_WRAPPER', stamp)
        print('Evidence:', out / 'verified_evidence.json')
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'verified_evidence.json').write_text(
            json.dumps(results, indent=2, default=str) + '\n')


if __name__ == '__main__':
    main()
