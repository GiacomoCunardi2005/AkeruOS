#!/usr/bin/env python3
"""Nikon COOLPIX S33 - AutoSceneLiveView event 0x81 handler (0x65B060).

Iteration 34 (Vibe offline, CPU bench with original windows).
Recovers and closes the work interrupted in iteration 33 (session
terminated for lack of output; census scripts in tmp/it33 were the
only surviving artifacts and are re-run here as static checks).

Question (open point it.30a): who consumes/produces [ctx+0x18] of the
AutoSceneLiveView context 0x681F5C after the open handler writes the
event argument there - in particular who cancels the stale deferred
value 0x100 left by the blocked reopen path of the 0x4405 close
handler (it.30 cases 7-9).

Static decode (GNU ARC700, original bytes):
  0x65B060 = notify handler of event 0x0081, registry p3 record 8
  (ev @0x783B48, handler @0x783B4C) of the AutoSceneLiveView window
  (registry p3 0x783B08, 39 records).  Three direct bl callers:
  0x6599C6 (bl,   0x4405 close handler, deferred-reopen path, after
                   [ctx+4]:=2, with r0=node),
  0x65B224 (bl_s, 0x0100 handler 0x65B1CC, after [ctx+4]:=2 gated by
                   byte [0x47BBC8]>0, it.28),
  0x65D0DE (bl,   helper 0x65D098: state==6 AND guard(0xCA310)==1 ->
                   0x149028(node,4), 0x149028(node,0xF),
                   0x176828(3,0,0x32), [ctx+4]:=2,
                   0x65B060(node,0x81,1), [ctx+0x1C]:=0, tail b
                   0x659588 into the shared open-handler epilogue;
                   the gate-failed path converges in the same tail).
  Body 0x65B060(r0=node, r1, r2): r1/r2 are DEAD after being saved to
  r17/r16 (millicode 0x334124 spills r17..r13); they only flow live
  into the first three calls (0x17083C(1,r1,r2), 0x148E68(ret,r1,r2),
  0x148E14(1,r1,r2)).
  - 0x17083C(1,...); r0=ret; 0x148E68(r0,...); ret==0 ->
    0x148E14(1,...); r15:=0;
  - 0xD103C(0); 0xD10C4(ret)  [gate]  ret==1 AND [ctx+4]==3 ->
    EARLY RETURN (nothing else happens, return value = ret 1);
  - 0xD10A8(0);
  - [ctx+0x18]==0x100 -> [ctx+0x18]:=0 (THE CANCELLER of the stale
    deferred value) + 0xCB5B0(0x100);  ==0x101 or any other value ->
    NOT cleared, no 0xCB5B0 call;
  - [ctx+4]: 2 or 3 -> TEARDOWN:
      [ctx+0x1E]:=1, [ctx+4]:=0, [ctx+0x1D]:=0,
      [[0x3669EC]+0xF0]:=0 and [0x442644+0xF0]=[0x442734]:=0 (the
      SAME two gate cells the 0x4405 close handler clears when
      0x14504C(node,0x12)==0x55, it.30 case 3);
      0xCD558(1,0x442644); ret!=0 -> 0x65CDF4(ret,0x442644);
      0x14A228, 0x65BBD8, 0x65DAD0;
      mode getter ORIGINAL 0xCAD30: ==0x7E -> 0x149028(node,9) +
        0x65DDA8(0,0);
      0x143AFC(0x16); 0x143AFC(0x15); 0x143AFC(0x14);
      0xCE5C8(); ret!=0 -> 0x2106F4(1);
      0x660C34(); 0xAD90C(ret,0x110);
      0x145C3C(0x7530) via bl.d + delay slot ld_s [pool 0x65B1C8];
      0x145150(node); mode re-read:
        0x2C -> 0x14905C(node,1,500,500,0);
        0x68 -> 0x14905C(node,0x13,100,100,0);
      0xCD8CC(); ret==0 -> 0x14905C(node,0xB,250,250,0);
      0x12845C(); ret!=0 -> 0x14905C(node,0xE,400,400,0);
      0x65CF58(node); return r0=ret;
    other states -> only 0x143AFC(0x16/0x15/0x14), return.

CPU cases (original windows .mili 0x334100..0x3341E4, .modeget
0xCAD30..0xCAD38, .modepool 0xCAAC4, .poolctx 0x65AFF8..0x65AFFC,
.poolg 0x65B00C..0x65B010, .b60 0x65B060..0x65B1CC):
 1 b060_clear_s5       state 5, arg18 0x100: cleared + CB5B0(0x100),
                       three 143AFC, NO teardown, state unchanged
 2 b060_noclear_101    state 5, arg18 0x101: NOT cleared, no CB5B0;
                       148E68 ret 0 -> 148E14(1) branch covered
 3 b060_early_s3       D10C4 ret 1 AND state 3: early return, no
                       D10A8/CB5B0/143AFC, arg18 stays 0x100, _ret 1
 4 b060_teardown_s2    D10C4 ret 1 (state 2 NOT blocked): clear +
                       full teardown; CD558 ret 1 -> 65CDF4 covered;
                       mode 2B -> 14905C(node,0xB,250)
 5 b060_teardown_s3_2c state 3, D10C4 ret 0: teardown; CD558 ret 0 ->
                       no 65CDF4; CE5C8 ret 1 -> 2106F4(1);
                       mode 2C -> 14905C(node,1,500); CD8CC ret 0 ->
                       14905C(node,0xB,250); 12845C ret 0 -> no 0xE
 6 b060_teardown_s2_68 mode 68 -> 14905C(node,0x13,100); CD8CC ret 1
                       -> NO 0xB call; 12845C ret 1 ->
                       14905C(node,0xE,400)
 7 b060_teardown_7e    mode 7E -> 149028(node,9) + 65DDA8(0,0) inside
                       the teardown, then the 2B tail
 8 b060_d10c41_s5     D10C4 ret 1 but state 5: NOT an early return,
                       clear + three 143AFC (gate is state==3 only)
 9 b060_teardown_s2_101 teardown with arg18 0x101: NOT cleared (stays
                       0x101), no CB5B0 - the teardown never writes
                       [ctx+0x18]

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
ENTRY = 0x65B060             # event 0x81 handler
MODE_CELL = 0xC8E80C         # mode byte read by 0xCAD30
GATE_CELL = 0x442734         # 0x442644+0xF0
GATE_P_CELL = 0x3669EC       # pointer cell of the second gate target
GATE_TGT = 0x3680F0          # [0x3669EC]+0xF0 fixture target
HELPER = 0x65D098            # third caller (static freeze only)

NODE = 0x1234
ARG1 = 0x81
ARG2 = 1

# original windows (payload, lo, hi, section)
W_MILI = (0, 0x334100, 0x3341E4, '.mili')
W_MODEGET = (0, 0xCAD30, 0xCAD38, '.modeget')
W_MODEPOOL = (0, 0xCAAC4, 0xCAAC8, '.modepool')
W_POOLCTX = (2, 0x65AFF8, 0x65AFFC, '.poolctx')
W_POOLG = (2, 0x65B00C, 0x65B010, '.poolg')
W_B60 = (2, 0x65B060, 0x65B1CC, '.b60')

ALL_WINS = [W_MILI, W_MODEGET, W_MODEPOOL, W_POOLCTX, W_POOLG, W_B60]

# bl targets actually reached by the 9 CPU cases (from the GNU listing
# of 0x65B060..0x65B1C2), minus originals (millicode 0x334124/0x334184,
# mode getter 0xCAD30) and minus branches never taken with the case
# fixtures (documented in the report; reaching a dropped target
# executes garbage and fails the case probe).
BL_TARGETS = [
    0x17083C, 0x148E14, 0x148E68,           # prologue services
    0xD103C, 0xD10A8, 0xD10C4,              # gate services
    0xCB5B0,                                # stale-0x100 cancel
    0x143AFC,                               # 0x16/0x15/0x14 pulses
    0xCD558, 0x65CDF4, 0x14A228, 0x65BBD8, 0x65DAD0,   # teardown
    0x149028, 0x65DDA8,                     # mode 0x7E branch
    0xCE5C8, 0x2106F4,                       # notify gates
    0x660C34, 0xAD90C, 0x145C3C, 0x145150,   # mid tail
    0x14905C, 0xCD8CC, 0x12845C,             # mode timers + gates
    0x65CF58]                                # final call

STUBS = {a: i + 1 for i, a in enumerate(sorted(set(BL_TARGETS)))}
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


def ctx_fixture(state=5, arg18=0x100):
    # 0xD0 bytes, sentinel 0xA5
    buf = bytearray(b'\xA5' * 0xD0)
    struct.pack_into('<I', buf, 4, state)          # word state
    buf[8] = 0xFF                                  # open leftover
    buf[9] = 0x5A                                  # open leftover
    struct.pack_into('<I', buf, 0x18, arg18)        # word arg18
    return bytes(buf)


def base_fix(state=5, arg18=0x100, mode=0x2B):
    return [('.ctxfix', CTX, ctx_fixture(state, arg18)),
            ('.modefix', MODE_CELL, bytes([mode])),
            ('.gatefix', GATE_CELL, b'\xA5'),
            ('.gptrfix', GATE_P_CELL,
             struct.pack('<I', 0x368000)),
            ('.tgtfix', GATE_TGT, b'\xA5'),
            ('.logfix', 0x367000, bytes(0x800))]


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'aslv_b060_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, _ = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp,
                   action='aslv-b060-handler-081',
                   limits=['Static analysis + 9 synthetic CPU cases; '
                           'no hardware',
                           'Deep callees are stubs (25); only the '
                           'handler body, millicode, the ORIGINAL mode '
                           'getter 0xCAD30 and its pool execute',
                           'ctx 0x681F5C fixture, mode byte 0xC8E80C, '
                           'gate cells 0x442734 and [0x3669EC]+0xF0 '
                           'fixtures; runtime producers not proven',
                           'Semantics of states 2/3/5, of the 0x81 '
                           'event and of services are structural, '
                           'not functionally identified',
                           'The +2 alignment sweep of the store '
                           'census produces 6 spurious addresses '
                           '(shifted copies); the it.33 carve of the '
                           '14 misaligned entries found no additional '
                           'stores (tmp/it33/census_recarve.py)',
                           'No physical button map, no hardware, no '
                           'scheduling; V1.1 dump only; NON_INSTALLARE'])
    try:
        p0, p2, p3 = payloads[0], payloads[2], payloads[3]

        # --- 1. static: registry p3 record for 0x81 -----------------
        recs = []
        k = 0
        while True:
            a = REG_P3 + 8 * k
            ev, pad, h = struct.unpack_from('<HHI', p3, a - base[3])
            recs.append((a, ev, h))
            if ev == 0:
                break
            k += 1
        assert len(recs) == 40, len(recs)
        m = {ev: (a, h) for (a, ev, h) in recs[:-1]}
        a81, h81 = m[0x81]
        assert h81 == ENTRY, hex(h81)
        a4405, h4405 = m[0x4405]
        assert h4405 == 0x65959C, hex(h4405)
        results['registry_p3'] = dict(
            n_records=len(recs) - 1,
            ev0081_handler=hex(h81), ev0081_fields=hex(a81),
            ev4405_handler=hex(h4405))

        # --- 2. static: pools ----------------------------------------
        pools = {0x65AFF4: 0x00B00100, 0x65AFF8: CTX,
                 0x65AFFC: 0x02600001, 0x65B00C: 0x442644,
                 0x65B1C4: GATE_P_CELL, 0x65B1C8: 0x7530,
                 0xCAAC4: MODE_CELL, 0x65D0E8: CTX}
        for a, v in pools.items():
            src, bb = (p0, base[0]) if a < base[2] else (p2, base[2])
            got = struct.unpack_from('<I', src, a - bb)[0]
            assert got == v, (hex(a), hex(got), hex(v))
        results['pools'] = {hex(a): hex(v) for a, v in pools.items()}

        # --- 3. static: LE scans --------------------------------------
        # ctx 0x681F5C: exactly the 20 window pools of block 2
        expect_pools = [0x659548, 0x659594, 0x65992C, 0x659CCC,
                        0x659F98, 0x65A3B8, 0x65A704, 0x65AC4C,
                        0x65AFF8, 0x65B394, 0x65B5BC, 0x65B710,
                        0x65B9CC, 0x65BEA0, 0x65C3FC, 0x65C910,
                        0x65CC2C, 0x65D0E8, 0x65D58C, 0x65D694]
        hits = [(i, a, o) for (i, a, o) in le_scan(payloads, base, CTX)
                if o == 0]
        assert len(hits) == 20, hits
        assert sorted(a for (i, a, o) in hits) == expect_pools, hits
        assert set(i for (i, a, o) in hits) == {2}, hits
        # [ctx+0x18] is never addressed directly anywhere
        hits74 = [(i, a, o) for (i, a, o)
                  in le_scan(payloads, base, CTX + 0x18) if o == 0]
        assert hits74 == [], hits74
        # the handler address appears exactly once: registry p3 field
        hitsE = [(i, a, o) for (i, a, o)
                 in le_scan(payloads, base, ENTRY) if o == 0]
        assert hitsE == [(3, a81 + 4, 0)], hitsE
        results['le_scans'] = dict(
            ctx_pool_sites=[hex(a) for a in expect_pools],
            ctx18_direct_sites=len(hits74),
            entry_sites=[(i, hex(a)) for i, a, o in hitsE])

        # --- 4. static: bl census of ENTRY across all block listings --
        objcopy = ROOT / 'work/build-arc/binutils/objcopy'
        objdump = ROOT / 'work/build-arc/binutils/objdump'
        assert objcopy.is_file() and objdump.is_file()
        call_sites = []
        total = 0
        with tempfile.TemporaryDirectory(prefix='it34-census-') as td:
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
                n = text.count(f';0x{ENTRY:x}')
                total += n
                if idx == 2:
                    text2 = text
                    for line in text.splitlines():
                        if f';0x{ENTRY:x}' not in line:
                            continue
                        parts = [p for p in line.split('\t') if p]
                        addr = int(parts[0].strip().rstrip(':'), 16)
                        mn = parts[2].strip() if len(parts) > 2 else ''
                        assert mn.startswith('bl'), (line, mn)
                        call_sites.append((addr, mn))
        assert total == 3, total
        assert sorted(a for a, _ in call_sites) == \
            [0x6599C6, 0x65B224, 0x65D0DE], call_sites
        results['bl_census'] = dict(
            total=total,
            sites=[(hex(a), mn) for a, mn in sorted(call_sites)],
            note='pure callback + 3 direct bl (handler 0x4405 '
                 'deferred path, handler 0x0100, helper 0x65D098)',
            review='b060-review-34: C1..C3 confirmed ex-novo; C5 '
                   'counterexample integrated (see store_census)')

        # --- 5. static: store census of disp 0x18 in the ASLV region --
        # region sweep at the default alignment (it.33:
        # tmp/it33/census_twoalign2.py; the +2 sweep yields shifted
        # spurious copies, and the carve of the 14 misaligned entries
        # adds nothing)
        rows = []
        for line in text2.splitlines():
            parts = [p.strip() for p in line.split('\t') if p.strip()]
            if len(parts) < 4:
                continue
            if not parts[0].endswith(':'):
                continue
            try:
                a = int(parts[0].rstrip(':'), 16)
            except ValueError:
                continue
            rows.append((a, parts[2], parts[3]))
        stores = [(a, mn, ops) for (a, mn, ops) in rows
                  if 0x6593A0 <= a <= 0x65D7A0
                  and mn.startswith('st')
                  and (ops.endswith(',0x18]') or ops.endswith(',24]'))]
        expect = [(0x659586, 'st_s'), (0x65996A, 'st_s'),
                  (0x6599B4, 'st_s'), (0x65AC0C, 'stw_s'),
                  (0x65AC18, 'stw_s'), (0x65B0B0, 'st_s')]
        assert sorted((a, mn) for a, mn, _ in stores) == \
            sorted(expect), stores
        results['store_census'] = dict(
            sites=[(hex(a), mn, ops) for a, mn, ops in sorted(stores)],
            note='[ctx+0x18] (0x681F74) writers: open 0x659586 '
                 '(arg), close deferred 0x65996A (0x100) / '
                 '0x6599B4 (0), this handler 0x65B0B0 (cancel to 0). '
                 'The stw_s sites 0x65AC0C/0x65AC18 belong to the '
                 '0x7D40 handler 0x65AB5C and use base r13 = pool '
                 '0x65AC50 = 0x681F98 (+r14*4 loop): they write '
                 '0x681FB0/B4/B8, NOT the ASLV [ctx+0x18] (review '
                 'b060-review-34, C5 counterexample)')

        # --- 6. static: opcode freezes --------------------------------
        freezes = [
            ('entry', 2, 0x65B060,
             'f1c0c6088e6cfc1cc8b60a23003708753a711a7201d8ca0f8d8af20d'
             'cd7680e004f401d8920dcd7600dfe970b20fcd3a'),
            ('d10c4_gate', 2, 0x65B090,
             '36080d3b64170ef081e005f4018683e08cf2'),
            ('arg18_clear', 2, 0x65B0A2,
             '00d806080d3b06868c20048005f4e6a6020d0d38'),
            ('state_dispatch', 2, 0x65B0B6,
             '018682e00ef283e00cf216d83e0a4d7415d8360a4d7414d8320a4d74'
             '74f0'),
            ('teardown', 2, 0x65B0D4,
             '3cd101d81eaee1a62081fdaef019c203281701f0f019c203'),
            ('tail', 2, 0x65B11C,
             '16d8e2094d7415d8da094d7414d8d6094d749e0c8d3980e004f201d8be0d8ddafa0ac0028a210404ca0f0d29f60a6d751fd0a97002080d75de0bcd37ace008f4a97001d98a22070d48730af0ca0bcd37e8e00af4a97013d964da48734a240000e20ecd764e0f0d3980e00af4a9700bd9fada48734a240000ca0ecd76c60a8d6680e00bf2a9700ed98a22060448734a240000b20ecd76a970a60dc000'),
            ('helper_d098', 2, HELPER,
             'f1c096088e6bfc1cc8b60a230037087610d5018586e01cf4620a8d3'
             '681e018f4c97004d96e0fcd75c9700fd9660fcd7503d800dfe9713'
             '2da5a0f8d8c02d801a5c97081d901da860fcffefcada5040ffe'),
            ('helper_pool', 2, 0x65D0E8, '5c1f6800'),
            ('wrap_epi', 2, 0x659588, '0a24c03604141b34'),
            ('caller_close', 2, 0x6599C2, 'c1a0a9709e0e8000'),
            ('caller_h100', 2, 0x65B21E, 'c9700a71e9728fff'),
            ('modeget', 0, 0xCAD30, '651700f60088e07e'),
            ('modepool', 0, 0xCAAC4, '0ce8c800'),
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

        # --- 7. CPU cases ----------------------------------------------
        r = Runner(SimpleNamespace(legacy_root=LEGACY,
                                   toolchain=TOOLCHAIN,
                                   output=out,
                                   action='aslv-b060-handler'))
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

        def HEAD(e68=1):
            # prologue until the D10C4 gate; a1/a2 stay (0x81, 1)
            return [(S[0x17083C], 1, 0x81, 1),
                    (S[0x148E68], 1, 0x81, 1)] if e68 else \
                   [(S[0x17083C], 1, 0x81, 1),
                    (S[0x148E68], 0, 0x81, 1),
                    (S[0x148E14], 1, 0x81, 1)]

        def GATE(ret_d103c=0):
            return [(S[0xD103C], 0, 0x81, 1),
                    (S[0xD10C4], ret_d103c, 0x81, 1)]

        def CLEAR():
            return [(S[0xD10A8], 0, 0x81, 1),
                    (S[0xCB5B0], 0x100, 0x81, 1)]

        def NOCLR():
            return [(S[0xD10A8], 0, 0x81, 1)]

        def PULSES_S(r1):
            return [(S[0x143AFC], 0x16, r1, 1),
                (S[0x143AFC], 0x15, r1, 1),
                (S[0x143AFC], 0x14, r1, 1)]

        def TEAR(mode, cd558=0, cdf4=0, ce5c8=0, f2106=0, cd8cc=0,
                 q128=0, r1mid=0x442644):
            # from CD558 to the end; mode = fixture mode byte.
            # r1mid: r1 at the pulses/CE5C8/2106F4/660C34 calls - the
            # 0x7E branch sets r1:=0 (mov_s r1,r0) at 0x65B116.
            log = [(S[0xCD558], 1, 0x442644, 1)]
            if cd558:
                log.append((S[0x65CDF4], cd558, 0x442644, 1))
            log += [(S[0x14A228], cdf4, 0x442644, 1),
                    (S[0x65BBD8], 0, 0x442644, 1),
                    (S[0x65DAD0], 0, 0x442644, 1)]
            if mode == 0x7E:
                log += [(S[0x149028], NODE, 9, 1),
                        (S[0x65DDA8], 0, 0, 1)]
            log += [(S[0x143AFC], 0x16, r1mid, 1),
                    (S[0x143AFC], 0x15, r1mid, 1),
                    (S[0x143AFC], 0x14, r1mid, 1)]
            log.append((S[0xCE5C8], 0, r1mid, 1))
            if ce5c8:
                log.append((S[0x2106F4], 1, r1mid, 1))
            log += [(S[0x660C34], f2106, r1mid, 1),
                    (S[0xAD90C], 0, 0x110, 1),
                    (S[0x145C3C], 0x7530, 0x110, 1),
                    (S[0x145150], NODE, 0x110, 1)]
            if mode == 0x2C:
                log.append((S[0x14905C], NODE, 1, 500))
                log.append((S[0xCD8CC], 0, 1, 500))
            elif mode == 0x68:
                log.append((S[0x14905C], NODE, 0x13, 0x64))
                log.append((S[0xCD8CC], 0, 0x13, 0x64))
            else:
                log.append((S[0xCD8CC], mode, 0x110, 1))
            if cd8cc == 0:
                log.append((S[0x14905C], NODE, 0xB, 0xFA))
                log.append((S[0x12845C], 0, 0xB, 0xFA))
            else:
                log.append((S[0x12845C], cd8cc, 1 if mode == 0x2C
                            else (0x13 if mode == 0x68 else 0x110),
                            500 if mode == 0x2C
                            else (0x64 if mode == 0x68 else 1)))
            if q128:
                log.append((S[0x14905C], NODE, 0xE, 0x190))
                log.append((S[0x65CF58], NODE, 0xE, 0x190))
            else:
                log.append((S[0x65CF58], NODE, 0xB, 0xFA))
            return log

        # memory asserts shared by all cases: open leftovers intact
        BASE_MEM = [(CTX + 8, 1, 0xFF), (CTX + 9, 1, 0x5A),
                    (CTX + 0x24, 1, 0xA5)]

        specs = []

        # 1 state 5, arg18 0x100 -> cancel + pulses, no teardown
        specs.append(spec(
            'b060_clear_s5',
            dict(state=5, arg18=0x100, mode=0x2B),
            {0x17083C: 1, 0x148E68: 1, '_ret': 0},
            HEAD() + GATE() + CLEAR() + PULSES_S(0x81),
            extra=BASE_MEM + [
                (CTX + 0x18, 4, 0), (CTX + 4, 4, 5),
                (CTX + 0x1E, 1, 0xA5), (CTX + 0x1D, 1, 0xA5),
                (GATE_CELL, 1, 0xA5), (GATE_TGT, 1, 0xA5)]))

        # 2 state 5, arg18 0x101 -> NO cancel; 148E14 branch
        specs.append(spec(
            'b060_noclear_101',
            dict(state=5, arg18=0x101, mode=0x2B),
            {'_ret': 0},
            HEAD(e68=0) + GATE() + NOCLR() + PULSES_S(0x81),
            extra=BASE_MEM + [
                (CTX + 0x18, 4, 0x101), (CTX + 4, 4, 5),
                (CTX + 0x1E, 1, 0xA5), (CTX + 0x1D, 1, 0xA5),
                (GATE_CELL, 1, 0xA5), (GATE_TGT, 1, 0xA5)]))

        # 3 D10C4 ret 1 AND state 3 -> early return
        specs.append(spec(
            'b060_early_s3',
            dict(state=3, arg18=0x100, mode=0x2B),
            {0x17083C: 1, 0x148E68: 1, 0xD10C4: 1, '_ret': 3},
            HEAD() + GATE(),
            extra=BASE_MEM + [
                (CTX + 0x18, 4, 0x100), (CTX + 4, 4, 3),
                (CTX + 0x1E, 1, 0xA5), (CTX + 0x1D, 1, 0xA5),
                (GATE_CELL, 1, 0xA5), (GATE_TGT, 1, 0xA5)]))

        # 4 D10C4 ret 1, state 2 (NOT blocked) -> cancel + teardown,
        #   CD558 ret 1 -> 65CDF4, mode 2B -> 14905C(node,0xB,250)
        specs.append(spec(
            'b060_teardown_s2',
            dict(state=2, arg18=0x100, mode=0x2B),
            {0x17083C: 1, 0x148E68: 1, 0xD10C4: 1, 0xCD558: 1, '_ret': 0},
            HEAD() + GATE() + CLEAR()
            + TEAR(mode=0x2B, cd558=1),
            extra=BASE_MEM + [
                (CTX + 0x18, 4, 0), (CTX + 4, 4, 0),
                (CTX + 0x1E, 1, 1), (CTX + 0x1D, 1, 0),
                (GATE_CELL, 1, 0), (GATE_TGT, 1, 0)]))

        # 5 state 3 (D10C4 ret 0): teardown; CD558 ret 0 -> no CDF4;
        #   CE5C8 ret 1 -> 2106F4(1); mode 2C -> 14905C(node,1,500);
        #   CD8CC ret 0 -> 0xB; 12845C ret 0 -> no 0xE
        specs.append(spec(
            'b060_teardown_s3_2c',
            dict(state=3, arg18=0x100, mode=0x2C),
            {0x17083C: 1, 0x148E68: 1, 0xCE5C8: 1, '_ret': 0},
            HEAD() + GATE() + CLEAR()
            + TEAR(mode=0x2C, ce5c8=1),
            extra=BASE_MEM + [
                (CTX + 0x18, 4, 0), (CTX + 4, 4, 0),
                (CTX + 0x1E, 1, 1), (CTX + 0x1D, 1, 0),
                (GATE_CELL, 1, 0), (GATE_TGT, 1, 0)]))

        # 6 state 2, mode 68 -> 14905C(node,0x13,100); CD8CC ret 1 ->
        #   NO 0xB call; 12845C ret 1 -> 14905C(node,0xE,400)
        specs.append(spec(
            'b060_teardown_s2_68',
            dict(state=2, arg18=0x100, mode=0x68),
            {0x17083C: 1, 0x148E68: 1, 0xCD8CC: 1, 0x12845C: 1, '_ret': 0},
            HEAD() + GATE() + CLEAR()
            + TEAR(mode=0x68, cd8cc=1, q128=1),
            extra=BASE_MEM + [
                (CTX + 0x18, 4, 0), (CTX + 4, 4, 0),
                (CTX + 0x1E, 1, 1), (CTX + 0x1D, 1, 0),
                (GATE_CELL, 1, 0), (GATE_TGT, 1, 0)]))

        # 7 state 2, mode 7E -> 149028(node,9) + 65DDA8(0,0) then 2B tail
        #   (after the 7E branch r1:=0: a1 of pulses/CE5C8/660C34 is 0)
        specs.append(spec(
            'b060_teardown_7e',
            dict(state=2, arg18=0x100, mode=0x7E),
            {0x17083C: 1, 0x148E68: 1, '_ret': 0},
            HEAD() + GATE() + CLEAR()
            + TEAR(mode=0x7E, r1mid=0),
            extra=BASE_MEM + [
                (CTX + 0x18, 4, 0), (CTX + 4, 4, 0),
                (CTX + 0x1E, 1, 1), (CTX + 0x1D, 1, 0),
                (GATE_CELL, 1, 0), (GATE_TGT, 1, 0)]))

        # 8 D10C4 ret 1 but state 5: NOT an early return
        specs.append(spec(
            'b060_d10c41_s5',
            dict(state=5, arg18=0x100, mode=0x2B),
            {0x17083C: 1, 0x148E68: 1, 0xD10C4: 1, '_ret': 0},
            HEAD() + GATE() + CLEAR() + PULSES_S(0x81),
            extra=BASE_MEM + [
                (CTX + 0x18, 4, 0), (CTX + 4, 4, 5),
                (CTX + 0x1E, 1, 0xA5), (CTX + 0x1D, 1, 0xA5),
                (GATE_CELL, 1, 0xA5), (GATE_TGT, 1, 0xA5)]))

        # 9 state 2, arg18 0x101 -> teardown but NO cancel
        specs.append(spec(
            'b060_teardown_s2_101',
            dict(state=2, arg18=0x101, mode=0x2B),
            {0x17083C: 1, 0x148E68: 1, '_ret': 0},
            HEAD() + GATE() + NOCLR()
            + TEAR(mode=0x2B),
            extra=BASE_MEM + [
                (CTX + 0x18, 4, 0x101), (CTX + 4, 4, 0),
                (CTX + 0x1E, 1, 1), (CTX + 0x1D, 1, 0),
                (GATE_CELL, 1, 0), (GATE_TGT, 1, 0)]))

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
            # stub layout: 10-byte bodies; assert no overlap
            prev_end = None
            for a in stub_addrs:
                if prev_end is not None and a < prev_end:
                    raise AssertionError(
                        f'stub overlap at {hex(a)} < {hex(prev_end)}')
                prev_end = a + 10
            stub_sections = (
                f'  .probe {hex(PROBE_AT)} : {{ *(.probe) }}\n'
                f'  .common {hex(COMMON_AT)} : {{ *(.common) }}\n'
                f'  .rettab {hex(RETTAB)} : {{ *(.rettab) }}\n')
            for a in stub_addrs:
                stub_sections += (
                    f'  .stub_{a:x} {hex(a)} : '
                    f'{{ *(.stub_{a:x}) }}\n')
            for sname, sbase, _ in fix:
                if sname == '.rettab':
                    continue
                stub_sections += \
                    f'  {sname} {hex(sbase)} : {{ *({sname}) }}\n'
            asm = (harness(ENTRY, list(args))
                   + ''.join(
                       (f'.section .stub_{a:x},"ax",@progbits\n'
                        ' .org 0\n' + stub_body(STUBS[a]))
                       for a in stub_addrs)
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
        results['status'] = 'PASS_ASLV_B060_HANDLER_081'
        print('PASS_ASLV_B060_HANDLER_081', stamp)
        print('Evidence:', out / 'verified_evidence.json')
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'verified_evidence.json').write_text(
            json.dumps(results, indent=2, default=str) + '\n')


if __name__ == '__main__':
    main()
