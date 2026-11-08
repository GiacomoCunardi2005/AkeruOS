#!/usr/bin/env python3
"""Nikon COOLPIX S33 - AutoSceneLiveView helper 0x65D098 (iteration 36).

Closes the open point left by iteration 34 (report
S33_GUI_AutoSceneLiveView_Handler_081_B060_CPU_20261101.md): the helper
was decoded statically and frozen but never executed in CPU. Question:
does state==6 AND guard(0xCA310)==1 really produce the predicted
short-circuit - 0x149028(node,4), 0x149028(node,0xF),
0x176828(3,0,0x32), [ctx+4]:=2, 0x65B060(node,0x81,1),
[ctx+0x1C]:=0, shared-epilogue return - and what does the helper do
(and return) when the gate fails?

Static decode (GNU ARC700, original bytes, block 2):
  65d098: push_s blink
  65d09a: bl 0x33412c            ; millicode push r15,r14,r13
  65d09e: st.aw fp,[sp,-4]
  65d0a2: mov fp,sp
  65d0a6: mov_s r14,r0           ; node
  65d0a8: ld_s r13,[pcl,0x40]    ; pool 0x65d0e8 = ctx 0x681F5C
  65d0aa: ld_s r0,[r13,0x4]      ; state word
  65d0ac: cmp_s r0,0x6
  65d0ae: bne_s 0x65d0e4         ; gate-failed -> shared tail
  65d0b0: bl 0xca310             ; ORIGINAL guard getter ([0x365751])
  65d0b4: cmp_s r0,0x1
  65d0b6: bne_s 0x65d0e4
  65d0b8..0d0: 149028(node,4), 149028(node,0xF), 176828(3,0,0x32)
  65d0d6: st_s r0,[r13,0x4]      ; [ctx+4]:=2 (WORD)
  65d0de: bl 0x65b060            ; (node,0x81,1) - the 0x81 handler
  65d0e2: stb_s r15,[r13,0x1c]   ; [ctx+0x1C]:=0 (r15=0, BYTE)
  65d0e4: b 0x659588            ; shared epilogue (disp -15196)
  65d0e8: pool 0x681F5C
  Gate-failed return value: r0 = state word (state!=6) or the guard
  value (state==6, guard!=1); the epilogue (mov sp,fp; ld.ab fp;
  b 0x334194 -> pop r15,r14,r13,blink; j_s [blink]) does not touch
  r0.
  bl census: 5 callers, all block 2, all in the ASLV window family:
  0x65B1F6 (handler 0x65B1CC, ev 0x0100), 0x65BFA0 (handler
  0x65BF00, ev 0x0600), 0x65C18C (handler 0x65C178, ev 0x3301),
  0x65C23C (handler 0x65C228, ev 0x3181), 0x65C30E (handler
  0x65C2CC, ev 0x0180) - range-based attribution over the sorted
  registry p3 handlers (0x65C18C falls INSIDE 0x65C178, one record
  earlier than the naive guess 0x65BF00).
  LE: no pool contains 0x65D098, 0xCA310 or 0x659588 (pure bl/rel).
  [ctx+0x1C] (0x681F78) IS pooled by 6 other sites: 0x659934,
  0x659f9c, 0x65a3e0, 0x65a49c, 0x65b874, 0x65b9d4 - attributed to
  handlers 0x4405, 0x4406, 0x440E (0x659FA0, the pools 0x65A3E0 and
  0x65A49C, correction d098-review-36) and 0x381/0x401. The helper
  writes the same field via r13; some pool sites use 0x681F78 as a
  BASE for nearby fields, not all read the +0x1C byte.

CPU cases (original windows; entry 0x65D098 with r0=NODE, r1/r2
garbage 0x11/0x22 to prove they are dead):
 1 d098_pass_s6_g1    state 6 + guard 1, 0x65B060 STUBBED:
    149028(node,4), 149028(node,0xF), 176828(3,0,0x32),
    65B060(node,0x81,1); [ctx+4]:=2 word, [ctx+0x1C]:=0 byte,
    0x1D neighbor and [ctx+0x18] untouched, ret 0
 2 d098_gate_s5      state 5: NO calls at all (getter skipped - the
    bne at 65d0ae fires before the bl), ret == state word 5
 3 d098_gate_g7      state 6 + guard 7: getter EXECUTED (original),
    gate fails, no stub calls, ret == guard value 7
 4 d098_gate_g0      state 6 + guard 0: same with guard 0, ret == 0
 5 d098_chain_teardown_2b  state 6 + guard 1, arg18 0x100, mode 2B,
    REAL 0x65B060 window: full integration - helper writes state 2,
    b060 sees state 2 -> cancel 0x100 + teardown (state 0, +0x1E:=1,
    +0x1D:=0, gate cells 0, CD558 ret 1 -> 65CDF4), mode 2B tail
    (14905C(node,0xB,250)), helper zeroes [ctx+0x1C], ret 0
 6 d098_chain_nocancel_2c  state 6 + guard 1, arg18 0x101, mode 2C,
    REAL b060: 0x101 NOT cancelled (no CB5B0), teardown still runs,
    14905C(node,1,500), CD8CC ret 0 -> 0xB, 12845C ret 1 ->
    14905C(node,0xE,400), ret 0
 7 d098_chain_7e      state 6 + guard 1, arg18 0x100, mode 7E, REAL
    b060: 149028(node,9) + 65DDA8(0,0) inside the teardown (3 total
    149028 calls with the helper's 2), pulses with r1=0, ret 0

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
ENTRY = 0x65D098             # helper
B060 = 0x65B060              # event 0x81 handler (chain cases)
GUARD_CELL = 0x365751        # byte read by 0xCA310 (pool 0xCA30C)
MODE_CELL = 0xC8E80C
GATE_CELL = 0x442734
GATE_P_CELL = 0x3669EC
GATE_TGT = 0x3680F0

NODE = 0x1234

# original windows (payload, lo, hi, section)
W_MILI = (0, 0x334100, 0x3341E4, '.mili')
W_GGET = (0, 0xCA30C, 0xCA318, '.gget')
W_MODEGET = (0, 0xCAD30, 0xCAD38, '.modeget')
W_MODEPOOL = (0, 0xCAAC4, 0xCAAC8, '.modepool')
W_EPI = (2, 0x659588, 0x659594, '.epi')
W_POOLCTX = (2, 0x65AFF8, 0x65AFFC, '.poolctx')
W_POOLG = (2, 0x65B00C, 0x65B010, '.poolg')
W_B60 = (2, 0x65B060, 0x65B1CC, '.b60')
W_HELPER = (2, 0x65D098, 0x65D0EC, '.helper')

WINS_ISOLATED = [W_MILI, W_GGET, W_EPI, W_HELPER]
WINS_CHAIN = [W_MILI, W_GGET, W_MODEGET, W_MODEPOOL, W_EPI, W_POOLCTX,
              W_POOLG, W_B60, W_HELPER]

# bl targets of the REAL 0x65B060 body (from the it.34 verifier,
# minus 0x65B060 itself) plus the helper-only 0x176828
BL_TARGETS_B60 = [
    0x17083C, 0x148E14, 0x148E68,
    0xD103C, 0xD10A8, 0xD10C4,
    0xCB5B0,
    0x143AFC,
    0xCD558, 0x65CDF4, 0x14A228, 0x65BBD8, 0x65DAD0,
    0x149028, 0x65DDA8,
    0xCE5C8, 0x2106F4,
    0x660C34, 0xAD90C, 0x145C3C, 0x145150,
    0x14905C, 0xCD8CC, 0x12845C,
    0x65CF58]
BL_TARGETS_HELPER = [0x149028, 0x176828]

ALL_STUBS = sorted(set(BL_TARGETS_B60 + BL_TARGETS_HELPER + [B060]))
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


def ctx_fixture(state=6, arg18=0x100):
    # 0xD0 bytes, sentinel 0xA5
    buf = bytearray(b'\xA5' * 0xD0)
    struct.pack_into('<I', buf, 4, state)          # word state
    buf[8] = 0xFF                                  # open leftover
    buf[9] = 0x5A                                  # open leftover
    struct.pack_into('<I', buf, 0x18, arg18)        # word arg18
    return bytes(buf)


def guard_fixture(guard=1):
    # 8 bytes at 0x365750 with the guard byte at +1
    buf = bytearray([0xA3] * 8)
    buf[1] = guard
    return bytes(buf)


def base_fix(state=6, guard=1, arg18=0x100, mode=0x2B):
    return [('.ctxfix', CTX, ctx_fixture(state, arg18)),
            ('.guardfix', GUARD_CELL - 1, guard_fixture(guard)),
            ('.modefix', MODE_CELL, bytes([mode])),
            ('.gatefix', GATE_CELL, b'\xA5'),
            ('.gptrfix', GATE_P_CELL,
             struct.pack('<I', 0x368000)),
            ('.tgtfix', GATE_TGT, b'\xA5'),
            ('.logfix', 0x367000, bytes(0x800))]


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'aslv_helper_d098_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, _ = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp,
                   action='aslv-helper-d098',
                   limits=['Static analysis + 7 synthetic CPU cases; '
                           'no hardware',
                           'Deep callees are stubs; originals executed: '
                           'helper body, millicode, guard getter 0xCA310, '
                           'shared epilogue, and (chain cases) the whole '
                           '0x65B060 handler body with its ORIGINAL mode '
                           'getter 0xCAD30',
                           'ctx 0x681F5C, guard byte 0x365751, mode byte '
                           '0xC8E80C, gate cells fixtures; runtime '
                           'producers not proven',
                           'Caller->event attribution over sorted registry '
                           'p3 handlers is range-based (heuristic)',
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
        a81, h81 = m[0x81]
        assert h81 == B060, hex(h81)
        a4405, h4405 = m[0x4405]
        assert h4405 == 0x65959C, hex(h4405)
        results['registry_p3'] = dict(
            n_records=len(recs) - 1,
            ev0081_handler=hex(h81),
            ev4405_handler=hex(h4405))

        # --- 2. static: pools --------------------------------------
        pools = {0x65D0E8: CTX, 0xCA30C: GUARD_CELL,
                 0x65AFF8: CTX, 0x65B00C: 0x442644,
                 0xCAAC4: MODE_CELL, 0x65B1C4: GATE_P_CELL,
                 0x65B1C8: 0x7530}
        for a, v in pools.items():
            src, bb = (p0, base[0]) if a < base[2] else (p2, base[2])
            got = struct.unpack_from('<I', src, a - bb)[0]
            assert got == v, (hex(a), hex(got), hex(v))
        results['pools'] = {hex(a): hex(v) for a, v in pools.items()}

        # --- 3. static: LE scans -----------------------------------
        hitsE = [(i, a, o) for (i, a, o)
                 in le_scan(payloads, base, ENTRY) if o == 0]
        assert hitsE == [], hitsE
        hitsG = [(i, a, o) for (i, a, o)
                 in le_scan(payloads, base, 0xCA310) if o == 0]
        assert hitsG == [], hitsG
        hitsW = [(i, a, o) for (i, a, o)
                 in le_scan(payloads, base, 0x659588) if o == 0]
        assert hitsW == [], hitsW
        # [ctx+0x1C] is pooled by 6 other sites (documented, NOT the
        # helper which uses r13 base addressing)
        hits1C = [(i, a, o) for (i, a, o)
                  in le_scan(payloads, base, CTX + 0x1C) if o == 0]
        expect1C = [0x659934, 0x659F9C, 0x65A3E0, 0x65A49C,
                   0x65B874, 0x65B9D4]
        assert sorted(a for (i, a, o) in hits1C) == expect1C, hits1C
        assert set(i for (i, a, o) in hits1C) == {2}, hits1C
        results['le_scans'] = dict(
            entry_pool_sites=len(hitsE),
            guard_getter_pool_sites=len(hitsG),
            epilogue_pool_sites=len(hitsW),
            ctx1c_pool_sites=[hex(a) for (i, a, o) in hits1C])

        # --- 4. static: bl census of the helper ---------------------
        objcopy = ROOT / 'work/build-arc/binutils/objcopy'
        objdump = ROOT / 'work/build-arc/binutils/objdump'
        assert objcopy.is_file() and objdump.is_file()
        call_sites = []
        total = 0
        with tempfile.TemporaryDirectory(prefix='it36-census-') as td:
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
                for line in text.splitlines():
                    if f';0x{ENTRY:x}' not in line:
                        continue
                    parts = [p for p in line.split('\t') if p]
                    addr = int(parts[0].strip().rstrip(':'), 16)
                    mn = parts[2].strip() if len(parts) > 2 else ''
                    assert mn.startswith('bl'), (line, mn)
                    call_sites.append((addr, mn))
        assert total == 5, total
        assert sorted(a for a, _ in call_sites) == \
            [0x65B1F6, 0x65BFA0, 0x65C18C, 0x65C23C, 0x65C30E], \
            call_sites
        # range-based attribution over the sorted registry handlers
        hs = sorted(set(h for (ev, h, a) in recs[:-1]))
        attrib = {}
        for site, _ in call_sites:
            owner = None
            for h in hs:
                if h <= site:
                    owner = h
            assert owner is not None, hex(site)
            evs = sorted(ev for (ev, h, a) in recs[:-1] if h == owner)
            attrib[hex(site)] = [hex(e) for e in evs]
        results['bl_census'] = dict(
            total=total,
            sites=[(hex(a), mn) for a, mn in sorted(call_sites)],
            caller_events=attrib)

        # --- 5. static: opcode freezes -------------------------------
        freezes = [
            ('helper_body', 2, ENTRY,
             'f1c096088e6bfc1cc8b60a230037087610d5018586e01cf4620a8d3'
             '681e018f4c97004d96e0fcd75c9700fd9660fcd7503d800dfe9713'
             '2da5a0f8d8c02d801a5c97081d901da860fcffefcada5040ffe'),
            ('helper_pool', 2, 0x65D0E8, '5c1f6800'),
            ('epilogue', 2, 0x659588, '0a24c03604141b3405044e6d'),
            ('guard_getter', 0, 0xCA30C, '51573600fc1700f00088e07e'),
            ('millicode_push', 0, 0x33412C,
             'fc1cc8b3fc1c88b3fc1c48b3e07e'),
            ('millicode_pop', 0, 0x334194,
             '04dc0cdd1ff0e078'),
            ('caller_1', 2, 0x65B1F6, 'a60ec000'),
            ('caller_2', 2, 0x65BFA0, 'fa088000'),
            ('caller_3', 2, 0x65C18C, '0e0f4000'),
            ('caller_4', 2, 0x65C23C, '5e0e4000'),
            ('caller_5', 2, 0x65C30E, '8e0d4000'),
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
        for (pidx, lo, hi, sec) in sorted(WINS_CHAIN,
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
                                   action='aslv-helper-d098'))
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

        def spec(name, chain, rets, fixkw, logs, extra=None):
            asserts = []
            for i, (sid, a0, a1, a2) in enumerate(logs):
                asserts += L(i, sid, a0, a1, a2)
            n = len(logs)
            asserts += [(CNT, 4, n)]
            asserts += L(n, 0, None, None, None)   # no extra calls
            asserts += [(RETCELL, 4, rets.pop('_ret'))]
            if extra:
                asserts += extra
            return (name, chain, rets, fixkw, asserts)

        # b060 log building blocks (from the it.34 verifier; b060 is
        # called by the helper with (node,0x81,1))
        def HEAD(e68=1):
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

        def TEAR(mode, cd558=0, cdf4=0, ce5c8=0, f2106=0, cd8cc=0,
                 q128=0, r1mid=0x442644):
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

        # helper head: the two 149028 calls see the harness r2
        # garbage (0x22); 176828 has both args set by the helper
        def HELPER_HEAD():
            return [(S[0x149028], NODE, 4, 0x22),
                    (S[0x149028], NODE, 0xF, 0x22),
                    (S[0x176828], 3, 0, 0x32)]

        # memory asserts shared by all cases
        BASE_MEM = [(CTX + 8, 1, 0xFF), (CTX + 9, 1, 0x5A),
                    (CTX + 0x24, 1, 0xA5),
                    (GUARD_CELL - 1, 1, 0xA3),
                    (GUARD_CELL + 1, 1, 0xA3)]

        specs = []

        # 1 gate pass, b060 stubbed
        specs.append(spec(
            'd098_pass_s6_g1', False,
            {0x65B060: 0, '_ret': 0},
            dict(state=6, guard=1, arg18=0x100, mode=0x2B),
            HELPER_HEAD() + [(S[0x65B060], NODE, 0x81, 1)],
            extra=BASE_MEM + [
                (CTX + 4, 4, 2), (CTX + 0x1C, 1, 0),
                (CTX + 0x1D, 1, 0xA5), (CTX + 0x18, 4, 0x100),
                (GUARD_CELL, 1, 1),
                (GATE_CELL, 1, 0xA5), (GATE_TGT, 1, 0xA5)]))

        # 2 gate fail on state (getter skipped)
        specs.append(spec(
            'd098_gate_s5', False,
            {'_ret': 5},
            dict(state=5, guard=1, arg18=0x100, mode=0x2B),
            [],
            extra=BASE_MEM + [
                (CTX + 4, 4, 5), (CTX + 0x1C, 1, 0xA5),
                (CTX + 0x18, 4, 0x100), (GUARD_CELL, 1, 1),
                (GATE_CELL, 1, 0xA5), (GATE_TGT, 1, 0xA5)]))

        # 3 gate fail on guard (getter executed, returns 7)
        specs.append(spec(
            'd098_gate_g7', False,
            {'_ret': 7},
            dict(state=6, guard=7, arg18=0x100, mode=0x2B),
            [],
            extra=BASE_MEM + [
                (CTX + 4, 4, 6), (CTX + 0x1C, 1, 0xA5),
                (CTX + 0x18, 4, 0x100), (GUARD_CELL, 1, 7),
                (GATE_CELL, 1, 0xA5), (GATE_TGT, 1, 0xA5)]))

        # 4 gate fail on guard 0 (boundary)
        specs.append(spec(
            'd098_gate_g0', False,
            {'_ret': 0},
            dict(state=6, guard=0, arg18=0x100, mode=0x2B),
            [],
            extra=BASE_MEM + [
                (CTX + 4, 4, 6), (CTX + 0x1C, 1, 0xA5),
                (CTX + 0x18, 4, 0x100), (GUARD_CELL, 1, 0),
                (GATE_CELL, 1, 0xA5), (GATE_TGT, 1, 0xA5)]))

        # 5 chain: helper -> REAL b060, mode 2B, arg18 0x100
        specs.append(spec(
            'd098_chain_teardown_2b', True,
            {0x17083C: 1, 0x148E68: 1, 0xCD558: 1, 0x65CF58: 0,
             '_ret': 0},
            dict(state=6, guard=1, arg18=0x100, mode=0x2B),
            HELPER_HEAD() + HEAD() + GATE() + CLEAR()
            + TEAR(mode=0x2B, cd558=1),
            extra=BASE_MEM + [
                (CTX + 4, 4, 0), (CTX + 0x1C, 1, 0),
                (CTX + 0x1E, 1, 1), (CTX + 0x1D, 1, 0),
                (CTX + 0x18, 4, 0), (GATE_CELL, 1, 0),
                (GATE_TGT, 1, 0), (GUARD_CELL, 1, 1)]))

        # 6 chain: arg18 0x101 NOT cancelled, mode 2C
        specs.append(spec(
            'd098_chain_nocancel_2c', True,
            {0x17083C: 1, 0x148E68: 1, 0x12845C: 1, 0x65CF58: 0,
             '_ret': 0},
            dict(state=6, guard=1, arg18=0x101, mode=0x2C),
            HELPER_HEAD() + HEAD() + GATE() + NOCLR()
            + TEAR(mode=0x2C, q128=1),
            extra=BASE_MEM + [
                (CTX + 4, 4, 0), (CTX + 0x1C, 1, 0),
                (CTX + 0x1E, 1, 1), (CTX + 0x1D, 1, 0),
                (CTX + 0x18, 4, 0x101), (GATE_CELL, 1, 0),
                (GATE_TGT, 1, 0), (GUARD_CELL, 1, 1)]))

        # 7 chain: mode 7E (149028(node,9) + 65DDA8 inside b060)
        specs.append(spec(
            'd098_chain_7e', True,
            {0x17083C: 1, 0x148E68: 1, 0x65CF58: 0, '_ret': 0},
            dict(state=6, guard=1, arg18=0x100, mode=0x7E),
            HELPER_HEAD() + HEAD() + GATE() + CLEAR()
            + TEAR(mode=0x7E, r1mid=0),
            extra=BASE_MEM + [
                (CTX + 4, 4, 0), (CTX + 0x1C, 1, 0),
                (CTX + 0x1E, 1, 1), (CTX + 0x1D, 1, 0),
                (CTX + 0x18, 4, 0), (GATE_CELL, 1, 0),
                (GATE_TGT, 1, 0), (GUARD_CELL, 1, 1)]))

        cases = []
        for idx, (name, chain, rets, fixkw, asserts) in \
                enumerate(specs):
            rets = dict(rets)
            success = 0xDEADB001 + idx
            stub_addrs = [a for a in ALL_STUBS
                          if not (chain and a == B060)]
            # assert no stub overlaps a loaded original window
            wins = WINS_CHAIN if chain else WINS_ISOLATED
            for a in stub_addrs:
                for (_, wlo, whi, _) in wins:
                    assert not (wlo <= a < whi), (hex(a), hex(wlo))
            rettab = bytearray(4 * (max(STUBS.values()) + 1))
            for a, v in rets.items():
                if a == '_ret':
                    continue
                struct.pack_into('<I', rettab, 4 * STUBS[a],
                                 v & 0xFFFFFFFF)
            fix = base_fix(**fixkw) + [('.rettab', RETTAB,
                                         bytes(rettab))]
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
            asm = (harness(ENTRY, [NODE, 0x11, 0x22])
                   + ''.join(
                       (f'.section .stub_{a:x},"ax",@progbits\n'
                        ' .org 0\n' + stub_body(STUBS[a]))
                       for a in stub_addrs)
                   + common_logger()
                   + probe(asserts, success, idx)
                   + fixture_sections(fix))
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
            cases.append(dict(name=name, entry=hex(ENTRY),
                              chain=chain,
                              success=hex(success),
                              exit_code=case['exit_code'],
                              instructions=case['instructions'],
                              fault=fault))
            print(f'PASS {name} -> {hex(success)}', flush=True)

        results['cpu_cases'] = cases
        results['stub_map'] = {hex(a): STUBS[a] for a in ALL_STUBS}
        results['status'] = 'PASS_ASLV_HELPER_D098'
        print('PASS_ASLV_HELPER_D098', stamp)
        print('Evidence:', out / 'verified_evidence.json')
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'verified_evidence.json').write_text(
            json.dumps(results, indent=2, default=str) + '\n')


if __name__ == '__main__':
    main()
