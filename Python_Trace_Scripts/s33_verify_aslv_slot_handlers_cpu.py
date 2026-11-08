#!/usr/bin/env python3
"""Static + CPU verification of the AutoSceneLiveView slot-button handlers of
the Nikon S33 firmware (V1.1): press collector 0x65C46C (registry events
0x580/0x700/0x2180/0x2700), release handler 0x65C6B4 (0x581/0x2701) and the
chained slot mapper 0x65C5F8.

Closes the open point of iteration 23 (checkpoint 2026-11-01): the p3 window
registry 0x783B08 (block 3, AutoSceneLiveView descriptor at 0x783AE8, name
"AutoSceneLiveView" at 0x783C4A, wrapper 0x6593A0 -> router 0x169F60) maps the
four logical button slots to ONE handler; here the handler chain is decoded
and executed on ORIGINAL firmware bytes.

Facts asserted here (byte-exact on the verified payloads + 16 CPU cases on
the GNU ARC700 simulator executing ORIGINAL firmware bytes):

- REGISTRY p3 0x783B08: 38 records {u16 ev, pad, u32 handler} stride 8,
  terminator {0, 0x20E814} at 0x783C40. 0x580/0x700/0x2180/0x2700 ->
  0x65C46C (0x783BAC/BB4/BB8/BC4), 0x581/0x2701 -> 0x65C6B4
  (0x783BCC/BD4), 0x4401 -> 0x659554, 0x7D40 -> 0x65AB5C.
  LE scans over all 16 payloads: 0x65C46C and 0x65C6B4 appear ONLY in the
  registry handler fields; 0x6593A0 only in the descriptor (0x783AF4);
  0x65C5F8 has ZERO 4-aligned words and exactly 2 bl callers
  (0x65C5D4 bl, 0x65C6F0 bl_s). 0x65C46C/0x65C6B4/0x6593A0 have ZERO bl
  callers in the 16 GNU listings.

- DESCRIPTOR 0x783AE8..0x783AFC: {0x442, 0x330087, 0x783A1C, 0x6593A0, 0,
  0x783C4A}; name "AutoSceneLiveView"; subwindow array at 0x783A1C with 14
  p3 pointers (IDs at +4: 0x480C, 0x480E, 0x480D, 0x4801, 0x4802, 0x4803,
  0x4804, 0x4805, 0x4809, 0x4806, 0x4807, 0x4808, 0x480A, 0x480B, order
  non-contiguous) then p1 pointers (0x3ABA38, ...). Wrapper 0x6593A0:
  event filter [0x80..0x307F], r14 = (ev & 0x3F80) >> 7, calls
  0x169F60(0x681F5C, 0x783B08, node, ev, arg) via pool 0x659550.

- PRESS 0x65C46C(node, ev, arg), r16 = 0:
  mode = ORIGINAL getter 0xCAD30 (byte 0xC8E80C). If mode == 0x7E: double
  gate 0xCD5AC (byte[0x3657DB] < 2, first call must be != 0, second == 1),
  then 0x145A60(node, 0x480C, 2) != 0 required; then event switch:
  0x700 -> FUNCTION EXIT (no notify); other than 0x580/0x2180/0x2700 ->
  EXIT; 0x580/0x2180/0x2700 -> 0xCD5AC() == 1 -> 0x65D534(node).
  Then v = 0x14918C(node, 9) (timer-exists predicate): v != 0 -> block
  0x65C516; v == 0 -> 0x14905C(node, 9, 0x1388, 0x32, 0) + 0x65D1CC +
  0x65D850 + 0x145150 and EXIT WITHOUT CHAIN (mode == 0x7E adds an
  0xCD5AC() == 0 second entry to 0x65C516). Block 0x65C516: if
  0x12845C() != 0: r13 = 0x14504C(node, 6); 0x149028(node, 0xE); r16 = 1;
  if r13 > 0 loop i = r13-1..0: id = halfword[[0x783A1C + 4*i] + 4];
  0x145B08(node, id, 0); then 0x145B08(node, 0x4A12/0x4A87/0x4A8A, 1) +
  0x145150(node) + 0x15A5C8() + 0x17BF60(0, 0x80, 0x307F) (queue cancel
  [0x80..0x307F]); if ev == 0x580 additionally 0x145B08(node, 0x4A87/0x4A8A,
  0) + 0x65D1CC + 0x65D850 + 0x145150. Then if mode == 0x2C and r16 == 0
  and ev in {0x580, 0x2700}: 0x26C508() and EXIT; else CHAIN
  0x65C5F8(node, ev, arg).

- CHAIN 0x65C5F8(node, ev, arg): 0x700 -> 0x632798(1) + 0x1453E4(2, 4);
  0x2180 -> 0x632798(2) + 0x1453E4(2, 5); 0x2700 -> 0x632798(3) +
  0x1453E4(0xB7, 1); 0x2701 -> mode gate 0x2C then as 0x2700, else
  0x1453E4(0, 0) (r14/r15 zeroed); 0x580 and default -> 0xD2500(0) and if
  mode == 0x2C exit, else 0x632798(0) + 0xCBDF8 + 0x177030 + 0xD0924
  (!= 0 -> 0xCB5E4) + 0xCAD30 + 0xCFCAC + 0x65E8C4(1) + 0xCA404(0x2C) +
  0xCAFBC + 0x1453E4(0x87, 0). This is the ORIGIN of the synthetic-bank
  observation "0x700 -> ID 2 arg 4, 0x2180 -> ID 2 arg 5" and gives the
  first slot-differentiated behaviour: slot 0 (0x580) drives a mode-0x2C
  transition + window 0x87, slot 3 (0x2700) notifies window 0xB7.

- RELEASE 0x65C6B4(node, ev, arg): r16 = 0; if mode == 0x2C and
  0x26C4F8() != 0 (byte[0x36B43D] != 0) then r16 = 1; 0x26C538() always;
  r16 == 0 -> EXIT without chain; else CHAIN 0x65C5F8(node, ev, arg).

- EXITS: 0x65C5D8/0x65C6B0 -> b 0x65B1B8 (mov sp,fp; ld.ab fp,[sp,4];
  b 0x334184 millicode pop), 0x65C6F2 -> b 0x659F8C (b 0x33418C). Both
  tail-b 32-bit negative displacements (-5152/-5368/-10084) were proven
  CORRECT in the simulator by micro-test (tmp/it25/blmicro, trace), unlike
  the it.44 wrap case.

CPU cases (original windows 0x65C46C..0x65C5F8 + pools, 0x65C5F8..0x65C6B4,
0x65C6B4..0x65C6F8, epilogues 0x65B1B8/0x659F8C, millicode push 0x334114..A /
pop 0x33417C..E4, ORIGINAL mode getter 0xCAAC4..0xCAD38; stubs log
{id, r0, r1, r2} at 0x367100+16k, counter 0x367000):
 1 press_700            mode 0x36 -> 0x1453E4(2, 4)
 2 press_2180           mode 0x36 -> 0x1453E4(2, 5)
 3 press_2700           mode 0x36 -> 0x1453E4(0xB7, 1)
 4 press_580_mode2c     mode 0x2C -> 0x26C508 only, NO chain
 5 press_580_not2c      mode 0x36 -> 0xCA404(0x2C) + 0x1453E4(0x87, 0)
 6 press_580_d0924gate  0xD0924 != 0 -> extra 0xCB5E4
 7 press_580_busy       0x14918C == 0 -> 0x14905C block, EXIT, no chain
 8 press_2180_closeblk  0x12845C != 0 -> close block (2 ids) + chain (2, 5)
 9 press_580_closeblk2c close block + 0x580 extras + chain exits in 0x2C
10 press_700_mode7e     mode 0x7E gates pass -> 0x700 EXITS, no notify
11 press_2180_mode7e   mode 0x7E -> 0x65D534(node) + chain (2, 5)
12 press_2180_cd5ac0    mode 0x7E, 0xCD5AC == 0 -> skip + chain (2, 5)
13 rel_2701_2c_gate     mode 0x2C, 0x26C4F8 != 0 -> chain -> (0xB7, 1)
14 rel_2701_2c_nogate   r16 = 0 -> 0x26C538 only, no chain
15 rel_581_2c_gate      chain default -> 0xD2500(0), exit (no notify)
16 rel_2701_not2c       mode 0x36 -> 0x26C538 only, no chain

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
LOCAL_COMMON_AT = 0x26C400     # logger for the 0x26C4F8/0x26C508 stub pair
CNT = 0x367000
LOG_ENT = 0x367100
RETTAB = 0x367400

# 0x26C4F8 and 0x26C508 are only 16 bytes apart: the standard 20-byte stub
# (mov r12 needs a LIMM for COMMON_AT) does not fit, so these two use a
# 6-byte short body (push/mov_s/b_s) to the local logger.
SHORT_STUBS = {0x26C4F8, 0x26C508}

# original windows (payload, lo, hi, section)
W_MILI_PUSH = (0, 0x334114, 0x33413A, '.mcpush')
W_MILI_POP = (0, 0x33417C, 0x3341E4, '.mcpop')
W_PRESS = (2, 0x65C46C, 0x65C5F8, '.press')     # handler + pools 65C5DC..F4
W_CHAIN = (2, 0x65C5F8, 0x65C6B4, '.chain')     # incl. tail-b 0x65C6B0
W_REL = (2, 0x65C6B4, 0x65C6F8, '.rrel')       # incl. tail-b 0x65C6F2
W_EPI_A = (2, 0x65B1B8, 0x65B1C4, '.epiA')     # -> millicode pop 0x334184
W_EPI_B = (2, 0x659F8C, 0x659F98, '.epiB')     # -> millicode pop 0x33418C
W_MODE = (0, 0xCAAC4, 0xCAD38, '.mode')         # mode getter + ld.as pool

ALL_WINS = [W_MILI_PUSH, W_MILI_POP, W_PRESS, W_CHAIN, W_REL,
            W_EPI_A, W_EPI_B, W_MODE]

# stubs: address -> sid
STUBS = {0xCD5AC: 1, 0x145A60: 2, 0x65D534: 3, 0x14918C: 4, 0x14905C: 5,
         0x65D1CC: 6, 0x65D850: 7, 0x145150: 8, 0x12845C: 9, 0x14504C: 10,
         0x149028: 11, 0x145B08: 12, 0x15A5C8: 13, 0x17BF60: 14,
         0x26C508: 15, 0x1453E4: 16, 0x632798: 17, 0xD2500: 18,
         0xCBDF8: 19, 0x177030: 20, 0xD0924: 21, 0xCB5E4: 22, 0xCFCAC: 23,
         0x65E8C4: 24, 0xCA404: 25, 0xCAFBC: 26, 0x26C4F8: 27, 0x26C538: 28}

NODE = 0x1234
ARG = 0x77

C_MODE = 0xC8E80C           # mode byte read by the ORIGINAL getter 0xCAD30
REG_P3 = 0x783B08            # AutoSceneLiveView notify registry
DESC = 0x783AE8              # descriptor {0x442, 0x330087, arr, wrapper,...}
ARR = 0x783A1C               # subwindow pointer array
ARR_FIX_N = 4                 # pointers mapped in CPU fixtures
P1 = 0x500000                # synthetic subwindow descriptors
P2 = 0x500010

WIN_PRESS = [W_MILI_PUSH, W_MILI_POP, W_PRESS, W_CHAIN, W_REL,
             W_EPI_A, W_EPI_B, W_MODE]
WIN_REL = WIN_PRESS


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


def short_stub_body(sid):
    """16 bytes exactly: push blink, sid in r7, absolute jl to the local
    logger (which pops blink itself). PC-relative branches here would be
    assembled against the section base and misplace after linking."""
    body = (' push_s blink\n'
            f' mov r7,{hex(sid)}\n'
            f' mov r12,{hex(LOCAL_COMMON_AT)}\n'
            ' jl_s [r12]\n')
    return body


def local_logger():
    """Same contract as common_logger, but pops blink itself (short stubs
    save blink and branch here)."""
    return (f'.section .lcommon,"ax",@progbits\n .org 0\n'
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
            ' pop_s blink\n'
            ' j_s [blink]\n')


def fixture_sections(fix):
    out = ''
    for name, base, data in fix:
        out += (f'.section {name},"aw",@progbits\n.align 4\n'
                + ''.join(f' .byte {b}\n' for b in data))
    return out


def L(idx, sid, a0, a1, a2):
    """expected log entry idx; None = don't care"""
    a = LOG_ENT + 16 * idx
    out = [(a, 4, sid)]
    for off, v in ((4, a0), (8, a1), (12, a2)):
        if v is not None:
            out.append((a + off, 4, v))
    return out


def arrfix(n=ARR_FIX_N):
    data = struct.pack('<I', P1) + struct.pack('<I', P2)
    data += b'\x00' * (4 * n - len(data))
    return data


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'aslv_slot_handlers_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, _ = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp, action='aslv-slot-handlers',
                   limits=['Static analysis + 16 synthetic CPU cases; no hardware',
                           'All deep callees are stubs (0x1453E4, 0x632798, '
                           '0x26C4F8/0x26C508/0x26C538, 0x14905C/0x14918C, '
                           '0x145B08, 0x17BF60, 0xCA404, ...); only the two '
                           'handlers, the chained mapper, the epilogues, the '
                           'millicode and the ORIGINAL mode getter execute',
                           'The mode byte 0xC8E80C, the subwindow array and '
                           'the descriptors are fixtures; runtime producers '
                           'are not proven',
                           'arg (r2) propagation through the chain is '
                           'preserved but its runtime meaning is unknown',
                           'No physical button map, no hardware, no '
                           'scheduling; V1.1 dump only; NON_INSTALLARE'])
    try:
        p2, p3 = payloads[2], payloads[3]
        p0 = payloads[0]

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
        assert len(recs) == 40, len(recs)     # 39 event records + terminator
        assert recs[-1] == (REG_P3 + 8 * 39, 0, 0, 0x20E814), recs[-1]
        for ev, h in ((0x580, 0x65C46C), (0x700, 0x65C46C),
                      (0x2180, 0x65C46C), (0x2700, 0x65C46C),
                      (0x581, 0x65C6B4), (0x2701, 0x65C6B4),
                      (0x4401, 0x659554), (0x7D40, 0x65AB5C),
                      (0x180, 0x65C2CC), (0x3101, 0x65C418)):
            assert m.get(ev) == h, (hex(ev), hex(m.get(ev) or 0), hex(h))
        assert m[0x580] == m[0x700] == m[0x2180] == m[0x2700]
        assert m[0x581] == m[0x2701]
        results['registry_p3'] = dict(
            n_records=len(recs) - 1,
            terminator=[hex(REG_P3 + 8 * 39), '0', hex(0x20E814)],
            slots={hex(k_): hex(v) for k_, v in m.items()
                   if k_ in (0x580, 0x700, 0x2180, 0x2700, 0x581, 0x2701)})

        # --- 2. static: descriptor + array + name ------------------------
        words = [struct.unpack_from('<I', p3, DESC + 4 * i - base[3])[0]
                 for i in range(6)]
        assert words == [0x442, 0x330087, ARR, 0x6593A0, 0, 0x783C4A], words
        name = p3[0x783C4A - base[3]:0x783C4A - base[3] + 18]
        assert name == b'AutoSceneLiveView\x00', name
        ids = []
        for i in range(14):
            ptr = struct.unpack_from('<I', p3, ARR + 4 * i - base[3])[0]
            assert base[3] <= ptr < base[3] + len(p3) - 8, hex(ptr)
            ids.append(struct.unpack_from('<H', p3, ptr + 4 - base[3])[0])
        assert ids == [0x480C, 0x480E, 0x480D, 0x4801, 0x4802, 0x4803,
                       0x4804, 0x4805, 0x4809, 0x4806, 0x4807, 0x4808,
                       0x480A, 0x480B], [hex(i) for i in ids]
        nxt = struct.unpack_from('<I', p3, ARR + 4 * 14 - base[3])[0]
        assert nxt == 0x3ABA38, hex(nxt)
        results['descriptor'] = dict(
            fields=[hex(w) for w in words], name=name[:-1].decode(),
            array_ids=[hex(i) for i in ids], array_14=hex(nxt))

        # --- 3. static: wrapper pools (p2) -------------------------------
        pools = {0x659548: 0x681F5C, 0x65954C: 0x30D40, 0x659550: REG_P3,
                 0x65C5DC: 0x480C, 0x65C5E0: 0x1388, 0x65C5E4: ARR,
                 0x65C5E8: 0x4A12, 0x65C5EC: 0x4A87, 0x65C5F0: 0x4A8A,
                 0x65C5F4: 0x307F}
        for a, v in pools.items():
            src, bb = (p2, base[2]) if a >= base[2] else (p3, base[3])
            got = struct.unpack_from('<I', src, a - bb)[0]
            assert got == v, (hex(a), hex(got), hex(v))
        results['pools'] = {hex(a): hex(v) for a, v in pools.items()}

        # --- 4. static: LE scans ----------------------------------------
        want = {0x65C46C: [(3, REG_P3 + 0xA4, 0), (3, REG_P3 + 0xAC, 0),
                           (3, REG_P3 + 0xB4, 0), (3, REG_P3 + 0xBC, 0)],
                0x65C6B4: [(3, REG_P3 + 0xC4, 0), (3, REG_P3 + 0xCC, 0)],
                0x6593A0: [(3, DESC + 0xC, 0)],
                0x65C5F8: [],
                REG_P3: [(2, 0x659550, 0)]}
        le = {}
        for t, exp in want.items():
            hits = [(i, a, o) for (i, a, o) in le_scan(payloads, base, t)
                    if o == 0]
            assert hits == exp, (hex(t), hits, exp)
            le[hex(t)] = [(i, hex(a), o) for i, a, o in hits]
        n659554 = [(i, hex(a), o) for (i, a, o)
                   in le_scan(payloads, base, 0x659554) if o == 0]
        results['le_scans'] = le
        results['le_659554_extra'] = n659554

        # --- 5. static: bl census on 16 GNU listings --------------------
        census = {0x65C46C: 0, 0x65C6B4: 0, 0x6593A0: 0, 0x65C5F8: 0}
        objcopy = ROOT / 'work/build-arc/binutils/objcopy'
        objdump = ROOT / 'work/build-arc/binutils/objdump'
        assert objcopy.is_file() and objdump.is_file()
        with tempfile.TemporaryDirectory(prefix='it25-census-') as td:
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
        assert census == {0x65C46C: 0, 0x65C6B4: 0, 0x6593A0: 0,
                          0x65C5F8: 2}, census
        results['bl_census'] = {hex(k): v for k, v in census.items()}

        # --- 6. static: opcode freezes ----------------------------------
        freezes = [
            ('press_prologue', 2, 0x65C46C, 'f1c0ba0cce6bfc1c'),
            ('press_cmp700', 2, 0x65C4AA, '8c271c90'),
            ('press_cmp580', 2, 0x65C4B2, '8c271690'),
            ('press_pool_area', 2, 0x65C5DC,
             '0c480000881300001c3a7800124a0000874a00008a4a00007f300000'),
            ('press_tailb', 2, 0x65C5D8, 'e1034fff'),
            ('chain_prologue', 2, 0x65C5F8, 'f1c02e0bce6bfc1c'),
            ('chain_cmp2180', 2, 0x65C610, 'd771000080213bf2'),
            ('chain_tailb', 2, 0x65C6B0, '09034fff'),
            ('rel_prologue', 2, 0x65C6B4, 'f1c0760ace6bfc1c'),
            ('rel_bls_chain', 2, 0x65C6F0, 'c2ff'),
            ('rel_tailb', 2, 0x65C6F2, '9d00cffe'),
            ('epiA', 2, 0x65B1B8, '0a24c03604141b34c5074e6c'),
            ('epiB', 2, 0x659F8C, '0a24c03604141b34f9010e6d'),
            ('modegetter', 0, 0xCAD30, '651700f60088e07e'),
            ('mode_pool', 0, 0xCAAC4, '0ce8c800'),
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
                                   output=out, action='aslv-slot-handlers'))
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

        def arr_fixture():
            return [('.arrfix', ARR, arrfix()),
                    ('.descfix', P1, descfix())]

        def descfix():
            buf = bytearray(b'\xA5' * 0x20)
            struct.pack_into('<H', buf, P1 + 4 - P1, 0x480C)
            struct.pack_into('<H', buf, P2 + 4 - P1, 0x480D)
            return bytes(buf)

        def base_fix(mode):
            return [('.modfix', C_MODE, bytes([mode, 0xA5, 0xA5, 0xA5])),
                    ('.logfix', 0x367000, bytes(0x300))]

        # (name, entry, args, rets, fixlist, asserts)
        specs = []

        def spec(name, entry, ev, mode, rets, logs, extra_fix=None,
                 cnt=None):
            args = (NODE, ev, ARG)
            asserts = []
            for i, (sid, a0, a1, a2) in enumerate(logs):
                asserts += L(i, sid, a0, a1, a2)
            n = cnt if cnt is not None else len(logs)
            asserts += [(CNT, 4, n)]
            asserts += L(n, 0, None, None, None)     # no extra calls
            asserts += [(C_MODE + 1, 1, 0xA5), (C_MODE + 3, 1, 0xA5)]
            fix = base_fix(mode) + (extra_fix or [])
            specs.append((name, entry, args, rets, fix, asserts))

        # shorthand
        s_14918C, s_12845C = 4, 9
        s_26C508, s_26C4F8, s_26C538 = 15, 27, 28
        s_632798, s_1453E4, s_D2500 = 17, 16, 18
        s_CBDF8, s_177030, s_D0924, s_CB5E4 = 19, 20, 21, 22
        s_CFCAC, s_65E8C4, s_CA404, s_CAFBC = 23, 24, 25, 26
        s_CD5AC, s_145A60, s_65D534 = 1, 2, 3
        s_14905C, s_65D1CC, s_65D850, s_145150 = 5, 6, 7, 8
        s_14504C, s_149028, s_145B08 = 10, 11, 12
        s_15A5C8, s_17BF60 = 13, 14

        # ---- press cases ----
        spec('press_700', 0x65C46C, 0x700, 0x36,
             {0x14918C: 1, 0x12845C: 0},
             [(s_14918C, NODE, 9, None), (s_12845C, 1, None, None),
              (s_632798, 1, None, None), (s_1453E4, 2, 4, None)])
        spec('press_2180', 0x65C46C, 0x2180, 0x36,
             {0x14918C: 1, 0x12845C: 0},
             [(s_14918C, NODE, 9, None), (s_12845C, 1, None, None),
              (s_632798, 2, None, None), (s_1453E4, 2, 5, None)])
        spec('press_2700', 0x65C46C, 0x2700, 0x36,
             {0x14918C: 1, 0x12845C: 0},
             [(s_14918C, NODE, 9, None), (s_12845C, 1, None, None),
              (s_632798, 3, None, None), (s_1453E4, 0xB7, 1, None)])
        spec('press_580_mode2c', 0x65C46C, 0x580, 0x2C,
             {0x14918C: 1, 0x12845C: 0},
             [(s_14918C, NODE, 9, None), (s_12845C, 1, None, None),
              (s_26C508, None, None, None)])
        spec('press_580_not2c', 0x65C46C, 0x580, 0x36,
             {0x14918C: 1, 0x12845C: 0},
             [(s_14918C, NODE, 9, None), (s_12845C, 1, None, None),
              (s_D2500, 0, None, None), (s_632798, 0, None, None),
              (s_CBDF8, None, None, None), (s_177030, None, None, None),
              (s_D0924, None, None, None), (s_CFCAC, None, None, None),
              (s_65E8C4, 1, None, None), (s_CA404, 0x2C, None, None),
              (s_CAFBC, None, None, None), (s_1453E4, 0x87, 0, None)])
        spec('press_580_d0924gate', 0x65C46C, 0x580, 0x36,
             {0x14918C: 1, 0x12845C: 0, 0xD0924: 1},
             [(s_14918C, NODE, 9, None), (s_12845C, 1, None, None),
              (s_D2500, 0, None, None), (s_632798, 0, None, None),
              (s_CBDF8, None, None, None), (s_177030, None, None, None),
              (s_D0924, None, None, None), (s_CB5E4, None, None, None),
              (s_CFCAC, None, None, None), (s_65E8C4, 1, None, None),
              (s_CA404, 0x2C, None, None), (s_CAFBC, None, None, None),
              (s_1453E4, 0x87, 0, None)])
        spec('press_580_busy', 0x65C46C, 0x580, 0x36,
             {0x14918C: 0},
             [(s_14918C, NODE, 9, None),
              (s_14905C, NODE, 9, 0x1388), (s_65D1CC, NODE, None, None),
              (s_65D850, None, None, None), (s_145150, NODE, None, None)])
        spec('press_2180_closeblk', 0x65C46C, 0x2180, 0x36,
             {0x14918C: 1, 0x12845C: 2, 0x14504C: 2},
             [(s_14918C, NODE, 9, None), (s_12845C, 1, None, None),
              (s_14504C, NODE, 6, None), (s_149028, NODE, 0xE, None),
              (s_145B08, NODE, 0x480D, 0), (s_145B08, NODE, 0x480C, 0),
              (s_145B08, NODE, 0x4A12, 1), (s_145B08, NODE, 0x4A87, 1),
              (s_145B08, NODE, 0x4A8A, 1), (s_145150, NODE, None, None),
              (s_15A5C8, None, None, None), (s_17BF60, 0, 0x80, 0x307F),
              (s_632798, 2, None, None), (s_1453E4, 2, 5, None)],
             extra_fix=arr_fixture())
        spec('press_580_closeblk2c', 0x65C46C, 0x580, 0x2C,
             {0x14918C: 1, 0x12845C: 1, 0x14504C: 1},
             [(s_14918C, NODE, 9, None), (s_12845C, 1, None, None),
              (s_14504C, NODE, 6, None), (s_149028, NODE, 0xE, None),
              (s_145B08, NODE, 0x480C, 0),
              (s_145B08, NODE, 0x4A12, 1), (s_145B08, NODE, 0x4A87, 1),
              (s_145B08, NODE, 0x4A8A, 1), (s_145150, NODE, None, None),
              (s_15A5C8, None, None, None), (s_17BF60, 0, 0x80, 0x307F),
              (s_145B08, NODE, 0x4A87, 0), (s_145B08, NODE, 0x4A8A, 0),
              (s_65D1CC, NODE, None, None), (s_65D850, None, None, None),
              (s_145150, NODE, None, None), (s_D2500, 0, None, None)],
             extra_fix=arr_fixture())
        spec('press_700_mode7e', 0x65C46C, 0x700, 0x7E,
             {0xCD5AC: 1, 0x145A60: 1},
             [(s_CD5AC, None, None, None), (s_CD5AC, None, None, None),
              (s_145A60, NODE, 0x480C, 2)])
        spec('press_2180_mode7e', 0x65C46C, 0x2180, 0x7E,
             {0xCD5AC: 1, 0x145A60: 1, 0x14918C: 1, 0x12845C: 0},
             [(s_CD5AC, None, None, None), (s_CD5AC, None, None, None),
              (s_145A60, NODE, 0x480C, 2), (s_CD5AC, None, None, None),
              (s_65D534, NODE, None, None), (s_14918C, NODE, 9, None),
              (s_12845C, 1, None, None), (s_632798, 2, None, None),
              (s_1453E4, 2, 5, None)])
        spec('press_2180_cd5ac0', 0x65C46C, 0x2180, 0x7E,
             {0xCD5AC: 0, 0x14918C: 1, 0x12845C: 0},
             [(s_CD5AC, None, None, None), (s_14918C, NODE, 9, None),
              (s_12845C, 1, None, None), (s_632798, 2, None, None),
              (s_1453E4, 2, 5, None)])
        # ---- release cases ----
        spec('rel_2701_2c_gate', 0x65C6B4, 0x2701, 0x2C,
             {0x26C4F8: 1, 0x26C538: 0},
             [(s_26C4F8, None, None, None), (s_26C538, None, None, None),
              (s_632798, 3, None, None), (s_1453E4, 0xB7, 1, None)])
        spec('rel_2701_2c_nogate', 0x65C6B4, 0x2701, 0x2C,
             {0x26C4F8: 0, 0x26C538: 0},
             [(s_26C4F8, None, None, None), (s_26C538, None, None, None)])
        spec('rel_581_2c_gate', 0x65C6B4, 0x581, 0x2C,
             {0x26C4F8: 1, 0x26C538: 0},
             [(s_26C4F8, None, None, None), (s_26C538, None, None, None),
              (s_D2500, 0, None, None)])
        spec('rel_2701_not2c', 0x65C6B4, 0x2701, 0x36,
             {0x26C538: 0},
             [(s_26C538, None, None, None)])

        cases = []
        for idx, (name, entry, args, rets, fix, asserts) in \
                enumerate(specs):
            success = 0xDEADB001 + idx
            stub_addrs = sorted(STUBS)
            rettab = bytearray(4 * (max(STUBS.values()) + 1))
            for a, v in rets.items():
                struct.pack_into('<I', rettab, 4 * STUBS[a], v & 0xFFFFFFFF)
            fix = list(fix) + [('.rettab', RETTAB, bytes(rettab))]
            stub_sections = (f'  .probe {hex(PROBE_AT)} : {{ *(.probe) }}\n'
                             f'  .common {hex(COMMON_AT)} : {{ *(.common) }}\n'
                             f'  .lcommon {hex(LOCAL_COMMON_AT)} : '
                             '{ *(.lcommon) }\n'
                             f'  .rettab {hex(RETTAB)} : {{ *(.rettab) }}\n')
            for addr in stub_addrs:
                stub_sections += (f'  .stub_{addr:x} {hex(addr)} : '
                                  f'{{ *(.stub_{addr:x}) }}\n')
            for sname, sbase, _ in fix:
                if sname == '.rettab':
                    continue
                stub_sections += f'  {sname} {hex(sbase)} : {{ *({sname}) }}\n'
            asm = (harness(entry, list(args))
                   + ''.join(f'.section .stub_{a:x},"ax",@progbits\n .org 0\n'
                             + (short_stub_body(STUBS[a]) if a in SHORT_STUBS
                                else stub_body(STUBS[a]))
                             for a in stub_addrs)
                   + common_logger()
                   + local_logger()
                   + probe(asserts, success, idx)
                   + fixture_sections(fix))
            case, sim_text = build_case(name, asm, WIN_PRESS,
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
        results['status'] = 'PASS_ASLV_SLOT_HANDLERS'
        print('PASS_ASLV_SLOT_HANDLERS', stamp)
        print('Evidence:', out / 'verified_evidence.json')
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'verified_evidence.json').write_text(
            json.dumps(results, indent=2, default=str) + '\n')


if __name__ == '__main__':
    main()
