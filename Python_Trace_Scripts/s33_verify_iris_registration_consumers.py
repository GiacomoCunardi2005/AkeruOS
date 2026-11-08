#!/usr/bin/env python3
"""Static verification of the runtime consumers of the iris pair
registration chain (V1.1) - iteration 34.

Closes the open point of iteration 31: WHO consumes, at runtime, the
registrations made by the iris setup 0x140568 - i.e. who reads
[0x5545F8+0x18] (the 0x1406D0 complement-commit invoker, stored by the
service 0x22C3BC) and [0x392AC0+0x1C] (the 0x140704 bit invoker, stored
by 0x16ACDC(7,2,ptr)) - and which task wakes on the event 0x3200002
bit 10 that 0x22C3BC raises at registration time.

Chain asserted here (payload0, byte-exact aligned windows + raw pools):

- MCUCTRL_Task = 0x15A80C (payload1 record 0x372508: id 0x3200001,
  entry 0x15A80C, stack 0x800, priority 6).  Its main loop CLEARS the
  waitable bits of the sibling event groups 0x3200002/0x3200003 at
  start-up, then WAITS with 0x158D04(0x3200002, 0x60F7F773, 0, 0),
  reads the received bits with 0x158E28(0x3200002, &sp) and
  auto-clears them with 0x158CE0(0x3200002, bits).  Dispatch:
  bit0 -> 0x241EC4, bits 4/5/6 -> 0x241F88, bits 8/9/10 -> 0x242104,
  bits 12..15 -> 0x2416F8, bits 20..23 -> 0x241E58 (a two-byte
  j_s [blink] EMPTY stub), bit 29 -> 0x241F0C + 0x241FC8; bit 30 clear
  loops back to the wait.
- 0x242104(bits) is the handler of bits 8/9/10 and the RUNTIME
  CONSUMER OF [0x5545F8+0x18]: on bit 8 it reads the current 32-bit
  value via 0x2D62B0, compares it with the halfword pair stored at
  [0x5545F8+0x2C/+0x2E], requires mode [0x5545F8+0x20]==2, refreshes
  the snapshot through 0x2B7190 (which stores value -> +0x30,
  value>>16 -> +0x28, value&0xFFFF -> +0x2A), increments the
  invocation counter +0x38 and, if [0x5545F8+0x18] != 0, calls it
  with r0 = [0x5545F8+0x30] (jl_s.d).  The registered pointer IS
  0x1406D0 (setup 0x140568 -> 0x22C3BC), so the iris complement
  commit is finally anchored to a runtime trigger.  On bit 9 it
  stores the new value pair at +0x2E/+0x2C and arms +0x20=2; on bit
  0xA it runs the stop sequence 0x2B7204 + 0x2B712C + 0x242094 and
  toggles the byte [0x5545F8+0] 0 -> 1.
- 0x241E5C is the RUNTIME CONSUMER OF [0x392AC0+0x1C]: it samples a
  value v through 0x169870, raises event 0x3200002 bit 1
  (0x158CBC(0x3200002, 2)), reads [0x392AC0+0x1C] and, if nonzero,
  calls it with r0 = v & 7 (bmsk r13,r0,0x2) and r1 = v & 0xF
  (bmsk r14,r0,0x3).  The registered pointer IS 0x140704 (setup
  0x140568 -> 0x16ACDC(7,2,ptr)): the three low bits dispatch to the
  id-1/id-2/id-4 cells of iteration 31.  0x241E5C has NO static
  caller: it lives as a function pointer in pool 0x241F78 and is
  registered under id 0x3002 by 0x241E94 (called once, at 0x16AA72,
  inside the 0x16AA5x init of the same family).
- 0x241EC4 is the RUNTIME CONSUMER OF [0x392AC0+0x18] (the second
  slot, written by 0x16AAB4 when the cell is empty and the gate byte
  [0x392AC0+0x2A] is set, which also raises event bit 0): it reads
  [r15+0x18] and calls it with r0 = [0x392AC0+0xC], writing the gate
  byte +0x2A around the call.  Audit reg-consumers-audit-34
  precision: the 0x16ABC0 store of [+0xC] runs only on its r0>0 path
  and both known call sites pass r0=0, so the STATIC writers of
  [+0xC] are the init 0x241E94 (stores 0x20 through 0x16AC14) and
  0x16C6AC (stores when [+0xC]==0).
- Event 0x3200002 producers mapped in this pass: 0x242040 (registered
  as a callback by 0x2420D0 through 0x16D898(0x609, fn); polls
  0x2D6200 and raises bit 8 = 256 on bit0, bit 9 = 512 on bit1),
  0x22C56C (stores its argument at [0x5545F8+0x8] and raises bit 10 =
  1024: a second bit-10 producer besides the 0x22C3BC registration),
  0x16C68C (raises bit 4 = 0x10 when the bytes +0x19/+0x0 of the
  struct 0x392D70 allow it; called from the iris setup itself at
  0x1405D6), 0x16C70C (raises bit 6 = 0x40 under the same gates).

Negatives: 0x1406D0 and 0x140704 have NO branch of any form toward
them in the whole linear listing (the only hit for 0x140704 is the
payload9 data artifact at 0xD3F696, classified with an aligned window:
the site is string/data fragments, not code).  0x241E5C, 0x242040,
0x16AAB4 and 0x22C56C have no direct bl callers: they are
pointer-only entries (0x16AAB4 is installed by the init 0x16A9F8
through pool 0x16ADC8 into the family table at struct+0x10, so it is
reachable through computed dispatch).  0x242104 has exactly ONE bl
caller: the MCUCTRL task site 0x15A8B6.  No LE word and no
middle-endian limm toward 0x5545F8/0x392AC0 outside the pool sites
asserted here (the unaligned LE hit of 0x1406D0 at 0x2B7475 is an
instruction straddle).

Read-only: firmware, blocks, tools and listings are never modified.
"""
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads
from s33_run_gnu_arc700 import ROOT, sha
from s33_verify_sensor_mmio_dialog import aligned_window

FIRMWARE = ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin'
EVIDENCE = ROOT / 'Risultati/Runtime_Kernel/Event_3200002_Consumers'
LISTING = ROOT / 'Risultati/Disassemblati/Firmware1.1.asm'

EVENT = 0x3200002
WAIT_MASK = 0x60F7F773
STRUCT_A = 0x5545F8          # monitor struct {+0x18 callback, +0x20 mode, ...}
STRUCT_B = 0x392AC0          # notification struct {+0xC value, +0x18/+0x1C ptrs}
TASK = 0x15A80C              # MCUCTRL_Task entry

# Literal words re-read from raw payload0 bytes (little-endian).
LITERALS = {
    0x15AAE0: EVENT,          # event id (task)
    0x15AAE4: WAIT_MASK,     # wait mask
    0x15AAE8: 0x3200003,     # sibling event group cleared at start
    0x15AAEC: 0x444CDC,      # task sub-object base
    0x15AAF0: 0x391B38,      # task context
    0x15AAF8: 0x15AAD4,      # deferred callback registered at init
    0x242200: STRUCT_A,       # monitor struct (handler 0x242104)
    0x242204: EVENT,          # event id (producer 0x242040)
    0x242208: 0x554634,      # status cell (producer 0x242040)
    0x242210: 0x242040,      # fn pointer registered by 0x2420D0
    0x242214: 0x36A6C8,      # flag struct of the handler
    0x242218: 0x1388,        # 5000 timeout
    0x24221C: 0x2420B4,      # timeout callback
    0x242220: 0x3A98,        # 15000 timeout
    0x241F70: EVENT,          # event id (mode consumer 0x241E5C)
    0x241F74: STRUCT_B,       # notification struct (mode consumer)
    0x241F78: 0x241E5C,      # mode consumer fn pointer
    0x241F7C: 0x3002,        # registration id
    0x241F80: 0x392ADC,      # STRUCT_B + 0x1C (gate bytes at +0xE/+0x5)
    0x24203C: 0x392D70,      # sibling struct (bits 4/5/6 handler)
    0x16ADC0: STRUCT_B,       # notification struct (0x16A family)
    0x16ADC4: 0x16AA94,      # fn pointer of the same family
    0x16ADC8: 0x16AAB4,      # fn pointer installed by 0x16A9F8 (+0x10)
    0x16AE00: 0x392ADC,      # STRUCT_B + 0x1C (byte cells)
    0x16AE04: EVENT,          # event id (producer 0x16AAB4)
    0x16C7C0: 0x392D70,      # sibling struct (0x16C6xx producers)
    0x16C7E4: EVENT,          # event id (producers 0x16C68C/0x16C70C)
    0x22C474: STRUCT_A,       # 0x22C3BC registration struct
    0x22C484: EVENT,          # event id raised by 0x22C3BC
    0x22C584: STRUCT_A,       # 0x22C56C struct
    0x22C588: EVENT,          # event id raised by 0x22C56C
    0x2B7234: STRUCT_A,       # monitor struct (0x2B71xx accessors)
    0x1405E8: 0x1406D0,      # complement invoker (setup registration)
    0x1405EC: 0x140704,      # bit invoker (setup registration)
}

# bl-form call censuses (linear GNU listing; chain sites re-asserted
# in aligned windows).
CENSUS_TARGETS = [0x242104, 0x241EC4, 0x241F88, 0x2416F8, 0x241E58,
                  0x241F0C, 0x241FC8, 0x241E94, 0x2420D0, 0x242094,
                  0x16C68C, 0x16C70C, 0x2B7190, 0x2D62B0, 0x2D6200,
                  0x22C35C, 0x16ABC0, 0x16AA94]
EXPECT_CALLS = {
    0x242104: {0x15A8B6},           # MCUCTRL task only
    0x241EC4: {0x15A896},
    0x241F88: {0x15A8A6},
    0x2416F8: {0x15A8C6},
    0x241E58: {0x15A8D6},           # bits 20..23 -> EMPTY stub
    0x241F0C: {0x15A8E0},
    0x241FC8: {0x15A8E4},
    0x241E94: {0x16AA72},           # init of the 0x16AA family
    0x2420D0: {0x22C3AE},           # 0x22C3xx service family
    0x242094: {0x2420C8, 0x2420F8, 0x242170, 0x2421EE},
    0x16C68C: {0x135580, 0x1405D6, 0x16C6D4},   # iris setup at 0x1405D6
    0x16C70C: {0x1406C8, 0x7D5396, 0x7D5434, 0x7D54D4,
               0x7D5660, 0x7D570A, 0x7D57B6},
    0x2B7190: {0x24214A, 0x2B71E4},
    0x2D62B0: {0x24212C, 0x242176, 0x2B71D6},
    0x2D6200: {0x242046, 0x2B71CE, 0x2B7222},
    0x22C35C: {0x15A84A},
    0x16ABC0: {0x241EDC, 0x241F30},
    0x16AA94: {0x16C704},
}


def he(n: int) -> str:
    return f'0x{n:x}'


def has(text: str, pattern: str) -> None:
    assert re.search(pattern, text), f'missing pattern: {pattern}'


def census_calls() -> dict:
    pat = re.compile(
        r'V([0-9A-F]{6,8}) \|[0-9a-f ]+\| '
        r'(bl|bl\.d|bl_s|bl_s\.d)\s+?-?\d+\s+;0x([0-9a-f]+)\b')
    hits = {t: [] for t in CENSUS_TARGETS}
    with LISTING.open('r', errors='replace') as fh:
        for line in fh:
            m = pat.search(line)
            if not m:
                continue
            target = int(m.group(3), 16)
            if target in hits:
                hits[target].append(int(m.group(1), 16))
    return hits


def census_branches(target: int) -> list:
    """All branch forms (bl* and b*) toward target in the listing."""
    pat = re.compile(
        r'V([0-9A-F]{6,8}) \|[0-9a-f ]+\| '
        r'(bl|bl\.d|bl_s|bl_s\.d|b|b\.d|b_s|b_s\.d)\s+?-?\d+\s+'
        r';0x([0-9a-f]+)\s*$')
    out = []
    with LISTING.open('r', errors='replace') as fh:
        for line in fh:
            m = pat.search(line)
            if m and int(m.group(3), 16) == target:
                out.append(int(m.group(1), 16))
    return out


def scan_word(payloads, info, value, middle_endian=False, aligned=True):
    """LE (or middle-endian limm) word sites of `value` per payload."""
    out = {}
    for idx, data in payloads.items():
        base = info[idx]['load_address_candidate']
        if middle_endian:
            pat = struct.pack('<H', value >> 16) + \
                struct.pack('<H', value & 0xFFFF)
        else:
            pat = struct.pack('<I', value)
        hits = []
        start = 0 if not aligned else (4 - base % 4) % 4
        for i in range(start, len(data) - 3, 4 if aligned else 1):
            if data[i:i + 4] == pat:
                hits.append(base + i)
        if hits:
            out[idx] = hits
    return out


def main() -> None:
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = EVIDENCE / stamp
    out.mkdir(parents=True, exist_ok=True)
    (out / 'script_snapshot.py').write_bytes(Path(__file__).read_bytes())
    assert sha(FIRMWARE) == ('1d34e990a8f99019ffa53ca5de785399'
                             'df863e942739a667ceb314ec6ce62a39')
    blocks, payloads, _ = verified_payloads(ROOT)
    info = {b['index']: b for b in blocks}
    base0 = info[0]['load_address_candidate']
    p0 = payloads[0]
    assert base0 == 0x0AD800

    # 1. Literal words verified against raw payload0 bytes.
    for addr, value in LITERALS.items():
        got = struct.unpack_from('<I', p0, addr - base0)[0]
        assert got == value, (hex(addr), hex(got), hex(value))

    # 2. MCUCTRL_Task record (payload1).
    p1 = payloads[1]
    base1 = info[1]['load_address_candidate']
    assert struct.unpack_from('<I', p1, 0x372508 - base1)[0] == 0x3200001
    assert struct.unpack_from('<I', p1, 0x37250C - base1)[0] == TASK
    assert struct.unpack_from('<I', p1, 0x372510 - base1)[0] == 0x800
    assert struct.unpack_from('<I', p1, 0x372514 - base1)[0] == 6

    # 3. Call censuses.
    got = census_calls()
    for target, expect in EXPECT_CALLS.items():
        assert set(got[target]) == expect, (
            he(target), sorted(map(he, got[target])),
            sorted(map(he, expect)))
    # No branch of any form to the two registered invokers, except the
    # payload9 data artifact.
    assert census_branches(0x1406D0) == []
    assert census_branches(0x140704) == [0xD3F696]

    # 4. Word scans: LE (payload0, every offset) and limm (16 payloads).
    le = {v: scan_word(payloads, info, v, aligned=False)[0]
          for v in (0x5545F8, 0x392AC0, 0x3200002, 0x241E5C,
                    0x242040, 0x1406D0, 0x140704)}
    assert set(le[0x5545F8]) == {0x22C474, 0x22C584, 0x242200, 0x2B7234}
    assert set(le[0x392AC0]) == {0x16ADC0, 0x241F74}
    assert set(le[0x3200002]) == {0x15AAE0, 0x16AE04, 0x16C7E4, 0x22C484,
                                  0x22C588, 0x241F70, 0x242204}
    assert set(le[0x241E5C]) == {0x241F78}
    assert set(le[0x242040]) == {0x242210}
    assert set(le[0x1406D0]) == {0x1405E8, 0x2B7475}   # 2nd = straddle
    assert set(le[0x140704]) == {0x1405EC}
    # aligned-only LE scan of the invoker pointers
    al = scan_word(payloads, info, 0x1406D0, aligned=True)
    assert set(al[0]) == {0x1405E8}, sorted(map(he, al[0]))
    # no middle-endian limm to the structs/handlers in any payload
    for v in (0x5545F8, 0x392AC0, 0x242104, 0x241E5C):
        assert scan_word(payloads, info, v, middle_endian=True) == {}

    # 5. Aligned windows.
    windows = {}
    for name, (lo, hi) in [
        ('task_head_15a80c', (0x15A80C, 0x15A912)),
        ('handler_bits8910_242104', (0x242104, 0x2421FC)),
        ('producer_status_242040', (0x242040, 0x2420D0)),
        ('register_2420d0', (0x2420D0, 0x242104)),
        ('mode_consumer_241e5c', (0x241E5C, 0x241E94)),
        ('register_241e94', (0x241E94, 0x241EC4)),
        ('bit0_consumer_241ec4', (0x241EC4, 0x241F10)),
        ('producer_bit0_16aab4', (0x16AAB4, 0x16AAF0)),
        ('init_family_16a9f8', (0x16A9F8, 0x16AA3A)),
        ('producers_16c6xx', (0x16C68C, 0x16C728)),
        ('svc_post_22c56c', (0x22C56C, 0x22C58C)),
        ('cluster_2b7190', (0x2B7190, 0x2B71F0)),
        ('setup_140568', (0x140568, 0x1405E8)),
    ]:
        windows[name] = aligned_window(p0, base0, lo, hi)
        assert windows[name].strip(), name
    # payload9 artifact classification (block 9, own address space)
    b9 = info[9]
    windows['payload9_artifact'] = aligned_window(
        payloads[9], b9['load_address_candidate'], 0xD3F650, 0xD3F6E0)
    (out / 'gnu_windows.txt').write_text(
        '\n\n'.join(f'=== {k} ===\n{v}' for k, v in windows.items()))

    def w(name: str) -> str:
        return windows[name]

    # 6. MCUCTRL_Task head: wait / read / auto-clear / dispatch.
    t = w('task_head_15a80c')
    has(t, r'push_s\s+blink')
    has(t, r'bl\s+\d+\s+;0x33412c\b')
    has(t, r'ld_s\s+r0,\[pcl,0x2d0\]\s+;0x15aae0')
    has(t, r'bl\.d\s+-?\d+\s+;0x158ce0\b')
    has(t, r'ld_s\s+r0,\[pcl,0x2cc\]\s+;0x15aae8')
    has(t, r'ld_s\s+r1,\[pcl,0x2c4\]\s+;0x15aae4')
    has(t, r'bl\.d\s+-?\d+\s+;0x138a98\b')
    has(t, r'bl\.d\s+-?\d+\s+;0x16c640\b')
    has(t, r'bl\.d\s+-?\d+\s+;0x22c35c\b')
    has(t, r'bl\.d\s+-?\d+\s+;0x24163c\b')
    has(t, r'bl\.d\s+-?\d+\s+;0x241e50\b')
    has(t, r'mov\s+r3,1000')
    # the wait: (0x3200002, 0x60F7F773, 0, 0)
    has(t, r'ld_s\s+r0,\[pcl,0x270\]\s+;0x15aae0')
    has(t, r'ld_s\s+r1,\[pcl,0x270\]\s+;0x15aae4')
    has(t, r'mov_s\s+r2,0\b')
    has(t, r'bl\.d\s+-?\d+\s+;0x158d04\b')
    has(t, r'mov_s\s+r3,r2')
    # read the received bits, then auto-clear them
    has(t, r'ld_s\s+r0,\[pcl,0x264\]\s+;0x15aae0')
    has(t, r'bl\.d\s+-?\d+\s+;0x158e28\b')
    has(t, r'mov_s\s+r1,sp')
    has(t, r'ld_s\s+r0,\[pcl,0x25c\]\s+;0x15aae0')
    has(t, r'ld_s\s+r1,\[sp,0\]')
    # dispatch
    has(t, r'bmsk\.f\s+0,r0,0x1')
    has(t, r'bl\s+\d+\s+;0x241ec4\b')
    has(t, r'and\.f\s+0,r0,0x70\b')
    has(t, r'bl\s+\d+\s+;0x241f88\b')
    has(t, r'and\.f\s+0,r0,0x700\b')
    has(t, r'bl\s+\d+\s+;0x242104\b')
    has(t, r'and\.f\s+0,r0,0xf000\b')
    has(t, r'bl\s+\d+\s+;0x2416f8\b')
    has(t, r'and\.f\s+0,r0,0xf00000\b')
    has(t, r'bl\s+\d+\s+;0x241e58\b')
    has(t, r'btst_s\s+r0,0x1d')
    has(t, r'bl\s+\d+\s+;0x241f0c\b')
    has(t, r'bl\s+\d+\s+;0x241fc8\b')
    has(t, r'btst_s\s+r0,0x1e')
    has(t, r'beq_s\s+-?\d+\s+;0x15a872\b')
    # bits 20..23 land on an EMPTY stub: 0x241E58 is j_s [blink]
    has(w('task_head_15a80c'), r'bl\s+\d+\s+;0x241e58\b')
    stub = aligned_window(p0, base0, 0x241E58, 0x241E5C)
    has(stub, r'j_s\s+\[blink\]')

    # 7. Handler of bits 8/9/10 = consumer of [0x5545F8+0x18].
    t = w('handler_bits8910_242104')
    has(t, r'push_s\s+blink')
    has(t, r'bl\s+\d+\s+;0x33412c\b')
    has(t, r'btst_s\s+r0,0x8')
    has(t, r'mov_s\s+r13,r0')
    has(t, r'beq_s\s+\d+\s+;0x242172\b')
    has(t, r'ld_s\s+r14,\[pcl,0x104\]\s+;0x242214')
    has(t, r'ld_s\s+r0,\[r14,0\]')
    has(t, r'bl\.d\s+-?\d+\s+;0x158fd0\b')
    has(t, r'mov_s\s+r0,0x1')
    has(t, r'bl\.d\s+-?\d+\s+;0x145c2c\b')
    has(t, r'bl\s+\d+\s+;0x2d62b0\b')
    has(t, r'ld_s\s+r14,\[pcl,0xd0\]\s+;0x242200')
    has(t, r'ldw_s\s+r1,\[r14,0x2c\]')
    has(t, r'ldw_s\s+r1,\[r14,0x2e\]')
    has(t, r'ld_s\s+r0,\[r14,0x20\]')
    has(t, r'cmp_s\s+r0,0x2')
    has(t, r'bl\s+\d+\s+;0x2b7190\b')
    # THE REGISTRATION READ + INVOCATION
    has(t, r'ld_s\s+r1,\[r14,0x18\]')
    has(t, r'ld_s\s+r0,\[r14,0x38\]')
    has(t, r'st_s\s+r0,\[r14,0x38\]')
    has(t, r'jl_s\.d\s+\[r1\]')
    has(t, r'ld_s\s+r0,\[r14,0x30\]')
    has(t, r'ld_s\s+r0,\[r14,0x34\]')
    # bit 9: refresh target pair, arm mode 2
    has(t, r'btst_s\s+r13,0x9')
    has(t, r'ld_s\s+r14,\[pcl,0x88\]\s+;0x242200')
    has(t, r'ldw_s\s+r1,\[r14,0x28\]')
    has(t, r'ldw_s\s+r1,\[r14,0x2a\]')
    has(t, r'stw_s\s+r0,\[r14,0x2e\]')
    has(t, r'stw_s\s+r2,\[r14,0x2c\]')
    has(t, r'ld_s\s+r0,\[r14,0x14\]')
    has(t, r'st_s\s+r3,\[r14,0x24\]')
    has(t, r'mov_s\s+r0,0x2')
    has(t, r'st_s\s+r0,\[r14,0x20\]')
    # bit 0xA: stop sequence + byte toggle on [0x5545F8+0]
    has(t, r'btst_s\s+r13,0xa')
    has(t, r'ld_s\s+r13,\[pcl,0x20\]\s+;0x242200')
    has(t, r'bl\.d\s+\d+\s+;0x2b7204\b')
    has(t, r'stb_s\s+r0,\[r13,0\]')
    has(t, r'bl\s+\d+\s+;0x2b712c\b')
    has(t, r'bl_s\s+-?\d+\s+;0x242094\b')
    has(t, r'mov_s\s+r0,0x1')

    # 8. Producer 0x242040 (status -> event bits 8/9) + helpers.
    t = w('producer_status_242040')
    has(t, r'push_s\s+blink')
    has(t, r'bl\s+\d+\s+;0x334130\b')
    has(t, r'bl\s+\d+\s+;0x2d6200\b')
    has(t, r'btst_s\s+r0,0\b')
    has(t, r'mov_s\s+r13,r0')
    has(t, r'ld_s\s+r14,\[pcl,0x1b4\]\s+;0x242200')
    has(t, r'st_s\s+r0,\[r14,0x58\]')
    has(t, r'ld_s\s+r0,\[pcl,0x1ac\]\s+;0x242204')
    has(t, r'mov\s+r1,256')
    has(t, r'bl\.d\s+-?\d+\s+;0x158cbc\b')
    has(t, r'btst_s\s+r13,0x1')
    has(t, r'st_s\s+r0,\[r14,0x54\]')
    has(t, r'ld_s\s+r0,\[pcl,0x198\]\s+;0x242204')
    has(t, r'mov\s+r1,512')
    has(t, r'ld_s\s+r0,\[pcl,0x194\]\s+;0x242208')
    has(t, r'stw_s\s+r13,\[r0,0x24\]')
    has(t, r'and\.f\s+0,r13,0xfffffffc')
    has(t, r'st_s\s+r0,\[r14,0x5c\]')
    has(t, r'bl\.d\s+\d+\s+;0x2d6214\b')
    # 0x242094: mode -> 1 on [0x5545F8+0x20]
    has(t, r'mov_s\s+r13,0x1')
    has(t, r'bl\.d\s+\d+\s+;0x2b71f0\b')
    has(t, r'st_s\s+r13,\[r0,0x20\]')
    # 0x2420B4: timeout callback (+0x3C counter, [0x36A6C8+0]=0)
    has(t, r'ld_s\s+r0,\[pcl,0x154\]\s+;0x24220c')
    has(t, r'ld_s\s+r1,\[pcl,0x140\]\s+;0x242200')
    has(t, r'ld_s\s+r0,\[r1,0x3c\]')
    has(t, r'st_s\s+r0,\[r1,0x3c\]')

    # 9. 0x2420D0: registers 0x242040 under id 1545 (0x609).
    t = w('register_2420d0')
    has(t, r'mov_s\s+r13,0\b')
    has(t, r'bl\.d\s+\d+\s+;0x2d614c\b')
    has(t, r'bl\s+\d+\s+;0x2b71ac\b')
    has(t, r'ld_s\s+r1,\[pcl,0x130\]\s+;0x242210')
    has(t, r'bl\.d\s+-?\d+\s+;0x16d898\b')
    has(t, r'mov\s+r0,1545')
    has(t, r'bl\.d\s+-?\d+\s+;0x16d7e8\b')
    has(t, r'mov_s\s+r1,0xff')
    has(t, r'bl_s\s+-?\d+\s+;0x242094\b')
    has(t, r'ld_s\s+r0,\[pcl,0x114\]\s+;0x24220c')
    has(t, r'st_s\s+r13,\[r0,0\]')

    # 10. Mode consumer 0x241E5C = consumer of [0x392AC0+0x1C].
    t = w('mode_consumer_241e5c')
    has(t, r'push_s\s+blink')
    has(t, r'bl\s+-?\d+\s+;0x169870\b')
    has(t, r'bl\.d\s+-?\d+\s+;0x16989c\b')
    has(t, r'bmsk\s+r14,r0,0x3')
    has(t, r'bmsk\s+r13,r0,0x2')
    has(t, r'bl\.d\s+-?\d+\s+;0x1698b0\b')
    has(t, r'mov_s\s+r0,r13')
    has(t, r'ld_s\s+r0,\[pcl,0xf8\]\s+;0x241f70')
    has(t, r'mov_s\s+r1,0x2')
    has(t, r'bl\.d\s+-?\d+\s+;0x158cbc\b')
    # THE REGISTRATION READ + INVOCATION with (v & 7, v & 0xF)
    has(t, r'ld_s\s+r0,\[pcl,0xf4\]\s+;0x241f74')
    has(t, r'ld_s\s+r2,\[r0,0x1c\]')
    has(t, r'cmp_s\s+r2,0\b')
    has(t, r'mov_s\s+r0,r13')
    has(t, r'jl_s\.d\s+\[r2\]')
    has(t, r'mov_s\s+r1,r14')

    # 11. 0x241E94 registers 0x241E5C under id 0x3002.
    t = w('register_241e94')
    has(t, r'ld_s\s+r1,\[pcl,0xe4\]\s+;0x241f78')
    has(t, r'bl\.d\s+\d+\s+;0x242414\b')
    has(t, r'ld_s\s+r0,\[pcl,0xe0\]\s+;0x241f7c')
    has(t, r'bl\.d\s+\d+\s+;0x2422e8\b')
    has(t, r'mov_s\s+r1,0x20')
    has(t, r'ld_s\s+r0,\[pcl,0xc4\]\s+;0x241f74')
    has(t, r'bl\.d\s+-?\d+\s+;0x16ac14\b')
    has(t, r'st_s\s+r1,\[r0,0xc\]')
    has(t, r'ld_s\s+r1,\[pcl,0xc8\]\s+;0x241f80')
    has(t, r'stb_s\s+r0,\[r1,0xc\]')

    # 12. Bit-0 consumer 0x241EC4 = consumer of [0x392AC0+0x18].
    t = w('bit0_consumer_241ec4')
    has(t, r'push_s\s+blink')
    has(t, r'bl\s+\d+\s+;0x334128\b')
    has(t, r'bl\.d\s+\d+\s+;0x242034\b')
    has(t, r'mov_s\s+r13,r0')
    has(t, r'btst_s\s+r13,0\b')
    has(t, r'mov_s\s+r16,r0')
    has(t, r'bl\.d\s+\d+\s+;0x242004\b')
    has(t, r'mov_s\s+r13,0\b')
    has(t, r'bl\.d\s+-?\d+\s+;0x16abc0\b')
    has(t, r'mov_s\s+r0,r13')
    # THE REGISTRATION READ + INVOCATION with [0x392AC0+0xC]
    has(t, r'ld_s\s+r15,\[pcl,0x94\]\s+;0x241f74')
    has(t, r'ld_s\s+r1,\[r15,0x18\]')
    has(t, r'ld_s\s+r14,\[pcl,0x9c\]\s+;0x241f80')
    has(t, r'cmp_s\s+r1,0\b')
    has(t, r'stb_s\s+r13,\[r14,0xe\]')
    has(t, r'jl_s\.d\s+\[r1\]')
    has(t, r'ld_s\s+r0,\[r15,0xc\]')
    has(t, r'mov_s\s+r0,0x1')
    has(t, r'st_s\s+r13,\[r15,0x24\]')
    has(t, r'stb_s\s+r0,\[r14,0x5\]')
    has(t, r'bl\s+\d+\s+;0x24201c\b')

    # 13. Producer/registration 0x16AAB4 (slot +0x18, event bit 0).
    t = w('producer_bit0_16aab4')
    has(t, r'push_s\s+blink')
    has(t, r'ld_s\s+r2,\[pcl,0x30c\]\s+;0x16adc0')
    has(t, r'cmp_s\s+r0,0\b')
    has(t, r'ldb_s\s+r1,\[r2,0\]')
    has(t, r'ld_s\s+r1,\[r2,0x18\]')
    has(t, r'st_s\s+r0,\[r2,0x18\]')
    has(t, r'ldb\s+r0,\[r2,42\]')
    has(t, r'ld_s\s+r0,\[pcl,0x334\]\s+;0x16ae04')
    has(t, r'mov_s\s+r1,0x1')
    has(t, r'bl\.d\s+-?\d+\s+;0x158cbc\b')
    has(t, r'ld_s\s+r0,\[pcl,0x328\]\s+;0x16ae04')
    has(t, r'mov_s\s+r0,0\b')
    has(t, r'st_s\s+r0,\[r2,0x18\]')

    # 13b. Init 0x16A9F8 installs 0x16AAB4 (pool 0x16ADC8) into the
    # family table at struct+0x10 (audit reg-consumers-audit-34).
    t = w('init_family_16a9f8')
    has(t, r'ld_s\s+r14,\[pcl,0x3c0\]\s+;0x16adc0')
    has(t, r'ld_s\s+r0,\[pcl,0x3a8\]\s+;0x16adc4')
    has(t, r'st_s\s+r0,\[r13,0xc\]')
    has(t, r'ld_s\s+r0,\[pcl,0x3a8\]\s+;0x16adc8')
    has(t, r'st_s\s+r0,\[r13,0x10\]')

    # 14. Producers 0x16C68C (bit 4) and 0x16C70C (bit 6).
    t = w('producers_16c6xx')
    has(t, r'ld_s\s+r1,\[pcl,0x134\]\s+;0x16c7c0')
    has(t, r'ldb_s\s+r0,\[r1,0x19\]')
    has(t, r'ldb_s\s+r0,\[r1,0\]')
    has(t, r'ld_s\s+r0,\[pcl,0x148\]\s+;0x16c7e4')
    has(t, r'mov_s\s+r1,0x10')
    has(t, r'bl\.d\s+-?\d+\s+;0x158cbc\b')
    has(t, r'ld_s\s+r1,\[pcl,0xb4\]\s+;0x16c7c0')
    has(t, r'ld_s\s+r0,\[pcl,0xc8\]\s+;0x16c7e4')
    has(t, r'mov_s\s+r1,0x40')

    # 15. 0x22C56C: value -> [0x5545F8+8] + event bit 10.
    t = w('svc_post_22c56c')
    has(t, r'push_s\s+blink')
    has(t, r'ld_s\s+r1,\[pcl,0x18\]\s+;0x22c584')
    has(t, r'stw_s\s+r0,\[r1,0x8\]')
    has(t, r'ld_s\s+r0,\[pcl,0x18\]\s+;0x22c588')
    has(t, r'mov\s+r1,1024')
    has(t, r'bl\.d\s+-?\d+\s+;0x158cbc\b')

    # 16. 0x2B7190 snapshot refresh: +0x30 arg, +0x28/+0x2A pair.
    t = w('cluster_2b7190')
    has(t, r'bl\.d\s+\d+\s+;0x2d627c\b')
    has(t, r'mov_s\s+r0,0x1')
    has(t, r'bl\s+\d+\s+;0x2d62d8\b')
    has(t, r'ld_s\s+r2,\[pcl,0x98\]\s+;0x2b7234')
    has(t, r'st_s\s+r0,\[r2,0x30\]')
    has(t, r'stw_s\s+r1,\[r2,0x28\]')
    has(t, r'stw_s\s+r0,\[r2,0x2a\]')
    # 0x2B71D4 tail: observed pair +0x2C/+0x2E
    has(t, r'bl\s+\d+\s+;0x2d62b0\b')
    has(t, r'ld_s\s+r1,\[pcl,0x5c\]\s+;0x2b7234')
    has(t, r'stw_s\s+r2,\[r1,0x2c\]')
    has(t, r'stw_s\s+r0,\[r1,0x2e\]')

    # 17. Iris setup 0x140568: the three registrations/notifications.
    t = w('setup_140568')
    has(t, r'bl\s+\d+\s+;0x22c3bc\b')
    has(t, r'bl\s+\d+\s+;0x16acdc\b')
    has(t, r'bl\s+\d+\s+;0x16c68c\b')

    # 18. Payload9 artifact: the only listing hit toward 0x140704 is
    # data (strings/tables), not code.
    t = w('payload9_artifact')
    has(t, r'\.word|\.long')
    has(t, r';0x140704')

    # 19. Model: every dispatch group is inside the wait mask, and
    # the handler bit tests are inside the dispatched group.
    mask_bits = {i for i in range(32) if WAIT_MASK >> i & 1}
    assert mask_bits == {0, 1, 4, 5, 6, 8, 9, 10, 12, 13, 14, 15, 16,
                          17, 18, 20, 21, 22, 23, 29, 30}
    for group in (0x1, 0x70, 0x700, 0xF000, 0xF00000, 0x20000000,
                  0x40000000):
        assert group & WAIT_MASK, hex(group)
    for bit in (8, 9, 10):
        assert (WAIT_MASK >> bit) & 1
    # dispatch groups asserted in the window
    for group in (0x1, 0x70, 0x700, 0xF000, 0xF00000):
        assert bin(group).count('1') >= 1

    result = dict(
        status='PASS_IRIS_REGISTRATION_CONSUMERS_STATIC',
        utc=stamp,
        question='Who consumes the iris pair registrations at runtime: '
                 'the readers/invokers of [0x5545F8+0x18] (=0x1406D0) '
                 'and [0x392AC0+0x1C]/[0x392AC0+0x18], and the task '
                 'waiting on event 0x3200002',
        answers=dict(
            task=dict(
                entry=he(TASK), record='0x372508 (payload1)',
                event_id='0x3200002', wait_mask='0x60f7f773',
                service_wait='0x158D04(0x3200002, 0x60F7F773, 0, 0)',
                service_read='0x158E28(0x3200002, &sp)',
                service_autoclear='0x158CE0(0x3200002, bits)',
                dispatch=dict(bit0='0x241EC4', bits_4_6='0x241F88',
                              bits_8_10='0x242104',
                              bits_12_15='0x2416F8',
                              bits_20_23='0x241E58 (EMPTY stub, '
                                         'j_s [blink])',
                              bit_29='0x241F0C + 0x241FC8',
                              bit_30='loop back to the wait if clear'),
            ),
            consumer_struct_A=dict(
                struct='0x5545F8', handler='0x242104',
                called_from=[he(s) for s in sorted(EXPECT_CALLS[0x242104])],
                slot='+0x18 (0x22C3BC registration = 0x1406D0)',
                invocation='jl_s.d [r1] at 0x24215A with '
                          'r0=[0x5545F8+0x30]',
                guards='bit 8 of the event; value from 0x2D62B0 == '
                       'pair [+0x2C/+0x2E]; mode [+0x20]==2',
                layout={'+0x8': 'value posted by 0x22C56C',
                        '+0x18': 'callback (0x1406D0)',
                        '+0x20': 'mode (0x242094->1, bit9->2)',
                        '+0x24': 'status halfword',
                        '+0x28/+0x2A': 'snapshot pair (0x2B7190)',
                        '+0x2C/+0x2E': 'target pair (bit 9 path)',
                        '+0x30': 'callback argument (0x2B7190)',
                        '+0x34': 'mismatch counter',
                        '+0x38': 'invocation counter',
                        '+0x3C': 'timeout counter (0x2420B4)',
                        '+0x40': 'error counter',
                        '+0x54/+0x58/+0x5C': 'producer counters'},
            ),
            consumer_struct_B_1c=dict(
                struct='0x392AC0', handler='0x241E5C',
                slot='+0x1C (0x16ACDC(7,2,ptr) = 0x140704)',
                invocation='jl_s.d [r2] at 0x241E8A with '
                          'r0=v&7, r1=v&0xF (v from 0x169870)',
                side_effect='raises event 0x3200002 bit 1 before the call',
                registration='pointer in pool 0x241F78, registered under '
                             'id 0x3002 by 0x241E94 via 0x242414; '
                             '0x241E94 called once at 0x16AA72',
            ),
            consumer_struct_B_18=dict(
                struct='0x392AC0', handler='0x241EC4 (task bit 0)',
                slot='+0x18 (0x16AAB4 registration)',
                invocation='jl_s.d [r1] at 0x241EEE with '
                          'r0=[0x392AC0+0xC]',
                value_note='audit reg-consumers-audit-34: the 0x16ABC0 '
                           'store of [+0xC] runs only on its r0>0 path '
                           'and both known call sites pass r0=0; the '
                           'static writers of [+0xC] are the init '
                           '0x241E94 (=0x20 via 0x16AC14) and 0x16C6AC',
                gate='byte [0x392AC0+0x2A] (written around the call; '
                     'set by 0x16AAB4 -> event bit 0)',
            ),
            producers=dict(
                bit_8='0x242040 on 0x2D6200 bit0 '
                      '(0x158CBC(0x3200002, 256))',
                bit_9='0x242040 on 0x2D6200 bit1 '
                      '(0x158CBC(0x3200002, 512))',
                bit_10='0x22C3BC registration (iteration 31) AND '
                       '0x22C56C (arg -> [0x5545F8+8], '
                       '0x158CBC(0x3200002, 1024))',
                bit_0='0x16AAB4 via gate byte [0x392AC0+0x2A]',
                bit_1='0x241E5C before invoking [+0x1C]',
                bit_4='0x16C68C via bytes of 0x392D70 (+0x19/+0x0); '
                      'called from the iris setup 0x140568 at 0x1405D6',
                bit_6='0x16C70C via the same gates',
            ),
            negatives=[
                'no branch of any form to 0x1406D0/0x140704 anywhere '
                'in the linear listing (the single 0x140704 hit at '
                'V00D3F696 is payload9 data: strings/tables, window-'
                'classified)',
                '0x241E5C/0x242040/0x16AAB4/0x22C56C have no direct bl '
                'caller: pointer-only entries (0x16AAB4 is installed '
                'by 0x16A9F8 through pool 0x16ADC8 into the family '
                'table at struct+0x10, audit reg-consumers-audit-34), '
                'while 0x242104 has exactly ONE bl caller: the task '
                'site 0x15A8B6',
                'no LE word or middle-endian limm to 0x5545F8/0x392AC0 '
                'outside the pool sites asserted (the unaligned LE '
                '0x1406D0 hit at 0x2B7475 is an instruction straddle)',
            ],
        ),
        census={he(t): sorted(he(s) for s in got[t])
                for t in CENSUS_TARGETS},
        word_scans={he(v): {str(k): sorted(he(x) for x in lst)
                            for k, lst in scan.items()}
                    for v, scan in [(v, {0: le[v]})
                                    for v in le]},
        model=dict(
            wait_mask_bits=sorted(mask_bits),
            dispatch_groups=['0x1', '0x70', '0x700', '0xf000',
                             '0xf00000', 'bit29', 'bit30-loop'],
            handler_bits=['8', '9', '10'],
        ),
        limits=[
            'Static only: no MMIO, camera or firmware execution; the '
            'handler semantics are reconstructions from byte-exact '
            'windows, not runtime observations',
            'The dispatcher of the id-0x3002 registration (service '
            '0x242414, callers {0x16D9B6, 0x1A083E, 0x23914E, '
            '0x241E98}) is not decoded: who calls 0x241E5C at runtime '
            'remains one layer deeper',
            'Same for 0x16D898(1545, 0x242040): the caller chain of '
            'the 0x2D62xx value provider family is not decoded',
            'Bits 16/17/18 and bit 1 are inside the wait mask but no '
            'dispatch test for them appears in the loop window '
            '0x15A80C..0x15A912 (handled elsewhere or unused)',
            'The exit path at 0x15A8EE..0x15A906 (0x145C2C, event SET '
            'with an encoded r1 constant GNU prints as "ror r1,0x1", '
            '0xB2C74) is not decoded',
            'census values come from the linear GNU listing: data '
            'decoded as branches can hide false positives/negatives; '
            'every chain site is re-asserted in an aligned window',
            'struct layouts are read-side reconstructions: the '
            'writer of [0x5545F8+0x20] mode transitions is inside the '
            'asserted windows, but runtime values are not derivable',
            'V1.1 sample analysed; the camera in the logs runs V1.0; '
            'addresses are not portable without proof',
        ],
        sources=dict(
            script=str(Path(__file__).relative_to(ROOT)),
            firmware=str(FIRMWARE.relative_to(ROOT)),
            manifest='S33-sections/TBM_blocks/manifest.json',
            listing=str(LISTING.relative_to(ROOT)),
            objdump='work/build-arc/binutils (GNU ARC700, -EL, aligned '
                    'windows)',
        ),
    )
    (out / 'registration_consumers.json').write_text(
        json.dumps(result, indent=1) + '\n')
    (EVIDENCE / 'latest.json').write_text(json.dumps(
        dict(status=result['status'], stamp=stamp,
             path=str(out.relative_to(ROOT)),
             script=str(Path(__file__).relative_to(ROOT))), indent=1)
        + '\n')
    print('PASS_IRIS_REGISTRATION_CONSUMERS_STATIC', stamp)


if __name__ == '__main__':
    main()
