#!/usr/bin/env python3
"""Static verification of the iris-move COMPLETION side (V1.1 Main payload0).

Closes the open point of iteration 21 ("lato completamento: handler
0x235AF8/0x235AE4, evento 0x10, chi azzera [0x36A464+6]") with byte-exact
windows, and CORRECTS one notation of iteration 21: the per-request counter
is the halfword [0x36A464+0x1c] (cell 0x36A480) - the SAME cell the request
pre-guard 0x235ABC compares against the acquire handle h, and the same
halfword 0x235A1C returns as h: a generation counter, not a double
dereference "[[0x36A464]+0x1c]".

Byte-verified completion story (payload0, base 0x0AD800):

- setter 0x18B85C always calls the request with wait=1 (mov_s r2,0x1 before
  bl.d 0x235B0C, timeout 0x3A98=15000 in r3) and commits the state byte
  [0x367FE8+2] only when the request returns 1; on failure it runs the
  completion synchronously via 0x18B9D4 (0x2359B0 + 0x23524C(2) + 0x235DE8).
- request 0x235B0C (inside its critical section, AFTER actuation):
  counter halfword [0x36A464+0x1c]++, event CLEAR 0x158CE0(1|1<<25, 0x10),
  deferred post 0x145F28(0x36A494, handler, r19, 0) with handler =
  0x235AF8 (wait!=0) / 0x235AE4 (wait==0); after the critical section, if
  wait and post ok: event WAIT 0x158D04(1|1<<25, 0x10, 1, 0).
- deferred handler 0x235AF8 = 0x235AE4 + event SET 0x158CBC(1|1<<25, 0x10);
  handler 0x235AE4 = completion body 0x2359B0 + release 0x23524C(2)
  (-> 0x235C60 -> 0x234CD0) + 0x235DE8 (clears in-motion byte [0x36A488]);
  both return via 0x234F18 (pop blink).
- completion body 0x2359B0: optional callback [0x36A464+0x3C] (jl_s [r0]),
  critical section, GPIO 0x0FF04024 |= 0x18 (BOTH iris bits), delay 500
  (0x23C620), critical section, GPIO &= -25 (both bits cleared),
  STATUS BYTE [0x36A464+6] = 0 (stb_s at 0x235A02), return 0.
- event group services: resolver 0x158C8C scans the table at [0x372A48]
  (stride 0x38, magic 0x45564E4C, bit31 gate at +8) for group id
  1|1<<25 = 0x2000001; 0x158CE0 -> 0x23C8AC CLEARS the bit (bic_s on
  [event+0x18]); 0x158CBC -> 0x23C758 SETS the bit (or_s on [event+0x18])
  and walks the waiter list rooted at [event+8]; 0x158D04 registers the
  waiter (blink stored at [event+0x2c]).
- deferred post service 0x145F28 (shared, 9 call sites): validates the
  handler, service object [0x146234]=0x366EBC ([+8] init flag, [+0xc] tick
  scale via 0x335B34 and divisor 0x2710, [+0x10] serial), arms the ARC700
  internal TIMER1 (aux limit1=0x1000000, count1, control1=2/3), scans 10
  slots of stride 20 at table 0x4437F4 (pool 0x146240) and stores the
  HANDLER at slot+16 (st r18,[r13,16]); deadline at slot+8 from the timeout
  via millicode 0x336364/0x335D34.
- in-motion bookkeeping: 0x235DE8 clears byte [0x36A488] (guarded by
  0x2C4F90 on [0x36A484]); 0x235A10 sets byte [0x36A47E]=1, called from
  the claim wrapper 0x18B928 before 0x235A1C(2, idx).
- diagnostic panel 0x2C5100 does NOT read [0x36A464+6]: it polls shadow
  bytes 0x446808+4*idx through getter 0x16F920 (pool 0x2C519C) at indices
  8/9/0xA with wait loops, then sets Big/Small with 0x18B85C(1)/(9).

Read-only: firmware, blocks and tools are never modified. Linear GNU
listings are candidate decodings; every asserted window here is
re-disassembled aligned at a call-verified entry, and every literal is
re-read from the raw payload bytes.
"""
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads, objdump_text, he
from s33_run_gnu_arc700 import ROOT, sha
from s33_verify_sensor_mmio_dialog import aligned_window

FIRMWARE = ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin'
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Iris_Completion'

# Literal words re-read from raw payload0 bytes (little-endian).
LITERALS = {
    0x18B8D0: 0x00003A98,  # setter: request timeout (delay slot of bl.d)
    0x18B788: 0x367FE8,   # iris state struct (byte index at +2)
    0x18B8DC: 0x367FEA,   # state alias cell ([0x367FE8+2]): getter 0x18B8D4
                          # and mini-setter 0x18B8E0 write it directly
    0x235AB4: 0x36A464,   # acquire: iris control struct
    0x235A18: 0x36A47E,   # 0x235A10: marker byte cell (set to 1)
    0x2359C8: 0x36A464,   # completion body: control struct
    0x2359CC: 0x0FF04024,  # completion body: iris GPIO register
    0x235AE0: 0x36A480,   # pre-guard: generation halfword cell
    0x235BC8: 0x36A464,   # request: control struct (counter +0x1c)
    0x235BCC: 0x235AF8,   # request: handler when wait != 0
    0x235BD0: 0x235AE4,   # request: handler when wait == 0
    0x235BD4: 0x36A494,   # request: post-service object cell
    0x235DE4: 0x36A488,   # 0x235DE8: in-motion byte cell (cleared)
    0x2353FC: 0x36A488,   # in-motion gate read (function at 0x2353C2)
    0x235E14: 0x36A484,   # 0x235DE8: logger gate cell
    0x158E48: 0x372A48,   # event resolver: event table base cell
    0x158E4C: 0x200307,   # event resolver: error code (no entry)
    0x158E50: 0x200304,   # event resolver: error code (bad magic/flag)
    0x146234: 0x366EBC,   # post service: service control object
    0x146238: 0x2710,     # post service: divisor 10000
    0x146240: 0x4437F4,   # post service: slot table base (10 x 20B)
    0x146248: 0x366ED0,   # re-post wrapper 0x146044: object cell
    0x2C519C: 0x16F920,   # panel: shadow getter dispatch
    0x16FA34: 0x446808,   # shadow getter: diagnostic byte table base
    0x2C51A0: 0x406E5E,   # panel string (payload1)
    0x2C51A8: 0x406E89,   # panel: "Iris status: Big"
    0x2C51AC: 0x406E9A,   # panel: "Iris status: Small"
}

# Raw-scan census (step 2, little-endian) of the iris control family cells.
POOLS_36A464 = {0x234CC8, 0x234D30, 0x234F44, 0x234F90, 0x2350BC, 0x2354D8,
                0x2355D8, 0x2356C8, 0x2357A0, 0x2358E0, 0x235968, 0x2359C8,
                0x235AB4, 0x235BC8, 0x235C5C, 0x235EEC, 0x235F6C, 0x236018,
                0x236078}
POOLS_36A480 = {0x235AE0}
POOLS_36A482 = {0x234BC0, 0x234FFC, 0x235854, 0x235BC4}
POOLS_36A494 = {0x235BD4}
POOLS_36A488 = {0x2353FC, 0x235DE4}
POOLS_36A484 = {0x235E14}
POOLS_36A47E = {0x235A18}

# Census of call sites (linear GNU listing of payload0, bl-forms only).
CALLS_2359B0 = {0x18B846, 0x18B9D6, 0x235AE6}
CALLS_235A10 = {0x18B936}
CALLS_235AE4 = {0x235AFA}
CALLS_235AF8 = set()          # function pointer only (pool 0x235BCC)
CALLS_235ABC = {0x18B968, 0x18B980, 0x235B28}
CALLS_235DE8 = {0x18B6C0, 0x18B9E0, 0x235AF0, 0x2381CC}
CALLS_235A1C = {0x18B886, 0x18B93E}
CALLS_235C60 = {0x235200, 0x235292}
CALLS_145F28 = {0x134758, 0x146056, 0x16E9C2, 0x16EA0A, 0x17AA54, 0x235092,
                0x2352F4, 0x235B86, 0x238C28}
CALLS_14605C = {0x16EA9A, 0x16EADA, 0x17ABF6}   # slot-cancel service users

LINE_PAT = re.compile(r'^\s*([0-9a-f]+):\t[0-9a-f ]+\t(\S+)\t?(.*)$')
CALL_TARGET = re.compile(r'^(-?\d+)\t;0x([0-9a-f]+)')


def has(text: str, pattern: str) -> None:
    assert re.search(pattern, text), f'missing pattern: {pattern}'


def count(text: str, pattern: str) -> int:
    return len(re.findall(pattern, text))


def main() -> None:
    out = EVIDENCE / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'script_snapshot.py').write_bytes(Path(__file__).read_bytes())
    firmware = FIRMWARE.read_bytes()
    assert sha(FIRMWARE) == '1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39'
    blocks, payloads, block_dir = verified_payloads(ROOT)
    info = {b['index']: b for b in blocks}
    base0 = info[0]['load_address_candidate']
    base1 = info[1]['load_address_candidate']
    p0, p1 = payloads[0], payloads[1]
    assert base0 == 0x0AD800 and base1 == 0x360800

    # 1. Literal words verified against raw payload bytes.
    for addr, value in LITERALS.items():
        got = struct.unpack_from('<I', p0, addr - base0)[0]
        assert got == value, (hex(addr), hex(got), hex(value))

    # 2. Panel strings in payload1.
    def p1_string(addr: int) -> bytes:
        off = addr - base1
        assert 0 <= off < len(p1)
        buf = bytearray()
        while p1[off] and len(buf) < 64:
            buf.append(p1[off])
            off += 1
        return bytes(buf)
    assert p1_string(0x406E89).startswith(b'Iris status: Big')
    assert p1_string(0x406E9A).startswith(b'Iris status: Small')

    # 3. Aligned windows.
    windows = {}
    for name, (lo, hi) in [
        ('handler_wait_235af8', (0x235AF8, 0x235B0C)),
        ('handler_nowait_235ae4', (0x235AE4, 0x235AF8)),
        ('body_head_2359b0', (0x2359B0, 0x2359C8)),
        ('body_cont_2359d0', (0x2359D0, 0x235A10)),
        ('request_235b0c', (0x235B0C, 0x235BB2)),
        ('preguard_235abc', (0x235ABC, 0x235AE0)),
        ('state_wait_18b954', (0x18B954, 0x18B994)),
        ('acquire_235a1c', (0x235A1C, 0x235AB4)),
        ('setter_18b85c', (0x18B85C, 0x18B8D4)),
        ('state_minisetter_18b8d4', (0x18B8D4, 0x18B8F8)),
        ('fail_entry_18b9d4', (0x18B9D4, 0x18B9E8)),
        ('sync_entry_18b844', (0x18B844, 0x18B854)),
        ('claim_18b928', (0x18B928, 0x18B952)),
        ('marker_235a10', (0x235A10, 0x235A1C)),
        ('release2_235c60', (0x235C60, 0x235C68)),
        ('inmotion_235de8', (0x235DE8, 0x235E14)),
        ('inmotion_gate_2353c2', (0x2353C2, 0x2353F0)),
        ('rel_epilogue_18b6b4', (0x18B6B4, 0x18B6D0)),
        ('ev_clear_158ce0', (0x158CE0, 0x158D04)),
        ('ev_set_158cbc', (0x158CBC, 0x158CE0)),
        ('ev_resolve_158c8c', (0x158C8C, 0x158CBC)),
        ('ev_bitclear_23c8ac', (0x23C8AC, 0x23C902)),
        ('ev_bitset_23c758', (0x23C758, 0x23C7B0)),
        ('ev_wait_head_158d04', (0x158D04, 0x158DB0)),
        ('ev_wait_tail_158da6', (0x158DA6, 0x158E20)),
        ('post_head_145f28', (0x145F28, 0x145F9C)),
        ('post_rest_145f9c', (0x145F9C, 0x146040)),
        ('post_sibling_146044', (0x146044, 0x14605C)),
        ('post_cancel_14605c', (0x14605C, 0x1460B0)),
        ('panel_head_2c50b6', (0x2C50B6, 0x2C5100)),
        ('panel_2c5100', (0x2C5100, 0x2C5180)),
        ('shadow_getter_16f920', (0x16F920, 0x16F950)),
    ]:
        windows[name] = aligned_window(p0, base0, lo, hi)
        assert windows[name].strip(), name
    (out / 'gnu_windows.txt').write_text(
        '\n\n'.join(f'=== {k} ===\n{v}' for k, v in windows.items()))

    def w(name: str) -> str:
        return windows[name]

    # 4. Handler 0x235AF8 (wait variant): completion + event SET.
    t = w('handler_wait_235af8')
    has(t, r'\tpush_s\tblink\b')
    has(t, r'\tbl_s\t-20\t;0x235ae4\b')
    has(t, r'\tmov_s\tr0,0x1\b')
    has(t, r'\tbset_s\tr0,r0,0x19\b')
    has(t, r'\tmov_s\tr1,0x10\b')
    has(t, r'\tbl\t-904772\t;0x158cbc\b')
    has(t, r'\tb\t-3052\t;0x234f18\b')

    # 5. Handler 0x235AE4 (base): completion body + release + in-motion clear.
    t = w('handler_nowait_235ae4')
    has(t, r'\tpush_s\tblink\b')
    has(t, r'\tbl\t-308\t;0x2359b0\b')
    has(t, r'\tmov_s\tr0,0x2\b')
    has(t, r'\tbl\t-2208\t;0x23524c\b')
    has(t, r'\tbl\t760\t;0x235de8\b')
    has(t, r'\tb\t-3036\t;0x234f18\b')

    # 6. Completion body 0x2359B0: callback [+0x3C], pulse both bits,
    #    delay 500, clear both bits, STATUS [0x36A464+6] = 0.
    t = w('body_head_2359b0') + w('body_cont_2359d0')
    has(t, r'\tbl\t1042300\t;0x33412c\b')
    has(t, r'\tld_s\tr14,\[pcl,0x14\]\t;0x2359c8\b')
    has(t, r'\tld_s\tr0,\[r14,0x3c\]')
    has(t, r'\tjl_s\t\[r0\]')
    has(t, r'\tbl\t-774872\t;0x1786e8\b')
    has(t, r'\tld_s\tr13,\[pcl,0x8\]\t;0x2359cc\b')
    has(t, r'\tb_s\t12\t;0x2359d0\b')
    has(t, r'\tldh\.di\tr0,\[r13\]')
    has(t, r'\tmov\tr15,-25\b')
    has(t, r'\tand_s\tr0,r0,r15\b')
    has(t, r'\tor\tr0,r0,0x18\b')
    has(t, r'\tsth\.di\tr0,\[r13\]')
    has(t, r'\tbl\t-771728\t;0x179354\b')
    has(t, r'\tmov\tr0,500\b')
    has(t, r'\tbl\t27700\t;0x23c620\b')
    has(t, r'\tbl\t-774920\t;0x1786e8\b')
    has(t, r'\tmov_s\tr13,0\b')
    has(t, r'\tstb_s\tr13,\[r14,0x6\]')      # status byte = 0 (0x235A02)
    has(t, r'\tbl\t-771760\t;0x179354\b')
    has(t, r'\tb\t-3044\t;0x234e24\b')
    assert count(t, r'\tsth\.di\tr0,\[r13\]') == 2

    # 7. Request 0x235B0C: counter, event clear, handler select, post, wait.
    t = w('request_235b0c')
    has(t, r'\tbl_s\t-108\t;0x235abc\b')       # pre-guard
    has(t, r'\tcmp\tr20,0\b')                  # wait flag
    has(t, r'\tldw_s\tr0,\[r0,0x1c\]')       # counter halfword read
    has(t, r'\tstw_s\tr0,\[r1,0x1c\]')       # counter halfword write
    has(t, r'\tld_s\tr15,\[pcl,0x60\]\t;0x235bcc\b')   # wait!=0 -> 0x235AF8
    has(t, r'\tld_s\tr15,\[pcl,0x60\]\t;0x235bd0\b')   # wait==0 -> 0x235AE4
    has(t, r'\tmov_s\tr0,0x1\b')
    assert count(t, r'\tbset_s\tr0,r0,0x19\b') == 2     # group id 0x2000001
    assert count(t, r'\tmov_s\tr1,0x10\b') == 2         # event bit 0x10
    has(t, r'\tbl\t-904856\t;0x158ce0\b')      # event CLEAR before the post
    has(t, r'\tld_s\tr0,\[pcl,0x58\]\t;0x235bd4\b')    # 0x36A494
    has(t, r'\tmov_s\tr1,r15\b')               # handler
    has(t, r'\tmov_s\tr2,r19\b')               # timeout argument
    has(t, r'\tmov_s\tr3,0\b')
    has(t, r'\tbl\t-982108\t;0x145f28\b')      # deferred post
    has(t, r'\tcmp_s\tr14,0\b')                # post result gate
    has(t, r'\tmov_s\tr2,0x1\b')
    has(t, r'\tmov_s\tr3,0\b')
    has(t, r'\tbl\t-904872\t;0x158d04\b')     # event WAIT (wait && ok)

    # 8. Pre-guard 0x235ABC: h vs halfword [0x36A480] (generation cell).
    t = w('preguard_235abc')
    has(t, r'\tmov_s\tr1,r0\b')
    has(t, r'\tld_s\tr0,\[pcl,0x1c\]\t;0x235ae0\b')
    has(t, r'\tldw_s\tr0,\[r0,0\]')
    has(t, r'\tcmp_s\tr1,r0\b')
    has(t, r'\tmov_s\tr0,0x1\b')
    has(t, r'\tmov_s\tr0,0\b')

    # 8b. State-wait helper 0x18B954(idx, h): double pre-guard + state byte
    #     compare + release; the state struct comes from the ld.as-scaled
    #     pool 0x18B8F9 -> 0x18B788 = 0x367FE8.
    t = w('state_wait_18b954')
    has(t, r'\tbl\t696660\t;0x235abc\b')
    has(t, r'\tcmp_s\tr0,0\b')
    has(t, r'\tmov_s\tr0,0\b')
    has(t, r'\tld\.as\tr15,\[pcl,-123\]\t;0x18b8f9\b')
    has(t, r'\tldb_s\tr0,\[r15,0x2\]')
    has(t, r'\tcmp_s\tr13,r0\b')
    has(t, r'\tbl\t696636\t;0x235abc\b')
    has(t, r'\tmov_s\tr0,0x2\b')
    has(t, r'\tbl\t694468\t;0x23524c\b')
    has(t, r'\tmov_s\tr0,0x1\b')

    # 9. Acquire 0x235A1C(type=2, &h): busy bit [+0x26], callback [+0x34],
    #    h = halfword [0x36A464+0x1c] (== 0x36A480).
    t = w('acquire_235a1c')
    has(t, r'\tcmp_s\tr0,0x2\b')
    has(t, r'\tld_s\tr15,\[pcl,0x64\]\t;0x235ab4\b')
    has(t, r'\tldw_s\tr0,\[r15,0x26\]')
    has(t, r'\tld_s\tr1,\[r15,0x34\]')
    has(t, r'\tbset\tr0,r0,r14\b')
    has(t, r'\tstw_s\tr0,\[r15,0x26\]')
    has(t, r'\tjl_s\t\[r1\]')
    has(t, r'\tldw_s\tr0,\[r15,0x1c\]')
    has(t, r'\tsth\tr0,\[r16\]')             # h = generation halfword

    # 10. Setter 0x18B85C: wait=1 always, commit on success, else 0x18B9D4.
    t = w('setter_18b85c')
    has(t, r'\tmov_s\tr2,0x1\b')                # wait = 1
    has(t, r'\tbl\.d\t696928\t;0x235b0c\b')
    has(t, r'\tld_s\tr3,\[pcl,0x20\]\t;0x18b8d0\b')    # timeout 0x3A98
    has(t, r'\tcmp_s\tr0,0x1\b')
    has(t, r'\tbl\t288\t;0x18b9d4\b')          # failure -> sync completion
    has(t, r'\tstb_s\tr13,\[r14,0x2\]')      # commit state byte

    # 10b. State alias accessors (audit find): getter 0x18B8D4 and direct
    #      mini-setter 0x18B8E0 of the byte [0x367FEA] ([0x367FE8+2]).
    t = w('state_minisetter_18b8d4')
    has(t, r'\tld_s\tr0,\[pcl,0x8\]\t;0x18b8dc\b')
    has(t, r'\tldb_s\tr0,\[r0,0\]')
    has(t, r'\tld\tr1,\[pcl,-12\]\t;0x18b8dc\b')
    has(t, r'\tstb_s\tr0,\[r1,0\]')

    # 11. Failure completion 0x18B9D4 = handler body, entered synchronously.
    t = w('fail_entry_18b9d4')
    has(t, r'\tbl\t696284\t;0x2359b0\b')
    has(t, r'\tmov_s\tr0,0x2\b')
    has(t, r'\tbl\t694384\t;0x23524c\b')
    has(t, r'\tbl\t697352\t;0x235de8\b')
    has(t, r'\tb\t-820\t;0x18b6b0\b')

    # 12. Synchronous variant 0x18B844: completion + 0x235188(2).
    t = w('sync_entry_18b844')
    has(t, r'\tpush_s\tblink\b')
    has(t, r'\tbl\t696684\t;0x2359b0\b')
    has(t, r'\tmov_s\tr0,0x2\b')
    has(t, r'\tbl\t694588\t;0x235188\b')
    has(t, r'\tb_s\t-416\t;0x18b6b0\b')

    # 13. Claim wrapper 0x18B928: marker 0x235A10 then acquire(2, idx).
    t = w('claim_18b928')
    has(t, r'\tmov_s\tr13,r0\b')
    has(t, r'\tbl\t696540\t;0x235a10\b')
    has(t, r'\tmov_s\tr0,0x2\b')
    has(t, r'\tmov_s\tr1,r13\b')
    has(t, r'\tbl\t696544\t;0x235a1c\b')
    # Marker 0x235A10 sets byte [0x36A47E] = 1.
    t = w('marker_235a10')
    has(t, r'\tld_s\tr0,\[pcl,0x8\]\t;0x235a18\b')
    has(t, r'\tmov_s\tr1,0x1\b')
    has(t, r'\tstb_s\tr1,\[r0,0\]')
    has(t, r'\tj_s\t\[blink\]')

    # 14. Release 0x23524C(2) -> 0x235C60 -> 0x234CD0.
    t = w('release2_235c60')
    has(t, r'\tmov_s\tr0,0x2\b')
    has(t, r'\tb\t-3984\t;0x234cd0\b')

    # 15. In-motion flag 0x235DE8: clears [0x36A488] under a gate.
    t = w('inmotion_235de8')
    has(t, r'\tbl\t13432\t;0x239264\b')
    has(t, r'\tld_s\tr1,\[pcl,0x24\]\t;0x235e14\b')
    has(t, r'\tld_s\tr1,\[r1,0\]')
    has(t, r'\tbl\t586140\t;0x2c4f90\b')
    has(t, r'\tmov\.f\tr13,r0\b')
    has(t, r'\tbl\t-775956\t;0x1786e8\b')
    has(t, r'\tld\tr0,\[pcl,-28\]\t;0x235de4\b')
    has(t, r'\tmov_s\tr1,0\b')
    has(t, r'\tstb_s\tr1,\[r0,0\]')
    has(t, r'\tbl\t-772788\t;0x179354\b')
    has(t, r'\tb\t-2472\t;0x235468\b')
    # Sibling user of 0x235DE8 in the type-1 epilogue 0x18B6B4.
    t = w('rel_epilogue_18b6b4')
    has(t, r'\tbl\t696596\t;0x2357c8\b')
    has(t, r'\tmov_s\tr0,0x1\b')
    has(t, r'\tbl\t695184\t;0x23524c\b')
    has(t, r'\tbl\t698152\t;0x235de8\b')
    # In-motion byte [0x36A488] also gates a logger dispatch at 0x2353C2.
    t = w('inmotion_gate_2353c2')
    has(t, r'\tld_s\tr0,\[pcl,0x2c\]\t;0x2353fc\b')
    has(t, r'\tldb_s\tr0,\[r0,0\](\s|$)')
    has(t, r'\tcmp_s\tr0,0\b')
    has(t, r'\tbl\t587856\t;0x2c4c2c\b')
    has(t, r'\tbl\t588040\t;0x2c4cf0\b')

    # 16. Event resolver 0x158C8C: table [0x372A48], stride 0x38, magic.
    t = w('ev_resolve_158c8c')
    has(t, r'\tld_s\tr2,\[pcl,0x1bc\]\t;0x158e48\b')
    has(t, r'\tadd_s\tr2,r2,0x38\b')
    has(t, r'\tld_s\tr3,\[r2,0x4\]')
    has(t, r'\tcmp_s\tr0,r3\b')
    has(t, r'\tbne_s\t-8\t;0x158c90\b')
    has(t, r'\tld_s\tr0,\[r2,0\]')
    has(t, r'\tcmp_s\tr0,0x45564e4c\b')
    has(t, r'\tld_s\tr0,\[r2,0x8\]')
    has(t, r'\tbtst_s\tr0,0x1f\b')
    has(t, r'\tst_s\tr2,\[r1,0\]')
    has(t, r'\tld_s\tr0,\[pcl,0x1a4\]\t;0x158e4c\b')
    has(t, r'\tld_s\tr0,\[pcl,0x1a0\]\t;0x158e50\b')

    # 17. Event CLEAR 0x158CE0 -> 0x23C8AC: bic of the bit on [event+0x18].
    t = w('ev_clear_158ce0')
    has(t, r'\tmov_s\tr13,r1\b')
    has(t, r'\tmov_s\tr1,sp\b')
    has(t, r'\tbl_s\t-92\t;0x158c8c\b')
    has(t, r'\tld_s\tr0,\[sp,0\]')
    has(t, r'\tadd_s\tr0,r0,0xc\b')
    has(t, r'\tbl\.d\t932792\t;0x23c8ac\b')
    has(t, r'\tmov_s\tr1,r13\b')
    has(t, r'\tbl\t141944\t;0x17b770\b')
    t = w('ev_bitclear_23c8ac')
    has(t, r'\tld_s\tr2,\[r0,0x18\]')
    has(t, r'\tbic_s\tr2,r2,r1\b')
    has(t, r'\tst_s\tr2,\[r0,0x18\]')

    # 18. Event SET 0x158CBC -> 0x23C758: or of the bit on [event+0x18].
    t = w('ev_set_158cbc')
    has(t, r'\tmov_s\tr13,r1\b')
    has(t, r'\tmov_s\tr1,sp\b')
    has(t, r'\tbl_s\t-56\t;0x158c8c\b')
    has(t, r'\tadd_s\tr0,r0,0xc\b')     # event services operate on entry+0xC
    has(t, r'\tbl\.d\t932488\t;0x23c758\b')
    has(t, r'\tmov_s\tr1,r13\b')
    has(t, r'\tbl\t141980\t;0x17b770\b')
    t = w('ev_bitset_23c758')
    has(t, r'\tldw_s\tr2,\[r0,0x10\]')
    has(t, r'\tld_s\tr3,\[r0,0x18\]')
    has(t, r'\tor_s\tr3,r3,r1\b')
    has(t, r'\tbreq\tr2,0,224\t;0x23c868\b')
    has(t, r'\tld\tr10,\[r0,8\]')            # waiter list root at event+8

    # 19. Event WAIT 0x158D04: registers the waiter (blink at event+0x2c).
    t = w('ev_wait_head_158d04')
    has(t, r'\tmov_s\tr18,r0\b')
    has(t, r'\tmov_s\tr17,r1\b')
    has(t, r'\tmov_s\tr16,r2\b')
    has(t, r'\tmov_s\tr14,r3\b')
    has(t, r'\tmov\tr13,blink\b')
    has(t, r'\tbl_s\t-156\t;0x158c8c\b')
    t = w('ev_wait_tail_158da6')
    has(t, r'\tld_s\tr0,\[sp,0\]')
    has(t, r'\tst_s\tr13,\[r0,0x2c\]')       # blink recorded at event+0x2c
    has(t, r'\tadd_s\tr0,r0,0xc\b')
    has(t, r'\tpop_s\tblink\b')
    has(t, r'\tld\.ab\tr18,\[sp,4\]')

    # 20. Deferred post service 0x145F28 (head): validation + timer1 arm.
    t = w('post_head_145f28')
    has(t, r'\tbl\t2023920\t;0x334118\b')
    has(t, r'\tmov_s\tr17,r0\b')
    has(t, r'\tmov\.f\tr18,r1\b')
    has(t, r'\tmov_s\tr16,r2\b')
    has(t, r'\tmov_s\tr13,r3\b')
    has(t, r'\tbeq_s\t8\t;0x145f40\b')        # null handler -> error
    has(t, r'\tcmp\tr17,0\b')
    has(t, r'\tmov_s\tr0,0x2\b')
    has(t, r'\tbset_s\tr0,r0,0x15\b')          # error 2|1<<0x15
    has(t, r'\tb_s\t238\t;0x146032\b')
    has(t, r'\tbl\t206756\t;0x1786e8\b')
    has(t, r'\tld_s\tr14,\[pcl,0x2ec\]\t;0x146234\b')   # 0x366EBC
    has(t, r'\tldb_s\tr0,\[r14,0x8\]')       # init flag
    has(t, r'\tbl\t963792\t;0x231420\b')
    has(t, r'\tbl\t2030552\t;0x335b34\b')      # millicode divide
    has(t, r'\tsr\t0x1000000,\[limit1\]')    # ARC700 timer1 limit
    has(t, r'\tsr\t0,\[count1\]')
    has(t, r'\tsr\t0x2,\[control1\]')
    has(t, r'\trsub\tr1,r0,0x1000000\b')
    has(t, r'\tsr\tr1,\[count1\]')
    has(t, r'\tsr\t0x3,\[control1\]')        # timer started

    # 21. Post service (rest): 10 slots stride 20, handler at slot+16.
    t = w('post_rest_145f9c')
    has(t, r'\tmov_s\tr14,0\b')
    has(t, r'\tcmp_s\tr14,0xa\b')              # exactly 10 slots
    has(t, r'\tld_s\tr1,\[pcl,0x298\]\t;0x146240\b')   # table 0x4437F4
    has(t, r'\tasl_s\tr0,r14,0x2\b')
    has(t, r'\tadd2_s\tr0,r0,r0\b')            # index*20
    has(t, r'\tldb_s\tr0,\[r1,r0\]')         # slot flags byte
    has(t, r'\tbne_s\t-16\t;0x145fa0\b')       # slot-busy loop
    has(t, r'\tbge\t114\t;0x146026\b')         # table full -> error
    has(t, r'\tld_s\tr12,\[pcl,0x284\]\t;0x146240\b')
    has(t, r'\tld_s\tr15,\[pcl,0x274\]\t;0x146234\b')
    has(t, r'\tasl_s\tr13,r14,0x2\b')
    has(t, r'\tadd2_s\tr13,r13,r13\b')
    has(t, r'\tadd_s\tr13,r13,r12\b')
    has(t, r'\tstb_s\tr0,\[r13,0\]')         # slot flags
    has(t, r'\tst_s\tr0,\[r13,0x4\]')        # slot serial
    has(t, r'\tmov_s\tr0,r16\b')               # timeout
    has(t, r'\tbl\.d\t2032516\t;0x336364\b')   # millicode scale
    has(t, r'\tbl\.d\t2030900\t;0x335d34\b')   # millicode mul
    has(t, r'\tst_s\tr0,\[r13,0x8\]')        # slot deadline
    has(t, r'\tst_s\tr0,\[r13,0xc\]')
    has(t, r'\tst\tr18,\[r13,16\]')          # HANDLER stored at slot+16
    has(t, r'\tst\tr1,\[r17\]')              # caller object updated
    has(t, r'\tst_s\tr0,\[r15,0x10\]')       # service serial
    has(t, r'\tstb_s\tr0,\[r15,0x8\]')       # service count
    has(t, r'\tbl\t209712\t;0x179354\b')
    # Sibling re-post wrapper at 0x146044 (census site 0x146056, real call).
    t = w('post_sibling_146044')
    has(t, r'\tld_s\tr0,\[pcl,0x1fc\]\t;0x146248\b')   # object 0x366ED0
    has(t, r'\tmov_s\tr1,r14\b')
    has(t, r'\tmov_s\tr2,r13\b')
    has(t, r'\tbl_s\t-300\t;0x145f28\b')
    # Slot-table CANCEL service 0x14605C: find slot by serial, clear flags,
    # decrement the service count.
    t = w('post_cancel_14605c')
    has(t, r'\tbl\.d\t206472\t;0x1786e8\b')
    has(t, r'\tld_s\tr1,\[pcl,0x1d0\]\t;0x146234\b')
    has(t, r'\tldb_s\tr0,\[r1,0x8\]')
    has(t, r'\tcmp_s\tr3,0xa\b')
    has(t, r'\tld_s\tr12,\[pcl,0x1c4\]\t;0x146240\b')
    has(t, r'\tasl_s\tr0,r3,0x2\b')
    has(t, r'\tadd2_s\tr0,r0,r0\b')
    has(t, r'\tld_s\tr2,\[r0,0x4\]')          # slot serial
    has(t, r'\tcmp_s\tr13,r2\b')                # match by serial
    has(t, r'\tldb_s\tr2,\[r0,0\]')            # slot flags
    has(t, r'\tstb_s\tr2,\[r0,0\]')           # flags cleared
    has(t, r'\tsub_s\tr0,r0,0x1\b')
    has(t, r'\tstb_s\tr0,\[r1,0x8\]')          # service count decremented

    # 22. Panel: shadow getter dispatch and wait loops (NOT [+6] direct).
    t = w('panel_head_2c50b6')
    has(t, r'\tld_s\tr14,\[pcl,0xe8\]\t;0x2c519c\b')   # getter 0x16F920
    has(t, r'\tmov_s\tr0,0x4\b')
    has(t, r'\tjl_s\t\[r14\]')
    has(t, r'\tmov_s\tr0,0x7\b')
    has(t, r'\tbne_s\t-6\t;0x2c50e6\b')        # poll shadow[7] until 0
    has(t, r'\tmov_s\tr0,0x8\b')
    has(t, r'\tbeq_s\t40\t;0x2c511c\b')
    t = w('panel_2c5100')
    has(t, r'\tbl\t-1284580\t;0x18b72c\b')     # iris subsystem init/reset
    has(t, r'\tmov_s\tr0,0x8\b')
    has(t, r'\tbne_s\t-4\t;0x2c5114\b')        # poll shadow[8] until 0
    has(t, r'\tmov_s\tr0,0x9\b')
    has(t, r'\tbeq_s\t44\t;0x2c514c\b')
    has(t, r'\tld_s\tr2,\[pcl,0x74\]\t;0x2c51a8\b')    # "Iris status: Big"
    has(t, r'\tmov_s\tr0,0x1\b')
    has(t, r'\tbl\t-1284324\t;0x18b85c\b')     # set Big
    has(t, r'\tbne_s\t-4\t;0x2c5144\b')        # poll shadow[9] until 0
    has(t, r'\tmov_s\tr0,0xa\b')
    has(t, r'\tbeq_s\t-154\t;0x2c50b6\b')
    has(t, r'\tld_s\tr2,\[pcl,0x48\]\t;0x2c51ac\b')    # "Iris status: Small"
    has(t, r'\tmov_s\tr0,0x9\b')
    has(t, r'\tbl\t-1284372\t;0x18b85c\b')     # set Small
    has(t, r'\tb_s\t-8\t;0x2c5174\b')         # poll shadow[0xA] until 0
    t = w('shadow_getter_16f920')
    has(t, r'\tld_s\tr1,\[pcl,0x114\]\t;0x16fa34\b')   # base 0x446808
    has(t, r'\tadd2_s\tr1,r1,r0\b')            # base + idx*4
    has(t, r'\tldb_s\tr0,\[r1,0\]')          # byte shadow[idx]

    # 23. Models.
    # Generation guard: acquire returns h = current counter; the pre-guard
    # passes iff h == counter; a successful request increments the counter,
    # so a stale handle fails the next pre-guard (including the wrap case).
    for c in range(0x10000):
        h = c
        assert h == c                      # fresh handle passes the pre-guard
        c2 = (c + 1) & 0xFFFF              # request success increments
        assert h != c2                     # stale handle fails the pre-guard
    # Critical-section pairing inside the completion body.
    t = w('body_head_2359b0') + w('body_cont_2359d0')
    assert count(t, r'\tbl\t-?\d+\t;0x1786e8\b') == 2
    assert count(t, r'\tbl\t-?\d+\t;0x179354\b') == 2
    # GPIO pulse end state: set both bits then clear both bits.
    for v in range(0x10000):
        assert (((v | 0x18) & ~0x18) & 0xFFFF) == (v & ~0x18 & 0xFFFF)
        assert ((v & ~0x18) & 0x18) == 0
    # Event bit clear/set semantics.
    for x in range(0x10000):
        assert (x & ~0x10 & 0xFFFF) == (x & 0xFFEF)
        assert (x | 0x10) & 0x10 == 0x10

    # 24. Pool census (raw scan, step 2, plus step-1 alignment check).
    def pools_of(value: int) -> set:
        return {base0 + o for o in range(0, len(p0) - 3, 2)
                if struct.unpack_from('<I', p0, o)[0] == value}
    assert pools_of(0x36A464) == POOLS_36A464, sorted(hex(x) for x in pools_of(0x36A464))
    assert pools_of(0x36A480) == POOLS_36A480
    assert pools_of(0x36A482) == POOLS_36A482
    assert pools_of(0x36A494) == POOLS_36A494
    assert pools_of(0x36A488) == POOLS_36A488
    assert pools_of(0x36A484) == POOLS_36A484
    assert pools_of(0x36A47E) == POOLS_36A47E
    odd_hits = [base0 + o for o in range(1, len(p0) - 3, 2)
                if struct.unpack_from('<I', p0, o)[0] in
                (0x36A464, 0x36A480, 0x36A482, 0x36A494, 0x36A488, 0x36A484,
                 0x36A47E)]

    # 25. Call-site census from the linear GNU listing.
    listing = objdump_text(ROOT, block_dir, info[0], p0)
    (out / 'linear_listing_size.txt').write_text(f'{len(listing.splitlines())}\n')
    calls = {t: set() for t in (0x2359B0, 0x235A10, 0x235AE4, 0x235AF8,
                                0x235ABC, 0x235DE8, 0x235A1C, 0x235C60,
                                0x145F28, 0x14605C)}
    for ln in listing.splitlines():
        m = LINE_PAT.match(ln)
        if not m:
            continue
        site = int(m.group(1), 16)
        mnemonic = m.group(2)
        rest = m.group(3).strip()
        if not re.match(r'^bln?(\.d|_s|_s\.d)?$', mnemonic):
            continue
        tm = CALL_TARGET.match(rest)
        if not tm:
            continue
        target = int(tm.group(2), 16)
        if target in calls:
            calls[target].add(site)
    assert calls[0x2359B0] == CALLS_2359B0, sorted(hex(s) for s in calls[0x2359B0])
    assert calls[0x235A10] == CALLS_235A10
    assert calls[0x235AE4] == CALLS_235AE4
    assert calls[0x235AF8] == CALLS_235AF8
    assert calls[0x235ABC] == CALLS_235ABC
    assert calls[0x235DE8] == CALLS_235DE8, sorted(hex(s) for s in calls[0x235DE8])
    assert calls[0x235A1C] == CALLS_235A1C
    assert calls[0x235C60] == CALLS_235C60
    assert calls[0x145F28] == CALLS_145F28, sorted(hex(s) for s in calls[0x145F28])
    assert calls[0x14605C] == CALLS_14605C, sorted(hex(s) for s in calls[0x14605C])

    # 26. Result JSON.
    stamp = out.name
    result = dict(
        status='PASS_IRIS_COMPLETION_STATIC',
        stamp=stamp,
        firmware_sha256=sha(FIRMWARE),
        correction=dict(
            what='iteration-21 notation "[[0x36A464]+0x1c]++" is a double '
                 'dereference that the bytes do not show: both loads take the '
                 'pool VALUE 0x36A464 and the counter is the halfword at '
                 '0x36A464+0x1c = cell 0x36A480',
            evidence='request 0x235B5E/0x235B60 (ld_s from pool 0x235BC8) + '
                     '0x235B66/0x235B6A (ldw_s/stw_s [r?,0x1c]); pre-guard '
                     '0x235AC6/0x235AC8 reads halfword [0x36A480]; acquire '
                     '0x235A60/0x235A66 returns the same halfword as h',
            consequence='the pre-guard is a GENERATION check: acquire returns '
                        'h = current counter; the request aborts without '
                        'actuating when h != counter; success increments the '
                        'counter so stale handles fail'),
        completion=dict(
            status_byte='[0x36A464+6]: set 1 by actuation paths 0x2358F4/0x235950 '
                        '(iteration 21), CLEARED to 0 by the deferred completion '
                        'body 0x2359B0 (stb_s at 0x235A02)',
            body_2359b0='callback [0x36A464+0x3C] -> critical section -> GPIO '
                        '0x0FF04024 |= 0x18 (both iris bits) -> delay 500 '
                        '(0x23C620) -> second critical section: GPIO &= -25 '
                        '(clears bits 3/4, preserves bits 0/1) and STATUS [0x36A464+6]=0 '
                        'STORED INSIDE the same critical section (stb_s at '
                        '0x235A02, before the 0x179354 exit) -> return 0',
            handler_235ae4='0x2359B0 + 0x23524C(2) (release: 0x235C60 -> '
                           '0x234CD0) + 0x235DE8 (clears in-motion byte '
                           '[0x36A488] under gate 0x2C4F90([0x36A484])) -> '
                           'return via 0x234F18',
            handler_235af8='0x235AE4 + event SET 0x158CBC(1|1<<25, 0x10)',
            event=dict(group_id='1|1<<25 = 0x2000001', bit=0x10,
                       table_cell=he(0x372A48), stride=0x38,
                       magic=0x45564E4C, gate_bit=31,
                       note='0x158CBC/0x158CE0 operate on entry+0xC '
                            '(add_s r0,r0,0xc): the bit field "[r0,0x18]" is '
                            'at entry+0x24 and the waiter list "[r0,8]" at '
                            'entry+0x14; the waiter registration '
                            '[event+0x2c] is unshifted',
                       clear='0x158CE0 -> 0x23C8AC bic_s on [entry+0x24] '
                             '(called BEFORE the post; no waiter scan)',
                       set='0x158CBC -> 0x23C758 or_s on [entry+0x24], walks '
                           'waiter list [entry+0x14]',
                       wait='0x158D04: registers waiter, blink stored at '
                            '[event+0x2c] (unshifted)'),
            post_service=dict(entry=he(0x145F28),
                              object_cell=he(0x36A494),
                              service_object=he(0x366EBC),
                              slot_table=he(0x4437F4), slots=10, stride=20,
                              handler_offset=16, deadline_offset=8,
                              timer='ARC700 timer1 aux (limit1=0x1000000, '
                                     'count1, control1 2/3)',
                              divisor=0x2710,
                              cancel_entry=he(0x14605C),
                              cancel_sites=sorted(he(s) for s in CALLS_14605C),
                              shared_call_sites=sorted(he(s) for s in CALLS_145F28)),
            setter='0x18B85C always requests with wait=1 (mov_s r2,0x1) and '
                   'blocks on event 0x10; commits the state byte only on '
                   'request success, else runs completion synchronously via '
                   '0x18B9D4 (same body as the handler)',
            other_completion_entries=[he(0x18B844), he(0x18B6B4)],
            state_alias_accessors=dict(getter=he(0x18B8D4),
                                       mini_setter=he(0x18B8E0),
                                       cell=he(0x367FEA),
                                       note='[0x367FE8+2] is also written '
                                            'directly, outside setter '
                                            '0x18B85C (audit find)'),
            state_wait_18b954='two pre-guards on DISTINCT branches around '
                              'the idx vs state compare; the idx!=state '
                              'branch issues the request with wait=0 '
                              '(mov_s r2,0 at 0x18B9AC)',
            marker='[0x36A47E]=1 set by 0x235A10 from claim wrapper 0x18B928 '
                   'before 0x235A1C(2, idx)'),
        panel=dict(
            what='0x2C5100 polls shadow bytes 0x446808+4*idx via getter '
                 '0x16F920 (indices 8/9/0xA, wait-until-zero loops) and then '
                 'sets Big/Small with 0x18B85C(1)/(9); it does NOT read '
                 '[0x36A464+6] directly',
            shadow_base=he(0x446808), writer='OPEN (not identified in this '
                                              'iteration)'),
        census=dict(
            pools_36a464=sorted(he(p) for p in POOLS_36A464),
            pools_36a480=sorted(he(p) for p in POOLS_36A480),
            pools_36a482=sorted(he(p) for p in POOLS_36A482),
            pools_36a494=sorted(he(p) for p in POOLS_36A494),
            pools_36a488=sorted(he(p) for p in POOLS_36A488),
            pools_36a484=sorted(he(p) for p in POOLS_36A484),
            pools_36a47e=sorted(he(p) for p in POOLS_36A47E),
            odd_aligned_hits=[he(h) for h in odd_hits],
            calls_2359b0=sorted(he(s) for s in CALLS_2359B0),
            calls_235a10=sorted(he(s) for s in CALLS_235A10),
            calls_235ae4=sorted(he(s) for s in CALLS_235AE4),
            calls_235af8=sorted(he(s) for s in CALLS_235AF8),
            calls_235abc=sorted(he(s) for s in CALLS_235ABC),
            calls_235de8=sorted(he(s) for s in CALLS_235DE8),
            calls_235a1c=sorted(he(s) for s in CALLS_235A1C),
            calls_235c60=sorted(he(s) for s in CALLS_235C60),
            calls_145f28=sorted(he(s) for s in CALLS_145F28)),
        limits=[
            'Static only: no MMIO, timer, interrupt, camera hardware or '
            'firmware execution',
            'WHO fires the deferred callbacks (timer1 consumer / interrupt '
            'handler reading the slot table 0x4437F4) is runtime and NOT '
            'identified here; the "deferred" semantics rest on the slot '
            'layout + handler store + timer arm, not on a proven caller',
            'Physical meaning of the both-bits pulse in 0x2359B0 (set 0x18, '
            'delay 500, clear -25) is inference (brake/park/release pulse?), '
            'as is the direction of the GPIO drive',
            'The blocking behaviour of 0x158D04 is a runtime model: the '
            'waiter-registration bytes are verified, the scheduler is not '
            'executed',
            'Writer of the panel shadow table 0x446808 is OPEN',
            'Linear-listing censuses can carry false positives near pools; '
            'all chain sites are re-verified in dedicated aligned windows '
            '(0x146056 sibling included), the peripheral census sites are '
            'candidate',
            'The register-masked RMW in 0x2349C0 could still touch bits 3/4 '
            'at runtime (iteration-21 caveat, unchanged)',
            'V1.1 sample analysed; camera in the logs runs V1.0; addresses '
            'are not portable without proof',
        ],
        sources=dict(
            script=str(Path(__file__).relative_to(ROOT)),
            firmware=str(FIRMWARE.relative_to(ROOT)),
            manifest='S33-sections/TBM_blocks/manifest.json',
            objdump='work/build-arc/binutils (GNU ARC700, -EL, aligned windows)'),
    )
    (out / 'iris_completion.json').write_text(json.dumps(result, indent=1) + '\n')
    (EVIDENCE / 'latest.json').write_text(json.dumps(
        dict(status=result['status'], stamp=stamp, path=str(out.relative_to(ROOT)),
             script=str(Path(__file__).relative_to(ROOT))), indent=1) + '\n')
    print('PASS_IRIS_COMPLETION_STATIC', stamp)


if __name__ == '__main__':
    main()
