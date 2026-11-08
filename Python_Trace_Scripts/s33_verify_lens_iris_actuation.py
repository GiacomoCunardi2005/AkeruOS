#!/usr/bin/env python3
"""Static verification of the iris (aperture) actuation chain in Main payload0.

Closes the long-standing open point "wrapper iris fra i 33 chiamanti di
0x25F338" with a NEGATIVE answer and a correction: the iris does NOT travel
on the lens-MCU wire (transaction 0x25F338 / port 0x0FF05000). It is driven
by dedicated GPIO-style bits of 0x0FF04024 (bit4 = Big, bit3 = Small) plus
clears of bits 0/1 of 0x0FEF0388, inside the request function 0x235B0C.

Byte-verified chain (V1.1 Main block0, base 0x0AD800):
- AE/iris block 0x1236BC..0x125xxx logs "Change Iris from MAX: %d To MIN: %d"
  (formats via pools 0x124F64/0x124F6C -> payload1 strings 0x3860EE/0x38612C)
  and calls the API 0x149530(idx) with idx = 9 (Small) at 0x124D8A/0x124E04
  and with the computed index at 0x124EEA (guard cmp_s r15,0x9);
- 0x149530(idx) -> 0x18B85C(idx): state byte [0x367FE8+2], request via
  0x235B0C(h, idx, 1, 0x3A98);
- 0x235B0C: critical section 0x1786E8/0x179354, busy check 0x234F1C on
  [[0x3EBD3C]+8], error byte [0x36A482]=0x15 when busy, branch idx==9:
  0x235950 (Small) / 0x2358F4 (Big), counter [[0x36A464]+0x1c]++,
  event 0x158CE0(1|1<<25, 0x10), mailbox 0x145F28([0x36A494],
  0x235AF8/0x235AE4, 0x3A98, 0), optional wait 0x158D04(1|1<<25,0x10,1,0);
- 0x2358F4 (Big, idx!=9): callback slot [0x36A464+0x40], RMW 0x0FEF0388
  bclr bit0 then bclr bit1, RMW 0x0FF04024 `and -25` + `bset bit4`
  -> bit4=1, bit3=0; status [0x36A464+6]=1;
- 0x235950 (Small, idx==9): identical but `bset bit3` -> bit3=1, bit4=0;
- diagnostic panel 0x2C5100 sets Big/Small with 0x18B85C(1)/0x18B85C(9)
  and reads status through the getter family (indices 8/9/0xA), printing
  "Iris status: Big/Small" (payload1 0x406E89/0x406E9A): confirms the
  encoding 1=Big / 9=Small of BCIP_Aperture SP2 at the actuation layer.

Census (payload0): word LE 0x0FF04024 appears only in the 13 pools listed
below; bits 3/4 are written only by the 0x234Dxx-0x235Dxx iris family
(caveat: 0x2349C0 does a register-masked RMW). No bl site inside the
AE/iris block targets any wire-cluster entry.

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
EVIDENCE = ROOT / 'Risultati/Lens_MCU_Interface/Iris_Actuation'

# Verified entries and helpers (Main = block0 base 0x0AD800).
AE_IRIS_LOG = (0x124D34, 0x124E12)        # AE block: Change-Iris log + sets
AE_IRIS_COND = (0x124EE2, 0x124EF0)        # AE block: conditional set (cmp 9)
API_149530 = (0x149530, 0x149546)          # SetIrisIndex API wrapper
SETTER_18B85C = (0x18B85C, 0x18B8D0)       # iris state setter
REQUEST_235B0C = (0x235B0C, 0x235BB2)      # request/actuation dispatcher
BIG_2358F4 = (0x2358F4, 0x235950)          # Big-iris actuation path
SMALL_235950 = (0x235950, 0x235970)        # Small-iris actuation path (head incl. tail b)
SMALL_CONT = (0x235970, 0x2359AE)          # Small-iris actuation (after pool)
PANEL_2C5100 = (0x2C5100, 0x2C5180)        # diagnostic Iris status panel
READER_25E0B8 = (0x25E0B8, 0x25E0D0)       # lens-ready bit7 getter (control)

# Literal words re-read from raw payload0 bytes (objdump pcl comments are the
# unscaled pool addresses; values are little-endian words of the raw bytes).
LITERALS = {
    0x18B788: 0x367FE8,   # setter: iris state struct (byte index at +2)
    0x18B8D0: 0x00003A98,  # request type id (delay slot of bl.d 0x235B0C)
    0x18B8DC: 0x367FEA,   # setter: state struct +2 (alias cell)
    0x235BC0: 0x3EBD3C,   # request: busy-object pointer cell
    0x235BC4: 0x36A482,   # request: error byte cell (0x15 when busy)
    0x235BC8: 0x36A464,   # request: iris control struct (counter +0x1c)
    0x235BCC: 0x235AF8,   # mailbox handler when wait!=0
    0x235BD0: 0x235AE4,   # mailbox handler when wait==0
    0x235AE0: 0x36A480,   # request pre-guard: expected halfword cell
    0x235BD4: 0x36A494,   # mailbox object cell
    0x2358E0: 0x36A464,   # Big path: control struct (callback +0x40, status +6)
    0x23590C: 0x0FEF0388,  # Big path: strobe/enable register
    0x235930: 0x0FF04024,  # Big path: iris GPIO register
    0x235968: 0x36A464,   # Small path: control struct
    0x23596C: 0x0FEF0388,  # Small path: strobe/enable register
    0x235990: 0x0FF04024,  # Small path: iris GPIO register
    0x124F64: 0x3860EE,   # AE log format 1 (payload1 string)
    0x124F6C: 0x38612C,   # AE log format 2 (payload1 string)
    0x2C51A8: 0x406E89,   # panel: "Iris status: Big"
    0x2C51AC: 0x406E9A,   # panel: "Iris status: Small"
    0x25E0C0: 0x0FF04024,  # lens-ready bit7 getter register
}

# Wire-cluster entries (transaction/sender/record/move/hub/switch/query).
WIRE_ENTRIES = (0x25F338, 0x25CB54, 0x25CB3C, 0x25F6A4, 0x29DDD4, 0x25C4B4,
                0x25C268, 0x25C3F8, 0x25C558, 0x25C1F0, 0x25C37C, 0x1EE148,
                0x1EE730, 0x1ED11C, 0x25F3F4, 0x2606B4, 0x260C6C)
AE_BLOCK = (0x123000, 0x126000)

# Census expectations (linear GNU listing of payload0).
CALLS_149530 = {0xDB46C, 0xDBD84, 0xE0A96, 0xEF1A4, 0xEF1B0, 0xEF1BC, 0xF01A4,
                0xF1998, 0x123078, 0x1231D2, 0x123330, 0x12370C, 0x123FF4,
                0x124D8A, 0x124E04, 0x124EEA, 0x1256FA, 0x125EA8, 0x14A3E6,
                0x1DD342, 0x2224F2, 0x222504, 0x284B96, 0x285902, 0x285A0A,
                0x285A9E, 0x28C29E, 0x28C35A, 0x28C3F6, 0x2FE394, 0x2FE57A,
                0x324A8C}
CALLS_18B85C = {0x146DB0, 0x147316, 0x147632, 0x14953E, 0x15708C, 0x157EB6,
                0x158690, 0x158730, 0x2C5140, 0x2C5170, 0x2FC528, 0x2FC54C,
                0x2FCB58, 0x2FCDD0, 0x2FCFD8, 0x2FD1AA, 0x2FD380, 0x2FD48A,
                0x2FD546, 0x2FD988, 0x2FDD24}
CALLS_235B0C = {0x18B8AC, 0x18B9AE}
CALLS_2358F4 = {0x235B5A}
CALLS_235950 = {0x235B54}

# All payload0 pools holding the word LE 0x0FF04024 (raw scan, step 2).
Pools_0FF04024 = {0x17B5F4, 0x234DD4, 0x23544C, 0x235734, 0x2357A8, 0x2357D8,
                  0x235868, 0x235930, 0x235990, 0x2359CC, 0x235BE8, 0x25A008,
                  0x25E0C0}
# Expected classification of each pool user (window at the referencing site).
POOL_USERS = {
    0x17B5F4: dict(site=0x17B5EE, kind='reader', detail='bit0 (bmsk_s 0)'),
    0x234DD4: dict(site=0x234DD0, kind='masked_write_runtime'),
    0x23544C: dict(site=0x235446, kind='set_both_0x18'),
    0x235734: dict(site=0x23572A, kind='set_bit4_big'),
    0x2357A8: dict(site=0x23579C, kind='set_bit3_small'),
    0x2357D8: dict(site=0x2357D2, kind='set_both_0x18_delay500'),
    0x235868: dict(site=0x235862, kind='clear_both'),
    0x235930: dict(site=0x23592A, kind='set_bit4_big'),
    0x235990: dict(site=0x23598A, kind='set_bit3_small'),
    0x2359CC: dict(site=0x2359C4, kind='set_both_0x18_delay500'),
    0x235BE8: dict(site=0x235BE2, kind='clear_both'),
    0x25A008: dict(site=0x25A004, kind='reader', detail='bit1 (btst_s 0x1)'),
    0x25E0C0: dict(site=0x25E0BA, kind='reader', detail='bit7 after lsr 7 (bmsk_s 0)', end=0x25E0D0),
}

LINE_PAT = re.compile(r'^\s*([0-9a-f]+):\t[0-9a-f ]+\t(\S+)\t?(.*)$')
CALL_TARGET = re.compile(r'^(-?\d+)\t;0x([0-9a-f]+)')
POOL_REF = re.compile(r';0x([0-9a-f]+)')


def has(text: str, pattern: str) -> None:
    assert re.search(pattern, text), f'missing pattern: {pattern}'


def safe_window(payload: bytes, base: int, lo: int, length: int) -> str:
    """Aligned window shrinking to the next shorter size if the end cuts an
    instruction (objdump flags out-of-bounds continuation addresses)."""
    for size in (length, length - 4, length - 8):
        try:
            return aligned_window(payload, base, lo, lo + size)
        except AssertionError:
            continue
    raise AssertionError(f'no clean window at {lo:#x}')


def classify_window(text: str) -> str:
    if re.search(r'and_s\tr0,r0,r13', text):
        return 'masked_write_runtime'
    if re.search(r'or\tr0,r0,0x18', text):
        return 'set_both_0x18' + ('_delay500' if re.search(r'bl\t-?\d+\t;0x23c620', text) else '')
    if re.search(r'bset_s\tr0,r0,0x3\b', text) and re.search(r'and\tr0,r0,-25', text):
        return 'set_bit3_small'
    if re.search(r'bset_s\tr0,r0,0x4\b', text) and re.search(r'and\tr0,r0,-25', text):
        return 'set_bit4_big'
    if re.search(r'and\tr0,r0,-25', text):
        return 'clear_both'
    if re.search(r'btst_s|bmsk_s', text):
        return 'reader'
    return 'other'


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

    # 2. String anchors in payload1 (log formats and panel labels).
    def p1_string(addr: int) -> bytes:
        off = addr - base1
        assert 0 <= off < len(p1)
        out_b = bytearray()
        while p1[off] and len(out_b) < 96:
            out_b.append(p1[off])
            off += 1
        return bytes(out_b)
    for addr in (0x3860EE, 0x38612C):
        assert p1_string(addr).startswith(b'Change Iris from MAX: %d  To MIN: %d')
    assert p1_string(0x406E89).startswith(b'Iris status: Big')
    assert p1_string(0x406E9A).startswith(b'Iris status: Small')

    # 3. Aligned windows.
    windows = {}
    for name, (lo, hi) in [
        ('ae_iris_log', AE_IRIS_LOG), ('ae_iris_cond', AE_IRIS_COND),
        ('api_149530', API_149530), ('setter_18b85c', SETTER_18B85C),
        ('request_235b0c', REQUEST_235B0C), ('big_2358f4', BIG_2358F4),
        ('small_235950', SMALL_235950), ('small_cont_235970', SMALL_CONT),
        ('panel_2c5100', PANEL_2C5100), ('reader_25e0b8', READER_25E0B8),
    ]:
        windows[name] = aligned_window(p0, base0, lo, hi)
        assert windows[name].strip(), name
    (out / 'gnu_windows.txt').write_text(
        '\n\n'.join(f'=== {k} ===\n{v}' for k, v in windows.items()))

    def w(name: str) -> str:
        return windows[name]

    # 4. AE block: log formats and iris set calls (idx = 9, Small).
    t = w('ae_iris_log')
    has(t, r'\tld_s\tr1,\[pcl,0x218\]\t;0x124f64\b')
    has(t, r'\tld_s\tr1,\[pcl,0x1a4\]\t;0x124f6c\b')
    has(t, r'\tbl\t33024\t;0x12ce54\b')
    has(t, r'\tmov\tr19,0x9\b')
    has(t, r'\tmov_s\tr0,0x9\b')
    has(t, r'\tbl\t149416\t;0x149530\b')      # 0x124D8A
    has(t, r'\tbl\t149292\t;0x149530\b')      # 0x124E04
    t = w('ae_iris_cond')
    has(t, r'\tcmp_s\tr15,0x9\b')
    has(t, r'\tmov_s\tr0,r15\b')
    has(t, r'\tbl\t149064\t;0x149530\b')      # 0x124EEA

    # 5. API wrapper 0x149530 -> setter 0x18B85C (prologue: blink + r13).
    t = w('api_149530')
    has(t, r'\tpush_s\tblink\b')
    has(t, r'\tpush_s\tr13\b')
    has(t, r'\tbl\t271136\t;0x18b85c\b')
    has(t, r'\tmov_s\tr0,0x1\b')
    has(t, r'\tb_s\t-482\t;0x149362\b')

    # 6. Setter 0x18B85C: state byte [0x367FE8+2], request via 0x235B0C.
    t = w('setter_18b85c')
    has(t, r'\tmov_s\tr13,r0\b')
    has(t, r'\tld\tr14,\[pcl,-228\]\t;0x18b788\b')
    has(t, r'\tldb_s\tr0,\[r14,0x2\]')
    has(t, r'\tcmp_s\tr13,r0\b')
    has(t, r'\tbl\t696728\t;0x235a1c\b')
    has(t, r'\tbl\t697616\t;0x235da0\b')
    has(t, r'\tbl\t694704\t;0x23524c\b')
    has(t, r'\tbl\.d\t696928\t;0x235b0c\b')
    has(t, r'\tld_s\tr3,\[pcl,0x20\]\t;0x18b8d0\b')  # delay slot: 0x3A98
    has(t, r'\tcmp_s\tr0,0x1\b')
    has(t, r'\tstb_s\tr13,\[r14,0x2\]')
    has(t, r'\tldb_s\tr0,\[r14,0x2\]')

    # 7. Request 0x235B0C: critical section, busy check, idx==9 branch,
    #    bookkeeping, mailbox and optional wait.
    t = w('request_235b0c')
    has(t, r'\tbl_s\t-108\t;0x235abc\b')   # pre-guard: h vs [0x36A480]
    has(t, r'\tbl\t-775240\t;0x1786e8\b')
    has(t, r'\tbl\t-772160\t;0x179354\b')
    has(t, r'\tld_s\tr0,\[pcl,0x8c\]\t;0x235bc0\b')
    has(t, r'\tld_s\tr0,\[r0,0x8\]')
    has(t, r'\tbl\t-3100\t;0x234f1c\b')
    has(t, r'\tld_s\tr0,\[pcl,0x80\]\t;0x235bc4\b')
    has(t, r'\tmov_s\tr1,0x15\b')
    has(t, r'\tstb_s\tr1,\[r0,0\]')
    has(t, r'\tcmp\tr18,0x9\b')
    has(t, r'\tbl\t-516\t;0x235950\b')        # idx == 9 -> Small
    has(t, r'\tbl\t-612\t;0x2358f4\b')        # idx != 9 -> Big
    has(t, r'\tldw_s\tr0,\[r0,0x1c\]')
    has(t, r'\tadd_s\tr0,r0,0x1\b')
    has(t, r'\tstw_s\tr0,\[r1,0x1c\]')
    has(t, r'\tmov_s\tr0,0x1\b')
    has(t, r'\tbset_s\tr0,r0,0x19\b')
    has(t, r'\tmov_s\tr1,0x10\b')
    has(t, r'\tbl\t-904856\t;0x158ce0\b')
    has(t, r'\tbl\t-982108\t;0x145f28\b')
    has(t, r'\tld_s\tr15,\[pcl,0x60\]\t;0x235bcc\b')
    has(t, r'\tld_s\tr15,\[pcl,0x60\]\t;0x235bd0\b')
    has(t, r'\tbl\t-904872\t;0x158d04\b')
    has(t, r'\tmov_s\tr2,0x1\b')
    has(t, r'\tmov_s\tr3,0\b')

    # 8. Big path 0x2358F4: callback, 0x0FEF0388 bclr 0/1, 0x0FF04024 bit4.
    t = w('big_2358f4')
    has(t, r'\tld\tr15,\[pcl,-24\]\t;0x2358e0\b')
    has(t, r'\tld_s\tr0,\[r15,0x40\]')
    has(t, r'\tjl_s\t\[r0\]')
    has(t, r'\tmov_s\tr13,0\b')
    has(t, r'\tld_s\tr14,\[pcl,0x8\]\t;0x23590c\b')
    has(t, r'\tldh\.di\tr10,\[r14\]')
    has(t, r'\tbclr\tr10,r10,r13\b')          # bclr bit0 (r13 == 0)
    has(t, r'\tmov_s\tr0,0x1\b')
    has(t, r'\tbclr\tr10,r10,r0\b')           # bclr bit1
    has(t, r'\tsth\.di\tr10,\[r14\]')
    has(t, r'\tld_s\tr14,\[pcl,0x8\]\t;0x235930\b')
    has(t, r'\tldh\.di\tr0,\[r14\]')
    has(t, r'\tand\tr0,r0,-25\b')             # clears bits 3 and 4
    has(t, r'\tbset_s\tr0,r0,0x4\b')          # Big: bit4 = 1
    has(t, r'\tsth\.di\tr0,\[r14\]')
    has(t, r'\tmov_s\tr0,0x1\b')
    has(t, r'\tstb_s\tr0,\[r15,0x6\]')      # status byte = 1
    has(t, r'\tb\t-2852\t;0x234e24\b')

    # 9. Small path 0x235950 (head + continuation after the pool).
    t = w('small_235950') + w('small_cont_235970')
    has(t, r'\tld_s\tr15,\[pcl,0x14\]\t;0x235968\b')
    has(t, r'\tld_s\tr0,\[r15,0x40\]')
    has(t, r'\tjl_s\t\[r0\]')
    has(t, r'\tmov_s\tr13,0\b')
    has(t, r'\tld_s\tr14,\[pcl,0xc\]\t;0x23596c\b')
    has(t, r'\tldh\.di\tr10,\[r14\]')
    has(t, r'\tbclr\tr10,r10,r13\b')
    has(t, r'\tmov_s\tr0,0x1\b')
    has(t, r'\tbclr\tr10,r10,r0\b')
    has(t, r'\tsth\.di\tr10,\[r14\]')
    has(t, r'\tld_s\tr14,\[pcl,0x8\]\t;0x235990\b')
    has(t, r'\tldh\.di\tr0,\[r14\]')
    has(t, r'\tand\tr0,r0,-25\b')
    has(t, r'\tbset_s\tr0,r0,0x3\b')         # Small: bit3 = 1
    has(t, r'\tsth\.di\tr0,\[r14\]')
    has(t, r'\tstb_s\tr0,\[r15,0x6\]')
    has(t, r'\tb\t-2948\t;0x234e24\b')

    # 10. Diagnostic panel: setter calls with 1 and 9, getter indices 8/9/0xA.
    t = w('panel_2c5100')
    has(t, r'\tmov_s\tr0,0x1\b')
    has(t, r'\tbl\t-1284324\t;0x18b85c\b')
    has(t, r'\tmov_s\tr0,0x9\b')
    has(t, r'\tbl\t-1284372\t;0x18b85c\b')
    has(t, r'\tmov_s\tr0,0x8\b')
    has(t, r'\tmov_s\tr0,0xa\b')
    has(t, r'\tjl_s\t\[r14\]')
    has(t, r'\tld_s\tr2,\[pcl,0x48\]\t;0x2c51ac\b')
    has(t, r'\tbl\t-1502344\t;0x1564a8\b')

    # 11. Control: lens-ready bit7 getter window unchanged.
    t = w('reader_25e0b8')
    has(t, r'\tpush_s\tblink\b')
    has(t, r'\tld_s\tr0,\[pcl,0x8\]\t;0x25e0c0\b')
    has(t, r'\tldh\.di\tr0,\[r0\]')
    has(t, r'\tlsr_s\tr0,r0,0x7\b')
    has(t, r'\tbmsk_s\tr0,r0,0\b')

    # 12. Model of the RMW semantics over all 65.536 values.
    for v in range(0x10000):
        base = v & ~0x18
        assert ((base | 0x10) & 0xFFFF) == ((v & ~0x18) | 0x10)
        assert ((base | 0x08) & 0xFFFF) == ((v & ~0x18) | 0x08)
        assert (v & ~0x18) == (v & 0xFFE7)

    # 13. Census from the linear GNU listing.
    listing = objdump_text(ROOT, block_dir, info[0], p0)
    (out / 'linear_listing_size.txt').write_text(f'{len(listing.splitlines())}\n')
    calls = {t: set() for t in (0x149530, 0x18B85C, 0x235B0C, 0x2358F4, 0x235950)}
    ae_block_targets = set()
    for ln in listing.splitlines():
        m = LINE_PAT.match(ln)
        if not m:
            continue
        site = int(m.group(1), 16)
        mnemonic = m.group(2)
        rest = m.group(3).strip()
        if not re.match(r'^bln?\.?[dsn]?$', mnemonic):
            continue
        tm = CALL_TARGET.match(rest)
        if not tm:
            continue
        target = int(tm.group(2), 16)
        if target in calls:
            calls[target].add(site)
        if AE_BLOCK[0] <= site < AE_BLOCK[1] and target in WIRE_ENTRIES:
            ae_block_targets.add((site, target))
    assert calls[0x149530] == CALLS_149530, sorted(hex(s) for s in calls[0x149530])
    assert calls[0x18B85C] == CALLS_18B85C, sorted(hex(s) for s in calls[0x18B85C])
    assert calls[0x235B0C] == CALLS_235B0C
    assert calls[0x2358F4] == CALLS_2358F4
    assert calls[0x235950] == CALLS_235950
    assert not ae_block_targets, sorted((hex(a), hex(b)) for a, b in ae_block_targets)

    # 14. Census of the 0x0FF04024 pools and their users' bit usage.
    hits = set()
    for off in range(0, len(p0) - 3, 2):
        if struct.unpack_from('<I', p0, off)[0] == 0x0FF04024:
            hits.add(base0 + off)
    assert hits == Pools_0FF04024, sorted(hex(h) for h in hits)
    users = {}
    for ln in listing.splitlines():
        m = LINE_PAT.match(ln)
        if not m:
            continue
        site = int(m.group(1), 16)
        rest = m.group(3)
        pm = POOL_REF.search(rest)
        if pm and int(pm.group(1), 16) in Pools_0FF04024 and 'pcl' in rest:
            pool = int(pm.group(1), 16)
            entry = POOL_USERS[pool]
            assert site == entry['site'], (hex(pool), hex(site), hex(entry['site']))
            head = safe_window(p0, base0, site, 0x10)
            tm = re.search(r'\tb_s\t-?\d+\t;0x([0-9a-f]+)', head)
            assert tm, (hex(pool), hex(site))
            cont = int(tm.group(1), 16)
            users[pool] = dict(site=he(site), kind=classify_window(
                head + safe_window(p0, base0, cont, 0x24)))
    assert len(users) == len(POOL_USERS), sorted(users)
    for pool, entry in POOL_USERS.items():
        assert users[pool]['kind'] == entry['kind'], (hex(pool), users[pool])
    # Reader details asserted on their own windows.
    has(aligned_window(p0, base0, 0x17B5EE, 0x17B5FE), r'\tbmsk_s\tr0,r0,0\b')
    has(aligned_window(p0, base0, 0x25A004, 0x25A034), r'\tbtst_s\tr0,0x1\b')

    # 15. Result JSON.
    stamp = out.name
    result = dict(
        status='PASS_IRIS_ACTUATION_STATIC',
        stamp=stamp,
        firmware_sha256=sha(FIRMWARE),
        chain=[
            dict(site=he(0x124D8A), what='AE: mov r19,0x9; mov r0,9; bl 0x149530'),
            dict(site=he(0x124E04), what='AE: mov r19,0x9; mov r0,9; bl 0x149530'),
            dict(site=he(0x124EEA), what='AE: conditional bl 0x149530(r15) under cmp_s r15,0x9'),
            dict(site=he(0x149530), what='SetIrisIndex API wrapper -> 0x18B85C'),
            dict(site=he(0x18B85C), what='setter: state [0x367FE8+2]; request 0x235B0C(h,idx,1,0x3A98)'),
            dict(site=he(0x235B0C), what='request: crit-section, busy check, branch idx==9'),
            dict(site=he(0x2358F4), what='BIG actuation: 0x0FEF0388 bclr bit0/1; 0x0FF04024 bit4=1 bit3=0'),
            dict(site=he(0x235950), what='SMALL actuation: 0x0FEF0388 bclr bit0/1; 0x0FF04024 bit3=1 bit4=0'),
            dict(site=he(0x2C5140), what='panel: bl 0x18B85C(1) Big'),
            dict(site=he(0x2C5170), what='panel: bl 0x18B85C(9) Small'),
        ],
        corrections=[
            'IRIS DOES NOT USE the lens-MCU wire: no bl from the AE/iris block reaches '
            'any wire-cluster entry; the "wrapper iris fra i 33 chiamanti di 0x25F338" '
            'open point is closed NEGATIVELY',
            'the Iris checkpoint claim "nessun GPIO iris-specifico" is CONTRADICTED: '
            'bits 3 (Small) / 4 (Big) of 0x0FF04024 are iris-specific GPIO outputs, '
            'plus clears of bits 0/1 of 0x0FEF0388',
            'BCIP_Aperture SP2 encoding 1:Big / 9:Small is confirmed at the actuation '
            'layer (cmp idx,9 selects the Small path)',
        ],
        iris_bits=dict(register=he(0x0FF04024), bit4='Big', bit3='Small',
                       strobe_register=he(0x0FEF0388), cleared_bits=[0, 1],
                       model_tuples=0x10000),
        request=dict(pre_guard='bl_s 0x235ABC: h vs [0x36A480], mismatch -> return 0 without actuation',
                    busy_object_cell=he(0x3EBD3C), error_cell=he(0x36A482),
                     error_value=0x15, control_struct=he(0x36A464),
                     counter_offset=0x1c, status_offset=6, callback_offset=0x40,
                     state_struct=he(0x367FE8), state_offset=2,
                     failure_branches=['235A1C fail -> return current (no release)',
                                     '235DA0 fail -> 0x23524C(2) then return current',
                                     'request fail -> 0x18B9D4 (iris both bits + delay 500 via 0x2359B0, 0x23524C(2), 0x235DE8) then return current'],
                     type_id=he(0x3A98), event_args=['1|1<<25', '0x10'],
                     mailbox_object_cell=he(0x36A494),
                     handlers=[he(0x235AF8), he(0x235AE4)]),
        pools_0ff04024={he(p): users[p] for p in sorted(users)},
        census=dict(calls_149530=len(CALLS_149530), calls_18b85c=len(CALLS_18B85C),
                    calls_235b0c=len(CALLS_235B0C), calls_2358f4=len(CALLS_2358F4),
                    calls_235950=len(CALLS_235950),
                    ae_block_wire_targets=0),
        limits=[
            'Static only: no MMIO, lens MCU, camera hardware or firmware execution',
            'Linear GNU listing census: branch sites near data pools can be false '
            'positives; all chain sites are re-verified in dedicated aligned windows',
            'Physical meaning of bits 3/4 of 0x0FF04024 and of bits 0/1 of 0x0FEF0388 '
            '(drive/strobe/enable) is inference from the RMW pattern; not proven '
            'electrically',
            'The register-masked RMW in 0x2349C0 could touch bits 3/4 at runtime '
            '(mask comes from a register); the sibling iris-family sites that set or '
            'clear BOTH bits (0x235438/0x2357C8/0x2359B0/0x235858/0x235BDC) are '
            'classified but their AE role is not decoded here',
            'Completion side not verified: who waits for the iris move to finish '
            '(status byte [0x36A464+6], event 0x10, mailbox handlers) is open',
            'V1.1 sample analysed; camera in the logs runs V1.0; addresses are not '
            'portable without proof',
        ],
        sources=dict(
            script=str(Path(__file__).relative_to(ROOT)),
            firmware=str(FIRMWARE.relative_to(ROOT)),
            manifest='S33-sections/TBM_blocks/manifest.json',
            objdump='work/build-arc/binutils (GNU ARC700, -EL, aligned windows)'),
    )
    (out / 'iris_actuation.json').write_text(json.dumps(result, indent=1) + '\n')
    (EVIDENCE / 'latest.json').write_text(json.dumps(
        dict(status=result['status'], stamp=stamp, path=str(out.relative_to(ROOT)),
             script=str(Path(__file__).relative_to(ROOT))), indent=1) + '\n')
    print('PASS_IRIS_ACTUATION_STATIC', stamp)


if __name__ == '__main__':
    main()
